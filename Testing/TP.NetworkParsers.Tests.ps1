#Requires -Version 7.0
#
# TP.NetworkParsers.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Answers an attacker can publish (an MX host's AAAA record, an MTA-STS policy
# body, a DoH TXT value) are parsed with bounds: a connection target must be
# globally routable unicast after unwrapping, an HTTPS body is read under one
# timeout with no redirect and a byte cap, and TXT data is joined in one pass.

Describe 'Network parsers are bounded' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    }
    AfterAll { Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }

    Context 'Test-TPGloballyRoutableAddress' {
        It 'refuses every private, special and wrapped-private form and names the reason' {
            foreach ($s in '::ffff:10.0.0.1', '::ffff:169.254.169.254', '64:ff9b::a00:1', '2002:c0a8:101::', '2001:0:1::1', '::', '0.0.0.0', '100.64.0.1', '127.0.0.1', '10.1.2.3', '172.20.0.1', '192.168.1.1', '169.254.1.1', '224.0.0.1', '255.255.255.255', 'fe80::1', 'fd00::1', 'ff02::1', '2001:db8::1', '2001:2::1', '2001:10::1', '2001:20::1', '2001:100::1', '2001:1::3', '3fff::1', '5f00::1', '192.0.2.1', '192.88.99.2', '198.18.0.1') {
                $r = Test-TPGloballyRoutableAddress -Address ([ipaddress]$s)
                $r.Allowed | Should -BeFalse -Because "$s must be refused"
                $r.Reason | Should -Not -BeNullOrEmpty
            }
        }
        It 'allows public addresses and hands back the unwrapped form to connect to' {
            foreach ($s in '1.1.1.1', '8.8.8.8', '2606:4700::1111', '::ffff:8.8.8.8', '2001:1::1', '2001:3::1', '2001:4:112::1', '2001:30::1', '2001:200::1') {
                $r = Test-TPGloballyRoutableAddress -Address ([ipaddress]$s)
                $r.Allowed | Should -BeTrue -Because "$s is public"
            }
            (Test-TPGloballyRoutableAddress -Address ([ipaddress]'::ffff:8.8.8.8')).Address.ToString() | Should -Be '8.8.8.8'
            foreach ($s in '64:ff9b::808:808', '2002:808:808::1') {
                $r = Test-TPGloballyRoutableAddress -Address ([ipaddress]$s)
                $r.Allowed | Should -BeTrue -Because "$s embeds a public IPv4 address"
                $r.Address.ToString() | Should -Be ([ipaddress]$s).ToString() -Because 'a NAT64 or 6to4 address stays the connection target'
            }
            (Test-TPGloballyRoutableAddress -Address ([ipaddress]'64:ff9b::a00:1')).Reason | Should -Match 'NAT64.*10/8'
        }
    }

    Context 'ConvertFrom-TPDnsTxtData' {
        It 'joins quoted segments with RFC 1035 escapes, passes bare values through, and refuses unterminated quoting fast' {
            $q = [string][char]34
            ConvertFrom-TPDnsTxtData -Data ($q + 'v=spf1 a' + $q + ' ' + $q + ' -all' + $q) | Should -Be 'v=spf1 a -all'
            ConvertFrom-TPDnsTxtData -Data ($q + 'say \' + $q + 'hi\' + $q + ' \\' + $q) | Should -Be ('say ' + $q + 'hi' + $q + ' \')
            ConvertFrom-TPDnsTxtData -Data 'v=spf1 -all' | Should -Be 'v=spf1 -all'
            ConvertFrom-TPDnsTxtData -Data ($q + 'a\032b\0659' + $q) | Should -Be 'a bA9' -Because '\DDD is a decimal octet; \065 then the literal 9'
            $null -eq (ConvertFrom-TPDnsTxtData -Data ($q + '\999' + $q)) | Should -BeTrue -Because 'an octet above 255 is malformed'
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $null -eq (ConvertFrom-TPDnsTxtData -Data ($q + (('\' + $q) * 25000))) | Should -BeTrue
            $sw.Stop(); $sw.ElapsedMilliseconds | Should -BeLessThan 2000 -Because 'the parser is linear'
        }
    }

    # The certificate probe shakes hands with a host the assessed tenant's DNS names
    # (autodiscover.<domain>, the first MX host). Every peer here is a loopback socket
    # served from this process: nothing leaves the machine.
    Context 'Get-TPBoundedTlsStream puts one deadline over the whole TLS handshake' {
        BeforeAll {
            $script:Mod = Get-Module -Name 'TenantPosture'
            $script:NewListener = {
                $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
                $listener.Start()
                $listener
            }
            $script:ConnectTo = {
                param($Listener)
                $client = [System.Net.Sockets.TcpClient]::new([System.Net.Sockets.AddressFamily]::InterNetwork)
                $client.Connect([System.Net.IPAddress]::Loopback, ([System.Net.IPEndPoint]$Listener.LocalEndpoint).Port)
                $client
            }
            # A server that never completes a handshake. It needs a thread of its own (the test's
            # thread is the client), so it is a script file run in a second runspace. It stops by
            # itself, when the client goes away or after about 40 seconds: a handshake that has
            # lost its deadline then fails these tests instead of hanging the suite.
            $script:PeerScript = Join-Path $TestDrive 'never-completes-a-handshake.ps1'
            Set-Content -LiteralPath $script:PeerScript -Encoding utf8 -Value @'
param($Listener, [string] $Mode)
$connection = $Listener.AcceptTcpClient()
$sent = 0
try {
    $stream = $connection.GetStream()
    if ($Mode -eq 'Trickle') {
        # A TLS record header announcing 16,384 bytes, then one byte every 100 ms.
        foreach ($octet in 0x16, 0x03, 0x03, 0x40, 0x00) { $stream.WriteByte($octet); $sent++ }
        while ($sent -lt 400) { Start-Sleep -Milliseconds 100; $stream.WriteByte(0); $sent++ }
    } else {
        # Takes whatever the client sends and never answers.
        $stream.ReadTimeout = 40000
        $buffer = [byte[]]::new(4096)
        while ($stream.Read($buffer, 0, $buffer.Length) -gt 0) { }
    }
} catch { $null = $_ } finally { $connection.Dispose() }
$sent
'@
            $script:StartPeer = {
                param($Listener, [string] $Mode)
                $shell = [powershell]::Create()
                $null = $shell.AddCommand($script:PeerScript).AddArgument($Listener).AddArgument($Mode)
                @{ Shell = $shell; Running = $shell.BeginInvoke() }
            }
            # Returns the number of bytes the peer sent. Call it after the client is disposed and
            # the listener stopped, which ends every call the peer can be blocked in; a peer that
            # still has not ended is left behind (-1), never waited for.
            $script:StopPeer = {
                param($Peer)
                if (-not $Peer.Running.AsyncWaitHandle.WaitOne(15000)) { $null = $Peer.Shell.BeginStop($null, $null); return -1 }
                $sent = [int](@($Peer.Shell.EndInvoke($Peer.Running)) | Select-Object -Last 1)
                $Peer.Shell.Dispose()
                $sent
            }
            # The helper is not exported: the collector calls it from inside the module.
            $script:Handshake = {
                param($Client, [int] $Deadline)
                $inner = $Client.GetStream()
                & $script:Mod { param($stream, $seconds) Get-TPBoundedTlsStream -InnerStream $stream -TargetHost 'mail.example.test' -TimeoutSeconds $seconds } $inner $Deadline
            }
        }

        It 'stops waiting for a server that accepts the connection and then says nothing' {
            $listener = & $script:NewListener
            $peer = & $script:StartPeer $listener 'Silent'
            $client = & $script:ConnectTo $listener
            $failure = $null; $closed = $false
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                try { $null = & $script:Handshake $client 2 } catch { $failure = [string]$_.Exception.Message }
                $sw.Stop()
                $closed = -not $client.Connected
            } finally { $client.Dispose(); $listener.Stop(); $null = & $script:StopPeer $peer }
            $failure | Should -Match 'TLS handshake timed out after 2 s'
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 12 -Because 'the synchronous handshake this replaces has no timeout and never returned'
            $closed | Should -BeTrue -Because 'the socket under the abandoned handshake is closed at the deadline'
        }

        It 'stops waiting for a server that sends one byte at a time' {
            # Every read succeeds, so a read timeout on the socket never fires; only a deadline
            # over the whole handshake ends it.
            $listener = & $script:NewListener
            $peer = & $script:StartPeer $listener 'Trickle'
            $client = & $script:ConnectTo $listener
            $failure = $null; $sent = 0
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                try { $null = & $script:Handshake $client 2 } catch { $failure = [string]$_.Exception.Message }
                $sw.Stop()
            } finally { $client.Dispose(); $listener.Stop(); $sent = & $script:StopPeer $peer }
            $failure | Should -Match 'TLS handshake timed out after 2 s'
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 12 -Because 'bytes that keep arriving must not extend the deadline'
            $sent | Should -BeGreaterThan 6 -Because 'the server was still sending when the deadline ended the handshake'
        }

        It 'still completes the handshake with a server that answers, and reads a certificate it would not trust' {
            # Self-signed, and for a name that is not the one probed: validation refuses it on both
            # counts, and certificates like it (expired, mismatched, untrusted) are what the probe reads.
            $key = [System.Security.Cryptography.RSA]::Create(2048)
            $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new('CN=not-the-probed-name.example.test', $key, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $selfSigned = $request.CreateSelfSigned([datetimeoffset]::UtcNow.AddDays(-1), [datetimeoffset]::UtcNow.AddDays(20))
            # Through PKCS#12 and back: Windows does not serve TLS from the in-memory key CreateSelfSigned leaves.
            $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($selfSigned.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx))
            $expected = $certificate.Thumbprint
            $listener = & $script:NewListener
            $client = & $script:ConnectTo $listener
            $accepted = $listener.AcceptTcpClient()
            $serverTls = [System.Net.Security.SslStream]::new($accepted.GetStream(), $false)
            # The server's half of the handshake runs on the thread pool; this thread is the client.
            $serving = $serverTls.AuthenticateAsServerAsync($certificate)
            $failure = $null; $tls = $null; $authenticated = $false; $thumbprint = ''; $server = 'did not finish'
            try {
                try { $tls = & $script:Handshake $client 10 } catch { $failure = [string]$_.Exception.Message }
                if ($tls) {
                    $authenticated = $tls.IsAuthenticated
                    $thumbprint = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($tls.RemoteCertificate).Thumbprint
                }
                try { if ($serving.Wait(5000)) { $server = 'served' } } catch { $server = [string]$_.Exception.Message }
            } finally {
                if ($tls) { $tls.Dispose() }
                $client.Dispose(); $serverTls.Dispose(); $accepted.Dispose(); $listener.Stop()
                $certificate.Dispose(); $selfSigned.Dispose(); $key.Dispose()
            }
            $failure | Should -BeNullOrEmpty -Because "a certificate nobody would trust is still read (server: $server)"
            $tls | Should -BeOfType ([System.Net.Security.SslStream])
            $authenticated | Should -BeTrue
            $thumbprint | Should -Be $expected -Because 'the certificate the server presented is the one handed back'
        }

        It 'starts a TLS client handshake nowhere but in the bounded helper, and the DNS collector uses it' {
            $starts = [System.Collections.Generic.List[string]]::new()
            $collectorCalls = @()
            foreach ($folder in 'Lib', 'Collectors', 'Evaluators', 'Publishers', 'Email-IR') {
                $files = Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot $folder) -Filter '*.ps1' -Recurse -File | Where-Object { $_.FullName -notmatch '[/\\]Testing[/\\]' }
                foreach ($file in $files) {
                    $tokens = $null; $errors = $null
                    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
                    foreach ($call in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true)) {
                        $member = [string]$call.Member.Extent.Text
                        if ($member -notmatch 'AuthenticateAsClient') { continue }
                        $owner = $call.Parent
                        while ($owner -and $owner -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $owner = $owner.Parent }
                        $starts.Add(('{0}:{1} {2} in {3}' -f $file.Name, $call.Extent.StartLineNumber, $member, $(if ($owner) { $owner.Name } else { 'no function' })))
                    }
                    foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-TPCollectDNSEmailRecords' }, $true)) {
                        $collectorCalls = @($fn.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { "$($_.GetCommandName())" })
                    }
                }
            }
            $starts.Count | Should -BeGreaterThan 0 -Because 'if this is 0 the search found nothing and the next line proves nothing'
            @($starts | Where-Object { $_ -notmatch ' in Get-TPBoundedTlsStream$' }) | Should -BeNullOrEmpty -Because 'a handshake with a host DNS names goes through Get-TPBoundedTlsStream'
            @($starts | Where-Object { $_ -match ' AuthenticateAsClient in ' }) | Should -BeNullOrEmpty -Because 'the synchronous SslStream.AuthenticateAsClient has no timeout of its own, wherever it is called'
            $collectorCalls | Should -Contain 'Get-TPBoundedTlsStream'
        }
    }

    Context 'Get-TPBoundedHttpText against a local TLS server' {
        BeforeAll {
            $script:Srv = $null
            $d = Join-Path $TestDrive 'srv'; New-Item -ItemType Directory -Path $d -Force | Out-Null
            $script:Dir = $d
            $null = & openssl req -x509 -newkey rsa:2048 -nodes -keyout (Join-Path $d 'key.pem') -out (Join-Path $d 'cert.pem') -days 2 -subj '/CN=127.0.0.1' -addext 'subjectAltName=IP:127.0.0.1' 2>&1
            $script:CertOk = Test-Path -LiteralPath (Join-Path $d 'cert.pem')
            $py = (Get-Command python3, python -ErrorAction SilentlyContinue | Select-Object -First 1).Source
            $script:PyOk = [bool]$py
            if ($script:CertOk -and $script:PyOk) {
                $server = @'
import http.server, ssl, sys, time
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        p = self.path
        if p == '/redir':
            self.send_response(302); self.send_header('Location', 'https://127.0.0.1:1/x'); self.end_headers(); return
        if p == '/big':
            body = b'a' * 300000
        elif p == '/slow':
            self.send_response(200); self.send_header('Content-Type', 'text/plain'); self.end_headers()
            self.wfile.write(b'version: STSv1\nmode: '); self.wfile.flush(); time.sleep(25); self.wfile.write(b'enforce\n'); return
        else:
            body = b'version: STSv1\nmode: enforce\nmx: mail.example\nmax_age: 86400\n'
        self.send_response(200); self.send_header('Content-Type', 'text/plain'); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
srv = http.server.HTTPServer(('127.0.0.1', int(sys.argv[1])), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain(sys.argv[2], sys.argv[3])
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
'@
                Set-Content -LiteralPath (Join-Path $d 'srv.py') -Value $server -Encoding utf8
                $script:Port = Get-Random -Minimum 20000 -Maximum 40000
                $script:Srv = Start-Process -FilePath $py -ArgumentList @('-I', (Join-Path $d 'srv.py'), $script:Port, (Join-Path $d 'cert.pem'), (Join-Path $d 'key.pem')) -PassThru -RedirectStandardError (Join-Path $d 'err.txt')
                Start-Sleep -Milliseconds 1500
            }
            # .NET on Linux and macOS reads SSL_CERT_FILE at process start, so the
            # calls run in a child pwsh that trusts the test certificate.
            $script:Call = {
                param([string] $Path, [int] $Timeout, [int] $Max, [string] $Pin = '')
                $pinArg = if ($Pin) { " -Address ([ipaddress]'$Pin')" } else { '' }
                $cmd = "Import-Module '$(Join-Path $script:RepoRoot 'TenantPosture.psm1')' -Force; try { `$t = Get-TPBoundedHttpText -Uri 'https://127.0.0.1:$($script:Port)$Path' -TimeoutSeconds $Timeout -MaxBytes $Max$pinArg; @{ ok = `$true; len = `$t.Length; text = `$t } | ConvertTo-Json -Compress } catch { @{ ok = `$false; err = `$_.Exception.Message } | ConvertTo-Json -Compress }"
                $env:SSL_CERT_FILE = Join-Path $script:Dir 'cert.pem'
                try { (& pwsh -NoProfile -Command $cmd 2>&1 | Select-Object -Last 1) | ConvertFrom-Json } finally { Remove-Item Env:SSL_CERT_FILE -ErrorAction SilentlyContinue }
            }
        }
        AfterAll { if ($script:Srv) { Stop-Process -Id $script:Srv.Id -Force -ErrorAction SilentlyContinue } }

        It 'reads a small policy body' {
            if (-not ($script:CertOk -and $script:PyOk -and $script:Srv)) { Set-ItResult -Skipped -Because 'no openssl, python or local server'; return }
            $r = & $script:Call '/policy' 10 65536
            $r.ok | Should -BeTrue -Because ($r.err)
            $r.text | Should -Match 'mode: enforce'
        }
        It 'connects to the pinned address, not to a second resolution of the name' {
            if (-not ($script:CertOk -and $script:PyOk -and $script:Srv)) { Set-ItResult -Skipped -Because 'no openssl, python or local server'; return }
            $r = & $script:Call '/policy' 10 65536 '127.0.0.1'
            $r.ok | Should -BeTrue -Because ($r.err)
            $r.text | Should -Match 'mode: enforce'
            # Pinned to an address nothing listens on, the name (which does resolve to the server) is not used to connect.
            $r2 = & $script:Call '/policy' 5 65536 '127.0.0.2'
            $r2.ok | Should -BeFalse -Because 'the connection must go to the pinned address only'
        }
        It 'refuses a redirect instead of following it' {
            if (-not ($script:CertOk -and $script:PyOk -and $script:Srv)) { Set-ItResult -Skipped -Because 'no local server'; return }
            $r = & $script:Call '/redir' 10 65536
            $r.ok | Should -BeFalse
            $r.err | Should -Match 'redirect'
        }
        It 'stops at the byte cap' {
            if (-not ($script:CertOk -and $script:PyOk -and $script:Srv)) { Set-ItResult -Skipped -Because 'no local server'; return }
            $r = & $script:Call '/big' 10 65536
            $r.ok | Should -BeFalse
            $r.err | Should -Match 'exceeds'
        }
        It 'times out a body that trickles, under the whole-transfer timeout' {
            if (-not ($script:CertOk -and $script:PyOk -and $script:Srv)) { Set-ItResult -Skipped -Because 'no local server'; return }
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $r = & $script:Call '/slow' 3 65536
            $sw.Stop()
            $r.ok | Should -BeFalse
            $r.err | Should -Match 'timed out'
            $sw.Elapsed.TotalSeconds | Should -BeLessThan 15 -Because 'the old -TimeoutSec covered only the headers and waited the full 25 s'
        }
    }
}
