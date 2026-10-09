#Requires -Version 7.0
#
# TP.NetworkEgress.Tests.ps1
#
# Locks down the tool's outbound network surface. Exists because an older
# version fetched a public Tor exit-node list from a Tor Project host
# on every Email-IR run — a connection to Tor infrastructure that
# Microsoft Defender / Cortex XDR / CrowdStrike flag as "malicious_tor_access"
# on the OPERATOR'S OWN endpoint. That fetch was removed in commit a614ca3,
# but nothing stopped it from being reintroduced. This suite makes the
# removal permanent and pins the allowed egress list so a new outbound host
# is a deliberate, reviewed change — never a surprise EDR alert on a client
# or operator machine.
#
# A read-only assessment tool has a small, auditable egress surface. If a
# host needs adding, add it to $AllowedEgressHosts below IN THE SAME PR that
# introduces the call, with a comment explaining why.

Describe 'Network egress surface' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        # All .ps1/.psm1 source, excluding tests and any output/.git.
        $script:SourceFiles = Get-ChildItem -Path $script:RepoRoot -Recurse -File -Include '*.ps1','*.psm1' |
            Where-Object { $_.FullName -notmatch '[\\/](Testing|output|\.git)[\\/]' }

        # Hosts the tool is permitted to contact. Everything read-only /
        # documented. Tor infrastructure is deliberately absent.
        $script:AllowedEgressHosts = @(
            'graph.microsoft.com'         # Microsoft Graph (all collectors)
            'login.microsoftonline.com'   # auth
            'outlook.office365.com'        # Exchange Online
            'api.bap.microsoft.com'        # Power Platform admin API
            'service.powerapps.com'        # Power Platform token audience
            'www.powershellgallery.com'    # module install (setup only)
            'rdap.org'                     # IP geolocation / ASN (sign-in triage)
            'crt.sh'                       # Certificate Transparency (DNS checks)
            'cloudflare-dns.com'           # DNS-over-HTTPS resolver (Resolve-TPDns, DNS email-auth)
            'dns.google'                   # DNS-over-HTTPS fallback resolver
            'aka.ms'                        # Microsoft doc redirects
            'timestamp.digicert.com'       # Authenticode timestamp (release signing)
            'timestamp.sectigo.com'        # Authenticode timestamp (release signing)
            'www.nrgtechservices.com'      # vendor branding link
        )
    }

    It 'No source file contacts Tor infrastructure (the Tor Project host or its bulk exit list)' {
        # Comments are allowed to REFERENCE it (removal notes explain why it's
        # gone); a non-comment source line that names it is a live fetch
        # sneaking back in.
        # The pattern is assembled from pieces so this file does not itself
        # contain the host name a keyword scan would flag.
        $torRx = ('to' + 'rproject') + '|' + ('to' + 'rbulk' + 'exitlist')
        $offenders = [System.Collections.Generic.List[string]]::new()
        foreach ($f in $script:SourceFiles) {
            $n = 0
            foreach ($line in (Get-Content -LiteralPath $f.FullName)) {
                $n++
                $trimmed = $line.TrimStart()
                if ($trimmed.StartsWith('#')) { continue }   # comment — allowed
                if ($line -imatch $torRx) {
                    $offenders.Add(('{0}:{1}: {2}' -f $f.Name, $n, $line.Trim()))
                }
            }
        }
        $offenders -join "`n" | Should -BeNullOrEmpty -Because 'contacting Tor Project hosts trips malicious_tor_access on the operator/client endpoint — standalone Tor-exit detection was removed from the tool entirely rather than reworked around it'
    }

    It 'Every hard-coded https host in source is on the allow-list' {
        $rx = [regex]'https?://([a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
        $seen = [System.Collections.Generic.Dictionary[string,string]]::new()
        foreach ($f in $script:SourceFiles) {
            $n = 0
            foreach ($line in (Get-Content -LiteralPath $f.FullName)) {
                $n++
                $trimmed = $line.TrimStart()
                if ($trimmed.StartsWith('#')) { continue }
                foreach ($m in $rx.Matches($line)) {
                    $egressHost = $m.Groups[1].Value.ToLowerInvariant()
                    # Ignore schema/spec/doc URLs that are never fetched at runtime.
                    if ($egressHost -match 'schema|w3\.org|json-schema|oasis|sarif|example\.|contoso|learn\.microsoft|github') { continue }
                    if (-not $seen.ContainsKey($egressHost)) { $seen[$egressHost] = ('{0}:{1}' -f $f.Name, $n) }
                }
            }
        }
        $unlisted = @($seen.Keys | Where-Object { $_ -notin $script:AllowedEgressHosts } | Sort-Object)
        ($unlisted | ForEach-Object { '{0}  (first seen {1})' -f $_, $seen[$_] }) -join "`n" |
            Should -BeNullOrEmpty -Because 'a new outbound host must be added to $AllowedEgressHosts in the same PR, with justification — this is how we keep the egress surface auditable and EDR-quiet'
    }
}
