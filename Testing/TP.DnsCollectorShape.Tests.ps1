#Requires -Version 7.0
#
# TP.DnsCollectorShape.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# The DNS collector builds each per-domain entry as an [ordered] dictionary.
# DNS-2.1 .. DNS-2.4 read that entry with "-is [hashtable]" (false for an
# OrderedDictionary) or PSObject.Properties (which never lists dictionary
# keys), so on every live run DNS-2.2 said "No CAA record published" for a
# domain whose CAA the collector had just read, and DNS-2.1 / 2.3 / 2.4 never
# reached a verdict. The evaluator tests fed plain @{} entries, which is why
# nothing caught it. These tests run the REAL collector (resolver mocked in
# module scope) and hand its output straight to the evaluators.

Describe 'DNS-2.x evaluators read what the DNS collector actually writes' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        $script:Orig = & $script:Mod { @{ Resolve = ${function:Resolve-TPDns}; Probe = ${function:Test-TPSafeProbeTarget}; Fetch = ${function:Get-TPBoundedHttpText}; Workstation = ${function:Resolve-TPWorkstationHostAddresses} } }

        & $script:Mod {
            $script:T_ProbeReason = $null
            Set-Item -Path 'function:script:Resolve-TPDns' -Value {
                [CmdletBinding()]
                param([string] $Name, [string] $Type, [int] $TimeoutSeconds = 6, [ref] $Outcome, [ref] $Reason)
                $e = $script:T_Dns["$($Name.ToLowerInvariant())|$Type"]
                if ($null -eq $e) { $e = @{ Outcome = 'NoRecord'; Records = @() } }
                if ($null -ne $Outcome) { $Outcome.Value = $e.Outcome }
                return @($e.Records)
            }
            Set-Item -Path 'function:script:Test-TPSafeProbeTarget' -Value { param([string] $HostName)
                $why = if ($script:T_ProbeReason) { $script:T_ProbeReason } else { 'no network in tests' }
                @{ Refused = $true; Reason = $why } }
            # The crt.sh and MTA-STS reads go through Get-TPBoundedHttpText (HttpClient), not
            # Invoke-WebRequest: with only the cmdlet stubbed, every Collect reached crt.sh for real.
            Set-Item -Path 'function:script:Get-TPBoundedHttpText' -Value {
                param([string] $Uri, [int] $TimeoutSeconds, [int] $MaxBytes, [System.Net.IPAddress] $Address)
                throw 'no network in tests' }
            Set-Item -Path 'function:script:Invoke-WebRequest' -Value { throw 'no network in tests' }
        }

        function script:Collect([hashtable] $Table, [string] $Domain = 'shape.test') {
            & $script:Mod { param($t) $script:T_Dns = $t } $Table
            Clear-TPState
            Invoke-TPCollectDNSEmailRecords -Domains @($Domain) 3>$null | Out-Null
            (Get-TPRawData -Key 'DNS-EmailRecords').Data.Domains[$Domain]
        }
        $script:A = { param([string[]] $r) @{ Outcome = 'Answered'; Records = $r } }
        function script:Run([hashtable] $Table, [string] $Fn, [string] $Cid, [string] $Domain = 'shape.test') {
            $null = Collect $Table $Domain
            Verdict $Fn $Cid
        }
        function script:Verdict([string] $Fn, [string] $Cid) {
            Clear-TPFindings
            & $Fn 3>$null | Out-Null
            @(Get-TPFindings | Where-Object ControlId -eq $Cid)[0]
        }
    }

    AfterAll {
        & $script:Mod { param($o)
            Set-Item -Path 'function:script:Resolve-TPDns' -Value $o.Resolve
            Set-Item -Path 'function:script:Test-TPSafeProbeTarget' -Value $o.Probe
            Set-Item -Path 'function:script:Get-TPBoundedHttpText' -Value $o.Fetch
            Set-Item -Path 'function:script:Resolve-TPWorkstationHostAddresses' -Value $o.Workstation
            Remove-Item -Path 'function:script:Invoke-WebRequest' -ErrorAction SilentlyContinue
        } $script:Orig
    }

    It 'the collector writes an ordered (non-hashtable) entry — the shape under test' {
        $d = Collect @{ 'shape.test|CAA' = @{ Outcome = 'Answered'; Records = @('0 issue "digicert.com"') } }
        $d | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
    }

    It 'DNS-2.2: a CAA record the collector read is not reported missing' {
        $null = Collect @{ 'shape.test|CAA' = @{ Outcome = 'Answered'; Records = @('0 issue "digicert.com"') } }
        $f = Verdict 'Test-TPControlDNSCAA' 'DNS-2.2'
        $f.State  | Should -Be 'Satisfied'
        $f.Detail | Should -Not -Match 'No CAA record'
    }

    It 'DNS-2.1 / 2.3 / 2.4 reach a verdict from data in the collector''s own containers' {
        $d = Collect @{}
        $d.DKIM.KeyAgeDays = 900
        $d.TLSCerts['MailHost'] = @{ Hostname = 'mx.shape.test'; DaysUntilExpiry = 3 }
        $d.CTLog.TotalCerts = 42; $d.CTLog.Issuers = @("C=US, O=Let's Encrypt, CN=R3"); $d.CTLog.QueryError = $null
        (Verdict 'Test-TPControlDNSDkimRotation'     'DNS-2.1').State | Should -Be 'Gap'
        (Verdict 'Test-TPControlDNSTLSCertExpiry'    'DNS-2.3').State | Should -Be 'Gap'
        (Verdict 'Test-TPControlDNSCertTransparency' 'DNS-2.4').State | Should -Not -Be 'NotApplicable'
    }

    It 'DNS-2.4 judges the issuers of certificates still valid; a CA seen only on expired certificates is history, not a finding (was: Partial for a 2005 VeriSign certificate)' {
        $d = Collect @{}
        $d.CTLog.TotalCerts = 5; $d.CTLog.QueryError = $null
        $d.CTLog.Issuers = @("C=US, O=`"VeriSign, Inc.`", OU=VeriSign Trust Network, CN=VeriSign Class 3 Secure Server CA", "C=US, O=Let's Encrypt, CN=R3")
        $d.CTLog.IssuersCurrent = @("C=US, O=Let's Encrypt, CN=R3")
        $f = Verdict 'Test-TPControlDNSCertTransparency' 'DNS-2.4'
        $f.State  | Should -Be 'Satisfied'
        $f.Detail | Should -Match 'expired certificates'
        $d.CTLog.IssuersCurrent = @("C=US, O=Let's Encrypt, CN=R3", 'C=XX, O=Unknown Issuer Ltd, CN=Unknown CA')
        $f = Verdict 'Test-TPControlDNSCertTransparency' 'DNS-2.4'
        $f.State  | Should -Be 'Partial'
        $f.Detail | Should -Match 'certificates still valid'
    }

    Context 'record parsing reads what the RFCs say (collector + evaluator, raw DNS answers)' {
        It 'SPF: two records is a permerror, +all and a bare all authorize everyone, >10 lookups fails' {
            (Run @{ 'shape.test|TXT' = & $A @('v=spf1 -all', 'v=spf1 include:spf.protection.outlook.com -all') } 'Test-TPControlDNSSPF' 'DNS-1.1').State | Should -Be 'Gap'
            (Run @{ 'shape.test|TXT' = & $A @('v=spf1 include:spf.protection.outlook.com +all') } 'Test-TPControlDNSSPF' 'DNS-1.1').State | Should -Be 'Gap'
            (Run @{ 'shape.test|TXT' = & $A @('v=spf1 mx all') } 'Test-TPControlDNSSPF' 'DNS-1.1').State | Should -Be 'Gap'
            $eleven = 'v=spf1 ' + ((1..11 | ForEach-Object { "include:s$_.example" }) -join ' ') + ' -all'
            (Run @{ 'shape.test|TXT' = & $A @($eleven) } 'Test-TPControlDNSSPF' 'DNS-1.1').State | Should -Be 'Gap'
            (Run @{ 'shape.test|TXT' = & $A @('v=spf1 include:spf.protection.outlook.com -all') } 'Test-TPControlDNSSPF' 'DNS-1.1').State | Should -Be 'Satisfied'
        }
        It 'SPF: redirect= is followed to the target (underscore label) and scored on its all' {
            $t = @{ 'shape.test|TXT' = & $A @('v=spf1 redirect=_spf.shape.test'); '_spf.shape.test|TXT' = & $A @('v=spf1 ip4:192.0.2.1 -all') }
            (Run $t 'Test-TPControlDNSSPF' 'DNS-1.1').State | Should -Be 'Satisfied'
        }
        It 'DMARC: whitespace in tags, quarantine meets the control, two records apply nothing, sp=none is part-way' {
            (Run @{ '_dmarc.shape.test|TXT' = & $A @('v=DMARC1; p = reject; pct = 100') } 'Test-TPControlDNSDMARC' 'DNS-1.3').Detail | Should -Match '^Verified: .*DMARC p=(reject|quarantine)'
            (Run @{ '_dmarc.shape.test|TXT' = & $A @('v=DMARC1; p=quarantine') } 'Test-TPControlDNSDMARC' 'DNS-1.3').Detail | Should -Match '^Verified: .*DMARC p=(reject|quarantine)'
            (Run @{ '_dmarc.shape.test|TXT' = & $A @('v=DMARC1; p=reject', 'v=DMARC1; p=none') } 'Test-TPControlDNSDMARC' 'DNS-1.3').State | Should -Be 'Gap'
            (Run @{ '_dmarc.shape.test|TXT' = & $A @('v=DMARC1; p=reject; sp=none') } 'Test-TPControlDNSDMARC' 'DNS-1.3').State | Should -Be 'Partial'
            (Run @{ '_dmarc.shape.test|TXT' = & $A @('v=dmarc1; p=reject') } 'Test-TPControlDNSDMARC' 'DNS-1.3').State | Should -Be 'Gap' -Because 'the version must be exactly DMARC1 (RFC 7489 §6.3)'
        }
        It 'DMARC / DNSSEC / CAA: a subdomain inherits its parent''s record where the RFCs say it does' {
            $t = @{ '_dmarc.shape.test|TXT' = & $A @('v=DMARC1; p=reject'); 'shape.test|DS' = & $A @('2371 13 2 1F98'); 'shape.test|CAA' = & $A @('0 issue "digicert.com"') }
            (Run $t 'Test-TPControlDNSDMARC'  'DNS-1.3' 'mail.shape.test').Detail | Should -Match '^Verified: .*DMARC p=(reject|quarantine)'
            (Run $t 'Test-TPControlDNSDNSSEC' 'DNS-1.6' 'mail.shape.test').State | Should -Be 'Satisfied'
            (Run $t 'Test-TPControlDNSCAA'    'DNS-2.2' 'mail.shape.test').State | Should -Be 'Satisfied'
            # A delegated subdomain (its own NS) needs its own DS.
            $t['mail.shape.test|NS'] = & $A @('ns1.elsewhere.example.')
            (Run $t 'Test-TPControlDNSDNSSEC' 'DNS-1.6' 'mail.shape.test').State | Should -Be 'Gap'
        }
        It 'CAA: iodef only restricts nothing; issuewild only restricts wildcards only' {
            (Run @{ 'shape.test|CAA' = & $A @('0 iodef "mailto:sec@shape.test"') } 'Test-TPControlDNSCAA' 'DNS-2.2').State | Should -Be 'Gap'
            (Run @{ 'shape.test|CAA' = & $A @('0 issuewild "digicert.com"') } 'Test-TPControlDNSCAA' 'DNS-2.2').State | Should -Be 'Partial'
        }
        It 'DKIM: selector2 alone is published DKIM, not "no DKIM"' {
            (Run @{ 'selector2._domainkey.shape.test|CNAME' = & $A @('selector2-shape-test._domainkey.shape.onmicrosoft.com.') } 'Test-TPControlDNSDKIM' 'DNS-1.2').State | Should -Be 'Partial'
        }
        It 'MTA-STS: a policy file that could not be fetched is not assessed, not a scored mode' {
            (Run @{ '_mta-sts.shape.test|TXT' = & $A @('v=STSv1; id=20260101') } 'Test-TPControlDNSMTASTS' 'DNS-1.4').State | Should -Be 'NotApplicable'
        }
        It 'MTA-STS: a policy host that does not exist is a Gap; one that could not be looked up is not assessed' {
            # Live tenant, 2026-09-25: "_mta-sts" TXT published on both domains,
            # mta-sts.<domain> did not resolve, reported as "not assessed".
            & $script:Mod { $script:T_ProbeReason = 'DNS resolution failed: No such host is known.' }
            try {
                $txt = @{ '_mta-sts.shape.test|TXT' = & $A @('v=STSv1; id=20260101') }
                $f = Run $txt 'Test-TPControlDNSMTASTS' 'DNS-1.4'
                $f.State  | Should -Be 'Gap'
                $f.Detail | Should -Match 'does not exist in DNS'
                $txt['mta-sts.shape.test|A'] = @{ Outcome = 'LookupFailed'; Records = @() }
                (Run $txt 'Test-TPControlDNSMTASTS' 'DNS-1.4').State | Should -Be 'NotApplicable' -Because 'a failed lookup is not an absent host'
            } finally { & $script:Mod { $script:T_ProbeReason = $null } }
        }
        It 'CT: a domain with no logged certificates is not a gap' {
            $d = Collect @{}
            $d.CTLog.TotalCerts = 0; $d.CTLog.QueryError = $null
            (Verdict 'Test-TPControlDNSCertTransparency' 'DNS-2.4').State | Should -Be 'NotApplicable'
        }
    }

    Context 'MTA-STS policy host: the tool''s own resolver answers when the workstation resolver cannot (2026-10-15 live run)' {
        # The REAL probe guard, with the workstation lookup and the bounded HTTPS read
        # stood in for. On the live run both tenant domains' mta-sts hosts (CNAMEs to a
        # GitHub Pages host) returned "No such host is known" from the operator's
        # network while the policies read mode: enforce from anywhere else.
        BeforeAll {
            & $script:Mod { param($o)
                Set-Item -Path 'function:script:Test-TPSafeProbeTarget' -Value $o.Probe
                $script:T_WsAnswer = { throw 'No such host is known.' }
                $script:T_Fetched = [System.Collections.Generic.List[object]]::new()
                Set-Item -Path 'function:script:Resolve-TPWorkstationHostAddresses' -Value {
                    param([string] $HostName) & $script:T_WsAnswer $HostName }
                # The bounded reader also serves the crt.sh lookup: only the policy URL is
                # answered and recorded; anything else is the no-network throw of the harness.
                Set-Item -Path 'function:script:Get-TPBoundedHttpText' -Value {
                    param([string] $Uri, [int] $TimeoutSeconds, [int] $MaxBytes, [System.Net.IPAddress] $Address)
                    if ($Uri -notlike '*/.well-known/mta-sts.txt') { throw 'no network in tests' }
                    $script:T_Fetched.Add([ordered]@{ Uri = $Uri; Address = [string]$Address })
                    return "version: STSv1`nmode: enforce`nmx: mail.shape.test`nmax_age: 604800`n" }
            } $script:Orig
            function script:Fetched { & $script:Mod { @($script:T_Fetched.ToArray()) } }
            function script:ResetFetch { & $script:Mod { $script:T_Fetched.Clear() } }
            $script:StsTxt = @{ '_mta-sts.shape.test|TXT' = & $A @('v=STSv1; id=20261002') }
        }
        AfterAll {
            & $script:Mod { param($o)
                Set-Item -Path 'function:script:Test-TPSafeProbeTarget' -Value { param([string] $HostName) @{ Refused = $true; Reason = 'no network in tests' } }
                Set-Item -Path 'function:script:Get-TPBoundedHttpText' -Value {
                    param([string] $Uri, [int] $TimeoutSeconds, [int] $MaxBytes, [System.Net.IPAddress] $Address)
                    throw 'no network in tests' }
                Set-Item -Path 'function:script:Resolve-TPWorkstationHostAddresses' -Value $o.Workstation
                $script:T_WsAnswer = $null
            } $script:Orig
        }
        BeforeEach { ResetFetch }

        It 'reads the policy through the public answer, pins the fetch to that address, and says which resolver answered' {
            $t = $script:StsTxt.Clone(); $t['mta-sts.shape.test|A'] = & $A @('185.199.108.153')
            $d = Collect $t
            $d.MTASTS.Mode                     | Should -Be 'enforce'
            $d.MTASTS.PolicyHostResolvedBy     | Should -Be 'public DNS'
            $d.MTASTS.WorkstationResolverError | Should -Match 'No such host'
            @(Fetched).Count                   | Should -Be 1
            @(Fetched)[0].Address               | Should -Be '185.199.108.153'
            @(Fetched)[0].Uri                   | Should -Be 'https://mta-sts.shape.test/.well-known/mta-sts.txt'
            @($d.Errors | Where-Object { $_ -like 'MTASTS.Policy: the workstation resolver could not resolve*' }).Count | Should -Be 1
            $f = Verdict 'Test-TPControlDNSMTASTS' 'DNS-1.4'
            $f.State        | Should -Be 'Satisfied'
            $f.Detail       | Should -Match 'resolved through public DNS because the workstation'
            $f.CurrentValue | Should -Match 'public DNS'
        }
        It 'an IPv6-only public answer is used the same way' {
            $t = $script:StsTxt.Clone(); $t['mta-sts.shape.test|AAAA'] = & $A @('2606:50c0:8000::153')
            $d = Collect $t
            $d.MTASTS.Mode       | Should -Be 'enforce'
            @(Fetched)[0].Address | Should -Be '2606:50c0:8000::153'
        }
        It 'the workstation answer is still used first, with no public-DNS note' {
            & $script:Mod { $script:T_WsAnswer = { param($h) [System.Net.IPAddress[]]@([System.Net.IPAddress]::Parse('185.199.109.153')) } }
            try {
                $t = $script:StsTxt.Clone(); $t['mta-sts.shape.test|A'] = & $A @('185.199.108.153')
                $d = Collect $t
                $d.MTASTS.PolicyHostResolvedBy | Should -Be 'workstation resolver'
                @(Fetched)[0].Address           | Should -Be '185.199.109.153'
                (Verdict 'Test-TPControlDNSMTASTS' 'DNS-1.4').Detail | Should -Not -Match 'public DNS'
            } finally { & $script:Mod { $script:T_WsAnswer = { throw 'No such host is known.' } } }
        }
        It 'an authoritative no-record from public DNS is still the Gap, and nothing is fetched' {
            $f = Run $script:StsTxt 'Test-TPControlDNSMTASTS' 'DNS-1.4'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'does not exist in DNS'
            @(Fetched).Count | Should -Be 0
        }
        It 'a public lookup that did not complete is not assessed, with both resolvers named' {
            $t = $script:StsTxt.Clone(); $t['mta-sts.shape.test|A'] = @{ Outcome = 'LookupFailed'; Records = @() }
            $d = Collect $t
            $d.MTASTS.PolicyHostMissing | Should -BeFalse
            $d.MTASTS.PolicyFetchError  | Should -Match 'DNS resolution failed: No such host is known\.; public DNS: lookup did not complete'
            @(Fetched).Count            | Should -Be 0
            (Verdict 'Test-TPControlDNSMTASTS' 'DNS-1.4').State | Should -Be 'NotApplicable'
        }
        It 'a public answer inside a private range is refused exactly as a workstation answer would be' {
            $t = $script:StsTxt.Clone(); $t['mta-sts.shape.test|A'] = & $A @('10.1.2.3')
            $d = Collect $t
            $d.MTASTS.PolicyFetchError | Should -Match 'refused'
            $d.MTASTS.PolicyFetchError | Should -Match 'RFC 1918'
            @(Fetched).Count           | Should -Be 0
            (Verdict 'Test-TPControlDNSMTASTS' 'DNS-1.4').State | Should -Be 'NotApplicable'
        }
        It 'DNS-1.4 enforce mode is Satisfied only when the policy''s mx: patterns cover every MX host (NIST SP 800-177r1 5-3)' {
            $t = $script:StsTxt.Clone(); $t['mta-sts.shape.test|A'] = & $A @('185.199.108.153')
            $t['shape.test|MX'] = & $A @('10 mail.shape.test.')
            $null = Collect $t
            $f = Verdict 'Test-TPControlDNSMTASTS' 'DNS-1.4'
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'Every MX host \(mail\.shape\.test\) matches the policy''s mx: patterns \(mail\.shape\.test\)'
            $t['shape.test|MX'] = & $A @('10 mail.shape.test.', '20 backup.other.test.')
            $null = Collect $t
            $f = Verdict 'Test-TPControlDNSMTASTS' 'DNS-1.4'
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match '^Verified: shape\.test MTA-STS is in enforce mode\. Shortfall: MX host\(s\) backup\.other\.test match none'
            @($f.AffectedObjects)[0].MxHost | Should -Be 'backup.other.test'
        }
        It 'DNS-1.4: an MX lookup that did not complete leaves the coverage not assessed, never a pass' {
            $t = $script:StsTxt.Clone(); $t['mta-sts.shape.test|A'] = & $A @('185.199.108.153')
            $t['shape.test|MX'] = @{ Outcome = 'LookupFailed'; Records = @() }
            $null = Collect $t
            $f = Verdict 'Test-TPControlDNSMTASTS' 'DNS-1.4'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'Not assessed: whether the policy covers every MX host, because the MX lookup did not complete'
            @($f.FrameworkIds).Count | Should -BeGreaterThan 0
        }
        It 'DNS-1.4: a replayed enforce result without the policy text is not assessed' {
            Clear-TPState
            Set-TPRawData -Key 'DNS-EmailRecords' -Data ([pscustomobject]@{ Success = $true; Data = [pscustomobject]@{ DomainCount = 1
                Domains = @{ 'old.test' = [pscustomobject]@{ MTASTS = [pscustomobject]@{ DNSRecord = 'v=STSv1; id=1'; Mode = 'enforce' }; MX = @([pscustomobject]@{ Preference = 10; Exchange = 'mx.old.test' }) } } } })
            (Verdict 'Test-TPControlDNSMTASTS' 'DNS-1.4').State | Should -Be 'NotApplicable'
        }
        It 'DNS-1.4: an mx: wildcard matches exactly one leftmost label (RFC 8461 section 4.1)' {
            & $script:Mod {
                Test-TPMtaStsMxPattern -Pattern '*.mail.protection.outlook.com' -HostName 'contoso-com.mail.protection.outlook.com.' | Should -BeTrue
                Test-TPMtaStsMxPattern -Pattern '*.example.com' -HostName 'example.com'        | Should -BeFalse
                Test-TPMtaStsMxPattern -Pattern '*.example.com' -HostName 'a.b.example.com'    | Should -BeFalse
                Test-TPMtaStsMxPattern -Pattern 'MX1.Example.com' -HostName 'mx1.example.COM.' | Should -BeTrue
                Test-TPMtaStsMxPattern -Pattern 'mx*.example.com' -HostName 'mx1.example.com'  | Should -BeFalse
                Test-TPMtaStsMxPattern -Pattern 'mx1.example.com' -HostName 'xmx1.example.com' | Should -BeFalse
            }
        }
        It 'an answer whose rows are not addresses is a lookup that did not complete, never a missing host' {
            $t = $script:StsTxt.Clone(); $t['mta-sts.shape.test|A'] = & $A @('not-an-address')
            $d = Collect $t
            $d.MTASTS.PolicyHostMissing | Should -BeFalse
            $d.MTASTS.PolicyFetchError  | Should -Match 'not IP addresses'
            (Verdict 'Test-TPControlDNSMTASTS' 'DNS-1.4').State | Should -Be 'NotApplicable'
        }
    }
}
