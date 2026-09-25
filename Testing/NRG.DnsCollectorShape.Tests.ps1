#Requires -Version 7.0
#
# NRG.DnsCollectorShape.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
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
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'
        $script:Orig = & $script:Mod { @{ Resolve = ${function:Resolve-NRGDns}; Probe = ${function:Test-NRGSafeProbeTarget} } }

        & $script:Mod {
            Set-Item -Path 'function:script:Resolve-NRGDns' -Value {
                [CmdletBinding()]
                param([string] $Name, [string] $Type, [int] $TimeoutSeconds = 6, [ref] $Outcome, [ref] $Reason)
                $e = $script:T_Dns["$($Name.ToLowerInvariant())|$Type"]
                if ($null -eq $e) { $e = @{ Outcome = 'NoRecord'; Records = @() } }
                if ($null -ne $Outcome) { $Outcome.Value = $e.Outcome }
                return @($e.Records)
            }
            Set-Item -Path 'function:script:Test-NRGSafeProbeTarget' -Value { param([string] $HostName) @{ Refused = $true; Reason = 'no network in tests' } }
            Set-Item -Path 'function:script:Invoke-WebRequest' -Value { throw 'no network in tests' }
        }

        function script:Collect([hashtable] $Table, [string] $Domain = 'shape.test') {
            & $script:Mod { param($t) $script:T_Dns = $t } $Table
            Clear-NRGState
            Invoke-NRGCollectDNSEmailRecords -Domains @($Domain) 3>$null | Out-Null
            (Get-NRGRawData -Key 'DNS-EmailRecords').Data.Domains[$Domain]
        }
        $script:A = { param([string[]] $r) @{ Outcome = 'Answered'; Records = $r } }
        function script:Run([hashtable] $Table, [string] $Fn, [string] $Cid, [string] $Domain = 'shape.test') {
            $null = Collect $Table $Domain
            Verdict $Fn $Cid
        }
        function script:Verdict([string] $Fn, [string] $Cid) {
            Clear-NRGFindings
            & $Fn 3>$null | Out-Null
            @(Get-NRGFindings | Where-Object ControlId -eq $Cid)[0]
        }
    }

    AfterAll {
        & $script:Mod { param($o)
            Set-Item -Path 'function:script:Resolve-NRGDns' -Value $o.Resolve
            Set-Item -Path 'function:script:Test-NRGSafeProbeTarget' -Value $o.Probe
            Remove-Item -Path 'function:script:Invoke-WebRequest' -ErrorAction SilentlyContinue
        } $script:Orig
    }

    It 'the collector writes an ordered (non-hashtable) entry — the shape under test' {
        $d = Collect @{ 'shape.test|CAA' = @{ Outcome = 'Answered'; Records = @('0 issue "digicert.com"') } }
        $d | Should -BeOfType [System.Collections.Specialized.OrderedDictionary]
    }

    It 'DNS-2.2: a CAA record the collector read is not reported missing' {
        $null = Collect @{ 'shape.test|CAA' = @{ Outcome = 'Answered'; Records = @('0 issue "digicert.com"') } }
        $f = Verdict 'Test-NRGControlDNSCAA' 'DNS-2.2'
        $f.State  | Should -Be 'Satisfied'
        $f.Detail | Should -Not -Match 'No CAA record'
    }

    It 'DNS-2.1 / 2.3 / 2.4 reach a verdict from data in the collector''s own containers' {
        $d = Collect @{}
        $d.DKIM.KeyAgeDays = 900
        $d.TLSCerts['MailHost'] = @{ Hostname = 'mx.shape.test'; DaysUntilExpiry = 3 }
        $d.CTLog.TotalCerts = 42; $d.CTLog.Issuers = @("C=US, O=Let's Encrypt, CN=R3"); $d.CTLog.QueryError = $null
        (Verdict 'Test-NRGControlDNSDkimRotation'     'DNS-2.1').State | Should -Be 'Gap'
        (Verdict 'Test-NRGControlDNSTLSCertExpiry'    'DNS-2.3').State | Should -Be 'Gap'
        (Verdict 'Test-NRGControlDNSCertTransparency' 'DNS-2.4').State | Should -Not -Be 'NotApplicable'
    }

    Context 'record parsing reads what the RFCs say (collector + evaluator, raw DNS answers)' {
        It 'SPF: two records is a permerror, +all and a bare all authorize everyone, >10 lookups fails' {
            (Run @{ 'shape.test|TXT' = & $A @('v=spf1 -all', 'v=spf1 include:spf.protection.outlook.com -all') } 'Test-NRGControlDNSSPF' 'DNS-1.1').State | Should -Be 'Gap'
            (Run @{ 'shape.test|TXT' = & $A @('v=spf1 include:spf.protection.outlook.com +all') } 'Test-NRGControlDNSSPF' 'DNS-1.1').State | Should -Be 'Gap'
            (Run @{ 'shape.test|TXT' = & $A @('v=spf1 mx all') } 'Test-NRGControlDNSSPF' 'DNS-1.1').State | Should -Be 'Gap'
            $eleven = 'v=spf1 ' + ((1..11 | ForEach-Object { "include:s$_.example" }) -join ' ') + ' -all'
            (Run @{ 'shape.test|TXT' = & $A @($eleven) } 'Test-NRGControlDNSSPF' 'DNS-1.1').State | Should -Be 'Gap'
            (Run @{ 'shape.test|TXT' = & $A @('v=spf1 include:spf.protection.outlook.com -all') } 'Test-NRGControlDNSSPF' 'DNS-1.1').State | Should -Be 'Satisfied'
        }
        It 'SPF: redirect= is followed to the target (underscore label) and scored on its all' {
            $t = @{ 'shape.test|TXT' = & $A @('v=spf1 redirect=_spf.shape.test'); '_spf.shape.test|TXT' = & $A @('v=spf1 ip4:192.0.2.1 -all') }
            (Run $t 'Test-NRGControlDNSSPF' 'DNS-1.1').State | Should -Be 'Satisfied'
        }
        It 'DMARC: whitespace in tags, quarantine meets the control, two records apply nothing, sp=none is part-way' {
            (Run @{ '_dmarc.shape.test|TXT' = & $A @('v=DMARC1; p = reject; pct = 100') } 'Test-NRGControlDNSDMARC' 'DNS-1.3').State | Should -Be 'Satisfied'
            (Run @{ '_dmarc.shape.test|TXT' = & $A @('v=DMARC1; p=quarantine') } 'Test-NRGControlDNSDMARC' 'DNS-1.3').State | Should -Be 'Satisfied'
            (Run @{ '_dmarc.shape.test|TXT' = & $A @('v=DMARC1; p=reject', 'v=DMARC1; p=none') } 'Test-NRGControlDNSDMARC' 'DNS-1.3').State | Should -Be 'Gap'
            (Run @{ '_dmarc.shape.test|TXT' = & $A @('v=DMARC1; p=reject; sp=none') } 'Test-NRGControlDNSDMARC' 'DNS-1.3').State | Should -Be 'Partial'
            (Run @{ '_dmarc.shape.test|TXT' = & $A @('v=dmarc1; p=reject') } 'Test-NRGControlDNSDMARC' 'DNS-1.3').State | Should -Be 'Gap' -Because 'the version must be exactly DMARC1 (RFC 7489 §6.3)'
        }
        It 'DMARC / DNSSEC / CAA: a subdomain inherits its parent''s record where the RFCs say it does' {
            $t = @{ '_dmarc.shape.test|TXT' = & $A @('v=DMARC1; p=reject'); 'shape.test|DS' = & $A @('2371 13 2 1F98'); 'shape.test|CAA' = & $A @('0 issue "digicert.com"') }
            (Run $t 'Test-NRGControlDNSDMARC'  'DNS-1.3' 'mail.shape.test').State | Should -Be 'Satisfied'
            (Run $t 'Test-NRGControlDNSDNSSEC' 'DNS-1.6' 'mail.shape.test').State | Should -Be 'Satisfied'
            (Run $t 'Test-NRGControlDNSCAA'    'DNS-2.2' 'mail.shape.test').State | Should -Be 'Satisfied'
            # A delegated subdomain (its own NS) needs its own DS.
            $t['mail.shape.test|NS'] = & $A @('ns1.elsewhere.example.')
            (Run $t 'Test-NRGControlDNSDNSSEC' 'DNS-1.6' 'mail.shape.test').State | Should -Be 'Gap'
        }
        It 'CAA: iodef only restricts nothing; issuewild only restricts wildcards only' {
            (Run @{ 'shape.test|CAA' = & $A @('0 iodef "mailto:sec@shape.test"') } 'Test-NRGControlDNSCAA' 'DNS-2.2').State | Should -Be 'Gap'
            (Run @{ 'shape.test|CAA' = & $A @('0 issuewild "digicert.com"') } 'Test-NRGControlDNSCAA' 'DNS-2.2').State | Should -Be 'Partial'
        }
        It 'DKIM: selector2 alone is published DKIM, not "no DKIM"' {
            (Run @{ 'selector2._domainkey.shape.test|CNAME' = & $A @('selector2-shape-test._domainkey.shape.onmicrosoft.com.') } 'Test-NRGControlDNSDKIM' 'DNS-1.2').State | Should -Be 'Partial'
        }
        It 'MTA-STS: a policy file that could not be fetched is not assessed, not a scored mode' {
            (Run @{ '_mta-sts.shape.test|TXT' = & $A @('v=STSv1; id=20260101') } 'Test-NRGControlDNSMTASTS' 'DNS-1.4').State | Should -Be 'NotApplicable'
        }
        It 'CT: a domain with no logged certificates is not a gap' {
            $d = Collect @{}
            $d.CTLog.TotalCerts = 0; $d.CTLog.QueryError = $null
            (Verdict 'Test-NRGControlDNSCertTransparency' 'DNS-2.4').State | Should -Be 'NotApplicable'
        }
    }
}
