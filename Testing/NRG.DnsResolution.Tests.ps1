#Requires -Version 7.0
#
# NRG.DnsResolution.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Pins Resolve-NRGDns against the DoH response shapes that are NOT a clean
# answer, which is where it previously guessed.
#
# The bug: the function returned `@()` for any response lacking an `Answer`
# property, without ever reading `Status`. Cloudflare returns SERVFAIL as
# HTTP 200 with `Status: 2` and no `Answer`, so a failing resolver was
# indistinguishable from NXDOMAIN — and because that was a bare `return`, it
# also short-circuited the Google fallback and the Resolve-DnsName fallback
# beneath it. One transient SERVFAIL therefore produced a confident "no DMARC
# record", and the DNS evaluators score an absent record as a Gap. The tool
# would tell a client their email authentication was missing when it was not.
#
# An empty result is ambiguous here exactly the way an empty collector section
# is, so the fix is the same shape: a tri-state outcome that distinguishes
# "resolved, no such record" from "could not resolve".
#
# Every fixture below is a RESPONSE SHAPE, not a hostname — the live-DNS
# behaviour is covered separately and cannot exercise SERVFAIL on demand.

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:ModuleRoot 'Lib/Resolve-NRGDns.ps1')

    # DoH JSON shapes, as the providers actually return them.
    function script:DohAnswer {
        param([string] $Data, [int] $Type = 16)
        [pscustomobject]@{ Status = 0; Answer = @([pscustomobject]@{ type = $Type; data = $Data }) }
    }
    function script:DohNxdomain { [pscustomobject]@{ Status = 3 } }
    function script:DohNodata   { [pscustomobject]@{ Status = 0 } }
    function script:DohServfail { [pscustomobject]@{ Status = 2 } }
    function script:DohRefused  { [pscustomobject]@{ Status = 5 } }

}

Describe 'Resolve-NRGDns — a failed lookup is not an absent record' {

    It 'reports LookupFailed when every provider SERVFAILs' {
        # THE bug. This previously returned @() with no way for the caller to
        # know it was a failure, and the DNS evaluators score that as a Gap.
        Mock Invoke-RestMethod { script:DohServfail }
        $o = ''
        $r = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o | Should -Be 'LookupFailed'
        $r.Count | Should -Be 0
    }

    It 'reports LookupFailed when every provider REFUSEs' {
        Mock Invoke-RestMethod { script:DohRefused }
        $o = ''
        $null = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o | Should -Be 'LookupFailed'
    }

    It 'reports LookupFailed when every provider throws' {
        Mock Invoke-RestMethod { throw 'connection reset' }
        $o = ''
        $null = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o | Should -Be 'LookupFailed'
    }

    It 'falls through to the SECOND provider when the first SERVFAILs' {
        # The short-circuit was the compounding half of the bug: one failing
        # resolver meant the healthy one was never asked.
        $script:calls = 0
        Mock Invoke-RestMethod {
            $script:calls++
            if ($script:calls -eq 1) { script:DohServfail }
            else { script:DohAnswer '"v=DMARC1; p=reject"' }
        }
        $o = ''
        $r = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $script:calls | Should -Be 2 -Because 'the second provider must be consulted after a non-authoritative status'
        $o            | Should -Be 'Answered'
        $r[0]         | Should -Be 'v=DMARC1; p=reject'
    }

    It 'reports LookupFailed, not NoRecord, when a provider returns a body with no Status' {
        # A TLS-inspecting egress proxy intercepts cloudflare-dns.com and
        # returns its HTML block page with HTTP 200. Invoke-RestMethod hands
        # back a [string]; there is no Status and no Answer. The first version
        # of this fix read "no Answer" as NoRecord and never asked Google —
        # every domain's SPF, DMARC, MTA-STS, TLS-RPT, DS and CAA would have
        # scored Gap on that network. A body we cannot read is a failure.
        Mock Invoke-RestMethod { '<html><body>Access to this site is blocked by policy.</body></html>' }
        $o = ''
        $r = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o       | Should -Be 'LookupFailed'
        $r.Count | Should -Be 0
    }

    It 'falls through to the second provider when the first returns a body with no Status' {
        $script:calls3 = 0
        Mock Invoke-RestMethod {
            $script:calls3++
            if ($script:calls3 -eq 1) { '<html>blocked</html>' }
            else { script:DohAnswer '"v=DMARC1; p=reject"' }
        }
        $o = ''
        $r = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $script:calls3 | Should -Be 2
        $o             | Should -Be 'Answered'
        $r[0]          | Should -Be 'v=DMARC1; p=reject'
    }

    It 'reports LookupFailed when Status is present but not numeric' {
        Mock Invoke-RestMethod { [pscustomobject]@{ Status = 'error'; message = 'rate limited' } }
        $o = ''
        $null = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o | Should -Be 'LookupFailed'
    }

    It 'names every provider that failed, and why, through -Reason' {
        # The evaluator's "every resolver failed" is only actionable if the
        # results JSON says what failed. Previously nothing did.
        Mock Invoke-RestMethod { throw 'connection reset by peer' }
        $o = ''; $why = ''
        $null = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o) -Reason ([ref]$why))
        $o   | Should -Be 'LookupFailed'
        $why | Should -Match 'cloudflare-dns\.com: connection reset'
        $why | Should -Match 'dns\.google: connection reset'
    }

    It 'reports the DoH Status code in -Reason on SERVFAIL' {
        Mock Invoke-RestMethod { script:DohServfail }
        $o = ''; $why = ''
        $null = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o) -Reason ([ref]$why))
        $why | Should -Match 'Status 2'
    }

    It 'leaves -Reason empty on a successful answer' {
        Mock Invoke-RestMethod { script:DohAnswer '"v=spf1 -all"' }
        $o = ''; $why = ''
        $null = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o) -Reason ([ref]$why))
        $why | Should -BeNullOrEmpty
    }

    It 'falls through to the second provider when the first throws' {
        $script:calls2 = 0
        Mock Invoke-RestMethod {
            $script:calls2++
            if ($script:calls2 -eq 1) { throw 'timeout' }
            else { script:DohAnswer '"v=spf1 -all"' }
        }
        $o = ''
        $r = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o    | Should -Be 'Answered'
        $r[0] | Should -Be 'v=spf1 -all'
    }
}

Describe 'Resolve-NRGDns — an authoritative answer is still authoritative' {

    It 'reports NoRecord on NXDOMAIN without consulting the second provider' {
        # The fix must not turn every genuine absence into a retry storm, nor
        # into LookupFailed — an absent SPF record IS a real finding.
        $script:nx = 0
        Mock Invoke-RestMethod { $script:nx++; script:DohNxdomain }
        $o = ''
        $r = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o        | Should -Be 'NoRecord'
        $r.Count  | Should -Be 0
        $script:nx | Should -Be 1 -Because 'NXDOMAIN is a real answer; asking a second resolver wastes a round trip'
    }

    It 'reports NoRecord on NODATA (name exists, no record of this type)' {
        Mock Invoke-RestMethod { script:DohNodata }
        $o = ''
        $null = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o | Should -Be 'NoRecord'
    }

    It 'reports NoRecord when the Answer holds no record of the requested type' {
        # A CNAME-only chain: a real answer, just not the type asked for.
        Mock Invoke-RestMethod { script:DohAnswer 'alias.example.net.' 5 }
        $o = ''
        $r = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o       | Should -Be 'NoRecord'
        $r.Count | Should -Be 0
    }

    It 'reports Answered and returns the record on success' {
        Mock Invoke-RestMethod { script:DohAnswer '"v=DMARC1; p=reject; pct=100"' }
        $o = ''
        $r = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o    | Should -Be 'Answered'
        $r[0] | Should -Be 'v=DMARC1; p=reject; pct=100'
    }
}

Describe 'Resolve-NRGDns — TXT assembly' {

    It 'joins a TXT record split across multiple character-strings' {
        # DNS splits any TXT string over 255 bytes, and long SPF/DMARC records
        # routinely are. Reading only the first segment would drop the tags
        # that decide the verdict.
        Mock Invoke-RestMethod {
            script:DohAnswer '"v=DMARC1; p=reject; rua=mailto:a@example.com" "; pct=100; fo=1"'
        }
        $o = ''
        $r = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $r[0] | Should -Be 'v=DMARC1; p=reject; rua=mailto:a@example.com; pct=100; fo=1'
        $r[0] | Should -Match 'pct=100' -Because 'the tag deciding Satisfied vs Partial lives in the second segment'
    }

    It 'handles an unquoted TXT payload' {
        Mock Invoke-RestMethod { script:DohAnswer 'v=spf1 include:spf.protection.outlook.com -all' }
        $o = ''
        $r = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $r[0] | Should -Be 'v=spf1 include:spf.protection.outlook.com -all'
    }
}

Describe 'Resolve-NRGDns — the optional-outcome contract' {

    It 'works unchanged when no -Outcome is supplied' {
        # Every existing call site omits it; none may change behaviour.
        Mock Invoke-RestMethod { script:DohAnswer '"v=spf1 -all"' }
        $r = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT')
        $r[0] | Should -Be 'v=spf1 -all'
    }

    It 'returns an empty array, not $null, on failure' {
        # Callers do @(Resolve-NRGDns ...).Count; $null would count as 1.
        Mock Invoke-RestMethod { script:DohServfail }
        $r = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT')
        $r.Count | Should -Be 0
    }
}

Describe 'Resolve-NRGDns — the Resolve-DnsName fallback reads the Win32 DNS code' {

    # Resolve-DnsName does not exist on Linux, so a stand-in is defined for
    # these tests. On Windows a function shadows the real cmdlet for the
    # duration of the block. Every DoH call is made to throw so the fallback
    # is reached.
    BeforeAll {
        function global:Resolve-DnsName { param($Name, $Type, $Server, [switch] $DnsOnly, $ErrorAction) throw 'stub not configured' }
    }
    AfterAll { Remove-Item -LiteralPath 'Function:\global:Resolve-DnsName' -ErrorAction SilentlyContinue }
    BeforeEach { Mock Invoke-RestMethod { throw 'DoH blocked on this network' } }

    It 'maps Win32 9003 (DNS_ERROR_RCODE_NAME_ERROR, NXDOMAIN) to NoRecord' {
        # The first draft mapped EVERY throw to LookupFailed. On a workstation
        # where DoH is blocked that meant no DNS control could ever report a
        # Gap: every genuine absence became NotApplicable, excluded from the
        # denominator, and a tenant's missing DMARC was never surfaced.
        function global:Resolve-DnsName { throw [System.ComponentModel.Win32Exception]::new(9003) }
        $o = ''
        $r = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o       | Should -Be 'NoRecord'
        $r.Count | Should -Be 0
    }

    It 'maps Win32 9501 (DNS_INFO_NO_RECORDS, NODATA) to NoRecord' {
        function global:Resolve-DnsName { throw [System.ComponentModel.Win32Exception]::new(9501) }
        $o = ''
        $null = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o | Should -Be 'NoRecord'
    }

    It 'maps Win32 9002 (SERVFAIL) to LookupFailed, with the code in -Reason' {
        function global:Resolve-DnsName { throw [System.ComponentModel.Win32Exception]::new(9002) }
        $o = ''; $why = ''
        $null = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o) -Reason ([ref]$why))
        $o   | Should -Be 'LookupFailed'
        $why | Should -Match 'Win32 9002'
    }

    It 'maps a timeout (Win32 1460) to LookupFailed' {
        function global:Resolve-DnsName { throw [System.ComponentModel.Win32Exception]::new(1460) }
        $o = ''
        $null = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o | Should -Be 'LookupFailed'
    }

    It 'reads the Win32 code off an inner exception' {
        function global:Resolve-DnsName {
            throw [System.InvalidOperationException]::new('wrapped', [System.ComponentModel.Win32Exception]::new(9003))
        }
        $o = ''
        $null = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o | Should -Be 'NoRecord'
    }

    It 'falls back to the error text when no Win32 code is present' {
        function global:Resolve-DnsName { throw 'example.com : DNS name does not exist (DNS_ERROR_RCODE_NAME_ERROR)' }
        $o = ''
        $null = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o | Should -Be 'NoRecord'
    }

    It 'maps an unreadable plain exception to LookupFailed, never NoRecord' {
        function global:Resolve-DnsName { throw 'something went wrong' }
        $o = ''
        $null = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o | Should -Be 'LookupFailed'
    }

    It 'returns Answered with the record when the fallback resolves' {
        function global:Resolve-DnsName { [pscustomobject]@{ Strings = @('v=spf1 include:x', ' -all') } }
        $o = ''
        $r = @(Resolve-NRGDns -Name 'example.com' -Type 'TXT' -Outcome ([ref]$o))
        $o    | Should -Be 'Answered'
        $r[0] | Should -Be 'v=spf1 include:x -all'
    }
}

Describe 'DNS evaluators — a failed lookup never scores as an absent record' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function script:DnsFixture {
            param([hashtable] $DomainEntry)
            Clear-NRGState
            Set-NRGRawData -Key 'DNS-EmailRecords' -Data ([ordered]@{
                CollectorId = 'DNS'; CollectedAt = '2026-09-17T00:00:00Z'; Success = $true
                Data = @{ DomainCount = 1; Domains = @{ 'example.com' = $DomainEntry } }
            })
        }
        function script:Verdict {
            param([string] $Evaluator, [string] $ControlId)
            & $Evaluator *>$null
            $f = @(Get-NRGFindings | Where-Object { $_.ControlId -eq $ControlId })[0]
            if ($f) { [string]$f.State } else { '(none)' }
        }
        # A domain with nothing configured. LookupStatus decides whether that
        # absence is a finding or an unknown.
        function script:BareDomain {
            param([hashtable] $LookupStatus, [switch] $NoLookupStatus)
            $entry = @{
                Domain = 'example.com'; SPF = $null; DMARC = $null; TLSRPT = $null
                DNSSEC = $false; MX = @(); Errors = @()
                MTASTS = @{ DNSRecord = $null; Policy = $null; Mode = $null }
                CAA    = @{ Present = $false; Records = @(); IssuanceAllowed = @(); WildcardAllowed = @(); IodefContact = @() }
                DKIM   = @{ Selector1 = $null; Selector2 = $null; CustomSelectors = @() }
            }
            # -NoLookupStatus omits the KEY, which is the pre-change result-JSON
            # shape. Passing @{} is a different branch (present-but-empty map)
            # and the first version of the replay test passed that, exercising
            # the wrong path while claiming to pin replay compatibility.
            if (-not $NoLookupStatus) { $entry.LookupStatus = $LookupStatus }
            $entry
        }
    }

    AfterAll { Clear-NRGState }

    # Every evaluator that scores an ABSENT record as a Gap. All seven, so a
    # future edit that drops the gate from one of them fails here.
    $cases = @(
        @{ Record = 'SPF';    Evaluator = 'Test-NRGControlDNSSPF';    ControlId = 'DNS-1.1' }
        @{ Record = 'DKIM';   Evaluator = 'Test-NRGControlDNSDKIM';   ControlId = 'DNS-1.2' }
        @{ Record = 'DMARC';  Evaluator = 'Test-NRGControlDNSDMARC';  ControlId = 'DNS-1.3' }
        @{ Record = 'MTASTS'; Evaluator = 'Test-NRGControlDNSMTASTS'; ControlId = 'DNS-1.4' }
        @{ Record = 'TLSRPT'; Evaluator = 'Test-NRGControlDNSTLSRPT'; ControlId = 'DNS-1.5' }
        @{ Record = 'DNSSEC'; Evaluator = 'Test-NRGControlDNSDNSSEC'; ControlId = 'DNS-1.6' }
        @{ Record = 'CAA';    Evaluator = 'Test-NRGControlDNSCAA';    ControlId = 'DNS-2.2' }
    )

    It 'reports NotApplicable, not Gap, when the <Record> lookup failed' -ForEach $cases {
        script:DnsFixture (script:BareDomain @{ $Record = 'LookupFailed' })
        script:Verdict $Evaluator $ControlId | Should -Be 'NotApplicable' `
            -Because 'a resolver failure is not evidence the record is missing'
    }

    It 'still reports Gap for <Record> when the lookup succeeded and found nothing' -ForEach $cases {
        # The fix must not suppress real findings: a domain genuinely without
        # SPF is exactly what this control exists to catch.
        script:DnsFixture (script:BareDomain @{ $Record = 'NoRecord' })
        script:Verdict $Evaluator $ControlId | Should -Be 'Gap' `
            -Because 'NoRecord is a real answer and an absent record is a real finding'
    }

    It 'treats result JSON with no LookupStatus key as collected (<Record>)' -ForEach $cases {
        # Replay compatibility, same rule SectionStatus uses. The key is ABSENT
        # here, not an empty map — that is the shape older results files have.
        script:DnsFixture (script:BareDomain -NoLookupStatus)
        script:Verdict $Evaluator $ControlId | Should -Be 'Gap'
    }

    It 'the lookup-failed finding carries the control citations (<Record>)' -ForEach $cases {
        # Without -FrameworkIds the finding has no NIST citation, the family
        # rollup drops it as unmapped, and it never reaches the NIST matrix's
        # "Not Assessed" sheet — the reader sees neither a verdict nor a row.
        script:DnsFixture (script:BareDomain @{ $Record = 'LookupFailed' })
        & $Evaluator *>$null
        $f = @(Get-NRGFindings | Where-Object { $_.ControlId -eq $ControlId })[0]
        $f.State | Should -Be 'NotApplicable'
        @($f.FrameworkIds).Count | Should -BeGreaterThan 0 -Because 'an uncited NotApplicable vanishes from the 800-53 rollup'
        $f.Severity | Should -Be 'Informational'
    }

    It 'the lookup-failed finding surfaces the collector reason when one was recorded' {
        $entry = script:BareDomain @{ SPF = 'LookupFailed' }
        $entry.Errors = @('SPF: lookup did not complete — cloudflare-dns.com: Status 2; dns.google: Status 2')
        script:DnsFixture $entry
        Test-NRGControlDNSSPF *>$null
        $f = @(Get-NRGFindings | Where-Object { $_.ControlId -eq 'DNS-1.1' })[0]
        $f.Detail | Should -Match 'Status 2'
    }

    It 'still reports Satisfied on a correctly configured domain' {
        script:DnsFixture @{
            Domain = 'example.com'
            SPF    = 'v=spf1 include:spf.protection.outlook.com -all'
            DMARC  = 'v=DMARC1; p=reject; pct=100'
            DMARCPolicy = 'reject'; DMARCPct = 100; DMARCSubPolicy = $null
            TLSRPT = 'v=TLSRPTv1; rua=mailto:a@example.com'
            DNSSEC = $true; MX = @()
            LookupStatus = @{ SPF='Answered'; DMARC='Answered'; MTASTS='Answered'; TLSRPT='Answered'; DNSSEC='Answered'; CAA='Answered' }
            MTASTS = @{ DNSRecord = 'v=STSv1; id=1'; Policy = 'mode: enforce'; Mode = 'enforce' }
            CAA    = @{ Present = $true; Records = @(); IssuanceAllowed = @('digicert.com'); WildcardAllowed = @(); IodefContact = @() }
            DKIM   = @{ Selector1 = $null; Selector2 = $null; CustomSelectors = @() }
        }
        script:Verdict 'Test-NRGControlDNSSPF'   'DNS-1.1' | Should -Be 'Satisfied'
        Clear-NRGState
        script:DnsFixture @{
            Domain = 'example.com'; SPF = 'v=spf1 -all'
            DMARC = 'v=DMARC1; p=reject; pct=100'; DMARCPolicy = 'reject'; DMARCPct = 100; DMARCSubPolicy = $null
            TLSRPT = $null; DNSSEC = $false; MX = @()
            LookupStatus = @{ DMARC = 'Answered' }
            MTASTS = @{ DNSRecord = $null; Policy = $null; Mode = $null }
            CAA    = @{ Present = $false; Records = @(); IssuanceAllowed = @(); WildcardAllowed = @(); IodefContact = @() }
            DKIM   = @{ Selector1 = $null; Selector2 = $null; CustomSelectors = @() }
        }
        script:Verdict 'Test-NRGControlDNSDMARC' 'DNS-1.3' | Should -Be 'Satisfied'
    }
}
