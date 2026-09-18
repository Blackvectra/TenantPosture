#Requires -Version 7.0
#
# NRG.DnsCollector.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Drives Invoke-NRGCollectDNSEmailRecords through a mocked resolver and pins
# what the COLLECTOR does with the resolver's tri-state — the half of the DNS
# fix that NRG.DnsResolution.Tests.ps1 (resolver + evaluators) never touched.
#
# Independent verification of the DNS fix found three collector defects that
# the resolver and evaluator tests could not see, because no test exercised
# the collector at all:
#
#   1. 'Failed' coverage was unreachable for a single-domain tenant. The
#      per-domain entry list was built with `$x = if (...) { @(...) }`, an
#      if-statement unrolls the array it yields, and the lone hashtable's
#      .Count was its KEY count — so every-lookup-failed reported Partial on
#      the most common tenant shape.
#   2. The throw path was silent: five per-record catches were empty and the
#      other three never registered an exception, so the coverage note's
#      "see Exceptions" pointed at an empty array.
#   3. The lookup outcome was written unvalidated, so a blank outcome would
#      have replaced the fail-closed default and opened the evaluator gate.
#
# The mock is injected INTO the module scope (Set-Item function:script:) so
# the collector's own call resolves to it; a test-scope Mock would not be
# seen from inside the module. Network probes (MTA-STS policy fetch, TLS,
# crt.sh) are disabled the same way.

Describe 'Invoke-NRGCollectDNSEmailRecords — what the collector does with the resolver outcome' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'

        # Install a function into the module's script scope.
        $script:Inject = {
            param([string] $Name, [string] $Body)
            & $script:Mod { param($n, $b) Set-Item -Path "function:script:$n" -Value ([scriptblock]::Create($b)) } $Name $Body
        }

        # The resolver stand-in reads the module-scoped $script:DnsProbeScenario
        # on every call; the scenario is set into module scope the same way the
        # stand-in is, so nothing leaks into the caller's session.
        & $script:Inject 'Resolve-NRGDns' @'
            [CmdletBinding()]
            param([string] $Name, [string] $Type, [int] $TimeoutSeconds = 6, [ref] $Outcome, [ref] $Reason)
            $set = { param($o, $r) if ($null -ne $Outcome) { $Outcome.Value = $o }; if ($null -ne $Reason) { $Reason.Value = $r } }
            switch ($script:DnsProbeScenario) {
                'AllFail'          { & $set 'LookupFailed' 'cloudflare-dns.com: Status 2; dns.google: Status 2'; return @() }
                'AllNoRecord'      { & $set 'NoRecord' ''; return @() }
                'DmarcThrows'      { if ($Name -like '_dmarc.*') { throw 'resolver exploded' }; & $set 'NoRecord' ''; return @() }
                'TlsRptThrows'     { if ($Name -like '_smtp._tls.*') { throw 'resolver exploded' }; & $set 'NoRecord' ''; return @() }
                'DkimThrows'       { if ($Name -like 'selector2._domainkey.*') { throw 'resolver exploded' }; & $set 'NoRecord' ''; return @() }
                'NeverSetsOutcome' { return @() }
                'BogusOutcome'     { & $set 'Maybe' ''; return @() }
                'DkimSel1AnsweredSel2Fails' {
                    if ($Name -like 'selector1._domainkey.*' -and $Type -eq 'CNAME') { & $set 'Answered' ''; return @('s1._domainkey.t.onmicrosoft.com.') }
                    if ($Name -like 'selector2._domainkey.*') { & $set 'LookupFailed' 'cloudflare-dns.com: Status 2'; return @() }
                    & $set 'NoRecord' ''; return @() }
                'DkimTxtAnsweredNoKey' {
                    # A TXT answer that carries no DKIM key is still an ANSWER.
                    if ($Name -like '*._domainkey.*' -and $Type -eq 'TXT') { & $set 'Answered' ''; return @('some unrelated txt') }
                    & $set 'NoRecord' ''; return @() }
                'SecondDomainFails' {
                    if ($Name -like '*second.test*') { & $set 'LookupFailed' 'x'; return @() }
                    & $set 'NoRecord' ''; return @() }
                default            { throw "scenario not configured: $($script:DnsProbeScenario)" }
            }
'@
        & $script:Inject 'Test-NRGSafeProbeTarget' 'param([string] $HostName) return @{ Refused = $true; Reason = "probe disabled in test" }'
        & $script:Inject 'Invoke-WebRequest' 'throw "no network in test"'

        function script:Run {
            param([string] $Scenario, [string[]] $Domains = @('first.test'))
            & $script:Mod { param($s) $script:DnsProbeScenario = $s } $Scenario
            Clear-NRGState
            $r = Invoke-NRGCollectDNSEmailRecords -Domains $Domains 3>$null
            [pscustomobject]@{
                Result     = $r
                Domain     = $r.Data.Domains[$Domains[0]]
                Coverage   = (Get-NRGCoverage)['DNS-EmailRecords']
                Exceptions = @(Get-NRGExceptions | Where-Object { $_.Source -eq 'DNS-Resolve' })
            }
        }
        $script:Gated = @('SPF', 'DKIM', 'DMARC', 'MTASTS', 'TLSRPT', 'DNSSEC', 'CAA')
    }

    AfterAll {
        Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue
    }

    Context 'coverage status' {

        It 'registers Failed, not Partial, when every gated lookup fails on a SINGLE-domain tenant' {
            # The if-block assignment trap: previously Partial here, Failed
            # only from two domains up.
            $o = Run 'AllFail'
            $o.Coverage.Status | Should -Be 'Failed'
            $o.Coverage.Note   | Should -Match 'did not complete on 1'
        }

        It 'registers Failed when every gated lookup fails on every one of several domains' {
            $o = Run 'AllFail' @('first.test', 'second.test')
            $o.Coverage.Status | Should -Be 'Failed'
        }

        It 'registers Partial when one of two domains fails' {
            $o = Run 'SecondDomainFails' @('first.test', 'second.test')
            $o.Coverage.Status | Should -Be 'Partial'
            $o.Coverage.Note   | Should -Match 'did not complete on 1'
        }

        It 'registers Collected when every lookup answered' {
            $o = Run 'AllNoRecord'
            $o.Coverage.Status | Should -Be 'Collected'
            foreach ($k in $script:Gated) { $o.Domain.LookupStatus[$k] | Should -Be 'NoRecord' -Because $k }
        }
    }

    Context 'the throw path is recorded, not swallowed' {

        It 'records a DMARC throw in Errors AND the Exceptions array, and leaves the gate closed' {
            $o = Run 'DmarcThrows'
            $o.Domain.LookupStatus['DMARC']            | Should -Be 'LookupFailed'
            @($o.Domain.Errors -like 'DMARC:*').Count  | Should -Be 1
            @($o.Exceptions | Where-Object { $_.Message -like '*DMARC*resolver exploded*' }).Count | Should -Be 1
            Test-NRGDnsLookupSucceeded -Domain $o.Domain -Record 'DMARC' | Should -BeFalse
        }

        It 'records a TLS-RPT throw (previously an empty catch)' {
            $o = Run 'TlsRptThrows'
            $o.Domain.LookupStatus['TLSRPT']           | Should -Be 'LookupFailed'
            @($o.Domain.Errors -like 'TLSRPT:*').Count | Should -Be 1
            @($o.Exceptions | Where-Object { $_.Message -like '*TLSRPT*' }).Count | Should -Be 1
            $o.Coverage.Status | Should -Be 'Partial'
        }

        It 'records a DKIM selector throw and fails the DKIM verdict' {
            $o = Run 'DkimThrows'
            $o.Domain.LookupStatus['DKIM']                    | Should -Be 'LookupFailed'
            @($o.Domain.Errors -like 'DKIM selector2:*').Count | Should -Be 1
            @($o.Exceptions | Where-Object { $_.Message -like '*DKIM selector2*' }).Count | Should -Be 1
        }

        It 'records a resolver-reported failure with the resolver''s reason' {
            $o = Run 'AllFail'
            @($o.Domain.Errors -like 'SPF: lookup did not complete*Status 2*').Count | Should -Be 1
            @($o.Exceptions | Where-Object { $_.Message -like '[[]first.test[]] SPF:*Status 2*' }).Count | Should -Be 1
        }
    }

    Context 'the outcome is validated before it is written (fail closed)' {

        It 'keeps every gated key LookupFailed when the resolver never sets -Outcome' {
            # Test-NRGDnsLookupSucceeded reads a blank as collected (replay
            # rule), so writing '' would have opened the gate.
            $o = Run 'NeverSetsOutcome'
            foreach ($k in $script:Gated) {
                $o.Domain.LookupStatus[$k] | Should -Be 'LookupFailed' -Because $k
                Test-NRGDnsLookupSucceeded -Domain $o.Domain -Record $k | Should -BeFalse -Because $k
            }
            $o.Coverage.Status | Should -Be 'Failed'
        }

        It 'treats an unrecognised outcome string as LookupFailed and says so' {
            $o = Run 'BogusOutcome'
            $o.Domain.LookupStatus['SPF']  | Should -Be 'LookupFailed'
            $o.Domain.LookupStatus['DKIM'] | Should -Be 'LookupFailed'
            @($o.Domain.Errors -like "SPF:*unrecognised outcome 'Maybe'*").Count | Should -Be 1
        }
    }

    Context 'DKIM per-selector fold' {

        It 'fails the DKIM verdict when one selector answered and the other failed' {
            # One failed selector turns a genuine Satisfied into a false Partial.
            $o = Run 'DkimSel1AnsweredSel2Fails'
            $o.Domain.DKIM.Selector1         | Should -Be 's1._domainkey.t.onmicrosoft.com.'
            $o.Domain.LookupStatus['DKIM']   | Should -Be 'LookupFailed'
        }

        It 'reads a TXT answer with no DKIM key as NoRecord, not a failure' {
            $o = Run 'DkimTxtAnsweredNoKey'
            $o.Domain.LookupStatus['DKIM'] | Should -Be 'NoRecord'
            $o.Domain.DKIM.Selector1       | Should -BeNullOrEmpty
        }
    }
}
