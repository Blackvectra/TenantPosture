#Requires -Version 7.0
#
# NRG.DkimRotation.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# DNS-2.1 must say, for every domain, when its DKIM key was last rotated.
# The 10-02 run on a real tenant reported only "3906 days old" for a key
# created 2016-01-22, and never read the n= creation timestamp Microsoft
# publishes in the key behind each selector CNAME, which is the independent
# check on Exchange's KeyCreationTime (the two agreed to the second on that
# tenant). These tests drive the real collector through a mocked resolver
# and the real evaluator, with raw API shapes: Exchange's KeyCreationTime
# string, a CNAME answer and a DKIM TXT record carrying n= and a real key.

Describe 'DKIM key rotation date (DNS-2.1)' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'

        $script:Inject = {
            param([string] $Name, [string] $Body)
            & $script:Mod { param($n, $b) Set-Item -Path "function:script:$n" -Value ([scriptblock]::Create($b)) } $Name $Body
        }

        $rsa = [System.Security.Cryptography.RSA]::Create(1024)
        $script:Key1024 = [Convert]::ToBase64String($rsa.ExportSubjectPublicKeyInfo())
        $rsa.Dispose()
        # 1453492002 = 2016-01-22T19:46:42Z, the value seen on the real tenant.
        $script:Txt = "v=DKIM1; k=rsa; p=$($script:Key1024); n=1453492002"

        & $script:Mod { param($t) $script:DkimTestTxt = $t } $script:Txt
        & $script:Inject 'Resolve-NRGDns' @'
            [CmdletBinding()]
            param([string] $Name, [string] $Type, [int] $TimeoutSeconds = 6, [ref] $Outcome, [ref] $Reason)
            $set = { param($o) if ($null -ne $Outcome) { $Outcome.Value = $o }; if ($null -ne $Reason) { $Reason.Value = '' } }
            if ($Name -eq 'selector1._domainkey.first.test' -and $Type -eq 'CNAME') { & $set 'Answered'; return @('selector1-first-test._domainkey.tenant.onmicrosoft.com.') }
            if ($Name -eq 'selector2._domainkey.first.test' -and $Type -eq 'CNAME') { & $set 'Answered'; return @('selector2-first-test._domainkey.tenant.onmicrosoft.com.') }
            # The active key is published; the inactive selector's target is gone.
            if ($Name -eq 'selector1-first-test._domainkey.tenant.onmicrosoft.com' -and $Type -eq 'TXT') { & $set 'Answered'; return @($script:DkimTestTxt) }
            & $set 'NoRecord'; return @()
'@
        & $script:Inject 'Test-NRGSafeProbeTarget' 'param([string] $HostName) return @{ Refused = $true; Reason = "probe disabled in test" }'
        & $script:Inject 'Invoke-WebRequest' 'throw "no network in test"'

        function script:Collect {
            param([string] $KeyCreationTime = '01/22/2016 19:46:42')
            Clear-NRGState
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data @{
                CollectorId = 'EXO-MailboxConfig'; Success = $true
                Data = @{ DkimSigningConfigs = @(@{
                    Domain = 'first.test'; Enabled = $true; Status = 'Valid'
                    Selector1KeySize = 1024; Selector2KeySize = 1024
                    KeyCreationTime = $KeyCreationTime; RotateOnDate = $KeyCreationTime
                    SelectorAfterRotateOnDate = 'Selector1'
                }) }
            }
            $r = Invoke-NRGCollectDNSEmailRecords -Domains @('first.test') 3>$null
            Set-NRGRawData -Key 'DNS-EmailRecords' -Data $r
            $r.Data.Domains['first.test']
        }
        function script:Verdict {
            Test-NRGControlDNSDkimRotation
            @(Get-NRGFindings | Where-Object { $_.ControlId -eq 'DNS-2.1' })[0]
        }
    }

    AfterAll {
        Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue
    }

    It 'the collector records the rotation date, key sizes and the active selector from Exchange' {
        $d = Collect
        $d.DKIM.LastRotated      | Should -Be '2016-01-22'
        $d.DKIM.KeyAgeDays       | Should -BeGreaterThan 3000
        $d.DKIM.Selector1KeySize | Should -Be 1024
        $d.DKIM.ActiveSelector   | Should -Be 'Selector1'
        $d.DKIM.RotationStatus   | Should -Be 'Overdue'
    }

    It 'the collector reads the published key: its n= creation date and key size, and an absent inactive key is no error' {
        $d = Collect
        $k1 = @($d.DKIM.KeyRecords | Where-Object { $_.Selector -eq 'selector1' })[0]
        $k1.Lookup     | Should -Be 'Answered'
        $k1.KeyCreated | Should -Be '2016-01-22'
        $k1.KeyBits    | Should -Be 1024
        $k2 = @($d.DKIM.KeyRecords | Where-Object { $_.Selector -eq 'selector2' })[0]
        $k2.Lookup     | Should -Be 'NoRecord'
        $d.LookupStatus['DKIM'] | Should -Be 'Answered' -Because 'the published-key read is informational and never gates DKIM'
        @($d.Errors | Where-Object { $_ -match 'DKIM' }) | Should -BeNullOrEmpty
    }

    It 'the finding states the date the key was last rotated, not only an age' {
        Collect | Out-Null
        $f = Verdict
        $f.State        | Should -Be 'Gap'
        $f.Detail       | Should -Match '^first\.test DKIM key last rotated 2016-01-22 \(\d+ days ago\)'
        $f.CurrentValue | Should -Match '^Last rotated 2016-01-22 \(\d+ days\)$'
        $f.Detail       | Should -Match 'Key sizes: selector1 1024-bit, selector2 1024-bit\.'
        $f.Detail       | Should -Match 'Published selector1 key created 2016-01-22, 1024-bit \(DKIM n= timestamp\)\.'
        $f.Detail       | Should -Match 'normal for the inactive selector'
    }

    It 'does not attribute a 365-day cryptoperiod to NIST SP 800-57' {
        Collect -KeyCreationTime ([datetime]::UtcNow.AddDays(-30).ToString('MM/dd/yyyy HH:mm:ss', [cultureinfo]::InvariantCulture)) | Out-Null
        $f = Verdict
        $f.State  | Should -Be 'Satisfied'
        $f.Detail | Should -Match '365-day rotation interval this assessment uses'
        $f.Detail | Should -Not -Match 'recommended by NIST'
        $src = Get-Content (Join-Path $script:RepoRoot 'Evaluators/Test-NRGControlDNS.ps1') -Raw
        $src | Should -Not -Match '365-day cryptoperiod recommended by NIST'
    }

    It 'says when Exchange and the published key disagree on the date' {
        Collect -KeyCreationTime '12/10/2024 15:18:22' | Out-Null
        (Verdict).Detail | Should -Match 'differs from Exchange''s key creation date \(2024-12-10\)'
    }

    It 'falls back to the published key timestamp when Exchange gives no key creation time, and says so' {
        Collect -KeyCreationTime '' | Out-Null
        $f = Verdict
        $f.State  | Should -Be 'Gap'
        $f.Detail | Should -Match 'last rotated 2016-01-22 \(\d+ days ago, from the published key timestamp\)'
    }

    It 'reports the date as unknown, never a pass, when neither source has one' {
        Clear-NRGState
        Set-NRGRawData -Key 'DNS-EmailRecords' -Data @{
            Success = $true
            Data = @{ DomainCount = 1; Domains = @{ 'first.test' = @{ DKIM = @{ KeyAgeDays = $null; KeyRecords = @() } } } }
        }
        $f = Verdict
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Match 'last rotation date unknown'
        $f.CurrentValue | Should -Be 'Last rotated: unknown'
    }

    It 'replayed results without the new fields still reach the age verdict' {
        Clear-NRGState
        Set-NRGRawData -Key 'DNS-EmailRecords' -Data ([pscustomobject]@{
            Success = $true
            Data = [pscustomobject]@{ DomainCount = 1; Domains = @{ 'first.test' = [pscustomobject]@{ DKIM = [pscustomobject]@{ KeyAgeDays = 900 } } } }
        })
        $f = Verdict
        $f.State  | Should -Be 'Gap'
        $f.Detail | Should -Match '^first\.test DKIM key is 900 days old \(the rotation date is not in this results file\)'
        $f.CurrentValue | Should -Be 'Key age 900 days'
    }
}
