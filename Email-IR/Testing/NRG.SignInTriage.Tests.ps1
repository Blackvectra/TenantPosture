#Requires -Version 7.0
#
# NRG.SignInTriage.Tests.ps1
#
# Pinned-behavior suite for the v4.12.0 admin-scope Sign-In Triage. Tests
# the IoC scoring + ranked-user aggregation against synthetic fixtures so
# a future refactor of the scoring weights can't silently change verdicts.

Describe 'NRG Sign-In Triage — IoC evaluators against synthetic fixtures' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Add-NRGFinding.ps1')
        . (Join-Path $script:RepoRoot 'Email-IR' 'Evaluators' 'Test-NRGSignInControls.ps1')

        function script:NewBag([string]$cid, $data) {
            [ordered]@{
                CollectorId = $cid
                CollectedAt = (Get-Date -Format 'o')
                Success     = $true
                Data        = $data
            }
        }
    }

    BeforeEach {
        Clear-NRGState
        Clear-NRGSignInTriageState
    }

    Context 'SIGNIN-1.1 Failed→Success cluster' {
        It 'Flags a credential-stuffing-succeeded cluster as Critical' {
            $base = (Get-Date).ToUniversalTime()
            $events = @()
            for ($i = 6; $i -ge 1; $i--) {
                $events += @{
                    userPrincipalName = 'alice@corp.com'
                    createdDateTime   = $base.AddMinutes(-$i).ToString('o')
                    ipAddress         = "203.0.113.$i"
                    status            = @{ errorCode = 50126 }   # password incorrect
                }
            }
            # Then the success
            $events += @{
                userPrincipalName = 'alice@corp.com'
                createdDateTime   = $base.AddMinutes(-0.5).ToString('o')
                ipAddress         = '203.0.113.99'
                status            = @{ errorCode = 0 }
            }
            Set-NRGRawData -Key 'IR-SignIn-Recent' -Data (NewBag 'IR-SignIn-Recent' @{
                WindowDays = 7
                Cutoff     = $base.AddDays(-7).ToString('o')
                Count      = $events.Count
                Events     = $events
            })

            Test-NRGSignInControl-FailedToSuccess
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'SIGNIN-1.1')
            $f.Count        | Should -Be 1
            $f[0].State     | Should -Be 'Gap'
            $f[0].Severity  | Should -Be 'Critical'
            $f[0].Detail    | Should -Match 'alice@corp.com'
            $f[0].Detail    | Should -Match '6 fails'
        }

        It 'Does not flag legitimate single login' {
            $base = (Get-Date).ToUniversalTime()
            $events = @(
                @{ userPrincipalName='bob@corp.com'; createdDateTime=$base.ToString('o'); ipAddress='198.51.100.1'; status=@{ errorCode = 0 } }
            )
            Set-NRGRawData -Key 'IR-SignIn-Recent' -Data (NewBag 'IR-SignIn-Recent' @{
                WindowDays = 7
                Cutoff     = $base.AddDays(-7).ToString('o')
                Count      = 1
                Events     = $events
            })
            Test-NRGSignInControl-FailedToSuccess
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'SIGNIN-1.1')
            $f[0].State | Should -Be 'Satisfied'
        }
    }

    Context 'SIGNIN-1.2 Anonymous-IP' {
        It 'Flags successful anon-IP sign-in as Critical' {
            $events = @(
                @{ userPrincipalName='carol@corp.com'; createdDateTime=(Get-Date).ToString('o'); ipAddress='185.220.101.1'; status=@{ errorCode = 0 }; riskEventTypes_v2=@('anonymizedIPAddress') }
            )
            Set-NRGRawData -Key 'IR-SignIn-AnonIp' -Data (NewBag 'IR-SignIn-AnonIp' @{
                Count = 1; Events = $events
            })
            Test-NRGSignInControl-AnonymousIp
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'SIGNIN-1.2')
            $f.Count       | Should -Be 1
            $f[0].State    | Should -Be 'Gap'
            $f[0].Severity | Should -Be 'Critical'
            $f[0].Detail   | Should -Match 'carol@corp.com'
        }
    }

    Context 'SIGNIN-1.4 Identity Protection risky users' {
        It 'Scores high-risk user with 50 points' {
            $users = @(
                @{ userPrincipalName='dave@corp.com'; userDisplayName='Dave'; riskLevel='high'; riskState='atRisk'; riskLastUpdatedDateTime=(Get-Date).ToString('o') }
            )
            Set-NRGRawData -Key 'IR-SignIn-RiskyUsers' -Data (NewBag 'IR-SignIn-RiskyUsers' @{
                Count = 1; Users = $users
            })
            Test-NRGSignInControl-RiskyUsers
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'SIGNIN-1.4')
            $f[0].State    | Should -Be 'Gap'
            $f[0].Severity | Should -Be 'High'
        }
    }

    Context 'SIGNIN-2.1 Rank aggregator' {
        It 'Ranks users by accumulated IoC score' {
            # alice: failed→success cluster only (60 pts)
            # bob:   anon-IP success + risky user (50 + 50 = 100 pts)
            # No collector data; we drive the aggregator directly via Add-NRGSignInScore.
            # Since Add-NRGSignInScore is script-scoped, we exercise it through
            # the public evaluators with minimal fixtures.

            # alice — failed→success
            $base = (Get-Date).ToUniversalTime()
            $aliceEvents = @()
            for ($i=6; $i -ge 1; $i--) {
                $aliceEvents += @{ userPrincipalName='alice@corp.com'; createdDateTime=$base.AddMinutes(-$i).ToString('o'); ipAddress="203.0.113.$i"; status=@{errorCode=50126} }
            }
            $aliceEvents += @{ userPrincipalName='alice@corp.com'; createdDateTime=$base.ToString('o'); ipAddress='203.0.113.99'; status=@{errorCode=0} }
            Set-NRGRawData -Key 'IR-SignIn-Recent' -Data (NewBag 'r' @{ WindowDays=7; Cutoff=$base.AddDays(-7).ToString('o'); Count=$aliceEvents.Count; Events=$aliceEvents })
            Test-NRGSignInControl-FailedToSuccess

            # bob — anon-IP success + risky user
            Set-NRGRawData -Key 'IR-SignIn-AnonIp' -Data (NewBag 'a' @{ Count=1; Events=@(
                @{ userPrincipalName='bob@corp.com'; createdDateTime=$base.ToString('o'); ipAddress='185.220.101.1'; status=@{errorCode=0}; riskEventTypes_v2=@('anonymizedIPAddress') }
            ) })
            Test-NRGSignInControl-AnonymousIp
            Set-NRGRawData -Key 'IR-SignIn-RiskyUsers' -Data (NewBag 'ru' @{ Count=1; Users=@(
                @{ userPrincipalName='bob@corp.com'; userDisplayName='Bob'; riskLevel='high'; riskState='atRisk'; riskLastUpdatedDateTime=$base.ToString('o') }
            ) })
            Test-NRGSignInControl-RiskyUsers

            # Rank
            Test-NRGSignInControl-RankUsers
            $rank = (Get-NRGRawData -Key 'IR-SignIn-Ranked').Data.Users
            $rank[0].UserPrincipalName | Should -Be 'bob@corp.com'
            $rank[0].Score            | Should -BeGreaterOrEqual 100
            $rank[1].UserPrincipalName | Should -Be 'alice@corp.com'
            $rank[1].Score            | Should -BeGreaterOrEqual 60
        }
    }

    Context 'Defensive — no data' {
        It 'NotApplicable when sign-in collection did not succeed' {
            Test-NRGSignInControl-FailedToSuccess
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'SIGNIN-1.1')
            $f[0].State | Should -Be 'NotApplicable'
        }
    }
}

Describe 'NRG Sign-In Triage — Geo-anomaly (SIGNIN-1.6)' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Add-NRGFinding.ps1')
        . (Join-Path $script:RepoRoot 'Email-IR' 'Evaluators' 'Test-NRGSignInControls.ps1')
        function script:NewBag($cid, $data) { [ordered]@{ CollectorId=$cid; CollectedAt=(Get-Date -Format 'o'); Success=$true; Data=$data } }
        function script:GeoEvents {
            $base=(Get-Date).ToUniversalTime()
            $e=@()
            1..8 | ForEach-Object { $e += @{ userPrincipalName="user$_@corp.com"; createdDateTime=$base.AddHours(-$_).ToString('o'); ipAddress="1.2.3.$_"; status=@{errorCode=0}; location=@{city='Fargo';state='North Dakota';countryOrRegion='US'} } }
            $e += @{ userPrincipalName='alice@corp.com'; createdDateTime=$base.ToString('o'); ipAddress='5.6.7.8'; status=@{errorCode=0}; location=@{city='Houston';state='Texas';countryOrRegion='US'} }
            $e += @{ userPrincipalName='bob@corp.com'; createdDateTime=$base.ToString('o'); ipAddress='9.9.9.9'; status=@{errorCode=0}; location=@{city='Moscow';state='Moscow';countryOrRegion='RU'} }
            $e
        }
    }
    BeforeEach { Clear-NRGState; Clear-NRGSignInTriageState }

    It 'Auto-detects the modal home state and flags out-of-state + foreign' {
        $ev = GeoEvents
        Set-NRGRawData -Key 'IR-SignIn-Recent' -Data (NewBag 'r' @{ WindowDays=7; Cutoff=(Get-Date).AddDays(-7).ToString('o'); Count=$ev.Count; Events=$ev })
        Test-NRGSignInControl-GeoAnomaly
        $f = @(Get-NRGFindings | Where-Object ControlId -eq 'SIGNIN-1.6')
        $f[0].State    | Should -Be 'Gap'
        $f[0].Severity | Should -Be 'Critical'
        $f[0].Detail   | Should -Match 'north dakota'
        $f[0].Detail   | Should -Match 'alice@corp.com'
        $f[0].Detail   | Should -Match 'foreign-country'
    }

    It 'Scores foreign-country (55) higher than out-of-state (35); failed-only not scored' {
        $base=(Get-Date).ToUniversalTime()
        $ev = GeoEvents
        $ev += @{ userPrincipalName='carol@corp.com'; createdDateTime=$base.ToString('o'); ipAddress='5.5.5.5'; status=@{errorCode=50126}; location=@{city='Dallas';state='Texas';countryOrRegion='US'} }
        Set-NRGRawData -Key 'IR-SignIn-Recent' -Data (NewBag 'r' @{ WindowDays=7; Cutoff=$base.AddDays(-7).ToString('o'); Count=$ev.Count; Events=$ev })
        Test-NRGSignInControl-GeoAnomaly
        Test-NRGSignInControl-RankUsers
        $rank = (Get-NRGRawData -Key 'IR-SignIn-Ranked').Data.Users
        $bob = ($rank | Where-Object UserPrincipalName -eq 'bob@corp.com').Score
        $alice = ($rank | Where-Object UserPrincipalName -eq 'alice@corp.com').Score
        $bob   | Should -BeGreaterOrEqual 55
        $alice | Should -BeGreaterOrEqual 35
        $bob   | Should -BeGreaterThan $alice
        @($rank | Where-Object UserPrincipalName -eq 'carol@corp.com') | Should -BeNullOrEmpty
    }

    It 'Honors -HomeState override' {
        $ev = GeoEvents
        Set-NRGRawData -Key 'IR-SignIn-Recent' -Data (NewBag 'r' @{ WindowDays=7; Cutoff=(Get-Date).AddDays(-7).ToString('o'); Count=$ev.Count; Events=$ev })
        Test-NRGSignInControl-GeoAnomaly -HomeState 'Texas' -HomeCountry 'US'
        $f = @(Get-NRGFindings | Where-Object ControlId -eq 'SIGNIN-1.6')
        $f[0].Detail | Should -Match 'texas'
        $f[0].Detail | Should -Match 'North Dakota'   # ND users now the anomalies
    }

    It 'NotApplicable when events carry no location' {
        Set-NRGRawData -Key 'IR-SignIn-Recent' -Data (NewBag 'r' @{ WindowDays=7; Cutoff=(Get-Date).AddDays(-7).ToString('o'); Count=1; Events=@(@{ userPrincipalName='x@corp.com'; createdDateTime=(Get-Date).ToString('o'); ipAddress='1.1.1.1'; status=@{errorCode=0} }) })
        Test-NRGSignInControl-GeoAnomaly
        $f = @(Get-NRGFindings | Where-Object ControlId -eq 'SIGNIN-1.6')
        $f[0].State | Should -Be 'NotApplicable'
    }
}
