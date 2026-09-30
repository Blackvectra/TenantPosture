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
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
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
                ipAddress         = '203.0.113.3'   # one of the addresses that failed
                status            = @{ errorCode = 0 }
            }
            Set-NRGRawData -Key 'IR-SignIn-Recent' -Data (NewBag 'IR-SignIn-Recent' @{
                WindowDays = 7
                Cutoff     = $base.AddDays(-7).ToString('o')
                Count      = $events.Count
                Events     = $events
            })

            Test-NRGSignInControlFailedToSuccess
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'SIGNIN-1.1')
            $f.Count        | Should -Be 1
            $f[0].State     | Should -Be 'Gap'
            $f[0].Severity  | Should -Be 'Critical'
            $f[0].Detail    | Should -Match 'alice@corp.com'
            $f[0].Detail    | Should -Match '6 credential failures'
            $f[0].Detail    | Should -Match 'confidence High'
        }

        Context 'the correlation is graded, not declared' {
            BeforeAll {
                function script:Seq($upn, $failIps, $failCode, $successIp, [bool] $withStatus = $true) {
                    $base = (Get-Date).ToUniversalTime(); $ev = @(); $n = @($failIps).Count
                    for ($i = 0; $i -lt $n; $i++) {
                        $e = @{ userPrincipalName = $upn; createdDateTime = $base.AddMinutes(-($n - $i + 1)).ToString('o'); ipAddress = @($failIps)[$i] }
                        if ($withStatus) { $e.status = @{ errorCode = $failCode } }
                        $ev += $e
                    }
                    $s = @{ userPrincipalName = $upn; createdDateTime = $base.ToString('o'); ipAddress = $successIp }
                    if ($withStatus) { $s.status = @{ errorCode = 0 } }
                    $ev += $s
                    Set-NRGRawData -Key 'IR-SignIn-Recent' -Data (NewBag 'IR-SignIn-Recent' @{ WindowDays = 7; Count = $ev.Count; Events = $ev })
                    Test-NRGSignInControlFailedToSuccess
                    @(Get-NRGFindings | Where-Object ControlId -eq 'SIGNIN-1.1')[0]
                }
            }
            It 'failures from one place then a success from somewhere unrelated is Low confidence and says it may be a legitimate sign-in' {
                $f = Seq 'a@corp.com' @('203.0.113.5','203.0.113.5','203.0.113.5','203.0.113.5','203.0.113.5') 50126 '198.51.100.44'
                $f.State    | Should -Be 'Gap'
                $f.Severity | Should -Be 'Medium'
                $f.Detail   | Should -Match 'confidence Low'
                $f.Detail   | Should -Match 'unrelated legitimate sign-in'
                $script:NRGSignInUserScores['a@corp.com'].Points | Should -BeLessThan 60
            }
            It 'the success from an address that also failed is High confidence' {
                $f = Seq 'a@corp.com' @('203.0.113.5','203.0.113.5','203.0.113.5','203.0.113.5','203.0.113.5') 50126 '203.0.113.5'
                $f.Severity | Should -Be 'Critical'
                $f.Detail   | Should -Match 'confidence High'
            }
            It 'the same /24 network is Medium confidence' {
                $f = Seq 'a@corp.com' @('203.0.113.5','203.0.113.6','203.0.113.7','203.0.113.8','203.0.113.9') 50126 '203.0.113.200'
                $f.Severity | Should -Be 'High'
                $f.Detail   | Should -Match 'confidence Medium'
            }
            It 'a distributed pattern (failures from 3 or more addresses) is stated' {
                $f = Seq 'a@corp.com' @('203.0.113.5','198.51.100.6','192.0.2.7','203.0.113.5','198.51.100.6') 50126 '192.0.2.7'
                $f.Detail | Should -Match 'Failures came from 3 or more addresses'
            }
            It 'failures that are not credential guesses (MFA required) followed by a success are not a correlation' {
                $f = Seq 'a@corp.com' @('203.0.113.5','203.0.113.5','203.0.113.5','203.0.113.5','203.0.113.5') 50074 '203.0.113.5'
                $f.State | Should -Be 'Satisfied'
            }
            It 'events with no readable status are neither failures nor successes' {
                $f = Seq 'a@corp.com' @('203.0.113.5','203.0.113.5','203.0.113.5','203.0.113.5','203.0.113.5') 50126 '203.0.113.5' $false
                $f.State | Should -Be 'Satisfied'
            }
            It 'a clean result over a truncated read is not cleared' {
                $base = (Get-Date).ToUniversalTime()
                Set-NRGRawData -Key 'IR-SignIn-Recent' -Data (NewBag 'IR-SignIn-Recent' @{ WindowDays = 7; Count = 1; Truncated = $true; Events = @(
                    @{ userPrincipalName = 'bob@corp.com'; createdDateTime = $base.ToString('o'); ipAddress = '198.51.100.1'; status = @{ errorCode = 0 } }) })
                Test-NRGSignInControlFailedToSuccess
                $f = @(Get-NRGFindings | Where-Object ControlId -eq 'SIGNIN-1.1')[0]
                $f.State  | Should -Be 'NotApplicable'
                $f.Detail | Should -Match 'Not cleared'
            }
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
            Test-NRGSignInControlFailedToSuccess
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
            Test-NRGSignInControlAnonymousIp
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
            Test-NRGSignInControlRiskyUsers
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
            $aliceEvents += @{ userPrincipalName='alice@corp.com'; createdDateTime=$base.ToString('o'); ipAddress='203.0.113.3'; status=@{errorCode=0} }
            Set-NRGRawData -Key 'IR-SignIn-Recent' -Data (NewBag 'r' @{ WindowDays=7; Cutoff=$base.AddDays(-7).ToString('o'); Count=$aliceEvents.Count; Events=$aliceEvents })
            Test-NRGSignInControlFailedToSuccess

            # bob — anon-IP success + risky user
            Set-NRGRawData -Key 'IR-SignIn-AnonIp' -Data (NewBag 'a' @{ Count=1; Events=@(
                @{ userPrincipalName='bob@corp.com'; createdDateTime=$base.ToString('o'); ipAddress='185.220.101.1'; status=@{errorCode=0}; riskEventTypes_v2=@('anonymizedIPAddress') }
            ) })
            Test-NRGSignInControlAnonymousIp
            Set-NRGRawData -Key 'IR-SignIn-RiskyUsers' -Data (NewBag 'ru' @{ Count=1; Users=@(
                @{ userPrincipalName='bob@corp.com'; userDisplayName='Bob'; riskLevel='high'; riskState='atRisk'; riskLastUpdatedDateTime=$base.ToString('o') }
            ) })
            Test-NRGSignInControlRiskyUsers

            # Rank
            Test-NRGSignInControlRankUsers
            $rank = (Get-NRGRawData -Key 'IR-SignIn-Ranked').Data.Users
            $rank[0].UserPrincipalName | Should -Be 'bob@corp.com'
            $rank[0].Score            | Should -BeGreaterOrEqual 100
            $rank[1].UserPrincipalName | Should -Be 'alice@corp.com'
            $rank[1].Score            | Should -BeGreaterOrEqual 60
        }
    }

    Context 'Defensive — no data' {
        It 'NotApplicable when sign-in collection did not succeed' {
            Test-NRGSignInControlFailedToSuccess
            $f = @(Get-NRGFindings | Where-Object ControlId -eq 'SIGNIN-1.1')
            $f[0].State | Should -Be 'NotApplicable'
        }
    }
}

Describe 'NRG Sign-In Triage — Geo-anomaly (SIGNIN-1.6)' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Add-NRGFinding.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
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
        Test-NRGSignInControlGeoAnomaly
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
        Test-NRGSignInControlGeoAnomaly
        Test-NRGSignInControlRankUsers
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
        Test-NRGSignInControlGeoAnomaly -HomeState 'Texas' -HomeCountry 'US'
        $f = @(Get-NRGFindings | Where-Object ControlId -eq 'SIGNIN-1.6')
        $f[0].Detail | Should -Match 'texas'
        $f[0].Detail | Should -Match 'North Dakota'   # ND users now the anomalies
    }

    It 'NotApplicable when events carry no location' {
        Set-NRGRawData -Key 'IR-SignIn-Recent' -Data (NewBag 'r' @{ WindowDays=7; Cutoff=(Get-Date).AddDays(-7).ToString('o'); Count=1; Events=@(@{ userPrincipalName='x@corp.com'; createdDateTime=(Get-Date).ToString('o'); ipAddress='1.1.1.1'; status=@{errorCode=0} }) })
        Test-NRGSignInControlGeoAnomaly
        $f = @(Get-NRGFindings | Where-Object ControlId -eq 'SIGNIN-1.6')
        $f[0].State | Should -Be 'NotApplicable'
    }
}

Describe 'NRG Sign-In Triage — flagged-IP scoring attributes success per user (SIGNIN-1.5)' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Add-NRGFinding.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
        . (Join-Path $script:RepoRoot 'Email-IR' 'Evaluators' 'Test-NRGSignInControls.ps1')
        # A stand-in for the RDAP lookup: every address is on hosting infrastructure.
        function script:Get-NRGIPSignInIntel { param([string] $IPAddress) [pscustomobject]@{ IPAddress = $IPAddress; Country = 'US'; ASNOwner = 'HOSTCO'; LookupStatus = 'Resolved'; Flags = @('HOSTING_ASN') } }
        function script:Bag([string]$key, $events) { [ordered]@{ CollectorId = $key; CollectedAt = (Get-Date -Format 'o'); Success = $true; Data = @{ Count = @($events).Count; Events = @($events) } } }
        function script:Ev([string]$upn, [string]$ip, [int]$err) { @{ userPrincipalName = $upn; ipAddress = $ip; createdDateTime = (Get-Date).ToString('o'); status = @{ errorCode = $err } } }
    }
    BeforeEach { Clear-NRGState; Clear-NRGSignInTriageState }

    It 'a user who only FAILED from a flagged shared address is not scored for another user''s success' {
        Set-NRGRawData -Key 'IR-SignIn-AnonIp' -Data (Bag 'a' @((Ev 'alice@corp.com' '203.0.113.9' 50126), (Ev 'bob@corp.com' '203.0.113.9' 0)))
        Set-NRGRawData -Key 'IR-SignIn-Travel' -Data (Bag 't' @())
        Test-NRGSignInControlIPIntel
        $script:NRGSignInUserScores.ContainsKey('bob@corp.com')   | Should -BeTrue
        $script:NRGSignInUserScores.ContainsKey('alice@corp.com') | Should -BeFalse -Because 'alice never signed in successfully from that address'
        $script:NRGSignInUserScores['bob@corp.com'].Reasons[0] | Should -Match '203\.0\.113\.9'
    }

    It 'two users who both succeeded from the address are both scored' {
        Set-NRGRawData -Key 'IR-SignIn-AnonIp' -Data (Bag 'a' @((Ev 'alice@corp.com' '203.0.113.9' 0), (Ev 'bob@corp.com' '203.0.113.9' 0)))
        Set-NRGRawData -Key 'IR-SignIn-Travel' -Data (Bag 't' @())
        Test-NRGSignInControlIPIntel
        $script:NRGSignInUserScores.ContainsKey('alice@corp.com') | Should -BeTrue
        $script:NRGSignInUserScores.ContainsKey('bob@corp.com')   | Should -BeTrue
    }

    It 'nobody succeeded: nobody is scored, and the finding says how many users were seen' {
        Set-NRGRawData -Key 'IR-SignIn-AnonIp' -Data (Bag 'a' @((Ev 'alice@corp.com' '203.0.113.9' 50126), (Ev 'bob@corp.com' '203.0.113.9' 50126)))
        Set-NRGRawData -Key 'IR-SignIn-Travel' -Data (Bag 't' @())
        Test-NRGSignInControlIPIntel
        $script:NRGSignInUserScores.Count | Should -Be 0
        $f = @(Get-NRGFindings | Where-Object { $_.ControlId -eq 'SIGNIN-1.5' })[0]
        $f.Detail | Should -Match 'users seen: 2, with a successful sign-in: 0; shared address'
    }

    It 'the remediation does not call a flagged address near-certain attacker infrastructure' {
        Set-NRGRawData -Key 'IR-SignIn-AnonIp' -Data (Bag 'a' @((Ev 'bob@corp.com' '203.0.113.9' 0)))
        Set-NRGRawData -Key 'IR-SignIn-Travel' -Data (Bag 't' @())
        Test-NRGSignInControlIPIntel
        $f = @(Get-NRGFindings | Where-Object { $_.ControlId -eq 'SIGNIN-1.5' })[0]
        $f.Remediation | Should -Not -Match 'near-certain'
        $f.Remediation | Should -Match 'shared address'
    }
}

Describe 'NRG Sign-In Triage — IP enrichment failure is never a clean negative (A07)' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Add-NRGFinding.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
        . (Join-Path $script:RepoRoot 'Email-IR' 'Evaluators' 'Test-NRGSignInControls.ps1')
        # Per-address outcomes for the stand-in lookup.
        $global:NRGTestOutcome = @{}
        function script:Get-NRGIPSignInIntel { param([string] $IPAddress)
            $o = $global:NRGTestOutcome[$IPAddress]
            if ($o -eq 'throw') { throw 'timeout' }
            [ordered]@{ IPAddress = $IPAddress; Country = 'US'; ASNOwner = $(if ($o -in 'Resolved') { 'Example Telecom' } elseif ($o -eq 'Flagged') { 'HOSTCO Hosting' } else { $null })
                        LookupStatus = $(if ($o -eq 'Flagged') { 'Resolved' } else { $o }); Flags = @($(if ($o -eq 'Flagged') { 'HOSTING_ASN' })) | Where-Object { $_ } }
        }
        function script:Bag([string]$key, $events) { [ordered]@{ CollectorId = $key; CollectedAt = (Get-Date -Format 'o'); Success = $true; Data = @{ Count = @($events).Count; Events = @($events) } } }
        function script:Ev([string]$upn, [string]$ip, [int]$err) { @{ userPrincipalName = $upn; ipAddress = $ip; createdDateTime = (Get-Date).ToString('o'); status = @{ errorCode = $err } } }
        function script:Run($events) {
            Clear-NRGState; Clear-NRGSignInTriageState
            Set-NRGRawData -Key 'IR-SignIn-AnonIp' -Data (Bag 'a' $events)
            Set-NRGRawData -Key 'IR-SignIn-Travel' -Data (Bag 't' @())
            Test-NRGSignInControlIPIntel
            @(Get-NRGFindings | Where-Object { $_.ControlId -eq 'SIGNIN-1.5' })[0]
        }
    }

    It 'every lookup failing is not assessed, never Satisfied' {
        $global:NRGTestOutcome = @{ '203.0.113.1' = 'Failed'; '203.0.113.2' = 'throw' }
        $f = Run @((Ev 'a@corp.com' '203.0.113.1' 0), (Ev 'b@corp.com' '203.0.113.2' 0))
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Match 'no registrant lookup completed'
    }
    It 'a lookup that answered but named no owner is not a successful negative' {
        $global:NRGTestOutcome = @{ '203.0.113.1' = 'NoOwnerData' }
        (Run @((Ev 'a@corp.com' '203.0.113.1' 0))).State | Should -Be 'NotApplicable'
    }
    It 'every address resolved and none flagged is Satisfied, and says how many resolved' {
        $global:NRGTestOutcome = @{ '203.0.113.1' = 'Resolved' }
        $f = Run @((Ev 'a@corp.com' '203.0.113.1' 0))
        $f.State  | Should -Be 'Satisfied'
        $f.Detail | Should -Match 'came back for 1 of 1'
    }
    It 'a flagged address is kept as a finding even when other lookups failed, and the failures are disclosed' {
        $global:NRGTestOutcome = @{ '203.0.113.1' = 'Flagged'; '203.0.113.2' = 'Failed' }
        $f = Run @((Ev 'a@corp.com' '203.0.113.1' 0), (Ev 'b@corp.com' '203.0.113.2' 0))
        $f.State  | Should -Be 'Gap'
        $f.Detail | Should -Match 'came back for 1 of 2 address\(es\) looked up; 1 lookup\(s\) failed'
        $f.CurrentValue | Should -Match 'not a malicious-IP verdict|context'
    }
    It 'nothing flagged but some lookups failed is not cleared' {
        $global:NRGTestOutcome = @{ '203.0.113.1' = 'Resolved'; '203.0.113.2' = 'Failed' }
        $f = Run @((Ev 'a@corp.com' '203.0.113.1' 0), (Ev 'b@corp.com' '203.0.113.2' 0))
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Match 'Not cleared'
    }
    It 'a failed lookup contributes no score, even for a user who signed in successfully' {
        $global:NRGTestOutcome = @{ '203.0.113.2' = 'Failed' }
        $null = Run @((Ev 'b@corp.com' '203.0.113.2' 0))
        $script:NRGSignInUserScores.Count | Should -Be 0
    }
}

Describe 'Get-NRGIPSignInIntel — lookup health is carried, not dropped (A07)' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
        . (Join-Path $script:RepoRoot 'Email-IR' 'Lib' 'Get-NRGIPThreatIntel.ps1')
    }
    It 'a geolocation error is Failed with no flags' {
        Mock Get-NRGIPGeolocation { [ordered]@{ IPAddress = '198.51.100.7'; Country = $null; ASNOwner = $null; CIDR = $null; Error = 'timeout' } }
        $r = Get-NRGIPSignInIntel -IPAddress '198.51.100.7'
        $r.LookupStatus | Should -Be 'Failed'
        $r.Error | Should -Be 'timeout'
        @($r.Flags).Count | Should -Be 0
    }
    It 'an answer with no owner is NoOwnerData, not a resolved negative' {
        Mock Get-NRGIPGeolocation { [ordered]@{ IPAddress = '198.51.100.7'; Country = 'US'; ASNOwner = $null; CIDR = $null; Error = $null } }
        (Get-NRGIPSignInIntel -IPAddress '198.51.100.7').LookupStatus | Should -Be 'NoOwnerData'
    }
    It 'an owner whose name matches a hosting pattern is Resolved and flagged as context' {
        Mock Get-NRGIPGeolocation { [ordered]@{ IPAddress = '198.51.100.7'; Country = 'US'; ASNOwner = 'Example Hosting LLC'; CIDR = $null; Error = $null } }
        $r = Get-NRGIPSignInIntel -IPAddress '198.51.100.7'
        $r.LookupStatus | Should -Be 'Resolved'
        @($r.Flags) | Should -Contain 'HOSTING_ASN'
        $r.Source | Should -Match 'not a reputation verdict'
    }
}
