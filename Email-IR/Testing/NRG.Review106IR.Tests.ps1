#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.Review106IR.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Regression tests for the review-106 incident-response defects. The
             rule they pin: a failed read, truncated evidence or a missing
             required input never produces a clean conclusion, and a Critical
             is reserved for what the evidence actually supports.
    Data keys consumed: IR-SignIn-*, IR-UserConsents, IR-UserAuthMethods,
    IR-MailboxSentItems, IR-MailboxProfile (all synthetic, raw API shapes).
    Graph scopes / cmdlets: none (the Graph boundary is mocked).
#>

Describe 'Review 106 — incident-response honesty' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Ok = { param([string] $Key, $Data) Set-NRGRawData -Key $Key -Data ([ordered]@{ CollectorId = $Key; CollectedAt = (Get-Date).ToString('o'); Success = $true; Data = $Data }) }
        $script:Finding = { param([string] $Cid) @(Get-NRGFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
    }
    AfterAll { Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }
    BeforeEach { Clear-NRGState; Clear-NRGSignInTriageState }

    Context 'B1: a sign-in bag derived from a failed read is not a successful read' {

        It 'every Graph read throwing (429): the anonymous-IP and travel bags are not successful, completeness says so, and SIGNIN-1.2 / 1.3 are not Satisfied' {
            Mock -ModuleName 'NRG-Assessment' Invoke-NRGGraphRequest { throw 'Response status code does not indicate success: TooManyRequests (Too Many Requests).' }
            Invoke-NRGEmailCollectSignIns -WindowDays 7 -MaxEvents 100
            (Get-NRGRawData -Key 'IR-SignIn-Recent').Success | Should -BeFalse
            (Get-NRGRawData -Key 'IR-SignIn-AnonIp').Success | Should -BeFalse -Because 'its server-side read failed and the recent read it falls back to failed too'
            (Get-NRGRawData -Key 'IR-SignIn-Travel').Success | Should -BeFalse -Because 'it is derived only from the recent read, which failed'
            (Get-NRGSignInCollectionCompleteness -Keys 'IR-SignIn-AnonIp').Complete | Should -BeFalse
            (Get-NRGSignInCollectionCompleteness -Keys 'IR-SignIn-Travel').Complete | Should -BeFalse
            Test-NRGSignInControlAnonymousIp
            Test-NRGSignInControlImpossibleTravel
            (& $script:Finding 'SIGNIN-1.2').State | Should -Not -Be 'Satisfied'
            (& $script:Finding 'SIGNIN-1.3').State | Should -Not -Be 'Satisfied'
            ((Get-NRGExceptions | ForEach-Object { $_.Message }) -join ' ') | Should -Match 'TooManyRequests'
        }

        It 'the server-side anonymous-IP filter failing over a complete recent read falls back, and says it did' {
            Mock -ModuleName 'NRG-Assessment' Invoke-NRGGraphRequest {
                if ($Uri -match 'anonymizedIPAddress') { throw 'Response status code does not indicate success: BadRequest (Bad Request).' }
                [ordered]@{ value = @() }
            }
            Invoke-NRGEmailCollectSignIns -WindowDays 7 -MaxEvents 100
            $anon = Get-NRGRawData -Key 'IR-SignIn-AnonIp'
            $anon.Success | Should -BeTrue
            $anon.Data.Source | Should -Match 'client-side over the recent read'
            $anon.Data.Truncated | Should -BeFalse
        }
    }

    Context 'B2: a truncated read cannot support "nothing found"' {

        It 'SIGNIN-1.2: an anonymous-IP read that stopped at its first page with nothing in it is not cleared, never Satisfied' {
            & $script:Ok 'IR-SignIn-AnonIp' ([ordered]@{ Count = 0; Source = 'server-side filter, first page (1000 events)'; Truncated = $true; Events = @() })
            Test-NRGSignInControlAnonymousIp
            $f = & $script:Finding 'SIGNIN-1.2'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '^Not cleared'
        }

        It 'SIGNIN-1.2: the client-side fallback over a truncated recent read is not cleared either' {
            & $script:Ok 'IR-SignIn-AnonIp' ([ordered]@{ Count = 0; Source = 'client-side over the recent read'; Truncated = $true; Events = @() })
            Test-NRGSignInControlAnonymousIp
            (& $script:Finding 'SIGNIN-1.2').State | Should -Be 'NotApplicable'
        }

        It 'SIGNIN-1.3: a travel bag derived from a truncated recent read is not cleared, never Satisfied' {
            & $script:Ok 'IR-SignIn-Travel' ([ordered]@{ Count = 0; Source = 'client-side over the recent read'; Truncated = $true; Events = @() })
            Test-NRGSignInControlImpossibleTravel
            $f = & $script:Finding 'SIGNIN-1.3'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '^Not cleared'
        }

        It 'SIGNIN-1.6: every located sign-in at home in a truncated recent read is not cleared, never Satisfied' {
            $ev = @(1..3 | ForEach-Object { @{ id = "e$_"; userPrincipalName = 'a@corp.example'; createdDateTime = (Get-Date).ToUniversalTime().AddHours(-$_).ToString('o'); ipAddress = '198.51.100.1'
                status = @{ errorCode = 0 }; location = @{ city = 'Fargo'; state = 'North Dakota'; countryOrRegion = 'US' } } })
            & $script:Ok 'IR-SignIn-Recent' ([ordered]@{ WindowDays = 7; Count = 100; MaxEvents = 100; Truncated = $true; Events = $ev })
            Test-NRGSignInControlGeoAnomaly
            $f = & $script:Finding 'SIGNIN-1.6'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '^Not cleared'
            $f.Detail | Should -Match 'stopped at 100 events'
        }

        It 'what a truncated read DID find is still reported, with the truncation stated beside it' {
            $ev = @(@{ id = 'x'; userPrincipalName = 'a@corp.example'; createdDateTime = (Get-Date).ToUniversalTime().ToString('o'); ipAddress = '203.0.113.9'; status = @{ errorCode = 0 }; riskEventTypes_v2 = @('anonymizedIPAddress') })
            & $script:Ok 'IR-SignIn-AnonIp' ([ordered]@{ Count = 1; Source = 'server-side filter, first page (1000 events)'; Truncated = $true; Events = $ev })
            Test-NRGSignInControlAnonymousIp
            $f = & $script:Finding 'SIGNIN-1.2'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'incomplete'
        }
    }
    Context 'B3: SIGNIN-1.5 is not assessed when the inputs it enriches were not read' {

        It 'anonymous-IP and travel reads both failed: not assessed, never "no suspicious source IPs"' {
            Set-NRGRawData -Key 'IR-SignIn-AnonIp' -Data @{ CollectorId = 'IR-SignIn-AnonIp'; Success = $false; Data = $null }
            Set-NRGRawData -Key 'IR-SignIn-Travel' -Data @{ CollectorId = 'IR-SignIn-Travel'; Success = $false; Data = $null }
            Test-NRGSignInControlIPIntel
            $f = & $script:Finding 'SIGNIN-1.5'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'IR-SignIn-AnonIp did not complete'
        }

        It 'one input failed and the other was empty: not assessed' {
            & $script:Ok 'IR-SignIn-AnonIp' ([ordered]@{ Count = 0; Source = 'server-side filter, first page (1000 events)'; Truncated = $false; Events = @() })
            Set-NRGRawData -Key 'IR-SignIn-Travel' -Data @{ CollectorId = 'IR-SignIn-Travel'; Success = $false; Data = $null }
            Test-NRGSignInControlIPIntel
            (& $script:Finding 'SIGNIN-1.5').State | Should -Be 'NotApplicable'
        }

        It 'every address read resolved unflagged, but an input was truncated: not cleared, never Satisfied' {
            Mock -ModuleName 'NRG-Assessment' Get-NRGIPSignInIntel { [ordered]@{ IPAddress = $IPAddress; Country = 'US'; ASNOwner = 'Example Telecom'; LookupStatus = 'Resolved'; Flags = @() } }
            $ev = @(@{ id = 'x'; userPrincipalName = 'a@corp.example'; createdDateTime = (Get-Date).ToUniversalTime().ToString('o'); ipAddress = '203.0.113.9'; status = @{ errorCode = 0 } })
            & $script:Ok 'IR-SignIn-AnonIp' ([ordered]@{ Count = 1; Source = 'server-side filter, first page (1000 events)'; Truncated = $true; Events = $ev })
            & $script:Ok 'IR-SignIn-Travel' ([ordered]@{ Count = 0; Source = 'client-side over the recent read'; Truncated = $false; Events = @() })
            Test-NRGSignInControlIPIntel
            $f = & $script:Finding 'SIGNIN-1.5'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'Not cleared'
        }

        It 'complete inputs with nothing to enrich stay Satisfied' {
            & $script:Ok 'IR-SignIn-AnonIp' ([ordered]@{ Count = 0; Source = 'server-side filter, first page (1000 events)'; Truncated = $false; Events = @() })
            & $script:Ok 'IR-SignIn-Travel' ([ordered]@{ Count = 0; Source = 'client-side over the recent read'; Truncated = $false; Events = @() })
            Test-NRGSignInControlIPIntel
            (& $script:Finding 'SIGNIN-1.5').State | Should -Be 'Satisfied'
        }
    }
    Context 'B4: a truncated consent-grant list cannot support "none carry mail or file scopes"' {
        BeforeAll {
            $script:Required = { foreach ($k in 'IR-MailboxProfile', 'IR-MailboxSentItems', 'IR-MailboxInbox', 'IR-MailboxRules') { & $script:Ok $k ([ordered]@{ Count = 0; Truncated = $false }) } }
            $script:Benign = [ordered]@{ GrantId = 'g1'; ClientSpId = 'sp1'; App = [ordered]@{ DisplayName = 'Teams'; AppId = 'a1'; PublisherName = 'Microsoft' }; ConsentType = 'Principal'; Scope = 'User.Read openid profile' }
        }

        It 'benign grants on a list that stopped at one page: not cleared, never Satisfied' {
            & $script:Ok 'IR-UserConsents' ([ordered]@{ Count = 1; Truncated = $true; Grants = @($script:Benign) })
            Test-NRGEmailControlOAuthConsents
            $f = & $script:Finding 'EMAIL-4.1'
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '^Not cleared'
            $f.Detail | Should -Match 'one page'
        }

        It 'an empty first page with more pages: not cleared' {
            & $script:Ok 'IR-UserConsents' ([ordered]@{ Count = 0; Truncated = $true; Grants = @() })
            Test-NRGEmailControlOAuthConsents
            (& $script:Finding 'EMAIL-4.1').State | Should -Be 'NotApplicable'
        }

        It 'a write-scope grant on a truncated list is still reported, with the truncation stated' {
            $bad = [ordered]@{ GrantId = 'g2'; ClientSpId = 'sp2'; App = $null; ConsentType = 'Principal'; Scope = 'Mail.ReadWrite' }
            & $script:Ok 'IR-UserConsents' ([ordered]@{ Count = 2; Truncated = $true; Grants = @($script:Benign, $bad) })
            Test-NRGEmailControlOAuthConsents
            $f = & $script:Finding 'EMAIL-4.1'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'more grants exist'
        }

        It 'the deep-dive evidence is not Complete when the (optional) consent read was truncated, and names it' {
            & $script:Required
            & $script:Ok 'IR-UserConsents' ([ordered]@{ Count = 1; Truncated = $true; Grants = @($script:Benign) })
            $e = Get-NRGDeepDiveEvidence
            $e.Complete | Should -BeFalse -Because 'the source was read and stopped early: a clean dive verdict would rest on truncated evidence'
            ($e.OptionalTruncated -join ' ') | Should -Match 'IR-UserConsents'
        }

        It 'an optional source that was simply not read keeps the documented behavior: named, not incomplete' {
            & $script:Required
            (Get-NRGDeepDiveEvidence).Complete | Should -BeTrue
        }
    }
    Context 'R1: RDAP answers are read as the RIRs shape them (RFC 9083)' {
        BeforeAll {
            # Minimal fields from live answers on 2026-10-04: https://rdap.org/ip/8.8.8.8 (ARIN)
            # and https://rdap.org/ip/193.0.6.139 (RIPE). Entity order is preserved.
            $script:Arin = @'
{"objectClassName":"ip network","handle":"NET-8-8-8-0-2","startAddress":"8.8.8.0","endAddress":"8.8.8.255","name":"GOGL","cidr0_cidrs":[{"v4prefix":"8.8.8.0","length":24}],
 "entities":[{"objectClassName":"entity","handle":"GOGL","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Google LLC"],["kind",{},"text","org"]]]}]}
'@
            $script:Ripe = @'
{"objectClassName":"ip network","handle":"193.0.0.0 - 193.0.7.255","startAddress":"193.0.0.0","endAddress":"193.0.7.255","name":"RIPE-NCC","country":"NL","cidr0_cidrs":[{"v4prefix":"193.0.0.0","length":21}],
 "entities":[{"objectClassName":"entity","handle":"MDIR-RIPE","roles":["administrative"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Managing Director"],["kind",{},"text","group"]]]},
  {"objectClassName":"entity","handle":"OPS4-RIPE","roles":["technical"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RIPE NCC Operations"],["kind",{},"text","group"]]]},
  {"objectClassName":"entity","handle":"ORG-RIEN1-RIPE","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","Reseaux IP Europeens Network Coordination Centre (RIPE NCC)"],["kind",{},"text","org"]]]},
  {"objectClassName":"entity","handle":"RIPE-NCC-MNT","roles":["registrant"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RIPE-NCC-MNT"],["kind",{},"text","individual"]]]},
  {"objectClassName":"entity","handle":"OPS4-RIPE","roles":["abuse"],"vcardArray":["vcard",[["version",{},"text","4.0"],["fn",{},"text","RIPE NCC Operations"],["kind",{},"text","group"]]]}]}
'@
        }
        BeforeEach { & (Get-Module 'NRG-Assessment') { Clear-NRGIPThreatIntelCache } }

        It 'an ARIN answer (no top-level country) resolves to its registrant, not a Failed lookup' {
            Mock -ModuleName 'NRG-Assessment' Invoke-RestMethod { $script:Arin | ConvertFrom-Json }
            $r = Get-NRGIPSignInIntel -IPAddress '8.8.8.8'
            $r.Error        | Should -BeNullOrEmpty
            $r.LookupStatus | Should -Be 'Resolved'
            $r.ASNOwner     | Should -Be 'Google LLC'
        }

        It 'a RIPE answer names the registrant organization, never the administrative contact listed first' {
            Mock -ModuleName 'NRG-Assessment' Invoke-RestMethod { $script:Ripe | ConvertFrom-Json }
            $r = Get-NRGIPSignInIntel -IPAddress '193.0.6.139'
            $r.LookupStatus | Should -Be 'Resolved'
            $r.ASNOwner     | Should -Be 'Reseaux IP Europeens Network Coordination Centre (RIPE NCC)'
            $r.Country      | Should -Be 'NL'
        }

        It 'an answer with contacts but no registrant is NoOwnerData, never a contact name judged as the owner' {
            Mock -ModuleName 'NRG-Assessment' Invoke-RestMethod {
                $o = $script:Ripe | ConvertFrom-Json
                $o.entities = @($o.entities | Where-Object { $_.roles -notcontains 'registrant' })
                $o
            }
            $r = Get-NRGIPSignInIntel -IPAddress '193.0.6.140'
            $r.LookupStatus | Should -Be 'NoOwnerData' -Because $r.Error
            $r.ASNOwner     | Should -BeNullOrEmpty
        }
    }
    Context 'R2a: SIGNIN-1.2 is Critical only when an anonymous-IP sign-in succeeded' {
        BeforeAll {
            $script:AnonEv = { param([string] $Upn, [int] $Err) @{ id = [guid]::NewGuid().ToString(); userPrincipalName = $Upn; createdDateTime = (Get-Date).ToUniversalTime().ToString('o'); ipAddress = '185.220.101.1'; status = @{ errorCode = $Err }; riskEventTypes_v2 = @('anonymizedIPAddress') } }
        }

        It 'failed-only anonymous-IP attempts are reported below Critical and score below a success' {
            & $script:Ok 'IR-SignIn-AnonIp' ([ordered]@{ Count = 2; Source = 'server-side filter, first page (1000 events)'; Truncated = $false; Events = @((& $script:AnonEv 'a@corp.example' 50126), (& $script:AnonEv 'a@corp.example' 50126)) })
            Test-NRGSignInControlAnonymousIp
            $f = & $script:Finding 'SIGNIN-1.2'
            $f.State    | Should -Be 'Gap'
            $f.Severity | Should -Be 'High' -Because 'no anonymous-IP sign-in succeeded'
            $f.Remediation | Should -Not -Match 'near-certain'
        }

        It 'a successful anonymous-IP sign-in stays Critical' {
            & $script:Ok 'IR-SignIn-AnonIp' ([ordered]@{ Count = 2; Source = 'server-side filter, first page (1000 events)'; Truncated = $false; Events = @((& $script:AnonEv 'a@corp.example' 50126), (& $script:AnonEv 'b@corp.example' 0)) })
            Test-NRGSignInControlAnonymousIp
            (& $script:Finding 'SIGNIN-1.2').Severity | Should -Be 'Critical'
        }
    }
    Context 'R2b: a repeated reason does not stack a user to Critical' {
        BeforeAll {
            $script:GeoRun = {
                param([int] $AwayCount)
                Clear-NRGState; Clear-NRGSignInTriageState
                $now = (Get-Date).ToUniversalTime()
                $ev = @(1..5 | ForEach-Object { @{ id = "h$_"; userPrincipalName = 'a@corp.example'; createdDateTime = $now.AddHours(-$_).ToString('o'); ipAddress = '198.51.100.1'; status = @{ errorCode = 0 }; location = @{ city = 'Fargo'; state = 'North Dakota'; countryOrRegion = 'US' } } })
                $ev += @(1..$AwayCount | ForEach-Object { @{ id = "m$_"; userPrincipalName = 'b@corp.example'; createdDateTime = $now.AddMinutes(-$_).ToString('o'); ipAddress = '198.51.100.77'; status = @{ errorCode = 0 }; location = @{ city = 'Moorhead'; state = 'Minnesota'; countryOrRegion = 'US' } } })
                & $script:Ok 'IR-SignIn-Recent' ([ordered]@{ WindowDays = 7; Count = $ev.Count; Truncated = $false; Events = $ev })
                & $script:Ok 'IR-SignIn-AnonIp' ([ordered]@{ Count = 0; Truncated = $false; Events = @() })
                & $script:Ok 'IR-SignIn-Travel' ([ordered]@{ Count = 0; Truncated = $false; Events = @() })
                Test-NRGSignInControlGeoAnomaly -HomeState 'North Dakota' -HomeCountry 'US'
                Test-NRGSignInControlRankUsers
                $score = @((Get-NRGRawData -Key 'IR-SignIn-Ranked').Data.Users | Where-Object { $_.UserPrincipalName -eq 'b@corp.example' })[0].Score
                [ordered]@{ Score = $score; Rank = (& $script:Finding 'SIGNIN-2.1') }
            }
        }

        It 'two successful sign-ins from the same neighboring-state city score the same as one, and the ranking is not Critical' {
            $one = & $script:GeoRun 1
            $two = & $script:GeoRun 2
            $two.Score | Should -Be $one.Score -Because 'the same reason is scored once per user'
            $two.Rank.Severity | Should -Not -Be 'Critical'
        }
    }
    Context 'R2c: an out-of-state success is visible but not Critical; an out-of-country success can be' {
        BeforeAll {
            $script:Geo = {
                param([string] $State, [string] $Country)
                $now = (Get-Date).ToUniversalTime()
                $ev = @(1..5 | ForEach-Object { @{ id = "h$_"; userPrincipalName = 'a@corp.example'; createdDateTime = $now.AddHours(-$_).ToString('o'); ipAddress = '198.51.100.1'; status = @{ errorCode = 0 }; location = @{ city = 'Fargo'; state = 'North Dakota'; countryOrRegion = 'US' } } })
                $ev += @{ id = 'away'; userPrincipalName = 'b@corp.example'; createdDateTime = $now.ToString('o'); ipAddress = '203.0.113.50'; status = @{ errorCode = 0 }; location = @{ city = 'X'; state = $State; countryOrRegion = $Country } }
                & $script:Ok 'IR-SignIn-Recent' ([ordered]@{ WindowDays = 7; Count = $ev.Count; Truncated = $false; Events = $ev })
                Test-NRGSignInControlGeoAnomaly -HomeState 'North Dakota' -HomeCountry 'US'
                & $script:Finding 'SIGNIN-1.6'
            }
        }

        It 'a single successful out-of-state sign-in is a High Gap, listed, not Critical' {
            $f = & $script:Geo 'Minnesota' 'US'
            $f.State    | Should -Be 'Gap'
            $f.Severity | Should -Be 'High'
            $f.Detail   | Should -Match 'b@corp\.example.*Minnesota'
        }

        It 'a successful out-of-country sign-in stays Critical' {
            (& $script:Geo 'Ile-de-France' 'FR').Severity | Should -Be 'Critical'
        }
    }
    Context 'R2d: EMAIL-4.1 is Critical only for an identified app with no publisher name' {
        BeforeAll {
            $script:Grant = { param($App) & $script:Ok 'IR-UserConsents' ([ordered]@{ Count = 1; Truncated = $false; Grants = @([ordered]@{ GrantId = 'g1'; ClientSpId = 'sp1'; App = $App; ConsentType = 'Principal'; Scope = 'Mail.ReadWrite Mail.Send offline_access' }) }) }
        }

        It 'an identified app with a publisher name holding a write scope is High (verify the app), not Critical' {
            & $script:Grant ([ordered]@{ DisplayName = 'Microsoft Outlook Sync'; AppId = 'a1'; PublisherName = 'Microsoft Services' })
            Test-NRGEmailControlOAuthConsents
            $f = & $script:Finding 'EMAIL-4.1'
            $f.State    | Should -Be 'Gap'
            $f.Severity | Should -Be 'High'
            $f.Detail   | Should -Match 'Microsoft Services'
        }

        It 'an identified app with no publisher name holding a write scope stays Critical' {
            & $script:Grant ([ordered]@{ DisplayName = 'Mail Helper Pro'; AppId = 'a2'; PublisherName = $null })
            Test-NRGEmailControlOAuthConsents
            (& $script:Finding 'EMAIL-4.1').Severity | Should -Be 'Critical'
        }
    }
    Context 'R3: dates are kept as ISO 8601 and parsed culture-invariantly' {
        BeforeAll {
            $script:WithCulture = {
                param([string] $Name, [scriptblock] $Body)
                $old = [System.Threading.Thread]::CurrentThread.CurrentCulture
                try { [System.Threading.Thread]::CurrentThread.CurrentCulture = [cultureinfo]::GetCultureInfo($Name); & $Body }
                finally { [System.Threading.Thread]::CurrentThread.CurrentCulture = $old }
            }
            # A recent day whose day-of-month differs from its month, so a
            # month/day swap cannot land on the same date.
            $script:Recent = (Get-Date).ToUniversalTime().Date.AddDays(-3).AddHours(10)
            if ($script:Recent.Day -eq $script:Recent.Month) { $script:Recent = $script:Recent.AddDays(-1) }
            # A day > 12 for the burst test: 25 September 2026, 10:00 UTC.
            $script:Day25 = [datetime]::new(2026, 9, 25, 10, 0, 0, [System.DateTimeKind]::Utc)
        }

        It 'the user-security collector stores an authentication method''s creation time as ISO 8601 under en-GB' {
            Mock -ModuleName 'NRG-Assessment' Invoke-NRGGraphRequest {
                if ($Uri -match 'authentication/methods') { return [ordered]@{ value = @(@{ '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod'; id = 'm1'; phoneNumber = '+1 555 0100'; createdDateTime = $script:Day25 }) } }
                [ordered]@{ value = @() }
            }
            & $script:WithCulture 'en-GB' { Invoke-NRGEmailCollectUserSecurity -TargetUpn 'a@corp.example' }
            (Get-NRGRawData -Key 'IR-UserAuthMethods').Data.Methods[0].CreatedDateTime | Should -Match '^2026-09-25T10:00:00'
        }

        It 'EMAIL-4.2 reads an older invariant-culture date under en-GB, and treats an unparseable one as unknown, never a throw' {
            & $script:Ok 'IR-UserAuthMethods' ([ordered]@{ Count = 2; Methods = @(
                [ordered]@{ Id = 'm1'; MethodType = 'phoneAuthenticationMethod'; Display = '+1 555 0100'; CreatedDateTime = $script:Recent.ToString('MM/dd/yyyy HH:mm:ss', [cultureinfo]::InvariantCulture) }
                [ordered]@{ Id = 'm2'; MethodType = 'microsoftAuthenticatorAuthenticationMethod'; Display = 'Phone'; CreatedDateTime = 'not a date' }) })
            & $script:WithCulture 'en-GB' { Test-NRGEmailControlAuthMethods }
            $f = & $script:Finding 'EMAIL-4.2'
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match '1 method\(s\) registered in the last 14 days: phoneAuthenticationMethod'
        }

        It 'EMAIL-2.1 finds a 25-message burst on the 25th under en-GB, whether the time is a DateTime or an ISO string' {
            foreach ($shape in 'DateTime', 'Iso') {
                Clear-NRGState
                & $script:Ok 'IR-MailboxProfile' ([ordered]@{ UserPrincipalName = 'a@corp.example' })
                $msgs = @(0..24 | ForEach-Object {
                    $t = $script:Day25.AddMinutes($_)
                    [ordered]@{ Id = "m$_"; Subject = 'Weekly notes'; SentDateTime = $(if ($shape -eq 'Iso') { $t.ToString('o') } else { $t }); Recipients = @('colleague@corp.example'); HasAttachments = $false; BodyURLs = @() } })
                & $script:Ok 'IR-MailboxSentItems' ([ordered]@{ WindowDays = 7; Count = 25; Truncated = $false; Messages = $msgs })
                & $script:WithCulture 'en-GB' { Test-NRGEmailControlOutboundActivity }
                $f = & $script:Finding 'EMAIL-2.1'
                $f.State  | Should -Be 'Gap' -Because "$shape shape: $($f.Detail)"
            }
        }

        It 'the mailbox collector stores sent times as ISO 8601 under en-GB' {
            Mock -ModuleName 'NRG-Assessment' Invoke-NRGGraphRequest {
                if ($Uri -match 'SentItems') { return [ordered]@{ value = @(@{ id = 's1'; subject = 's'; sentDateTime = $script:Day25; toRecipients = @(); ccRecipients = @(); bccRecipients = @(); hasAttachments = $false; bodyPreview = '' }) } }
                [ordered]@{ value = @() }
            }
            & $script:WithCulture 'en-GB' { Invoke-NRGEmailCollectMailbox -WindowDays 7 }
            $bag = Get-NRGRawData -Key 'IR-MailboxSentItems'
            $bag.Data.Messages[0].SentDateTime | Should -Match '^2026-09-25T10:00:00'
            $bag.Data.EarliestObserved | Should -Match '^2026-09-25T10:00:00'
        }
    }
}
