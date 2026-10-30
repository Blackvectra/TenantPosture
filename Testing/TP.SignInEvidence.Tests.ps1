#Requires -Version 7.0
#
# TP.SignInEvidence.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Pins the sign-in evidence collector (AAD-SignInEvidence) and the judgment the
# baseline's effectiveness column draws from it (Get-TPSignInEffectiveness).
#
# The rules under test, in order of consequence:
#   - an incomplete read never yields Effective (a truncated or failed read
#     with no bypass is Unknown);
#   - one bypass in any read is Ineffective, even when the read was cut short;
#   - a log that cannot be read says why (Entra ID P1/P2, reader role) and is
#     Unknown, never a pass;
#   - the evidence never changes a row's ObservedState;
#   - no IP address, location or device detail reaches the raw data.
#
# The Graph stand-in is injected into MODULE scope, because the collector's
# call to Invoke-TPGraphRequest resolves inside the module. It answers with
# the beta signIn shape, ipAddress and location included, so the projection
# is exercised against what Graph really sends.

Describe 'Sign-in evidence' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'

        & $script:Mod { param($n, $b) Set-Item -Path "function:script:$n" -Value ([scriptblock]::Create($b)) } 'Invoke-TPGraphRequest' @'
[CmdletBinding()]
param([string] $Uri, [string] $Method = 'GET', $Body, $Headers, [string] $OutputType = 'HashTable')
$script:SieUris.Add($Uri)
$s = $script:SieScenario
$f = [uri]::UnescapeDataString($Uri)
$row = {
    param([string] $upn, [string] $uid, [string] $client, [string] $resource)
    @{ id = [guid]::NewGuid().ToString(); createdDateTime = '2026-10-20T10:00:00Z'; userPrincipalName = $upn; userId = $uid
       userDisplayName = $upn; userType = 'member'; appDisplayName = 'Mail client'; resourceId = $resource
       resourceDisplayName = 'Office 365 Exchange Online'; clientAppUsed = $client; isInteractive = $true
       ipAddress = '203.0.113.9'; location = @{ city = 'Somewhere'; countryOrRegion = 'US' }
       deviceDetail = @{ operatingSystem = 'Windows' }; status = @{ errorCode = 0 }
       authenticationDetails = @(@{ authenticationMethod = 'Password'; authenticationStepRequirement = 'Primary authentication'
                                    succeeded = $true; authenticationStepResultDetail = 'Correct password'; authenticationStepDateTime = '2026-10-20T10:00:00Z' }) }
}
if ($s -eq 'Premium') { throw 'Authentication_RequestFromNonPremiumTenantOrB2CTenant: Neither tenant is B2C or tenant doesn''t have premium license' }
if ($s -eq 'Denied')  { throw 'Response status code does not indicate success: 403 (Forbidden). Authorization_RequestDenied' }
if ($f -like "*authenticationRequirement eq 'singleFactorAuthentication'*") {
    if ($s -eq 'Slow') { Start-Sleep -Milliseconds 1500; return @{ value = @() } }
    if ($s -eq 'SingleFactor') { return @{ value = @(& $row 'alice@contoso.test' 'AAAA0000-0000-0000-0000-000000000001' 'Browser' '00000003-0000-0000-c000-000000000000') } }
    if ($s -eq 'Paged') { return @{ value = @(); '@odata.nextLink' = 'https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=next' } }
    if ($s -eq 'SecondPageFails') {
        return @{ value = @(& $row 'alice@contoso.test' 'AAAA0000-0000-0000-0000-000000000001' 'Browser' '00000003-0000-0000-c000-000000000000')
                  '@odata.nextLink' = 'https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=fails' }
    }
    return @{ value = @() }
}
if ($f -like "*clientAppUsed eq 'IMAP4'*") {
    if ($s -eq 'ImapFails') { throw 'Request timed out' }
    if ($s -eq 'Legacy' -and $f -notlike '*nonInteractiveUser*') {
        return @{ value = @(& $row 'bob@contoso.test' 'bbbb0000-0000-0000-0000-000000000002' 'IMAP4' '00000002-0000-0ff1-ce00-000000000000') }
    }
}
if ($Uri -like '*skiptoken=fails*') { throw 'Request timed out' }
if ($Uri -like '*skiptoken=next*') { return @{ value = @(); '@odata.nextLink' = 'https://graph.microsoft.com/beta/auditLogs/signIns?$skiptoken=next' } }
return @{ value = @() }
'@

        function script:Collect {
            param([string] $Scenario)
            & $script:Mod { param($s) $script:SieScenario = $s; $script:SieUris = [System.Collections.Generic.List[string]]::new() } $Scenario
            Clear-TPState
            $r = Invoke-TPCollectAADSignInEvidence -MaxPages 2 -Now ([datetime]'2026-10-26T00:00:00Z') 3>$null
            $uris = & $script:Mod { $script:SieUris.ToArray() }
            [pscustomobject]@{ Raw = $r; Uris = $uris }
        }
        function script:Judge {
            param([string] $Check, [string] $Scope, $RawData, $EmergencyAccess = @{})
            & $script:Mod { param($c, $s, $r, $e) Get-TPSignInEffectiveness -Check $c -Scope $s -RawData $r -EmergencyAccess $e } $Check $Scope $RawData $EmergencyAccess
        }
        # Evidence built directly, in the collector's stored shape.
        function script:Evidence {
            param([object[]] $Legacy = @(), [object[]] $Single = @(), [string] $LegacyStatus = 'Collected', [string] $SingleStatus = 'Collected',
                  [bool] $LegacyTruncated = $false, [bool] $SingleTruncated = $false, [bool] $Available = $true, [string] $Reason = '')
            @{ 'AAD-SignInEvidence' = @{ Success = $true; Data = @{
                WindowDays = 30; Available = $Available; UnavailableReason = $Reason
                SectionStatus = @{ LegacyAuth = $LegacyStatus; SingleFactor = $SingleStatus }
                Sections = @{ LegacyAuth = @{ Truncated = $LegacyTruncated; Events = @($Legacy) }; SingleFactor = @{ Truncated = $SingleTruncated; Events = @($Single) } } } } }
        }
        # A single-factor sign-in as the collector stores it: by default its
        # recorded steps show a password and nothing else.
        function script:Ev {
            param([string] $Upn, [string] $Uid, [string] $Client = 'IMAP4', [string] $Resource = '00000002-0000-0ff1-ce00-000000000000',
                  [object[]] $Auth = @(@{ Method = 'Password'; Step = 'Primary authentication'; Succeeded = $true; Result = 'Correct password' }))
            @{ UserPrincipalName = $Upn; UserId = $Uid; ClientAppUsed = $Client; AppDisplayName = 'App'; ResourceId = $Resource; AuthDetails = $Auth }
        }
    }

    Context 'Collector' {
        It 'reads beta with server-side filters and finds a clean tenant clean' {
            $c = Collect 'Clean'
            $c.Raw.Success | Should -BeTrue
            $c.Raw.Data.Available | Should -BeTrue
            $c.Raw.Data.SectionStatus.LegacyAuth | Should -Be 'Collected'
            $c.Raw.Data.SectionStatus.SingleFactor | Should -Be 'Collected'
            @($c.Uris | Where-Object { $_ -notlike 'https://graph.microsoft.com/beta/auditLogs/signIns?*' }).Count | Should -Be 0
            # 13 legacy clients x (interactive + non-interactive) + 1 single-factor read.
            $c.Uris.Count | Should -Be 27
            $decoded = @($c.Uris | ForEach-Object { [uri]::UnescapeDataString($_) })
            @($decoded | Where-Object { $_ -notlike '*createdDateTime ge 2026-09-26T00:00:00Z and status/errorCode eq 0*' }).Count | Should -Be 0
            @($decoded | Where-Object { $_ -like "*signInEventTypes/any(t: t eq 'nonInteractiveUser')*" }).Count | Should -Be 13
            @($decoded | Where-Object { $_ -like "*clientAppUsed eq 'Outlook Anywhere (RPC over HTTP)'*" }).Count | Should -Be 2
        }

        It 'keeps only the fields the judgment needs: no IP address, location or device' {
            $c = Collect 'Legacy'
            $e = @($c.Raw.Data.Sections.LegacyAuth.Events)
            $e.Count | Should -Be 1
            $e[0].UserPrincipalName | Should -Be 'bob@contoso.test'
            $e[0].ClientAppUsed | Should -Be 'IMAP4'
            $e[0].ErrorCode | Should -Be 0
            foreach ($k in @('ipAddress', 'IpAddress', 'location', 'Location', 'deviceDetail', 'DeviceDetail')) { $e[0].Contains($k) | Should -BeFalse }
            ($c.Raw | ConvertTo-Json -Depth 10) | Should -Not -Match '203\.0\.113\.9|Somewhere'
        }

        It 'keeps the authentication steps, so an earlier MFA claim can be told from a single factor' {
            $c = Collect 'SingleFactor'
            $d = @(@($c.Raw.Data.Sections.SingleFactor.Events)[0].AuthDetails)
            $d.Count | Should -Be 1
            $d[0].Method | Should -Be 'Password'
            $d[0].Step | Should -Be 'Primary authentication'
            $d[0].Contains('authenticationStepDateTime') | Should -BeFalse
        }

        It 'keeps the events read before a later page failed, and fails the section' {
            $c = Collect 'SecondPageFails'
            $c.Raw.Data.SectionStatus.SingleFactor | Should -Be 'Failed'
            @($c.Raw.Data.Sections.SingleFactor.Events).Count | Should -Be 1
            $c.Raw.Data.Available | Should -BeTrue
            (Judge 'SingleFactorSuccess' 'AllUsers' @{ 'AAD-SignInEvidence' = $c.Raw }).State | Should -Be 'Ineffective'
        }

        It 'stores user ids lower-case so the emergency-access record matches' {
            $c = Collect 'SingleFactor'
            @($c.Raw.Data.Sections.SingleFactor.Events)[0].UserId | Should -Be 'aaaa0000-0000-0000-0000-000000000001'
        }

        It 'records a tenant without Entra ID P1 or P2 as unavailable and stops asking' {
            $c = Collect 'Premium'
            $c.Raw.Data.Available | Should -BeFalse
            $c.Raw.Data.UnavailableReason | Should -Be 'PremiumLicenseRequired'
            $c.Uris.Count | Should -Be 1
            $c.Raw.Data.SectionStatus.LegacyAuth | Should -Be 'Failed'
        }

        It 'records an account without a reader role as unavailable' {
            $c = Collect 'Denied'
            $c.Raw.Data.UnavailableReason | Should -Be 'AccessDenied'
            $c.Uris.Count | Should -Be 1
        }

        It 'marks a read that stopped at its page cap as truncated' {
            $c = Collect 'Paged'
            $c.Raw.Data.Sections.SingleFactor.Truncated | Should -BeTrue
            $c.Raw.Data.SectionStatus.SingleFactor | Should -Be 'Collected'
        }

        It 'fails the legacy section when one client read fails' {
            $c = Collect 'ImapFails'
            $c.Raw.Data.SectionStatus.LegacyAuth | Should -Be 'Failed'
            @($c.Raw.Data.Errors | Where-Object { $_ -like '*IMAP4*' }).Count | Should -BeGreaterThan 0
        }
    }

    Context 'Judgment' {
        It 'reports progress after every read: 27 reads, the last one numbered 27/27' {
            & $script:Mod { $script:SieScenario = 'Clean'; $script:SieUris = [System.Collections.Generic.List[string]]::new() }
            $lines = [System.Collections.Generic.List[string]]::new()
            Clear-TPState
            $r = Invoke-TPCollectAADSignInEvidence -MaxPages 2 -Now ([datetime]'2026-10-26T00:00:00Z') -Progress { param($m) $lines.Add($m) }.GetNewClosure() 3>$null
            $lines.Count | Should -Be 27
            $lines[0] | Should -Match '^single-factor sign-ins: 0 event\(s\) \(1/27\)$'
            $lines[-1] | Should -Match '\(27/27\)$'
            $lines | Where-Object { $_ -match 'non-interactive' } | Should -Not -BeNullOrEmpty
            $r.Data.TimeBudget.Reached | Should -BeFalse
            $r.Data.TimeBudget.ReadsSkipped | Should -Be 0
            # A progress callback that throws never breaks the collection.
            Clear-TPState
            $r2 = Invoke-TPCollectAADSignInEvidence -MaxPages 2 -Now ([datetime]'2026-10-26T00:00:00Z') -Progress { throw 'console gone' } 3>$null
            $r2.Data.SectionStatus.LegacyAuth | Should -Be 'Collected'
        }
        It 'stops at its time budget: reads not made are skipped, the section fails with the reason, and nothing reads as clean' {
            & $script:Mod { $script:SieScenario = 'Slow'; $script:SieUris = [System.Collections.Generic.List[string]]::new() }
            Clear-TPState
            $r = Invoke-TPCollectAADSignInEvidence -MaxPages 2 -Now ([datetime]'2026-10-26T00:00:00Z') -TimeBudgetSeconds 1 3>$null
            $uris = & $script:Mod { $script:SieUris.ToArray() }
            @($uris).Count | Should -Be 1 -Because 'only the single-factor read was made before the budget ran out'
            $r.Success | Should -BeTrue
            $r.Data.TimeBudget.Reached | Should -BeTrue
            $r.Data.TimeBudget.ReadsSkipped | Should -Be 26
            $r.Data.SectionStatus.SingleFactor | Should -Be 'Collected'
            $r.Data.SectionStatus.LegacyAuth | Should -Be 'Failed'
            ($r.Data.Errors -join ' ') | Should -Match 'time budget was reached'
            (Get-TPCoverage)['AAD-SignInEvidence'].Note | Should -Match 'time budget'
            $legacy = Judge 'LegacyAuthSuccess' 'All' @{ 'AAD-SignInEvidence' = $r }
            $legacy.State | Should -Be 'Unknown'
            $legacy.Detail | Should -Match "stopped at the collector's 0 ?\.?\d*-minute time budget"
            # The read that did finish still answers.
            (Judge 'SingleFactorSuccess' 'AllUsers' @{ 'AAD-SignInEvidence' = $r }).State | Should -Be 'Effective'
        }
        It 'the entry point skips the collector with -SkipSignInEvidence, records the skip, and hands the collector a progress line' {
            $entry = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
            $entry | Should -Match '\[switch\] \$SkipSignInEvidence'
            $entry | Should -Match "if \(-not \`$SkipSignInEvidence\) \{\s+Invoke-TPCollectorStep 'Sign-in evidence \(30 days\)'"
            $entry | Should -Match "@\{ On = \`$SkipSignInEvidence; Flag = '-SkipSignInEvidence'; Keys = @\('AAD-SignInEvidence'\) \}"
            $entry | Should -Match "Parameters\.ContainsKey\('Progress'\)"
        }
        It 'checks the budget between pages, keeping the events already read' {
            & $script:Mod {
                $script:SieUris = [System.Collections.Generic.List[string]]::new(); $script:SieScenario = 'Clean'
                $page = Read-TPSignInEvidencePages -Uri 'https://graph.microsoft.com/beta/auditLogs/signIns?x' -Deadline ([datetime]::UtcNow.AddSeconds(-1))
                $page.BudgetReached | Should -BeTrue
                $page.Pages | Should -Be 0
                $page.Error | Should -Match 'time budget'
                $script:SieUris.Count | Should -Be 0
            }
        }
        It 'is Effective only from a complete read with no bypass, and says what that does not prove' {
            $j = Judge 'LegacyAuthSuccess' 'All' (Evidence)
            $j.State | Should -Be 'Effective'
            $j.Detail | Should -Match 'not proof'
        }

        It 'is Ineffective on one bypass and names the account' {
            $j = Judge 'LegacyAuthSuccess' 'All' (Evidence -Legacy @(Ev 'bob@contoso.test' 'b1'))
            $j.State | Should -Be 'Ineffective'
            $j.Detail | Should -Match 'bob@contoso\.test'
        }

        It 'is still Ineffective when the read was cut short or partly failed' {
            (Judge 'LegacyAuthSuccess' 'All' (Evidence -Legacy @(Ev 'bob@contoso.test' 'b1') -LegacyTruncated $true)).State | Should -Be 'Ineffective'
            (Judge 'LegacyAuthSuccess' 'All' (Evidence -Legacy @(Ev 'bob@contoso.test' 'b1') -LegacyStatus 'Failed')).State | Should -Be 'Ineffective'
        }

        It 'is never Effective from a truncated or failed read' {
            (Judge 'SingleFactorSuccess' 'AllUsers' (Evidence -SingleTruncated $true)).State | Should -Be 'Unknown'
            (Judge 'SingleFactorSuccess' 'AllUsers' (Evidence -SingleStatus 'Failed')).State | Should -Be 'Unknown'
            (Judge 'SingleFactorSuccess' 'AllUsers' (Evidence -SingleStatus 'NotRun')).State | Should -Be 'Unknown'
        }

        It 'is Unknown when the evidence was not collected or could not be read, and says why' {
            (Judge 'LegacyAuthSuccess' 'All' @{}).State | Should -Be 'Unknown'
            (Judge 'LegacyAuthSuccess' 'All' $null).State | Should -Be 'Unknown'
            $j = Judge 'LegacyAuthSuccess' 'All' (Evidence -Available $false -Reason 'PremiumLicenseRequired')
            $j.State | Should -Be 'Unknown'
            $j.Detail | Should -Match 'Entra ID P1 or P2'
            (Judge 'LegacyAuthSuccess' 'All' (Evidence -Available $false -Reason 'AccessDenied')).Detail | Should -Match 'Reports Reader'
        }

        It 'sets aside an approved emergency-access user by object id and names it' {
            $ea = @{ 'user:e1' = @{ ObjectId = 'e1' } }
            $j = Judge 'SingleFactorSuccess' 'AllUsers' (Evidence -Single @(Ev 'bg1@contoso.test' 'e1' 'Browser')) $ea
            $j.State | Should -Be 'Effective'
            $j.Detail | Should -Match 'bg1@contoso\.test'
            # A group on the record is not resolved, so its members are not set aside.
            (Judge 'SingleFactorSuccess' 'AllUsers' (Evidence -Single @(Ev 'x@contoso.test' 'e1' 'Browser')) @{ 'group:e1' = @{} }).State | Should -Be 'Ineffective'
        }

        It 'scopes Exchange and SharePoint by resource' {
            $spo = Ev 'carol@contoso.test' 'c1' 'Other clients' '00000003-0000-0ff1-ce00-000000000000'
            (Judge 'LegacyAuthSuccess' 'SharePoint' (Evidence -Legacy @($spo))).State | Should -Be 'Ineffective'
            (Judge 'LegacyAuthSuccess' 'Exchange' (Evidence -Legacy @($spo))).State | Should -Be 'Effective'
            $exo = Ev 'bob@contoso.test' 'b1' 'IMAP4'
            (Judge 'LegacyAuthSuccess' 'Exchange' (Evidence -Legacy @($exo))).State | Should -Be 'Ineffective'
            (Judge 'LegacyAuthSuccess' 'SharePoint' (Evidence -Legacy @($exo))).State | Should -Be 'Effective'
        }

        It 'judges privileged-role holders only, and only when the role data was read' {
            $ev = Evidence -Single @((Ev 'admin@contoso.test' 'a1' 'Browser'), (Ev 'user@contoso.test' 'u1' 'Browser'))
            $roles = @{ Success = $true; Data = @{ SectionStatus = @{ RoleAssignments = 'Collected' }; AllPrivilegedAssignments = @(@{ PrincipalId = 'A1' }) } }
            $ev['AAD-DirectoryRoles'] = $roles
            $j = Judge 'SingleFactorSuccess' 'PrivilegedRoles' $ev
            $j.State | Should -Be 'Ineffective'
            $j.Detail | Should -Match 'admin@contoso\.test'
            $j.Detail | Should -Not -Match 'user@contoso\.test'
            $ev['AAD-DirectoryRoles'] = @{ Success = $true; Data = @{ SectionStatus = @{ RoleAssignments = 'Failed' }; AllPrivilegedAssignments = @() } }
            (Judge 'SingleFactorSuccess' 'PrivilegedRoles' $ev).State | Should -Be 'Unknown'
            $ev.Remove('AAD-DirectoryRoles')
            (Judge 'SingleFactorSuccess' 'PrivilegedRoles' $ev).State | Should -Be 'Unknown'
        }

        It 'does not count a single-factor sign-in whose steps show an earlier MFA claim' {
            $claim = @(@{ Method = 'Previously satisfied'; Step = 'Multifactor authentication'; Succeeded = $true; Result = 'MFA requirement satisfied by claim in the token' })
            $j = Judge 'SingleFactorSuccess' 'AllUsers' (Evidence -Single @(Ev 'alice@contoso.test' 'a1' 'Browser' -Auth $claim))
            $j.State | Should -Be 'Effective'
            $j.Detail | Should -Match 'show MFA in their authentication steps'
            $push = @(@{ Method = 'Password'; Step = 'Primary authentication'; Succeeded = $true; Result = '' }, @{ Method = 'Mobile app notification'; Step = 'MFA'; Succeeded = $true; Result = 'MFA successfully completed' })
            (Judge 'SingleFactorSuccess' 'AllUsers' (Evidence -Single @(Ev 'alice@contoso.test' 'a1' 'Browser' -Auth $push))).State | Should -Be 'Effective'
            # A reused FIRST factor is not MFA, whatever the method is called.
            $first = @(@{ Method = 'Previously satisfied'; Step = 'Primary authentication'; Succeeded = $true; Result = 'First factor requirement satisfied by claim in the token' })
            (Judge 'SingleFactorSuccess' 'AllUsers' (Evidence -Single @(Ev 'alice@contoso.test' 'a1' 'Browser' -Auth $first))).State | Should -Be 'Ineffective'
            # A second factor that failed is not MFA.
            $denied = @(@{ Method = 'Password'; Step = 'Primary authentication'; Succeeded = $true; Result = '' }, @{ Method = 'Text message'; Step = 'MFA'; Succeeded = $false; Result = 'Invalid authentication' })
            (Judge 'SingleFactorSuccess' 'AllUsers' (Evidence -Single @(Ev 'alice@contoso.test' 'a1' 'Browser' -Auth $denied))).State | Should -Be 'Ineffective'
        }

        It 'never calls a sign-in with no recorded steps a bypass or a pass' {
            $j = Judge 'SingleFactorSuccess' 'AllUsers' (Evidence -Single @(Ev 'alice@contoso.test' 'a1' 'Browser' -Auth @()))
            $j.State | Should -Be 'Unknown'
            $j.Detail | Should -Match 'carried no authentication steps'
            $j2 = Judge 'SingleFactorSuccess' 'AllUsers' (Evidence -Single @((Ev 'alice@contoso.test' 'a1' 'Browser' -Auth @()), (Ev 'bob@contoso.test' 'b1' 'Browser')))
            $j2.State | Should -Be 'Ineffective'
            $j2.Detail | Should -Match 'bob@contoso\.test'
            $j2.Detail | Should -Not -Match 'alice@contoso\.test \('
        }

        It 'treats unread PIM eligibility as an incomplete holder list' {
            $ev = Evidence -Single @((Ev 'admin@contoso.test' 'a1' 'Browser'))
            $ev['AAD-DirectoryRoles'] = @{ Success = $true; Data = @{ SectionStatus = @{ RoleAssignments = 'Collected'; RoleEligibilitySchedules = 'Failed' }; AllPrivilegedAssignments = @(@{ PrincipalId = 'a1' }) } }
            (Judge 'SingleFactorSuccess' 'PrivilegedRoles' $ev).State | Should -Be 'Ineffective'
            $ev['AAD-DirectoryRoles'].Data.AllPrivilegedAssignments = @(@{ PrincipalId = 'zz' })
            $j = Judge 'SingleFactorSuccess' 'PrivilegedRoles' $ev
            $j.State | Should -Be 'Unknown'
            $j.Detail | Should -Match 'PIM-eligible'
        }

        It 'refuses a scope that does not belong to the check' {
            { Judge 'LegacyAuthSuccess' 'AllUsers' (Evidence) } | Should -Throw
            { Judge 'SingleFactorSuccess' 'Exchange' (Evidence) } | Should -Throw
        }
    }

    Context 'Baseline' {
        BeforeAll {
            $script:Def = & $script:Mod { Get-TPBaselineDefinition }
            $script:NoExc = @{ Available = $false; Path = ''; Entries = @(); Approved = @{}; Rejected = @(); EmergencyAccess = @{}; EmergencyAccessEntries = @(); EmergencyAccessRejected = @() }
        }

        It 'names sign-in evidence on exactly the five rows it can judge' {
            $rows = @($script:Def.Controls.Values | Where-Object { $_.EffectivenessCapability -eq 'Collected' })
            @($rows.ControlId | Sort-Object) | Should -Be @('AAD-1.2', 'CIS-5.2.2.1', 'CIS-5.2.2.3', 'EXO-1.6', 'SPO-1.3')
            $want = @{ 'AAD-1.2' = 'SingleFactorSuccess/AllUsers'; 'CIS-5.2.2.1' = 'SingleFactorSuccess/PrivilegedRoles'
                       'CIS-5.2.2.3' = 'LegacyAuthSuccess/All'; 'EXO-1.6' = 'LegacyAuthSuccess/Exchange'; 'SPO-1.3' = 'LegacyAuthSuccess/SharePoint' }
            foreach ($r in $rows) {
                $r.EffectivenessEvidence.Type | Should -Be 'SignInLog'
                "$($r.EffectivenessEvidence.Check)/$($r.EffectivenessEvidence.Scope)" | Should -Be $want[$r.ControlId]
            }
        }

        It 'never lists the evidence key as a row dependency, so an unread log cannot change ObservedState' {
            @($script:Def.Controls.Values | Where-Object { @($_.RawDataKeys) -contains 'AAD-SignInEvidence' }).Count | Should -Be 0
        }

        It 'says the operator skipped the sign-in evidence when -SkipSignInEvidence was recorded' {
            $finding = @{ ControlId = 'AAD-1.2'; State = 'Satisfied'; Detail = 'MFA required for all users.'; Timestamp = (Get-Date).ToUniversalTime().ToString('o') }
            $raw = @{ 'AAD-CAPolicies' = @{ Success = $true; Data = @{} } }
            $cov = @{ 'AAD-SignInEvidence' = @{ Status = 'Skipped'; Note = 'Skipped for this run with -SkipSignInEvidence.' } }
            $c = & $script:Mod { param($f, $r, $d, $x, $v) Get-TPBaselineCompliance -Findings @($f) -TargetTier Minimum -Definition $d -Exceptions $x -RawData $r -Coverage $v } $finding $raw $script:Def $script:NoExc $cov
            $row = @($c.Controls | Where-Object { $_.ControlId -eq 'AAD-1.2' })[0]
            $row.EffectivenessState | Should -Be 'Unknown'
            $row.EffectivenessDetail | Should -Match 'skipped by the operator'
            $plain = & $script:Mod { param($f, $r, $d, $x) Get-TPBaselineCompliance -Findings @($f) -TargetTier Minimum -Definition $d -Exceptions $x -RawData $r -Coverage @{} } $finding $raw $script:Def $script:NoExc
            $before = @($plain.Controls | Where-Object { $_.ControlId -eq 'AAD-1.2' })[0]
            $row.ObservedState | Should -Be $before.ObservedState -Because 'the evidence key is not a row dependency, so skipping it never changes the observed state'
            $row.ReasonCode | Should -Be $before.ReasonCode
        }

        It 'fills the effectiveness column and leaves the observed state alone' {
            $finding = @{ ControlId = 'AAD-1.2'; State = 'Satisfied'; Detail = 'MFA required for all users.'; Timestamp = (Get-Date).ToUniversalTime().ToString('o') }
            $rawBase = @{ 'AAD-CAPolicies' = @{ Success = $true; Data = @{} } }
            $rawWith = Evidence -Single @(Ev 'alice@contoso.test' 'a1' 'Browser')
            $rawWith['AAD-CAPolicies'] = $rawBase['AAD-CAPolicies']
            $run = {
                param($raw)
                & $script:Mod { param($f, $r, $d, $x) Get-TPBaselineCompliance -Findings @($f) -TargetTier Minimum -Definition $d -Exceptions $x -RawData $r -Coverage @{} } $finding $raw $script:Def $script:NoExc
            }
            $without = @((& $run $rawBase).Controls | Where-Object { $_.ControlId -eq 'AAD-1.2' })[0]
            $with    = @((& $run $rawWith).Controls | Where-Object { $_.ControlId -eq 'AAD-1.2' })[0]
            $without.EffectivenessState | Should -Be 'Unknown'
            $with.EffectivenessState | Should -Be 'Ineffective'
            $with.EffectivenessDetail | Should -Match 'alice@contoso\.test'
            $with.ObservedState | Should -Be $without.ObservedState
            $with.ReasonCode | Should -Be $without.ReasonCode
        }

        It 'accepts an exceptions object that carries no EmergencyAccess block' {
            $finding = @{ ControlId = 'AAD-1.2'; State = 'Satisfied'; Detail = 'MFA required for all users.'; Timestamp = (Get-Date).ToUniversalTime().ToString('o') }
            $raw = Evidence -Single @(Ev 'alice@contoso.test' 'a1' 'Browser')
            $older = @{ Available = $false; Approved = @{}; Rejected = @() }
            $c = & $script:Mod { param($f, $r, $d, $x) Get-TPBaselineCompliance -Findings @($f) -TargetTier Minimum -Definition $d -Exceptions $x -RawData $r -Coverage @{} } $finding $raw $script:Def $older
            @($c.Controls | Where-Object { $_.ControlId -eq 'AAD-1.2' })[0].EffectivenessState | Should -Be 'Ineffective'
        }
    }
}
