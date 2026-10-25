#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
#
# TP.EmergencyAccess.Tests.ps1
# TenantPosture
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# An exclusion is judged on whether it is approved, not on whether it exists
# (owner's 2026-10-15 decision). A Conditional Access control judged on combined
# coverage reports Partial when every qualifying policy excludes the same
# principals, which is how Microsoft says emergency-access accounts are set up.
# The tenant's EmergencyAccess record (Config/baseline-exceptions/<tenant>.psd1)
# is the approval: approved and current, it turns that Partial into Satisfied
# with the principals named; an account's name alone establishes nothing, one
# principal not on the record keeps the finding Partial, and a role is never
# approved. The pass judges structured AffectedObjects, never prose, and is
# idempotent on a republish.
#
# Dependencies: TenantPosture.psm1 (module under test)

Describe 'Approved emergency-access exclusions' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        function script:Bag([hashtable] $Data) { [ordered]@{ CollectorId = 'x'; CollectedAt = '2026-10-15T00:00:00Z'; Success = $true; Data = $Data } }
        function script:Pol {
            param([string] $Name = 'p', [string] $State = 'enabled', [string[]] $Users = @('All'), [string[]] $Groups = @(), [string[]] $Roles = @(),
                  [string[]] $ExUsers = @(), [string[]] $ExGroups = @(), [string[]] $ExRoles = @(), [string[]] $Apps = @('All'), [string[]] $ExApps = @(),
                  [string[]] $ClientApps = @('all'), [string[]] $Grant = @(), [string] $Op = 'OR', [string[]] $SignInRisk = @())
            @{ Id = $Name; DisplayName = $Name; State = $State
               Conditions = @{ ClientAppTypes = $ClientApps; SignInRiskLevels = $SignInRisk; UserRiskLevels = @(); AuthFlows = @(); Platforms = @(); ExcludePlatforms = @()
                               Users = @{ IncludeUsers = $Users; IncludeGroups = $Groups; IncludeRoles = $Roles; ExcludeUsers = $ExUsers; ExcludeGroups = $ExGroups; ExcludeRoles = $ExRoles }
                               Applications = @{ Include = $Apps; Exclude = $ExApps; UserActions = @() }
                               Locations = @{ Include = @(); Exclude = @() }; Devices = @{ FilterMode = ''; FilterRule = '' }; ClientApplications = @{ IncludeServicePrincipals = @() } }
               GrantControls = @{ Operator = $Op; BuiltInControls = $Grant; CustomControls = @(); AuthStrengthId = ''; AuthStrengthName = ''; AuthStrengthCombinations = @(); TermsOfUse = @() }
               SessionControls = @{} }
        }
        function script:Ca([object[]] $Policies) {
            Clear-TPState
            Set-TPRawData -Key 'AAD-CAPolicies' -Data (Bag @{ Policies = @($Policies); SectionStatus = @{ TokenProtection = 'Collected'; NamedLocations = 'Collected' } })
            Set-TPRawData -Key 'AAD-AuthPolicies' -Data (Bag @{ SecurityDefaults = @{ IsEnabled = $false } })
            $u = @(@{ Id = 'u-1'; UserPrincipalName = 'a@corp.example'; AccountEnabled = $true; UserType = 'Member' },
                   @{ Id = 'u-2'; UserPrincipalName = 'b@corp.example'; AccountEnabled = $true; UserType = 'Member' })
            $reg = @($u | ForEach-Object { @{ UserPrincipalName = $_.UserPrincipalName; IsMfaRegistered = $true } })
            Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = $u; MFARegistration = @{ RegistrationDetails = $reg }; SectionStatus = @{ MFARegistration = 'Collected' } })
            Set-TPRawData -Key 'Intune-DeviceCompliance' -Data (Bag @{ CompliancePolicies = @(); SectionStatus = @{ CompliancePolicies = 'Collected' } })
        }
        function script:V([string] $Fn, [string] $Cid) { & $Fn 3>$null | Out-Null; @(Get-TPFindings | Where-Object ControlId -eq $Cid)[0] }
        # One of the two members not registered for MFA (AAD-1.2 reports that beside enforcement).
        function script:Set-Unregistered {
            $u = @(@{ Id = 'u-1'; UserPrincipalName = 'a@corp.example'; AccountEnabled = $true; UserType = 'Member' },
                   @{ Id = 'u-2'; UserPrincipalName = 'b@corp.example'; AccountEnabled = $true; UserType = 'Member' })
            $reg = @(@{ UserPrincipalName = 'a@corp.example'; IsMfaRegistered = $true }, @{ UserPrincipalName = 'b@corp.example'; IsMfaRegistered = $false })
            Set-TPRawData -Key 'AAD-Users' -Data (Bag @{ Users = $u; MFARegistration = @{ RegistrationDetails = $reg }; SectionStatus = @{ MFARegistration = 'Collected' } })
        }
        function script:F([string] $Cid) { @(Get-TPFindings | Where-Object ControlId -eq $Cid)[0] }
        # Three controls from one policy set, each judged on combined coverage.
        function script:Evaluate([object[]] $Policies) {
            Ca $Policies
            & 'Test-TPControlAADMFA' 3>$null | Out-Null
            & 'Test-TPControlAADDeviceComplianceCA' 3>$null | Out-Null
            & 'Test-TPControlIntune' 3>$null | Out-Null
        }
        $script:U1 = '11111111-1111-1111-1111-111111111111'
        $script:U2 = '22222222-2222-2222-2222-222222222222'
        $script:G1 = '33333333-3333-3333-3333-333333333333'
        $script:Future = (Get-Date).AddMonths(6).ToString('yyyy-MM-dd')
        $script:Past   = (Get-Date).AddDays(-1).ToString('yyyy-MM-dd')
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-ea-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
        # One EmergencyAccess entry as PSD1 text; omit a field by passing ''.
        function script:Entry([string] $Id, [string] $Kind = 'User', [string] $Review = $script:Future, [string] $Approver = 'security@nrg.example', [string] $Upn = 'bg1@contoso.example', [string] $Expiry = '') {
            $lines = @("        @{", "            ObjectId = '$Id'")
            if ($Kind)     { $lines += "            Kind = '$Kind'" }
            if ($Upn)      { $lines += "            UserPrincipalName = '$Upn'" }
            $lines += "            Reason = 'Emergency access account per Microsoft guidance'"
            if ($Approver) { $lines += "            Approver = '$Approver'" }
            $lines += "            ApprovedDate = '2026-09-01'"
            if ($Review)   { $lines += "            ReviewDate = '$Review'" }
            if ($Expiry)   { $lines += "            ExpiryDate = '$Expiry'" }
            $lines += "        }"
            $lines -join "`n"
        }
        function script:Record([string[]] $Entries) {
            $p = Join-Path $script:Tmp ([guid]::NewGuid().ToString('N') + '.psd1')
            $text = "@{`n    Exceptions = @()`n    EmergencyAccess = @(`n$($Entries -join "`n")`n    )`n}`n"
            Set-Content -LiteralPath $p -Value $text -Encoding utf8
            $p
        }
        $script:Marker = & $script:Mod { $script:TPEmergencyAccessMarker }
    }
    AfterAll {
        Clear-TPState
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
        Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue
    }

    Context 'the record (Get-TPBaselineExceptions, EmergencyAccess block)' {
        It 'approves a user with every field and a future review date, keyed user:<id> in lower case' {
            $e = Get-TPBaselineExceptions -Path (Record @((Entry -Id $script:U1.ToUpperInvariant())))
            $e.Available | Should -BeTrue
            $e.EmergencyAccess.Count | Should -Be 1
            $e.EmergencyAccess.ContainsKey("user:$($script:U1)") | Should -BeTrue
            $e.EmergencyAccess["user:$($script:U1)"].Verdict | Should -Match '^Approved by security@nrg\.example on 2026-09-01; review by '
            @($e.EmergencyAccessRejected).Count | Should -Be 0
        }
        It 'approves a group (Kind = Group) keyed group:<id>' {
            $e = Get-TPBaselineExceptions -Path (Record @((Entry -Id $script:G1 -Kind 'Group' -Upn '')))
            $e.EmergencyAccess.ContainsKey("group:$($script:G1)") | Should -BeTrue
        }
        It 'rejects a lapsed review date, a missing approver, a non-GUID ObjectId, a Role kind and an expired entry, each with the reason' {
            $e = Get-TPBaselineExceptions -Path (Record @(
                (Entry -Id $script:U1 -Review $script:Past),
                (Entry -Id $script:U2 -Approver ''),
                (Entry -Id 'breakglass1'),
                (Entry -Id $script:G1 -Kind 'Role'),
                (Entry -Id '44444444-4444-4444-4444-444444444444' -Expiry $script:Past)))
            $e.EmergencyAccess.Count | Should -Be 0
            $v = @($e.EmergencyAccessRejected | ForEach-Object { $_.Verdict })
            $v.Count | Should -Be 5
            ($v -join "`n") | Should -Match 'review date .* has passed'
            ($v -join "`n") | Should -Match 'missing Approver'
            ($v -join "`n") | Should -Match "ObjectId 'breakglass1' is not an Entra object id"
            ($v -join "`n") | Should -Match "Kind 'Role' is not User or Group"
            ($v -join "`n") | Should -Match 'expired'
        }
        It 'rejects an approval date that is not a date or has not arrived (review finding: the record turns a shortfall into a pass)' {
            $txt = (Entry -Id $script:U1) -replace "ApprovedDate = '2026-09-01'", "ApprovedDate = 'next week'"
            $e = Get-TPBaselineExceptions -Path (Record @($txt))
            $e.EmergencyAccess.Count | Should -Be 0
            @($e.EmergencyAccessRejected)[0].Verdict | Should -Match "ApprovedDate 'next week' is not a date"
            $txt = (Entry -Id $script:U1) -replace "ApprovedDate = '2026-09-01'", "ApprovedDate = '$((Get-Date).AddDays(7).ToString('yyyy-MM-dd'))'"
            $e = Get-TPBaselineExceptions -Path (Record @($txt))
            $e.EmergencyAccess.Count | Should -Be 0
            @($e.EmergencyAccessRejected)[0].Verdict | Should -Match 'approval date .* is in the future'
        }
        It 'a file without the block reads as no approvals, not an error' {
            $p = Join-Path $script:Tmp 'plain.psd1'
            Set-Content -LiteralPath $p -Value "@{ Exceptions = @() }" -Encoding utf8
            $e = Get-TPBaselineExceptions -Path $p
            $e.Available | Should -BeTrue
            $e.EmergencyAccess.Count | Should -Be 0
            @($e.EmergencyAccessEntries).Count | Should -Be 0
        }
    }

    Context 'the pass (Set-TPEmergencyAccessApproval)' {
        It 'a coverage finding carries its shared exclusions as structured AffectedObjects, never only as prose' {
            Evaluate @((Pol -Name 'MFA' -Grant @('mfa') -ExUsers @($script:U1)), (Pol -Name 'Device' -Grant @('compliantDevice') -ExUsers @($script:U1)))
            foreach ($cid in @('AAD-1.2', 'AAD-2.3', 'INT-1.2')) {
                $f = F $cid
                $f.State | Should -Be 'Partial' -Because "${cid}: a shared exclusion is a shortfall until approved"
                @($f.AffectedObjects).Count | Should -Be 1
                [string](Get-TPObjectField -Item @($f.AffectedObjects)[0] -Key 'Principal') | Should -Be "user:$($script:U1)"
                [string](Get-TPObjectField -Item @($f.AffectedObjects)[0] -Key 'Exclusion') | Should -Be 'SharedByEveryQualifyingPolicy'
            }
        }
        It 'every excluded principal on the current record: Partial becomes Satisfied, prefixed, naming the account, the original result kept and the exclusion still listed' {
            Evaluate @((Pol -Name 'MFA' -Grant @('mfa') -ExUsers @($script:U1)), (Pol -Name 'Device' -Grant @('compliantDevice') -ExUsers @($script:U1)))
            $n = Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1 -Upn 'bg1@contoso.example')))
            $n | Should -Be 3
            foreach ($cid in @('AAD-1.2', 'AAD-2.3', 'INT-1.2')) {
                $f = F $cid
                $f.State    | Should -Be 'Satisfied'
                $f.Severity | Should -Be 'Informational'
                $f.Detail   | Should -Match "^$([regex]::Escape($script:Marker)) 1 principal\(s\) excluded from every qualifying policy are on this tenant's current approval record \(Approved by security@nrg\.example on 2026-09-01; review by \d{4}-\d{2}-\d{2}\.\): user:$($script:U1) \(bg1@contoso\.example\)\."
                $f.Detail   | Should -Match 'permitted deviation, not coverage'
                $f.Detail   | Should -Match 'Result before the approval record was applied: Partial\. .*Shortfall: every qualifying policy excludes the same principal'
                $f.CurrentValue | Should -Match 'approved emergency-access exceptions: 1$'
                @($f.AffectedObjects).Count | Should -Be 1 -Because 'the excluded principal stays listed'
            }
        }
        It 'one principal not on the record keeps the finding Partial and names both answers' {
            Evaluate @((Pol -Name 'Device' -Grant @('compliantDevice') -ExUsers @($script:U1, $script:U2)))
            $n = Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1)))
            $n | Should -Be 0
            $f = F 'AAD-2.3'
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match "Approval record: approved emergency-access exception\(s\): user:$($script:U1) \(bg1@contoso\.example\)\. Not approved: user:$($script:U2) \(not on the approval record\)\."
        }
        It 'a lapsed approval keeps the finding Partial and names the lapse' {
            Evaluate @((Pol -Name 'Device' -Grant @('compliantDevice') -ExUsers @($script:U1)))
            $n = Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1 -Review $script:Past)))
            $n | Should -Be 0
            (F 'AAD-2.3').Detail | Should -Match "Not approved: user:$($script:U1) \(Not approved: review date .* has passed"
        }
        It 'a group approval is honored and the finding says membership was not resolved' {
            Evaluate @((Pol -Name 'Device' -Grant @('compliantDevice') -ExGroups @($script:G1)))
            $n = Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:G1 -Kind 'Group' -Upn '')))
            $n | Should -Be 2
            $f = F 'INT-1.2'
            $f.State  | Should -Be 'Satisfied'
            $f.Detail | Should -Match 'A group approval attests that the group holds only emergency-access accounts; the assessment did not resolve its membership'
        }
        It 'a role exclusion is never approved' {
            Evaluate @((Pol -Name 'Device' -Grant @('compliantDevice') -ExRoles @($script:G1)))
            $n = Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:G1 -Kind 'User' -Upn '')))
            $n | Should -Be 0
            $f = F 'AAD-2.3'
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match "role:$($script:G1) \(a role is never an emergency-access principal\)"
        }
        It 'a narrowed policy (Gap) and different exclusions (not assessed) are never touched' {
            Evaluate @((Pol -Name 'Device' -Grant @('compliantDevice') -ExUsers @($script:U1) -ExApps @('app-1')))
            (F 'AAD-2.3').State | Should -Be 'Gap'
            (Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1)))) | Should -Be 0
            (F 'AAD-2.3').State | Should -Be 'Gap'
            Evaluate @((Pol -Name 'a' -Grant @('compliantDevice') -ExUsers @($script:U1)), (Pol -Name 'b' -Grant @('compliantDevice') -ExUsers @($script:U2)))
            (F 'AAD-2.3').State | Should -Be 'NotApplicable'
            (Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1), (Entry -Id $script:U2)))) | Should -Be 0
            (F 'AAD-2.3').State | Should -Be 'NotApplicable' -Because 'different exclusions are unproven coverage, which no approval resolves'
        }
        It 'a second run re-derives the same result: the prefix appears once and the count is the same' {
            Evaluate @((Pol -Name 'Device' -Grant @('compliantDevice') -ExUsers @($script:U1)))
            $rec = Record @((Entry -Id $script:U1))
            (Set-TPEmergencyAccessApproval -Path $rec) | Should -Be 2
            $first = (F 'INT-1.2').Detail
            (Set-TPEmergencyAccessApproval -Path $rec) | Should -Be 2
            (F 'INT-1.2').Detail | Should -Be $first
            ([regex]::Matches((F 'INT-1.2').Detail, [regex]::Escape($script:Marker))).Count | Should -Be 1
        }
        It 'an approval that lapsed, or a record that was removed, undoes an earlier run''s approval on a republish (review finding)' {
            Evaluate @((Pol -Name 'Device' -Grant @('compliantDevice') -ExUsers @($script:U1)))
            $original = (F 'AAD-2.3').Detail; $originalCv = (F 'AAD-2.3').CurrentValue
            (Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1)))) | Should -Be 2
            (F 'AAD-2.3').State | Should -Be 'Satisfied'
            # The same findings, replayed against a record whose review date has passed.
            $replay = @((Get-TPFindings | ConvertTo-Json -Depth 12) | ConvertFrom-Json)
            (Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1 -Review $script:Past))) -Findings $replay) | Should -Be 0
            $f = @($replay | Where-Object { $_.ControlId -eq 'AAD-2.3' })[0]
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'Not approved: user:.* review date .* has passed'
            $f.Detail | Should -Not -Match [regex]::Escape($script:Marker)
            # Replayed against no record at all: back to the plain pre-approval finding.
            $replay = @((Get-TPFindings | ConvertTo-Json -Depth 12) | ConvertFrom-Json)
            (Set-TPEmergencyAccessApproval -TenantDomain 'no-such-tenant.example' -Findings $replay) | Should -Be 0
            $f = @($replay | Where-Object { $_.ControlId -eq 'AAD-2.3' })[0]
            $f.State        | Should -Be 'Partial'
            $f.Severity     | Should -Be 'Medium'
            $f.Detail       | Should -Be $original
            $f.CurrentValue | Should -Be $originalCv
            # A partly-approved note from an earlier run is replaced, never stacked.
            Evaluate @((Pol -Name 'Device' -Grant @('compliantDevice') -ExUsers @($script:U1, $script:U2)))
            $rec1 = Record @((Entry -Id $script:U1))
            (Set-TPEmergencyAccessApproval -Path $rec1) | Should -Be 0
            (F 'AAD-2.3').Detail | Should -Match "Not approved: user:$($script:U2)"
            (Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1), (Entry -Id $script:U2 -Upn 'bg2@contoso.example')))) | Should -Be 2
            (F 'AAD-2.3').State  | Should -Be 'Satisfied'
            ([regex]::Matches((F 'AAD-2.3').Detail, 'Approval record:')).Count | Should -Be 0
        }
        It 'an approved exclusion beside another shortfall never makes the finding Satisfied: AAD-1.2 with an unregistered user, AAD-1.4 with no medium-risk policy (review finding)' {
            Ca @(Pol -Name 'MFA' -Grant @('mfa') -ExUsers @($script:U1)); Set-Unregistered
            $f = V 'Test-TPControlAADMFA' 'AAD-1.2'
            $f.State | Should -Be 'Partial'
            @($f.AffectedObjects | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Shortfall' -Default '') }).Count | Should -Be 1 -Because 'the registration shortfall is recorded beside the exclusion'
            (Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1)))) | Should -Be 0
            $f = F 'AAD-1.2'
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'Approval record: approved emergency-access exception\(s\): user:.* The finding has 1 other shortfall\(s\) besides the exclusion, so it stays Partial'
            Ca @(Pol -Name 'High risk' -Grant @('mfa') -SignInRisk @('high') -ExUsers @($script:U1))
            $f = V 'Test-TPControlAADSignInRisk' 'AAD-1.4'
            $f.State | Should -Be 'Partial'
            (Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1)))) | Should -Be 0
            (F 'AAD-1.4').State  | Should -Be 'Partial'
            (F 'AAD-1.4').Detail | Should -Match 'other shortfall'
            # With both levels covered the same exclusion is the only shortfall and is approved.
            Ca @((Pol -Name 'High risk' -Grant @('mfa') -SignInRisk @('high') -ExUsers @($script:U1)), (Pol -Name 'Medium risk' -Grant @('mfa') -SignInRisk @('medium') -ExUsers @($script:U1)))
            (V 'Test-TPControlAADSignInRisk' 'AAD-1.4').State | Should -Be 'Partial'
            (Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1)))) | Should -Be 1
            (F 'AAD-1.4').State | Should -Be 'Satisfied'
        }
        It 'an approved exclusion beside a component that was not established never makes the finding Satisfied (review finding: AAD-1.3 with the role catalog unread)' {
            Clear-TPState
            $ctrl = [pscustomobject]@{ Category = 'Identity'; Title = 'T'; Severity = 'High'; Remediation = 'r' }
            $cov = [ordered]@{ Kind = 'Exceptions'; Names = @('p'); FullNames = @(); Exceptions = @("user:$($script:U1)"); ExcludedBy = [ordered]@{ p = @("user:$($script:U1)") }; Narrowed = @() }
            $cv = & $script:Mod { param($c) Get-TPCACoverageVerdict -Coverage $c -What 'MFA is required' } $cov
            $u = @($cv.NotEstablished) + "whether p covers every privileged role, because this tenant's role catalog was not read."
            Add-TPExpectedStateFinding -ControlId 'AAD-1.3' -Control $ctrl -FrameworkIds @() -Verified $cv.Verified -Shortfalls $cv.Shortfalls -NotEstablished $u -AffectedObjects $cv.AffectedObjects
            $f = F 'AAD-1.3'
            $f.State | Should -Be 'Partial'
            @($f.AffectedObjects | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'NotEstablished' -Default '') }).Count | Should -Be 1
            (Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1)))) | Should -Be 0
            $f = F 'AAD-1.3'
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'Approval record: approved emergency-access exception\(s\): user:.* The finding has 1 component\(s\) that were not assessed, so an approval cannot make it a pass'
        }
        It 'tenant text that contains the words of the note is never cut out, and a finding without this pass''s exclusions is never touched (review finding)' {
            # A policy named with the note's own words appears in the coverage detail.
            Evaluate @((Pol -Name 'Approval record: Primary policy' -Grant @('compliantDevice') -ExUsers @($script:U1)))
            $original = (F 'AAD-2.3').Detail
            $original | Should -Match 'Approval record: Primary policy'
            $rec = Record @((Entry -Id $script:U1))
            (Set-TPEmergencyAccessApproval -Path $rec) | Should -Be 2
            (F 'AAD-2.3').Detail | Should -Match 'Result before the approval record was applied: Partial\. .*Approval record: Primary policy'
            (Set-TPEmergencyAccessApproval -TenantDomain 'no-such-tenant.example') | Should -Be 0
            (F 'AAD-2.3').Detail | Should -Be $original -Because 'the restore keeps the policy name intact'
            # Partly approved: the note is appended once and the policy name survives a second run.
            Evaluate @((Pol -Name 'Approval record: Primary policy' -Grant @('compliantDevice') -ExUsers @($script:U1, $script:U2)))
            (Set-TPEmergencyAccessApproval -Path $rec) | Should -Be 0
            (Set-TPEmergencyAccessApproval -Path $rec) | Should -Be 0
            $d = (F 'AAD-2.3').Detail
            ([regex]::Matches($d, 'Approval record: Primary policy')).Count | Should -Be 1
            ([regex]::Matches($d, 'Approval record: approved emergency-access exception')).Count | Should -Be 1
            # No exclusions at all (an OR grant): the finding is Partial and carries the words, and is left alone.
            Evaluate @((Pol -Name 'Approval record: Primary policy' -Grant @('compliantDevice', 'mfa') -Op 'OR'))
            $before = (F 'AAD-2.3').Detail
            (F 'AAD-2.3').State | Should -Be 'Partial'
            (Set-TPEmergencyAccessApproval -Path $rec) | Should -Be 0
            (F 'AAD-2.3').Detail | Should -Be $before
        }
        It 'exclusions the policies do not share stay a blocker: a shared approved principal beside differing group exclusions is never a pass (review finding)' {
            Evaluate @((Pol -Name 'A' -Grant @('compliantDevice') -ExUsers @($script:U1) -ExGroups @('g-h1')), (Pol -Name 'B' -Grant @('compliantDevice') -ExUsers @($script:U1) -ExGroups @('g-h2')))
            $f = F 'AAD-2.3'
            $f.State  | Should -Be 'Partial'
            $f.Detail | Should -Match 'Not assessed: whether any further user is excluded from every one of these policies through the exclusions they do not share.*A also excludes 1; B also excludes 1'
            @($f.AffectedObjects | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'NotEstablished' -Default '') }).Count | Should -Be 1
            (Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1)))) | Should -Be 0
            (F 'AAD-2.3').State  | Should -Be 'Partial'
            (F 'AAD-2.3').Detail | Should -Match 'component\(s\) that were not assessed, so an approval cannot make it a pass'
            # The same two policies excluding only the shared principal are approvable.
            Evaluate @((Pol -Name 'A' -Grant @('compliantDevice') -ExUsers @($script:U1)), (Pol -Name 'B' -Grant @('compliantDevice') -ExUsers @($script:U1)))
            (Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1)))) | Should -Be 2
        }
        It 'a Partial that license gating wrapped in the results file is unwrapped before the record is applied, so a republish answers as a live run (review finding)' {
            Evaluate @((Pol -Name 'Device' -Grant @('compliantDevice') -ExUsers @($script:U1)))
            $f = F 'INT-1.2'
            $orig = $f.Detail
            # The shape Set-TPLicenseGating writes for an unlicensed control.
            $f.State = 'NotApplicable'; $f.Detail = "Not scored: this control requires M365 Business Premium or Intune Plan 1, which this tenant does not hold — upgrade opportunity, not counted against the score. Result before the license check: Partial — $orig"; $f.CurrentValue = 'Requires M365 Business Premium or Intune Plan 1 (not licensed)'
            $replay = @((Get-TPFindings | ConvertTo-Json -Depth 12) | ConvertFrom-Json)
            (Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1))) -Findings $replay) | Should -BeGreaterOrEqual 1
            $g = @($replay | Where-Object { $_.ControlId -eq 'INT-1.2' })[0]
            $g.State  | Should -Be 'Satisfied'
            $g.Detail | Should -Match "Result before the approval record was applied: Partial\. $([regex]::Escape($orig))$"
            $g.CurrentValue | Should -Be 'Approved emergency-access exceptions: 1'
            # Without a record the wrapper is unwrapped to its Partial, which gating re-wraps afterwards on the entry point.
            $replay = @((Get-TPFindings | ConvertTo-Json -Depth 12) | ConvertFrom-Json)
            (Set-TPEmergencyAccessApproval -TenantDomain 'no-such-tenant.example' -Findings $replay) | Should -Be 0
            $g = @($replay | Where-Object { $_.ControlId -eq 'INT-1.2' })[0]
            $g.State | Should -Be 'Partial'
            $g.Detail | Should -Be $orig
        }
        It 'editing a baseline exception keeps the emergency-access block (New, Set and Remove write it back as read; review finding)' {
            $rec = Record @((Entry -Id $script:U1 -Upn 'bg1@contoso.example'), (Entry -Id $script:U2 -Review $script:Past))
            $future = (Get-Date).AddMonths(3)
            $null = New-TPBaselineException -TenantDomain contoso.example -ControlId 'AAD-1.2' -Reason 'r' -CompensatingControl 'c' -Approver 'a@nrg.example' -ReviewDate $future -Path $rec -Confirm:$false
            $e = Get-TPBaselineExceptions -Path $rec
            $e.Approved.ContainsKey('AAD-1.2') | Should -BeTrue
            @($e.EmergencyAccessEntries).Count | Should -Be 2 -Because 'both entries, the lapsed one included, are written back as read'
            $e.EmergencyAccess.ContainsKey("user:$($script:U1)") | Should -BeTrue
            $e.EmergencyAccess["user:$($script:U1)"].UserPrincipalName | Should -Be 'bg1@contoso.example'
            $null = Set-TPBaselineException -TenantDomain contoso.example -ControlId 'AAD-1.2' -Reason 'changed' -Path $rec -Confirm:$false
            @((Get-TPBaselineExceptions -Path $rec).EmergencyAccessEntries).Count | Should -Be 2
            $null = Remove-TPBaselineException -TenantDomain contoso.example -ControlId 'AAD-1.2' -Path $rec -Confirm:$false
            $e = Get-TPBaselineExceptions -Path $rec
            @($e.Entries).Count | Should -Be 0
            @($e.EmergencyAccessEntries).Count | Should -Be 2
            # The written block is data only and re-reads to the same approval.
            (Set-TPEmergencyAccessApproval -Path $rec -Findings @()) | Should -Be 0
        }
        It 'rewrites findings replayed from a results file (JSON round trip) the same way' {
            Evaluate @((Pol -Name 'Device' -Grant @('compliantDevice') -ExUsers @($script:U1)))
            $replay = @((Get-TPFindings | ConvertTo-Json -Depth 12) | ConvertFrom-Json)
            $target = @($replay | Where-Object { $_.ControlId -eq 'AAD-2.3' })[0]
            $target.State | Should -Be 'Partial'
            (Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1))) -Findings $replay) | Should -Be 2
            $target.State  | Should -Be 'Satisfied'
            $target.Detail | Should -Match "^$([regex]::Escape($script:Marker))"
        }
        It 'with no record file nothing changes' {
            Evaluate @((Pol -Name 'Device' -Grant @('compliantDevice') -ExUsers @($script:U1)))
            (Set-TPEmergencyAccessApproval -TenantDomain 'no-such-tenant.example') | Should -Be 0
            (F 'AAD-2.3').State  | Should -Be 'Partial'
            (F 'AAD-2.3').Detail | Should -Not -Match 'Approval record:'
        }
        It 'AAD-11.1 (device code block) with a shared exclusion is approved the same way' {
            $p = Pol -Name 'Block device code' -Grant @('block') -ExUsers @($script:U1)
            $p.Conditions.AuthFlows = @(@{ transferMethods = 'deviceCodeFlow' })
            Ca @($p)
            (V 'Test-TPControlAADDeviceCode' 'AAD-11.1').State | Should -Be 'Partial'
            (Set-TPEmergencyAccessApproval -Path (Record @((Entry -Id $script:U1)))) | Should -Be 1
            (F 'AAD-11.1').State | Should -Be 'Satisfied'
        }
    }

    Context 'entry point' {
        It 'runs the pass on both the live and the -FromResults path, after the declarations and before license gating' {
            $text = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-TPAssessment.ps1') -Raw -Encoding utf8
            $calls = [regex]::Matches($text, 'Set-TPEmergencyAccessApproval -TenantDomain')
            $calls.Count | Should -Be 2
            foreach ($m in $calls) {
                $gate = $text.IndexOf('Set-TPLicenseGating', $m.Index)
                $gate | Should -BeGreaterThan $m.Index -Because 'an approved exception is applied before license gating'
                $awareness = $text.LastIndexOf('Set-TPThirdPartyAwareness', $m.Index)
                $awareness | Should -BeGreaterThan 0
                ($m.Index - $awareness) | Should -BeLessThan 1200 -Because 'it sits with the other post-evaluation passes'
            }
            $text | Should -Match '\$conn\.TenantDomain\)' -Because 'the live path reads the CONNECTED tenant'
            $text | Should -Match 'Set-TPEmergencyAccessApproval -TenantDomain \(\[string\]\$reportMetadata\.TenantDomain\) -Findings \$findings'
        }
    }
}
