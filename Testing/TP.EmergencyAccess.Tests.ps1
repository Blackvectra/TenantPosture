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
                  [string[]] $ClientApps = @('all'), [string[]] $Grant = @(), [string] $Op = 'OR')
            @{ Id = $Name; DisplayName = $Name; State = $State
               Conditions = @{ ClientAppTypes = $ClientApps; SignInRiskLevels = @(); UserRiskLevels = @(); AuthFlows = @(); Platforms = @(); ExcludePlatforms = @()
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
        It 'is idempotent: a second run changes nothing and the prefix appears once' {
            Evaluate @((Pol -Name 'Device' -Grant @('compliantDevice') -ExUsers @($script:U1)))
            $rec = Record @((Entry -Id $script:U1))
            (Set-TPEmergencyAccessApproval -Path $rec) | Should -Be 2
            (Set-TPEmergencyAccessApproval -Path $rec) | Should -Be 0
            ([regex]::Matches((F 'INT-1.2').Detail, [regex]::Escape($script:Marker))).Count | Should -Be 1
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
