#Requires -Version 7.0
#
# TP.CAChecklist.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Guards the Conditional Access checklist (Lib/Get-TPCAChecklist.ps1,
# Publishers/Publish-TPCAChecklist.ps1, Config/ca-checklist.json), the What If
# simulation (Lib/Invoke-TPCAWhatIf.ps1, Collectors/AAD/Invoke-TPCollectAADCAWhatIf.ps1)
# and the referenced-object read in the CA collector:
#   - the catalog: unique ids, a rule for every presence check, Microsoft
#     Learn sources, known license strings, report-only templates
#   - the Maester port: each presence rule passes on Maester's pattern and is
#     "Report-only" when only a report-only policy matches; a disabled policy
#     never counts
#   - hygiene: break-glass exclusions from the approved record, deleted objects
#     (404 only), unprotected groups, exclusions without a fallback (approved
#     emergency access not counted), retired grant, untargeted policies,
#     Microsoft-managed policies in report-only, combined risk, device
#     registration conflict, sync accounts
#   - simulation: an enabled block passes, a report-only block is named, a
#     break-glass account reached by a policy fails, no record is not assessed
#   - not read is "Not assessed", never passed or failed
#   - the report-only files: state, exclusions, no unexpanded token
#   - the one POST: only Invoke-TPCAWhatIfEvaluation posts, to a constant URI,
#     from validated ids; Invoke-TPGraphRequest stays GET-only
#   - the report never says "compliant", escapes, loads nothing
# Data keys consumed: synthetic raw data only. Graph scopes / cmdlets: none.

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    $script:Mod = Get-Module 'TenantPosture'
    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('tp-cac-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    $null = New-Item -ItemType Directory -Path $script:Tmp -Force
    $script:Catalog = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/ca-checklist.json') -Raw | ConvertFrom-Json -AsHashtable
    $script:BreakGlass = '99999999-9999-9999-9999-999999999999'
    $script:Ea = @{ EmergencyAccess = @{ "user:$($script:BreakGlass)" = 1 } }
    $script:AdminRoles = @($script:Catalog.adminRoles | ForEach-Object { $_.Id })

    # One projected policy, in the shape Invoke-TPCollectAADCAPolicies stores.
    $script:Pol = {
        param([string] $Name, [string] $State = 'enabled', [hashtable] $Over = @{})
        $p = @{
            Id = [guid]::NewGuid().ToString(); DisplayName = $Name; State = $State
            Conditions = @{
                ClientAppTypes = @('all'); SignInRiskLevels = @(); UserRiskLevels = @(); AuthFlows = @(); Platforms = @(); ExcludePlatforms = @()
                Locations = @{ Include = @(); Exclude = @() }
                Users = @{ IncludeUsers = @('All'); ExcludeUsers = @($script:BreakGlass); IncludeGroups = @(); ExcludeGroups = @(); IncludeRoles = @(); ExcludeRoles = @(); IncludeGuestsOrExternalUsers = $null; ExcludeGuestsOrExternalUsers = $null }
                Applications = @{ Include = @('All'); Exclude = @(); UserActions = @(); AuthenticationContext = @(); ApplicationFilterPresent = $false }
                Devices = @{ FilterMode = ''; FilterRule = '' }
                ClientApplications = @{ IncludeServicePrincipals = @(); ExcludeServicePrincipals = @() }
                AgentIdRiskLevels = @()
            }
            GrantControls = @{ Operator = 'OR'; BuiltInControls = @('mfa'); CustomControls = @(); AuthStrengthId = ''; AuthStrengthRequirementsSatisfied = '' }
            SessionControls = @{ SignInFrequency = $null; PersistentBrowser = $null; ApplicationEnforcedRestrictions = $null }
        }
        foreach ($k in $Over.Keys) {
            $parts = $k -split '\.'
            $node = $p
            for ($i = 0; $i -lt $parts.Count - 1; $i++) { $node = $node[$parts[$i]] }
            $node[$parts[-1]] = $Over[$k]
        }
        $p
    }
    $script:Raw = {
        param([object[]] $Policies, [hashtable] $Extra = @{}, [object[]] $Objects = @(), [string] $RefStatus = 'Collected')
        $r = @{ 'AAD-CAPolicies' = @{ Success = $true; Data = @{ Policies = @($Policies); NamedLocations = @(); SectionStatus = @{ ReferencedObjects = $RefStatus; PolicyCompleteness = 'Collected' }; ReferencedObjects = @{ Objects = @($Objects) } } } }
        foreach ($k in $Extra.Keys) { $r[$k] = $Extra[$k] }
        $r
    }
    $script:Row = { param($View, [string] $Id) @($View.Rows | Where-Object { $_.Id -eq $Id })[0] }
    $script:Check = { param([object[]] $Policies, [string] $Id, [hashtable] $Extra = @{}) & $script:Row (Get-TPCAChecklist -RawData (& $script:Raw $Policies $Extra) -EmergencyAccessRecord $script:Ea) $Id }
}

AfterAll {
    if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'The checklist catalog' {
    It 'has unique ids, a known kind, a Microsoft Learn source and a license string the profile helper understands' {
        $plans = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/license-service-plans.json') -Raw | ConvertFrom-Json
        $reqKeys = @($plans.requirements.PSObject.Properties.Name)
        $ids = @($script:Catalog.checks | ForEach-Object { $_.Id })
        ($ids | Sort-Object -Unique).Count | Should -Be $ids.Count
        foreach ($c in $script:Catalog.checks) {
            $c.Kind | Should -BeIn @('Presence', 'Hygiene', 'Simulation')
            $c.SourceUrl | Should -Match '\Ahttps://learn\.microsoft\.com/'
            $reqKeys | Should -Contain $c.LicenseRequirement
            $c.Severity | Should -BeIn @('High', 'Medium', 'Low')
            if ($c.Template) { $script:Catalog.templates.Keys | Should -Contain $c.Template }
        }
    }

    It 'follows Maester test ids, and covers the presence, hygiene and What If tests' {
        $ids = @($script:Catalog.checks | ForEach-Object { $_.Id })
        foreach ($want in 'MT.1001', 'MT.1003', 'MT.1004', 'MT.1005', 'MT.1006', 'MT.1007', 'MT.1008', 'MT.1009', 'MT.1010', 'MT.1011', 'MT.1012', 'MT.1013', 'MT.1014', 'MT.1015', 'MT.1016', 'MT.1017', 'MT.1018', 'MT.1019', 'MT.1020', 'MT.1033', 'MT.1034', 'MT.1035', 'MT.1036', 'MT.1038', 'MT.1049', 'MT.1052', 'MT.1061', 'MT.1066', 'MT.1072', 'MT.1181', 'MT.1184', 'MT.1224') {
            $ids | Should -Contain $want
        }
    }

    It 'every template is a report-only policy with a Microsoft Learn source' {
        foreach ($k in $script:Catalog.templates.Keys) {
            $t = $script:Catalog.templates[$k]
            $t.SourceUrl | Should -Match '\Ahttps://learn\.microsoft\.com/'
            $t.Policy.state | Should -Be 'enabledForReportingButNotEnforced'
            $t.Policy.displayName | Should -Not -BeNullOrEmpty
            ($null -ne $t.Policy.grantControls -or $null -ne $t.Policy.sessionControls) | Should -BeTrue
        }
    }

    It 'lists the 14 administrator roles Maester and Microsoft name, as role template ids' {
        $script:AdminRoles.Count | Should -Be 14
        $script:AdminRoles | Should -Contain '62e90394-69f5-4237-9190-012177145e10'
        foreach ($r in $script:AdminRoles) { $r | Should -Match '\A[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\z' }
    }
}

Describe 'Presence rows: the Maester port' {
    It 'MFA for all users passes on an enabled all-users all-resources MFA policy' {
        (& $script:Check @((& $script:Pol 'MFA all')) 'MT.1007').Status | Should -Be 'Pass'
    }
    It 'a disabled policy never counts, a report-only one is named "Report-only"' {
        (& $script:Check @((& $script:Pol 'MFA all' 'disabled')) 'MT.1007').Status | Should -Be 'Fail'
        $row = & $script:Check @((& $script:Pol 'MFA all' 'enabledForReportingButNotEnforced')) 'MT.1007'
        $row.Status | Should -Be 'Staged'
        $row.Detail | Should -Match 'report-only'
        $row.StatusLabel | Should -Be 'Report-only'
    }
    It 'a risk-only MFA policy does not count as MFA for all users (Maester removes them)' {
        (& $script:Check @((& $script:Pol 'Risky' 'enabled' @{ 'Conditions.SignInRiskLevels' = @('high') })) 'MT.1007').Status | Should -Be 'Fail'
    }
    It 'an authentication strength counts as MFA' {
        (& $script:Check @((& $script:Pol 'Strength' 'enabled' @{ 'GrantControls.BuiltInControls' = @(); 'GrantControls.AuthStrengthId' = '00000000-0000-0000-0000-000000000002'; 'GrantControls.AuthStrengthRequirementsSatisfied' = 'mfa' })) 'MT.1007').Status | Should -Be 'Pass'
    }
    It 'MFA for admins needs every one of the 14 roles, and none excluded' {
        $some = & $script:Pol 'Admins' 'enabled' @{ 'Conditions.Users.IncludeUsers' = @(); 'Conditions.Users.IncludeRoles' = @($script:AdminRoles | Select-Object -First 13) }
        (& $script:Check @($some) 'MT.1006').Status | Should -Be 'Fail'
        $all = & $script:Pol 'Admins' 'enabled' @{ 'Conditions.Users.IncludeUsers' = @(); 'Conditions.Users.IncludeRoles' = $script:AdminRoles }
        (& $script:Check @($all) 'MT.1006').Status | Should -Be 'Pass'
        $excl = & $script:Pol 'All but GA' 'enabled' @{ 'Conditions.Users.ExcludeRoles' = @('62e90394-69f5-4237-9190-012177145e10') }
        (& $script:Check @($excl) 'MT.1006').Status | Should -Be 'Fail'
    }
    It 'block legacy needs block, the Other clients type, all users and all resources' {
        $legacy = & $script:Pol 'Legacy' 'enabled' @{ 'GrantControls.BuiltInControls' = @('block'); 'Conditions.ClientAppTypes' = @('exchangeActiveSync', 'other') }
        (& $script:Check @($legacy) 'MT.1009').Status | Should -Be 'Pass'
        (& $script:Check @($legacy) 'MT.1010').Status | Should -Be 'Pass'
        $mfaOnly = & $script:Pol 'Legacy MFA' 'enabled' @{ 'Conditions.ClientAppTypes' = @('exchangeActiveSync', 'other') }
        (& $script:Check @($mfaOnly) 'MT.1009').Status | Should -Be 'Fail'
    }
    It 'device code needs the flow condition, all users, all client apps, and block or a managed device' {
        $dc = & $script:Pol 'Device code' 'enabled' @{ 'GrantControls.BuiltInControls' = @('block'); 'Conditions.AuthFlows' = @(@{ transferMethods = 'deviceCodeFlow' }) }
        (& $script:Check @($dc) 'MT.1052').Status | Should -Be 'Pass'
        $mfa = & $script:Pol 'Device code MFA' 'enabled' @{ 'Conditions.AuthFlows' = @(@{ transferMethods = 'deviceCodeFlow' }) }
        (& $script:Check @($mfa) 'MT.1052').Status | Should -Be 'Fail'
    }
    It 'security info registration needs the user action, all locations and a trusted exclusion' {
        $sec = & $script:Pol 'Sec info' 'enabled' @{ 'Conditions.Applications.Include' = @(); 'Conditions.Applications.UserActions' = @('urn:user:registersecurityinfo'); 'Conditions.Locations' = @{ Include = @('All'); Exclude = @('AllTrusted') } }
        (& $script:Check @($sec) 'MT.1011').Status | Should -Be 'Pass'
        $sec.Conditions.Locations.Exclude = @('11111111-1111-1111-1111-111111111111')
        (& $script:Check @($sec) 'MT.1011').Status | Should -Be 'Fail'
    }
    It 'risk rows read the levels Maester reads' {
        $si = & $script:Pol 'Sign-in risk' 'enabled' @{ 'Conditions.SignInRiskLevels' = @('high', 'medium') }
        (& $script:Check @($si) 'MT.1012').Status | Should -Be 'Pass'
        $siHigh = & $script:Pol 'Sign-in risk high' 'enabled' @{ 'Conditions.SignInRiskLevels' = @('high') }
        (& $script:Check @($siHigh) 'MT.1012').Status | Should -Be 'Fail'
        $ur = & $script:Pol 'User risk' 'enabled' @{ 'Conditions.UserRiskLevels' = @('high'); 'GrantControls.BuiltInControls' = @('mfa', 'passwordChange'); 'GrantControls.Operator' = 'AND' }
        (& $script:Check @($ur) 'MT.1013').Status | Should -Be 'Pass'
    }
    It 'admin device compliance needs the device control without an MFA alternative' {
        $dev = & $script:Pol 'Admin device' 'enabled' @{ 'Conditions.Users.IncludeUsers' = @(); 'Conditions.Users.IncludeRoles' = $script:AdminRoles; 'GrantControls.BuiltInControls' = @('compliantDevice', 'domainJoinedDevice') }
        (& $script:Check @($dev) 'MT.1014').Status | Should -Be 'Pass'
        $dev.GrantControls.BuiltInControls = @('compliantDevice', 'mfa')
        (& $script:Check @($dev) 'MT.1014').Status | Should -Be 'Fail'
    }
    It 'guest MFA passes on an all-users MFA policy and fails when guests are excluded' {
        (& $script:Check @((& $script:Pol 'MFA all')) 'MT.1016').Status | Should -Be 'Pass'
        $x = & $script:Pol 'MFA all but guests' 'enabled' @{ 'Conditions.Users.ExcludeGuestsOrExternalUsers' = @{ GuestOrExternalUserTypes = 'internalGuest' } }
        (& $script:Check @($x) 'MT.1016').Status | Should -Be 'Fail'
    }
    It 'unmanaged device session rows need the device filter Maester matches' {
        $s = & $script:Pol 'Unmanaged' 'enabled' @{
            'GrantControls.BuiltInControls' = @()
            'Conditions.Devices' = @{ FilterMode = 'include'; FilterRule = 'device.trustType -ne "ServerAD" -or device.isCompliant -ne True' }
            'SessionControls.PersistentBrowser' = @{ IsEnabled = $true; Mode = 'never' }
            'SessionControls.SignInFrequency' = @{ IsEnabled = $true; FrequencyInterval = 'timeBased'; Value = 1; Type = 'hours' }
        }
        (& $script:Check @($s) 'MT.1017').Status | Should -Be 'Pass'
        (& $script:Check @($s) 'MT.1018').Status | Should -Be 'Pass'
        $s.Conditions.Devices = @{ FilterMode = ''; FilterRule = '' }
        (& $script:Check @($s) 'MT.1017').Status | Should -Be 'Fail'
    }
    It 'unknown platforms, app-enforced restrictions, compliant device and the agent row' {
        (& $script:Check @((& $script:Pol 'Platforms' 'enabled' @{ 'GrantControls.BuiltInControls' = @('block'); 'Conditions.Platforms' = @('all') })) 'MT.1015').Status | Should -Be 'Pass'
        (& $script:Check @((& $script:Pol 'AER' 'enabled' @{ 'GrantControls.BuiltInControls' = @(); 'Conditions.Applications.Include' = @('Office365'); 'SessionControls.ApplicationEnforcedRestrictions' = $true })) 'MT.1019').Status | Should -Be 'Pass'
        (& $script:Check @((& $script:Pol 'Compliant' 'enabled' @{ 'GrantControls.BuiltInControls' = @('compliantDevice', 'mfa') })) 'MT.1001').Status | Should -Be 'Pass'
        (& $script:Check @((& $script:Pol 'Agents' 'enabled' @{ 'GrantControls.BuiltInControls' = @('block'); 'Conditions.AgentIdRiskLevels' = @('high') })) 'MT.1181').Status | Should -Be 'Pass'
    }
    It 'the agent row is not assessed when no policy carries agent risk levels (an older results file)' {
        $old = & $script:Pol 'MFA all'
        $old.Conditions.Remove('AgentIdRiskLevels')
        (& $script:Check @($old) 'MT.1181').Status | Should -Be 'NotAssessed'
    }
    It 'every presence check in the catalog has a rule' {
        $view = Get-TPCAChecklist -RawData (& $script:Raw @((& $script:Pol 'MFA all'))) -EmergencyAccessRecord $script:Ea
        $presence = @($view.Rows | Where-Object { $_.Kind -eq 'Presence' })
        $presence.Count | Should -Be @($script:Catalog.checks | Where-Object { $_.Kind -eq 'Presence' }).Count
        foreach ($r in $presence) { $r.Status | Should -BeIn @('Pass', 'Fail', 'Staged', 'NotAssessed', 'NeedsLicense') }
    }
    It 'a positively missing license is "Needs license"; an unread license profile never is' {
        $lic = Get-TPTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'SPB'; ServicePlans = @('AAD_PREMIUM', 'INTUNE_A') })
        $view = Get-TPCAChecklist -RawData (& $script:Raw @((& $script:Pol 'MFA all'))) -EmergencyAccessRecord $script:Ea -LicenseProfile $lic
        (& $script:Row $view 'MT.1012').Status | Should -Be 'NeedsLicense'
        $view2 = Get-TPCAChecklist -RawData (& $script:Raw @((& $script:Pol 'MFA all'))) -EmergencyAccessRecord $script:Ea -LicenseProfile $null
        (& $script:Row $view2 'MT.1012').Status | Should -Be 'Fail'
    }
}

Describe 'Hygiene rows' {
    It 'MT.1005 judges the approved record: every policy must exclude every approved account' {
        $a = & $script:Pol 'A'; $b = & $script:Pol 'B' 'enabled' @{ 'Conditions.Users.ExcludeUsers' = @() }
        (& $script:Check @($a) 'MT.1005').Status | Should -Be 'Pass'
        $row = & $script:Check @($a, $b) 'MT.1005'
        $row.Status | Should -Be 'Fail'
        @($row.Policies).Count | Should -Be 1
    }
    It 'MT.1005 without a record says the pass rests on an inference' {
        $row = & $script:Row (Get-TPCAChecklist -RawData (& $script:Raw @((& $script:Pol 'A'))) -EmergencyAccessRecord $null) 'MT.1005'
        $row.Status | Should -Be 'Pass'
        $row.Detail | Should -Match 'inference'
    }
    It 'MT.1066 and MT.1038 report only objects Graph answered 404 for; an unread object is not a deleted one' {
        $gid = '22222222-2222-2222-2222-222222222222'
        $p = & $script:Pol 'Group policy' 'enabled' @{ 'Conditions.Users.ExcludeGroups' = @($gid) }
        $gone = Get-TPCAChecklist -RawData (& $script:Raw @($p) @{} @(@{ Kind = 'Group'; Id = $gid; Exists = $false })) -EmergencyAccessRecord $script:Ea
        (& $script:Row $gone 'MT.1038').Status | Should -Be 'Fail'
        (& $script:Row $gone 'MT.1066').Status | Should -Be 'Fail'
        @((& $script:Row $gone 'MT.1066').Items)[0].UsedBy | Should -Contain 'Group policy'
        $unread = Get-TPCAChecklist -RawData (& $script:Raw @($p) @{} @() 'Partial') -EmergencyAccessRecord $script:Ea
        (& $script:Row $unread 'MT.1066').Status | Should -Be 'NotAssessed'
        $none = Get-TPCAChecklist -RawData (& $script:Raw @($p) @{} @() 'NotRun') -EmergencyAccessRecord $script:Ea
        (& $script:Row $none 'MT.1038').Status | Should -Be 'NotAssessed'
    }
    It 'MT.1035 fails a group that is neither role-assignable nor restricted, and passes a protected one' {
        $gid = '33333333-3333-3333-3333-333333333333'
        $p = & $script:Pol 'Group policy' 'enabled' @{ 'Conditions.Users.ExcludeGroups' = @($gid) }
        $open = Get-TPCAChecklist -RawData (& $script:Raw @($p) @{} @(@{ Kind = 'Group'; Id = $gid; Exists = $true; DisplayName = 'CA exclusions'; IsAssignableToRole = $false; IsManagementRestricted = $false })) -EmergencyAccessRecord $script:Ea
        (& $script:Row $open 'MT.1035').Status | Should -Be 'Fail'
        $safe = Get-TPCAChecklist -RawData (& $script:Raw @($p) @{} @(@{ Kind = 'Group'; Id = $gid; Exists = $true; DisplayName = 'CA exclusions'; IsAssignableToRole = $true; IsManagementRestricted = $null })) -EmergencyAccessRecord $script:Ea
        (& $script:Row $safe 'MT.1035').Status | Should -Be 'Pass'
    }
    It 'MT.1036 does not count an approved emergency-access exclusion, and fails any other exclusion with no fallback' {
        (& $script:Check @((& $script:Pol 'A')) 'MT.1036').Status | Should -Be 'Pass'
        $x = & $script:Pol 'B' 'enabled' @{ 'Conditions.Users.ExcludeUsers' = @($script:BreakGlass, '44444444-4444-4444-4444-444444444444') }
        $row = & $script:Check @($x) 'MT.1036'
        $row.Status | Should -Be 'Fail'
        @($row.Items).Count | Should -Be 1
    }
    It 'MT.1072, MT.1184, MT.1224 and MT.1049 read what Maester reads' {
        (& $script:Check @((& $script:Pol 'Old' 'enabled' @{ 'GrantControls.BuiltInControls' = @('approvedApplication') })) 'MT.1072').Status | Should -Be 'Fail'
        (& $script:Check @((& $script:Pol 'Nothing' 'disabled' @{ 'Conditions.Applications.Include' = @('None') })) 'MT.1184').Status | Should -Be 'Fail'
        (& $script:Check @((& $script:Pol 'Microsoft-managed: Block legacy authentication' 'enabledForReportingButNotEnforced')) 'MT.1224').Status | Should -Be 'Fail'
        (& $script:Check @((& $script:Pol 'MFA all')) 'MT.1224').Status | Should -Be 'NotApplicable'
        (& $script:Check @((& $script:Pol 'Both' 'enabled' @{ 'Conditions.SignInRiskLevels' = @('high'); 'Conditions.UserRiskLevels' = @('high') })) 'MT.1049').Status | Should -Be 'Fail'
        (& $script:Check @((& $script:Pol 'MFA all')) 'MT.1049').Status | Should -Be 'NotApplicable'
    }
    It 'MT.1184 is not assessed on an older results file that never read application filters' {
        $p = & $script:Pol 'Nothing' 'disabled' @{ 'Conditions.Applications.Include' = @() }
        $p.Conditions.Applications.Remove('ApplicationFilterPresent')
        (& $script:Check @($p) 'MT.1184').Status | Should -Be 'NotAssessed'
    }
    It 'MT.1061 fails only when device settings require MFA AND a policy targets the register-device action' {
        $reg = & $script:Pol 'Register device' 'enabled' @{ 'Conditions.Applications.Include' = @(); 'Conditions.Applications.UserActions' = @('urn:user:registerdevice') }
        $ds = { param($v) @{ 'AAD-DirectorySettings' = @{ Success = $true; Data = @{ DeviceRegistration = @{ MultiFactorAuthConfiguration = $v } } } } }
        (& $script:Check @($reg) 'MT.1061' (& $ds 'required')).Status | Should -Be 'Fail'
        (& $script:Check @($reg) 'MT.1061' (& $ds 'notRequired')).Status | Should -Be 'Pass'
        (& $script:Check @($reg) 'MT.1061' (& $ds '')).Status | Should -Be 'NotAssessed'
    }
    It 'MT.1020 fails an all-resources policy that reaches the sync account, and passes once the role is excluded' {
        $sync = '55555555-5555-5555-5555-555555555555'
        $roles = @{ 'AAD-DirectoryRoles' = @{ Success = $true; Data = @{ SectionStatus = @{ RoleAssignments = 'Collected' }; RoleAssignments = @(@{ RoleDefinitionId = 'd29b2b05-8046-44ba-8758-1e26182fcf32'; PrincipalId = $sync; PrincipalType = '#microsoft.graph.user' }) } } }
        (& $script:Check @((& $script:Pol 'MFA all')) 'MT.1020' $roles).Status | Should -Be 'Fail'
        (& $script:Check @((& $script:Pol 'MFA all' 'enabled' @{ 'Conditions.Users.ExcludeRoles' = @('d29b2b05-8046-44ba-8758-1e26182fcf32') })) 'MT.1020' $roles).Status | Should -Be 'Pass'
        (& $script:Check @((& $script:Pol 'MFA all')) 'MT.1020').Status | Should -Be 'NotAssessed'
    }
}

Describe 'What If rows' {
    BeforeAll {
        $script:WhatIf = {
            param([object[]] $Users)
            @{ 'AAD-CAWhatIf' = @{ Success = $true; Data = @{ Available = $true; Users = @($Users) } } }
        }
        $script:Res = { param([object[]] $Applied) @{ Read = $true; Error = ''; Applied = @($Applied) } }
        $script:Applied = { param([string] $State, [bool] $Blocks, [bool] $Mfa = $false) @{ Id = 'x'; DisplayName = "P $State"; State = $State; Grants = @(); Blocks = $Blocks; RequiresMfa = $Mfa } }
    }
    It 'MT.1033 passes only when an enabled policy blocks; a report-only block is "Report-only"' {
        $u = @{ UserId = '11111111-0000-0000-0000-000000000001'; UserPrincipalName = 'a@contoso.com'; Kind = 'Regular'; Results = @{ LegacyAuth = (& $script:Res @((& $script:Applied 'enabled' $true))); Mfa = (& $script:Res @()) } }
        (& $script:Check @((& $script:Pol 'MFA all')) 'MT.1033' (& $script:WhatIf @($u))).Status | Should -Be 'Pass'
        $u.Results.LegacyAuth = & $script:Res @((& $script:Applied 'enabledForReportingButNotEnforced' $true))
        (& $script:Check @((& $script:Pol 'MFA all')) 'MT.1033' (& $script:WhatIf @($u))).Status | Should -Be 'Staged'
        $u.Results.LegacyAuth = & $script:Res @((& $script:Applied 'enabled' $false))
        $row = & $script:Check @((& $script:Pol 'MFA all')) 'MT.1033' (& $script:WhatIf @($u))
        $row.Status | Should -Be 'Fail'
        @($row.Items)[0].DisplayName | Should -Be 'a@contoso.com'
    }
    It 'MT.1034 fails when a policy reaches an approved break-glass account and is not assessed without a record' {
        $bg = @{ UserId = $script:BreakGlass; UserPrincipalName = 'bg@contoso.com'; Kind = 'Emergency'; Results = @{ LegacyAuth = (& $script:Res @()); Mfa = (& $script:Res @((& $script:Applied 'enabled' $false $true))) } }
        (& $script:Check @((& $script:Pol 'MFA all')) 'MT.1034' (& $script:WhatIf @($bg))).Status | Should -Be 'Fail'
        $bg.Results.Mfa = & $script:Res @()
        (& $script:Check @((& $script:Pol 'MFA all')) 'MT.1034' (& $script:WhatIf @($bg))).Status | Should -Be 'Pass'
        $none = Get-TPCAChecklist -RawData (& $script:Raw @((& $script:Pol 'MFA all')) (& $script:WhatIf @($bg))) -EmergencyAccessRecord $null
        (& $script:Row $none 'MT.1034').Status | Should -Be 'NotAssessed'
    }
    It 'the MFA row passes on an enabled MFA policy and is not assessed when the evaluation failed' {
        $u = @{ UserId = '11111111-0000-0000-0000-000000000001'; UserPrincipalName = 'a@contoso.com'; Kind = 'Regular'; Results = @{ LegacyAuth = (& $script:Res @()); Mfa = (& $script:Res @((& $script:Applied 'enabled' $false $true))) } }
        (& $script:Check @((& $script:Pol 'MFA all')) 'TP-WHATIF-MFA' (& $script:WhatIf @($u))).Status | Should -Be 'Pass'
        $u.Results.Mfa = @{ Read = $false; Error = 'throttled'; Applied = @() }
        (& $script:Check @((& $script:Pol 'MFA all')) 'TP-WHATIF-MFA' (& $script:WhatIf @($u))).Status | Should -Be 'NotAssessed'
    }
    It 'with no simulation data every What If row is not assessed' {
        $view = Get-TPCAChecklist -RawData (& $script:Raw @((& $script:Pol 'MFA all'))) -EmergencyAccessRecord $script:Ea
        foreach ($r in @($view.Rows | Where-Object { $_.Kind -eq 'Simulation' })) { $r.Status | Should -Be 'NotAssessed' }
    }
}

Describe 'Not read is not assessed' {
    It 'with no Conditional Access data no presence or hygiene row passes or fails' {
        $view = Get-TPCAChecklist -RawData @{} -EmergencyAccessRecord $script:Ea
        $view.Available | Should -BeTrue
        foreach ($r in @($view.Rows | Where-Object { $_.Kind -ne 'Simulation' })) { $r.Status | Should -Be 'NotAssessed' }
        @($view.Fixes).Count | Should -Be 0
        $view.Notes -join ' ' | Should -Match 'not read'
    }
    It 'a failed CA collector is not read' {
        $view = Get-TPCAChecklist -RawData @{ 'AAD-CAPolicies' = @{ Success = $false; Data = @{ Policies = @() } } } -EmergencyAccessRecord $script:Ea
        (& $script:Row $view 'MT.1007').Status | Should -Be 'NotAssessed'
    }
    It 'replays a results file (JSON round trip) to the same statuses' {
        $raw = & $script:Raw @((& $script:Pol 'MFA all'), (& $script:Pol 'Legacy' 'enabledForReportingButNotEnforced' @{ 'GrantControls.BuiltInControls' = @('block'); 'Conditions.ClientAppTypes' = @('exchangeActiveSync', 'other') }))
        $live = Get-TPCAChecklist -RawData $raw -EmergencyAccessRecord $script:Ea
        $replayed = Get-TPCAChecklist -RawData ($raw | ConvertTo-Json -Depth 20 | ConvertFrom-Json) -EmergencyAccessRecord $script:Ea
        foreach ($r in $live.Rows) { (& $script:Row $replayed $r.Id).Status | Should -Be $r.Status -Because $r.Id }
    }
}

Describe 'Report-only policy files' {
    BeforeAll {
        $script:View = Get-TPCAChecklist -RawData (& $script:Raw @((& $script:Pol 'Nothing useful' 'disabled'))) -EmergencyAccessRecord @{ EmergencyAccess = @{ "user:$($script:BreakGlass)" = 1; 'group:66666666-6666-6666-6666-666666666666' = 1 } }
    }
    It 'returns one file per missing template, every one report-only, with the approved accounts excluded and no token left' {
        @($script:View.Fixes).Count | Should -BeGreaterThan 5
        foreach ($fx in $script:View.Fixes) {
            $fx.Policy.state | Should -Be 'enabledForReportingButNotEnforced'
            $json = $fx.Policy | ConvertTo-Json -Depth 20
            $json | Should -Not -Match '@AdminRoles|@SyncRole'
            if ($fx.Policy.conditions.users.Contains('includeUsers') -or $fx.Policy.conditions.users.Contains('includeRoles')) {
                $fx.Policy.conditions.users.excludeUsers | Should -Contain $script:BreakGlass
                $fx.Policy.conditions.users.excludeGroups | Should -Contain '66666666-6666-6666-6666-666666666666'
            }
        }
        $admins = @($script:View.Fixes | Where-Object { $_.Key -eq 'mfa-admins' })[0]
        @($admins.Policy.conditions.users.includeRoles).Count | Should -Be 14
        $all = @($script:View.Fixes | Where-Object { $_.Key -eq 'mfa-all-users' })[0]
        $all.Policy.conditions.users.excludeRoles | Should -Contain 'd29b2b05-8046-44ba-8758-1e26182fcf32'
    }
    It 'returns no file for a check met only by a report-only policy (turn it on instead)' {
        $view = Get-TPCAChecklist -RawData (& $script:Raw @((& $script:Pol 'MFA all' 'enabledForReportingButNotEnforced'))) -EmergencyAccessRecord $script:Ea
        @($view.Fixes | Where-Object { $_.Key -eq 'mfa-all-users' }).Count | Should -Be 0
    }
    It 'publishes HTML, Markdown and the policy folder, loads nothing and never says compliant' {
        $files = Publish-TPCAChecklist -Model $script:View -OutputPath (Join-Path $script:Tmp 'contoso-ca-checklist.html') -TenantDomain 'contoso.com' -GeneratedAt ([datetime]'2026-10-28T00:00:00Z')
        Test-Path -LiteralPath $files.Html | Should -BeTrue
        Test-Path -LiteralPath $files.Markdown | Should -BeTrue
        $files.PolicyFolder | Should -Match 'contoso-ca-policies\z'
        Test-Path -LiteralPath (Join-Path $files.PolicyFolder 'README.md') | Should -BeTrue
        foreach ($f in @($files.PolicyFiles | Where-Object { $_ -like '*.json' })) {
            (Get-Content -LiteralPath $f -Raw | ConvertFrom-Json).state | Should -Be 'enabledForReportingButNotEnforced'
        }
        $html = Get-Content -LiteralPath $files.Html -Raw
        $html | Should -Not -Match '<script|<link |src="http|@import'
        foreach ($t in @($html, (Get-Content -LiteralPath $files.Markdown -Raw), (Get-Content -LiteralPath (Join-Path $files.PolicyFolder 'README.md') -Raw))) {
            $t | Should -Not -Match '(?i)\bcompliant with\b|\bis compliant\b|\bfully compliant\b'
        }
        (Get-Content -LiteralPath (Join-Path $files.PolicyFolder 'README.md') -Raw) | Should -Match 'created nothing in the tenant'
    }
    It 'escapes a hostile policy name in both formats' {
        $view = Get-TPCAChecklist -RawData (& $script:Raw @((& $script:Pol '<img src=x onerror=alert(1)>[x](http://evil)'))) -EmergencyAccessRecord $script:Ea
        $files = Publish-TPCAChecklist -Model $view -OutputPath (Join-Path $script:Tmp 'evil-ca-checklist.html') -NoPolicyFiles
        (Get-Content -LiteralPath $files.Html -Raw) | Should -Not -Match '<img src=x'
        (Get-Content -LiteralPath $files.Markdown -Raw) | Should -Not -Match '\[x\]\(http'
        $files.PolicyFolder | Should -BeNullOrEmpty
    }
    It 'is a view: the findings and the raw data are not changed' {
        $raw = & $script:Raw @((& $script:Pol 'MFA all'))
        $before = $raw | ConvertTo-Json -Depth 20
        $null = Get-TPCAChecklist -RawData $raw -EmergencyAccessRecord $script:Ea
        ($raw | ConvertTo-Json -Depth 20) | Should -Be $before
    }
}

Describe 'The one POST' {
    It 'only Invoke-TPCAWhatIfEvaluation calls Invoke-MgGraphRequest with POST, and its URI is a constant' {
        $hits = [System.Collections.Generic.List[string]]::new()
        foreach ($dir in 'Lib', 'Collectors', 'Evaluators', 'Publishers') {
            foreach ($file in Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot $dir) -Filter '*.ps1' -Recurse) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$null)
                foreach ($cmd in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Invoke-MgGraphRequest' }, $true)) {
                    $text = $cmd.Extent.Text
                    if ($text -notmatch '(?i)-Method\s+[''"]?GET\b' -and $text -match '(?i)-Method') {
                        $fn = $cmd.Parent
                        while ($fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
                        $hits.Add("$($file.Name):$($fn.Name)")
                        $text | Should -Match "-Uri 'https://graph\.microsoft\.com/v1\.0/identity/conditionalAccess/evaluate'"
                    }
                }
            }
        }
        @($hits) | Should -Be @('Invoke-TPCAWhatIf.ps1:Invoke-TPCAWhatIfEvaluation')
    }
    It 'Invoke-TPGraphRequest stays GET-only' {
        { Invoke-TPGraphRequest -Method POST -Uri 'https://graph.microsoft.com/v1.0/x' } | Should -Throw
    }
    It 'refuses an id that is not a GUID and a client app type Microsoft does not define' {
        { Invoke-TPCAWhatIfEvaluation -UserId "x'; DROP" -ApplicationId '00000002-0000-0ff1-ce00-000000000000' -ClientAppType browser } | Should -Throw
        { Invoke-TPCAWhatIfEvaluation -UserId '11111111-1111-1111-1111-111111111111' -ApplicationId '00000002-0000-0ff1-ce00-000000000000' -ClientAppType 'anything' } | Should -Throw
    }
    It 'sends the body Microsoft documents and reads only the policies that apply' {
        & $script:Mod {
            $script:TPTestCalls = [System.Collections.Generic.List[object]]::new()
            function script:Invoke-MgGraphRequest { param($Method, $Uri, $Body, $ContentType, $OutputType)
                $script:TPTestCalls.Add(@{ Method = $Method; Uri = $Uri; Body = $Body })
                @{ value = @(
                    @{ id = 'a'; displayName = 'Block legacy'; state = 'enabled'; policyApplies = $true; grantControls = @{ builtInControls = @('block'); operator = 'OR' } },
                    @{ id = 'b'; displayName = 'Not this one'; state = 'enabled'; policyApplies = $false; grantControls = @{ builtInControls = @('mfa') } },
                    @{ id = 'c'; displayName = 'MFA or device'; state = 'enabled'; policyApplies = $true; grantControls = @{ builtInControls = @('mfa', 'compliantDevice'); operator = 'OR' } },
                    @{ id = 'd'; displayName = 'Strength'; state = 'enabled'; policyApplies = $true; grantControls = @{ builtInControls = @(); authenticationStrength = @{ requirementsSatisfied = 'mfa' } } }) }
            }
            try {
                $r = @(Invoke-TPCAWhatIfEvaluation -UserId '11111111-1111-1111-1111-111111111111' -ApplicationId '00000002-0000-0ff1-ce00-000000000000' -ClientAppType exchangeActiveSync)
                $r.Count | Should -Be 3
                ($r | Where-Object Id -eq 'a').Blocks | Should -BeTrue
                ($r | Where-Object Id -eq 'c').RequiresMfa | Should -BeFalse
                ($r | Where-Object Id -eq 'd').RequiresMfa | Should -BeTrue
                $call = $script:TPTestCalls[0]
                $call.Method | Should -Be 'POST'
                $body = $call.Body | ConvertFrom-Json
                $body.signInIdentity.userId | Should -Be '11111111-1111-1111-1111-111111111111'
                $body.signInConditions.clientAppType | Should -Be 'exchangeActiveSync'
                $body.appliedPoliciesOnly | Should -BeTrue
            } finally { Remove-Item function:Invoke-MgGraphRequest -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'The What If collector' {
    It 'samples enabled members by UPN, never an emergency account, and records each evaluation' {
        & $script:Mod {
            param($bg)
            Clear-TPState
            Set-TPRawData -Key 'AAD-Users' -Data @{ Success = $true; Data = @{ Users = @(
                @{ Id = '00000000-0000-0000-0000-00000000000c'; UserPrincipalName = 'c@contoso.com'; AccountEnabled = $true; UserType = 'Member' },
                @{ Id = '00000000-0000-0000-0000-00000000000a'; UserPrincipalName = 'a@contoso.com'; AccountEnabled = $true; UserType = 'Member' },
                @{ Id = '00000000-0000-0000-0000-00000000000d'; UserPrincipalName = 'd@contoso.com'; AccountEnabled = $false; UserType = 'Member' },
                @{ Id = '00000000-0000-0000-0000-00000000000e'; UserPrincipalName = 'e@contoso.com'; AccountEnabled = $true; UserType = 'Guest' },
                @{ Id = $bg; UserPrincipalName = 'bg@contoso.com'; AccountEnabled = $true; UserType = 'Member' }) } }
            $script:TPWhatIfCalls = [System.Collections.Generic.List[string]]::new()
            function script:Invoke-TPCAWhatIfEvaluation { param($UserId, $ApplicationId, $ClientAppType)
                $script:TPWhatIfCalls.Add("$UserId|$ClientAppType")
                if ($UserId -like '*c' -and $ClientAppType -eq 'browser') { throw 'throttled' }
                @(@{ Id = 'p'; DisplayName = 'Block legacy'; State = 'enabled'; Grants = @('block'); Blocks = $true; RequiresMfa = $false })
            }
            try {
                $r = Invoke-TPCollectAADCAWhatIf -EmergencyAccessUserIds @($bg) -SampleSize 2
                $r.Success | Should -BeTrue
                $regular = @($r.Data.Users | Where-Object Kind -eq 'Regular')
                @($regular.UserPrincipalName) | Should -Be @('a@contoso.com', 'c@contoso.com')
                @($r.Data.Users | Where-Object Kind -eq 'Emergency').UserPrincipalName | Should -Be 'bg@contoso.com'
                $r.Data.SectionStatus.Regular | Should -Be 'Partial'
                ($regular | Where-Object UserPrincipalName -eq 'c@contoso.com').Results.Mfa.Read | Should -BeFalse
                $script:TPWhatIfCalls.Count | Should -Be 6
                (Get-TPRawData -Key 'AAD-CAWhatIf').Data.Available | Should -BeTrue
            } finally { Remove-Item function:Invoke-TPCAWhatIfEvaluation -ErrorAction SilentlyContinue; Clear-TPState }
        } $script:BreakGlass
    }
    It 'simulates nothing and says so when the users were not read' {
        & $script:Mod {
            Clear-TPState
            $r = Invoke-TPCollectAADCAWhatIf
            $r.Data.Available | Should -BeFalse
            $r.Data.UnavailableReason | Should -Be 'UsersNotRead'
            Clear-TPState
        }
    }
}

Describe 'The referenced-object read' {
    It 'files a 404 as a deleted object, any other error as unread, and reads group protection from beta' {
        & $script:Mod {
            function script:Invoke-TPGraphRequest { param($Method, $Uri, $Headers, $OutputType)
                if ($Uri -match '/users/11111111') { return @{ id = '11111111-1111-1111-1111-111111111111'; displayName = 'Alice'; userPrincipalName = 'alice@contoso.com' } }
                if ($Uri -match '/groups/22222222') { throw [System.Exception]::new('Response status code does not indicate success: 404 (Not Found).') }
                if ($Uri -match '/groups/33333333') { if ($Uri -notmatch '/beta/') { throw 'expected beta' }; return @{ id = '33333333-3333-3333-3333-333333333333'; displayName = 'G'; isAssignableToRole = $false; isManagementRestricted = $true } }
                throw [System.Exception]::new('Response status code does not indicate success: 429 (Too Many Requests).')
            }
            try {
                $pols = @(@{ Conditions = @{ Users = @{ IncludeUsers = @('All', '11111111-1111-1111-1111-111111111111'); ExcludeUsers = @(); IncludeGroups = @('22222222-2222-2222-2222-222222222222'); ExcludeGroups = @('33333333-3333-3333-3333-333333333333'); IncludeRoles = @(); ExcludeRoles = @('44444444-4444-4444-4444-444444444444') } } })
                $r = Get-TPCAReferencedObjects -Policies $pols
                $r.Requested | Should -Be 4
                ($r.Objects | Where-Object Kind -eq 'User').Exists | Should -BeTrue
                ($r.Objects | Where-Object { $_.Id -like '2222*' }).Exists | Should -BeFalse
                ($r.Objects | Where-Object { $_.Id -like '3333*' }).IsManagementRestricted | Should -BeTrue
                ($r.Objects | Where-Object Kind -eq 'Role').Exists | Should -BeNullOrEmpty
                $r.Unread | Should -Be 1
            } finally { Remove-Item function:Invoke-TPGraphRequest -ErrorAction SilentlyContinue }
        }
    }
}

Describe 'Entry point wiring' {
    It 'writes the view to the results JSON as CAChecklist under a name that shadows no parameter' {
        $text = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
        $text | Should -Match 'CAChecklist\s+=\s+\$caChecklistView'
        $text | Should -Match '\[switch\] \$CAChecklist'
        $text | Should -Match '\[switch\] \$SkipCAWhatIf'
        $text | Should -Not -Match '(?m)^\s*\$caChecklist\s*='
        $text | Should -Match "Invoke-TPCollectorStep 'Conditional Access What If \(sample\)'"
    }
}
