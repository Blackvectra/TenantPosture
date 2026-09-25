#Requires -Version 7.0
#
# NRG.ConditionalAccessView.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Pins Lib/Get-NRGConditionalAccessView.ps1 — the Conditional Access
# inventory and recommended-baseline view. Owner's ask, 2026-09-25: "does
# the report say what CA policies are enabled in audit mode and maybe
# provide CA that should be in place for future. I know you can add so many
# policies i could add one just for an app we use or linkedin for example."
#
# Two real bugs were caught while writing this feature, and each has a test
# that pins the fix: (1) a policy scoped to one app (the owner's own
# LinkedIn example) matched the "mfa-admins" template, because that
# template's eligibility check never looked at which resources the policy
# targeted; (2) every baseline row read "not licensed" even when a policy
# was actually enforcing it, because the license check ran before the
# match check and treated an unread license profile as a confirmed
# absence.
#
# Data keys: AAD-CAPolicies, AAD-AuthPolicies (via Get-NRGSecurityDefaultsState),
#            AAD-DirectoryRoles, Config/conditional-access-baseline.json.

Describe 'Conditional Access view (inventory + recommended baseline)' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'

        function script:View { param([object]$LicenseProfile = $null)
            & $script:Mod { param($lp) Get-NRGConditionalAccessView -LicenseProfile $lp } $LicenseProfile
        }

        function script:Pol {
            param(
                [string] $Id = 'p1', [string] $Name = 'Test policy', [string] $State = 'enabled',
                [string[]] $IncludeUsers = @('All'), [string[]] $IncludeRoles = @(), [string[]] $ExcludeRoles = @(),
                [string[]] $IncludeApps = @('All'), [string[]] $ExcludeApps = @(),
                [string[]] $ClientAppTypes = @('all'),
                [string] $Operator = 'OR', [string[]] $BuiltInControls = @('mfa'),
                [string] $AuthStrengthId = '', [string[]] $AuthStrengthCombinations = @(),
                [string[]] $SignInRiskLevels = @(), [string[]] $UserRiskLevels = @(),
                [string[]] $DeviceCodeTransferMethods = @(),
                [hashtable] $PersistentBrowser = $null
            )
            @{
                Id = $Id; DisplayName = $Name; State = $State
                Conditions = @{
                    ClientAppTypes = @($ClientAppTypes)
                    Users = @{ IncludeUsers = @($IncludeUsers); ExcludeUsers = @(); IncludeGroups = @(); ExcludeGroups = @(); IncludeRoles = @($IncludeRoles); ExcludeRoles = @($ExcludeRoles) }
                    Applications = @{ Include = @($IncludeApps); Exclude = @($ExcludeApps); UserActions = @() }
                    SignInRiskLevels = @($SignInRiskLevels); UserRiskLevels = @($UserRiskLevels)
                    AuthFlows = @(if ($DeviceCodeTransferMethods.Count -gt 0) { @{ transferMethods = ($DeviceCodeTransferMethods -join ',') } })
                }
                GrantControls = @{
                    Operator = $Operator; BuiltInControls = @($BuiltInControls); CustomControls = @()
                    AuthStrengthId = $AuthStrengthId; AuthStrengthName = ''; AuthStrengthCombinations = @($AuthStrengthCombinations); TermsOfUse = @()
                }
                SessionControls = @{ PersistentBrowser = $PersistentBrowser }
            }
        }

        function script:SetCA { param([object[]] $Policies = @(), [bool] $Success = $true)
            Set-NRGRawData -Key 'AAD-CAPolicies' -Data @{ Success = $Success; Data = @{ Policies = @($Policies); SectionStatus = @{} } }
        }
        function script:SetSD { param([object] $IsEnabled)
            if ($null -eq $IsEnabled) { Set-NRGRawData -Key 'AAD-AuthPolicies' -Data @{ Success = $true; Data = @{ SecurityDefaults = @{} } } }
            else { Set-NRGRawData -Key 'AAD-AuthPolicies' -Data @{ Success = $true; Data = @{ SecurityDefaults = @{ IsEnabled = $IsEnabled } } } }
        }
        function script:SetRoles { param([string[]] $PrivIds = @('62e90394-69f5-4237-9190-012177145e10'))
            $defs = @($PrivIds | ForEach-Object { @{ Id = $_; DisplayName = "Role-$_"; IsPriv = $true } })
            Set-NRGRawData -Key 'AAD-DirectoryRoles' -Data @{ Success = $true; Data = @{ RoleDefinitions = $defs } }
        }
        function script:Baseline([object] $v, [string] $Id) { @($v.Baseline | Where-Object { $_.Id -eq $Id })[0] }
    }
    BeforeEach { Clear-NRGState }
    AfterAll { Clear-NRGState }

    Context 'Not read is never "none"' {
        It 'no AAD-CAPolicies key -> NotCollected, empty policies, empty baseline' {
            $v = View
            $v.ReadStatus | Should -Be 'NotCollected'
            $v.Available | Should -BeTrue
            @($v.Policies).Count | Should -Be 0
            @($v.Baseline).Count | Should -Be 0
        }
        It 'a failed collector read -> CollectorFailed, not "no policies"' {
            SetCA -Success $false
            $v = View
            $v.ReadStatus | Should -Be 'CollectorFailed'
            @($v.Baseline).Count | Should -Be 0
        }
    }

    Context 'State labels: On, Report-only (audit), Off, Unknown — never blurred' {
        It 'maps every Graph state to the label a client actually reads' {
            SetCA -Policies @(
                (Pol -Id 'a' -State 'enabled'),
                (Pol -Id 'b' -State 'enabledForReportingButNotEnforced'),
                (Pol -Id 'c' -State 'disabled'),
                (Pol -Id 'd' -State 'somethingNew')
            )
            $v = View
            ($v.Policies | Where-Object Id -eq 'a').StateLabel | Should -Be 'On'
            ($v.Policies | Where-Object Id -eq 'b').StateLabel | Should -Be 'Report-only (audit)'
            ($v.Policies | Where-Object Id -eq 'c').StateLabel | Should -Be 'Off'
            ($v.Policies | Where-Object Id -eq 'd').StateLabel | Should -Match '^Unknown state'
            $v.Counts.On | Should -Be 1
            $v.Counts.ReportOnly | Should -Be 1
            $v.Counts.Off | Should -Be 1
            $v.Counts.Unknown | Should -Be 1
            ($v.Counts.On + $v.Counts.ReportOnly + $v.Counts.Off + $v.Counts.Unknown) | Should -Be $v.Counts.Total
        }
        It 'a report-only policy is never shown as Enforced in the baseline' {
            SetSD -IsEnabled $false
            SetCA -Policies @((Pol -State 'enabledForReportingButNotEnforced'))
            $v = View
            (Baseline $v 'mfa-all-users').Status | Should -Be 'Similar'
        }
    }

    Context 'The owner''s own example: a policy scoped to one app (LinkedIn) is Custom, never judged' {
        It 'never matches mfa-admins, mfa-all-users, or any other broad template — the original bug' {
            SetRoles
            SetCA -Policies @((Pol -Name 'ZZLINKEDIN' -IncludeApps @('11111111-1111-1111-1111-111111111111') -IncludeRoles @('62e90394-69f5-4237-9190-012177145e10')))
            $v = View
            $p = $v.Policies[0]
            $p.Classification | Should -Be 'Custom'
            @($p.MatchedTemplateIds).Count | Should -Be 0
            @($p.SimilarTemplateIds).Count | Should -Be 0
            $v.Custom.Count | Should -Be 1
            $v.Custom[0].DisplayName | Should -Be 'ZZLINKEDIN'
            (Baseline $v 'mfa-admins').Status | Should -Be 'Missing'
            (Baseline $v 'mfa-all-users').Status | Should -Be 'Missing'
        }
    }

    Context 'mfa-all-users' {
        BeforeEach { SetSD -IsEnabled $false }
        It 'enabled, all users, all apps, mfa -> Enforced' {
            SetCA -Policies @((Pol))
            (Baseline (View) 'mfa-all-users').Status | Should -Be 'Enforced'
        }
        It 'an app exclusion narrows the resource scope -> Similar, never Enforced' {
            SetCA -Policies @((Pol -ExcludeApps @('some-app-id')))
            (Baseline (View) 'mfa-all-users').Status | Should -Be 'Similar'
        }
        It 'scoped to a group, not All users -> does not match at all' {
            SetCA -Policies @((Pol -IncludeUsers @()))
            (Baseline (View) 'mfa-all-users').Status | Should -Be 'Missing'
        }
    }

    Context 'mfa-admins (14 named roles per Microsoft; this tenant''s own privileged-role catalog decides coverage)' {
        BeforeEach { SetSD -IsEnabled $false }
        It 'a policy covering every role this tenant marks privileged, all apps, mfa -> Enforced' {
            SetRoles -PrivIds @('r1', 'r2')
            SetCA -Policies @((Pol -IncludeUsers @() -IncludeRoles @('r1', 'r2')))
            (Baseline (View) 'mfa-admins').Status | Should -Be 'Enforced'
        }
        It 'covering only some of the tenant''s privileged roles -> Similar' {
            SetRoles -PrivIds @('r1', 'r2')
            SetCA -Policies @((Pol -IncludeUsers @() -IncludeRoles @('r1')))
            (Baseline (View) 'mfa-admins').Status | Should -Be 'Similar'
        }
        It 'the role catalog was not collected -> the view still returns, and this template is not falsely Enforced' {
            SetCA -Policies @((Pol -IncludeUsers @() -IncludeRoles @('r1')))
            $v = View
            $v.Available | Should -BeTrue
            (Baseline $v 'mfa-admins').Status | Should -Not -Be 'Enforced'
        }
    }

    Context 'admin-phish-resistant-mfa' {
        BeforeEach { SetSD -IsEnabled $false }
        It 'admin roles + phishing-resistant authentication strength -> Enforced' {
            SetRoles -PrivIds @('r1')
            SetCA -Policies @((Pol -IncludeUsers @() -IncludeRoles @('r1') -AuthStrengthId '00000000-0000-0000-0000-000000000004'))
            (Baseline (View) 'admin-phish-resistant-mfa').Status | Should -Be 'Enforced'
        }
        It 'admin roles with plain MFA (not phishing-resistant) -> does not match' {
            SetRoles -PrivIds @('r1')
            SetCA -Policies @((Pol -IncludeUsers @() -IncludeRoles @('r1')))
            (Baseline (View) 'admin-phish-resistant-mfa').Status | Should -Be 'Missing'
        }
    }

    Context 'block-legacy-auth' {
        BeforeEach { SetSD -IsEnabled $false }
        It 'blocks exchangeActiveSync/other for all users, all apps -> Enforced' {
            SetCA -Policies @((Pol -ClientAppTypes @('exchangeActiveSync', 'other') -Operator 'OR' -BuiltInControls @('block')))
            (Baseline (View) 'block-legacy-auth').Status | Should -Be 'Enforced'
        }
        It 'scoped to one app -> never Enforced, even though it blocks legacy auth for that app' {
            SetCA -Policies @((Pol -ClientAppTypes @('exchangeActiveSync', 'other') -BuiltInControls @('block') -IncludeApps @('one-app')))
            (Baseline (View) 'block-legacy-auth').Status | Should -Be 'Missing'
        }
    }

    Context 'block-device-code' {
        BeforeEach { SetSD -IsEnabled $false }
        It 'blocks deviceCode transfer method for all users -> Enforced' {
            SetCA -Policies @((Pol -DeviceCodeTransferMethods @('deviceCode') -BuiltInControls @('block')))
            (Baseline (View) 'block-device-code').Status | Should -Be 'Enforced'
        }
        It 'a device-code policy that only requires MFA (does not block) -> NoMatch, not a partial credit (attackers relay the MFA prompt)' {
            SetCA -Policies @((Pol -DeviceCodeTransferMethods @('deviceCode') -BuiltInControls @('mfa')))
            (Baseline (View) 'block-device-code').Status | Should -Be 'Missing'
        }
    }

    Context 'mfa-azure-mgmt (deliberately resource-scoped, not an all-apps template)' {
        BeforeEach { SetSD -IsEnabled $false }
        It 'scoped to the Windows Azure Service Management API resource, all users, mfa -> Enforced' {
            SetCA -Policies @((Pol -IncludeApps @('797f4846-ba00-4fd7-ba43-dac1f8f63013')))
            (Baseline (View) 'mfa-azure-mgmt').Status | Should -Be 'Enforced'
        }
    }

    Context 'sign-in-risk / user-risk (Entra ID P2)' {
        BeforeEach { SetSD -IsEnabled $false }
        It 'signInRiskLevels set with an MFA/block response, all users -> Enforced' {
            SetCA -Policies @((Pol -SignInRiskLevels @('high', 'medium')))
            (Baseline (View) 'sign-in-risk').Status | Should -Be 'Enforced'
        }
        It 'userRiskLevels set with a passwordChange response -> Enforced' {
            SetCA -Policies @((Pol -UserRiskLevels @('high') -BuiltInControls @('passwordChange')))
            (Baseline (View) 'user-risk').Status | Should -Be 'Enforced'
        }
    }

    Context 'device-compliance-all-users vs compliant-hybrid-or-mfa-all-users' {
        BeforeEach { SetSD -IsEnabled $false }
        It 'device compliance REQUIRED (not one of several OR alternatives) -> device-compliance-all-users Enforced' {
            SetCA -Policies @((Pol -Operator 'AND' -BuiltInControls @('compliantDevice')))
            (Baseline (View) 'device-compliance-all-users').Status | Should -Be 'Enforced'
        }
        It 'the lighter OR alternative (compliant device OR mfa) satisfies the alt template but not the strict one' {
            SetCA -Policies @((Pol -Operator 'OR' -BuiltInControls @('compliantDevice', 'mfa')))
            (Baseline (View) 'compliant-hybrid-or-mfa-all-users').Status | Should -Be 'Enforced'
            (Baseline (View) 'device-compliance-all-users').Status | Should -Not -Be 'Enforced'
        }
    }

    Context 'persistent-browser' {
        BeforeEach { SetSD -IsEnabled $false }
        It 'PersistentBrowser enabled, mode never, all users/apps -> Enforced' {
            SetCA -Policies @((Pol -PersistentBrowser @{ IsEnabled = $true; Mode = 'never' }))
            (Baseline (View) 'persistent-browser').Status | Should -Be 'Enforced'
        }
    }

    Context 'Security Defaults: no Conditional Access policy can be in force while it is on' {
        It 'covers block-legacy-auth, mfa-admins, mfa-azure-mgmt, block-device-code; leaves the rest Missing with a stated reason' {
            SetSD -IsEnabled $true
            SetCA -Policies @()
            $v = View
            $v.SecurityDefaultsState | Should -BeTrue
            (Baseline $v 'block-legacy-auth').Status | Should -Be 'CoveredBySecurityDefaults'
            (Baseline $v 'mfa-admins').Status | Should -Be 'CoveredBySecurityDefaults'
            $mfaAll = Baseline $v 'mfa-all-users'
            $mfaAll.Status | Should -Be 'Missing'
            $mfaAll.Note | Should -Match 'Security Defaults'
        }
        It 'never claims a real On policy while Security Defaults reads on (the two reads should not both be trusted blindly, but the view does not crash or double-count)' {
            SetSD -IsEnabled $true
            SetCA -Policies @((Pol -State 'enabled'))
            $v = View
            $v.Available | Should -BeTrue
            $v.Counts.Total | Should -Be 1
        }
        It 'Security Defaults state not read, and no policy On -> baseline says NotRead, not a guess' {
            SetSD -IsEnabled $null
            SetCA -Policies @()
            (Baseline (View) 'mfa-all-users').Status | Should -Be 'NotRead'
        }
        It 'Security Defaults state not read, but a policy IS On -> the CA read settles it, no NotRead needed' {
            SetSD -IsEnabled $null
            SetCA -Policies @((Pol -State 'enabled'))
            (Baseline (View) 'mfa-all-users').Status | Should -Be 'Enforced'
        }
    }

    Context 'Licensing: absence of evidence is never evidence of "not licensed"' {
        It 'the original bug: every baseline row read NotLicensed even when a matching policy was live, because the license check ran before the match check' {
            SetCA -Policies @((Pol -ClientAppTypes @('exchangeActiveSync', 'other') -BuiltInControls @('block')))
            $v = View -LicenseProfile $null
            (Baseline $v 'block-legacy-auth').Status | Should -Be 'Enforced'
        }
        It 'no license profile at all (not read) -> Missing with a note that says unread, never a confirmed NotLicensed' {
            SetSD -IsEnabled $false
            SetCA -Policies @()
            $b = Baseline (View -LicenseProfile $null) 'sign-in-risk'
            $b.Status | Should -Be 'Missing'
            $b.Note | Should -Match 'not read'
        }
        It 'a license profile that positively lacks the requirement -> NotLicensed' {
            SetSD -IsEnabled $false
            SetCA -Policies @()
            $fakeProfile = [pscustomobject]@{ SuppressedLicenseRequirements = [System.Collections.Generic.HashSet[string]]::new(); ServicePlans = @() }
            $b = Baseline (View -LicenseProfile $fakeProfile) 'sign-in-risk'
            $b.Status | Should -Be 'NotLicensed'
        }
    }

    Context 'View contract: no findings, no score change' {
        It 'emits no findings and calls none of the finding/scoring/write functions' {
            SetCA -Policies @((Pol))
            $before = @(Get-NRGFindings).Count
            $null = View
            @(Get-NRGFindings).Count | Should -Be $before
        }
        It 'the source file calls none of Add-NRGFinding, Register-NRGCoverage, Set-NRGRawData, Invoke-NRGGraphRequest' {
            $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Get-NRGConditionalAccessView.ps1') -Raw
            foreach ($forbidden in @('Add-NRGFinding', 'Register-NRGCoverage', 'Set-NRGRawData', 'Invoke-NRGGraphRequest', 'Invoke-RestMethod')) {
                $src | Should -Not -Match ([regex]::Escape($forbidden)) -Because "the view must never call $forbidden"
            }
        }
        It 'is not exported (module surface stays 324)' {
            $manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $script:RepoRoot 'NRG-Assessment.psd1')
            $manifest.FunctionsToExport | Should -Not -Contain 'Get-NRGConditionalAccessView'
        }
    }

    Context 'Catalog integrity' {
        It 'every template cites a real learn.microsoft.com source and a license requirement the profile helper understands' {
            $catalog = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/conditional-access-baseline.json') -Raw | ConvertFrom-Json
            $plans = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/license-service-plans.json') -Raw | ConvertFrom-Json
            $reqKeys = @($plans.requirements.PSObject.Properties.Name)
            @($catalog.templates).Count | Should -BeGreaterThan 5
            foreach ($t in $catalog.templates) {
                $t.SourceUrl | Should -Match '^https://learn\.microsoft\.com/'
                $reqKeys | Should -Contain $t.LicenseRequirement
            }
            (@($catalog.templates.Id) | Sort-Object -Unique).Count | Should -Be (@($catalog.templates.Id)).Count
        }
    }

    Context 'Rendering (HTML + Markdown), including the hostile-name / injection case' {
        BeforeAll {
            $script:Metadata = @{ TenantDomain = 'contoso.onmicrosoft.com'; TenantId = '00000000-0000-0000-0000-000000000000'; Operator = 'a@b.com'; AssessmentDate = 'Sep 25, 2026'; AssessmentTime = '2026-09-25T00:00:00Z'; ToolVersion = '4.14.1'; QuickScan = $false }
            $script:Connections = @{ Graph = $true; EXO = $true; IPPSSession = $true; Teams = $true; SharePoint = $true }
            $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-catest-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
            New-Item -ItemType Directory -Force -Path $script:Tmp | Out-Null
        }
        # Runs AFTER the Describe-level BeforeEach (Clear-NRGState) — a
        # Context BeforeAll here would run BEFORE that outer BeforeEach on
        # the first It and have its raw data wiped out from under it.
        BeforeEach {
            SetSD -IsEnabled $false
            SetCA -Policies @(
                (Pol -Id 'ro1' -Name 'ZZROPOLICY' -State 'enabledForReportingButNotEnforced'),
                (Pol -Id 'x1'  -Name 'a|b [x](javascript:alert(1)) <script>nrgxsscav</script>' -IncludeApps @('some-app-guid'))
            )
            Add-NRGFinding -ControlId 'AAD-1.1' -State 'Satisfied' -Category 'Identity' -Title 'x' -Detail 'x'
            $script:Findings = Get-NRGFindings
        }

        It 'the HTML report renders both cards, marks the report-only policy correctly, and escapes the hostile name' {
            $out = Join-Path $script:Tmp 'r.html'
            Publish-NRGAssessmentHTML -Metadata $script:Metadata -Findings $script:Findings -Connections $script:Connections -OutputPath $out -ErrorAction Stop
            $html = Get-Content -LiteralPath $out -Raw
            $q = [char]34
            $html.Contains("id=$q" + 'ca-policies' + "$q") | Should -BeTrue
            $html.Contains("id=$q" + 'ca-baseline' + "$q") | Should -BeTrue
            $html | Should -Match 'data-goto="ca-policies"'
            ($html -match 'ZZROPOLICY[\s\S]{0,400}Report-only') | Should -BeTrue
            $html | Should -Not -Match '<script>nrgxsscav'
            $html | Should -Not -Match 'href="javascript:'
            $html | Should -Match 'nrgxsscav'
        }

        It 'the Markdown summary lists the ## Conditional Access section with a working Microsoft Learn link' {
            $out = Join-Path $script:Tmp 'r.md'
            Publish-NRGAssessmentSummary -Metadata $script:Metadata -Findings $script:Findings -Connections $script:Connections -OutputPath $out -ErrorAction Stop
            $md = Get-Content -LiteralPath $out -Raw
            $md | Should -Match '## Conditional Access'
            $md | Should -Match 'ZZROPOLICY'
            ($md -match ('\[Block legacy authentication\]\(https://learn\.microsoft\.com')) | Should -BeTrue
        }

        It 'renders a graceful state when Conditional Access data was not collected, instead of omitting the section silently' {
            Clear-NRGState
            Add-NRGFinding -ControlId 'AAD-1.1' -State 'Satisfied' -Category 'Identity' -Title 'x' -Detail 'x'
            $findings2 = Get-NRGFindings
            $out = Join-Path $script:Tmp 'r2.html'
            Publish-NRGAssessmentHTML -Metadata $script:Metadata -Findings $findings2 -Connections $script:Connections -OutputPath $out -ErrorAction Stop
            $html2 = Get-Content -LiteralPath $out -Raw
            $q = [char]34
            $html2.Contains("id=$q" + 'ca-policies' + "$q") | Should -BeFalse -Because 'no AAD-CAPolicies raw data at all is NotCollected, and the section is omitted rather than shown empty'
        }
    }
}
