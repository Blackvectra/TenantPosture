#Requires -Version 7.0
#
# NRG.AppPermissions.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Pins AAD-15.1 / AAD-15.2 — APPLICATION (app-only) permission grants.
#
# WHY THESE CONTROLS EXIST
# ------------------------
# AAD-12.4 reads `oauth2PermissionGrants`, the DELEGATED consent table. An
# app-only grant is an `appRoleAssignment` and does not appear there at all, so
# a malicious application permission returns ZERO rows from the endpoint
# AAD-12.4 queries and the report says the tenant is clean. These controls read
# the other table.
#
# WHAT THESE TESTS GUARD
# ----------------------
# The highest-consequence failure is not a missed finding, it is a FALSE PASS:
# a tenant-takeover control reporting Satisfied because the query 403'd. Several
# tests below exist solely to prove that cannot happen.
#
# The Graph mock is injected into MODULE scope (Set-Item function:script:),
# because the collector's call to Invoke-NRGGraphRequest resolves inside the
# module and a test-scope Mock would never be seen. It returns the real Graph
# shapes: a `value` array, `@odata.nextLink`, `appRoles` with id/value pairs,
# and `appRoleAssignedTo` rows keyed by principalId and appRoleId.

Describe 'Application (app-only) permission controls' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'

        $script:MsOrg  = 'f8cdef31-a31e-4b4a-93e4-5f571e91255a'
        $script:Tenant = '11111111-1111-1111-1111-111111111111'
        $script:Ext    = '99999999-9999-9999-9999-999999999999'

        # Note the organization branch is anchored on '/organization?'. An
        # unanchored '*organization*' also matches the SELECT list, which
        # contains appOwnerOrganizationId, because -like is case-insensitive —
        # that mistake silently fed the principal lookup the wrong response and
        # made every grant's owner read as Unknown.
        & $script:Mod { param($n, $b) Set-Item -Path "function:script:$n" -Value ([scriptblock]::Create($b)) } 'Invoke-NRGGraphRequest' @'
[CmdletBinding()]
param([string] $Uri, [string] $Method = 'GET', $Body, $Headers, [string] $OutputType = 'HashTable')
$s = $script:AppPermScenario
if ($s -eq 'GraphFails' -and $Uri -like "*appId eq '00000003-0000-0000-c000-000000000000'*") { throw 'Graph 403 Forbidden' }
if ($Uri -like '*/organization?*') { return @{ value = @(@{ id = '11111111-1111-1111-1111-111111111111' }) } }

if ($Uri -like '*servicePrincipals?*$select=id,appId,displayName,appOwnerOrganizationId*') {
    return @{ value = @(
        @{ id='sp-ms';    appId='aaaa'; displayName='Microsoft Intune';   appOwnerOrganizationId='f8cdef31-a31e-4b4a-93e4-5f571e91255a'; servicePrincipalType='Application'; accountEnabled=$true }
        @{ id='sp-own';   appId='bbbb'; displayName='Our Backup Tool';    appOwnerOrganizationId='11111111-1111-1111-1111-111111111111'; servicePrincipalType='Application'; accountEnabled=$true }
        @{ id='sp-ext';   appId='cccc'; displayName='ThirdParty Connect'; appOwnerOrganizationId='99999999-9999-9999-9999-999999999999'; servicePrincipalType='Application'; accountEnabled=$true }
        @{ id='sp-noown'; appId='dddd'; displayName='Mystery App';        servicePrincipalType='Application'; accountEnabled=$true }
    ) }
}
if ($Uri -like "*appId eq '*'*") {
    $rid = if ($Uri -like '*00000002-0000-0ff1-ce00*') { 'sp-exo' } elseif ($Uri -like '*00000003-0000-0ff1-ce00*') { 'sp-spo' } else { 'sp-graph' }
    return @{ value = @(@{ id = $rid; displayName = $rid; appRoles = @(
        @{ id='role-rmrw';    value='RoleManagement.ReadWrite.Directory' }
        @{ id='role-mailrw';  value='Mail.ReadWrite' }
        @{ id='role-userr';   value='User.Read.All' }
        @{ id='role-full';    value='full_access_as_app' }
        @{ id='role-unrated'; value='Printer.Read.All' }
    ) }) }
}
if ($Uri -like '*appRoleAssignedTo*') {
    if ($s -eq 'ExoFails' -and $Uri -like '*sp-exo*') { throw 'EXO 403 Forbidden' }
    if ($s -eq 'Clean') { return @{ value = @() } }
    if ($Uri -like '*sp-exo*') {
        if ($s -eq 'ExoFullAccess') { return @{ value = @(@{ principalId='sp-ext'; principalDisplayName='ThirdParty Connect'; principalType='ServicePrincipal'; appRoleId='role-full'; createdDateTime='2026-09-10T00:00:00Z' }) } }
        return @{ value = @() }
    }
    if ($Uri -notlike '*sp-graph*') { return @{ value = @() } }

    # Paging: the first Graph page hands back a nextLink, the second does not.
    if ($s -eq 'Paged') {
        if ($Uri -notlike '*page2*') {
            return @{ '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/servicePrincipals/sp-graph/appRoleAssignedTo?page2'
                      value = @(@{ principalId='sp-own'; principalDisplayName='Our Backup Tool'; principalType='ServicePrincipal'; appRoleId='role-userr'; createdDateTime='2024-05-05T00:00:00Z' }) }
        }
        return @{ value = @(@{ principalId='sp-ext'; principalDisplayName='ThirdParty Connect'; principalType='ServicePrincipal'; appRoleId='role-rmrw'; createdDateTime='2026-09-18T00:00:00Z' }) }
    }

    $v = @(
        @{ principalId='sp-ms';    principalDisplayName='Microsoft Intune';   principalType='ServicePrincipal'; appRoleId='role-rmrw';    createdDateTime='2020-01-01T00:00:00Z' }
        @{ principalId='sp-own';   principalDisplayName='Our Backup Tool';    principalType='ServicePrincipal'; appRoleId='role-userr';   createdDateTime='2024-05-05T00:00:00Z' }
        @{ principalId='sp-noown'; principalDisplayName='Mystery App';        principalType='ServicePrincipal'; appRoleId='role-unrated'; createdDateTime='2024-05-05T00:00:00Z' }
    )
    if ($s -eq 'ExternalTakeover') { $v += @{ principalId='sp-ext'; principalDisplayName='ThirdParty Connect'; principalType='ServicePrincipal'; appRoleId='role-rmrw';   createdDateTime='2026-09-18T00:00:00Z' } }
    if ($s -eq 'ExternalData')     { $v += @{ principalId='sp-ext'; principalDisplayName='ThirdParty Connect'; principalType='ServicePrincipal'; appRoleId='role-mailrw'; createdDateTime='2026-09-01T00:00:00Z' } }
    if ($s -eq 'UnknownOwner')     { $v += @{ principalId='sp-noown'; principalDisplayName='Mystery App';      principalType='ServicePrincipal'; appRoleId='role-rmrw';   createdDateTime='2026-09-18T00:00:00Z' } }
    return @{ value = $v }
}
return @{ value = @() }
'@

        function script:Run {
            param([string] $Scenario)
            & $script:Mod { param($s) $script:AppPermScenario = $s } $Scenario
            Clear-NRGState
            $raw = Invoke-NRGCollectAADAppPermissions 3>$null
            Test-NRGControlAppPermTenantTakeover
            Test-NRGControlAppPermDataAccess
            $f = @(Get-NRGFindings)
            [pscustomobject]@{
                Raw = $raw
                T1  = @($f | Where-Object { $_.ControlId -eq 'AAD-15.1' })[0]
                T2  = @($f | Where-Object { $_.ControlId -eq 'AAD-15.2' })[0]
            }
        }
    }

    AfterAll { Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    Context 'a failed query is never a pass' {

        It 'reports NotApplicable, not Satisfied, when the Graph resource query fails' {
            # THE failure that matters. An empty grant list after a 403 is
            # indistinguishable from a genuinely clean tenant, and a Critical
            # control must not resolve that ambiguity in the tenant's favour.
            $o = Run 'GraphFails'
            $o.T1.State  | Should -Be 'NotApplicable'
            $o.T2.State  | Should -Be 'NotApplicable'
            $o.T1.Detail | Should -Match 'did not complete'
            $o.T1.Detail | Should -Not -Match '(?i)no (non-Microsoft )?application holds'
        }

        It 'refuses a verdict when any ONE watched resource fails, even if the others succeeded' {
            # Exchange is where full_access_as_app lives. Scoring the Graph
            # results alone and calling it clean would miss the worst grant in
            # the product.
            $o = Run 'ExoFails'
            @($o.Raw.Data.Grants).Count | Should -BeGreaterThan 0 -Because 'Graph still returned rows'
            $o.T1.State | Should -Be 'NotApplicable'
            $o.T2.State | Should -Be 'NotApplicable'
            $o.T1.Detail | Should -Match 'Exchange'
        }

        It 'registers Partial coverage when one resource fails, never Collected' {
            $null = Run 'ExoFails'
            (Get-NRGCoverage)['AAD-AppPermissions'].Status | Should -Be 'Partial'
        }

        It 'reports NotApplicable when the collector never ran at all' {
            Clear-NRGState
            Test-NRGControlAppPermTenantTakeover
            Test-NRGControlAppPermDataAccess
            $f = @(Get-NRGFindings)
            @($f | Where-Object { $_.ControlId -eq 'AAD-15.1' })[0].State | Should -Be 'NotApplicable'
            @($f | Where-Object { $_.ControlId -eq 'AAD-15.2' })[0].State | Should -Be 'NotApplicable'
        }
    }

    Context 'verdicts' {

        It 'reports Satisfied when every resource was enumerated and nothing scored' {
            $o = Run 'Clean'
            $o.T1.State | Should -Be 'Satisfied'
            $o.T2.State | Should -Be 'Satisfied'
            (Get-NRGCoverage)['AAD-AppPermissions'].Status | Should -Be 'Collected'
        }

        It 'flags an external app holding a tenant-takeover permission as a Critical gap' {
            $o = Run 'ExternalTakeover'
            $o.T1.State    | Should -Be 'Gap'
            $o.T1.Severity | Should -Be 'Critical'
            ($o.T1.AffectedObjects -join ' ') | Should -Match 'ThirdParty Connect'
            ($o.T1.AffectedObjects -join ' ') | Should -Match 'RoleManagement.ReadWrite.Directory'
            ($o.T1.AffectedObjects -join ' ') | Should -Match 'External'
        }

        It 'flags Exchange full_access_as_app, which reads every mailbox in the tenant' {
            $o = Run 'ExoFullAccess'
            $o.T1.State    | Should -Be 'Gap'
            $o.T1.Severity | Should -Be 'Critical'
            ($o.T1.AffectedObjects -join ' ') | Should -Match 'full_access_as_app'
            ($o.T1.AffectedObjects -join ' ') | Should -Match 'Exchange'
        }

        It 'names mass data-access grants and rates them High when an outside party holds them' {
            $o = Run 'ExternalData'
            $o.T2.State    | Should -Be 'Gap'
            $o.T2.Severity | Should -Be 'High'
            ($o.T2.AffectedObjects -join ' ') | Should -Match 'Mail.ReadWrite'
        }

        It 'rates data access Medium when only the tenant''s own applications hold it' {
            # Same permission, lower exposure: the organization owns the app.
            $o = Run 'Default'
            $o.T2.State    | Should -Be 'Gap'
            $o.T2.Severity | Should -Be 'Medium'
            ($o.T2.AffectedObjects -join ' ') | Should -Match 'Our Backup Tool'
        }

        It 'records the grant date, which is what makes a new grant an indicator' {
            $o = Run 'ExternalTakeover'
            ($o.T1.AffectedObjects -join ' ') | Should -Match '2026-09-18'
        }

        It 'carries framework citations on every finding it emits' {
            # An uncited finding is dropped by the 800-53 family rollup as
            # unmapped and never reaches the NIST matrix.
            foreach ($sc in @('Clean', 'ExternalTakeover', 'GraphFails')) {
                $o = Run $sc
                @($o.T1.FrameworkIds).Count | Should -BeGreaterThan 0 -Because $sc
                @($o.T2.FrameworkIds).Count | Should -BeGreaterThan 0 -Because $sc
            }
        }
    }

    Context 'Microsoft first-party apps are set aside, never hidden' {

        It 'does not score a Microsoft-published app holding a tenant-takeover permission' {
            # Microsoft's own service principals legitimately hold these.
            # Scoring them buries the one grant that matters under the ones
            # that do not.
            $o = Run 'Default'
            $o.T1.State | Should -Be 'Satisfied'
        }

        It 'states how many first-party grants were set aside, so nothing is silently dropped' {
            $o = Run 'Default'
            $o.T1.Detail | Should -Match 'Microsoft first-party'
            $o.T1.Detail | Should -Match '\d+ grant'
        }

        It 'scores an app whose owner cannot be determined, rather than assuming it is Microsoft' {
            # An unattributable app is the one to look at hardest, not the one
            # to wave through.
            $o = Run 'UnknownOwner'
            $o.T1.State | Should -Be 'Gap'
            ($o.T1.AffectedObjects -join ' ') | Should -Match 'Mystery App'
        }
    }

    Context 'collection mechanics' {

        It 'follows @odata.nextLink' {
            # Get-NRGNestedProperty splits its path on '.', so a read of
            # '@odata.nextLink' through it resolves @odata -> nextLink, returns
            # the default, and paging silently stops after page one — a tenant
            # would be reported as fully enumerated off a partial list.
            $o = Run 'Paged'
            @($o.Raw.Data.Grants).Count | Should -Be 2
            ($o.T1.AffectedObjects -join ' ') | Should -Match 'ThirdParty Connect' -Because 'the takeover grant is only on page 2'
        }

        It 'collects a permission the catalog does not rate, but does not score it' {
            # Absence from the catalog is "unrated", not "safe".
            $o = Run 'Default'
            @($o.Raw.Data.Grants | Where-Object { $_.Permission -eq 'Printer.Read.All' }).Count | Should -Be 1
            ($o.T1.AffectedObjects -join ' ') | Should -Not -Match 'Printer.Read.All'
            ($o.T2.AffectedObjects -join ' ') | Should -Not -Match 'Printer.Read.All'
        }

        It 'resolves appRoleId GUIDs to permission names' {
            $o = Run 'Default'
            @($o.Raw.Data.Grants | Where-Object { $_.Permission -eq 'role-rmrw' }).Count | Should -Be 0
            @($o.Raw.Data.Grants | Where-Object { $_.Permission -eq 'RoleManagement.ReadWrite.Directory' }).Count | Should -BeGreaterThan 0
        }

        It 'publishes a SectionStatus entry for every watched resource' {
            $o = Run 'Clean'
            @($o.Raw.Data.SectionStatus.Keys).Count | Should -Be 3
        }
    }

    Context 'the risk catalog' {

        BeforeAll { $script:Cat = Get-NRGAppPermissionRiskCatalog }

        It 'loads' { $script:Cat | Should -Not -BeNullOrEmpty }

        It 'gives every entry a permission and a reason' {
            foreach ($tier in @('tier1', 'tier2')) {
                foreach ($e in @($script:Cat.$tier)) {
                    $e.Permission | Should -Not -BeNullOrEmpty
                    $e.Why        | Should -Not -BeNullOrEmpty -Because "$($e.Permission) must say why it is rated"
                }
            }
        }

        It 'never lists the same permission in both tiers' {
            $t1 = @($script:Cat.tier1 | ForEach-Object { $_.Permission })
            $t2 = @($script:Cat.tier2 | ForEach-Object { $_.Permission })
            @($t1 | Where-Object { $_ -in $t2 }) | Should -BeNullOrEmpty
        }

        It 'rates the permissions that actually confer takeover' {
            $t1 = @($script:Cat.tier1 | ForEach-Object { $_.Permission })
            foreach ($p in @('RoleManagement.ReadWrite.Directory', 'Application.ReadWrite.All',
                             'AppRoleAssignment.ReadWrite.All', 'Domain.ReadWrite.All', 'full_access_as_app')) {
                $t1 | Should -Contain $p
            }
        }

        It 'rates the mass data-access permissions' {
            $t2 = @($script:Cat.tier2 | ForEach-Object { $_.Permission })
            foreach ($p in @('Mail.ReadWrite', 'Mail.Send', 'Files.ReadWrite.All', 'MailboxSettings.ReadWrite')) {
                $t2 | Should -Contain $p
            }
        }
    }

    Context 'wiring' {

        It 'has both controls in controls.json pointing at these evaluators' {
            $defs = @(Get-NRGControlDefinitions)
            foreach ($pair in @(@{ Id = 'AAD-15.1'; Fn = 'Test-NRGControlAppPermTenantTakeover' },
                                @{ Id = 'AAD-15.2'; Fn = 'Test-NRGControlAppPermDataAccess' })) {
                $c = @($defs | Where-Object { $_.ControlId -eq $pair.Id })
                $c.Count | Should -Be 1
                $c[0].EvaluatorFunction    | Should -Be $pair.Fn
                $c[0].CollectorDependency  | Should -Be 'AAD-AppPermissions'
                Get-Command $pair.Fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty
            }
        }

        It 'rates the takeover control Critical in controls.json' {
            @(Get-NRGControlDefinitions | Where-Object { $_.ControlId -eq 'AAD-15.1' })[0].Severity | Should -Be 'Critical'
        }

        It 'needs no Graph scope the tool does not already request' {
            # The selling point: this closes the biggest hole with no re-consent
            # in any client tenant.
            $conn = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Connect-NRGServices.ps1') -Raw
            foreach ($scope in @('Application.Read.All', 'Directory.Read.All', 'Organization.Read.All')) {
                $conn | Should -Match ([regex]::Escape($scope))
            }
        }
    }
}
