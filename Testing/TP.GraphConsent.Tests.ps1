#Requires -Version 7.0
#
# TP.GraphConsent.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# AAD-8.2, AAD-11.3 and DEF-4.6 need a Graph permission that each client
# tenant must consent to once. Without it they reported a generic "not
# collected" that did not say which permission, why, or how to fix it.
# Connect-TPServices now records the token's granted scopes, and these
# controls name the missing consent — but ONLY when the granted list was
# actually read. No record, or an empty list, is "unknown" and keeps the
# generic message: absence of evidence is never evidence.

Describe 'Graph consent is named, never guessed' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        $script:AllScopes = @(& $script:Mod { Get-TPGraphScopeList })

        function script:Set-Consent {
            param([string[]]$Granted, [string]$Mode = 'Delegated')
            & $script:Mod { param($g, $m, $all) Set-TPGraphConsentState -Mode $m -GrantedScopes $g -RequestedScopes $all | Out-Null } $Granted $Mode $script:AllScopes
        }
        function script:Set-Unreadable {
            Set-TPRawData -Key 'AAD-PIMSchedules' -Data ([ordered]@{
                CollectorId = 'AAD-PIM'; CollectedAt = '2026-09-24T00:00:00Z'; Success = $true
                PIMAvailable = $true; AccessReviewsCollected = $false; Data = @{ AccessReviews = @() } })
            Set-TPRawData -Key 'AAD-AuthPolicies' -Data ([ordered]@{
                CollectorId = 'AAD-AuthPolicies'; CollectedAt = '2026-09-24T00:00:00Z'; Success = $true; Data = @{} })
            Set-TPRawData -Key 'Defender-Policies' -Data ([ordered]@{
                CollectorId = 'Defender'; CollectedAt = '2026-09-24T00:00:00Z'; Success = $true
                Data = @{ AttackSimulations = @{ Available = $false } } })
        }
        function script:Get-Detail([string]$Fn, [string]$Cid) {
            & $Fn | Out-Null
            @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid })[0]
        }
    }

    BeforeEach { Clear-TPState; Set-Unreadable }

    $cases = @(
        @{ Cid = 'AAD-8.2';  Fn = 'Test-TPControlAADAccessReviews';          Scope = 'AccessReview.Read.All' }
        @{ Cid = 'AAD-11.3'; Fn = 'Test-TPControlAADRiskyServicePrincipals'; Scope = 'IdentityRiskyServicePrincipal.Read.All' }
        @{ Cid = 'DEF-4.6';  Fn = 'Test-TPControlDefenderAttackSim';         Scope = 'AttackSimulation.Read.All' }
    )

    It '<Cid>: names the missing consent and how to fix it when the token lacks <Scope>' -TestCases $cases {
        Set-Consent -Granted @($script:AllScopes | Where-Object { $_ -ne $Scope })
        $f = Get-Detail $Fn $Cid
        $f.State  | Should -Be 'NotApplicable'
        $f.Detail | Should -Match ([regex]::Escape("has not granted admin consent for the $Scope"))
        $f.Detail | Should -Match 'Grant-TPGraphConsent\.ps1'
        $f.Detail | Should -Match 'not a pass'
    }

    It '<Cid>: app-only mode points at the app registration, not the delegated script' -TestCases $cases {
        Set-Consent -Mode AppOnly -Granted @('Directory.Read.All')
        $f = Get-Detail $Fn $Cid
        $f.Detail | Should -Match 'APPLICATION permission'
        $f.Detail | Should -Not -Match 'Grant-TPGraphConsent'
    }

    It '<Cid>: keeps the generic message when the scope WAS granted (the cause is elsewhere, e.g. licensing)' -TestCases $cases {
        Set-Consent -Granted $script:AllScopes
        (Get-Detail $Fn $Cid).Detail | Should -Not -Match 'has not granted admin consent'
    }

    It '<Cid>: never claims missing consent when the granted list is unknown' -TestCases $cases {
        (Get-Detail $Fn $Cid).Detail | Should -Not -Match 'has not granted admin consent' -Because 'no Graph-Consent record at all'
        Set-Consent -Granted @()
        (Get-Detail $Fn $Cid).Detail | Should -Not -Match 'has not granted admin consent' -Because 'an empty scope list is unknown, not "nothing granted"'
    }

    It '<Cid>: the consent-missing finding keeps its framework citations' -TestCases $cases {
        Set-Consent -Granted @('Directory.Read.All')
        (@((Get-Detail $Fn $Cid).FrameworkIds) -join ' ') | Should -Match 'NIST:'
    }

    It 'the scope-to-control map covers exactly the three consent controls' {
        $map = @(& $script:Mod { Get-TPConsentScopeMap })
        ($map.ControlId | Sort-Object) -join ',' | Should -Be 'AAD-11.3,AAD-8.2,DEF-4.6'
        foreach ($m in $map) { $script:AllScopes | Should -Contain $m.Scope }
    }

    It 'the missing list reaches the console as scope names, not "System.Object[]"' {
        # Connect-TPServices wraps the call in @(); a function that returned
        # ,$missing handed it a one-element array holding the array, so the
        # console printed System.Object[] and the blocked-control line (which
        # matches scope names) never printed at all.
        $granted = @($script:AllScopes | Where-Object { $_ -ne 'AccessReview.Read.All' -and $_ -ne 'AttackSimulation.Read.All' })
        # Joined inside module scope, exactly as Connect-TPServices does:
        # returning the array out of the scriptblock would unroll it and hide the bug.
        $line = & $script:Mod { param($g, $all)
            $m = @(Set-TPGraphConsentState -Mode Delegated -GrantedScopes $g -RequestedScopes $all)
            "$($m.Count)|$(($m | Sort-Object) -join ', ')" } $granted $script:AllScopes
        $line | Should -Be '2|AccessReview.Read.All, AttackSimulation.Read.All'
        $connect = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Connect-TPServices.ps1') -Raw
        $connect | Should -Match '\$missingScopes = @\(Set-TPGraphConsentState'
    }

    It 'app-only onboarding requests the three consent permissions' {
        $reg = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Onboard/Register-TPTenantApp.ps1') -Raw
        foreach ($s in 'IdentityRiskyServicePrincipal.Read.All', 'AttackSimulation.Read.All', 'AccessReview.Read.All') {
            $reg | Should -Match ([regex]::Escape("'$s'"))
        }
    }

    It 'Grant-TPGraphConsent.ps1 only signs in and reads — no Graph write cmdlets' {
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Grant-TPGraphConsent.ps1') -Raw
        $src | Should -Not -Match '\b(New|Update|Remove|Set)-Mg'
        $src | Should -Not -Match 'Invoke-(MgGraphRequest|RestMethod|WebRequest)'
        $src | Should -Match 'Get-TPGraphScopeList'
    }
}
