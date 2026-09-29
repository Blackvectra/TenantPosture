#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.BaselinePlan.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Pins the baseline plan (Get-NRGBaselinePlan): every required
             control lands in exactly one expected bucket; licensing that was
             not read is Unknown, never assumed held or blocked; a declared
             third-party EDR, a skipped workload and an optional collector move
             the right controls; the plan creates no finding; the comparison
             names what the run did not verify that the plan expected it to;
             the optional-collector catalog matches the evaluators; and the
             standalone entry point connects to nothing.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'NRG baseline plan — predictive, never a verdict' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        Clear-NRGState
        $script:Def = Get-NRGBaselineDefinition -Force
        $script:Plan = Get-NRGBaselinePlan -TargetTier Standard
        $script:Buckets = @('Automatic', 'Manual', 'ThirdPartyHandled', 'OptionalCollectorRequired', 'SkippedByOperator', 'LicenseBlockedExpected', 'LicensingUnknown')
    }
    AfterAll { Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    It 'covers every required control once and the buckets sum to the required count' {
        $required = @(Get-NRGBaselineRequiredControls -TargetTier Standard -Definition $script:Def)
        @($script:Plan.Controls).Count | Should -Be $required.Count
        @($script:Plan.Controls | ForEach-Object { $_.ControlId } | Select-Object -Unique).Count | Should -Be $required.Count
        $sum = 0; foreach ($b in $script:Buckets) { $sum += [int]$script:Plan.Summary[$b] }
        $sum | Should -Be $script:Plan.Summary.RequiredControls
        foreach ($r in $script:Plan.Controls) { $r.Expected | Should -BeIn $script:Buckets -Because "$($r.ControlId) must land in a known bucket" }
    }

    It 'keeps BaselineVersion 1.0 and names the tier' {
        $script:Plan.BaselineVersion | Should -Be '1.0'
        $script:Plan.Summary.BaselineVersion | Should -Be '1.0'
        $script:Plan.TargetTier | Should -Be 'Standard'
    }

    It 'creates no finding and touches no module state' {
        @(Get-NRGFindings).Count | Should -Be 0
        $null = Get-NRGBaselinePlan -TargetTier Hardened -ThirdPartyEDR 'Cortex XDR' -IncludeSharePointShell
        @(Get-NRGFindings).Count | Should -Be 0
    }

    It 'reports licensing as Unknown until connection when no profile is supplied — never held, never blocked' {
        $script:Plan.Summary.LicenseSource | Should -Be 'not read'
        $script:Plan.Summary.LicenseBlockedExpected | Should -Be 0
        $unknown = @($script:Plan.Controls | Where-Object { $_.Expected -eq 'LicensingUnknown' })
        $unknown.Count | Should -BeGreaterThan 0
        foreach ($r in $unknown) {
            $r.LicenseRequirement | Should -Not -Match '^Included'
            $r.Reason | Should -Match 'Unknown until tenant connection'
        }
        # An Included requirement never waits for licensing.
        foreach ($r in @($script:Plan.Controls | Where-Object { $_.LicenseRequirement -match '^Included' })) {
            $r.Expected | Should -Not -Be 'LicensingUnknown' -Because "$($r.ControlId) is Included"
        }
    }

    It 'a profile without SKU data counts as not read' {
        $empty = Get-NRGTenantLicenseProfile -SubscribedSkus @()
        $p = Get-NRGBaselinePlan -TargetTier Standard -LicenseProfile $empty -LicenseSource 'empty'
        $p.Summary.LicenseSource | Should -Be 'not read'
        $p.Summary.LicensingUnknown | Should -Be $script:Plan.Summary.LicensingUnknown
    }

    It 'a profile with SKU data resolves licensing: a held requirement is Automatic, an unmet one is LicenseBlockedExpected' {
        # Business Premium: Entra P1, Intune P1, Defender for Office P1 held; Entra P2 not.
        $bp = Get-NRGTenantLicenseProfile -SubscribedSkus @(
            [pscustomobject]@{ skuPartNumber = 'SPB'; servicePlans = @(
                [pscustomobject]@{ servicePlanName = 'AAD_PREMIUM';         provisioningStatus = 'Success' },
                [pscustomobject]@{ servicePlanName = 'INTUNE_A';            provisioningStatus = 'Success' },
                [pscustomobject]@{ servicePlanName = 'ATP_ENTERPRISE';      provisioningStatus = 'Success' },
                [pscustomobject]@{ servicePlanName = 'EXCHANGE_S_STANDARD'; provisioningStatus = 'Success' },
                [pscustomobject]@{ servicePlanName = 'WINDEFATP';           provisioningStatus = 'Success' }
            ) }
        )
        $bp.HasLicenseData | Should -BeTrue
        $p = Get-NRGBaselinePlan -TargetTier Hardened -LicenseProfile $bp -LicenseSource 'test'
        $p.Summary.LicensingUnknown | Should -Be 0
        $p.Summary.LicenseSource | Should -Be 'test'
        $p2 = @($p.Controls | Where-Object { $_.LicenseRequirement -match 'P2' })
        $p2.Count | Should -BeGreaterThan 0 -Because 'Hardened carries Entra ID P2 controls'
        foreach ($r in $p2) { $r.Expected | Should -Be 'LicenseBlockedExpected' -Because "$($r.ControlId) needs P2 and Business Premium lacks it" }
        $p1 = @($p.Controls | Where-Object { $_.ControlId -eq 'AAD-1.1' })[0]
        $p1.Expected | Should -Be 'Automatic'
        $p1.LicenseStatus | Should -Be 'Met'
    }

    It 'a declared third-party EDR moves exactly the Defender endpoint checks to ThirdPartyHandled, attested and not verified' {
        $p = Get-NRGBaselinePlan -TargetTier Standard -ThirdPartyEDR 'Cortex XDR'
        $ids = @(& (Get-Module 'NRG-Assessment') { Get-NRGDefenderEndpointCheckIds })
        $handled = @($p.Controls | Where-Object { $_.Expected -eq 'ThirdPartyHandled' })
        $handled.Count | Should -BeGreaterThan 0
        foreach ($r in $handled) {
            $r.ControlId | Should -BeIn $ids
            $r.Reason | Should -Match 'attested and not verified'
        }
        foreach ($r in @($p.Controls | Where-Object { $_.ControlId -in $ids })) { $r.Expected | Should -Be 'ThirdPartyHandled' }
        $script:Plan.Summary.ThirdPartyHandled | Should -Be 0 -Because 'nothing is third-party handled without a declaration'
    }

    It 'a skipped workload moves its controls to SkippedByOperator, counted as expected NotVerified' {
        $p = Get-NRGBaselinePlan -TargetTier Standard -SkipCollectors @('Purview', 'Teams')
        $skipped = @($p.Controls | Where-Object { $_.Expected -eq 'SkippedByOperator' })
        $skipped.Count | Should -BeGreaterThan 0
        foreach ($r in $skipped) {
            @($r.RawDataKeys | Where-Object { $_ -in @('Purview', 'Teams') }).Count | Should -BeGreaterThan 0
            $r.ExpectedNotVerified | Should -BeTrue
        }
        $svc = @($p.RequiredCollectors | Where-Object { $_.Service -eq 'Teams' })[0]
        $svc.Status | Should -Be 'Skipped by operator'
        $p.Summary.ExpectedNotVerified | Should -Be ($p.Summary.Manual + $p.Summary.SkippedByOperator + $p.Summary.OptionalCollectorRequired)
    }

    It 'a required control that needs the SharePoint shell is OptionalCollectorRequired until the shell is enabled' {
        $catalog = Get-NRGOptionalCollectorCatalog
        $catalog.Contains('SharePointShell') | Should -BeTrue
        $needs = @($script:Plan.Controls | Where-Object { $_.OptionalCollector -eq $catalog['SharePointShell'].Name })
        $needs.Count | Should -BeGreaterThan 0
        foreach ($r in $needs) {
            $r.Expected | Should -Be 'OptionalCollectorRequired'
            $r.Reason | Should -Match 'IncludeSharePointShell'
        }
        $opt = @($script:Plan.OptionalCollectors | Where-Object { $_.Switch -eq '-IncludeSharePointShell' })[0]
        $opt.Enabled | Should -BeFalse
        $opt.Controls | Should -Be $needs.Count
        $on = Get-NRGBaselinePlan -TargetTier Standard -IncludeSharePointShell
        $on.Summary.OptionalCollectorRequired | Should -Be 0
        foreach ($r in @($on.Controls | Where-Object { $_.ControlId -in @($needs | ForEach-Object { $_.ControlId }) })) {
            $r.Expected | Should -Not -Be 'OptionalCollectorRequired'
        }
    }

    It 'the manual control is Manual and expected NotVerified' {
        $vm = @($script:Plan.Controls | Where-Object { $_.ControlId -eq 'VM-VERIFY-01' })[0]
        $vm.Expected | Should -Be 'Manual'
        $vm.ExpectedNotVerified | Should -BeTrue
    }

    It 'lists every connection the required controls need' {
        $services = @($script:Plan.RequiredCollectors | ForEach-Object { $_.Service })
        foreach ($s in 'Graph', 'Exchange Online', 'Purview (Security & Compliance)', 'Teams') { $services | Should -Contain $s }
        @($services | Where-Object { $_ -like 'DNS*' }).Count | Should -Be 1
        @($services | Where-Object { $_ -like 'Unknown*' }).Count | Should -Be 0 -Because 'every raw-data key in the baseline maps to a connection'
    }

    It 'an approved exception is a disposition and changes no expected state' {
        $exc = @{ Available = $true; Approved = @{ 'AAD-1.1' = @{ ControlId = 'AAD-1.1' } }; Rejected = @() }
        $p = Get-NRGBaselinePlan -TargetTier Standard -Exceptions $exc
        $row = @($p.Controls | Where-Object { $_.ControlId -eq 'AAD-1.1' })[0]
        $row.Disposition | Should -Match '^ApprovedException'
        $row.Expected | Should -Be (@($script:Plan.Controls | Where-Object { $_.ControlId -eq 'AAD-1.1' })[0].Expected)
        $p.Summary.ApprovedExceptions | Should -Be 1
    }

    It 'the operator summary never reassures' {
        $text = (Format-NRGBaselinePlanSummary -Plan $script:Plan) -join "`n"
        $text | Should -Match 'required controls'
        $text | Should -Match 'Potential NotVerified before run'
        $text | Should -Match 'Licensing: not read'
        foreach ($bad in 'compliant', 'no issues', 'secure', 'passes') { $text | Should -Not -Match $bad }
        $script:Plan.Note | Should -Match 'Predictive'
    }
}

Describe 'NRG baseline plan — comparison with the run that followed' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        Clear-NRGState
        $script:Plan = Get-NRGBaselinePlan -TargetTier Standard
        $script:Compliance = {
            param([hashtable] $States)
            $rows = @(foreach ($cid in $States.Keys) {
                $st = $States[$cid]
                [ordered]@{ ControlId = $cid; ObservedState = $st; NotVerifiedCause = $(if ($st -eq 'NotVerified') { 'Evidence not read' } else { '' }); Constraint = 'None' }
            })
            [ordered]@{ Available = $true; BaselineVersion = '1.0'; TargetTier = 'Standard'; Controls = $rows; Summary = @{} }
        }
    }
    AfterAll { Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    It 'a run that matches the plan reports nothing unexpected' {
        $states = @{}
        foreach ($r in $script:Plan.Controls) { $states[$r.ControlId] = $(if ($r.ExpectedNotVerified) { 'NotVerified' } else { 'Satisfied' }) }
        $c = Compare-NRGBaselinePlan -Plan $script:Plan -Compliance (& $script:Compliance $states)
        $c.Available | Should -BeTrue
        @($c.UnexpectedNotVerified).Count | Should -Be 0
        @($c.ExpectedButVerified).Count | Should -Be 0
        $c.ExpectedNotVerified | Should -Be $script:Plan.Summary.ExpectedNotVerified
        $c.ObservedNotVerified | Should -Be $c.ExpectedNotVerified
    }

    It 'a control the plan expected to assess but the run did not verify is named, with its cause' {
        $states = @{}
        foreach ($r in $script:Plan.Controls) { $states[$r.ControlId] = $(if ($r.ExpectedNotVerified) { 'NotVerified' } else { 'Satisfied' }) }
        $states['EXO-7.2'] = 'NotVerified'
        $c = Compare-NRGBaselinePlan -Plan $script:Plan -Compliance (& $script:Compliance $states)
        @($c.UnexpectedNotVerified).Count | Should -Be 1
        $c.UnexpectedNotVerified[0].ControlId | Should -Be 'EXO-7.2'
        $c.UnexpectedNotVerified[0].Cause | Should -Be 'Evidence not read'
        $c.Note | Should -Match '1 not expected'
    }

    It 'a control the plan expected NotVerified that the run verified is named, and one the plan never knew is listed, not compared' {
        $states = @{}
        foreach ($r in $script:Plan.Controls) { $states[$r.ControlId] = $(if ($r.ExpectedNotVerified) { 'NotVerified' } else { 'Satisfied' }) }
        $states['VM-VERIFY-01'] = 'Satisfied'
        $states['SPO-3.3'] = 'NotVerified'
        $c = Compare-NRGBaselinePlan -Plan $script:Plan -Compliance (& $script:Compliance $states)
        @($c.ExpectedButVerified | ForEach-Object { $_.ControlId }) | Should -Contain 'VM-VERIFY-01'
        @($c.NotInPlan) | Should -Contain 'SPO-3.3'
        @($c.UnexpectedNotVerified | ForEach-Object { $_.ControlId }) | Should -Not -Contain 'SPO-3.3'
    }

    It 'is unavailable without a plan or a compliance view' {
        (Compare-NRGBaselinePlan -Plan $null -Compliance $null).Available | Should -BeFalse
        (Compare-NRGBaselinePlan -Plan $script:Plan -Compliance @{ Available = $false }).Available | Should -BeFalse
    }
}

Describe 'NRG baseline plan — rendered beside the compliance view' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        Clear-NRGState
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-plan-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
        $script:Plan = Get-NRGBaselinePlan -TargetTier Standard
        # One finding so the compliance view has a row; everything else NotVerified.
        Add-NRGFinding -ControlId 'AAD-1.1' -State 'Satisfied' -Category 'Identity' -Title 'Legacy auth blocked' -Severity 'High' -Detail 'blocked'
        $script:Findings = @(Get-NRGFindings)
        $script:Compliance = Get-NRGBaselineCompliance -Findings $script:Findings -TargetTier Standard -RawData @{} -Coverage @{}
        $script:Cmp = Compare-NRGBaselinePlan -Plan $script:Plan -Compliance $script:Compliance
        $script:Meta = @{
            TenantDomain = 'contoso.onmicrosoft.com'; TenantId = '00000000-0000-0000-0000-000000000000'
            Operator = 'assessor@nrgtechservices.com'; AssessmentDate = 'September 29, 2026'
            AssessmentTime = '2026-09-29T00:00:00.0000000+00:00'; ToolVersion = '4.14.3'; QuickScan = $false
            BaselineVersion = '1.0'; TargetTier = 'Standard'
        }
        $script:Conn = @{ Graph = $true; EXO = $false; Teams = $false; IPPSSession = $false; SharePoint = $false; TenantId = $script:Meta.TenantId }
    }
    AfterAll {
        Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue
        if ($script:Tmp -and (Test-Path $script:Tmp)) { Remove-Item $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'the comparison names the rows the plan expected to assess that the run did not verify' {
        $script:Cmp.Available | Should -BeTrue
        @($script:Cmp.UnexpectedNotVerified).Count | Should -BeGreaterThan 0 -Because 'nothing was collected, so every automatic control is an unexpected NotVerified'
        @($script:Cmp.UnexpectedNotVerified | ForEach-Object { $_.ControlId }) | Should -Not -Contain 'AAD-1.1'
    }

    It 'the Markdown summary renders the plan-versus-run block without reassuring' {
        $md = Join-Path $script:Tmp 'summary.md'
        Publish-NRGAssessmentSummary -Metadata $script:Meta -Findings $script:Findings -Connections $script:Conn -OutputPath $md -BaselinePlanComparison $script:Cmp | Out-Null
        $text = Get-Content -LiteralPath $md -Raw
        $text | Should -Match 'Expected before the run vs observed'
        $text | Should -Match ('Not verified, expected before the run \| ' + $script:Cmp.ExpectedNotVerified)
        $text | Should -Match ('Not verified, observed \| ' + $script:Cmp.ObservedNotVerified)
        $text | Should -Match '\| Not expected \| Cause \| Plan said \|'
        $text | Should -Not -Match 'is compliant'
    }

    It 'the HTML report renders the same block inside the baseline section' {
        $html = Join-Path $script:Tmp 'report.html'
        Publish-NRGAssessmentHTML -Metadata $script:Meta -Findings $script:Findings -Connections $script:Conn -OutputPath $html -BaselinePlanComparison $script:Cmp | Out-Null
        $text = Get-Content -LiteralPath $html -Raw
        $i = $text.IndexOf("id='nrg-baseline'")
        $i | Should -BeGreaterThan 0
        $section = $text.Substring($i)
        $section | Should -Match 'Expected before the run vs observed'
        $section | Should -Match 'Not verified, expected before the run'
        $section | Should -Match '<th>Not expected</th><th>Cause</th><th>Plan said</th>'
    }
}

Describe 'NRG baseline plan — catalog and entry point integrity' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Catalog = Get-NRGOptionalCollectorCatalog -Force
        $script:SpoSrc = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Evaluators/Test-NRGControlSharePoint.ps1') -Raw
        $script:Entry = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1') -Raw
        $script:Wrapper = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Get-NRGBaselinePlan.ps1') -Raw
        $script:Lib = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Get-NRGBaselinePlan.ps1') -Raw
    }
    AfterAll { Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    It 'the SharePoint shell catalog lists exactly the controls whose evaluator reads the shell' {
        # Split the evaluator into per-control segments (a "# SPO-x.y —" header
        # or a function boundary) and read which segments touch the shell.
        $segments = [regex]::Split($script:SpoSrc, '(?m)^(?=\s*# (?:── )?SPO-\d+\.\d+\b|function )')
        $derived = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($seg in $segments) {
            if ($seg -notmatch 'Get-NRGSpoShellUnread -Shell|\$noShell|IncludeSharePointShell') { continue }
            foreach ($m in [regex]::Matches($seg, "SPO-\d+\.\d+")) { $null = $derived.Add($m.Value) }
        }
        # The helper definition and the SPO-1.x preamble mention no shell-gated verdict of their own.
        $listed = @($script:Catalog['SharePointShell'].Controls.Keys)
        foreach ($cid in $listed) { $derived.Contains($cid) | Should -BeTrue -Because "$cid is in the catalog, so its evaluator must read the shell" }
        foreach ($cid in $derived) {
            if ($cid -in @('SPO-1.1', 'SPO-1.3')) { continue }   # share the SPO-1.x block; assessed from Graph alone
            $listed | Should -Contain $cid -Because "$cid's evaluator reads the shell, so the catalog must list it"
        }
    }

    It 'every catalog control exists in controls.json' {
        foreach ($cid in @($script:Catalog['SharePointShell'].Controls.Keys)) {
            (Get-NRGControlById -ControlId $cid) | Should -Not -BeNullOrEmpty -Because "$cid must be a real control"
        }
    }

    It 'Get-NRGWorkloadSkipMap equals the entry point''s skip table' {
        foreach ($sf in Get-NRGWorkloadSkipMap) {
            $keys = (@($sf.Keys) | ForEach-Object { "'$_'" }) -join ', '
            $script:Entry | Should -Match ([regex]::Escape("@{ On = `$$($sf.Flag);") + '\s+Flag = ' + [regex]::Escape("'-$($sf.Flag)'") + ';\s+Keys = @\(' + [regex]::Escape($keys) + '\)') `
                -Because "the entry point must skip the same keys for -$($sf.Flag)"
        }
        @(Get-NRGWorkloadSkipMap).Count | Should -Be ([regex]::Matches($script:Entry, '@\{ On = \$Skip\w+;\s+Flag = ')).Count
    }

    It 'the standalone entry point and the library connect to nothing' {
        foreach ($src in @($script:Wrapper, $script:Lib)) {
            foreach ($forbidden in 'Invoke-NRGGraphRequest', 'graph\.microsoft', 'Invoke-RestMethod', 'Invoke-WebRequest',
                                   'Connect-MgGraph', 'Connect-ExchangeOnline', 'Connect-IPPSSession', 'Connect-MicrosoftTeams',
                                   'Connect-NRGServices', 'Get-NRGRawData -Key', 'Invoke-NRGCollect') {
                $src | Should -Not -Match $forbidden -Because "the baseline plan must not $forbidden"
            }
        }
        $script:Wrapper | Should -Match "Import-Module \(Join-Path \`$scriptDir 'NRG-Assessment\.psm1'\)"
    }

    It 'the entry point computes the plan before connecting and the comparison after the compliance view' {
        $planAt = $script:Entry.IndexOf('$baselinePlan = Get-NRGBaselinePlan')
        $connAt = $script:Entry.IndexOf('Write-Host "[-] Connecting to M365 services..."')
        $cmpAt  = $script:Entry.IndexOf('Compare-NRGBaselinePlan -Plan $baselinePlan -Compliance $baselineCompliance')
        $planAt | Should -BeGreaterThan 0
        $planAt | Should -BeLessThan $connAt
        $cmpAt  | Should -BeGreaterThan $connAt
        $script:Entry | Should -Match 'BaselinePlan\s+=\s+\$baselinePlan'
        $script:Entry | Should -Match 'BaselinePlanComparison\s*=\s*\$baselinePlanComparison'
        $script:Entry | Should -Match '-BaselinePlanComparison \$baselinePlanComparison'
    }
}
