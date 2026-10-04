#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.Review106Site.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Regression tests for the review of the report site and the web GUI sign-in:
             a run with no findings still writes the site and its action plan; skipped
             workloads and Error findings are labeled as what they are.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

BeforeAll {
    $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    $script:Meta = @{ TenantId = '00000000-0000-0000-0000-000000000000'; TenantDomain = 'contoso.example'; AssessmentTime = '2026-09-30T10:49:00-05:00'; ToolVersion = '4.14.3' }
    $script:NewOut = { Join-Path ([IO.Path]::GetTempPath()) ("nrg-r106-" + [Guid]::NewGuid().ToString('N').Substring(0, 8)) }
}

Describe 'S1: a run with no findings still writes the site and an empty action plan' {
    BeforeAll {
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        Clear-NRGState
        $script:Out = & $script:NewOut
    }
    AfterAll { Remove-Item -LiteralPath $script:Out -Recurse -Force -ErrorAction SilentlyContinue; Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    It 'does not throw and writes ActionPlan.csv with only the header' {
        { $script:R = Publish-NRGReportSite -Metadata $script:Meta -Findings @() -OutputPath $script:Out } | Should -Not -Throw
        $csv = Join-Path $script:Out 'ActionPlan.csv'
        Test-Path -LiteralPath $csv | Should -BeTrue
        $lines = @(Get-Content -LiteralPath $csv)
        $lines.Count | Should -Be 1
        $lines[0] | Should -Match '^"Control ID",'
        Test-Path -LiteralPath (Join-Path $script:Out 'index.html') | Should -BeTrue
        $script:R.ActionPlanRows | Should -Be 0
    }
}

Describe 'S2: New-NRGReportSite.ps1 builds the site from a results file with "Findings": []' {
    BeforeAll {
        $script:Out2 = & $script:NewOut
        $null = New-Item -ItemType Directory -Force -Path $script:Out2
        $script:Res2 = Join-Path $script:Out2 'empty-results.json'
        Set-Content -LiteralPath $script:Res2 -Encoding utf8 -Value (@{ Metadata = $script:Meta; Findings = @() } | ConvertTo-Json -Depth 5)
    }
    AfterAll { Remove-Item -LiteralPath $script:Out2 -Recurse -Force -ErrorAction SilentlyContinue; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    It 'the results file really carries an empty Findings array' {
        (Get-Content -LiteralPath $script:Res2 -Raw) | Should -Match '"Findings":\s*\[\s*\]'
    }
    It 'does not throw and writes index.html and a header-only ActionPlan.csv' {
        $site = Join-Path $script:Out2 'site'
        { $null = & (Join-Path $script:Root 'New-NRGReportSite.ps1') -ResultsPath $script:Res2 -OutputPath $site 6>$null } | Should -Not -Throw
        Test-Path -LiteralPath (Join-Path $site 'index.html') | Should -BeTrue
        @(Get-Content -LiteralPath (Join-Path $site 'ActionPlan.csv')).Count | Should -Be 1
    }
}

Describe 'S3: the site takes each control''s not-scored category from Get-NRGAssessmentScope' {
    BeforeAll {
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Ctl = @((Get-Content -LiteralPath (Join-Path $script:Root 'Config/controls.json') -Raw | ConvertFrom-Json).controls)
        $script:Tms = @($script:Ctl | Where-Object { $_.CollectorDependency -eq 'Teams' } | ForEach-Object { $_.ControlId } | Sort-Object)
        # The limitation sentence the site prints for each scope bucket.
        $script:Expect = [ordered]@{
            CollectionIncomplete  = 'Collection: the evidence was not read'
            NoProgrammaticCheck   = 'Manual check: no automated test'
            ThirdPartyAttested    = 'Operator declaration: not verified by this assessment'
            LicenceBlocked        = 'Licensing: not scored'
            StandardNotApproved   = 'An NRG standard is not approved or configured'
            NotApplicableToTenant = 'Reported not applicable'
            SkippedByOperator     = 'Skipped by the operator: this workload was not assessed this run'
        }
        # Run every evaluator on the prepared state, publish the site, and read back each
        # control's verdict pill and limitation line, plus the scope buckets for the same state.
        $script:Run = {
            param([scriptblock] $Prepare)
            Clear-NRGState
            & $Prepare
            foreach ($ev in @($script:Ctl | ForEach-Object { $_.EvaluatorFunction } | Sort-Object -Unique)) { try { Invoke-NRGEvaluatorSafe -EvaluatorFunction $ev } catch { $null = $_ } }
            $findings = @(Get-NRGFindings)
            $cov = Get-NRGCoverage
            $scope = Get-NRGAssessmentScope -Findings $findings -Coverage $cov
            $out = & $script:NewOut
            $null = Publish-NRGReportSite -Metadata $script:Meta -Findings $findings -OutputPath $out -Coverage $cov
            $rows = @{}
            foreach ($page in Get-ChildItem -LiteralPath $out -Filter '*.html' | Where-Object BaseName -ne 'index') {
                $html = Get-Content -LiteralPath $page.FullName -Raw
                foreach ($m in [regex]::Matches($html, "<tr><td><b>([^<]+)</b>.*?<span class='pill \w+'>([^<]+)</span>.*?</tr>")) {
                    $lim = [regex]::Match($m.Value, '<dt>Limitation</dt><dd>([^<]*)</dd>')
                    $rows[$m.Groups[1].Value] = [pscustomobject]@{ Label = $m.Groups[2].Value; Limitation = $(if ($lim.Success) { [System.Net.WebUtility]::HtmlDecode($lim.Groups[1].Value) } else { '' }) }
                }
            }
            $plan = @(Import-Csv -LiteralPath (Join-Path $out 'ActionPlan.csv'))
            Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue
            [pscustomobject]@{ Scope = $scope; Rows = $rows; Plan = $plan }
        }
        $script:Disagree = {
            param($r)
            foreach ($b in $script:Expect.Keys) {
                foreach ($c in @($r.Scope[$b])) {
                    $row = $r.Rows[$c.ControlId]
                    if ($null -eq $row) { "$($c.ControlId): no row"; continue }
                    if ($row.Limitation -ne $script:Expect[$b]) { "$($c.ControlId): scope $b, site '$($row.Limitation)'" }
                }
            }
        }
        $script:Skipped = & $script:Run { Register-NRGCoverage -Family 'Teams' -Status 'Skipped' -Note 'Skipped for this run with -SkipTeams.' }
        $script:HardEvidence = & $script:Run { Set-NRGRawData -Key 'AAD-Inventory' -Data @{ CollectorId = 'AAD-Inventory'; Success = $true; Data = @{} } }
    }
    AfterAll { Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    It 'the repro: the scope files the Teams controls as skipped by the operator' {
        # Every control the scope files as skipped depends on the Teams collector (an advisory
        # control keeps its own bucket, which the scope decides first).
        $script:SkipIds = @($script:Skipped.Scope.SkippedByOperator | ForEach-Object { $_.ControlId } | Sort-Object)
        $script:SkipIds.Count | Should -BeGreaterThan 15
        foreach ($cid in $script:SkipIds) { $script:Tms | Should -Contain $cid }
        $script:SkipIds | Should -Contain 'TMS-2.1'
        $script:SkipIds | Should -Contain 'TMS-2.5'
    }
    It 'a skipped workload says skipped by the operator on the site, including TMS-2.1 and TMS-2.5' {
        foreach ($cid in $script:SkipIds) {
            $script:Skipped.Rows[$cid].Limitation | Should -Be $script:Expect.SkippedByOperator -Because "$cid was skipped by the operator"
            $script:Skipped.Rows[$cid].Label | Should -Match 'skipped by the operator'
        }
    }
    It 'a skipped workload produces no action-plan row' {
        @($script:Skipped.Plan | Where-Object { $_.'Control ID' -in $script:SkipIds }) | Should -BeNullOrEmpty
    }
    It 'the site and the scope agree on every not-scored control (skip run)' {
        @(& $script:Disagree $script:Skipped) | Should -BeNullOrEmpty
    }
    It 'the site applies the scope''s hard-evidence step (raw data present, collector absent)' {
        # TMS-2.1 and TMS-2.5 say why they do not apply without reading data; with raw data
        # present and no Teams result the scope files them as a collection gap.
        @($script:HardEvidence.Scope.CollectionIncomplete | ForEach-Object { $_.ControlId }) | Should -Contain 'TMS-2.1'
        @(& $script:Disagree $script:HardEvidence) | Should -BeNullOrEmpty
    }
}

Describe 'S3: New-NRGReportSite.ps1 reads the run''s coverage from the results file' {
    BeforeAll {
        $script:Out3 = & $script:NewOut
        $null = New-Item -ItemType Directory -Force -Path $script:Out3
        $script:Res3 = Join-Path $script:Out3 'skip-results.json'
        $doc = [ordered]@{
            Metadata = $script:Meta
            Findings = @([ordered]@{ ControlId = 'TMS-1.1'; State = 'NotApplicable'; Category = 'Teams'; Title = 'External access'; Severity = 'High'; Detail = 'Teams collector did not run.'; FrameworkIds = 'NIST:AC-20' })
            Coverage = @{ Teams = @{ Status = 'Skipped'; Note = 'Skipped for this run with -SkipTeams.' } }
        }
        Set-Content -LiteralPath $script:Res3 -Encoding utf8 -Value ($doc | ConvertTo-Json -Depth 6)
        $script:Site3 = Join-Path $script:Out3 'site'
        $null = & (Join-Path $script:Root 'New-NRGReportSite.ps1') -ResultsPath $script:Res3 -OutputPath $script:Site3 6>$null
    }
    AfterAll { Remove-Item -LiteralPath $script:Out3 -Recurse -Force -ErrorAction SilentlyContinue; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    It 'labels the skipped control skipped by the operator and gives it no action-plan row' {
        (Get-Content -LiteralPath (Join-Path $script:Site3 'TMS.html') -Raw) | Should -Match 'Not assessed \(skipped by the operator\)'
        @(Import-Csv -LiteralPath (Join-Path $script:Site3 'ActionPlan.csv')) | Should -BeNullOrEmpty
    }
}

Describe 'S4: an Error finding is not assessed (the check errored), never a Gap to remediate' {
    BeforeAll {
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        Clear-NRGState
        Add-NRGFinding -ControlId 'AAD-1.1' -State 'Gap' -Category 'Identity' -Title 'Legacy auth' -Severity 'High' -Detail 'Shortfall: not blocked.' -FrameworkIds 'NIST:AC-17'
        Add-NRGFinding -ControlId 'AAD-1.2' -State 'Error' -Category 'Identity' -Title 'MFA all users' -Severity 'High' -Detail 'Evaluator threw: boom.' -FrameworkIds 'NIST:IA-2'
        $script:Out4 = & $script:NewOut
        $null = Publish-NRGReportSite -Metadata $script:Meta -Findings @(Get-NRGFindings) -OutputPath $script:Out4
        $script:Aad4 = Get-Content -LiteralPath (Join-Path $script:Out4 'AAD.html') -Raw
        $script:Idx4 = Get-Content -LiteralPath (Join-Path $script:Out4 'index.html') -Raw
        $script:Plan4 = @(Import-Csv -LiteralPath (Join-Path $script:Out4 'ActionPlan.csv'))
    }
    AfterAll { Remove-Item -LiteralPath $script:Out4 -Recurse -Force -ErrorAction SilentlyContinue; Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    It 'the verdict reads Not assessed (the check errored)' {
        [regex]::Match($script:Aad4, "<b>AAD-1\.2</b>.*?<span class='pill \w+'>([^<]+)</span>").Groups[1].Value | Should -Be 'Not assessed (the check errored)'
    }
    It 'the action is to re-run or investigate the check, not to remediate' {
        $row = $script:Plan4 | Where-Object { $_.'Control ID' -eq 'AAD-1.2' }
        $row.'Action type' | Should -Be 'Re-run or investigate the check'
        $row.'NRG verdict' | Should -Be 'Not assessed (the check errored)'
        ($script:Plan4 | Where-Object { $_.'Control ID' -eq 'AAD-1.1' }).'Action type' | Should -Be 'Remediate'
    }
    It 'Error is counted apart from Gap on the landing page' {
        [regex]::Match($script:Idx4, "<div class='stat'><b>(\d+)</b>Gap</div>").Groups[1].Value | Should -Be '1'
        [regex]::Match($script:Idx4, "<div class='stat'><b>(\d+)</b>Not assessed \(the check errored\)</div>").Groups[1].Value | Should -Be '1'
        $hdr = @([regex]::Matches([regex]::Match($script:Idx4, '<h2>Workloads</h2><table><thead><tr>(.*?)</tr>').Groups[1].Value, '<th>([^<]+)</th>') | ForEach-Object { $_.Groups[1].Value })
        $cells = @([regex]::Matches([regex]::Match($script:Idx4, "<tr><td><a href='AAD\.html'>.*?</tr>").Value, '<td>([^<]*)</td>') | ForEach-Object { $_.Groups[1].Value })
        # The first cell (the workload link) holds markup and is not captured; data cells follow it.
        $cells[$hdr.IndexOf('Gap') - 1] | Should -Be '1'
        $cells[$hdr.IndexOf('Errored') - 1] | Should -Be '1'
    }
}

Describe 'G1: interactive Graph sign-in uses the supported default path and writes no Graph options' {
    # Set-MgGraphOption -DisableLoginByWAM only applies with a custom ClientId (the SDK's
    # AuthContext: WamEnabled => !(DisableWAMForMSGraph && IsCustomClientId)), and the cmdlet
    # writes a settings file to the operator's profile every time it runs. The tool signs in with
    # the default client, so the option changed nothing and persisted a file. The supported path is
    # the default client (WAM on Windows) with nothing written to the Graph options.
    BeforeAll {
        $script:ModuleFiles = @(foreach ($d in 'Lib', 'Collectors', 'Evaluators', 'Publishers', 'Email-IR/Lib', 'Email-IR/Collectors', 'Email-IR/Evaluators', 'Email-IR/Publishers') {
            Get-ChildItem -LiteralPath (Join-Path $script:Root $d) -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue
        }) + @(Get-Item -LiteralPath (Join-Path $script:Root 'NRG-Assessment.psm1'))
        $script:ConnPath = Join-Path $script:Root 'Lib' 'Connect-NRGServices.ps1'
        $script:ConnAst = [System.Management.Automation.Language.Parser]::ParseFile($script:ConnPath, [ref]$null, [ref]$null)
    }

    It 'no module-loaded file calls Set-MgGraphOption or reads/sets NRG_DISABLE_WAM' {
        $hits = foreach ($f in $script:ModuleFiles) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and "$($n.GetCommandName())" -eq 'Set-MgGraphOption' }, $true) |
                ForEach-Object { "$($f.Name):$($_.Extent.StartLineNumber) Set-MgGraphOption" }
            $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] -and $n.VariablePath.UserPath -eq 'env:NRG_DISABLE_WAM' }, $true) |
                ForEach-Object { "$($f.Name):$($_.Extent.StartLineNumber) NRG_DISABLE_WAM" }
        }
        @($hits) | Should -BeNullOrEmpty
    }
    It 'the interactive Connect-MgGraph call passes no -ClientId (default client)' {
        $calls = @($script:ConnAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and "$($n.GetCommandName())" -eq 'Connect-MgGraph' }, $true))
        # The interactive call is the splatted one; the other is the app-only certificate path.
        $interactive = @($calls | Where-Object { $_.Extent.Text -match '@mgConnectParams' })
        $interactive.Count | Should -Be 1
        @($interactive[0].CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'ClientId' }) | Should -BeNullOrEmpty
        $src = Get-Content -LiteralPath $script:ConnPath -Raw
        $src | Should -Not -Match "mgConnectParams\[\s*'ClientId'\s*\]|mgConnectParams\.ClientId"
        [regex]::Match($src, '\$mgConnectParams\s*=\s*@\{[^}]*\}').Value | Should -Not -Match 'ClientId'
        $src | Should -Not -Match 'Sign-in uses the system browser'
    }
}
