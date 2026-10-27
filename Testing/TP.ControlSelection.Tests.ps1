#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    TP.ControlSelection.Tests.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: Control selection (Invoke-TPAssessment.ps1 -ControlId /
             -ExcludeControlId). A partial run assesses only the chosen
             controls, collects only what their evaluators read, and signs in
             only to the services those collectors need. It must never read as
             a whole-tenant result: an unselected control is "not assessed: not
             selected", never a pass, never a collection failure, never a tool
             fault, and never a regression or a resolution against another run.
    Invariants pinned here:
      - the pattern rule, its copies in the entry point and the batch runner,
        and the resolver's refusals (no match, empty selection, bad pattern)
      - evaluator, raw-data key, collector and service derivation, including a
        key read beyond CollectorDependency and the never-under-collect fallback
      - the collector catalog matches every Set-TPRawData call in Collectors/
      - the scope bucket NotSelected and the bucket-sum invariant
      - the baseline reason code NotSelected, the plan and the coverage lines
      - the maturity label is qualified on a partial run
      - regressions and the delta report never compare an unselected control
      - the real entry point: refusals before sign-in, and a -ControlId AAD-1.2
        run against stubbed modules that never attempts Exchange
    Data keys consumed: none live. Graph scopes / cmdlets: none (stubs only).
#>

Describe 'Control selection (-ControlId / -ExcludeControlId)' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module TenantPosture
        $script:Controls = @((Get-Content -LiteralPath (Join-Path $script:Root 'Config/controls.json') -Raw | ConvertFrom-Json).controls)
        $script:Total = $script:Controls.Count
        $script:Resolve = { param($inc, $exc) & $script:Mod { param($i, $e) Resolve-TPControlSelection -Include $i -Exclude $e } $inc $exc }
        $script:Rule = & $script:Mod { Get-TPControlIdPatternRule }
        $script:Unscored = {
            param($s)
            $all = @($s.LicenceBlocked) + @($s.CollectionIncomplete) + @($s.NoProgrammaticCheck) + @($s.ThirdPartyAttested) +
                   @($s.StandardNotApproved) + @($s.NotApplicableToTenant) + @($s.NotEvaluatedThisMode) + @($s.NotSelected) +
                   @($s.SkippedByOperator) + @($s.NoResult)
            , @($all | Where-Object { $null -ne $_ } | ForEach-Object { $_.ControlId })
        }
    }
    AfterAll {
        & $script:Mod { Clear-TPState }
        Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue
    }

    Context 'The pattern rule' {
        It 'the entry point and the batch runner carry the resolver''s rule, case-sensitive, on both parameters' {
            foreach ($file in 'Invoke-TPAssessment.ps1', 'Invoke-TPBatchAssessment.ps1') {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root $file), [ref]$null, [ref]$null)
                foreach ($name in 'ControlId', 'ExcludeControlId') {
                    $p = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq $name })
                    $p.Count | Should -Be 1 -Because "$file declares -$name"
                    $attr = @($p[0].Attributes | Where-Object { $_.TypeName.Name -eq 'ValidatePattern' })
                    $attr.Count | Should -Be 1
                    $attr[0].PositionalArguments[0].Value | Should -BeExactly $script:Rule -Because "$file -$name is a copy of Get-TPControlIdPatternRule"
                    @($attr[0].NamedArguments | Where-Object { $_.ArgumentName -eq 'Options' -and $_.Argument.Extent.Text -eq "'None'" }).Count | Should -Be 1
                }
            }
        }
        It 'the parameter attribute refuses anything but letters, digits, dot, hyphen and the two wildcards' {
            # The same attribute text the entry point carries (the test above pins it to the rule).
            $sb = { param([ValidatePattern('\A[A-Za-z0-9.*?-]{1,40}\z', Options = 'None')] [string[]] $p) $p }
            $sb.Ast.ParamBlock.Parameters[0].Attributes[0].PositionalArguments[0].Value | Should -BeExactly $script:Rule
            foreach ($good in 'EXO-1.6', 'AAD-*', 'aad-1.?', 'SPO-5.*') { { & $sb -p $good } | Should -Not -Throw -Because $good }
            foreach ($bad in @('A[1]', 'AAD 1', 'AAD-1;x', 'AAD-1''', ('A' * 41), '', ([string][char]0x212A + '-1'))) {
                { & $sb -p $bad } | Should -Throw -Because "'$bad' is not a control pattern"
            }
        }
        It 'the resolver refuses a bad pattern itself (defense in depth)' {
            $r = & $script:Resolve @('A[1]') @()
            $r.Valid | Should -BeFalse
            ($r.Errors -join ' ') | Should -Match 'A\[1\]'
        }
    }

    Context 'Matching' {
        It 'an exact ID selects that control only' {
            $r = & $script:Resolve @('EXO-1.6') @()
            $r.Valid | Should -BeTrue
            $r.SelectedControlIds | Should -Be @('EXO-1.6')
            $r.Partial | Should -BeTrue
            $r.TotalControls | Should -Be $script:Total
        }
        It 'matching is case-insensitive' {
            (& $script:Resolve @('exo-1.6') @()).SelectedControlIds | Should -Be @('EXO-1.6')
        }
        It 'a wildcard selects a workload' {
            $r = & $script:Resolve @('AAD-*') @()
            $want = @($script:Controls | Where-Object { $_.ControlId -like 'AAD-*' })
            $r.SelectedCount | Should -Be $want.Count
            $r.Workloads.Keys | Should -Be @('AAD')
        }
        It 'a list combines exact IDs and wildcards' {
            $r = & $script:Resolve @('AAD-1.2', 'AAD-1.3', 'SPO-5.*') @()
            $want = @($script:Controls | Where-Object { $_.ControlId -in 'AAD-1.2', 'AAD-1.3' -or $_.ControlId -like 'SPO-5.*' } | ForEach-Object ControlId)
            @($r.SelectedControlIds) | Should -Be $want
        }
        It 'exclusions narrow the selection, alone or beside -ControlId' {
            $r = & $script:Resolve @('AAD-*') @('AAD-1.*')
            @($r.SelectedControlIds | Where-Object { $_ -like 'AAD-1.*' }) | Should -BeNullOrEmpty
            $r.SelectedCount | Should -Be @($script:Controls | Where-Object { $_.ControlId -like 'AAD-*' -and $_.ControlId -notlike 'AAD-1.*' }).Count
            $only = & $script:Resolve @() @('PVW-*')
            $only.SelectedCount | Should -Be ($script:Total - @($script:Controls | Where-Object { $_.ControlId -like 'PVW-*' }).Count)
        }
        It 'a pattern that matches nothing is refused and named, include or exclude' {
            $r = & $script:Resolve @('ZZZ-*', 'AAD-1.2') @()
            $r.Valid | Should -BeFalse
            ($r.Errors -join ' ') | Should -Match "ZZZ-\*"
            $x = & $script:Resolve @('AAD-1.2') @('QQQ-9')
            $x.Valid | Should -BeFalse
            ($x.Errors -join ' ') | Should -Match 'QQQ-9'
        }
        It 'a selection emptied by its exclusions is refused' {
            $r = & $script:Resolve @('AAD-1.2') @('AAD-*')
            $r.Valid | Should -BeFalse
            ($r.Errors -join ' ') | Should -Match 'nothing would be assessed'
        }
    }

    Context 'What runs: evaluators, raw-data keys, collectors and services' {
        It 'AAD-1.2 runs its own evaluator and signs in to Graph only' {
            $r = & $script:Resolve @('AAD-1.2') @()
            $ev = ($script:Controls | Where-Object ControlId -eq 'AAD-1.2').EvaluatorFunction
            $r.EvaluatorFunctions | Should -Be @($ev)
            $r.Services.Graph | Should -BeTrue
            foreach ($svc in 'Exchange', 'Purview', 'Teams', 'SharePointShell', 'PowerPlatform', 'DNS') { $r.Services[$svc] | Should -BeFalse -Because "$svc is not read by AAD-1.2" }
            $r.Collectors | Should -Contain 'Invoke-TPCollectAADCAPolicies'
            $r.Collectors | Should -Not -Contain 'Invoke-TPCollectEXOMailboxConfig'
            $r.Collectors | Should -Not -Contain 'Invoke-TPCollectTeams'
            $r.Fallback | Should -BeFalse
        }
        It 'AAD-Inventory is always collected (license gating reads it)' {
            (& $script:Resolve @('TMS-1.1') @()).RawDataKeys | Should -Contain 'AAD-Inventory'
        }
        It 'an EXO-* selection needs Exchange Online' {
            $r = & $script:Resolve @('EXO-*') @()
            $r.Services.Exchange | Should -BeTrue
            $r.Collectors | Should -Contain 'Invoke-TPCollectEXOInventory'
        }
        It 'TMS-5.6 reads Defender data beyond its CollectorDependency, so Exchange is signed in to' {
            $c = $script:Controls | Where-Object ControlId -eq 'TMS-5.6'
            ([string]$c.CollectorDependency) | Should -Not -Match 'Defender-Policies' -Because 'the point is a key the declaration does not name'
            $r = & $script:Resolve @('TMS-5.6') @()
            $r.RawDataKeys | Should -Contain 'Defender-Policies'
            $r.RawDataKeys | Should -Contain 'Teams'
            $r.Services.Exchange | Should -BeTrue
            $r.Services.Teams | Should -BeTrue
        }
        It 'a key read through a variable resolves to the key names that function writes as literals' {
            $k = & $script:Mod { (Get-TPFunctionRawDataKeys -Name 'Test-TPControlTeams').Keys }
            $k | Should -Contain 'AAD-IdentityGovernance' -Because 'TMS-1.6 reads Get-TPRawData -Key $src.K over a literal list'
        }
        It 'a collector''s own reads are prerequisites (DNS reads the accepted domains, Copilot reads Purview)' {
            (& $script:Resolve @('DNS-1.1') @()).RawDataKeys | Should -Contain 'EXO-MailboxConfig'
            $c = & $script:Resolve @('PPL-3.1') @()
            $c.RawDataKeys | Should -Contain 'Purview'
            $c.Services.Purview | Should -BeTrue
        }
        It 'a baseline row''s sign-in effectiveness evidence is collected with its control' {
            (& $script:Resolve @('AAD-1.2') @()).RawDataKeys | Should -Contain 'AAD-SignInEvidence'
        }
        It 'every selected evaluator''s reads are determined from the code (no fallback on the shipped evaluators)' {
            $r = & $script:Resolve @() @('AAD-1.1')
            @($r.Undetermined) | Should -BeNullOrEmpty -Because (@($r.Undetermined | ForEach-Object { "$($_.Function): $($_.Reason)" }) -join '; ')
        }
        It 'an evaluator whose read cannot be resolved makes the run collect everything (never under-collect)' {
            $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-sel-" + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path (Join-Path $dir 'Evaluators') -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $dir 'Evaluators/Fake.ps1') -Value 'function Test-TPControlFake { $k = Get-Something; $r = Get-TPRawData -Key $k }'
            try {
                $r = & $script:Mod {
                    param($d)
                    $idx = Get-TPRawDataReadIndex -Root $d
                    Resolve-TPControlSelection -Include 'FAKE-1' -Controls @([pscustomobject]@{ ControlId = 'FAKE-1'; Workload = 'AAD'; CollectorDependency = 'AAD-Users'; EvaluatorFunction = 'Test-TPControlFake' }, [pscustomobject]@{ ControlId = 'FAKE-2'; Workload = 'AAD'; CollectorDependency = ''; EvaluatorFunction = 'Test-TPControlOther' }) -ReadIndex $idx -BaselineDefinition @{ Controls = @{} }
                } $dir
                $r.Fallback | Should -BeTrue
                @($r.Undetermined).Count | Should -BeGreaterThan 0
                $all = & $script:Mod { @(Get-TPCollectorCatalog | ForEach-Object { $_.Function }) }
                @($r.Collectors) | Should -Be $all
                foreach ($svc in 'Exchange', 'Purview', 'Teams', 'PowerPlatform', 'DNS') { $r.Services[$svc] | Should -BeTrue }
            } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
        }
        It 'the collector catalog matches every Set-TPRawData call under Collectors/, both ways' {
            $fromCode = @{}
            foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:Root 'Collectors') -Recurse -Filter '*.ps1') {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
                foreach ($cmd in $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] -and $a.GetCommandName() -eq 'Set-TPRawData' }, $true)) {
                    $keyArg = $null
                    for ($i = 1; $i -lt $cmd.CommandElements.Count; $i++) {
                        $e = $cmd.CommandElements[$i]
                        if ($e -is [System.Management.Automation.Language.CommandParameterAst] -and $e.ParameterName -eq 'Key') { $keyArg = $cmd.CommandElements[$i + 1].Value }
                    }
                    $fn = $cmd.Parent; while ($fn -and $fn -isnot [System.Management.Automation.Language.FunctionDefinitionAst]) { $fn = $fn.Parent }
                    if (-not $fn -or -not $keyArg) { continue }
                    if ($keyArg -in 'EXO-DistributionLists', 'Device-Compliance') { continue }   # not assessment collectors (own scan / -DeviceResults)
                    $fromCode["$($fn.Name)|$keyArg"] = $true
                }
            }
            $fromCatalog = @{}
            foreach ($c in (& $script:Mod { Get-TPCollectorCatalog })) { foreach ($k in $c.Keys) { $fromCatalog["$($c.Function)|$k"] = $true } }
            @($fromCode.Keys | Where-Object { -not $fromCatalog.ContainsKey($_) }) | Should -BeNullOrEmpty -Because 'a collector key missing from the catalog would never be selected'
            @($fromCatalog.Keys | Where-Object { -not $fromCode.ContainsKey($_) }) | Should -BeNullOrEmpty -Because 'a catalog entry no code sets is stale'
        }
        It 'every catalog collector is one the entry point runs' {
            $entry = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-TPAssessment.ps1') -Raw
            foreach ($c in (& $script:Mod { Get-TPCollectorCatalog })) { $entry | Should -Match ([regex]::Escape("'$($c.Function)'")) }
        }
        It 'Connect-TPServices can leave Exchange out, and the entry point asks it to when nothing selected reads Exchange' {
            (Get-Command Connect-TPServices).Parameters.ContainsKey('SkipExchange') | Should -BeTrue
            $entry = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-TPAssessment.ps1') -Raw
            $entry | Should -Match "if \(-not \`$controlSelection\.Services\.Exchange\) \{ \`$connectParams\['SkipExchange'\] = \`$true \}"
        }
    }

    Context 'Assessment scope: NotSelected' {
        BeforeAll {
            $script:Sel = & $script:Mod { ConvertTo-TPControlSelectionRecord -Selection (Resolve-TPControlSelection -Include 'AAD-1.2', 'EXO-1.6') }
            $script:Two = @(
                [pscustomobject]@{ ControlId = 'AAD-1.2'; State = 'Satisfied'; Severity = 'High'; Detail = 'd' }
                [pscustomobject]@{ ControlId = 'EXO-1.6'; State = 'Gap'; Severity = 'High'; Detail = 'd' }
            )
            # Raw data from a run that collected only Graph: without the selection every
            # unselected Exchange control would read as a collection failure.
            $script:Raw = @{ 'AAD-CAPolicies' = @{ Success = $true; Data = @{} }; 'AAD-AuthPolicies' = @{ Success = $true; Data = @{} }; 'EXO-MailboxConfig' = @{ Success = $true; Data = @{} } }
        }
        It 'files every unselected control under NotSelected, never NoResult or CollectionIncomplete' {
            $s = & $script:Mod { param($f, $ids, $raw) Get-TPAssessmentScope -Findings $f -Coverage @{} -RawData $raw -SelectedControls $ids } $script:Two $script:Sel.SelectedControlIds $script:Raw
            $s.NotSelected.Count | Should -Be ($script:Total - 2)
            $s.NoResult | Should -BeNullOrEmpty
            $s.CollectionIncomplete | Should -BeNullOrEmpty
            $s.ScoredControls | Should -Be 2
            $s.PartialRun | Should -BeTrue
            ($s.NotSelected[0].Reason) | Should -Match 'not selected'
        }
        It 'the buckets still sum to the unscored count with no control in two of them' {
            $s = & $script:Mod { param($f, $ids, $raw) Get-TPAssessmentScope -Findings $f -Coverage @{} -RawData $raw -SelectedControls $ids } $script:Two $script:Sel.SelectedControlIds $script:Raw
            $ids = & $script:Unscored $s
            $ids.Count | Should -Be $s.UnscoredControls
            @($ids | Select-Object -Unique).Count | Should -Be $ids.Count
        }
        It 'says the run was partial and never reassures' {
            $s = & $script:Mod { param($f, $ids) Get-TPAssessmentScope -Findings $f -Coverage @{} -RawData @{} -SelectedControls $ids } $script:Two $script:Sel.SelectedControlIds
            $text = $s.Limitations -join ' '
            $text | Should -Match 'partial run'
            $text | Should -Not -Match 'is compliant|no issues found|fully secure|all clear'
        }
        It 'reads the run''s selection from module state when none is passed, and Clear-TPState forgets it' {
            $n = & $script:Mod { param($f, $rec) Set-TPControlSelection -Selection $rec; (Get-TPAssessmentScope -Findings $f -Coverage @{} -RawData @{}).NotSelected.Count } $script:Two $script:Sel
            $n | Should -Be ($script:Total - 2)
            $after = & $script:Mod { param($f) Clear-TPState; (Get-TPAssessmentScope -Findings $f -Coverage @{} -RawData @{}).NotSelected.Count } $script:Two
            $after | Should -Be 0
        }
        It 'a full run (no selection) has no NotSelected bucket entries' {
            $s = & $script:Mod { param($f) Get-TPAssessmentScope -Findings $f -Coverage @{} -RawData @{} -SelectedControls $null } $script:Two
            $s.NotSelected | Should -BeNullOrEmpty
            $s.NoResult.Count | Should -Be ($script:Total - 2)
        }
    }

    Context 'NRG baseline: reason code NotSelected' {
        BeforeAll {
            $script:Sel2 = & $script:Mod { ConvertTo-TPControlSelectionRecord -Selection (Resolve-TPControlSelection -Include 'AAD-1.2') }
            $script:Bl = & $script:Mod {
                param($ids)
                $f = @([pscustomobject]@{ ControlId = 'AAD-1.2'; State = 'Satisfied'; Severity = 'High'; Detail = 'MFA is required for all users.' })
                Get-TPBaselineCompliance -Findings $f -TargetTier Standard -RawData @{ 'AAD-CAPolicies' = @{ Success = $true; Data = @{} }; 'AAD-AuthPolicies' = @{ Success = $true; Data = @{} } } -Coverage @{} -SelectedControls $ids
            } $script:Sel2.SelectedControlIds
        }
        It 'is in the catalog right after SkippedByOperator' {
            $codes = @(& $script:Mod { (Get-TPBaselineReasonCodes).Keys })
            [array]::IndexOf($codes, 'NotSelected') | Should -Be ([array]::IndexOf($codes, 'SkippedByOperator') + 1)
        }
        It 'every unselected automated required control resolves NotVerified / NotSelected, never Satisfied and never CollectorUnavailable' {
            $other = @($script:Bl.Controls | Where-Object { $_.ControlId -ne 'AAD-1.2' -and $_.ReasonCode -ne 'ManualVerificationRequired' })
            $other.Count | Should -BeGreaterThan 0
            foreach ($r in $other) {
                $r.ObservedState | Should -Be 'NotVerified'
                $r.ReasonCode | Should -Be 'NotSelected' -Because "$($r.ControlId) was not selected"
                $r.EffectivenessState | Should -Be 'Unknown'
            }
            ($script:Bl.Controls | Where-Object ControlId -eq 'AAD-1.2').ReasonCode | Should -Be 'Satisfied'
        }
        It 'the evidence coverage line counts NotSelected as evidence not obtained' {
            $ev = $script:Bl.EvidenceCoverage
            $ev.Gaps.Contains('NotSelected') | Should -BeTrue
            ($ev.Known + $ev.Unknown + $ev.LicenseBlocked) | Should -Be $ev.Applicable
            $ev.Known | Should -Be 1
        }
        It 'the plan expects the unselected controls NotSelected, and the run matches the plan' {
            $res = & $script:Mod {
                param($ids, $bl)
                $p = Get-TPBaselinePlan -TargetTier Standard -SelectedControls $ids
                [pscustomobject]@{ Plan = $p; Cmp = (Compare-TPBaselinePlan -Plan $p -Compliance $bl) }
            } $script:Sel2.SelectedControlIds $script:Bl
            $res.Plan.Summary.NotSelected | Should -BeGreaterThan 0
            @($res.Plan.Controls | Where-Object { $_.Expected -eq 'NotSelected' } | ForEach-Object ReasonCode | Select-Object -Unique) | Should -Be @('NotSelected')
            @($res.Cmp.UnexpectedNotVerified | Where-Object { $_.ReasonCode -eq 'NotSelected' }) | Should -BeNullOrEmpty -Because 'a control the plan knew was not selected is not a surprise'
        }
    }

    Context 'Maturity is qualified on a partial run' {
        It 'a three-control run that passes is never an unqualified tier' {
            $m = & $script:Mod {
                $sel = ConvertTo-TPControlSelectionRecord -Selection (Resolve-TPControlSelection -Include 'AAD-1.1', 'AAD-1.2', 'AAD-1.3')
                $f = @('AAD-1.1', 'AAD-1.2', 'AAD-1.3' | ForEach-Object { [pscustomobject]@{ ControlId = $_; State = 'Satisfied'; Severity = 'High' } })
                Get-TPMaturityTier -Findings $f -Selection $sel
            }
            $m.ObservedLabel | Should -Be 'Optimizing'
            $m.EvidenceComplete | Should -BeFalse
            $m.PartialRun | Should -BeTrue
            $m.Label | Should -Match 'provisional: partial run, 3 of \d+ controls'
            $m.Qualification | Should -Match 'Partial run: 3 of'
        }
        It 'a full run keeps the existing label' {
            $m = & $script:Mod { Get-TPMaturityTier -Findings @([pscustomobject]@{ ControlId = 'AAD-1.1'; State = 'Satisfied'; Severity = 'High' }) }
            $m.Label | Should -Be 'Optimizing'
            $m.PartialRun | Should -BeFalse
        }
    }

    Context 'Comparisons never read an unselected control as a change' {
        It 'baseline regressions list a control the partial run did not select as not compared' {
            $res = & $script:Mod {
                $prior = @{ BaselineVersion = '2.0'; TargetTier = 'Standard'; Controls = @(
                    [pscustomobject]@{ ControlId = 'AAD-1.1'; RequiredTier = 'Minimum'; BaselineStatus = 'Satisfied'; ReasonCode = 'Satisfied' }
                    [pscustomobject]@{ ControlId = 'AAD-1.2'; RequiredTier = 'Minimum'; BaselineStatus = 'Satisfied'; ReasonCode = 'Satisfied' }
                    [pscustomobject]@{ ControlId = 'AAD-1.3'; RequiredTier = 'Minimum'; BaselineStatus = 'Failed'; ReasonCode = 'NotSelected' }) }
                $cur = @{ BaselineVersion = '2.0'; TargetTier = 'Standard'; Controls = @(
                    [pscustomobject]@{ ControlId = 'AAD-1.1'; RequiredTier = 'Minimum'; BaselineStatus = 'NotVerified'; ReasonCode = 'NotSelected'; NotVerifiedCause = 'Not selected' }
                    [pscustomobject]@{ ControlId = 'AAD-1.2'; RequiredTier = 'Minimum'; BaselineStatus = 'Failed'; ReasonCode = 'ControlFailed' }
                    [pscustomobject]@{ ControlId = 'AAD-1.3'; RequiredTier = 'Minimum'; BaselineStatus = 'Satisfied'; ReasonCode = 'Satisfied' }) }
                Get-TPBaselineRegressions -Current $cur -Prior $prior
            }
            @($res.Regressions | ForEach-Object ControlId) | Should -Be @('AAD-1.2')
            @($res.Improvements) | Should -BeNullOrEmpty -Because 'AAD-1.3 was not selected in the prior run, so passing now is not an improvement'
            @($res.NotCompared | ForEach-Object ControlId | Sort-Object) | Should -Be @('AAD-1.1', 'AAD-1.3')
            $res.Note | Should -Match 'not compared \(not selected\)'
        }
        It 'the delta report compares only what both runs assessed, and reads no drift from a collector not run' {
            $dir = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-seldelta-" + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            try {
                $tid = '11111111-2222-3333-4444-555555555555'
                $base = [ordered]@{
                    Metadata = @{ TenantId = $tid; TenantDomain = 'contoso.example'; AssessmentDate = 'October 01, 2026' }
                    Findings = @(
                        @{ ControlId = 'AAD-1.1'; State = 'Satisfied'; Severity = 'High'; Title = 'one' }
                        @{ ControlId = 'AAD-1.2'; State = 'Gap'; Severity = 'High'; Title = 'two' }
                        @{ ControlId = 'EXO-1.6'; State = 'Satisfied'; Severity = 'High'; Title = 'three' })
                    RawData = @{
                        'AAD-CAPolicies' = @{ Success = $true; Data = @{ CAPolicies = @(@{ Id = 'p1'; DisplayName = 'Require MFA'; State = 'enabled' }) } }
                    }
                }
                $basePath = Join-Path $dir 'base.json'
                $base | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $basePath -Encoding utf8
                $out = Join-Path $dir 'delta.md'
                & $script:Mod {
                    param($basePath, $out, $tid)
                    $sel = ConvertTo-TPControlSelectionRecord -Selection (Resolve-TPControlSelection -Include 'AAD-1.2')
                    $cur = @([pscustomobject]@{ ControlId = 'AAD-1.2'; State = 'Satisfied'; Severity = 'High'; Title = 'two' })
                    # Only Graph identity data this run, and no CA policies collected at all.
                    Publish-TPDeltaReport -CurrentFindings $cur -CurrentRawData @{ 'AAD-Inventory' = @{ Success = $true; Data = @{} } } `
                        -BaselineResultsPath $basePath -Metadata @{ TenantId = $tid; TenantDomain = 'contoso.example'; ControlSelection = $sel } -OutputPath $out
                } $basePath $out $tid
                $md = Get-Content -LiteralPath $out -Raw
                $md | Should -Match 'Partial run comparison'
                $md | Should -Match 'Not compared \(not selected\) \(2\)'
                $md | Should -Match 'Resolved \(1\)'
                $md | Should -Match 'New Gaps \(0\)'
                $md | Should -Match '\| Security Score \| 0/100 \| 100/100 \|' -Because 'both scores cover AAD-1.2 only'
                $md | Should -Not -Match '\| Removed\s+\|' -Because 'a CA collector that did not run this time is not every policy removed'
                $md | Should -Match 'Not compared: AAD-CAPolicies'
            } finally { Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction SilentlyContinue }
        }
        It 'the SSP never derives Implemented for a requirement whose mapped controls were not run' {
            $p = & $script:Mod {
                $f = @($script:TPControls | Where-Object { $_.ControlId -like 'AAD-*' } | ForEach-Object { [pscustomobject]@{ ControlId = $_.ControlId; State = 'Satisfied'; Severity = $_.Severity } })
                if (-not $f) { $f = @(Get-TPControlDefinitions | Where-Object { $_.ControlId -like 'AAD-*' } | ForEach-Object { [pscustomobject]@{ ControlId = $_.ControlId; State = 'Satisfied'; Severity = $_.Severity } }) }
                Get-TPSSPPosture -Findings $f
            }
            $withNotRun = @($p.Requirements | Where-Object { $_['NotRun'] -gt 0 })
            $withNotRun.Count | Should -BeGreaterThan 0
            foreach ($r in $withNotRun) { $r['Status'] | Should -Not -Be 'Implemented' -Because "$($r['Id']) has mapped controls this partial run did not assess" }
        }
    }

    Context 'The real entry point' {
        BeforeAll {
            $script:Tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-selrun-" + [guid]::NewGuid().ToString('N'))
            $script:Mods = Join-Path $script:Tmp 'mods'
            New-Item -ItemType Directory -Path $script:Mods -Force | Out-Null
            $script:ExoMark = Join-Path $script:Tmp 'exo-connect-called.txt'
            $exoVersion = [string](& $script:Mod { Get-TPExoModuleFloor }).Min
            $stub = {
                param([string] $Name, [string] $Version, [string] $Guid, [string] $Body)
                $d = Join-Path $script:Mods $Name $Version
                New-Item -ItemType Directory -Path $d -Force | Out-Null
                Set-Content -LiteralPath (Join-Path $d "$Name.psd1") -Encoding utf8 -Value "@{ RootModule = '$Name.psm1'; ModuleVersion = '$Version'; GUID = '$Guid'; FunctionsToExport = '*'; CmdletsToExport = @(); AliasesToExport = @() }"
                Set-Content -LiteralPath (Join-Path $d "$Name.psm1") -Encoding utf8 -Value $Body
            }
            & $stub 'Microsoft.Graph.Authentication' '2.40.0' 'b0b0b0b0-1111-4222-8333-444444444444' @'
function Connect-MgGraph { [CmdletBinding()] param($Scopes, $ContextScope, [switch] $NoWelcome, $TenantId, $Environment) }
function Disconnect-MgGraph { [CmdletBinding()] param() }
function Get-MgContext { [pscustomobject]@{ Account = 'admin@selection.example'; TenantId = '00000000-0000-0000-0000-00000000abcd'; Scopes = @(); Environment = 'Global' } }
function Invoke-MgGraphRequest { [CmdletBinding()] param($Uri, $Method, $OutputType, $Headers, $Body) @{ value = @() } }
'@
            # Any Exchange, Security & Compliance or Teams sign-in leaves a mark the test
            # reads; the stubs take the path from the environment the child inherits.
            & $stub 'ExchangeOnlineManagement' $exoVersion 'c0c0c0c0-1111-4222-8333-555555555555' (@'
function Connect-ExchangeOnline { [CmdletBinding()] param([switch] $ShowBanner, [switch] $DisableWAM, $Organization, $UserPrincipalName, $DelegatedOrganization, [switch] $SkipLoadingFormatData) Add-Content -LiteralPath $env:TP_SELECTION_SIGNIN_MARK -Value 'Connect-ExchangeOnline' }
function Connect-IPPSSession { Add-Content -LiteralPath $env:TP_SELECTION_SIGNIN_MARK -Value 'Connect-IPPSSession' }
function Disconnect-ExchangeOnline { [CmdletBinding()] param($Confirm) }
function Get-ConnectionInformation { @() }
'@)
            & $stub 'MicrosoftTeams' '5.9.0' 'd0d0d0d0-1111-4222-8333-666666666666' (@'
function Connect-MicrosoftTeams { Add-Content -LiteralPath $env:TP_SELECTION_SIGNIN_MARK -Value 'Connect-MicrosoftTeams' }
function Disconnect-MicrosoftTeams { }
'@)
            $script:Run = {
                param([string] $ArgText)
                $old = $env:PSModulePath
                $oldMark = $env:TP_SELECTION_SIGNIN_MARK
                try {
                    $env:TP_SELECTION_SIGNIN_MARK = $script:ExoMark
                    $env:PSModulePath = $script:Mods + [System.IO.Path]::PathSeparator + $env:PSModulePath
                    $cmd = "& '$(Join-Path $script:Root 'Invoke-TPAssessment.ps1')' $ArgText; exit `$LASTEXITCODE"
                    $text = (& pwsh -NoProfile -NonInteractive -Command $cmd *>&1 | Out-String)
                    $code = $LASTEXITCODE
                } finally { $env:PSModulePath = $old; $env:TP_SELECTION_SIGNIN_MARK = $oldMark }
                [pscustomobject]@{ Output = ($text -replace "\e\[[0-9;]*m", ''); ExitCode = $code }
            }
        }
        AfterAll {
            if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
        }

        It 'refuses -ControlId with -Quick before anything connects (exit 4)' {
            $out = Join-Path $script:Tmp 'quick'
            $r = & $script:Run "-NonInteractive -ControlId AAD-1.2 -Quick -OutputPath '$out'"
            $r.ExitCode | Should -Be 4 -Because $r.Output
            $r.Output | Should -Match '-Quick'
            $r.Output | Should -Not -Match 'Connecting to M365'
        }
        It 'refuses -ControlId with -FromResults (exit 4)' {
            $fake = Join-Path $script:Tmp 'prior-results.json'
            Set-Content -LiteralPath $fake -Value '{"Metadata":{},"Findings":[]}' -Encoding utf8
            $out = Join-Path $script:Tmp 'fromresults'
            $r = & $script:Run "-NonInteractive -ControlId AAD-1.2 -FromResults '$fake' -OutputPath '$out'"
            $r.ExitCode | Should -Be 4 -Because $r.Output
            $r.Output | Should -Match '-FromResults'
            @(Get-ChildItem -LiteralPath $out -Filter '*-results.json' -ErrorAction SilentlyContinue).Count | Should -Be 0
        }
        It 'refuses a pattern that matches no control, naming it (exit 4)' {
            $out = Join-Path $script:Tmp 'nomatch'
            $r = & $script:Run "-NonInteractive -ControlId 'ZZZ-*' -OutputPath '$out'"
            $r.ExitCode | Should -Be 4 -Because $r.Output
            $r.Output | Should -Match "ZZZ-\*"
            $r.Output | Should -Not -Match 'Connecting to M365'
        }

        It 'the sign-in mark works: -ControlId EXO-1.6 does sign in to Exchange (so the AAD-1.2 assertion is not vacuous)' {
            if (Test-Path -LiteralPath $script:ExoMark) { Remove-Item -LiteralPath $script:ExoMark -Force }
            $out = Join-Path $script:Tmp 'exo'
            $r = & $script:Run "-NonInteractive -ControlId EXO-1.6 -JsonOnly -OutputPath '$out'"
            $r.ExitCode | Should -BeIn @(0, 3) -Because $r.Output
            Test-Path -LiteralPath $script:ExoMark | Should -BeTrue -Because $r.Output
            (Get-Content -LiteralPath $script:ExoMark -Raw) | Should -Match 'Connect-ExchangeOnline'
            (Get-Content -LiteralPath $script:ExoMark -Raw) | Should -Not -Match 'Connect-MicrosoftTeams' -Because 'EXO-1.6 reads nothing from Teams'
        }

        Context '-ControlId AAD-1.2 against the stubs' {
            BeforeAll {
                if (Test-Path -LiteralPath $script:ExoMark) { Remove-Item -LiteralPath $script:ExoMark -Force }
                $script:SelOut = Join-Path $script:Tmp 'selected'
                $script:Sel = & $script:Run "-NonInteractive -ControlId AAD-1.2 -AllFiles -OutputPath '$script:SelOut'"
                $script:SelFile = Get-ChildItem -LiteralPath $script:SelOut -Filter '*-results.json' -ErrorAction SilentlyContinue | Select-Object -First 1
                $script:SelJson = if ($script:SelFile) { Get-Content -LiteralPath $script:SelFile.FullName -Raw | ConvertFrom-Json -AsHashtable -Depth 40 } else { $null }
                $script:Expected = & $script:Mod { Resolve-TPControlSelection -Include 'AAD-1.2' }
            }
            It 'finishes with a reported result (0 or 3)' {
                $script:Sel.ExitCode | Should -BeIn @(0, 3) -Because $script:Sel.Output
                $script:SelJson | Should -Not -BeNullOrEmpty
            }
            It 'never attempts an Exchange, Purview or Teams sign-in' {
                Test-Path -LiteralPath $script:ExoMark | Should -BeFalse -Because "a sign-in was attempted: $(if (Test-Path -LiteralPath $script:ExoMark) { Get-Content -LiteralPath $script:ExoMark -Raw })"
                $script:Sel.Output | Should -Match 'Exchange Online not needed by the selected controls'
            }
            It 'runs only the collectors the selection needs' {
                foreach ($label in 'Mailboxes: forwarding, audit, SMTP AUTH', 'Defender for Office 365 policies', 'Meetings, external access, messaging', 'Tenant sharing settings', 'Environments, tenant isolation, DLP', 'SPF, DKIM, DMARC') {
                    $script:Sel.Output | Should -Not -Match ([regex]::Escape($label)) -Because "$label is not read by AAD-1.2"
                }
                $script:Sel.Output | Should -Match 'Conditional Access policies'
                $collected = @($script:SelJson.RawData.Keys)
                foreach ($k in $collected) { $k | Should -BeIn (@($script:Expected.RawDataKeys) + @('Graph-Consent', 'Config-MonitoringAddresses')) -Because "$k was collected outside the selection" }
            }
            It 'scores the selected control only and records the selection' {
                @($script:SelJson.Findings | ForEach-Object { $_.ControlId } | Sort-Object -Unique) | Should -Be @('AAD-1.2')
                $cs = $script:SelJson.Metadata.ControlSelection
                $cs.Include | Should -Be @('AAD-1.2')
                $cs.SelectedCount | Should -Be 1
                $cs.TotalControls | Should -Be $script:Total
                @($cs.SelectedControlIds) | Should -Be @('AAD-1.2')
            }
            It 'the maturity label is qualified' {
                $script:SelJson.Metadata.Maturity.Label | Should -Match 'partial run, 1 of'
                $script:SelJson.Metadata.Maturity.EvidenceComplete | Should -BeFalse
            }
            It 'the baseline view files the other required controls NotSelected' {
                $codes = @($script:SelJson.BaselineCompliance.Controls | Where-Object { $_.ControlId -ne 'AAD-1.2' } | ForEach-Object { $_.ReasonCode } | Sort-Object -Unique)
                $codes | Should -Not -Contain 'CollectorUnavailable'
                $codes | Should -Contain 'NotSelected'
            }
            It 'the console, the HTML report and the Markdown summary say the run was partial' {
                $script:Sel.Output | Should -Match "Partial run: 1 of $($script:Total) controls selected"
                $html = Get-Content -LiteralPath (Get-ChildItem -LiteralPath $script:SelOut -Filter '*-assessment.html').FullName -Raw
                $html | Should -Match "id='partial-run'"
                $html | Should -Match "Partial run: 1 of $($script:Total) controls selected"
                $html | Should -Match 'not selected for this run'
                $md = Get-Content -LiteralPath (Get-ChildItem -LiteralPath $script:SelOut -Filter '*-assessment.md').FullName -Raw
                $md | Should -Match "Partial run: 1 of $($script:Total) controls selected"
                $md | Should -Match 'Not assessed — not selected for this run'
            }
            It 'no publisher failed' {
                $script:Sel.Output | Should -Not -Match 'publish failed' -Because $script:Sel.Output
            }
            It 'a republish of the partial results stays partial' {
                $out2 = Join-Path $script:Tmp 'republish'
                $r = & $script:Run "-FromResults '$($script:SelFile.FullName)' -NonInteractive -OutputPath '$out2'"
                $r.ExitCode | Should -BeIn @(0, 3) -Because $r.Output
                $html = Get-Content -LiteralPath (Get-ChildItem -LiteralPath $out2 -Filter '*-assessment.html').FullName -Raw
                $html | Should -Match "Partial run: 1 of $($script:Total) controls selected"
                $html | Should -Not -Match 'produced no result at all \(' -Because 'an unselected control is not a tool fault'
            }
        }
    }

    Context 'The batch runner' {
        It 'forwards -ControlId and -ExcludeControlId to every client''s run' {
            $batch = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-TPBatchAssessment.ps1') -Raw
            $batch | Should -Match "\`$params\['ControlId'\]\s*=\s*@\(\`$ControlId\)"
            $batch | Should -Match "\`$params\['ExcludeControlId'\]\s*=\s*@\(\`$ExcludeControlId\)"
            $batch | Should -Match 'Resolve-TPControlSelection'
        }
    }
}
