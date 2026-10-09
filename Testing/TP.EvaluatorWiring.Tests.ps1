#Requires -Version 7.0
#
# TP.EvaluatorWiring.Tests.ps1
#
# Guards the controls.json -> Evaluators/ wiring. Exists because a bad edit
# once deleted ~30 evaluator FUNCTION DEFINITIONS from the twin repo's AAD
# evaluator file while controls.json (and the module export lists) kept
# referencing them — 30 AAD controls silently stopped evaluating on every
# assessment for a month, and no gate caught it: schema validation checks the
# JSON, TP.ExportSync.Tests.ps1 checks psd1<->psm1, but nothing verified the
# functions actually EXIST. This suite closes that hole.

Describe 'controls.json -> evaluator wiring' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }

        $json = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw | ConvertFrom-Json
        $script:Controls = @($json.controls)

        # Function names DEFINED anywhere under Evaluators/ (AST-parsed, so a
        # syntax-corrupted file surfaces here as parse errors, not silence).
        $script:Defined = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $script:ParseFailures = @()
        foreach ($f in Get-ChildItem (Join-Path $script:RepoRoot 'Evaluators') -Filter '*.ps1' -File) {
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors)
            if ($errors -and $errors.Count -gt 0) {
                $script:ParseFailures += ('{0}: {1}' -f $f.Name, $errors[0].Message)
                continue
            }
            $funcs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)
            foreach ($fn in $funcs) { $null = $script:Defined.Add($fn.Name) }
        }

        # Export list from the manifest (Import-PowerShellDataFile — no module load).
        $manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $script:RepoRoot 'TenantPosture.psd1')
        $script:Exported = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]@($manifest.FunctionsToExport), [StringComparer]::OrdinalIgnoreCase)
    }

    It 'Every evaluator file parses cleanly' {
        $script:ParseFailures -join "`n" | Should -BeNullOrEmpty -Because 'a syntax-corrupted evaluator file silently drops every function defined after the corruption point'
    }

    It 'Every EvaluatorFunction referenced by controls.json is DEFINED in Evaluators/' {
        $missing = @($script:Controls | Where-Object { -not $script:Defined.Contains($_.EvaluatorFunction) } |
            ForEach-Object { '{0} -> {1}' -f $_.ControlId, $_.EvaluatorFunction } | Sort-Object -Unique)
        $missing -join "`n" | Should -BeNullOrEmpty -Because 'a referenced-but-undefined evaluator means that control silently never evaluates — the exact failure mode this suite exists to catch'
    }

    It 'Every EvaluatorFunction referenced by controls.json is EXPORTED in the manifest' {
        $unexported = @($script:Controls | Where-Object { -not $script:Exported.Contains($_.EvaluatorFunction) } |
            ForEach-Object { '{0} -> {1}' -f $_.ControlId, $_.EvaluatorFunction } | Sort-Object -Unique)
        $unexported -join "`n" | Should -BeNullOrEmpty -Because 'CLAUDE.md requires every evaluator in FunctionsToExport; an unexported evaluator breaks external invocation and drifts the manifest'
    }

    It 'Sanity: at least 150 distinct evaluator functions are wired' {
        @($script:Controls.EvaluatorFunction | Sort-Object -Unique).Count | Should -BeGreaterThan 150
    }

    It 'every CollectorDependency is set by a collector the entry point actually runs' {
        # EXO-3.1 read EXO-ConnectionFilter, whose collector existed but was
        # never called by Invoke-TPAssessment.ps1, so the control reported
        # "not collected" on every run and nothing flagged it.
        $setBy = @{}
        foreach ($f in Get-ChildItem (Join-Path $script:RepoRoot 'Collectors') -Filter '*.ps1' -File -Recurse) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                foreach ($m in [regex]::Matches($fn.Extent.Text, "Set-TPRawData\s+-Key\s+'([^']+)'")) {
                    if (-not $setBy.ContainsKey($m.Groups[1].Value)) { $setBy[$m.Groups[1].Value] = [System.Collections.Generic.List[string]]::new() }
                    $setBy[$m.Groups[1].Value].Add($fn.Name)
                }
            }
        }
        $entry = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
        $orphans = @(foreach ($key in @($script:Controls.CollectorDependency | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Sort-Object -Unique)) {
            $fns = if ($setBy.ContainsKey($key)) { @($setBy[$key]) } else { @() }
            if (-not @($fns | Where-Object { $entry -match "'$([regex]::Escape($_))'" })) { "$key (set by: $(if ($fns) { $fns -join ', ' } else { 'nothing' }))" }
        })
        $orphans | Should -BeNullOrEmpty -Because "no collector the entry point runs sets: $($orphans -join '; ')"
    }
}
