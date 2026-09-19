#Requires -Version 7.0
#
# NRG.EvaluatorWiring.Tests.ps1
#
# Guards the controls.json -> Evaluators/ wiring. Exists because a bad edit
# once deleted ~30 evaluator FUNCTION DEFINITIONS from the twin repo's AAD
# evaluator file while controls.json (and the module export lists) kept
# referencing them — 30 AAD controls silently stopped evaluating on every
# assessment for a month, and no gate caught it: schema validation checks the
# JSON, NRG.ExportSync.Tests.ps1 checks psd1<->psm1, but nothing verified the
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
        $manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $script:RepoRoot 'NRG-Assessment.psd1')
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
}
