#Requires -Version 7.0
#
# NRG.DocAccuracy.Tests.ps1
#
# Fails the build when README.md / CLAUDE.md state a headline number that no
# longer matches the source of truth. Every count asserted here is COMPUTED
# from Config/controls.json, the module manifest, Lib/Connect-NRGServices.ps1,
# or the Testing/ folder — then checked against the prose. A control added
# without a doc update, or a doc number left stale, turns red in CI instead of
# silently misleading a reader. This closes the exact "266 exports but the
# README said 220", "24 scopes but CLAUDE said 23" class of drift that keeps
# recurring because the numbers are hand-typed.
#
# Design note: only STATICALLY DERIVABLE counts are pinned. The Pester runtime
# test count is deliberately NOT asserted — NRG.FrameworkCoverage.Tests.ps1 uses
# It -ForEach, so the executed test total expands at discovery time and cannot
# be computed from source. The suite (file) count IS deterministic, so that is
# what the docs advertise and what this suite enforces.

Describe 'Documentation stays in sync with the source of truth' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:Readme = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'README.md') -Raw
        $script:Claude = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'CLAUDE.md') -Raw

        $controls = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw | ConvertFrom-Json).controls)
        $script:ControlCount   = $controls.Count
        $script:WorkloadCount  = @($controls | Select-Object -ExpandProperty Workload -Unique).Count
        $script:ByWorkload     = $controls | Group-Object Workload |
            ForEach-Object { [pscustomobject]@{ WL = $_.Name; N = $_.Count } }
        $script:BySeverity     = @{}
        foreach ($g in ($controls | Group-Object Severity)) { $script:BySeverity[$g.Name] = $g.Count }

        $manifest = Import-PowerShellDataFile -LiteralPath (Join-Path $script:RepoRoot 'NRG-Assessment.psd1')
        $script:ExportCount = @($manifest.FunctionsToExport).Count

        # Graph scopes: pull the string constants out of the `$scopes = @(...)`
        # assignment in Connect-NRGServices via AST. Parsing the assignment RHS
        # (not the whole file) means the header-comment scope list and the
        # subset re-consent checks elsewhere in the file cannot inflate the count.
        $connPath = Join-Path $script:RepoRoot 'Lib/Connect-NRGServices.ps1'
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($connPath, [ref]$tokens, [ref]$errors)
        $assign = $ast.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $n.Left.VariablePath.UserPath -eq 'scopes'
        }, $true) | Select-Object -First 1
        $scopeStrings = @()
        if ($assign) {
            $scopeStrings = $assign.Right.FindAll({
                param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst]
            }, $true) | ForEach-Object { $_.Value } |
                Where-Object { $_ -match '\.(Read\.All|Read\.AzureAD|Read\.PermissionGrant)$' }
        }
        $script:ScopeCount = @($scopeStrings | Sort-Object -Unique).Count

        $script:SuiteCount = @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'Testing') -Filter '*.Tests.ps1' -File).Count
    }

    Context 'Control counts' {

        It 'README states the correct total control count' {
            $script:Readme | Should -Match ("\b{0}\b\s+(security\s+)?controls?" -f $script:ControlCount) `
                -Because "README must advertise $($script:ControlCount) controls (controls.json is the source of truth)"
        }

        It 'CLAUDE.md states the correct total control count' {
            $script:Claude | Should -Match ("\b{0}\b\s+(total\s+)?controls?" -f $script:ControlCount)
        }

        It 'no "<n> controls across" / "<n> total controls" claim is stale in either doc' {
            $blob = $script:Readme + "`n" + $script:Claude
            foreach ($m in [regex]::Matches($blob, '(\d+)\s+controls across')) {
                [int]$m.Groups[1].Value | Should -Be $script:ControlCount -Because 'a "<n> controls across" phrase must equal the live control count'
            }
            foreach ($m in [regex]::Matches($blob, '(\d+)\s+total controls')) {
                [int]$m.Groups[1].Value | Should -Be $script:ControlCount
            }
            foreach ($m in [regex]::Matches($blob, 'controls-(\d+)')) {   # shields.io badge
                [int]$m.Groups[1].Value | Should -Be $script:ControlCount
            }
        }

        It 'docs state the correct workload count' {
            $script:Readme | Should -Match ("\b{0}\s+workloads\b" -f $script:WorkloadCount)
            $script:Claude | Should -Match ("\b{0}\s+workloads\b" -f $script:WorkloadCount)
        }

        It 'CLAUDE.md per-workload "(WL, n)" counts are all correct' {
            foreach ($row in $script:ByWorkload) {
                $script:Claude | Should -Match ("\(\s*{0}\s*,\s*{1}\s*\)" -f [regex]::Escape($row.WL), $row.N) `
                    -Because "CLAUDE.md must list ($($row.WL), $($row.N))"
            }
        }

        It 'no "(WL, n)" pair in CLAUDE.md contradicts controls.json' {
            foreach ($m in [regex]::Matches($script:Claude, '\(\s*([A-Z]{3})\s*,\s*(\d+)\s*\)')) {
                $wl = $m.Groups[1].Value
                $expected = ($script:ByWorkload | Where-Object { $_.WL -eq $wl }).N
                if ($expected) {
                    [int]$m.Groups[2].Value | Should -Be $expected -Because "($wl, ...) must equal the live count for $wl"
                }
            }
        }

        It 'CLAUDE.md severity breakdown matches controls.json' {
            foreach ($sev in 'Critical', 'High', 'Medium', 'Low') {
                if ($script:BySeverity.ContainsKey($sev)) {
                    $script:Claude | Should -Match ("\b{0}\s+{1}\b" -f $script:BySeverity[$sev], $sev) `
                        -Because "CLAUDE.md must state $($script:BySeverity[$sev]) $sev controls"
                }
            }
        }
    }

    Context 'Manifest and scopes' {

        It 'README states the correct exported-function count' {
            $script:Readme | Should -Match ("\b{0}\b\s+export" -f $script:ExportCount)
        }

        It 'no export-count claim in README is stale' {
            foreach ($m in [regex]::Matches($script:Readme, '(\d+)\s+export(?:s|ed functions)')) {
                [int]$m.Groups[1].Value | Should -Be $script:ExportCount
            }
        }

        It 'AST scope extraction actually found the scopes array' {
            $script:ScopeCount | Should -BeGreaterThan 0 -Because 'if this is 0 the assignment shape changed and the scope guard below is meaningless'
        }

        It 'CLAUDE.md states the correct Graph scope count' {
            $script:Claude | Should -Match ("Graph Scopes \({0} total\)" -f $script:ScopeCount)
            $script:Claude | Should -Match ("Graph \({0} scopes\)" -f $script:ScopeCount)
        }
    }

    Context 'Test suite advertising' {

        It 'every "<n> Pester suites" claim equals the live suite (file) count' {
            $found = [regex]::Matches($script:Readme, '(\d+)\s+Pester suites')
            $found.Count | Should -BeGreaterThan 0 -Because 'the README should advertise the suite count somewhere'
            foreach ($m in $found) {
                [int]$m.Groups[1].Value | Should -Be $script:SuiteCount
            }
        }

        It 'every bare "<n> suites" claim equals the live suite (file) count' {
            foreach ($m in [regex]::Matches($script:Readme, '(\d+)\s+suites\b')) {
                [int]$m.Groups[1].Value | Should -Be $script:SuiteCount
            }
        }
    }
}
