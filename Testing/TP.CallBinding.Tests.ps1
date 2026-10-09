#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    TP.CallBinding.Tests.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: Every call from repo code to a function this module defines must
             name only parameters that function has. `Get-TPRawData -AllKeys`
             shipped in both incident-response entry points with no such
             parameter: each stopped after all collection was done, before any
             report, and the suite stayed green because no test launches those
             scripts. Binding is checked statically over the parsed AST, so it
             needs no tenant and no sign-in.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Calls to module functions bind to real parameters' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:Common = @('Verbose', 'Debug', 'ErrorAction', 'WarningAction', 'InformationAction', 'ErrorVariable', 'WarningVariable',
                           'InformationVariable', 'OutVariable', 'OutBuffer', 'PipelineVariable', 'ProgressAction', 'WhatIf', 'Confirm')
        # Function name -> set of parameter names, from every function definition
        # in the repo's own module-loaded code (Lib, Collectors, Evaluators,
        # Publishers, Email-IR) plus the entry-point scripts' own param blocks.
        $script:Funcs = @{}
        $script:Files = @(Get-ChildItem -LiteralPath $script:Root -Recurse -Filter '*.ps1' -File |
            Where-Object { $_.FullName -notmatch '[\\/](Testing|Device|Onboard|tools|\.git|output|realtime)[\\/]' })
        foreach ($f in $script:Files) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                $names = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                $pb = if ($fn.Body.ParamBlock) { $fn.Body.ParamBlock } else { $null }
                if ($pb) { foreach ($p in $pb.Parameters) { $null = $names.Add($p.Name.VariablePath.UserPath) ; foreach ($a in $p.Attributes) { if ($a.TypeName.Name -eq 'Alias') { foreach ($arg in $a.PositionalArguments) { $null = $names.Add([string]$arg.Value) } } } } }
                elseif ($fn.Parameters) { foreach ($p in $fn.Parameters) { $null = $names.Add($p.Name.VariablePath.UserPath) } }
                # A function defined twice (a helper redefined in a test or a fallback) keeps the union.
                if ($script:Funcs.ContainsKey($fn.Name)) { foreach ($n in $script:Funcs[$fn.Name]) { $null = $names.Add($n) } }
                $script:Funcs[$fn.Name] = $names
            }
        }
    }

    It 'indexes a realistic number of module functions (the check is not vacuous)' {
        $script:Funcs.Count | Should -BeGreaterThan 300
        $script:Funcs.ContainsKey('Get-TPRawData') | Should -BeTrue
        @($script:Funcs['Get-TPRawData']) | Should -Contain 'Key'
        @($script:Funcs['Get-TPRawData']) | Should -Not -Contain 'AllKeys'
    }

    It 'no call in the repo names a parameter its target function does not have' {
        $bad = [System.Collections.Generic.List[string]]::new()
        foreach ($f in $script:Files) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            foreach ($cmd in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $name = $cmd.GetCommandName()
                if (-not $name -or -not $script:Funcs.ContainsKey($name)) { continue }
                $has = $script:Funcs[$name]
                foreach ($el in $cmd.CommandElements) {
                    if ($el -isnot [System.Management.Automation.Language.CommandParameterAst]) { continue }
                    $pn = $el.ParameterName
                    if ($script:Common -contains $pn) { continue }
                    if ($has.Contains($pn)) { continue }
                    # A unique prefix of a real parameter binds too (PowerShell allows abbreviation).
                    if (@($has | Where-Object { $_ -like "$pn*" }).Count -eq 1) { continue }
                    $bad.Add("$($f.FullName.Substring($script:Root.Length + 1)):$($el.Extent.StartLineNumber) $name -$pn")
                }
            }
        }
        $bad | Should -BeNullOrEmpty -Because ("these calls would throw a parameter-binding error at run time:`n" + ($bad -join "`n"))
    }

    It 'both incident-response entry points read the raw-data map with no argument' {
        foreach ($s in 'Invoke-TPEmailAssessment.ps1', 'Invoke-TPSignInTriage.ps1') {
            $src = Get-Content -LiteralPath (Join-Path $script:Root $s) -Raw
            $src | Should -Not -Match 'Get-TPRawData\s+-AllKeys'
            $src | Should -Match '\$rawData\s+=\s+Get-TPRawData\s*\r?\n'
        }
    }
}
