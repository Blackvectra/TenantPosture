#Requires -Version 7.0
#
# NRG.ExportSync.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Pins the two export lists to each other and to the code: FunctionsToExport
# in NRG-Assessment.psd1 must equal $script:ExportedFunctions in
# NRG-Assessment.psm1, and every name on either list must be a function the
# module actually defines.
#
# Why this exists. The psm1 list is what Export-ModuleMember publishes; the
# psd1 list is what the manifest ADVERTISES (and what Import-Module -Name uses
# for discovery). They are maintained by hand in two files, and the CLAUDE.md
# "add a new control" recipe requires editing both. Drift is silent: a
# function in the psm1 but not the psd1 works interactively and vanishes from
# manifest-based discovery; a name in either list with no definition makes
# Export-ModuleMember warn on every import. NRG.EvaluatorWiring.Tests.ps1 has
# claimed since it was written that "Export List Sync checks psd1<->psm1" — the
# twin repo had that check and this one did not. Now it does.
#
# The comparison is a set comparison in BOTH directions plus a duplicate check,
# not a count comparison alone: two lists can have equal counts and differ.

Describe 'Export List Sync — NRG-Assessment.psd1 vs NRG-Assessment.psm1' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }

        # psm1: $script:ExportedFunctions = @( 'A', 'B', ... )
        $psm1Content = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Raw
        $script:Psm1Functions = @()
        if ($psm1Content -match '(?s)\$script:ExportedFunctions\s*=\s*@\((.*?)\)') {
            $script:Psm1Functions = @([regex]::Matches($Matches[1], "'([^']+)'") | ForEach-Object { $_.Groups[1].Value })
        }

        # psd1: FunctionsToExport = @( ... ), read as data, never executed.
        $psd1Data = Import-PowerShellDataFile -LiteralPath (Join-Path $script:RepoRoot 'NRG-Assessment.psd1')
        $script:Psd1Functions = @($psd1Data.FunctionsToExport)

        # Every function the module defines, from the AST rather than by
        # importing the module: importing needs Graph/EXO modules that CI does
        # not install, and a definition is a definition whether or not the
        # file loads. Same folders the psm1 $loadOrder dot-sources.
        $script:Defined = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $roots = @('Lib', 'Collectors', 'Evaluators', 'Publishers', 'Email-IR') | ForEach-Object { Join-Path $script:RepoRoot $_ }
        foreach ($file in Get-ChildItem -Path $roots -Filter '*.ps1' -Recurse -File -ErrorAction SilentlyContinue) {
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
            foreach ($fn in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                $null = $script:Defined.Add($fn.Name)
            }
        }
    }

    It 'finds $script:ExportedFunctions in the psm1' {
        $script:Psm1Functions.Count | Should -BeGreaterThan 0 -Because 'the regex must still match the psm1 shape; an empty list here means the parse failed, not that nothing is exported'
    }

    It 'finds FunctionsToExport in the psd1' {
        $script:Psd1Functions.Count | Should -BeGreaterThan 0
    }

    It 'has no duplicate names in the psm1 list' {
        $dupes = @($script:Psm1Functions | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
        $dupes | Should -BeNullOrEmpty -Because "duplicates: $($dupes -join ', ')"
    }

    It 'has no duplicate names in the psd1 list' {
        $dupes = @($script:Psd1Functions | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
        $dupes | Should -BeNullOrEmpty -Because "duplicates: $($dupes -join ', ')"
    }

    It 'exports every psm1 function from the psd1' {
        $missing = @($script:Psm1Functions | Where-Object { $_ -notin $script:Psd1Functions })
        $missing | Should -BeNullOrEmpty -Because "in psm1 but not psd1: $($missing -join ', ')"
    }

    It 'lists every psd1 function in the psm1' {
        $extra = @($script:Psd1Functions | Where-Object { $_ -notin $script:Psm1Functions })
        $extra | Should -BeNullOrEmpty -Because "in psd1 but not psm1: $($extra -join ', ')"
    }

    It 'has the same count in both lists' {
        $script:Psm1Functions.Count | Should -Be $script:Psd1Functions.Count
    }

    It 'defines every exported function somewhere under Lib, Collectors, Evaluators, Publishers or Email-IR' {
        # An exported name with no definition is not a silent no-op:
        # Export-ModuleMember warns on every import, and a caller that relies
        # on the manifest gets a command that does not exist.
        $undefined = @($script:Psm1Functions | Where-Object { -not $script:Defined.Contains($_) })
        $undefined | Should -BeNullOrEmpty -Because "exported but never defined: $($undefined -join ', ')"
    }

    It 'matches the count the README advertises' {
        # README.md says "N exported functions" in two places; the DocAccuracy
        # suite pins those to the manifest count, and this pins the manifest
        # count to the psm1, closing the loop.
        $readme = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'README.md') -Raw
        $claims = @([regex]::Matches($readme, '(\d+) exported functions') | ForEach-Object { [int]$_.Groups[1].Value })
        $claims.Count | Should -BeGreaterThan 0
        foreach ($c in $claims) { $c | Should -Be $script:Psm1Functions.Count }
    }

    It 'exports only Verb-Noun names, so importing the module prints no restricted-character warning' {
        # A second hyphen (Test-NRGEmailControl-AuthMethods) made every import
        # print "Some imported command names contain one or more of the
        # following restricted characters" at the top of each run.
        $bad = @($script:Psm1Functions | Where-Object { $_ -notmatch '^[A-Za-z]+-[A-Za-z0-9]+$' })
        $bad | Should -BeNullOrEmpty -Because "not Verb-Noun: $($bad -join ', ')"
    }
}
