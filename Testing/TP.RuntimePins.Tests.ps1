#Requires -Version 7.0
#
# TP.RuntimePins.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# The runtime dependencies are pinned, not floating: the Microsoft modules the tool signs in
# with are pinned in tools/pinned-modules.psd1 (exact version and SHA-256, the same freshness
# check the CI pins get), and the Python packages it runs (openpyxl, pypdf) are pinned by
# version and hash in .github/runtime-requirements.txt, which Dependabot updates. These tests
# keep each pin exact and keep the copies that must agree with it (the installer, the SBOM,
# the docs) from drifting.

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    $script:Pins = Import-PowerShellDataFile -LiteralPath (Join-Path $script:RepoRoot 'tools/pinned-modules.psd1')
    $script:Req = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.github/runtime-requirements.txt') -Raw
    $script:Installer = Join-Path $script:RepoRoot 'Install-TPPrerequisites.ps1'
}

Describe 'Runtime dependencies are pinned' {

    It 'pins the Microsoft runtime modules the tool signs in with, by exact version and SHA-256' {
        foreach ($name in 'ExchangeOnlineManagement', 'Microsoft.Graph.Authentication', 'MicrosoftTeams') {
            $script:Pins.ContainsKey($name) | Should -BeTrue -Because "$name must be in tools/pinned-modules.psd1"
            [string]$script:Pins[$name]['Version'] | Should -Match '\A\d+\.\d+\.\d+\z'
            [string]$script:Pins[$name]['Sha256'] | Should -Match '\A[0-9a-f]{64}\z'
        }
    }

    It 'pins openpyxl and pypdf with ==, and every requirement line carries a hash' {
        $script:Req | Should -Match '(?m)^openpyxl==\d+\.\d+\.\d+ \\'
        $script:Req | Should -Match '(?m)^pypdf==\d+\.\d+\.\d+ \\'
        $names = @([regex]::Matches($script:Req, '(?m)^[A-Za-z0-9._-]+==').Count)
        $hashed = @([regex]::Matches($script:Req, '(?m)^[A-Za-z0-9._-]+==[^\r\n]*\\\r?\n\s+--hash=sha256:[0-9a-f]{64}').Count)
        $names[0] | Should -BeGreaterThan 2
        $hashed | Should -Be $names[0] -Because 'every requirement must list its hashes'
    }

    It 'the installer reads its Python pins from the requirements file, not from literals' {
        $text = Get-Content -LiteralPath $script:Installer -Raw
        $text | Should -Match "Get-TPRuntimePin -Name 'pypdf'"
        $text | Should -Match "Get-TPRuntimePin -Name 'openpyxl'"
        $text | Should -Not -Match "\`$pypdfPin = '\d"
        $text | Should -Not -Match "\`$openpyxlPin = '\d"
    }

    It 'the installer resolves the pin from the file and refuses a package it does not list' {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Installer, [ref] $tokens, [ref] $errors)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-TPRuntimePin' }, $true) | Select-Object -First 1
        $fn | Should -Not -BeNullOrEmpty
        $scriptDir = $script:RepoRoot
        . ([scriptblock]::Create($fn.Extent.Text))
        Get-TPRuntimePin -Name 'pypdf' | Should -Match '\A\d+\.\d+\.\d+\z'
        Get-TPRuntimePin -Name 'openpyxl' | Should -Match '\A\d+\.\d+\.\d+\z'
        { Get-TPRuntimePin -Name 'no-such-package' } | Should -Throw
    }

    It 'the SBOM and the docs state the pypdf version the requirements file pins' {
        $pypdf = [regex]::Match($script:Req, '(?m)^pypdf==(?<v>[^\s\\]+)').Groups['v'].Value
        $pypdf | Should -Not -BeNullOrEmpty
        $sbom = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'tools/Generate-SBOM.ps1') -Raw
        $sbom | Should -Match "Name = 'pypdf'[^\r\n]*Version = '$([regex]::Escape($pypdf))'"
        $doc = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'docs/security/SBOM.md') -Raw
        $doc | Should -Match "pypdf \| $([regex]::Escape($pypdf)) "
    }
}
