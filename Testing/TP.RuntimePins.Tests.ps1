#Requires -Version 7.0
#
# TP.RuntimePins.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# The runtime dependencies are pinned, not floating: the Microsoft modules the tool signs in
# with are pinned in tools/pinned-modules.psd1 (exact version and SHA-256, the same freshness
# check the CI pins get), and the Python packages it runs are pinned by version and hash in
# .github/runtime-xlsx-requirements.txt (the XLSX publishers) and
# .github/runtime-pdf-requirements.txt (the questionnaire PDF importers), which Dependabot
# updates. Two files, not one, because pip verifies a whole requirements file in hash mode and
# refuses a package named on the command line for carrying no hash, so either set has to be
# installable on its own. These tests keep each pin exact, keep every install going through
# --require-hashes, and keep the copies that must agree (the installer, the SBOM, the docs)
# from drifting.

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    $script:Pins = Import-PowerShellDataFile -LiteralPath (Join-Path $script:RepoRoot 'tools/pinned-modules.psd1')
    $script:ReqFile = [ordered] @{
        xlsx = Join-Path $script:RepoRoot '.github/runtime-xlsx-requirements.txt'
        pdf  = Join-Path $script:RepoRoot '.github/runtime-pdf-requirements.txt'
    }
    $script:Req = @{}
    foreach ($key in @($script:ReqFile.Keys)) {
        $script:Req[$key] = Get-Content -LiteralPath $script:ReqFile[$key] -Raw
    }
    $script:Installer = Join-Path $script:RepoRoot 'Install-TPPrerequisites.ps1'
    $script:InstallerText = Get-Content -LiteralPath $script:Installer -Raw
}

Describe 'Runtime dependencies are pinned' {

    It 'pins the Microsoft runtime modules the tool signs in with, by exact version and SHA-256' {
        foreach ($name in 'ExchangeOnlineManagement', 'Microsoft.Graph.Authentication', 'MicrosoftTeams') {
            $script:Pins.ContainsKey($name) | Should -BeTrue -Because "$name must be in tools/pinned-modules.psd1"
            [string]$script:Pins[$name]['Version'] | Should -Match '\A\d+\.\d+\.\d+\z'
            [string]$script:Pins[$name]['Sha256'] | Should -Match '\A[0-9a-f]{64}\z'
        }
    }

    It 'pins every Python package with ==, and every requirement line carries a hash' {
        foreach ($key in @($script:ReqFile.Keys)) {
            $text = $script:Req[$key]
            $names = @([regex]::Matches($text, '(?m)^[A-Za-z0-9._-]+==').Count)
            $hashed = @([regex]::Matches($text, '(?m)^[A-Za-z0-9._-]+==[^\r\n]*\\\r?\n\s+--hash=sha256:[0-9a-f]{64}').Count)
            $names[0] | Should -BeGreaterThan 1 -Because "$key must pin its package and its dependencies"
            $hashed[0] | Should -Be $names[0] -Because "every requirement in $key must list its hashes"
        }
        $script:Req['xlsx'] | Should -Match '(?m)^openpyxl==\d+\.\d+\.\d+ \\'
        $script:Req['pdf'] | Should -Match '(?m)^pypdf==\d+\.\d+\.\d+ \\'
    }

    It 'gives each file its own dependency closure, so either installs without the other' {
        # --require-hashes resolves a whole file: a dependency pinned in the other file
        # would make that file uninstallable on its own, which is the only reason to split.
        $script:Req['xlsx'] | Should -Match '(?m)^et-xmlfile==' -Because 'openpyxl needs it'
        $script:Req['pdf'] | Should -Match '(?m)^typing_extensions==' -Because 'pypdf needs it below Python 3.11'
        $script:Req['xlsx'] | Should -Not -Match '(?m)^pypdf=='
        $script:Req['pdf'] | Should -Not -Match '(?m)^openpyxl=='
    }

    It 'installs every Python package with --require-hashes, never a bare name==version' {
        # The finding this closes: the hashes above were recorded but never checked,
        # because the installer ran `pip install openpyxl==<version>`. A compromised
        # index or mirror can serve different content for the same version.
        $installs = @([regex]::Matches($script:InstallerText, "'pip',\s*'install'[^\]]*\]"))
        $installs.Count | Should -BeGreaterThan 0 -Because 'the installer must still install the Python packages'
        foreach ($m in $installs) {
            $m.Value | Should -Match "'--require-hashes'" -Because "$($m.Value) must verify the recorded hash"
            $m.Value | Should -Match "'--only-binary=:all:'" -Because 'a wheel hash does not cover an sdist build'
            $m.Value | Should -Match "'-r'" -Because 'hash mode reads the requirements file'
            $m.Value | Should -Not -Match '==' -Because 'a bare name==version install verifies no hash'
        }
        # The advice printed when pypdf is absent is a command the operator will paste.
        $script:InstallerText | Should -Not -Match "pip install pypdf=="
        # A refused hash must not reach the operator as "install failed": pip still prints
        # the mismatch under --quiet, so every install reports why pip refused.
        $callSites = @([regex]::Matches($script:InstallerText, '-Script \$script:TPPipInstallScript')).Count
        $callSites | Should -BeGreaterThan 0
        ([regex]::Matches($script:InstallerText, 'Write-TPPipFailure -Output')).Count |
            Should -Be $callSites -Because 'every install must report why pip refused'
    }

    It 'the installer reads its Python pins from the requirements files, not from literals' {
        $script:InstallerText | Should -Match "Get-TPRuntimeRequirement -Name 'pypdf'"
        $script:InstallerText | Should -Match "Get-TPRuntimeRequirement -Name 'openpyxl'"
        $script:InstallerText | Should -Not -Match "\`$pypdfPin = '\d"
        $script:InstallerText | Should -Not -Match "\`$openpyxlPin = '\d"
    }

    It 'the installer resolves each package to the file that pins it, and refuses one it does not list' {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Installer, [ref] $tokens, [ref] $errors)
        $fn = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Get-TPRuntimeRequirement' }, $true) | Select-Object -First 1
        $fn | Should -Not -BeNullOrEmpty
        # The body comes off the AST instead of being rebuilt from its source text:
        # [scriptblock]::Create() over an extent is string evaluation, which the injection
        # rules flag and the baseline is not for. GetScriptBlock() keeps the param block, so
        # -Name binds as it does in the installer and $scriptDir resolves from this scope.
        $getReq = $fn.Body.GetScriptBlock()
        $scriptDir = $script:RepoRoot
        foreach ($case in @(@{ Name = 'openpyxl'; File = 'xlsx' }, @{ Name = 'et-xmlfile'; File = 'xlsx' },
                            @{ Name = 'pypdf'; File = 'pdf' }, @{ Name = 'typing_extensions'; File = 'pdf' })) {
            $r = & $getReq -Name $case.Name
            $r.Version | Should -Match '\A\d+\.\d+\.\d+\z'
            # The path is what the install runs -r against, so it must be the file that pins
            # it. Compared resolved, because the installer builds the path with Join-Path
            # segments and this file spells it with a forward slash: the same file, but not
            # the same string on Windows.
            Test-Path -LiteralPath $r.Path -PathType Leaf | Should -BeTrue
            (Resolve-Path -LiteralPath $r.Path).ProviderPath |
                Should -Be (Resolve-Path -LiteralPath $script:ReqFile[$case.File]).ProviderPath
        }
        { & $getReq -Name 'no-such-package' } | Should -Throw
    }

    It 'the SBOM and the docs state the pypdf version the requirements file pins' {
        $pypdf = [regex]::Match($script:Req['pdf'], '(?m)^pypdf==(?<v>[^\s\\]+)').Groups['v'].Value
        $pypdf | Should -Not -BeNullOrEmpty
        $sbom = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'tools/Generate-SBOM.ps1') -Raw
        $sbom | Should -Match "Name = 'pypdf'[^\r\n]*Version = '$([regex]::Escape($pypdf))'"
        $doc = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'docs/security/SBOM.md') -Raw
        $doc | Should -Match "pypdf \| $([regex]::Escape($pypdf)) "
    }
}
