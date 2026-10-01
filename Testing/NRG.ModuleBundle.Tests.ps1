#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.ModuleBundle.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Pester coverage for the tool-local module bundle: Config/module-bundle.json,
             Lib/Get-NRGModuleBundle.ps1 (validate, enable, disable, bundle-aware lookup) and
             Lib/New-NRGModuleBundle.ps1 (the builder behind
             Install-NRGPrerequisites.ps1 -Local). NRG.ModuleBundleRun.Tests.ps1 proves the
             whole thing against the real entry points; this proves the pieces and pins the
             rules that keep the bundle honest:
      - one version of each module, and a bundle is used all or nothing (a half-built or stale
        one is reported and NOT activated, never mixed with the machine's copies);
      - the lock file is written last, so an interrupted build is never activated;
      - nothing in the bundle that is not in the spec (Save-Module drags PackageManagement and
        PowerShellGet in with ExchangeOnlineManagement, and they would shadow the machine's);
      - the Exchange version follows Get-NRGExoModuleFloor for the PowerShell in use;
      - activation touches this process's PSModulePath only and Disable puts it back;
      - the builder removes nothing without -Force, then only the bundle's own folders, and is
        called from nowhere but the installer;
      - every entry point that imports the tool activates the bundle BEFORE that import (the
        manifest's RequiredModules are loaded by it) and restores PSModulePath in a finally;
      - no #Requires -Modules line pre-empts activation, and no repo-wide scan, signer or
        integrity hash walks into .modules.
    Service boundary: stub module folders in a temp directory. No network, no tenant, no
    installs. Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Module bundle — pins, validation, activation, builder' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:Tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-bundle-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
        $script:Sep = [string][System.IO.Path]::PathSeparator

        . (Join-Path $script:Root 'Lib/Get-NRGObjectField.ps1') -ErrorAction SilentlyContinue
        . (Join-Path $script:Root 'Lib/Get-NRGModuleInstallScope.ps1')
        . (Join-Path $script:Root 'Lib/Get-NRGModuleHealth.ps1')
        . (Join-Path $script:Root 'Lib/Get-NRGModuleBundle.ps1')
        . (Join-Path $script:Root 'Lib/New-NRGModuleBundle.ps1')

        $script:Spec = @(Get-NRGModuleBundleSpec -ToolRoot $script:Root)
        $script:Floor76 = [ordered]@{ Min = '3.10.0'; Max = $null;   Supported = $true;  StoreBuild = $false; Reason = 'PowerShell 7.6 or later needs ExchangeOnlineManagement 3.10.0 or later.' }
        $script:Floor75 = [ordered]@{ Min = '3.7.2';  Max = '3.9.99'; Supported = $true;  StoreBuild = $false; Reason = 'PowerShell 7.4 and 7.5 run ExchangeOnlineManagement 3.7.2 to 3.9.x; 3.10.0 and later need 7.6.' }
        $script:Floor72 = [ordered]@{ Min = '3.7.2';  Max = '3.4.99'; Supported = $false; StoreBuild = $false; Reason = 'PowerShell 7.2 cannot run ExchangeOnlineManagement 3.7.2 or later; upgrade PowerShell.' }

        # A stand-in for the download: writes <Path>\<Name>\<Version>\<Name>.psd1 and records the
        # call. A range request resolves the way the gallery would (the newest in it).
        $script:Calls = [System.Collections.Generic.List[string]]::new()
        $script:FakeSave = {
            param($Name, $Request, $Path)
            $script:Calls.Add("$Name $Request")
            $v = if ($Request -match '^\[([^,]+),(.*)\]$|^\[([^,]+),\)$') { if ($Request -match ',\)$') { '3.10.1' } else { '3.9.2' } } else { $Request }
            $dir = Join-Path (Join-Path $Path $Name) $v
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
            Set-Content -LiteralPath (Join-Path $dir "$Name.psd1") -Encoding utf8 -Value "@{ ModuleVersion = '$v'; GUID = '$([guid]::NewGuid())' }"
        }
        $script:Build = {
            param([string] $Path, $Floor = $script:Floor76, $Spec = $script:Spec, [switch] $Force, [switch] $Spo, [scriptblock] $Save)
            $args2 = @{ ToolRoot = $script:Root; Path = $Path; SaveAction = $(if ($Save) { $Save } else { $script:FakeSave }); Spec = $Spec; ExoFloor = $Floor; Confirm = $false }
            if ($Force) { $args2['Force'] = $true }
            if ($Spo)   { $args2['IncludeSharePointShell'] = $true }
            New-NRGModuleBundle @args2 6>$null
        }
        $script:NewPath = { Join-Path $script:Tmp ([guid]::NewGuid().ToString('N')) }
        $script:NoScan = { param($r) @() }
        $script:Check = {
            param([string] $Path, $Floor = $script:Floor76, $Spec = $script:Spec)
            Test-NRGModuleBundle -ToolRoot $script:Root -Path $Path -Spec $Spec -ExoFloor $Floor -PlaceholderScanner $script:NoScan
        }
        $script:Codes = { param($r, [string] $Kind = 'Errors') @($r[$Kind] | ForEach-Object { ($_ -split ':', 2)[0] }) }

        $script:SavedPSModulePath = $env:PSModulePath
        $script:SavedBundleEnv = $env:NRG_MODULE_BUNDLE
    }

    AfterAll {
        $env:PSModulePath = $script:SavedPSModulePath
        $env:NRG_MODULE_BUNDLE = $script:SavedBundleEnv
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) {
            Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
    }

    AfterEach {
        $env:PSModulePath = $script:SavedPSModulePath
        if ($null -eq $script:SavedBundleEnv) { Remove-Item Env:NRG_MODULE_BUNDLE -ErrorAction SilentlyContinue } else { $env:NRG_MODULE_BUNDLE = $script:SavedBundleEnv }
        $script:Calls.Clear()
    }

    Context 'Config/module-bundle.json — the pins' {
        It 'every module has a name, an exact version, a family, a policy and a reason' {
            $script:Spec.Count | Should -BeGreaterThan 8
            foreach ($m in $script:Spec) {
                $m['Name'] | Should -Not -BeNullOrEmpty
                $m['Version'] | Should -Match '^\d+(\.\d+){2,3}$' -Because "$($m['Name']) needs a pinned version"
                $m['Family'] | Should -BeIn @('Graph', 'Exchange', 'Teams', 'SharePoint')
                $m['VersionPolicy'] | Should -BeIn @('Exact', 'ExchangeFloor')
                $m['Why'] | Should -Not -BeNullOrEmpty
            }
            @($script:Spec | ForEach-Object { $_['Name'] } | Select-Object -Unique).Count | Should -Be $script:Spec.Count
        }
        It 'only Exchange follows Get-NRGExoModuleFloor, and only the SharePoint shell is opt-in' {
            @($script:Spec | Where-Object { $_['VersionPolicy'] -eq 'ExchangeFloor' } | ForEach-Object { $_['Name'] }) | Should -Be @('ExchangeOnlineManagement')
            @($script:Spec | Where-Object { $_['Optional'] } | ForEach-Object { $_['Name'] }) | Should -Be @('Microsoft.Online.SharePoint.PowerShell')
        }
        It 'the Graph modules share one version (each submodule needs Authentication at that version or newer)' {
            @($script:Spec | Where-Object { $_['Family'] -eq 'Graph' } | ForEach-Object { $_['Version'] } | Select-Object -Unique).Count | Should -Be 1
        }
        It 'the pins satisfy the RequiredModules ranges in NRG-Assessment.psd1, or importing the tool would fail' {
            $psd1 = Import-PowerShellDataFile -LiteralPath (Join-Path $script:Root 'NRG-Assessment.psd1')
            foreach ($req in @($psd1.RequiredModules)) {
                $pin = $script:Spec | Where-Object { $_['Name'] -eq $req.ModuleName }
                $pin | Should -Not -BeNullOrEmpty -Because "$($req.ModuleName) is a RequiredModule of the tool"
                [version]$pin['Version'] | Should -BeGreaterOrEqual ([version]$req.ModuleVersion)
                [version]$pin['Version'] | Should -BeLessOrEqual ([version]$req.MaximumVersion)
            }
        }
        It 'MicrosoftTeams is at least the version Get-NRGModuleHealth requires' {
            [version](@($script:Spec | Where-Object { $_['Name'] -eq 'MicrosoftTeams' })[0]['Version']) | Should -BeGreaterOrEqual ([version]'5.0.0')
        }
        It 'carries every Graph submodule Connect-NRGServices pre-imports' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root 'Lib/Connect-NRGServices.ps1'), [ref]$null, [ref]$null)
            $assign = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$graphSubModules' }, $true)
            $assign | Should -Not -BeNullOrEmpty
            $names = @($assign.Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object { $_.Value })
            $names.Count | Should -BeGreaterThan 0
            foreach ($n in $names) { @($script:Spec | ForEach-Object { $_['Name'] }) | Should -Contain $n }
        }
        It 'carries the module of every Microsoft.Graph cmdlet the module-loaded code calls (a Get-Command check would otherwise autoload the machine copy)' {
            # The Authentication cmdlets are the only ones the read path may call unconditionally.
            $authOnly = @('Connect-MgGraph', 'Disconnect-MgGraph', 'Get-MgContext', 'Invoke-MgGraphRequest', 'Get-MgGraphAccessToken')
            $owner = @{ 'Get-MgGroup' = 'Microsoft.Graph.Groups'; 'Get-MgDirectoryRole' = 'Microsoft.Graph.Identity.DirectoryManagement'; 'Get-MgDirectoryRoleMember' = 'Microsoft.Graph.Identity.DirectoryManagement' }
            $found = [System.Collections.Generic.HashSet[string]]::new()
            foreach ($d in 'Lib', 'Collectors', 'Evaluators', 'Publishers', 'Email-IR/Lib', 'Email-IR/Collectors', 'Email-IR/Evaluators', 'Email-IR/Publishers') {
                foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:Root $d) -Filter '*.ps1' -Recurse -File) {
                    $a = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
                    foreach ($c in $a.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $n.Value -match '^(Get|New|Set|Update|Remove)-Mg[A-Z]' }, $true)) {
                        if ($c.Value -notin $authOnly) { [void]$found.Add($c.Value) }
                    }
                }
            }
            foreach ($cmd in $found) {
                $owner.ContainsKey($cmd) | Should -BeTrue -Because "$cmd is called on the module-loaded path: add its module to Config/module-bundle.json and to this map"
                @($script:Spec | ForEach-Object { $_['Name'] }) | Should -Contain $owner[$cmd]
            }
        }
    }

    Context 'Get-NRGModuleBundlePath' {
        It 'defaults to .modules inside the tool' {
            Remove-Item Env:NRG_MODULE_BUNDLE -ErrorAction SilentlyContinue
            Get-NRGModuleBundlePath -ToolRoot $script:Root | Should -Be ([System.IO.Path]::GetFullPath((Join-Path $script:Root '.modules')))
        }
        It 'honors NRG_MODULE_BUNDLE, so one bundle can live outside OneDrive or be shared' {
            $env:NRG_MODULE_BUNDLE = (Join-Path $script:Tmp 'elsewhere')
            Get-NRGModuleBundlePath -ToolRoot $script:Root | Should -Be (Join-Path $script:Tmp 'elsewhere')
        }
        It 'resolves a relative override against the PowerShell location, not the process directory' {
            $env:NRG_MODULE_BUNDLE = 'rel-bundle'
            Push-Location $script:Tmp
            try { $p = Get-NRGModuleBundlePath -ToolRoot $script:Root } finally { Pop-Location }
            $p | Should -Be (Join-Path (Resolve-Path -LiteralPath $script:Tmp).ProviderPath 'rel-bundle')
        }
    }

    Context 'Get-NRGModuleManifestVersion' {
        It 'reads a plain manifest' {
            $p = Join-Path $script:Tmp 'plain.psd1'
            Set-Content -LiteralPath $p -Value "@{ RootModule = 'x.psm1'; ModuleVersion = '2.40.0'; GUID = 'a' }"
            Get-NRGModuleManifestVersion -Path $p | Should -Be ([version]'2.40.0')
        }
        It 'reads the shape ExchangeOnlineManagement ships, which Import-PowerShellDataFile cannot' {
            $p = Join-Path $script:Tmp 'exo.psd1'
            Set-Content -LiteralPath $p -Value @'
@{
RootModule = 'ExchangeOnlineManagement.psm1'
ModuleVersion = '3.10.1'
FunctionsToExport = @()
CmdletsToExport = if ($PSEdition -eq 'Core') { @('Get-A') } else { @('Get-B') }
PrivateData = @{ PSData = @{ Tags = @('x') } }
}
'@
            { Import-PowerShellDataFile -LiteralPath $p } | Should -Throw -Because 'this is the reason the manifest is parsed rather than imported'
            Get-NRGModuleManifestVersion -Path $p | Should -Be ([version]'3.10.1')
        }
        It 'never executes the manifest' {
            $marker = Join-Path $script:Tmp 'executed.txt'
            $p = Join-Path $script:Tmp 'evil.psd1'
            Set-Content -LiteralPath $p -Value "@{ ModuleVersion = '1.0.0'; X = (Set-Content -LiteralPath '$marker' -Value 'ran') }"
            Get-NRGModuleManifestVersion -Path $p | Should -Be ([version]'1.0.0')
            Test-Path -LiteralPath $marker | Should -BeFalse
        }
        It 'returns nothing for a missing version, a broken file or a missing file' {
            $p = Join-Path $script:Tmp 'nover.psd1'
            Set-Content -LiteralPath $p -Value "@{ RootModule = 'x' }"
            Get-NRGModuleManifestVersion -Path $p | Should -BeNullOrEmpty
            $b = Join-Path $script:Tmp 'broken.psd1'
            Set-Content -LiteralPath $b -Value '@{ ModuleVersion = '
            Get-NRGModuleManifestVersion -Path $b | Should -BeNullOrEmpty
            Get-NRGModuleManifestVersion -Path (Join-Path $script:Tmp 'missing.psd1') | Should -BeNullOrEmpty
        }
    }

    Context 'Test-NRGModuleBundle' {
        BeforeAll {
            $script:Good = & $script:NewPath
            $null = & $script:Build $script:Good
        }
        It 'a folder that does not exist is simply not present, with no error' {
            $r = & $script:Check (& $script:NewPath)
            $r['Present'] | Should -BeFalse
            $r['Valid'] | Should -BeFalse
            $r['Errors'] | Should -BeNullOrEmpty
        }
        It 'a complete bundle is valid and lists one entry per module' {
            $r = & $script:Check $script:Good
            $r['Errors'] | Should -BeNullOrEmpty -Because ($r['Errors'] -join '; ')
            $r['Valid'] | Should -BeTrue
            @($r['Modules']).Count | Should -Be (@($script:Spec | Where-Object { -not $_['Optional'] }).Count)
        }
        It 'an empty folder, or one with no lock file, is not valid (an interrupted build)' {
            $p = & $script:NewPath
            New-Item -ItemType Directory -Path $p | Out-Null
            & $script:Codes (& $script:Check $p) | Should -Contain 'no-lock'
            $q = & $script:NewPath
            $null = & $script:Build $q
            Remove-Item -LiteralPath (Join-Path $q 'nrg-bundle.json')
            & $script:Codes (& $script:Check $q) | Should -Contain 'no-lock'
        }
        It 'an unreadable lock file is bad-lock, not an exception' {
            $p = & $script:NewPath
            $null = & $script:Build $p
            Set-Content -LiteralPath (Join-Path $p 'nrg-bundle.json') -Value '{ not json'
            & $script:Codes (& $script:Check $p) | Should -Contain 'bad-lock'
        }
        It 'a required module missing from the lock is reported by name' {
            $p = & $script:NewPath
            $null = & $script:Build $p
            $lockFile = Join-Path $p 'nrg-bundle.json'
            $lock = Get-Content -LiteralPath $lockFile -Raw | ConvertFrom-Json
            $lock.Modules = @($lock.Modules | Where-Object { $_.Name -ne 'MicrosoftTeams' })
            $lock | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $lockFile
            $r = & $script:Check $p
            @($r['Errors'] | Where-Object { $_ -like 'missing: MicrosoftTeams*' }).Count | Should -Be 1
        }
        It 'a locked module whose folder is gone is not-built' {
            $p = & $script:NewPath
            $null = & $script:Build $p
            Remove-Item -LiteralPath (Join-Path $p 'MicrosoftTeams') -Recurse -Force
            & $script:Codes (& $script:Check $p) | Should -Contain 'not-built'
        }
        It 'two versions of one module are refused: a bundle holds exactly one' {
            $p = & $script:NewPath
            $null = & $script:Build $p
            New-Item -ItemType Directory -Path (Join-Path $p 'Microsoft.Graph.Users/2.9.1') -Force | Out-Null
            & $script:Codes (& $script:Check $p) | Should -Contain 'multiple-versions'
        }
        It 'a manifest that disagrees with the lock is version-mismatch' {
            $p = & $script:NewPath
            $null = & $script:Build $p
            Set-Content -LiteralPath (Join-Path $p 'Microsoft.Graph.Users/2.40.0/Microsoft.Graph.Users.psd1') -Value "@{ ModuleVersion = '2.1.0' }"
            & $script:Codes (& $script:Check $p) | Should -Contain 'version-mismatch'
        }
        It 'a module that is not in the spec is refused, because it would shadow the machine''s copy (Save-Module drags PowerShellGet in)' {
            $p = & $script:NewPath
            $null = & $script:Build $p
            New-Item -ItemType Directory -Path (Join-Path $p 'PowerShellGet/2.2.5') -Force | Out-Null
            $r = & $script:Check $p
            & $script:Codes $r | Should -Contain 'unexpected-module'
            $r['Valid'] | Should -BeFalse
        }
        It 'dot-prefixed folders and loose files in the bundle folder are ignored' {
            $p = & $script:NewPath
            $null = & $script:Build $p
            New-Item -ItemType Directory -Path (Join-Path $p '.cache') | Out-Null
            Set-Content -LiteralPath (Join-Path $p 'notes.txt') -Value 'x'
            (& $script:Check $p)['Valid'] | Should -BeTrue
        }
        It 'a Graph submodule newer than Authentication is graph-skew (it would not import)' {
            $skew = @($script:Spec | ForEach-Object { $c = [ordered]@{} + $_; if ($c['Name'] -eq 'Microsoft.Graph.Users') { $c['Version'] = '2.41.0' }; $c })
            $p = & $script:NewPath
            $null = & $script:Build $p -Spec $skew
            & $script:Codes (& $script:Check $p $script:Floor76 $skew) | Should -Contain 'graph-skew'
        }
        It 'a pin edited after the bundle was built is a warning only: the bundle is still consistent' {
            $moved = @($script:Spec | ForEach-Object { $c = [ordered]@{} + $_; if ($c['Name'] -eq 'Microsoft.Graph.Reports') { $c['Version'] = '2.41.0' }; $c })
            $r = & $script:Check $script:Good $script:Floor76 $moved
            $r['Valid'] | Should -BeTrue
            & $script:Codes $r 'Warnings' | Should -Contain 'pin-drift'
        }
        It 'Exchange outside the range this PowerShell allows is refused, e.g. a bundle built under 7.5 and used after upgrading to 7.6' {
            $p = & $script:NewPath
            $null = & $script:Build $p -Floor $script:Floor75     # 3.9.2
            (& $script:Check $p $script:Floor75)['Valid'] | Should -BeTrue
            $r = & $script:Check $p $script:Floor76
            & $script:Codes $r | Should -Contain 'exchange-range'
            ($r['Errors'] -join ' ') | Should -Match '3\.9\.2'
        }
        It 'an unsupported PowerShell refuses the bundle with the floor''s own reason' {
            $r = & $script:Check $script:Good $script:Floor72
            & $script:Codes $r | Should -Contain 'powershell-unsupported'
        }
        It 'online-only OneDrive placeholders are an error that says how to fix it' {
            $r = Test-NRGModuleBundle -ToolRoot $script:Root -Path $script:Good -Spec $script:Spec -ExoFloor $script:Floor76 -PlaceholderScanner { param($root) @('C:\Users\x\OneDrive\.modules\Microsoft.Graph.Reports\Microsoft.Graph.Reports.dll') }
            & $script:Codes $r | Should -Contain 'cloud-placeholder'
            ($r['Errors'] -join ' ') | Should -Match 'NRG_MODULE_BUNDLE'
        }
        It 'a bundle inside a OneDrive folder is a warning, not an error, while every file is on the device' {
            $p = Join-Path (Join-Path $script:Tmp 'OneDrive - Contoso') 'bundle'
            $null = & $script:Build $p
            $r = & $script:Check $p
            $r['Valid'] | Should -BeTrue
            & $script:Codes $r 'Warnings' | Should -Contain 'onedrive-path'
        }
        It 'a scanner that throws is reported, not propagated' {
            $r = Test-NRGModuleBundle -ToolRoot $script:Root -Path $script:Good -Spec $script:Spec -ExoFloor $script:Floor76 -PlaceholderScanner { throw 'access denied' }
            & $script:Codes $r | Should -Contain 'unreadable'
        }
        It 'the real placeholder scan reports nothing for ordinary files' {
            @(Get-NRGBundlePlaceholderFile -Path $script:Good).Count | Should -Be 0
        }
        It 'the optional SharePoint shell is not required, and is accepted when it was built in' {
            (& $script:Check $script:Good)['Valid'] | Should -BeTrue
            $p = & $script:NewPath
            $null = & $script:Build $p -Spo
            $r = & $script:Check $p
            $r['Valid'] | Should -BeTrue -Because ($r['Errors'] -join '; ')
            @($r['Modules'] | Where-Object { $_['Name'] -eq 'Microsoft.Online.SharePoint.PowerShell' }).Count | Should -Be 1
        }
    }

    Context 'Enable-NRGModuleBundle and Disable-NRGModuleBundle' {
        BeforeAll {
            $script:Active = & $script:NewPath
            $null = & $script:Build $script:Active $script:Floor76
            # The real Exchange floor of THIS PowerShell decides validity at Enable time, so build
            # the bundle that PowerShell accepts.
            $script:RealFloor = Get-NRGExoModuleFloor
            $script:Live = & $script:NewPath
            $null = & $script:Build $script:Live $script:RealFloor
        }
        It 'does nothing when there is no bundle: PSModulePath untouched, nothing to restore' {
            $before = $env:PSModulePath
            $s = Enable-NRGModuleBundle -ToolRoot $script:Root -Path (& $script:NewPath)
            $s['Present'] | Should -BeFalse
            $s['Enabled'] | Should -BeFalse
            $env:PSModulePath | Should -Be $before
            Disable-NRGModuleBundle -State $s
            $env:PSModulePath | Should -Be $before
        }
        It 'warns, and leaves PSModulePath alone, when the bundle is present but invalid' {
            $p = & $script:NewPath
            $null = & $script:Build $p $script:RealFloor
            Remove-Item -LiteralPath (Join-Path $p 'nrg-bundle.json')
            $before = $env:PSModulePath
            $w = $null
            $s = Enable-NRGModuleBundle -ToolRoot $script:Root -Path $p -WarningVariable w -WarningAction SilentlyContinue
            $s['Present'] | Should -BeTrue
            $s['Valid'] | Should -BeFalse
            $s['Enabled'] | Should -BeFalse
            ($w -join ' ') | Should -Match 'was not used'
            $env:PSModulePath | Should -Be $before
        }
        It 'puts a valid bundle first, for this process, and Disable restores PSModulePath exactly' {
            $before = $env:PSModulePath
            $s = Enable-NRGModuleBundle -ToolRoot $script:Root -Path $script:Live 6>$null
            $s['Enabled'] | Should -BeTrue
            $s['Changed'] | Should -BeTrue
            @($env:PSModulePath -split [regex]::Escape($script:Sep))[0] | Should -Be $script:Live
            (Get-NRGActiveModuleBundlePath) | Should -Be $script:Live
            Disable-NRGModuleBundle -State $s
            $env:PSModulePath | Should -Be $before
            Get-NRGActiveModuleBundlePath | Should -BeNullOrEmpty
        }
        It 'is idempotent: a second Enable (the per-client assessment under the batch runner) adds nothing and takes nothing back' {
            $before = $env:PSModulePath
            $outer = Enable-NRGModuleBundle -ToolRoot $script:Root -Path $script:Live 6>$null
            $afterOuter = $env:PSModulePath
            $inner = Enable-NRGModuleBundle -ToolRoot $script:Root -Path $script:Live 6>$null
            $inner['Enabled'] | Should -BeTrue
            $inner['Changed'] | Should -BeFalse
            $env:PSModulePath | Should -Be $afterOuter
            Disable-NRGModuleBundle -State $inner
            $env:PSModulePath | Should -Be $afterOuter -Because 'the inner run did not add the entry, so it must not remove it'
            Disable-NRGModuleBundle -State $outer
            $env:PSModulePath | Should -Be $before
        }
        It 'removes only its own entry, leaving a PSModulePath change made since' {
            $before = $env:PSModulePath
            $s = Enable-NRGModuleBundle -ToolRoot $script:Root -Path $script:Live 6>$null
            $env:PSModulePath = $env:PSModulePath + $script:Sep + (Join-Path $script:Tmp 'added-later')
            Disable-NRGModuleBundle -State $s
            $env:PSModulePath | Should -Be ($before + $script:Sep + (Join-Path $script:Tmp 'added-later'))
        }
        It 'puts PSModulePath back to unset when it was unset' {
            $env:PSModulePath = $null
            $s = Enable-NRGModuleBundle -ToolRoot $script:Root -Path $script:Live 6>$null
            $env:PSModulePath | Should -Be $script:Live
            Disable-NRGModuleBundle -State $s
            [Environment]::GetEnvironmentVariable('PSModulePath') | Should -BeNullOrEmpty
        }
        It 'Disable tolerates a null state and a foreign object' {
            { Disable-NRGModuleBundle -State $null } | Should -Not -Throw
            { Disable-NRGModuleBundle -State 'x' } | Should -Not -Throw
        }
        It 'warns when NRG_MODULE_BUNDLE names a folder that does not exist (a typo must not look like "no bundle")' {
            $env:NRG_MODULE_BUNDLE = (Join-Path $script:Tmp 'typo')
            $w = $null
            $null = Enable-NRGModuleBundle -ToolRoot $script:Root -WarningVariable w -WarningAction SilentlyContinue
            ($w -join ' ') | Should -Match 'NRG_MODULE_BUNDLE is set to'
        }
    }

    Context 'Get-NRGBundledModule and Get-NRGAvailableModule' {
        BeforeAll {
            $script:Live2 = & $script:NewPath
            $null = & $script:Build $script:Live2 (Get-NRGExoModuleFloor)
            # The machine's own copy: HIGHER than the bundle's, so "newest wins" picks it.
            $script:Mach = & $script:NewPath
            foreach ($v in '2.99.0', '2.9.1') {
                $d = Join-Path $script:Mach "Microsoft.Graph.Authentication/$v"
                New-Item -ItemType Directory -Path $d -Force | Out-Null
                Set-Content -LiteralPath (Join-Path $d 'Microsoft.Graph.Authentication.psd1') -Value "@{ ModuleVersion = '$v'; GUID = '$([guid]::NewGuid())' }"
            }
        }
        It 'without a bundle, returns the machine''s copies newest first, as before' {
            $env:PSModulePath = $script:Mach + $script:Sep + $script:SavedPSModulePath
            $r = @(Get-NRGAvailableModule -Name 'Microsoft.Graph.Authentication')
            $r[0].Version | Should -Be ([version]'2.99.0')
            Get-NRGBundledModule -Name 'Microsoft.Graph.Authentication' | Should -BeNullOrEmpty
        }
        It 'with the bundle first on PSModulePath, returns the bundle''s copy even though the machine has a higher version' {
            $s = Enable-NRGModuleBundle -ToolRoot $script:Root -Path $script:Live2 6>$null
            $env:PSModulePath = $env:PSModulePath + $script:Sep + $script:Mach
            $r = @(Get-NRGAvailableModule -Name 'Microsoft.Graph.Authentication')
            $r.Count | Should -Be 1
            $r[0].Source | Should -Be 'Bundle'
            $r[0].Version | Should -Be ([version](@($script:Spec | Where-Object { $_['Name'] -eq 'Microsoft.Graph.Authentication' })[0]['Version']))
            # The pattern this replaces, which is why a plain "sort by version" import is a bug here:
            @(Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication' | Sort-Object Version -Descending)[0].Version | Should -Be ([version]'2.99.0')
            Disable-NRGModuleBundle -State $s
        }
        It 'falls back to the machine for a module the bundle does not carry (the opt-in SharePoint shell)' {
            $s = Enable-NRGModuleBundle -ToolRoot $script:Root -Path $script:Live2 6>$null
            Get-NRGBundledModule -Name 'Microsoft.Online.SharePoint.PowerShell' | Should -BeNullOrEmpty
            Get-NRGBundledModule -Name 'MicrosoftTeams' | Should -Not -BeNullOrEmpty
            Disable-NRGModuleBundle -State $s
        }
    }

    Context 'Get-NRGModuleHealth with the bundle active' {
        BeforeAll {
            $script:Live3 = & $script:NewPath
            $null = & $script:Build $script:Live3 (Get-NRGExoModuleFloor)
            $script:Mach3 = & $script:NewPath
            foreach ($v in '2.99.0', '2.9.1') {
                $d = Join-Path $script:Mach3 "Microsoft.Graph.Authentication/$v"
                New-Item -ItemType Directory -Path $d -Force | Out-Null
                Set-Content -LiteralPath (Join-Path $d 'Microsoft.Graph.Authentication.psd1') -Value "@{ ModuleVersion = '$v'; GUID = '$([guid]::NewGuid())' }"
            }
        }
        It 'machine duplicates ARE the conflict risk without a bundle' {
            $env:PSModulePath = $script:Mach3 + $script:Sep + $script:SavedPSModulePath
            $h = Get-NRGModuleHealth
            $auth = @($h['Modules'] | Where-Object { $_['Name'] -eq 'Microsoft.Graph.Authentication' })[0]
            $auth['MultipleVersions'] | Should -BeTrue
            $h['HasConflictRisk'] | Should -BeTrue
            $h['Bundle']['Active'] | Should -BeFalse
        }
        It 'with the bundle active they are shadowed, listed, and no longer a risk' {
            $s = Enable-NRGModuleBundle -ToolRoot $script:Root -Path $script:Live3 6>$null
            $env:PSModulePath = $env:PSModulePath + $script:Sep + $script:Mach3
            $h = Get-NRGModuleHealth
            $auth = @($h['Modules'] | Where-Object { $_['Name'] -eq 'Microsoft.Graph.Authentication' })[0]
            $auth['Source'] | Should -Be 'Bundle'
            $auth['MultipleVersions'] | Should -BeFalse
            @($auth['Versions']).Count | Should -Be 1
            @($auth['ShadowedVersions']) | Should -Contain '2.99.0'
            @($auth['ShadowedVersions']) | Should -Contain '2.9.1'
            $h['HasConflictRisk'] | Should -BeFalse
            $h['Bundle']['Active'] | Should -BeTrue
            Disable-NRGModuleBundle -State $s
        }
        It '-InstalledOverride still ignores the bundle and the machine, so synthetic-state tests stay deterministic' {
            $s = Enable-NRGModuleBundle -ToolRoot $script:Root -Path $script:Live3 6>$null
            $h = Get-NRGModuleHealth -InstalledOverride @{ 'Microsoft.Graph.Authentication' = @([pscustomobject]@{ Version = [version]'2.0.0'; ModuleBase = 'C:\m' }) }
            $h['Bundle']['Active'] | Should -BeFalse
            @($h['Modules'] | Where-Object { $_['Source'] -eq 'Bundle' }) | Should -BeNullOrEmpty
            Disable-NRGModuleBundle -State $s
        }
    }

    Context 'Resolve-NRGModuleBundlePlan — the Exchange version follows Get-NRGExoModuleFloor' {
        It 'on PowerShell 7.6 the preferred 3.10.1 is inside the allowed range, so it is requested exactly' {
            $exo = @(Resolve-NRGModuleBundlePlan -Spec $script:Spec -ExoFloor $script:Floor76 | Where-Object { $_['Name'] -eq 'ExchangeOnlineManagement' })[0]
            $exo['Request'] | Should -Be '3.10.1'
            $exo['IsRange'] | Should -BeFalse
        }
        It 'on PowerShell 7.4 and 7.5 the preferred version is above the ceiling, so the range is requested (newest 3.9.x)' {
            $exo = @(Resolve-NRGModuleBundlePlan -Spec $script:Spec -ExoFloor $script:Floor75 | Where-Object { $_['Name'] -eq 'ExchangeOnlineManagement' })[0]
            $exo['Request'] | Should -Be '[3.7.2,3.9.99]'
            $exo['IsRange'] | Should -BeTrue
        }
        It 'a preferred version below the floor is replaced by the range too' {
            $low = @($script:Spec | ForEach-Object { $c = [ordered]@{} + $_; if ($c['Name'] -eq 'ExchangeOnlineManagement') { $c['Version'] = '3.9.0' }; $c })
            (@(Resolve-NRGModuleBundlePlan -Spec $low -ExoFloor $script:Floor76 | Where-Object { $_['Name'] -eq 'ExchangeOnlineManagement' })[0]['Request']) | Should -Be '[3.10.0,)'
        }
        It 'an unsupported PowerShell refuses to plan, with the reason' {
            { Resolve-NRGModuleBundlePlan -Spec $script:Spec -ExoFloor $script:Floor72 } | Should -Throw '*cannot run ExchangeOnlineManagement*'
        }
        It 'every other module is requested at its exact pin' {
            foreach ($p in @(Resolve-NRGModuleBundlePlan -Spec $script:Spec -ExoFloor $script:Floor76 | Where-Object { $_['Name'] -ne 'ExchangeOnlineManagement' })) {
                $p['IsRange'] | Should -BeFalse
                $p['Request'] | Should -Be (@($script:Spec | Where-Object { $_['Name'] -eq $p['Name'] })[0]['Version'])
            }
        }
        It 'the SharePoint shell is in the plan only when asked for' {
            @(Resolve-NRGModuleBundlePlan -Spec $script:Spec -ExoFloor $script:Floor76 | ForEach-Object { $_['Name'] }) | Should -Not -Contain 'Microsoft.Online.SharePoint.PowerShell'
            @(Resolve-NRGModuleBundlePlan -Spec $script:Spec -ExoFloor $script:Floor76 -IncludeSharePointShell | ForEach-Object { $_['Name'] }) | Should -Contain 'Microsoft.Online.SharePoint.PowerShell'
        }
    }

    Context 'New-NRGModuleBundle' {
        It 'saves every module once, writes the lock, and ends with a valid bundle' {
            $p = & $script:NewPath
            $r = & $script:Build $p
            $r['Valid'] | Should -BeTrue -Because ($r['Errors'] -join '; ')
            $r['Applied'] | Should -BeTrue
            @($r['Saved']).Count | Should -Be (@($script:Spec | Where-Object { -not $_['Optional'] }).Count)
            $script:Calls.Count | Should -Be @($r['Saved']).Count
            $lock = Get-Content -LiteralPath (Join-Path $p 'nrg-bundle.json') -Raw | ConvertFrom-Json
            $lock.SchemaVersion | Should -Be 1
            $lock.PowerShell | Should -Be $PSVersionTable.PSVersion.ToString()
            $lock.Exchange.Min | Should -Be '3.10.0'
            @($lock.Modules).Count | Should -Be @($r['Saved']).Count
        }
        It 'never asks for the SharePoint shell unless told to' {
            $p = & $script:NewPath
            $null = & $script:Build $p
            $script:Calls | Should -Not -Contain ('Microsoft.Online.SharePoint.PowerShell ' + (@($script:Spec | Where-Object { $_['Name'] -like 'Microsoft.Online*' })[0]['Version']))
            $script:Calls.Clear()
            $q = & $script:NewPath
            $null = & $script:Build $q -Spo
            @($script:Calls | Where-Object { $_ -like 'Microsoft.Online.SharePoint.PowerShell *' }).Count | Should -Be 1
        }
        It 'a second run is a no-op that still reports a valid bundle' {
            $p = & $script:NewPath
            $null = & $script:Build $p
            $script:Calls.Clear()
            $r = & $script:Build $p
            $script:Calls.Count | Should -Be 0
            $r['Applied'] | Should -BeFalse
            $r['Valid'] | Should -BeTrue
            @($r['AlreadyPresent']).Count | Should -BeGreaterThan 8
        }
        It 'writes the lock LAST: a build that fails part-way leaves a folder that is not a valid bundle' {
            $p = & $script:NewPath
            # (A counter inside a scriptblock is a local copy per call; the shared call log counts.)
            $flaky = { param($Name, $Request, $Path) if ($script:Calls.Count -eq 3) { throw 'network down' }; & $script:FakeSave $Name $Request $Path }
            $r = & $script:Build $p -Save $flaky
            $r['Valid'] | Should -BeFalse
            @($r['Failed']).Count | Should -Be 1
            ($r['Errors'] -join ' ') | Should -Match 'network down'
            Test-Path -LiteralPath (Join-Path $p 'nrg-bundle.json') | Should -BeFalse
            & $script:Codes (& $script:Check $p) | Should -Contain 'no-lock'
        }
        It 'an interrupted build is recognized as ours and resumes WITHOUT -Force, saving only what is missing' {
            $p = & $script:NewPath
            $flaky = { param($Name, $Request, $Path) if ($script:Calls.Count -eq 3) { throw 'network down' }; & $script:FakeSave $Name $Request $Path }
            $null = & $script:Build $p -Save $flaky
            Test-Path -LiteralPath (Join-Path $p '.nrg-bundle-incomplete') | Should -BeTrue -Because 'the marker is what lets the next run recognize the folder'
            $script:Calls.Clear()
            $r = & $script:Build $p
            $r['Valid'] | Should -BeTrue -Because ($r['Errors'] -join '; ')
            @($r['AlreadyPresent']).Count | Should -Be 3
            $script:Calls.Count | Should -Be (@($script:Spec | Where-Object { -not $_['Optional'] }).Count - 3) -Because 'the three modules already saved are not downloaded again'
            Test-Path -LiteralPath (Join-Path $p '.nrg-bundle-incomplete') | Should -BeFalse -Because 'a finished build removes the marker'
            Test-Path -LiteralPath (Join-Path $p 'nrg-bundle.json') | Should -BeTrue
        }
        It 'a module folder left incomplete by an interrupted save needs -Force to clear' {
            $p = & $script:NewPath
            $flaky = { param($Name, $Request, $Path) if ($script:Calls.Count -eq 1) { New-Item -ItemType Directory -Path (Join-Path (Join-Path $Path $Name) $Request) -Force | Out-Null; throw 'killed mid-extract' }; & $script:FakeSave $Name $Request $Path }
            $null = & $script:Build $p -Save $flaky
            $r = & $script:Build $p
            ($r['Errors'] -join ' ') | Should -Match 'incomplete folder'
            ($r['Errors'] -join ' ') | Should -Match '-Force'
            $r2 = & $script:Build $p -Force
            $r2['Valid'] | Should -BeTrue -Because ($r2['Errors'] -join '; ')
        }
        It 'a finished build leaves no build marker, and a valid bundle that is only extended keeps working while it is' {
            $p = & $script:NewPath
            $null = & $script:Build $p
            Test-Path -LiteralPath (Join-Path $p '.nrg-bundle-incomplete') | Should -BeFalse
            $r = & $script:Build $p -Spo
            $r['Valid'] | Should -BeTrue -Because ($r['Errors'] -join '; ')
            @($r['Saved']).Count | Should -Be 1 -Because 'only the SharePoint shell was missing'
            @($r['AlreadyPresent']).Count | Should -BeGreaterThan 8
            Test-Path -LiteralPath (Join-Path $p '.nrg-bundle-incomplete') | Should -BeFalse
        }
        It 'refuses a folder that already holds something else, and changes nothing in it' {
            $p = & $script:NewPath
            New-Item -ItemType Directory -Path $p | Out-Null
            Set-Content -LiteralPath (Join-Path $p 'precious.txt') -Value 'keep'
            $r = & $script:Build $p -Force
            $r['Applied'] | Should -BeFalse
            ($r['Errors'] -join ' ') | Should -Match 'not a module bundle'
            (Get-Content -LiteralPath (Join-Path $p 'precious.txt') -Raw).Trim() | Should -Be 'keep'
            $script:Calls.Count | Should -Be 0
        }
        It 'refuses a path that is a file' {
            $f = & $script:NewPath
            Set-Content -LiteralPath $f -Value 'x'
            $r = & $script:Build $f
            ($r['Errors'] -join ' ') | Should -Match 'is a file'
        }
        It 'accepts an empty existing folder' {
            $p = & $script:NewPath
            New-Item -ItemType Directory -Path $p | Out-Null
            (& $script:Build $p)['Valid'] | Should -BeTrue
        }
        It 'removes nothing without -Force: a different pinned version asks for -Force and touches nothing' {
            $p = & $script:NewPath
            $null = & $script:Build $p
            $newer = @($script:Spec | ForEach-Object { $c = [ordered]@{} + $_; if ($c['Family'] -eq 'Graph') { $c['Version'] = '2.41.0' }; $c })
            $script:Calls.Clear()
            $r = & $script:Build $p -Spec $newer
            ($r['Errors'] -join ' ') | Should -Match '-Force'
            @($r['Removed']).Count | Should -Be 0
            $script:Calls.Count | Should -Be 0
            Test-Path -LiteralPath (Join-Path $p 'Microsoft.Graph.Authentication/2.40.0') | Should -BeTrue
        }
        It '-Force rebuilds, removing only the bundle''s own module folders and leaving everything else' {
            $p = & $script:NewPath
            $null = & $script:Build $p
            Set-Content -LiteralPath (Join-Path $p 'notes.txt') -Value 'mine'
            New-Item -ItemType Directory -Path (Join-Path $p '.cache') | Out-Null
            $newer = @($script:Spec | ForEach-Object { $c = [ordered]@{} + $_; if ($c['Family'] -eq 'Graph') { $c['Version'] = '2.41.0' }; $c })
            $r = & $script:Build $p -Spec $newer -Force
            $r['Valid'] | Should -BeTrue -Because ($r['Errors'] -join '; ')
            @($r['Removed']).Count | Should -BeGreaterThan 8
            Test-Path -LiteralPath (Join-Path $p 'Microsoft.Graph.Authentication/2.40.0') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $p 'Microsoft.Graph.Authentication/2.41.0') | Should -BeTrue
            (Get-Content -LiteralPath (Join-Path $p 'notes.txt') -Raw).Trim() | Should -Be 'mine'
            Test-Path -LiteralPath (Join-Path $p '.cache') | Should -BeTrue
        }
        It '-Force never follows a link out of the bundle' {
            $p = & $script:NewPath
            $null = & $script:Build $p
            $outside = & $script:NewPath
            New-Item -ItemType Directory -Path $outside | Out-Null
            Set-Content -LiteralPath (Join-Path $outside 'survivor.txt') -Value 'x'
            $link = Join-Path $p 'MicrosoftTeams'
            Remove-Item -LiteralPath $link -Recurse -Force
            try { New-Item -ItemType SymbolicLink -Path $link -Target $outside -ErrorAction Stop | Out-Null } catch { Set-ItResult -Skipped -Because 'symbolic links need privileges here'; return }
            $r = & $script:Build $p -Force
            ($r['Errors'] -join ' ') | Should -Match 'not an ordinary folder'
            Test-Path -LiteralPath (Join-Path $outside 'survivor.txt') | Should -BeTrue
        }
        It '-WhatIf creates and removes nothing' {
            $p = & $script:NewPath
            $r = New-NRGModuleBundle -ToolRoot $script:Root -Path $p -SaveAction $script:FakeSave -Spec $script:Spec -ExoFloor $script:Floor76 -WhatIf 6>$null
            $r['Applied'] | Should -BeFalse
            Test-Path -LiteralPath $p | Should -BeFalse
            $script:Calls.Count | Should -Be 0
        }
        It 'a bundle built under PowerShell 7.5 is replaced by -Force after an upgrade to 7.6' {
            $p = & $script:NewPath
            $null = & $script:Build $p -Floor $script:Floor75
            (& $script:Check $p $script:Floor76)['Valid'] | Should -BeFalse
            $r = & $script:Build $p -Floor $script:Floor76
            $r['Applied'] | Should -BeFalse -Because 'replacing Exchange needs -Force'
            ($r['Errors'] -join ' ') | Should -Match '-Force'
            $r2 = & $script:Build $p -Floor $script:Floor76 -Force
            $r2['Valid'] | Should -BeTrue -Because ($r2['Errors'] -join '; ')
            (& $script:Check $p $script:Floor76)['Valid'] | Should -BeTrue
        }
        It 'fails cleanly on an unsupported PowerShell, before touching disk' {
            $p = & $script:NewPath
            $r = & $script:Build $p -Floor $script:Floor72
            $r['Applied'] | Should -BeFalse
            ($r['Errors'] -join ' ') | Should -Match 'cannot run ExchangeOnlineManagement'
            Test-Path -LiteralPath $p | Should -BeFalse
        }
    }

    Context 'the real download is Save-PSResource -SkipDependencyCheck, never Save-Module' {
        BeforeAll {
            $script:BuilderAst = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root 'Lib/New-NRGModuleBundle.ps1'), [ref]$null, [ref]$null)
            $script:BuilderCmds = @($script:BuilderAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))
        }
        It 'calls Save-PSResource with -SkipDependencyCheck (ExchangeOnlineManagement lists PackageManagement and PowerShellGet as dependencies)' {
            $save = @($script:BuilderCmds | Where-Object { $_.GetCommandName() -eq 'Save-PSResource' })
            $save.Count | Should -Be 1
            @($save[0].CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'SkipDependencyCheck' }).Count | Should -Be 1
        }
        It 'never calls Save-Module, which follows those dependencies into the bundle' {
            @($script:BuilderCmds | Where-Object { $_.GetCommandName() -in @('Save-Module', 'Install-Module', 'Install-PSResource') }).Count | Should -Be 0
        }
        It 'never touches a tenant or the machine''s module folders: no Graph, Exchange or Uninstall call' {
            @($script:BuilderCmds | Where-Object { $_.GetCommandName() -match '^(Uninstall-|Connect-|Invoke-MgGraphRequest|Set-ExecutionPolicy)' }).Count | Should -Be 0
        }
        It 'every Remove-Item it makes names -LiteralPath' {
            foreach ($c in @($script:BuilderCmds | Where-Object { $_.GetCommandName() -eq 'Remove-Item' })) {
                @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'LiteralPath' }).Count | Should -Be 1
            }
        }
    }

    Context 'the builder is operator-invoked only' {
        It 'is called by Install-NRGPrerequisites.ps1 and by nothing else in the product' {
            $callers = [System.Collections.Generic.List[string]]::new()
            foreach ($f in Get-ChildItem -LiteralPath $script:Root -Recurse -File -Include '*.ps1', '*.psm1' |
                    Where-Object { $_.FullName -notmatch '[\\/](Testing|output|\.git|\.modules)[\\/]' }) {
                $a = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
                if ($a.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'New-NRGModuleBundle' }, $true).Count -gt 0) { $callers.Add($f.Name) }
            }
            @($callers) | Should -Be @('Install-NRGPrerequisites.ps1')
        }
        It 'Repair-NRGModuleHealth is still called by no one (it stays the only operation that removes modules from the operator''s own folders)' {
            $hits = foreach ($f in Get-ChildItem -LiteralPath $script:Root -Recurse -File -Include '*.ps1' |
                    Where-Object { $_.FullName -notmatch '[\\/](Testing|output|\.git|\.modules)[\\/]' -and $_.Name -ne 'Repair-NRGModuleHealth.ps1' }) {
                $a = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
                if ($a.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Repair-NRGModuleHealth' -and $f.Name -ne 'Install-NRGPrerequisites.ps1' }, $true).Count -gt 0) { $f.Name }
            }
            @($hits) | Should -BeNullOrEmpty
        }
        It 'Install-NRGPrerequisites.ps1 -Local stops before any machine-wide step' {
            $src = Get-Content -LiteralPath (Join-Path $script:Root 'Install-NRGPrerequisites.ps1') -Raw
            $localAt = $src.IndexOf('if ($Local) {')
            $localAt | Should -BeGreaterThan 0
            foreach ($later in 'Set-ExecutionPolicy', 'Install-PSResource', 'Repair-NRGModuleHealth', 'Unblock-File') {
                $src.IndexOf($later) | Should -BeGreaterThan $localAt -Because "$later must come after the -Local block, which exits"
            }
            $block = $src.Substring($localAt, $src.IndexOf('# ── Execution policy') - $localAt)
            $block | Should -Match '(?s)exit 0.*exit 1'
        }
        It 'Install-NRGPrerequisites.ps1 -Local refuses a folder that is not a bundle, in a real child process, before saving anything' {
            $p = & $script:NewPath
            New-Item -ItemType Directory -Path $p | Out-Null
            Set-Content -LiteralPath (Join-Path $p 'precious.txt') -Value 'keep'
            $out = & ([System.Environment]::ProcessPath) -NoProfile -NonInteractive -File (Join-Path $script:Root 'Install-NRGPrerequisites.ps1') -Local -BundlePath $p *>&1 | Out-String
            $LASTEXITCODE | Should -Be 1 -Because $out
            $out | Should -Match 'not a module bundle'
            (Get-Content -LiteralPath (Join-Path $p 'precious.txt') -Raw).Trim() | Should -Be 'keep'
            @(Get-ChildItem -LiteralPath $p -Force).Count | Should -Be 1
        }
    }

    Context 'entry points activate the bundle before the tool is imported, and restore PSModulePath in a finally' {
        BeforeAll {
            # Every top-level script that imports the tool's MANIFEST (which loads RequiredModules),
            # whether the path is spelled out or held in $manifestPath, plus the batch triage runner
            # whose children do. A new entry point that imports the manifest is picked up here.
            # (Parsed, not text-matched: Apply-NRGBaseline.ps1 reads the manifest as DATA and says in a
            # comment that it does not Import-Module; it loads nothing from Graph or Exchange.)
            $script:EntryPoints = @(Get-ChildItem -LiteralPath $script:Root -Filter '*.ps1' -File | Where-Object {
                    $a = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]$null)
                    $imports = @($a.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Import-Module' -and $n.Extent.Text -match 'manifestPath|NRG-Assessment\.psd1' }, $true))
                    ($imports.Count -gt 0) -or $_.Name -eq 'Invoke-NRGBatchSignInTriage.ps1'
                } | ForEach-Object { $_.Name })
        }
        It 'covers the six entry points that load Graph or Exchange (assessment, batch, both IR scripts, batch triage, consent)' {
            $script:EntryPoints | Should -Contain 'Invoke-NRGAssessment.ps1'
            $script:EntryPoints | Should -Contain 'Invoke-NRGBatchAssessment.ps1'
            $script:EntryPoints | Should -Contain 'Invoke-NRGSignInTriage.ps1'
            $script:EntryPoints | Should -Contain 'Invoke-NRGEmailAssessment.ps1'
            $script:EntryPoints | Should -Contain 'Invoke-NRGBatchSignInTriage.ps1'
            $script:EntryPoints | Should -Contain 'Grant-NRGGraphConsent.ps1'
        }
        It 'each one dot-sources both libraries, calls Enable before its first import or connect, and wraps the rest in try/finally Disable' {
            foreach ($name in $script:EntryPoints) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root $name), [ref]$null, [ref]$null)
                $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true))
                $dot = @($cmds | Where-Object { $_.InvocationOperator -eq 'Dot' -and $_.Extent.Text -match 'Get-NRGModuleBundle\.ps1' })
                $dotScope = @($cmds | Where-Object { $_.InvocationOperator -eq 'Dot' -and $_.Extent.Text -match 'Get-NRGModuleInstallScope\.ps1' })
                $dot.Count | Should -Be 1 -Because "$name must dot-source Lib/Get-NRGModuleBundle.ps1"
                $dotScope.Count | Should -Be 1 -Because "$name must dot-source Lib/Get-NRGModuleInstallScope.ps1 (Get-NRGExoModuleFloor)"
                $enable = @($cmds | Where-Object { $_.GetCommandName() -eq 'Enable-NRGModuleBundle' })
                $enable.Count | Should -Be 1 -Because "$name must call Enable-NRGModuleBundle once"
                $first = @($cmds | Where-Object { $_.GetCommandName() -in @('Import-Module', 'Connect-MgGraph') } | Sort-Object { $_.Extent.StartOffset })[0]
                if ($first) { $enable[0].Extent.StartOffset | Should -BeLessThan $first.Extent.StartOffset -Because "$name must activate the bundle before its first Import-Module / Connect-MgGraph (the manifest's RequiredModules load on import)" }
                $dot[0].Extent.StartOffset | Should -BeLessThan $enable[0].Extent.StartOffset
                # The Disable call sits in the finally of a try that starts after Enable and covers the first import.
                $try = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.TryStatementAst] -and $null -ne $n.Finally -and $n.Finally.Extent.Text -match 'Disable-NRGModuleBundle' }, $true))
                $try.Count | Should -BeGreaterThan 0 -Because "$name must restore PSModulePath in a finally"
                $outer = @($try | Sort-Object { $_.Extent.StartOffset })[0]
                $outer.Extent.StartOffset | Should -BeGreaterThan $enable[0].Extent.StartOffset
                if ($first) { $first.Extent.StartOffset | Should -BeGreaterThan $outer.Extent.StartOffset -Because "$name's try/finally must cover the first import, or an early exit skips the restore" }
                # ... and it is the outermost statement block: the script's last statement is that try.
                $outer.Extent.EndOffset | Should -BeGreaterOrEqual ($ast.EndBlock.Statements[-1].Extent.EndOffset - 1) -Because "$name's try/finally must run to the end of the script so every exit path restores PSModulePath"
            }
        }
        It 'no script declares #Requires -Modules for Graph, Exchange or Teams: a #Requires line imports the module before any code runs, ahead of the bundle' {
            foreach ($f in Get-ChildItem -LiteralPath $script:Root -Recurse -File -Include '*.ps1', '*.psm1' |
                    Where-Object { $_.FullName -notmatch '[\\/](Testing|output|\.git|\.modules)[\\/]' }) {
                $hits = @(Get-Content -LiteralPath $f.FullName | Where-Object { $_ -match '^\s*#Requires\s+-Modules.*(Microsoft\.Graph|ExchangeOnlineManagement|MicrosoftTeams)' })
                $hits | Should -BeNullOrEmpty -Because "$($f.Name) pre-empts the module bundle"
            }
        }
        It 'the batch runners still check for the modules they used to require, after the bundle is active' {
            foreach ($name in 'Invoke-NRGBatchAssessment.ps1', 'Invoke-NRGBatchSignInTriage.ps1') {
                (Get-Content -LiteralPath (Join-Path $script:Root $name) -Raw) | Should -Match "Get-NRGAvailableModule -Name"
            }
        }
        It 'the batch runner can actually start: its own -WhatIf switch must not collide with SupportsShouldProcess' {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root 'Invoke-NRGBatchAssessment.ps1'), [ref]$null, [ref]$null)
            $cb = $ast.ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' }
            $sps = @($cb.NamedArguments | Where-Object { $_.ArgumentName -eq 'SupportsShouldProcess' }).Count -gt 0
            $declaresWhatIf = @($ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'WhatIf' }).Count -gt 0
            ($sps -and $declaresWhatIf) | Should -BeFalse -Because 'PowerShell rejects the script at binding: "A parameter with the name WhatIf was defined multiple times"'
        }
    }

    Context 'nothing sorts module copies by version across paths' {
        It 'Connect-NRGServices and the Power Platform collector pick modules through Get-NRGAvailableModule' {
            $connect = Get-Content -LiteralPath (Join-Path $script:Root 'Lib/Connect-NRGServices.ps1') -Raw
            $pp = Get-Content -LiteralPath (Join-Path $script:Root 'Collectors/PowerPlatform/Invoke-NRGCollectPowerPlatform.ps1') -Raw
            # (The Exchange HINT lookup lists copies too, but only to word a message; it reads the loaded module first.)
            ($connect -match 'Get-Module\s+-ListAvailable\s+-Name\s+Microsoft\.Graph\.Authentication') | Should -BeFalse -Because 'listing every copy and sorting by Version hands a higher-version machine copy the win'
            ($connect -match 'Get-Module\s+-ListAvailable\s+-Name\s+Microsoft\.Online\.SharePoint\.PowerShell[^\r\n]*Sort-Object') | Should -BeFalse
            ($pp -match 'Get-Module\s+-ListAvailable\s+Microsoft\.Graph\.Authentication') | Should -BeFalse
            ($connect -match "Get-NRGAvailableModule -Name 'Microsoft.Graph.Authentication'") | Should -BeTrue
            ($connect -match "Get-NRGAvailableModule -Name 'Microsoft.Online.SharePoint.PowerShell'") | Should -BeTrue
            ($pp -match "Get-NRGAvailableModule -Name 'Microsoft.Graph.Authentication'") | Should -BeTrue
        }
        It 'with the bundle active, only the bundle''s Graph submodules are pre-imported' {
            (Get-Content -LiteralPath (Join-Path $script:Root 'Lib/Connect-NRGServices.ps1') -Raw) | Should -Match 'Get-NRGBundledModule -Name \$gm'
        }
    }

    Context 'the bundle is never swept up by a repo-wide scan, signer or hash' {
        It '.gitignore lists .modules/' {
            @(Get-Content -LiteralPath (Join-Path $script:Root '.gitignore')) | Should -Contain '.modules/'
        }
        It 'every recursive Get-ChildItem rooted at the repo excludes .modules (tests, integrity manifest, release signing)' {
            $files = @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'Testing') -Filter '*.Tests.ps1' -File) +
                @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'Email-IR/Testing') -Filter '*.Tests.ps1' -File -ErrorAction SilentlyContinue) +
                @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'tools') -Filter '*.ps1' -File) +
                @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'Build') -Filter '*.ps1' -File) +
                @(Get-Item -LiteralPath (Join-Path $script:Root 'Install-NRGPrerequisites.ps1'))
            $offenders = [System.Collections.Generic.List[string]]::new()
            foreach ($f in $files) {
                if ($f.Name -eq 'NRG.ModuleBundle.Tests.ps1') { continue }
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
                foreach ($c in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Get-ChildItem' }, $true)) {
                    $recurse = @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] -and $_.ParameterName -eq 'Recurse' }).Count -gt 0
                    if (-not $recurse) { continue }
                    # Rooted at the repo itself (a bare root variable), not at a sub-folder.
                    $rooted = @($c.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.VariableExpressionAst] -and $_.VariablePath.UserPath -match '(?i)(^|:)(repo)?root$|(^|:)scriptdir$' }).Count -gt 0
                    if (-not $rooted) { continue }
                    $stmt = $c.Parent
                    while ($stmt -and $stmt -isnot [System.Management.Automation.Language.StatementAst]) { $stmt = $stmt.Parent }
                    if ($stmt.Extent.Text -notmatch '\.modules') { $offenders.Add("$($f.Name):$($c.Extent.StartLineNumber)") }
                }
            }
            @($offenders) | Should -BeNullOrEmpty -Because "these scan the whole repo and would walk into .modules (Microsoft's own packages): $($offenders -join ', ')"
        }
        It 'the release signer and the integrity manifest skip .modules explicitly' {
            foreach ($rel in 'Build/Sign-Release.ps1', 'tools/Verify-Integrity.ps1') {
                (Get-Content -LiteralPath (Join-Path $script:Root $rel) -Raw) | Should -Match '\\\.modules'
            }
        }
    }

    Context 'documentation' {
        It 'README explains -Local, the override variable and the fallback' {
            $readme = Get-Content -LiteralPath (Join-Path $script:Root 'README.md') -Raw
            # Boolean checks: a failed -Match would echo the whole README into the test log.
            ($readme -match 'Install-NRGPrerequisites\.ps1 -Local') | Should -BeTrue -Because 'README must name the command that builds the bundle'
            ($readme -match 'NRG_MODULE_BUNDLE') | Should -BeTrue -Because 'README must document the override variable'
            ($readme -match '\.modules') | Should -BeTrue -Because 'README must name the folder'
        }
    }
}
