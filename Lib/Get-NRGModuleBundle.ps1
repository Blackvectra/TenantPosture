#Requires -Version 7.0
#
# Get-NRGModuleBundle.ps1
# Dependencies: Get-NRGExoModuleFloor (Lib/Get-NRGModuleInstallScope.ps1) for the
#               Exchange version check. Reads the bundle folder and
#               Config/module-bundle.json. No tenant calls, nothing installed,
#               nothing written to disk. The only state it changes is this
#               process's PSModulePath, and Disable-NRGModuleBundle puts it back.
#
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: the tool's module bundle, a venv equivalent. Install-NRGPrerequisites.ps1
#   -Local saves exactly one pinned version of each Microsoft module the tool uses
#   into .modules/ inside the tool (Lib/New-NRGModuleBundle.ps1). When that folder
#   exists and passes Test-NRGModuleBundle, Enable-NRGModuleBundle puts it FIRST on
#   PSModulePath for this process, so a duplicate or an online-only OneDrive copy
#   elsewhere on the machine cannot win. When the folder is absent nothing changes:
#   the tool behaves as it did before the bundle existed.
#
# WHY FIRST ON PSModulePath IS ENOUGH, AND WHERE IT IS NOT:
#   Checked on PowerShell 7.6: with the bundle first, Import-Module by name, the
#   RequiredModules in NRG-Assessment.psd1 and command autoload all pick the bundle
#   copy even when a LATER path holds a higher version. Code that lists every copy
#   and sorts by Version across paths defeats that (Connect-NRGServices did, and
#   imported the highest copy by explicit path). Those sites go through
#   Get-NRGAvailableModule, which returns the bundle copy when the bundle is active.
#
# THE ENTRY POINTS MUST ACTIVATE IT BEFORE Import-Module NRG-Assessment.psd1:
#   the manifest's RequiredModules (Graph.Authentication, ExchangeOnlineManagement)
#   are imported by that call, from whatever PSModulePath resolves first. That is why
#   this file is dot-sourced by the entry points rather than reached through the
#   module, and why "active" is read back from PSModulePath itself (the first entry
#   carries nrg-bundle.json) instead of being kept as separate state that could
#   disagree with it.
#
# A module that is already loaded in the session cannot be replaced by a path change.
# Enable-NRGModuleBundle reports those (LoadedOutside) so the operator is told to open a
# new window rather than being left with the same hang and no explanation.
#
# Consumes: nothing.  Sets: nothing.  Graph scopes / cmdlets: none.

# Name of the lock file the builder writes LAST. Its presence is what makes a folder
# "ours" for the builder, and its absence is how an interrupted build is recognized.
$script:NRGModuleBundleLockName = 'nrg-bundle.json'

function Get-NRGModuleBundleSpec {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [string] $ToolRoot
    )

    Set-StrictMode -Version Latest

    $file = Join-Path (Join-Path $ToolRoot 'Config') 'module-bundle.json'
    $json = Get-Content -LiteralPath $file -Raw -Encoding utf8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop

    $read = {
        param($Item, [string] $Key, $Default)
        $p = $Item.PSObject.Properties[$Key]
        if ($null -eq $p -or $null -eq $p.Value) { $Default } else { $p.Value }
    }

    $modules = [System.Collections.Generic.List[object]]::new()
    foreach ($m in @(& $read $json 'Modules' @())) {
        $modules.Add([ordered]@{
            Name          = [string](& $read $m 'Name' '')
            Version       = [string](& $read $m 'Version' '')
            Family        = [string](& $read $m 'Family' '')
            VersionPolicy = [string](& $read $m 'VersionPolicy' 'Exact')
            Optional      = [bool](& $read $m 'Optional' $false)
            Why           = [string](& $read $m 'Why' '')
        })
    }
    return @($modules)
}

# Where the bundle lives. NRG_MODULE_BUNDLE overrides the default <tool>\.modules so one
# bundle can be shared by several checkouts, or kept OUTSIDE OneDrive when the tool
# folder itself is inside it. A relative override resolves against the PowerShell
# location, not the process working directory (they differ after Set-Location).
function Get-NRGModuleBundlePath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $ToolRoot
    )

    Set-StrictMode -Version Latest

    $override = [Environment]::GetEnvironmentVariable('NRG_MODULE_BUNDLE')
    $candidate = if ($override -and $override.Trim()) { $override.Trim() } else { Join-Path $ToolRoot '.modules' }
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($candidate)
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($full.Length -gt $root.Length) { $full = $full.TrimEnd([char]'\', [char]'/') }
    return $full
}

# ModuleVersion from a module manifest WITHOUT running it. Import-PowerShellDataFile
# cannot be used: ExchangeOnlineManagement's own manifest contains $PSEdition
# conditionals, so it is not data-only and the cmdlet throws on it (found by reading the
# real 3.10.1 package). The manifest is parsed, never executed.
function Get-NRGModuleManifestVersion {
    [CmdletBinding()]
    [OutputType([version])]
    param(
        [Parameter(Mandatory)] [string] $Path
    )

    Set-StrictMode -Version Latest

    $tokens = $null; $errs = $null
    try {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
    } catch { return $null }
    if ($null -eq $ast -or ($errs -and $errs.Count -gt 0)) { return $null }

    # The first hashtable in tree order is the manifest's own top-level one.
    $table = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.HashtableAst] }, $true)
    if ($null -eq $table) { return $null }
    foreach ($pair in $table.KeyValuePairs) {
        $key = $pair.Item1
        if ($key -is [System.Management.Automation.Language.StringConstantExpressionAst] -and $key.Value -eq 'ModuleVersion') {
            $const = $pair.Item2.Find({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)
            if ($null -eq $const) { return $null }
            $v = $null
            if ([version]::TryParse([string]$const.Value, [ref]$v)) { return $v }
            return $null
        }
    }
    return $null
}

# Files OneDrive Files On-Demand has not materialized. Attribute flags only: nothing is
# opened, so scanning does not itself download anything. The flags are Windows-specific
# and are never set on other platforms.
function Get-NRGBundlePlaceholderFile {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string] $Path
    )

    Set-StrictMode -Version Latest

    # FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
    $cloudMask = 0x1000 -bor 0x40000 -bor 0x400000
    $found = [System.Collections.Generic.List[string]]::new()
    $options = [System.IO.EnumerationOptions]::new()
    $options.RecurseSubdirectories = $true
    $options.IgnoreInaccessible = $false
    $options.AttributesToSkip = [System.IO.FileAttributes]0
    foreach ($f in [System.IO.Directory]::EnumerateFiles($Path, '*', $options)) {
        if (([int][System.IO.File]::GetAttributes($f) -band $cloudMask) -ne 0) { $found.Add($f) }
    }
    return @($found)
}

# Judge a bundle folder. A bundle is used all or nothing: a half-built or stale one that
# was activated would mix its copies with the machine's, which is the problem it exists
# to remove. Errors make it unusable; Warnings do not.
#
#   Present  the folder exists (absence is not an error: the tool falls back silently)
#   Valid    Present and no Errors
#
# Every entry in Errors / Warnings starts with a stable code and a colon, so a caller or a
# test keys on the code and the rest is for the operator.
function Test-NRGModuleBundle {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $ToolRoot,

        [Parameter()] [AllowNull()] [string] $Path,

        # Test seams: a synthetic spec, a synthetic Exchange floor, and a scanner that
        # reports online-only files without needing OneDrive.
        [Parameter()] [AllowNull()] [object[]] $Spec,
        [Parameter()] [AllowNull()] [System.Collections.IDictionary] $ExoFloor,
        [Parameter()] [AllowNull()] [scriptblock] $PlaceholderScanner
    )

    Set-StrictMode -Version Latest

    if (-not $Path) { $Path = Get-NRGModuleBundlePath -ToolRoot $ToolRoot }
    $errors   = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $modules  = [System.Collections.Generic.List[object]]::new()

    $result = {
        [ordered]@{
            Path     = $Path
            Present  = $present
            Valid    = ($present -and $errors.Count -eq 0)
            Errors   = @($errors)
            Warnings = @($warnings)
            Modules  = @($modules)
        }
    }

    $present = [bool](Test-Path -LiteralPath $Path -PathType Container)
    if (-not $present) { return (& $result) }

    $rebuild = 'Rebuild it: .\Install-NRGPrerequisites.ps1 -Local -Force'

    # ── Lock file: written last by the builder, so its absence means an interrupted build.
    $lockPath = Join-Path $Path $script:NRGModuleBundleLockName
    if (-not (Test-Path -LiteralPath $lockPath -PathType Leaf)) {
        $errors.Add("no-lock: $script:NRGModuleBundleLockName is missing, so this folder was not completely built by Install-NRGPrerequisites.ps1 -Local. $rebuild")
        return (& $result)
    }
    $lock = $null
    try {
        $lock = Get-Content -LiteralPath $lockPath -Raw -Encoding utf8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        $errors.Add("bad-lock: $script:NRGModuleBundleLockName could not be read ($($_.Exception.Message)). $rebuild")
        return (& $result)
    }
    $lockModules = @()
    $lockProp = $lock.PSObject.Properties['Modules']
    if ($null -ne $lockProp -and $null -ne $lockProp.Value) { $lockModules = @($lockProp.Value) }
    $schema = $lock.PSObject.Properties['SchemaVersion']
    if ($null -eq $schema -or [string]$schema.Value -ne '1' -or $lockModules.Count -eq 0) {
        $errors.Add("bad-lock: $script:NRGModuleBundleLockName has an unknown shape. $rebuild")
        return (& $result)
    }

    if (-not $PSBoundParameters.ContainsKey('Spec') -or $null -eq $Spec) { $Spec = Get-NRGModuleBundleSpec -ToolRoot $ToolRoot }
    $specByName = @{}
    foreach ($s in $Spec) { $specByName[[string]$s['Name']] = $s }

    $locked = @{}
    foreach ($lm in $lockModules) {
        $np = $lm.PSObject.Properties['Name']; $vp = $lm.PSObject.Properties['Version']
        if ($null -eq $np -or $null -eq $vp) { continue }
        $locked[[string]$np.Value] = [string]$vp.Value
    }

    # ── Every required module must be in the bundle (an optional one only when it was asked for).
    foreach ($name in $specByName.Keys) {
        if ($specByName[$name]['Optional']) { continue }
        if (-not $locked.ContainsKey($name)) {
            $errors.Add("missing: $name is listed in Config/module-bundle.json but is not in the bundle. $rebuild")
        }
    }

    # ── Each locked module: one version on disk, matching the lock and its own manifest.
    foreach ($name in @($locked.Keys | Sort-Object)) {
        $wanted = $locked[$name]
        $modDir = Join-Path $Path $name
        $versionDirs = @()
        if (Test-Path -LiteralPath $modDir -PathType Container) {
            $versionDirs = @(Get-ChildItem -LiteralPath $modDir -Directory -Force -ErrorAction SilentlyContinue)
        }
        if ($versionDirs.Count -eq 0) {
            $errors.Add("not-built: $name $wanted is in the lock but no folder exists for it. $rebuild")
            continue
        }
        if ($versionDirs.Count -gt 1) {
            $errors.Add("multiple-versions: $name has $($versionDirs.Count) versions in the bundle ($(($versionDirs | ForEach-Object { $_.Name }) -join ', ')); a bundle holds exactly one. $rebuild")
            continue
        }
        $dir = $versionDirs[0]
        $psd1 = Join-Path $dir.FullName "$name.psd1"
        if ($dir.Name -ne $wanted -or -not (Test-Path -LiteralPath $psd1 -PathType Leaf)) {
            $errors.Add("version-mismatch: $name is locked at $wanted but the folder on disk is '$($dir.Name)'$(if (-not (Test-Path -LiteralPath $psd1 -PathType Leaf)) { ' and has no manifest' }). $rebuild")
            continue
        }
        # Opening the manifest also surfaces an online-only OneDrive file whose attribute
        # flags were not set ("The cloud file provider is not running").
        try {
            $fs = [System.IO.File]::OpenRead($psd1)
            try { $null = $fs.ReadByte() } finally { $fs.Dispose() }
        } catch {
            $errors.Add("unreadable: $name's manifest cannot be read ($($_.Exception.Message)). If the folder is synced by OneDrive, set it to Always keep on this device, or build the bundle outside it (set NRG_MODULE_BUNDLE).")
            continue
        }
        $manifestVersion = Get-NRGModuleManifestVersion -Path $psd1
        if ($null -eq $manifestVersion -or $manifestVersion.ToString() -ne $wanted) {
            $errors.Add("version-mismatch: $name's manifest says $(if ($manifestVersion) { $manifestVersion } else { 'a version that could not be read' }) but the lock says $wanted. $rebuild")
            continue
        }
        $modules.Add([ordered]@{
            Name       = $name
            Version    = $wanted
            Path       = $psd1
            ModuleBase = $dir.FullName
        })

        # A pin edited after the bundle was built: still self-consistent, so a warning only.
        if ($specByName.ContainsKey($name)) {
            $s = $specByName[$name]
            if ([string]$s['VersionPolicy'] -ne 'ExchangeFloor' -and [string]$s['Version'] -and [string]$s['Version'] -ne $wanted) {
                $warnings.Add("pin-drift: $name is $wanted in the bundle but Config/module-bundle.json pins $($s['Version']). The bundle still works; rebuild to match: .\Install-NRGPrerequisites.ps1 -Local -Force")
            }
        }
    }

    # ── Anything in the bundle that is not in the spec would shadow the machine's copy of it.
    # (Saving ExchangeOnlineManagement with Save-Module also saves PackageManagement and
    # PowerShellGet, which would shadow the real ones. The builder prevents that; this is
    # the check that proves it, and it catches a folder added by hand.)
    foreach ($d in @(Get-ChildItem -LiteralPath $Path -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($d.Name.StartsWith('.')) { continue }
        if (-not $specByName.ContainsKey($d.Name)) {
            $errors.Add("unexpected-module: '$($d.Name)' is in the bundle but not in Config/module-bundle.json; it would shadow the machine's copy of that module. Remove the folder, or rebuild: .\Install-NRGPrerequisites.ps1 -Local -Force")
        }
    }

    # ── Graph modules: a submodule needs Microsoft.Graph.Authentication at its version or newer.
    $authVersion = $null
    if ($locked.ContainsKey('Microsoft.Graph.Authentication')) {
        $av = $null
        if ([version]::TryParse($locked['Microsoft.Graph.Authentication'], [ref]$av)) { $authVersion = $av }
    }
    if ($null -ne $authVersion) {
        $graphVersions = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($name in $locked.Keys) {
            if (-not ($specByName.ContainsKey($name) -and [string]$specByName[$name]['Family'] -eq 'Graph')) { continue }
            [void]$graphVersions.Add($locked[$name])
            $gv = $null
            if ([version]::TryParse($locked[$name], [ref]$gv) -and $gv -gt $authVersion) {
                $errors.Add("graph-skew: $name $gv needs Microsoft.Graph.Authentication $gv or newer but the bundle has $authVersion. $rebuild")
            }
        }
        if ($graphVersions.Count -gt 1 -and -not (@($errors | Where-Object { $_ -like 'graph-skew:*' }).Count)) {
            $warnings.Add("graph-versions-differ: the Graph modules in the bundle are not all one version ($(@($graphVersions | Sort-Object) -join ', ')).")
        }
    }

    # ── Exchange must be inside the range Get-NRGExoModuleFloor allows for THIS PowerShell.
    # A bundle built under PowerShell 7.5 and used after an upgrade to 7.6 carries an
    # Exchange version that fails inside the module at connect time with a bare null-reference.
    if ($locked.ContainsKey('ExchangeOnlineManagement')) {
        $floor = $ExoFloor
        if ($null -eq $floor -and (Get-Command Get-NRGExoModuleFloor -ErrorAction SilentlyContinue)) { $floor = Get-NRGExoModuleFloor }
        if ($null -ne $floor) {
            $exo = $null
            [void][version]::TryParse($locked['ExchangeOnlineManagement'], [ref]$exo)
            if (-not [bool]$floor['Supported']) {
                $errors.Add("powershell-unsupported: $($floor['Reason'])")
            } elseif ($null -ne $exo) {
                $min = [version][string]$floor['Min']
                $max = if ($floor['Max']) { [version][string]$floor['Max'] } else { $null }
                if ($exo -lt $min -or ($null -ne $max -and $exo -gt $max)) {
                    $range = if ($max) { "$min to $max" } else { "$min or later" }
                    $errors.Add("exchange-range: the bundle has ExchangeOnlineManagement $exo but PowerShell $($PSVersionTable.PSVersion) needs $range. $($floor['Reason']) Rebuild: .\Install-NRGPrerequisites.ps1 -Local -Force")
                }
            }
        }
    }

    # ── OneDrive: online-only files are an error; merely living under OneDrive is a warning.
    $scanner = if ($PlaceholderScanner) { $PlaceholderScanner } else { { param($root) Get-NRGBundlePlaceholderFile -Path $root } }
    $placeholders = @()
    try { $placeholders = @(& $scanner $Path) } catch {
        $errors.Add("unreadable: the bundle could not be scanned ($($_.Exception.Message)).")
    }
    if ($placeholders.Count -gt 0) {
        $errors.Add("cloud-placeholder: $($placeholders.Count) file(s) in the bundle are online-only OneDrive placeholders (first: $($placeholders[0])). Set the folder to Always keep on this device, or keep the bundle outside OneDrive by setting NRG_MODULE_BUNDLE to a folder such as C:\NRG\modules and rebuilding there.")
    } elseif ($Path -match '(?i)\bOneDrive\b') {
        $warnings.Add("onedrive-path: the bundle is inside a OneDrive folder. It works while every file stays on this device; if OneDrive frees the space it can fail the way the machine's own module folder did. Keeping it outside OneDrive (NRG_MODULE_BUNDLE) avoids that.")
    }

    return (& $result)
}

# The bundle that is active in THIS process: the first PSModulePath entry, when that
# folder carries the lock file. Nothing else to keep in step.
function Get-NRGActiveModuleBundlePath {
    [CmdletBinding()]
    [OutputType([string])]
    param()

    Set-StrictMode -Version Latest

    $mp = [Environment]::GetEnvironmentVariable('PSModulePath')
    if (-not $mp) { return $null }
    $first = @($mp -split [regex]::Escape([string][System.IO.Path]::PathSeparator))[0]
    if (-not $first) { return $null }
    if (Test-Path -LiteralPath (Join-Path $first $script:NRGModuleBundleLockName) -PathType Leaf) { return $first }
    return $null
}

# The bundle's copy of a module, or $null when the bundle is not active or does not carry it.
function Get-NRGBundledModule {
    [CmdletBinding()]
    [OutputType([object])]
    param(
        [Parameter(Mandatory)] [string] $Name
    )

    Set-StrictMode -Version Latest

    $root = Get-NRGActiveModuleBundlePath
    if (-not $root) { return $null }
    $dir = Join-Path $root $Name
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { return $null }

    $best = $null
    foreach ($d in @(Get-ChildItem -LiteralPath $dir -Directory -Force -ErrorAction SilentlyContinue)) {
        $v = $null
        if (-not [version]::TryParse($d.Name, [ref]$v)) { continue }
        if ($null -eq $best -or $v -gt $best.Version) { $best = [pscustomobject]@{ Version = $v; Dir = $d.FullName } }
    }
    if ($null -eq $best) { return $null }
    $psd1 = Join-Path $best.Dir "$Name.psd1"
    if (-not (Test-Path -LiteralPath $psd1 -PathType Leaf)) { return $null }
    return [pscustomobject]@{ Name = $Name; Version = $best.Version; Path = $psd1; ModuleBase = $best.Dir; Source = 'Bundle' }
}

# Loaded copies of a module (this session) whose files are NOT in the bundle. A path change
# cannot replace a loaded module, so each one means the run is using a copy the bundle was meant
# to keep out. Empty when no bundle is active. -BundlePath names the bundle explicitly (Enable
# calls it right after changing PSModulePath); without it the active bundle is used.
function Get-NRGLoadedModuleOutsideBundle {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter()] [AllowNull()] [string] $BundlePath
    )

    Set-StrictMode -Version Latest

    $root = if ($BundlePath) { $BundlePath } else { Get-NRGActiveModuleBundlePath }
    if (-not $root) { return @() }
    $prefix = $root.TrimEnd([char]'\', [char]'/') + [System.IO.Path]::DirectorySeparatorChar
    return @(Get-Module -Name $Name -ErrorAction SilentlyContinue | Where-Object {
            -not ([string]$_.ModuleBase + [System.IO.Path]::DirectorySeparatorChar).StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)
        })
}

# Every copy of a module the caller may import, best first. With the bundle active that is
# the bundle's single copy; otherwise the machine's copies, newest first (what the tool
# did before the bundle existed). Callers that sort Get-Module -ListAvailable by Version
# themselves get the highest copy ACROSS paths, which is how a decoy beats the bundle.
function Get-NRGAvailableModule {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [string] $Name
    )

    Set-StrictMode -Version Latest

    $bundled = Get-NRGBundledModule -Name $Name
    if ($null -ne $bundled) { return @($bundled) }
    return @(Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue | Sort-Object Version -Descending)
}

# Put the bundle first on PSModulePath for this process. Returns a state object to hand to
# Disable-NRGModuleBundle. Never throws for a missing or unusable bundle: it falls back to
# the machine's modules, and says so when a bundle was present but not used.
function Enable-NRGModuleBundle {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $ToolRoot,

        [Parameter()] [AllowNull()] [string] $Path,

        # Test seam: passed through to Test-NRGModuleBundle.
        [Parameter()] [AllowNull()] [scriptblock] $PlaceholderScanner
    )

    Set-StrictMode -Version Latest

    $override = [Environment]::GetEnvironmentVariable('NRG_MODULE_BUNDLE')
    $bundle = if ($Path) { $Path } else { Get-NRGModuleBundlePath -ToolRoot $ToolRoot }
    $sep = [string][System.IO.Path]::PathSeparator

    $state = [ordered]@{
        Path                 = $bundle
        Present              = $false
        Valid                = $false
        Enabled              = $false
        Changed              = $false
        PreviousPSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath')
        Errors               = @()
        Warnings             = @()
        Modules              = @()
        LoadedOutside        = @()
    }

    if (-not (Test-Path -LiteralPath $bundle -PathType Container)) {
        if (-not $Path -and $override -and $override.Trim()) {
            Write-Warning "NRG_MODULE_BUNDLE is set to '$bundle' but that folder does not exist, so the module bundle was not used. Build it there with .\Install-NRGPrerequisites.ps1 -Local, or clear the variable."
        } else {
            Write-Verbose "No module bundle at $bundle; using the modules installed on this machine."
        }
        return $state
    }
    $state['Present'] = $true

    $testArgs = @{ ToolRoot = $ToolRoot; Path = $bundle }
    if ($PlaceholderScanner) { $testArgs['PlaceholderScanner'] = $PlaceholderScanner }
    $check = Test-NRGModuleBundle @testArgs
    $state['Errors']   = @($check['Errors'])
    $state['Warnings'] = @($check['Warnings'])
    $state['Modules']  = @($check['Modules'])
    if (-not $check['Valid']) {
        Write-Warning ("The module bundle at $bundle was not used, so this run falls back to the modules installed on this machine:`n  " +
            (@($check['Errors']) -join "`n  "))
        return $state
    }
    $state['Valid'] = $true

    $current = [Environment]::GetEnvironmentVariable('PSModulePath')
    $first = if ($current) { @($current -split [regex]::Escape($sep))[0] } else { '' }
    if ($first -and [string]::Equals($first.TrimEnd([char]'\', [char]'/'), $bundle, [System.StringComparison]::OrdinalIgnoreCase)) {
        # Already first (an earlier entry point in this process, or the caller): nothing to add
        # and nothing for Disable to take back.
        $state['Enabled'] = $true
    } else {
        $env:PSModulePath = if ($current) { $bundle + $sep + $current } else { $bundle }
        $state['Enabled'] = $true
        $state['Changed'] = $true
    }

    # A module already loaded from elsewhere stays loaded; a path change cannot swap it, and
    # Connect-NRGServices leaves it in place rather than force-importing the bundle's copy over it.
    $outside = [System.Collections.Generic.List[string]]::new()
    foreach ($m in $state['Modules']) {
        foreach ($loaded in @(Get-NRGLoadedModuleOutsideBundle -Name ([string]$m['Name']) -BundlePath $bundle)) {
            $outside.Add("$($loaded.Name) $($loaded.Version) from $($loaded.ModuleBase)")
        }
    }
    $state['LoadedOutside'] = @($outside)
    if ($outside.Count -gt 0) {
        Write-Warning ("The module bundle is active, but this PowerShell session already loaded " +
            (@($outside) -join '; ') +
            ". A loaded module cannot be replaced, so this run uses that copy. Open a new PowerShell window and run again to use the bundle.")
    } else {
        Write-Host "  [+] Module bundle: $bundle ($(@($state['Modules']).Count) modules, one version each)" -ForegroundColor Green
    }
    foreach ($w in @($check['Warnings'])) { Write-Host "  [i] Module bundle: $w" -ForegroundColor DarkGray }
    return $state
}

# Take back what Enable-NRGModuleBundle added: remove the bundle's own entry from PSModulePath
# and nothing else, so a change made to PSModulePath since is left alone. A no-op when Enable
# did not change anything (no bundle, an invalid one, or one that was already first).
function Disable-NRGModuleBundle {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] $State
    )

    Set-StrictMode -Version Latest

    if ($null -eq $State -or $State -isnot [System.Collections.IDictionary]) { return }
    if (-not $State.Contains('Changed') -or -not [bool]$State['Changed']) { return }

    $bundle = [string]$State['Path']
    $sep = [string][System.IO.Path]::PathSeparator
    $current = [Environment]::GetEnvironmentVariable('PSModulePath')
    if (-not $current) { return }

    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.AddRange([string[]]@($current -split [regex]::Escape($sep)))
    for ($i = 0; $i -lt $parts.Count; $i++) {
        if ([string]::Equals($parts[$i].TrimEnd([char]'\', [char]'/'), $bundle, [System.StringComparison]::OrdinalIgnoreCase)) {
            $parts.RemoveAt($i)
            break
        }
    }
    $restored = $parts -join $sep
    # An empty result means PSModulePath was unset before: unset it again rather than leave ''.
    [Environment]::SetEnvironmentVariable('PSModulePath', $(if ($restored) { $restored } else { $null }))
}
