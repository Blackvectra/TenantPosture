#Requires -Version 7.0
#
# Get-NRGModuleBundle.ps1
# Dependencies: Get-NRGExoModuleFloor (Lib/Get-NRGModuleInstallScope.ps1). Reads
#               Config/module-bundle.json and the bundle folder. No tenant calls,
#               no installs, and nothing is ever deleted.
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
#
# Purpose: The runtime half of the module bundle, the equivalent of a Python
#   virtual environment for this tool. Install-NRGPrerequisites.ps1 -Local saves
#   exactly one pinned version of every module the tool needs into a folder
#   inside the tool (.modules/). The entry points then put that folder FIRST on
#   PSModulePath for their own process and import from it, so a second copy of
#   Microsoft.Graph.Authentication or ExchangeOnlineManagement elsewhere on the
#   machine, or a OneDrive online-only placeholder in the user module folder,
#   cannot be the one that loads.
#
# WHY A PREPEND ALONE IS NOT ENOUGH (measured on PowerShell 7.5.4, pinned by
#   NRG.ModuleBundle.Tests.ps1 so a change in PowerShell fails the build):
#     - Import-Module by name, with or without a version range, and cmdlet
#       auto-loading all take the FIRST PSModulePath entry that holds the module,
#       even when a copy further down has a higher version. The prepend wins.
#     - But `Get-Module -ListAvailable | Sort-Object Version -Descending |
#       Select-Object -First 1`, which Connect-NRGServices and the entry point's
#       preflight both used, picks the HIGHEST version across every path, and
#       `Import-Module <that path> -Force` then loads the outsider. A decoy with a
#       higher version defeated the bundle. Get-NRGEffectiveModule is the one
#       selector that prefers the bundle, and every such call site uses it.
#
# WHAT THE BUNDLE CANNOT DO: replace a module already loaded in the current
#   PowerShell window. A loaded assembly stays loaded. Enable-NRGModuleBundle
#   reports those modules (LoadedElsewhere) so the operator is told to open a new
#   window instead of discovering it as a hang at the first collector.
#
# PSModulePath is changed for THIS PROCESS ONLY ($env:PSModulePath, never the
#   User or Machine scope) and Disable-NRGModuleBundle restores it, so running
#   an assessment from an interactive window does not leave the window altered.
#
# Not hermetic on purpose: other modules the session needs (Pester, Pode for the
#   -Web GUI, PSResourceGet itself, the engine's own modules) live elsewhere on
#   PSModulePath and must stay visible. The bundle is put first, not alone.
#
# The bundle is trusted as code, like the tool itself. It is only as safe as the
#   folder's write permissions: whoever can write there can plant a module that
#   loads with the operator's credentials, exactly as for a user module folder.
#
# Testability: -ToolRoot / -Path / -PowerShellVersion / -PSHomePath /
#   -FileAttributeProvider let a test drive every branch against a temp folder
#   with stub modules. The real environment is read when they are omitted.
#
# Consumes: nothing.  Sets: nothing.  Graph scopes / cmdlets: none.

# Constants are functions, not $script: variables. This file is dot-sourced by
# the module loader, by the entry points before the module exists, and by tests;
# under StrictMode an unset script-scope variable THROWS, and which scope a
# dot-sourced file's variables land in differs between those callers.

# The environment variable (process scope) that relocates the bundle. Needed when
# the tool itself sits inside a OneDrive-synced folder: a bundle there would hold
# the same online-only placeholders as the user module folder.
function Get-NRGModuleBundleEnvVarName { [CmdletBinding()] [OutputType([string])] param() 'NRG_MODULE_BUNDLE' }

# The file inside a bundle that records what was built. It doubles as the marker
# that says the folder was created by this tool.
function Get-NRGModuleBundleLockName { [CmdletBinding()] [OutputType([string])] param() 'nrg-module-bundle.json' }

# FILE_ATTRIBUTE_RECALL_ON_OPEN (0x40000) | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
# (0x400000): set on a OneDrive Files On-Demand placeholder whose content is not
# on this machine. Reading the attribute does not hydrate the file.
function Get-NRGCloudPlaceholderMask { [CmdletBinding()] [OutputType([int])] param() 0x40000 -bor 0x400000 }

# A path with no trailing separator, so two spellings of one folder compare equal.
# A filesystem root keeps its separator ('C:\', '/').
function ConvertTo-NRGBundleFullPath {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path)
    $full = [System.IO.Path]::GetFullPath($Path)
    $root = [System.IO.Path]::GetPathRoot($full)
    if ($full.Length -gt $root.Length) { $full = $full.TrimEnd([char]'\', [char]'/') }
    return $full
}

# Windows paths compare case-insensitively, Linux and macOS paths do not.
function Get-NRGBundlePathComparison {
    [CmdletBinding()]
    [OutputType([System.StringComparison])]
    param()
    if ($IsWindows) { return [System.StringComparison]::OrdinalIgnoreCase }
    return [System.StringComparison]::Ordinal
}

function Test-NRGSamePath {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $Left,
        [AllowNull()] [AllowEmptyString()] [string] $Right
    )
    if ([string]::IsNullOrWhiteSpace($Left) -or [string]::IsNullOrWhiteSpace($Right)) { return $false }
    try {
        return [string]::Equals((ConvertTo-NRGBundleFullPath $Left), (ConvertTo-NRGBundleFullPath $Right), (Get-NRGBundlePathComparison))
    } catch { return $false }
}

# True when Path is Root or sits beneath it. The separator boundary matters:
# C:\tools\.modules-old must not count as under C:\tools\.modules.
function Test-NRGPathUnder {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $Path,
        [AllowNull()] [AllowEmptyString()] [string] $Root
    )
    if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Root)) { return $false }
    try {
        $p = ConvertTo-NRGBundleFullPath $Path
        $r = ConvertTo-NRGBundleFullPath $Root
    } catch { return $false }
    $cmp = Get-NRGBundlePathComparison
    if ([string]::Equals($p, $r, $cmp)) { return $true }
    $prefix = $r.TrimEnd([char]'\', [char]'/') + [System.IO.Path]::DirectorySeparatorChar
    return $p.StartsWith($prefix, $cmp)
}

# Where the bundle lives. An explicit -Path wins, then NRG_MODULE_BUNDLE, then
# <tool root>\.modules. Returns Path, Source (Parameter / Environment / Default)
# and Problem. A value that is not an absolute path, or that carries a '..'
# segment, is a Problem and yields no Path: guessing a different folder than the
# operator named would be worse than naming the mistake.
function Get-NRGModuleBundlePath {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $Path,
        [AllowNull()] [AllowEmptyString()] [string] $ToolRoot
    )

    Set-StrictMode -Version Latest

    $source = 'Default'
    $value  = $null
    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $source = 'Parameter'; $value = $Path
    } else {
        $fromEnv = [Environment]::GetEnvironmentVariable((Get-NRGModuleBundleEnvVarName))
        if (-not [string]::IsNullOrWhiteSpace($fromEnv)) { $source = 'Environment'; $value = $fromEnv }
    }

    if ($source -eq 'Default') {
        $root = if ([string]::IsNullOrWhiteSpace($ToolRoot)) { Split-Path -Parent $PSScriptRoot } else { $ToolRoot }
        return [ordered]@{
            Path    = (ConvertTo-NRGBundleFullPath (Join-Path $root '.modules'))
            Source  = $source
            Problem = ''
        }
    }

    $label = if ($source -eq 'Environment') { "$((Get-NRGModuleBundleEnvVarName))" } else { '-BundlePath' }
    if ($value -match '(^|[\\/])\.\.([\\/]|$)') {
        return [ordered]@{ Path = $null; Source = $source; Problem = "$label '$value' contains a '..' segment; give the absolute path." }
    }
    if (-not [System.IO.Path]::IsPathRooted($value)) {
        return [ordered]@{ Path = $null; Source = $source; Problem = "$label '$value' is not an absolute path." }
    }
    return [ordered]@{ Path = (ConvertTo-NRGBundleFullPath $value); Source = $source; Problem = '' }
}

# What the bundle must hold for the PowerShell in use, read from
# Config/module-bundle.json. Exchange's version is NOT in that file:
# Get-NRGExoModuleFloor decides it, so there is one rule, not two.
function Get-NRGModuleBundlePolicy {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $ToolRoot,
        [version] $PowerShellVersion = $PSVersionTable.PSVersion,
        [AllowNull()] [AllowEmptyString()] [string] $PSHomePath = $PSHOME,
        # Make the SharePoint Management Shell a REQUIRED member (the installer
        # passes it with -IncludeSharePointShell). Without it the module is
        # optional: validated when present, never demanded.
        [switch] $IncludeSharePointShell
    )

    Set-StrictMode -Version Latest

    $root = if ([string]::IsNullOrWhiteSpace($ToolRoot)) { Split-Path -Parent $PSScriptRoot } else { $ToolRoot }
    $file = Join-Path $root 'Config' 'module-bundle.json'
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Module bundle policy not found: $file" }
    $cfg = Get-Content -LiteralPath $file -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop

    $field = {
        param($Obj, [string] $Key)
        if ($null -ne $Obj -and $Obj.PSObject.Properties[$Key]) { return $Obj.$Key }
        return $null
    }

    $floor = Get-NRGExoModuleFloor -PSVersion $PowerShellVersion -PSHomePath $PSHomePath
    $modules = [System.Collections.Generic.List[object]]::new()

    # An exact pin is also expressed as a NuGet range so Save-PSResource cannot
    # read it as "this version or later".
    $exact = {
        param([string] $Name, [string] $Group, [string] $Version, [bool] $Required, [bool] $Carrier)
        [ordered]@{
            Name = $Name; Group = $Group; MsalCarrier = $Carrier; Required = $Required
            Version = $Version; Min = $Version; Max = $Version
            SaveRange = "[$Version,$Version]"
        }
    }

    $graph = & $field $cfg 'Graph'
    $graphVersion = [string](& $field $graph 'Version')
    $graphNames   = @(& $field $graph 'Modules')
    if (-not $graphVersion -or $graphNames.Count -eq 0) { throw "Config/module-bundle.json: Graph needs a Version and a Modules list." }
    foreach ($n in $graphNames) { $modules.Add((& $exact ([string]$n) 'Graph' $graphVersion $true ([string]$n -eq 'Microsoft.Graph.Authentication'))) }

    $exo = & $field $cfg 'ExchangeOnline'
    $exoName = [string](& $field $exo 'Name')
    if (-not $exoName) { throw "Config/module-bundle.json: ExchangeOnline needs a Name." }
    $exoMax = if ($floor.Max) { [string]$floor.Max } else { $null }
    $modules.Add([ordered]@{
        Name = $exoName; Group = 'Exchange'; MsalCarrier = $true; Required = $true
        Version = $null; Min = [string]$floor.Min; Max = $exoMax
        SaveRange = if ($exoMax) { "[$($floor.Min),$exoMax]" } else { "[$($floor.Min),)" }
    })

    $teams = & $field $cfg 'Teams'
    $teamsName = [string](& $field $teams 'Name'); $teamsVer = [string](& $field $teams 'Version')
    if (-not $teamsName -or -not $teamsVer) { throw "Config/module-bundle.json: Teams needs a Name and a Version." }
    $modules.Add((& $exact $teamsName 'Teams' $teamsVer $true $false))

    $spo = & $field $cfg 'SharePointShell'
    $spoName = [string](& $field $spo 'Name'); $spoVer = [string](& $field $spo 'Version')
    if (-not $spoName -or -not $spoVer) { throw "Config/module-bundle.json: SharePointShell needs a Name and a Version." }
    $modules.Add((& $exact $spoName 'SharePointShell' $spoVer ([bool]$IncludeSharePointShell) $false))

    [ordered]@{
        PowerShellVersion = $PowerShellVersion.ToString()
        Floor             = $floor
        Supported         = [bool]$floor.Supported
        Modules           = @($modules)
    }
}

# Counts the files under Root whose content is not on this machine (a OneDrive
# online-only placeholder). Windows only; elsewhere there is nothing to read and
# the answer is 0. -Provider replaces the attribute read so a test can mark files.
function Get-NRGCloudPlaceholderCount {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [string] $Root,
        [AllowNull()] [scriptblock] $Provider
    )

    Set-StrictMode -Version Latest

    if (-not $Provider -and -not $IsWindows) { return 0 }
    $count = 0
    try {
        foreach ($f in [System.IO.Directory]::EnumerateFiles($Root, '*', [System.IO.SearchOption]::AllDirectories)) {
            $attr = if ($Provider) { [int](& $Provider $f) } else { [int][System.IO.File]::GetAttributes($f) }
            if (($attr -band (Get-NRGCloudPlaceholderMask)) -ne 0) { $count++ }
        }
    } catch {
        Write-Verbose "Get-NRGCloudPlaceholderCount: stopped reading $Root. $($_.Exception.Message)"
    }
    return $count
}

# Inspect a bundle folder and say whether it is safe to put first on PSModulePath.
#   Absent  - no folder, or an empty one: nothing to use, nothing wrong.
#   Valid   - every required module is present at exactly one version, and it is
#             the pinned version (or, for Exchange, one the running PowerShell
#             supports).
#   Invalid - something is missing, doubled or off-pin, or files are OneDrive
#             placeholders. An Invalid bundle is NOT used: putting a wrong
#             Exchange build first would be worse than the machine's own copy.
# A bundle that merely sits inside OneDrive is a warning, not a failure: a
# folder that is fully on this machine works, and failing it would reject a
# working setup. Placeholders are the failure.
function Test-NRGModuleBundle {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $Path,
        [AllowNull()] [AllowEmptyString()] [string] $ToolRoot,
        [version] $PowerShellVersion = $PSVersionTable.PSVersion,
        [AllowNull()] [AllowEmptyString()] [string] $PSHomePath = $PSHOME,
        [AllowNull()] [scriptblock] $FileAttributeProvider
    )

    Set-StrictMode -Version Latest

    $resolved = Get-NRGModuleBundlePath -Path $Path -ToolRoot $ToolRoot
    $result = [ordered]@{
        Status            = 'Absent'
        Path              = $resolved.Path
        PathSource        = $resolved.Source
        Modules           = @()
        Extra             = @()
        Issues            = @()
        Warnings          = @()
        OneDrivePath      = $false
        CloudPlaceholders = 0
        Lock              = $null
        Message           = ''
    }

    if ($resolved.Problem) {
        $result.Status  = 'Invalid'
        $result.Issues  = @($resolved.Problem)
        $result.Message = $resolved.Problem
        return $result
    }
    if (-not (Test-Path -LiteralPath $resolved.Path -PathType Container)) {
        $result.Message = "No module bundle at $($resolved.Path)."
        return $result
    }
    $dirs = @(Get-ChildItem -LiteralPath $resolved.Path -Directory -Force -ErrorAction SilentlyContinue)
    if ($dirs.Count -eq 0) {
        $result.Message = "The module bundle folder $($resolved.Path) is empty."
        return $result
    }

    $policy = Get-NRGModuleBundlePolicy -ToolRoot $ToolRoot -PowerShellVersion $PowerShellVersion -PSHomePath $PSHomePath
    $issues   = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    if (-not $policy.Supported) { $issues.Add([string]$policy.Floor.Reason) }

    $byName = @{}
    foreach ($d in $dirs) { $byName[$d.Name.ToLowerInvariant()] = $d }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $policy.Modules) {
        $row = [ordered]@{
            Name = $m.Name; Group = $m.Group; Required = [bool]$m.Required
            Present = $false; Versions = @(); Version = $null
            Expected = if ($m.Version) { [string]$m.Version } elseif ($m.Max) { "$($m.Min) to $($m.Max)" } else { "$($m.Min) or later" }
            Base = $null; Ok = $false; Issues = @()
        }
        $rowIssues = [System.Collections.Generic.List[string]]::new()
        $dir = $byName[$m.Name.ToLowerInvariant()]
        if (-not $dir) {
            if ($m.Required) { $rowIssues.Add("$($m.Name) is missing from the bundle (expected $($row.Expected)).") }
            $row.Ok = (-not $m.Required)
            $row.Issues = @($rowIssues)
            foreach ($i in $rowIssues) { $issues.Add($i) }
            $rows.Add($row)
            continue
        }

        $row.Present = $true
        # Save-PSResource lays a module out as <Name>\<Version>\<Name>.psd1.
        $versions = [System.Collections.Generic.List[object]]::new()
        foreach ($vd in @(Get-ChildItem -LiteralPath $dir.FullName -Directory -Force -ErrorAction SilentlyContinue)) {
            $v = $null
            if ([version]::TryParse(($vd.Name -replace '-.*$', ''), [ref]$v)) { $versions.Add([pscustomobject]@{ Version = $v; Dir = $vd.FullName }) }
        }
        $row.Versions = @($versions | Sort-Object Version -Descending | ForEach-Object { $_.Version.ToString() })

        if ($versions.Count -eq 0) {
            $rowIssues.Add("$($m.Name) has no version folder in the bundle.")
        } elseif ($versions.Count -gt 1) {
            $rowIssues.Add("$($m.Name) has $($versions.Count) versions in the bundle ($($row.Versions -join ', ')); keep one.")
        } else {
            $got = $versions[0]
            $row.Version = $got.Version.ToString()
            $row.Base    = $got.Dir
            $manifest = Join-Path $got.Dir "$($m.Name).psd1"
            if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
                $rowIssues.Add("$($m.Name) $($row.Version) has no $($m.Name).psd1 in the bundle.")
            } else {
                # The folder name is what PSResourceGet wrote; the manifest is what
                # PowerShell reads. They disagree only if the folder was assembled by hand.
                $declared = $null
                try {
                    $text = Get-Content -LiteralPath $manifest -Raw -ErrorAction Stop
                    if ($text -match "(?im)^\s*ModuleVersion\s*=\s*['""]([0-9][0-9.]*)['""]") { $declared = $Matches[1] }
                } catch {
                    $rowIssues.Add("$($m.Name) $($row.Version): the manifest could not be read ($($_.Exception.Message)).")
                }
                if ($declared) {
                    $dv = $null
                    if ([version]::TryParse($declared, [ref]$dv) -and $dv -ne $got.Version) {
                        $rowIssues.Add("$($m.Name): the folder says $($row.Version) but the manifest says $declared.")
                    }
                }
            }
            if ($m.Version) {
                if ($got.Version -ne [version]$m.Version) {
                    $rowIssues.Add("$($m.Name) $($row.Version) is in the bundle; the pin is $($m.Version).")
                }
            } else {
                if ($got.Version -lt [version]$m.Min -or ($m.Max -and $got.Version -gt [version]$m.Max)) {
                    $rowIssues.Add("$($m.Name) $($row.Version) is in the bundle; PowerShell $($policy.PowerShellVersion) supports $($row.Expected).")
                }
            }
        }
        $row.Ok = ($rowIssues.Count -eq 0)
        $row.Issues = @($rowIssues)
        foreach ($i in $rowIssues) { $issues.Add($i) }
        $rows.Add($row)
    }

    $known = @($policy.Modules | ForEach-Object { $_.Name.ToLowerInvariant() })
    $result.Extra = @($dirs | Where-Object { $known -notcontains $_.Name.ToLowerInvariant() } | ForEach-Object { $_.Name })

    $result.OneDrivePath = [bool]($resolved.Path -match '(?i)\bOneDrive\b')
    if ($result.OneDrivePath) {
        $warnings.Add("The bundle sits inside a OneDrive-synced folder ($($resolved.Path)). It works while its files are kept on this machine; if OneDrive turns any into online-only placeholders, Windows cannot read them. Relocate it with Install-NRGPrerequisites.ps1 -Local -BundlePath <folder outside OneDrive> and set $((Get-NRGModuleBundleEnvVarName)).")
    }
    $result.CloudPlaceholders = Get-NRGCloudPlaceholderCount -Root $resolved.Path -Provider $FileAttributeProvider
    if ($result.CloudPlaceholders -gt 0) {
        $issues.Add("$($result.CloudPlaceholders) file(s) in the bundle are OneDrive online-only placeholders; Windows cannot read them while OneDrive is not running. Move the bundle outside OneDrive (Install-NRGPrerequisites.ps1 -Local -BundlePath <folder>) or mark it Always keep on this device.")
    }

    $lockFile = Join-Path $resolved.Path (Get-NRGModuleBundleLockName)
    if (Test-Path -LiteralPath $lockFile -PathType Leaf) {
        try {
            $lock = Get-Content -LiteralPath $lockFile -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
            $result.Lock = $lock
            $builtFor = if ($lock.PSObject.Properties['PowerShell']) { [string]$lock.PowerShell } else { '' }
            $bv = $null
            if ($builtFor -and [version]::TryParse($builtFor, [ref]$bv) -and
                ($bv.Major -ne $PowerShellVersion.Major -or $bv.Minor -ne $PowerShellVersion.Minor)) {
                $warnings.Add("The bundle was built under PowerShell $builtFor and this is $PowerShellVersion. It is used only because every module in it is still in the supported range.")
            }
        } catch { $warnings.Add("The bundle's $((Get-NRGModuleBundleLockName)) could not be read: $($_.Exception.Message)") }
    }

    $result.Modules  = @($rows)
    $result.Issues   = @($issues)
    $result.Warnings = @($warnings)
    if ($issues.Count -eq 0) {
        $result.Status  = 'Valid'
        $result.Message = "Module bundle at $($resolved.Path) is complete."
    } else {
        $result.Status  = 'Invalid'
        $result.Message = "Module bundle at $($resolved.Path) is not usable: $($issues[0])"
    }
    return $result
}

# The bundle's folder when it is ACTIVE, that is first on this process's
# PSModulePath and present on disk; otherwise $null. Stateless on purpose: it is
# derived from PSModulePath itself, so a caller that never ran Enable (a script
# that imported the module by hand) correctly sees "no bundle".
function Get-NRGActiveModuleBundlePath {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyString()] [string] $ToolRoot)

    Set-StrictMode -Version Latest

    $resolved = Get-NRGModuleBundlePath -ToolRoot $ToolRoot
    if (-not $resolved.Path) { return $null }
    if (-not (Test-Path -LiteralPath $resolved.Path -PathType Container)) { return $null }
    $first = @($env:PSModulePath -split [regex]::Escape([System.IO.Path]::PathSeparator) | Where-Object { $_ }) | Select-Object -First 1
    if (Test-NRGSamePath $first $resolved.Path) { return [string]$resolved.Path }
    return $null
}

# The copy of a module this run will really use. With an active bundle that holds
# the module, that is the bundle's copy, whatever else is installed at a higher
# version. Otherwise it is the newest installed, which is what the call sites did
# before the bundle existed. Returns the same PSModuleInfo `Get-Module
# -ListAvailable` does ($null when nothing is installed).
function Get-NRGEffectiveModule {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [AllowNull()] [AllowEmptyString()] [string] $ToolRoot
    )

    Set-StrictMode -Version Latest

    $all = @(Get-Module -ListAvailable -Name $Name -ErrorAction SilentlyContinue)
    $bundle = Get-NRGActiveModuleBundlePath -ToolRoot $ToolRoot
    if ($bundle) {
        $inside = @($all | Where-Object { Test-NRGPathUnder -Path ([string]$_.ModuleBase) -Root $bundle })
        if ($inside.Count -gt 0) { return @($inside | Sort-Object Version -Descending | Select-Object -First 1)[0] }
    }
    if ($all.Count -eq 0) { return $null }
    return @($all | Sort-Object Version -Descending | Select-Object -First 1)[0]
}

# Make the bundle the first place this process looks for modules, then load the
# two MSAL carriers from it by explicit path. Never throws and never leaves the
# process worse off: an absent or invalid bundle changes nothing and says why.
#
# Returns Status ('Active' / 'Absent' / 'Invalid'), Active, Changed (this call
# altered PSModulePath, so the caller must hand the state to Disable-NRGModule-
# Bundle), Path, the validation Issues and Warnings, Imported / ImportFailures,
# and LoadedElsewhere: modules this window already loaded from OUTSIDE the
# bundle. Those win for the life of the window; the entry point tells the
# operator to open a new one.
#
# Only the two carriers are imported here. MicrosoftTeams must not be: it loads
# its own Microsoft.Identity.Client and, loaded before Exchange connects, makes
# Exchange and Purview fail with 0x80131040 (see Connect-NRGServices). It, the
# Graph submodules and the SharePoint shell resolve by name from the bundle,
# because the bundle is first.
function Enable-NRGModuleBundle {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $Path,
        [AllowNull()] [AllowEmptyString()] [string] $ToolRoot,
        [string[]] $Import = @('Microsoft.Graph.Authentication', 'ExchangeOnlineManagement'),
        [switch] $SkipImport,
        [version] $PowerShellVersion = $PSVersionTable.PSVersion,
        [AllowNull()] [AllowEmptyString()] [string] $PSHomePath = $PSHOME,
        [AllowNull()] [scriptblock] $FileAttributeProvider
    )

    Set-StrictMode -Version Latest

    $state = [ordered]@{
        Status          = 'Absent'
        Active          = $false
        Changed         = $false
        Path            = $null
        PathSource      = 'Default'
        Modules         = @()
        Issues          = @()
        Warnings        = @()
        Imported        = @()
        ImportFailures  = @()
        LoadedElsewhere = @()
        Original        = $env:PSModulePath
        Activated       = $env:PSModulePath
        Message         = ''
    }

    try {
        $check = Test-NRGModuleBundle -Path $Path -ToolRoot $ToolRoot -PowerShellVersion $PowerShellVersion `
            -PSHomePath $PSHomePath -FileAttributeProvider $FileAttributeProvider
    } catch {
        $state.Status  = 'Invalid'
        $state.Issues  = @("The module bundle could not be checked: $($_.Exception.Message)")
        $state.Message = $state.Issues[0]
        return $state
    }
    $state.Path       = $check.Path
    $state.PathSource = $check.PathSource
    $state.Modules    = @($check.Modules | Where-Object { $_.Present })
    $state.Issues     = @($check.Issues)
    $state.Warnings   = @($check.Warnings)
    $state.Message    = $check.Message
    if ($check.Status -ne 'Valid') {
        $state.Status = $check.Status
        return $state
    }

    $sep     = [System.IO.Path]::PathSeparator
    $entries = @($env:PSModulePath -split [regex]::Escape($sep) | Where-Object { $_ })
    $first   = $entries | Select-Object -First 1
    if (-not (Test-NRGSamePath $first $check.Path)) {
        $rest = @($entries | Where-Object { -not (Test-NRGSamePath $_ $check.Path) })
        $env:PSModulePath = (@([string]$check.Path) + $rest) -join $sep
        $state.Changed    = $true
        $state.Activated  = $env:PSModulePath
    }
    $state.Active = $true
    $state.Status = 'Active'

    $elsewhere = [System.Collections.Generic.List[object]]::new()
    foreach ($row in $state.Modules) {
        foreach ($loaded in @(Get-Module -Name $row.Name -ErrorAction SilentlyContinue)) {
            if (-not (Test-NRGPathUnder -Path ([string]$loaded.ModuleBase) -Root $check.Path)) {
                $elsewhere.Add([ordered]@{ Name = $row.Name; Version = $loaded.Version.ToString(); Path = [string]$loaded.ModuleBase })
            }
        }
    }
    $state.LoadedElsewhere = @($elsewhere)

    if (-not $SkipImport) {
        $imported = [System.Collections.Generic.List[string]]::new()
        $failures = [System.Collections.Generic.List[object]]::new()
        foreach ($name in $Import) {
            $row = @($state.Modules | Where-Object { $_.Name -eq $name }) | Select-Object -First 1
            if (-not $row -or -not $row.Base) { continue }
            # A copy already loaded from elsewhere stays: loading a second one beside
            # it would add a second Microsoft.Identity.Client to the problem.
            if (@($elsewhere | Where-Object { $_.Name -eq $name }).Count -gt 0) { continue }
            try {
                Import-Module -Name (Join-Path $row.Base "$name.psd1") -Global -ErrorAction Stop -WarningAction SilentlyContinue 3>$null | Out-Null
                $imported.Add("$name $($row.Version)")
            } catch {
                $failures.Add([ordered]@{ Name = $name; Reason = $_.Exception.Message })
            }
        }
        $state.Imported       = @($imported)
        $state.ImportFailures = @($failures)
    }
    return $state
}

# Undo Enable-NRGModuleBundle's change to PSModulePath. A no-op when Enable did
# not change it (an absent bundle, or a nested run that inherited the bundle from
# its caller, which must not strip it out from under that caller). If something
# else rewrote PSModulePath in the meantime, only the bundle's entry is removed:
# restoring the saved string would discard that change.
function Disable-NRGModuleBundle {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] $State)

    Set-StrictMode -Version Latest

    if ($null -eq $State) { return $false }
    $changed = $false
    if ($State -is [System.Collections.IDictionary] -and $State.Contains('Changed')) { $changed = [bool]$State['Changed'] }
    if (-not $changed) { return $false }

    $current = [string]$env:PSModulePath
    if ($current -ceq [string]$State['Activated']) {
        $env:PSModulePath = [string]$State['Original']
        return $true
    }
    $sep   = [System.IO.Path]::PathSeparator
    $parts = @($current -split [regex]::Escape($sep) | Where-Object { $_ })
    $dropped = $false
    $kept = foreach ($p in $parts) {
        if (-not $dropped -and (Test-NRGSamePath $p ([string]$State['Path']))) { $dropped = $true; continue }
        $p
    }
    $env:PSModulePath = (@($kept) -join $sep)
    return $true
}

# One place for the console wording, so the single-tenant entry point and the
# batch runner say the same thing. Absent is quiet on purpose: the folder is
# optional, and nagging every operator who never built one would train them to
# ignore the lines that matter.
function Write-NRGModuleBundleStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $State)

    switch ($State.Status) {
        'Active' {
            $names = @($State.Modules | ForEach-Object { "$($_.Name) $($_.Version)" })
            $graph = @($State.Modules | Where-Object { $_.Group -eq 'Graph' })
            $others = @($State.Modules | Where-Object { $_.Group -ne 'Graph' } | ForEach-Object { "$($_.Name) $($_.Version)" })
            $summary = @()
            if ($graph.Count -gt 0) { $summary += "Microsoft.Graph.* $($graph[0].Version) ($($graph.Count) modules)" }
            $summary += $others
            if ($summary.Count -eq 0) { $summary = $names }
            Write-Host "  [+] Module bundle active: $($State.Path)" -ForegroundColor Green
            Write-Host "      $($summary -join '; ')" -ForegroundColor DarkGray
            Write-Host "      First on PSModulePath for this run only; the original is restored on exit." -ForegroundColor DarkGray
        }
        'Invalid' {
            Write-Host "  [!] Module bundle at $($State.Path) is NOT usable and was not used; falling back to the installed modules." -ForegroundColor Yellow
            foreach ($i in @($State.Issues)) { Write-Host "      - $i" -ForegroundColor DarkYellow }
            Write-Host "      Rebuild it: .\Install-NRGPrerequisites.ps1 -Local -Force" -ForegroundColor DarkYellow
        }
        default {
            if ($State.PathSource -eq 'Environment') {
                Write-Host "  [!] NRG_MODULE_BUNDLE points to $($State.Path), but there is no module bundle there; using the installed modules." -ForegroundColor Yellow
            } else {
                Write-Host "  [i] No module bundle ($($State.Path)); using the installed modules. For an isolated copy: .\Install-NRGPrerequisites.ps1 -Local" -ForegroundColor DarkGray
            }
        }
    }
    foreach ($w in @($State.Warnings)) { Write-Host "      $w" -ForegroundColor Yellow }
    foreach ($f in @($State.ImportFailures)) { Write-Host "  [!] Could not load $($f.Name) from the bundle: $($f.Reason)" -ForegroundColor Red }
    if (@($State.LoadedElsewhere).Count -gt 0) {
        foreach ($l in $State.LoadedElsewhere) {
            Write-Host "  [!] $($l.Name) $($l.Version) is already loaded in this PowerShell window from $($l.Path), and a loaded module cannot be replaced." -ForegroundColor Yellow
        }
        Write-Host "      Close this window, open a NEW PowerShell 7 window, and run the assessment first thing in it." -ForegroundColor Yellow
    }
}
