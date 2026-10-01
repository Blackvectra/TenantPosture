#Requires -Version 7.0
#
# New-NRGModuleBundle.ps1
# Dependencies: Save-PSResource (Microsoft.PowerShell.PSResourceGet, shipped with
#               PowerShell 7.4 and later), Lib/Get-NRGModuleBundle.ps1 and
#               Get-NRGExoModuleFloor (Lib/Get-NRGModuleInstallScope.ps1).
#               No tenant calls of any kind.
#
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: build the tool's module bundle (see Get-NRGModuleBundle.ps1): save exactly one
#   pinned version of each Microsoft module the tool uses into .modules/, inside the tool,
#   instead of installing anything on the machine. Run by
#   Install-NRGPrerequisites.ps1 -Local; never from the assessment path.
#
# WHAT IT WRITES, AND THE ONE THING IT CAN REMOVE:
#   It writes only inside the bundle folder. It removes nothing unless -Force is given, and
#   then only the bundle's own module folders (names from Config/module-bundle.json) and its
#   lock file, inside a folder that already carries that lock file. Repair-NRGModuleHealth
#   remains the only operation that removes modules from the OPERATOR's module folders; this
#   one cannot reach them. A non-empty folder without the lock file is refused outright, so a
#   mistyped -Path can never point it at a folder that is not a bundle.
#
# THE LOCK FILE IS WRITTEN LAST. Until it exists the folder is not a valid bundle
# (Test-NRGModuleBundle: no-lock), so a build interrupted by a network failure or a closed
# window never leaves something that gets activated half-built.
#
# WHY Save-PSResource AND NOT Save-Module: ExchangeOnlineManagement's gallery metadata lists
# PackageManagement and PowerShellGet as dependencies. Save-Module follows them and put
# PackageManagement 1.4.8.1 and PowerShellGet 2.2.5 into the folder (observed against 3.10.1);
# first on PSModulePath they would shadow the machine's own package tooling. Save-PSResource
# -SkipDependencyCheck saves only what is named. Every module in the spec is named, and the
# Graph submodules depend on nothing but Microsoft.Graph.Authentication at the same version.
#
# Consumes: nothing.  Sets: nothing.  Graph scopes / cmdlets: none.

# Present while a build is under way and removed when the lock is written. It is how a build
# that was interrupted (network down, window closed) is recognized as ours on the next run, so
# the run can resume instead of refusing a non-empty folder that has no lock file yet.
$script:NRGModuleBundleBuildMarker = '.nrg-bundle-incomplete'

# The modules that are complete on disk: exactly one version folder whose manifest says that
# same version. Anything else (a half-extracted module, two versions) is not counted as present.
function Get-NRGBundleModulesOnDisk {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $Path
    )

    Set-StrictMode -Version Latest

    $found = @{}
    foreach ($d in @(Get-ChildItem -LiteralPath $Path -Directory -Force -ErrorAction SilentlyContinue)) {
        if ($d.Name.StartsWith('.')) { continue }
        $versions = @(Get-ChildItem -LiteralPath $d.FullName -Directory -Force -ErrorAction SilentlyContinue)
        if ($versions.Count -ne 1) { continue }
        $psd1 = Join-Path $versions[0].FullName "$($d.Name).psd1"
        if (-not (Test-Path -LiteralPath $psd1 -PathType Leaf)) { continue }
        $v = Get-NRGModuleManifestVersion -Path $psd1
        if ($null -ne $v -and $v.ToString() -eq $versions[0].Name) { $found[$d.Name] = $versions[0].Name }
    }
    return $found
}

# What to ask the gallery for, per module. Exchange is the one whose range comes from
# Get-NRGExoModuleFloor: the spec's version is a preference, used only when it is inside that
# range; otherwise the request is the range itself and the gallery returns its newest member.
function Resolve-NRGModuleBundlePlan {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [object[]] $Spec,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $ExoFloor,
        [switch] $IncludeSharePointShell
    )

    Set-StrictMode -Version Latest

    $plan = [System.Collections.Generic.List[object]]::new()
    foreach ($m in $Spec) {
        $name = [string]$m['Name']
        if ([bool]$m['Optional'] -and -not ($IncludeSharePointShell -and [string]$m['Family'] -eq 'SharePoint')) { continue }

        $request = [string]$m['Version']
        $note = ''
        if ([string]$m['VersionPolicy'] -eq 'ExchangeFloor') {
            if (-not [bool]$ExoFloor['Supported']) {
                throw "$name cannot be bundled for PowerShell $($PSVersionTable.PSVersion): $($ExoFloor['Reason'])"
            }
            $min = [version][string]$ExoFloor['Min']
            $max = if ($ExoFloor['Max']) { [version][string]$ExoFloor['Max'] } else { $null }
            $pref = $null
            $inRange = [version]::TryParse($request, [ref]$pref) -and $pref -ge $min -and ($null -eq $max -or $pref -le $max)
            if ($inRange) {
                $note = "preferred version, inside the range this PowerShell allows"
            } else {
                $request = if ($max) { "[$min,$max]" } else { "[$min,)" }
                $note = "the preferred version is outside the range this PowerShell allows; the newest version in $request"
            }
        }
        if (-not $request) { throw "Config/module-bundle.json has no version for $name." }
        $plan.Add([ordered]@{
            Name     = $name
            Family   = [string]$m['Family']
            Request  = $request
            IsRange  = ($request -match '^[\[(]')
            Optional = [bool]$m['Optional']
            Note     = $note
        })
    }
    return @($plan)
}

# The real download. -SkipDependencyCheck is not optional (see the header). No
# -AuthenticodeCheck: it is Windows-only and a build that works on one platform and errors on
# another is worse than a bundle that was saved, then verified by Test-NRGModuleBundle.
function Invoke-NRGModuleBundleSave {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Request,
        [Parameter(Mandatory)] [string] $Path
    )

    Set-StrictMode -Version Latest

    if (-not (Get-Command Save-PSResource -ErrorAction SilentlyContinue)) {
        throw "Save-PSResource is not available. It ships with PowerShell 7.4 and later (Microsoft.PowerShell.PSResourceGet); install it with: Install-Module Microsoft.PowerShell.PSResourceGet -Scope CurrentUser"
    }
    Save-PSResource -Name $Name -Version $Request -Repository PSGallery -TrustRepository -Path $Path -SkipDependencyCheck -ErrorAction Stop
}

function New-NRGModuleBundle {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $ToolRoot,

        # Defaults to NRG_MODULE_BUNDLE, else <tool>\.modules.
        [Parameter()] [AllowNull()] [string] $Path,

        # Also save the SharePoint Online Management Shell (opt-in; see the spec).
        [switch] $IncludeSharePointShell,

        # Rebuild from scratch: remove the bundle's own module folders and lock first.
        [switch] $Force,

        # Test seams. SaveAction receives -Name -Request -Path; Spec and ExoFloor replace the
        # spec file and Get-NRGExoModuleFloor so a test needs neither the network nor a
        # particular PowerShell version.
        [Parameter()] [AllowNull()] [scriptblock] $SaveAction,
        [Parameter()] [AllowNull()] [object[]] $Spec,
        [Parameter()] [AllowNull()] [System.Collections.IDictionary] $ExoFloor
    )

    Set-StrictMode -Version Latest

    $bundle = if ($Path) { $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path).TrimEnd([char]'\', [char]'/') } else { Get-NRGModuleBundlePath -ToolRoot $ToolRoot }
    $lockName = $script:NRGModuleBundleLockName
    $lockPath = Join-Path $bundle $lockName
    $markerPath = Join-Path $bundle $script:NRGModuleBundleBuildMarker

    $result = [ordered]@{
        Path           = $bundle
        Planned        = @()
        Saved          = @()
        AlreadyPresent = @()
        Removed        = @()
        Failed         = @()
        Errors         = @()
        Warnings       = @()
        Valid          = $false
        Applied        = $false
    }
    $fail = {
        param([string] $Message)
        $result['Errors'] = @($result['Errors']) + $Message
        return $result
    }

    if (-not $PSBoundParameters.ContainsKey('Spec') -or $null -eq $Spec) { $Spec = Get-NRGModuleBundleSpec -ToolRoot $ToolRoot }
    if (-not $PSBoundParameters.ContainsKey('ExoFloor') -or $null -eq $ExoFloor) { $ExoFloor = Get-NRGExoModuleFloor }

    # ── The folder must be ours or empty. A mistyped -Path must not be able to aim this at
    # a folder that holds anything else.
    # Ours means: it has the lock file (a finished build) or the in-progress marker (an
    # interrupted one).
    $exists = Test-Path -LiteralPath $bundle -PathType Container
    $hasLock = $exists -and (Test-Path -LiteralPath $lockPath -PathType Leaf)
    $ours = $hasLock -or ($exists -and (Test-Path -LiteralPath $markerPath -PathType Leaf))
    if ($exists -and -not $ours) {
        $any = @(Get-ChildItem -LiteralPath $bundle -Force -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($any.Count -gt 0) {
            return (& $fail "$bundle already exists, is not empty and is not a module bundle (no $lockName). Nothing was changed. Choose an empty or new folder.")
        }
    }
    if (Test-Path -LiteralPath $bundle -PathType Leaf) {
        return (& $fail "$bundle is a file, not a folder.")
    }

    try {
        $plan = @(Resolve-NRGModuleBundlePlan -Spec $Spec -ExoFloor $ExoFloor -IncludeSharePointShell:$IncludeSharePointShell)
    } catch {
        return (& $fail $_.Exception.Message)
    }
    $result['Planned'] = @($plan | ForEach-Object { "$($_['Name']) $($_['Request'])" })

    $specByName = @{}
    foreach ($s in $Spec) { $specByName[[string]$s['Name']] = $s }

    # ── What is already there, so a re-run saves only what is missing.
    $present = @{}
    if ($ours) { $present = Get-NRGBundleModulesOnDisk -Path $bundle }
    $satisfied = {
        param($Item)
        if (-not $present.ContainsKey($Item['Name'])) { return $false }
        $have = $null
        if (-not [version]::TryParse($present[$Item['Name']], [ref]$have)) { return $false }
        if ($Item['IsRange']) {
            $lo = $null; $hi = $null
            $m = [regex]::Match([string]$Item['Request'], '^\[([^,]+),([^\]\)]*)[\]\)]$')
            if (-not $m.Success -or -not [version]::TryParse($m.Groups[1].Value, [ref]$lo)) { return $false }
            if ($have -lt $lo) { return $false }
            if ($m.Groups[2].Value -and [version]::TryParse($m.Groups[2].Value, [ref]$hi) -and $have -gt $hi) { return $false }
            return $true
        }
        return ($present[$Item['Name']] -eq [string]$Item['Request'])
    }

    $todo = [System.Collections.Generic.List[object]]::new()
    $already = [System.Collections.Generic.List[string]]::new()
    $replace = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $plan) {
        if (& $satisfied $item) { $already.Add("$($item['Name']) $($present[$item['Name']])"); continue }
        $todo.Add($item)
        if ($present.ContainsKey($item['Name'])) { $replace.Add("$($item['Name']) $($present[$item['Name']])") }
    }
    $result['AlreadyPresent'] = @($already)

    if ($replace.Count -gt 0 -and -not $Force) {
        return (& $fail ("The bundle at $bundle holds a different version of: $($replace -join ', '). Replacing it removes the bundle's old copy; re-run with -Force to rebuild it (nothing outside the bundle folder is touched)."))
    }

    # A module folder that exists but is not complete (an interrupted save inside it) is debris
    # this run would collide with. Clearing it is a removal, so it needs -Force like any other.
    $debris = @($todo | Where-Object { -not $present.ContainsKey($_['Name']) -and (Test-Path -LiteralPath (Join-Path $bundle $_['Name'])) } | ForEach-Object { $_['Name'] })
    if ($debris.Count -gt 0 -and -not $Force) {
        return (& $fail ("The bundle at $bundle has an incomplete folder for: $($debris -join ', ') (a save was interrupted inside it). Re-run with -Force to clear and rebuild it (nothing outside the bundle folder is touched)."))
    }

    # Even when everything wanted is present, a bundle that fails validation (extra module, a
    # leftover second version) is rebuilt only on request.
    if ($todo.Count -eq 0 -and -not $Force) {
        $final = Test-NRGModuleBundle -ToolRoot $ToolRoot -Path $bundle -Spec $Spec -ExoFloor $ExoFloor
        $result['Valid'] = [bool]$final['Valid']
        $result['Errors'] = @($final['Errors'])
        $result['Warnings'] = @($final['Warnings'])
        if (-not $final['Valid']) { $result['Errors'] = @($result['Errors']) + "The bundle has everything wanted but does not validate; re-run with -Force to rebuild it." }
        return $result
    }

    if (-not $PSCmdlet.ShouldProcess($bundle, "Build the module bundle ($($plan.Count) modules$(if ($Force -and $ours) { ', replacing the existing bundle' }))")) {
        return $result
    }

    # ── -Force: remove the bundle's own module folders, lock first so a bundle that is
    # only partly removed is invalid rather than activated.
    if ($Force -and $ours) {
        $names = @($specByName.Keys)
        try {
            if ($hasLock) { Remove-Item -LiteralPath $lockPath -Force -ErrorAction Stop }
            $bundleFull = (Resolve-Path -LiteralPath $bundle).ProviderPath.TrimEnd([char]'\', [char]'/') + [System.IO.Path]::DirectorySeparatorChar
            foreach ($n in $names) {
                $dir = Join-Path $bundle $n
                if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
                $dirItem = Get-Item -LiteralPath $dir -Force
                $resolved = (Resolve-Path -LiteralPath $dir).ProviderPath
                # Stay inside the bundle, and never follow a junction or symlink out of it.
                if (-not ($resolved + [System.IO.Path]::DirectorySeparatorChar).StartsWith($bundleFull, [System.StringComparison]::OrdinalIgnoreCase) -or
                    ($dirItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                    throw "$dir is not an ordinary folder inside the bundle; it was left alone and the rebuild stopped."
                }
                Remove-Item -LiteralPath $dir -Recurse -Force -ErrorAction Stop
                $result['Removed'] = @($result['Removed']) + $n
            }
        } catch {
            return (& $fail "Could not remove the old bundle: $($_.Exception.Message) Close PowerShell windows that have loaded these modules (a loaded DLL cannot be deleted on Windows) and re-run.")
        }
        # Everything is gone, so everything is to be saved.
        $todo = [System.Collections.Generic.List[object]]::new()
        foreach ($item in $plan) { $todo.Add($item) }
        $result['AlreadyPresent'] = @()
    }

    $result['Applied'] = $true
    [void][System.IO.Directory]::CreateDirectory($bundle)
    # From here until the lock is written this folder is a build in progress.
    Set-Content -LiteralPath $markerPath -Value 'A module bundle build is in progress or was interrupted. Re-run Install-NRGPrerequisites.ps1 -Local to finish it.' -Encoding utf8

    $save = if ($SaveAction) { $SaveAction } else { { param($Name, $Request, $Path) Invoke-NRGModuleBundleSave -Name $Name -Request $Request -Path $Path } }
    foreach ($item in $todo) {
        Write-Host "  [*] Saving $($item['Name']) $($item['Request'])..." -ForegroundColor Cyan
        try {
            & $save -Name $item['Name'] -Request $item['Request'] -Path $bundle
            $dir = Join-Path $bundle $item['Name']
            $landed = @(Get-ChildItem -LiteralPath $dir -Directory -Force -ErrorAction SilentlyContinue)
            if ($landed.Count -eq 0) { throw "nothing was saved under $dir" }
            $result['Saved'] = @($result['Saved']) + "$($item['Name']) $($landed[0].Name)"
        } catch {
            # Fail fast: what was saved stays (a re-run saves only the rest), and with no lock
            # file yet the folder is not a valid bundle, so nothing half-built gets activated.
            $result['Failed'] = @($result['Failed']) + [ordered]@{ Name = $item['Name']; Request = $item['Request']; Reason = $_.Exception.Message }
            return (& $fail "Saving $($item['Name']) $($item['Request']) failed: $($_.Exception.Message) The bundle is not complete and will not be used; re-run to finish it.")
        }
    }

    # ── Commit: the lock file, written last and atomically (temp beside it, then move).
    $lockModules = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $plan) {
        $dir = Join-Path $bundle $item['Name']
        $verDirs = @(Get-ChildItem -LiteralPath $dir -Directory -Force -ErrorAction SilentlyContinue)
        if ($verDirs.Count -ne 1) {
            return (& $fail "$($item['Name']) has $($verDirs.Count) version folders after saving; a bundle holds exactly one. Re-run with -Force.")
        }
        $lockModules.Add([ordered]@{ Name = $item['Name']; Version = $verDirs[0].Name; Family = $item['Family'] })
    }
    $lockBody = [ordered]@{
        SchemaVersion = 1
        BuiltUtc      = (Get-Date).ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture)
        PowerShell    = $PSVersionTable.PSVersion.ToString()
        Exchange      = [ordered]@{ Min = [string]$ExoFloor['Min']; Max = $(if ($ExoFloor['Max']) { [string]$ExoFloor['Max'] } else { $null }) }
        Modules       = @($lockModules)
    }
    $tmp = Join-Path $bundle ("$lockName." + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $lockBody | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $tmp -Encoding utf8 -ErrorAction Stop
        Move-Item -LiteralPath $tmp -Destination $lockPath -Force -ErrorAction Stop
    } catch {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        return (& $fail "Could not write ${lockName}: $($_.Exception.Message)")
    }

    # The lock is in place: the build is complete.
    Remove-Item -LiteralPath $markerPath -Force -ErrorAction SilentlyContinue

    $final = Test-NRGModuleBundle -ToolRoot $ToolRoot -Path $bundle -Spec $Spec -ExoFloor $ExoFloor
    $result['Valid'] = [bool]$final['Valid']
    $result['Errors'] = @($final['Errors'])
    $result['Warnings'] = @($final['Warnings'])
    return $result
}
