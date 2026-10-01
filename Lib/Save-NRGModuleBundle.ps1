#Requires -Version 7.0
#
# Save-NRGModuleBundle.ps1
# Dependencies: Lib/Get-NRGModuleBundle.ps1, Lib/Get-NRGModuleInstallScope.ps1,
#               and Save-PSResource (PSResourceGet) or Save-Module (PowerShellGet).
#               Reads the PowerShell Gallery; writes only the bundle folder and its
#               sibling .staging-* / .previous-* folders. No tenant calls of any kind.
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
#
# Purpose: Build the module bundle that Get-NRGModuleBundle.ps1 validates and the
#   entry points put first on PSModulePath: exactly one pinned version of every
#   module the tool needs, saved into a folder inside the tool (.modules/).
#   Install-NRGPrerequisites.ps1 -Local is the operator-facing wrapper.
#
# THIS DELETES NOTHING. Repair-NRGModuleHealth stays the tool's only code that
#   removes an installed module, and it asks first. The builder is additive:
#     - the bundle is built in a STAGING folder beside the target, checked with
#       Test-NRGModuleBundle, given its lock file, and only then renamed into
#       place, so a failed download leaves any working bundle exactly as it was;
#     - replacing an existing bundle (-Force) RENAMES it to <name>.previous-<time>
#       and says where it went; the operator deletes it when they choose to;
#     - a failed or interrupted build leaves its staging folder and reports the
#       path, rather than the tool removing a directory tree on its own;
#     - nothing is saved into, renamed or replaced in a folder the tool did not
#       create: an existing non-empty folder is accepted only when it carries
#       this tool's own lock file, so -BundlePath pointed at Documents or at a
#       project folder is refused instead of being taken over.
#   It does not touch PSModulePath, any installed module, or any tenant.
#
# The bundle is built from the PowerShell Gallery. -SaveAction replaces the
#   download in a test, receiving (plan item, staging folder).
#
# Consumes: nothing.  Sets: nothing.  Graph scopes / cmdlets: none.

function Save-NRGModuleBundle {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $Path,
        [AllowNull()] [AllowEmptyString()] [string] $ToolRoot,
        # Also save the SharePoint Online Management Shell (the one optional module).
        [switch] $IncludeSharePointShell,
        # Rebuild even when the bundle is already complete, and replace one that is
        # not. The old folder is renamed aside, never deleted.
        [switch] $Force,
        # Build inside a OneDrive-synced folder anyway. Refused by default: that is
        # the condition that makes a module file an online-only placeholder.
        [switch] $AllowSyncedPath,
        [version] $PowerShellVersion = $PSVersionTable.PSVersion,
        [AllowNull()] [AllowEmptyString()] [string] $PSHomePath = $PSHOME,
        [AllowNull()] [scriptblock] $SaveAction,
        [AllowNull()] [scriptblock] $FileAttributeProvider
    )

    Set-StrictMode -Version Latest

    $result = [ordered]@{
        Status   = 'Failed'      # Built / UpToDate / Planned / Refused / Failed
        Path     = $null
        Plan     = @()
        Saved    = @()
        Failures = @()
        Staging  = $null
        Previous = $null
        Message  = ''
    }
    $fail = { param([string] $Status, [string] $Message) $result.Status = $Status; $result.Message = $Message; return $result }

    $resolved = Get-NRGModuleBundlePath -Path $Path -ToolRoot $ToolRoot
    if ($resolved.Problem) { return (& $fail 'Refused' $resolved.Problem) }
    $target = [string]$resolved.Path
    $result.Path = $target

    $policy = Get-NRGModuleBundlePolicy -ToolRoot $ToolRoot -PowerShellVersion $PowerShellVersion `
        -PSHomePath $PSHomePath -IncludeSharePointShell:$IncludeSharePointShell
    if (-not $policy.Supported) { return (& $fail 'Refused' ([string]$policy.Floor.Reason)) }
    $plan = @($policy.Modules | Where-Object { $_.Required } | ForEach-Object {
        [ordered]@{
            Name = $_.Name; Group = $_.Group; Version = $_.Version; Min = $_.Min; Max = $_.Max
            SaveRange = $_.SaveRange
            Describe  = if ($_.Version) { [string]$_.Version } else { "newest in $($_.SaveRange)" }
        }
    })
    $result.Plan = $plan

    # Never build into a filesystem root, the tool folder itself, or the user's
    # home: a bundle there would be indistinguishable from the folder around it.
    $toolRootFull = ConvertTo-NRGBundleFullPath $(if ([string]::IsNullOrWhiteSpace($ToolRoot)) { Split-Path -Parent $PSScriptRoot } else { $ToolRoot })
    $homeFull = if ($HOME) { ConvertTo-NRGBundleFullPath $HOME } else { '' }
    $rootOfTarget = [System.IO.Path]::GetPathRoot($target)
    if ((Test-NRGSamePath $target $rootOfTarget) -or (Test-NRGSamePath $target $toolRootFull) -or
        ($homeFull -and (Test-NRGSamePath $target $homeFull))) {
        return (& $fail 'Refused' "$target is a drive root, the tool folder or the home folder; name a dedicated folder (the default is $(Join-Path $toolRootFull '.modules')).")
    }
    if (($target -match '(?i)\bOneDrive\b') -and -not $AllowSyncedPath) {
        return (& $fail 'Refused' "$target is inside a OneDrive-synced folder, where module files become online-only placeholders and fail with 'The cloud file provider is not running'. Use -BundlePath <folder outside OneDrive> (for example C:\NRG\modules) and set the $((Get-NRGModuleBundleEnvVarName)) environment variable to it, or pass -AllowSyncedPath to build here anyway.")
    }

    # An existing folder: ours (carries the lock file) or empty, or not ours.
    $lockPath = Join-Path $target (Get-NRGModuleBundleLockName)
    $exists   = Test-Path -LiteralPath $target
    if ($exists -and -not (Test-Path -LiteralPath $target -PathType Container)) {
        return (& $fail 'Refused' "$target exists and is not a folder.")
    }
    $hasContent = $exists -and (@(Get-ChildItem -LiteralPath $target -Force -ErrorAction SilentlyContinue).Count -gt 0)
    $isOurs     = $hasContent -and (Test-Path -LiteralPath $lockPath -PathType Leaf)
    if ($hasContent -and -not $isOurs) {
        return (& $fail 'Refused' "$target is not empty and was not created by this tool (it has no $((Get-NRGModuleBundleLockName))). Nothing was changed. Name a different folder with -BundlePath.")
    }

    if ($isOurs) {
        $current = Test-NRGModuleBundle -Path $target -ToolRoot $ToolRoot -PowerShellVersion $PowerShellVersion `
            -PSHomePath $PSHomePath -FileAttributeProvider $FileAttributeProvider
        $hasSpo = @($current.Modules | Where-Object { $_.Group -eq 'SharePointShell' -and $_.Present }).Count -gt 0
        $complete = ($current.Status -eq 'Valid') -and (-not $IncludeSharePointShell -or $hasSpo)
        if ($complete -and -not $Force) {
            $result.Status  = 'UpToDate'
            $result.Message = "The bundle at $target already holds the pinned modules; nothing to do. -Force rebuilds it."
            return $result
        }
        if (-not $Force) {
            return (& $fail 'Refused' "The bundle at $target does not match what this tool needs ($($current.Message)). Re-run with -Force to move it aside to $target.previous-<time> and rebuild; nothing was changed.")
        }
    }

    $label = "$($plan.Count) module(s) into $target"
    if (-not $PSCmdlet.ShouldProcess($label, 'Save pinned module bundle')) {
        $result.Status  = 'Planned'
        $result.Message = "Would save $label."
        return $result
    }

    # Build beside the target (same volume, so the final rename is atomic).
    $stagingName = '{0}.staging-{1}' -f (Split-Path -Leaf $target), [guid]::NewGuid().ToString('N')
    $staging = Join-Path (Split-Path -Parent $target) $stagingName
    $result.Staging = $staging
    try {
        # CreateDirectory, not New-Item: New-Item has no -LiteralPath, and the path
        # here is operator-supplied (-BundlePath), so a '[' must not become a wildcard.
        [void][System.IO.Directory]::CreateDirectory($staging)
    } catch {
        return (& $fail 'Failed' "Could not create the staging folder $staging. $($_.Exception.Message)")
    }

    $saved = [System.Collections.Generic.List[string]]::new()
    foreach ($item in $plan) {
        try {
            if ($SaveAction) {
                & $SaveAction $item $staging
            } elseif (Get-Command Save-PSResource -ErrorAction SilentlyContinue) {
                # Dependencies are skipped because every module the tool needs is in
                # the plan at its own pinned version; a dependency resolver is free to
                # pull a different, newer copy of one of them.
                Save-PSResource -Name $item.Name -Version $item.SaveRange -Repository PSGallery -Path $staging `
                    -TrustRepository -SkipDependencyCheck -ErrorAction Stop
            } elseif (Get-Command Save-Module -ErrorAction SilentlyContinue) {
                $sm = @{ Name = $item.Name; Path = $staging; Repository = 'PSGallery'; Force = $true; ErrorAction = 'Stop' }
                if ($item.Version) { $sm['RequiredVersion'] = $item.Version }
                else { $sm['MinimumVersion'] = $item.Min; if ($item.Max) { $sm['MaximumVersion'] = $item.Max } }
                Save-Module @sm
            } else {
                throw 'Neither Save-PSResource nor Save-Module is available.'
            }
            $saved.Add([string]$item.Name)
        } catch {
            $result.Saved    = @($saved)
            $result.Failures = @([ordered]@{ Name = $item.Name; Reason = $_.Exception.Message })
            $result.Message  = "Could not save $($item.Name) ($($item.Describe)): $($_.Exception.Message) The partial download was left in $staging and any existing bundle is unchanged; delete the staging folder when you no longer need it."
            return $result
        }
    }
    $result.Saved = @($saved)

    $check = Test-NRGModuleBundle -Path $staging -ToolRoot $ToolRoot -PowerShellVersion $PowerShellVersion `
        -PSHomePath $PSHomePath -FileAttributeProvider $FileAttributeProvider
    if ($check.Status -ne 'Valid') {
        $result.Failures = @($check.Issues | ForEach-Object { [ordered]@{ Name = ''; Reason = $_ } })
        $result.Message  = "The downloaded bundle did not validate: $(@($check.Issues) -join ' ') It was left in $staging and any existing bundle is unchanged."
        return $result
    }

    # The lock file is both the record of what was built and the marker that says
    # this folder is ours, which is what lets a later -Force replace it safely.
    $resolvedVersions = @($check.Modules | Where-Object { $_.Present } | ForEach-Object { [ordered]@{ Name = $_.Name; Version = $_.Version } })
    $resourceGet = Get-Module -ListAvailable -Name Microsoft.PowerShell.PSResourceGet -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1
    $lock = [ordered]@{
        SchemaVersion = 1
        Tool          = 'NRG-Assessment'
        BuiltAtUtc    = [datetime]::UtcNow.ToString('o', [cultureinfo]::InvariantCulture)
        PowerShell    = $PowerShellVersion.ToString()
        Source        = 'PSGallery'
        PSResourceGet = if ($resourceGet) { $resourceGet.Version.ToString() } else { '' }
        Modules       = $resolvedVersions
    }
    try {
        $lock | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $staging (Get-NRGModuleBundleLockName)) -Encoding utf8 -ErrorAction Stop
    } catch {
        $result.Message = "Could not write the bundle's $((Get-NRGModuleBundleLockName)): $($_.Exception.Message) The bundle was left in $staging."
        return $result
    }

    # Swap. Moving the old bundle aside is a rename, so it is reversible by hand.
    $moved = $null
    if ($exists -and $hasContent) {
        $moved = '{0}.previous-{1}' -f $target, (Get-Date -Format 'yyyyMMddHHmmss')
        try {
            Move-Item -LiteralPath $target -Destination $moved -ErrorAction Stop
            $result.Previous = $moved
        } catch {
            $result.Message = "The new bundle is ready in $staging but the existing one at $target could not be moved aside ($($_.Exception.Message)); close anything using it (a PowerShell window that loaded these modules) and rename the staging folder to $target yourself."
            return $result
        }
    } elseif ($exists) {
        # An empty folder we are about to replace: Move-Item onto an existing folder
        # would nest the staging folder inside it, so move the empty one aside too.
        $moved = '{0}.previous-{1}' -f $target, (Get-Date -Format 'yyyyMMddHHmmss')
        try { Move-Item -LiteralPath $target -Destination $moved -ErrorAction Stop; $result.Previous = $moved }
        catch {
            $result.Message = "The new bundle is ready in $staging but the empty folder at $target could not be moved aside ($($_.Exception.Message)); rename the staging folder to $target yourself."
            return $result
        }
    }
    try {
        Move-Item -LiteralPath $staging -Destination $target -ErrorAction Stop
    } catch {
        if ($moved) { try { Move-Item -LiteralPath $moved -Destination $target -ErrorAction Stop; $result.Previous = $null } catch { } }
        $result.Message = "The new bundle is ready in $staging but could not be moved to $target ($($_.Exception.Message))."
        return $result
    }

    $result.Staging = $null
    $result.Status  = 'Built'
    $result.Message = "Saved $($saved.Count) module(s) into $target."
    return $result
}
