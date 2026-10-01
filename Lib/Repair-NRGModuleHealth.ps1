#Requires -Version 7.0
#
# Repair-NRGModuleHealth.ps1
# Dependencies: PowerShellGet / PSResourceGet (Uninstall-PSResource or
#               Uninstall-Module). No tenant calls of any kind.
#
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Resolve the ONE environment condition Get-NRGModuleHealth detects and
#   could not previously fix: multiple installed versions of a Microsoft.Identity.Client
#   (MSAL) carrier module. .NET loads exactly one version of an assembly per
#   process, so with two versions of Microsoft.Graph.Authentication side by side
#   which MSAL wins is nondeterministic -- producing either the cryptic
#   "Could not load file or assembly 'Microsoft.Identity.Client'" at Exchange
#   connect, or a token acquisition that never returns and hangs the first
#   collector with no error at all.
#
# WHY THIS EXISTS AS ITS OWN FUNCTION:
#   Get-NRGModuleHealth is deliberately inspect-only and stays that way. The
#   preflight in Connect-NRGServices told operators to "run
#   Install-NRGPrerequisites.ps1", but that script only reconciles versions for
#   modules carrying a PinVersion (ExchangeOnlineManagement, until its 3.2.0
#   pin was lifted for the 3.7.2 floor; nothing is pinned now).
#   Microsoft.Graph.Authentication has no pin, so it took the "any version above
#   the minimum is fine" branch, inspected only the NEWEST installed version,
#   reported OK and left the duplicate in place. The detector was right, the
#   remedy it named was a no-op, and the operator was sent in a circle.
#
# THIS IS THE TOOL'S ONLY DESTRUCTIVE LOCAL OPERATION.
#   It removes PowerShell modules from the operator's workstation. It therefore:
#     - is NEVER called from the assessment path (no collector, evaluator or
#       publisher invokes it; a read-only assessment must not uninstall software
#       as a side effect of being run),
#     - declares SupportsShouldProcess with ConfirmImpact High, so -WhatIf and
#       an interactive confirmation both work by default,
#     - acts ONLY on an internal allowlist of module names. The module to operate
#       on is chosen from that list, never taken as free-form caller input, so no
#       argument can direct it at an unrelated module.
#   It touches nothing in any tenant. The tool's read-only-without-exception rule
#   is about tenant configuration; this is the operator's own module install
#   state, and it still asks first.
#
# Consumes: nothing.
# Sets:     nothing.
# Graph scopes / cmdlets: none.

# Uninstall-PSResource searches the current-user scope unless told otherwise, and PowerShell 7 also
# lists modules from other folders on PSModulePath (the all-users folder the installer uses, the
# Windows PowerShell 5.1 folder, or a copy placed by hand). For those it answers "version ... does not
# exist" even though Get-Module lists them and they still load. The first live repair on a work
# computer hit exactly that and removed nothing. This decides whether one version folder reported
# by Get-Module is safe to delete directly: the path must be <PSModulePath entry>\<module>\<version>
# (or <module>\<version>\ with a file-version leaf), nothing else.
function Test-NRGSafeModuleVersionPath {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $Path,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [string] $Version,
        [AllowNull()] [AllowEmptyString()] [string] $PSModulePathValue = $env:PSModulePath
    )
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    $full = $Path.TrimEnd('\', '/')
    $leaf = ($full -split '[\\/]')[-1]
    $parent = $full.Substring(0, [Math]::Max(0, $full.Length - $leaf.Length)).TrimEnd('\', '/')
    $parentLeaf = ($parent -split '[\\/]')[-1]
    $root = $parent.Substring(0, [Math]::Max(0, $parent.Length - $parentLeaf.Length)).TrimEnd('\', '/')
    if ($parentLeaf -ne $Name) { return $false }
    # Leaf is the version folder. Some modules use a 4-part folder name; compare numerically.
    $lv = $null; $wv = $null
    if (-not [version]::TryParse($leaf, [ref]$lv)) { return $false }
    if (-not [version]::TryParse($Version, [ref]$wv)) { return $false }
    if ($lv -ne $wv) { return $false }
    # The folder two levels up must be an entry on PSModulePath (never a drive root or arbitrary path).
    # ';' separates Windows entries and cannot occur inside a drive-letter path, unlike ':' on Linux/macOS.
    $sepChar = if ($PSModulePathValue -match ';') { ';' } else { [string][IO.Path]::PathSeparator }
    foreach ($entry in @($PSModulePathValue -split [regex]::Escape($sepChar) | Where-Object { $_ })) {
        if ($entry.TrimEnd('\', '/') -ieq $root) { return $true }
    }
    return $false
}

function Repair-NRGModuleHealth {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        # Report what would be removed and change nothing. Equivalent to -WhatIf
        # but returns the plan as an object so a caller can render it.
        [Parameter()]
        [switch] $PlanOnly,

        # Testability: same shape Get-NRGModuleHealth accepts, so a synthetic
        # install state can be exercised with no modules present on the machine.
        [Parameter()]
        [AllowNull()]
        [hashtable] $InstalledOverride,

        # Testability: a scriptblock invoked in place of the real uninstall,
        # receiving (Name, Version). Without it the real uninstall runs.
        [Parameter()]
        [AllowNull()]
        [scriptblock] $RemoveAction
    )

    Set-StrictMode -Version Latest

    # Allowlist. The MSAL carriers are the only modules whose duplicate versions
    # cause the assembly conflict, and they are the only ones this will remove.
    # MicrosoftTeams is deliberately absent: it does not bundle MSAL, so multiple
    # versions of it are harmless and removing them would be destruction with no
    # benefit. Get-NRGModuleHealth applies the same rule when it sets
    # HasConflictRisk.
    $carriers = @{
        'Microsoft.Graph.Authentication' = $null        # keep newest
        'ExchangeOnlineManagement'       = $null        # keep newest (no pin since the 3.7.2 floor)
    }

    $health = if ($PSBoundParameters.ContainsKey('InstalledOverride') -and $null -ne $InstalledOverride) {
        Get-NRGModuleHealth -InstalledOverride $InstalledOverride
    } else {
        Get-NRGModuleHealth
    }

    $plan      = [System.Collections.Generic.List[object]]::new()
    $removed   = [System.Collections.Generic.List[object]]::new()
    $failed    = [System.Collections.Generic.List[object]]::new()
    $notes     = [System.Collections.Generic.List[string]]::new()

    foreach ($m in $health.Modules) {
        $name = [string](Get-NRGObjectField -Item $m -Key 'Name' -Default '')
        if (-not $carriers.ContainsKey($name)) { continue }

        $versions = @(Get-NRGObjectField -Item $m -Key 'Versions' -Default @())
        if ($versions.Count -le 1) { continue }

        # Parse and sort descending. A version that will not parse is left alone
        # rather than guessed at -- removing the wrong build is unrecoverable
        # without a reinstall.
        $parsed = @()
        foreach ($v in $versions) {
            $pv = $null
            if ([version]::TryParse([string]$v, [ref]$pv)) { $parsed += $pv }
            else { $notes.Add("$name : version '$v' could not be parsed and was left in place.") }
        }
        if ($parsed.Count -le 1) { continue }
        $parsed = @($parsed | Sort-Object -Descending -Unique)

        # Which one survives: the pin if that pin is actually installed,
        # otherwise the newest. Naming a pin that is NOT installed must not make
        # this remove every version -- that would leave the operator with no
        # module at all, which is strictly worse than the duplicate.
        $pin  = $carriers[$name]
        $keep = if ($pin -and ($parsed -contains $pin)) { $pin } else { $parsed[0] }
        if ($pin -and ($parsed -notcontains $pin)) {
            $notes.Add("$name : recommended version $pin is not installed; keeping newest ($keep) instead of removing everything.")
        }

        foreach ($v in $parsed) {
            if ($v -eq $keep) { continue }
            $plan.Add([ordered]@{ Name = $name; Version = $v.ToString(); Keeping = $keep.ToString() })
        }
    }

    # An assembly already loaded into this process cannot be unloaded. Removing
    # the files on disk does not change what this session has in memory, so the
    # repair only takes effect in a NEW PowerShell session. Saying so is not
    # optional: an operator who repairs and immediately re-runs in the same
    # window sees the identical hang and concludes the fix did not work.
    $msalLoaded = @(Get-NRGObjectField -Item $health -Key 'LoadedMsalVersions' -Default @())
    $restartRequired = ($plan.Count -gt 0 -and $msalLoaded.Count -gt 0)

    if ($PlanOnly -or $plan.Count -eq 0) {
        return [ordered]@{
            Planned         = @($plan)
            Removed         = @()
            Failed          = @()
            Notes           = @($notes)
            RestartRequired = $restartRequired
            LoadedMsal      = @($msalLoaded)
            Applied         = $false
        }
    }

    foreach ($item in $plan) {
        $target = "$($item.Name) $($item.Version)"
        if (-not $PSCmdlet.ShouldProcess($target, 'Uninstall module version')) { continue }

        try {
            if ($RemoveAction) {
                & $RemoveAction $item.Name $item.Version
            } else {
                $done = $false
                $pkgError = $null
                if (Get-Command Uninstall-PSResource -ErrorAction SilentlyContinue) {
                    try { Uninstall-PSResource -Name $item.Name -Version $item.Version -ErrorAction Stop; $done = $true }
                    catch { $pkgError = $_.Exception.Message }
                } elseif (Get-Command Uninstall-Module -ErrorAction SilentlyContinue) {
                    try { Uninstall-Module -Name $item.Name -RequiredVersion $item.Version -Force -ErrorAction Stop; $done = $true }
                    catch { $pkgError = $_.Exception.Message }
                } else {
                    $pkgError = 'Neither Uninstall-PSResource nor Uninstall-Module is available.'
                }
                if (-not $done) {
                    # The package manager could not find it. Remove the exact version folder Get-Module lists,
                    # only when it passes the path check; otherwise report the package manager's error.
                    $viaPath = $false
                    $want = [version]$item.Version
                    $found = @(Get-Module -ListAvailable -Name $item.Name -ErrorAction SilentlyContinue | Where-Object { $_.Version -eq $want })
                    foreach ($mod in $found) {
                        if (Test-NRGSafeModuleVersionPath -Path ([string]$mod.ModuleBase) -Name $item.Name -Version $item.Version) {
                            Remove-Item -LiteralPath ([string]$mod.ModuleBase) -Recurse -Force -ErrorAction Stop
                            $viaPath = $true
                        }
                    }
                    if (-not $viaPath) { throw $pkgError }
                }
            }
            $removed.Add($item)
        } catch {
            # Record and continue: one locked version (OneDrive, in use by
            # another session) must not abort the remaining removals.
            $failed.Add([ordered]@{
                Name    = $item.Name
                Version = $item.Version
                Reason  = $_.Exception.Message
            })
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'ModuleRepair' `
                    -Message ("Could not remove {0} {1}: {2}" -f $item.Name, $item.Version, $_.Exception.Message)
            }
        }
    }

    # Applied must reflect whether a ShouldProcess call actually returned
    # true, not merely that this branch was reached — under -WhatIf every
    # ShouldProcess call in the loop above returns false, so the loop runs to
    # completion having attempted nothing, and $removed/$failed both stay
    # empty. A caller trusting a hardcoded $true here would believe a -WhatIf
    # run had repaired the module when it removed zero files.
    [ordered]@{
        Planned         = @($plan)
        Removed         = @($removed)
        Failed          = @($failed)
        Notes           = @($notes)
        RestartRequired = $restartRequired
        LoadedMsal      = @($msalLoaded)
        Applied         = (($removed.Count + $failed.Count) -gt 0)
    }
}
