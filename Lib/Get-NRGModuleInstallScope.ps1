#Requires -Version 7.0
#
# Get-NRGModuleInstallScope.ps1
# Dependencies: None (reads $env:PSModulePath + the current Windows identity;
#               no tenant calls, no installs)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
#
# Purpose: Decide WHERE a fresh module install should land so it doesn't
#   recreate the MSAL assembly-conflict condition Get-NRGModuleHealth exists
#   to detect. The CurrentUser module path lives under $HOME\Documents, and
#   on machines with OneDrive Known Folder Move enabled — a common ORG POLICY
#   the operator does not control — Documents is silently redirected into
#   OneDrive. OneDrive then locks and partially syncs module DLLs, which is
#   the single most common cause of "Could not load file or assembly
#   Microsoft.Identity.Client" at Exchange connect.
#
# This was previously decided independently in Install-NRGPrerequisites.ps1
# and, less carefully, inline in Invoke-NRGAssessment.ps1's own "Install/fix
# modules now?" prompt — the latter hardcoded -Scope CurrentUser with no
# OneDrive check at all, so the path most operators actually take (answering
# Y to that prompt) reintroduced the exact condition the rest of the tool
# warns about. One decision, two callers, so a future fix here reaches both
# instead of drifting.
#
# This function only DECIDES; it never installs, removes, or writes
# anything. Callers still choose whether/how to print the OneDrive warning
# and whether to actually pass -Scope $result.Scope to the module installer.
#
# Testability: pass -UserModulePathOverride / -IsElevatedOverride to drive
# this deterministically in a test. Omitting either reads the real
# environment ($env:PSModulePath / current Windows identity).

function Get-NRGModuleInstallScope {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()]
        [string] $UserModulePathOverride,

        [AllowNull()]
        [object] $IsElevatedOverride
    )

    Set-StrictMode -Version Latest

    $userModuleDir = if ($PSBoundParameters.ContainsKey('UserModulePathOverride')) {
        $UserModulePathOverride
    } else {
        ($env:PSModulePath -split [IO.Path]::PathSeparator |
            Where-Object { $_ -like "$HOME*" } | Select-Object -First 1)
    }
    $userPathIsSynced = [bool]($userModuleDir -match '(?i)\bOneDrive\b')

    $isElevated = if ($PSBoundParameters.ContainsKey('IsElevatedOverride')) {
        [bool]$IsElevatedOverride
    } else {
        $elevated = $false
        try {
            $elevated = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
                ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        } catch { $elevated = $false }
        $elevated
    }

    # AllUsers ($env:ProgramFiles\PowerShell\Modules) is never OneDrive-
    # redirected, so when the user path is synced and the session is
    # elevated, install there instead. A non-elevated session synced into
    # OneDrive has no escape from here — the module WILL land in OneDrive —
    # so callers must surface StillSynced and tell the operator how to fix
    # it themselves (elevate, or reconfigure OneDrive backup/KFM).
    $scope = if ($userPathIsSynced -and $isElevated) { 'AllUsers' } else { 'CurrentUser' }

    [ordered]@{
        Scope            = $scope
        UserModuleDir    = $userModuleDir
        UserPathIsSynced = $userPathIsSynced
        IsElevated       = $isElevated
        StillSynced      = ($userPathIsSynced -and -not $isElevated)
    }
}

# ExchangeOnlineManagement's supported version depends on the PowerShell in
# use (Microsoft's "About the Exchange Online PowerShell module" support
# table): 3.10.0 and later need 7.6; 3.5.0 to 3.9.2 need 7.4 or later; 3.0.0
# to 3.4.0 run on 7.2 to 7.3.7. The tool's own floor is 3.7.2 (-DisableWAM).
# The first live run of v4.14.3 found 3.9.2 installed beside PowerShell 7.6.6:
# the installer accepted it because it only checked the minimum, and
# Connect-ExchangeOnline then failed inside the module with "You cannot call
# a method on a null-valued expression". The floor must RISE with PowerShell,
# not only the ceiling fall. One function so the installer, the entry point's
# preflight and Get-NRGModuleHealth cannot disagree.
#
# The Microsoft Store (MSIX) build of PowerShell is reported too: its $PSHOME
# lives under WindowsApps, a folder Windows locks, and the Exchange module
# failed to import from it on that same machine ("Access to the path
# '...\WindowsApps\...\Scripts' is denied"). The MSI build has no such limit.
function Get-NRGExoModuleFloor {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [version] $PSVersion = $PSVersionTable.PSVersion,
        [AllowNull()] [AllowEmptyString()] [string] $PSHomePath = $PSHOME
    )
    $store = [bool]($PSHomePath -and $PSHomePath -match '[\\/]WindowsApps[\\/]')
    if ($PSVersion -ge [version]'7.6.0') {
        return [ordered]@{ Min = '3.10.0'; Max = $null;    Supported = $true;  StoreBuild = $store
                           Reason = 'PowerShell 7.6 or later needs ExchangeOnlineManagement 3.10.0 or later.' }
    }
    if ($PSVersion -ge [version]'7.4.0') {
        return [ordered]@{ Min = '3.7.2';  Max = '3.9.99'; Supported = $true;  StoreBuild = $store
                           Reason = 'PowerShell 7.4 and 7.5 run ExchangeOnlineManagement 3.7.2 to 3.9.x; 3.10.0 and later need 7.6.' }
    }
    return [ordered]@{ Min = '3.7.2'; Max = '3.4.99'; Supported = $false; StoreBuild = $store
                       Reason = "PowerShell $PSVersion cannot run ExchangeOnlineManagement 3.7.2 or later (the tool's floor, which added -DisableWAM); upgrade PowerShell to 7.4 or later (winget install --id Microsoft.PowerShell)." }
}

# What to tell the operator before an Exchange Online sign-in, in one place so the full assessment and the
# distribution-list scan cannot word it differently: the PowerShell is too old, it is the Microsoft Store build,
# and (when the installed module is given) the module is older or newer than this PowerShell supports. Each
# note carries a Level: 'Error' means a sign-in cannot succeed, 'Warning' means it may fail inside the module.
function Get-NRGExoPreflightNotes {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] $Floor,
        [AllowNull()] [version] $InstalledVersion
    )
    $notes = [System.Collections.Generic.List[object]]::new()
    if (-not $Floor.Supported) { $notes.Add([ordered]@{ Level = 'Error'; Text = [string]$Floor.Reason }) }
    if ($Floor.StoreBuild) {
        $notes.Add([ordered]@{ Level = 'Warning'; Text = "Microsoft Store build of PowerShell detected (`$PSHOME is under WindowsApps); the Exchange Online module has failed to import from it. Install the MSI build: winget install --id Microsoft.PowerShell --source winget" })
    }
    if ($null -ne $InstalledVersion -and $Floor.Supported) {
        if ($InstalledVersion -lt [version]$Floor.Min) {
            $notes.Add([ordered]@{ Level = 'Error'; Text = "ExchangeOnlineManagement $InstalledVersion is older than the $($Floor.Min) this PowerShell needs. Run .\Install-NRGPrerequisites.ps1, then retry." })
        } elseif ($Floor.Max -and $InstalledVersion -gt [version]$Floor.Max) {
            $notes.Add([ordered]@{ Level = 'Warning'; Text = "ExchangeOnlineManagement $InstalledVersion is newer than PowerShell $($PSVersionTable.PSVersion) supports (up to $($Floor.Max)); connecting will fail inside the module. Upgrade PowerShell or install a version in [$($Floor.Min),$($Floor.Max)]." })
        }
    }
    return @($notes)
}
