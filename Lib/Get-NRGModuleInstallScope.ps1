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
# and whether to actually pass -Scope $result.Scope to Install-PSResource.
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
