#Requires -Version 7.0
#
# Get-TPModuleInstallScope.ps1
# Dependencies: None (reads $env:PSModulePath + the current Windows identity;
#               no tenant calls, no installs)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
#
# Purpose: Decide WHERE a fresh module install should land so it doesn't
#   recreate the MSAL assembly-conflict condition Get-TPModuleHealth exists
#   to detect. The CurrentUser module path lives under $HOME\Documents, and
#   on machines with OneDrive Known Folder Move enabled — a common ORG POLICY
#   the operator does not control — Documents is silently redirected into
#   OneDrive. OneDrive then locks and partially syncs module DLLs, which is
#   the single most common cause of "Could not load file or assembly
#   Microsoft.Identity.Client" at Exchange connect.
#
# This was previously decided independently in Install-TPPrerequisites.ps1
# and, less carefully, inline in Invoke-TPAssessment.ps1's own "Install/fix
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

function Get-TPModuleInstallScope {
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
# preflight and Get-TPModuleHealth cannot disagree.
#
# The Microsoft Store (MSIX) build of PowerShell is reported too: its $PSHOME
# lives under WindowsApps, a folder Windows locks, and the Exchange module
# failed to import from it on that same machine ("Access to the path
# '...\WindowsApps\...\Scripts' is denied"). The MSI build has no such limit.
function Get-TPExoModuleFloor {
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
function Get-TPExoPreflightNotes {
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
            $notes.Add([ordered]@{ Level = 'Error'; Text = "ExchangeOnlineManagement $InstalledVersion is older than the $($Floor.Min) this PowerShell needs. Run .\Install-TPPrerequisites.ps1, then retry." })
        } elseif ($Floor.Max -and $InstalledVersion -gt [version]$Floor.Max) {
            $notes.Add([ordered]@{ Level = 'Warning'; Text = "ExchangeOnlineManagement $InstalledVersion is newer than PowerShell $($PSVersionTable.PSVersion) supports (up to $($Floor.Max)); connecting will fail inside the module. Upgrade PowerShell or install a version in [$($Floor.Min),$($Floor.Max)]." })
        }
    }
    return @($notes)
}

# Is the PowerShell running the tool still supported by Microsoft? The dates come from
# Config/powershell-lifecycle.json, copied from Microsoft's PowerShell Support Lifecycle page
# (7.4 LTS and 7.5 end on 2026-11-10; 7.6 LTS runs to 2028-11-14). An operator on an
# out-of-support release gets no security updates for the shell that holds tenant tokens,
# and the Exchange module's floor rises with PowerShell (Get-TPExoModuleFloor), so this is a
# warning, never a refusal: the run still works. A release line not in the file (a preview,
# or a release newer than the file) is reported as unknown, never as supported.
function Get-TPPowerShellSupportStatus {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        # A string or version object: $PSVersionTable.PSVersion is a SemanticVersion, which
        # a [version] parameter cannot bind when it carries a preview label.
        [object] $PSVersion = $PSVersionTable.PSVersion,
        [datetime] $AsOf = [datetime]::UtcNow,
        [string] $Path
    )
    if (-not $Path) { $Path = Join-Path (Split-Path -Parent $PSScriptRoot) 'Config' 'powershell-lifecycle.json' }
    $text = [string]$PSVersion
    $PreReleaseLabel = $null
    if ($text -match '\A(\d+)\.(\d+)(?:\.\d+)?(?:-([0-9A-Za-z.]+))?') { $line = '{0}.{1}' -f $Matches[1], $Matches[2]; $PreReleaseLabel = $Matches[3] }
    else { $line = $text }
    $PSVersion = ($text -split '-', 2)[0]
    $result = [ordered]@{ Version = [string]$PSVersion; Line = $line; EndOfSupport = $null; State = 'Unknown'; Level = 'None'; Text = ''; Source = $null }
    $catalog = $null
    try { $catalog = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch {
        $result.Text = "PowerShell $PSVersion support status was not checked: the lifecycle file could not be read."
        return $result
    }
    $result.Source = [string]$catalog.source
    $upgrade = 'Install the current LTS release: winget install --id Microsoft.PowerShell --source winget'
    if (-not [string]::IsNullOrWhiteSpace($PreReleaseLabel)) {
        $result.State = 'Preview'; $result.Level = 'Warning'
        $result.Text  = "PowerShell $PSVersion-$PreReleaseLabel is a preview release; Microsoft does not support previews in production. $upgrade"
        return $result
    }
    $entry = @($catalog.releases | Where-Object { [string]$_.Line -eq $line }) | Select-Object -First 1
    if (-not $entry) {
        $result.Text = "PowerShell $PSVersion is not in the tool's lifecycle list ($($catalog.sourceRetrieved)); its support status was not checked."
        return $result
    }
    $eos = [datetime]::MinValue
    if (-not [datetime]::TryParseExact([string]$entry.EndOfSupport, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$eos)) {
        $result.Text = "PowerShell $PSVersion support status was not checked: the lifecycle file's date for $line is not a date."
        return $result
    }
    $result.EndOfSupport = $eos.ToString('yyyy-MM-dd')
    $warnDays = 90
    if ($catalog.PSObject.Properties['warnDays'] -and [int]::TryParse([string]$catalog.warnDays, [ref]$null)) { $warnDays = [int]$catalog.warnDays }
    # Support ends at the end of the stated day; compare dates, not instants.
    $today = $AsOf.ToUniversalTime().Date
    if ($today -gt $eos.Date) {
        $result.State = 'EndOfSupport'; $result.Level = 'Warning'
        $result.Text  = "PowerShell $line reached end of support on $($result.EndOfSupport) and no longer receives security updates. $upgrade"
    } elseif (($eos.Date - $today).TotalDays -le $warnDays) {
        $result.State = 'EndingSoon'; $result.Level = 'Warning'
        $result.Text  = "PowerShell $line reaches end of support on $($result.EndOfSupport) ($([int]($eos.Date - $today).TotalDays) days). Move to the current LTS before then; on 7.6 the Exchange module floor is 3.10.0. $upgrade"
    } else {
        $result.State = 'Supported'
        $result.Text  = "PowerShell $line is supported until $($result.EndOfSupport)."
    }
    return $result
}
