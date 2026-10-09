#Requires -Version 7.0
#
# Get-TPModuleHealth.ps1
# Dependencies: None (reads Get-Module + the current AppDomain; no tenant calls)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
#
# Purpose: Detect the environment condition that produces the single most common
#   failure in Microsoft-365 PowerShell assessment tools (ours and CISA's
#   ScubaGear alike): the Microsoft.Identity.Client (MSAL) ASSEMBLY conflict.
#
# THE BUG THIS GUARDS:
#   Microsoft.Graph.Authentication and ExchangeOnlineManagement each ship their
#   own copy of Microsoft.Identity.Client.dll. .NET loads exactly ONE version of
#   an assembly per process, so when Graph loads MSAL vX and EXO then needs MSAL
#   vY the connect fails with a cryptic
#       "Could not load file or assembly 'Microsoft.Identity.Client...'"
#   or
#       "Method not found: '...PublicClientApplicationBuilder...WithBroker(...)'".
#   The two conditions that make this near-certain are:
#     1) MULTIPLE VERSIONS of Graph.Authentication or EXO installed side by side
#        (Get-Module -ListAvailable returns more than one), so which MSAL wins is
#        nondeterministic; and
#     2) a module installed under a OneDrive-REDIRECTED path — OneDrive locks the
#        DLL and PowerShell can't cleanly load/replace it.
#   ScubaGear's own tracker is full of these (issues #1917, #17, #1980). Neither
#   is a bug in the assessment logic — it's the operator's module install state —
#   so the right fix is to DETECT and EXPLAIN it before the cryptic error, not to
#   try to work around it at connect time.
#
# This function only INSPECTS state (never installs/removes anything). Callers
# (Connect-TPServices preflight, Test-TPModulePrerequisites) decide what to do.
#
# Testability: pass -InstalledOverride @{ '<ModuleName>' = @(<objs with .Version
#   and .ModuleBase>) } to evaluate synthetic install states without any modules
#   present. Omit it to read the real machine via Get-Module -ListAvailable.
#   When supplied, the override is authoritative for ALL THREE tracked modules,
#   not just the ones named in it: a name the caller left out is "not
#   installed", never a silent fallback to Get-Module for that one module —
#   otherwise a test overriding only one carrier would have its result depend
#   on whatever happens to be installed on the machine running it.

function Get-TPModuleHealth {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter()] [AllowNull()] [hashtable] $InstalledOverride
    )

    Set-StrictMode -Version Latest

    # Critical modules. ExchangeOnlineManagement needs 3.7.2, which added
    # -DisableWAM (the supported way around the WAM broker crash the old 3.2.0
    # pin worked around); no version is pinned. The MSAL carriers are the two
    # that bundle Microsoft.Identity.Client and therefore drive the assembly
    # conflict.
    $exoMin = [version]'3.7.2'
    if (Get-Command Get-TPExoModuleFloor -ErrorAction SilentlyContinue) { $exoMin = [version](Get-TPExoModuleFloor).Min }
    $specs = @(
        @{ Name = 'Microsoft.Graph.Authentication'; Min = [version]'2.0.0'; Pin = $null; MsalCarrier = $true  }
        @{ Name = 'ExchangeOnlineManagement';       Min = $exoMin;          Pin = $null; MsalCarrier = $true  }
        @{ Name = 'MicrosoftTeams';                 Min = [version]'5.0.0'; Pin = $null; MsalCarrier = $false }
    )

    $modules = [System.Collections.Generic.List[object]]::new()
    $anyRisk = $false

    foreach ($s in $specs) {
        $found = @()
        if ($InstalledOverride) {
            # -InstalledOverride replaces the machine as the source of truth
            # for THIS call. A module the caller did not name in it is "not
            # installed", never a silent fallback to the real machine — a
            # test that overrides only one carrier (e.g. MicrosoftTeams) but
            # not Microsoft.Graph.Authentication would otherwise read the
            # ACTUAL workstation's Graph install state, making the test's
            # result depend on what happens to be on the machine running it.
            if ($InstalledOverride.ContainsKey($s.Name)) {
                $found = @($InstalledOverride[$s.Name])
            }
        } elseif (Get-Command Get-Module -ErrorAction SilentlyContinue) {
            try { $found = @(Get-Module -ListAvailable -Name $s.Name -ErrorAction SilentlyContinue) } catch { $found = @() }
        }

        # Distinct versions (defensive: tolerate string or [version]).
        $versions = @($found | ForEach-Object {
            $v = $_.Version
            if ($v -is [version]) { $v } else { try { [version]([string]$v) } catch { $null } }
        } | Where-Object { $_ } | Sort-Object -Descending -Unique)

        $installed = ($found.Count -gt 0)
        $newest    = if ($versions.Count -gt 0) { $versions[0] } else { $null }
        $multiple  = ($versions.Count -gt 1)
        $oneDrive  = [bool]( @($found | Where-Object { [string]$_.ModuleBase -match '(?i)\bOneDrive\b' }).Count -gt 0 )
        $belowMin  = ($installed -and $newest -and $newest -lt $s.Min)
        $offPin    = ($installed -and $s.Pin -and $newest -and $newest -ne $s.Pin)

        $issues = [System.Collections.Generic.List[string]]::new()
        if (-not $installed) { $issues.Add('missing') }
        if ($multiple)       { $issues.Add('multiple-versions') }
        if ($oneDrive)       { $issues.Add('onedrive-path') }
        if ($belowMin)       { $issues.Add('below-min') }
        if ($offPin)         { $issues.Add('off-pin') }

        # The assembly conflict is driven by the MSAL carriers having more than
        # one version present OR living under OneDrive. Those two flip the risk.
        if ($s.MsalCarrier -and ($multiple -or $oneDrive)) { $anyRisk = $true }

        $modules.Add([ordered]@{
            Name               = $s.Name
            Installed          = $installed
            Versions           = @($versions | ForEach-Object { $_.ToString() })
            Newest             = if ($newest) { $newest.ToString() } else { $null }
            MultipleVersions   = $multiple
            OneDrivePath       = $oneDrive
            BelowMin           = $belowMin
            OffPin             = $offPin
            MsalCarrier        = [bool]$s.MsalCarrier
            RecommendedVersion = if ($s.Pin) { $s.Pin.ToString() } else { $null }
            Issues             = @($issues)
        })
    }

    # Which Microsoft.Identity.Client version(s) are ALREADY loaded in this
    # process. Normally 0 (fresh session) or 1; anything is informational and
    # helps an operator see what MSAL is pinned once a connect has happened.
    $msalLoaded = @()
    try {
        $msalLoaded = @([System.AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GetName().Name -eq 'Microsoft.Identity.Client' } |
            ForEach-Object { $_.GetName().Version.ToString() } |
            Sort-Object -Unique)
    } catch { $msalLoaded = @() }

    [ordered]@{
        Modules            = @($modules)
        LoadedMsalVersions = @($msalLoaded)
        HasConflictRisk    = $anyRisk
    }
}
