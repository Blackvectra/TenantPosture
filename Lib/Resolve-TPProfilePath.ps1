#Requires -Version 7.0
#
# Resolve-TPProfilePath.ps1  (v4.14.x)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: The one definition of "which profile file does this run use". A
#          profile name is a short lower-case token (letters, digits, hyphens),
#          never a path; it names Config/profiles/<name>.psd1. With no name the
#          run uses Config/branding.psd1. A name that is not a token, or names
#          a profile that does not exist, is an ERROR and not a fallback:
#          running a different practice's defaults than the one asked for is a
#          wrong-practice failure nothing in the output would reveal.
#
#          Loaded by TenantPosture.psm1 (the module's profile) and dot-sourced
#          by Invoke-TPAssessment.ps1 before the module import, so the entry
#          point can stop with exit code 4 on a bad name instead of seeing a
#          generic module-load failure. Pure: it reads no profile file.
#
# Inputs:  -Root (the install folder), -Name (-Profile or TP_PROFILE).
# Output:  [pscustomobject] Status (Default, Ok, BadName, NotFound), Name,
#          Path, Message, Available (the profile names that exist).
# Cmdlets: none beyond Join-Path / Test-Path / Get-ChildItem.

# The one profile-name rule. A function and not a script variable, so it holds wherever this
# file is dot-sourced (the module, the entry point, a test, the web server's own scope).
function Get-TPProfileNamePattern { '\A[a-z0-9][a-z0-9-]{0,31}\z' }

function Resolve-TPProfilePath {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Root,
        [AllowNull()] [AllowEmptyString()] [string] $Name = ''
    )
    $branding = Join-Path $Root 'Config' 'branding.psd1'
    $dir = Join-Path $Root 'Config' 'profiles'
    $available = @(if (Test-Path -LiteralPath $dir -PathType Container) {
        Get-ChildItem -LiteralPath $dir -Filter '*.psd1' -File | ForEach-Object { $_.BaseName } |
            Where-Object { $_ -cmatch (Get-TPProfileNamePattern) } | Sort-Object
    })
    $make = {
        param($status, $n, $path, $msg)
        [pscustomobject]@{ Status = $status; Name = $n; Path = $path; Message = $msg; Available = $available }
    }
    if ([string]::IsNullOrEmpty($Name)) { return (& $make 'Default' 'branding' $branding '') }
    if ($Name -cnotmatch (Get-TPProfileNamePattern)) {
        return (& $make 'BadName' $Name '' "The profile name is not a name: use lower-case letters, digits and hyphens only (at most 32), never a path. Available profiles: $(if ($available.Count) { $available -join ', ' } else { '(none)' }).")
    }
    $candidate = Join-Path $dir "$Name.psd1"
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
        return (& $make 'NotFound' $Name '' "There is no profile '$Name' (Config/profiles/$Name.psd1). Available profiles: $(if ($available.Count) { $available -join ', ' } else { '(none)' }). Check the spelling, or unset TP_PROFILE to use Config/branding.psd1.")
    }
    return (& $make 'Ok' $Name $candidate '')
}
