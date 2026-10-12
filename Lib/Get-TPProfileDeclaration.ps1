#Requires -Version 7.0
#
# Get-TPProfileDeclaration.ps1  (v4.14.x)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: A product the active PROFILE declares the practice runs for every client
#          (EdrStack: the third-party EDR; AwarenessStack: the phishing-simulation
#          platform). Declared by the assessor, never verified: the checks that
#          depend on it go out of the score rather than pass. Read from the profile
#          the module loaded ($TPBrand), never from a second read of
#          Config/branding.psd1, which ignored the profile and applied or dropped
#          the wrong practice's declarations.
#
#          The value must be a plain product name; anything else is ignored with a
#          warning that names the profile and the key.
#
# Inputs:  -Brand (the loaded profile data), -Key (EdrStack or AwarenessStack),
#          -Example (a product name for the warning text).
# Output:  [string], '' when the profile declares none or declares an unusable value.
# Cmdlets: none beyond Get-TPObjectField / Write-Warning.

function Get-TPProfileDeclaration {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] $Brand,
        [Parameter(Mandatory)] [ValidateSet('EdrStack', 'AwarenessStack')] [string] $Key,
        [string] $Example = 'Cortex XDR'
    )
    $value = "$(Get-TPObjectField -Item $Brand -Key $Key -Default '')".Trim()
    if (-not $value) { return '' }
    if ($value -match '^[A-Za-z0-9][A-Za-z0-9 .&()+/-]{1,59}$') { return $value }
    $profileName = [string](Get-TPObjectField -Item $Brand -Key 'ProfileName' -Default 'active')
    Write-Warning "Ignoring $Key '$value' in the $profileName profile: use a plain product name such as '$Example'."
    return ''
}
