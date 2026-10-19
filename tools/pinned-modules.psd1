# pinned-modules.psd1
# TenantPosture
# Author: Matthew Levorson
#
# The PowerShell modules CI installs, each by exact version and the SHA-256 of
# its PowerShell Gallery package (.nupkg). tools/Install-TPPinnedModule.ps1
# downloads the package, refuses it unless the hash matches, and extracts it:
# a module republished or substituted on the gallery, or altered in transit,
# never runs in CI. Dependabot cannot track the gallery, so a bump is a
# deliberate edit of a version and its hash together:
#
#   curl -sSL -o x.nupkg https://www.powershellgallery.com/api/v2/package/<Name>/<Version>
#   sha256sum x.nupkg
#
# Data only; read with Import-PowerShellDataFile, never executed.
@{
    PSScriptAnalyzer = @{ Version = '1.25.0'; Sha256 = '14e634c828eb98efb9f40b2918ba90f139ed5eccdf663a2a747736d996995d60' }
    Pester           = @{ Version = '6.2.0';  Sha256 = 'e6ac7418d4f12500269aaca58ae56cf1caafbbf1afa2cec334e289d1cf50a239' }
    InjectionHunter  = @{ Version = '1.0.0';  Sha256 = 'feb24c5c3e98f4741f3967a558983e5e23303e6fd9ed4f34e4b96cbe72a8f650' }
    Pode             = @{ Version = '2.14.1'; Sha256 = '38f7bedb4fd40a65d7518fc87de483450fafab22f5274ef82ebcfb0fca8ec6de' }
}
