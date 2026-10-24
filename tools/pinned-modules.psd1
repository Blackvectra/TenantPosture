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
    # The runtime modules the tool signs in with. CI does not install them (they are
    # about 500 MB together); the pin is the version the tool is validated against,
    # and the weekly freshness check reports and fails a pin that has fallen behind.
    ExchangeOnlineManagement       = @{ Version = '3.10.1'; Sha256 = '545fb0fdf65b96abed37f4f5b5d7db661276ddc7de48a742bb6e7199ab9414a3' }
    'Microsoft.Graph.Authentication' = @{ Version = '2.41.2'; Sha256 = 'a4f41cab6fc3ce0891a9295f191a218e0cfe692f21c6395763f339260c00d98c' }
    MicrosoftTeams                 = @{ Version = '8.0.0';  Sha256 = '6aa426d37913dee78628ad36dfc26e40161702018479f110f396712e896f2882' }
}
