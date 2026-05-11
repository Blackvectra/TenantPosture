#
# NRG-Assessment.psd1
# PowerShell module manifest for NRG-Assessment v4
#
# Author: Matthew Levorson, NRG Technology Services
# License: Proprietary - NRG Technology Services / NextLayerSec LLC
#

@{
    RootModule        = 'NRG-Assessment.psm1'
    ModuleVersion     = '4.0.0'
    GUID              = '8a7c4f12-3b9e-4d5a-9c8f-1e2d3b4a5c6d'
    Author            = 'Matthew Levorson'
    CompanyName       = 'NRG Technology Services'
    Copyright         = '(c) 2026 NRG Technology Services. All rights reserved.'
    Description       = 'Microsoft 365 Security Assessment Framework - reads tenant configuration via Graph and EXO, scores against 8+ compliance frameworks, generates client deliverables.'
    PowerShellVersion = '7.2'

    RequiredModules   = @(
        @{ ModuleName = 'Microsoft.Graph.Authentication';      ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Users';               ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Identity.SignIns';    ModuleVersion = '2.0.0' }
        @{ ModuleName = 'Microsoft.Graph.Identity.DirectoryManagement'; ModuleVersion = '2.0.0' }
        @{ ModuleName = 'ExchangeOnlineManagement';            ModuleVersion = '3.0.0' }
    )

    FunctionsToExport = '*'
    CmdletsToExport   = @()
    VariablesToExport = @('NRGAssessmentVersion','NRGBrand')
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Security','M365','Assessment','NIST','CIS','HIPAA','CISA','SCuBA','MSP')
            ProjectUri   = 'https://github.com/Blackvectra/NRG-Assessment'
            ReleaseNotes = 'v4.0.0 - Complete architectural rebuild. Clean collector/evaluator separation. Device code auth. JSON-driven control definitions. See CHANGELOG.md.'
        }
    }
}
