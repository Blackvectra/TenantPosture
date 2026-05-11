#
# Add-NRGFinding.ps1
# Register a control assessment finding. Used by all evaluators.
#
# State values: Satisfied | Partial | Gap | NotApplicable
# Severity:     Critical  | High    | Medium | Low | Informational
#

function Add-NRGFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ControlId,
        [Parameter(Mandatory)] [ValidateSet('Satisfied','Partial','Gap','NotApplicable')] [string] $State,
        [Parameter(Mandatory)] [string] $Category,
        [Parameter(Mandatory)] [string] $Title,
        [ValidateSet('Critical','High','Medium','Low','Informational')] [string] $Severity = 'Medium',
        [string]   $Detail        = '',
        [string]   $CurrentValue  = '',
        [string]   $RequiredValue = '',
        [string]   $Instance      = '',
        [string[]] $FrameworkIds  = @(),
        [string]   $Remediation   = '',
        [string]   $RemediationLink = ''
    )

    $finding = [PSCustomObject]@{
        ControlId       = $ControlId
        State           = $State
        Category        = $Category
        Title           = $Title
        Severity        = if ($State -eq 'Satisfied') { 'Informational' } else { $Severity }
        Detail          = $Detail
        CurrentValue    = $CurrentValue
        RequiredValue   = $RequiredValue
        Instance        = $Instance
        FrameworkIds    = $FrameworkIds
        Remediation     = $Remediation
        RemediationLink = $RemediationLink
        Timestamp       = [DateTime]::UtcNow.ToString('o')
    }

    $script:NRGFindings.Add($finding)
}

function Get-NRGFindings {
    [CmdletBinding()] param()
    return ,$script:NRGFindings.ToArray()
}

function Clear-NRGFindings {
    [CmdletBinding()] param()
    $script:NRGFindings.Clear()
    $script:NRGExceptions.Clear()
    $script:NRGCoverage.Clear()
    $script:NRGRawData = @{}
}

function Register-NRGException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Source,
        [Parameter(Mandatory)] [string] $Message,
        [string] $Severity = 'Warning'
    )

    $script:NRGExceptions.Add([PSCustomObject]@{
        Source    = $Source
        Message   = $Message
        Severity  = $Severity
        Timestamp = [DateTime]::UtcNow.ToString('o')
    })
}

function Get-NRGExceptions {
    [CmdletBinding()] param()
    return ,$script:NRGExceptions.ToArray()
}

function Register-NRGCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Family,
        [Parameter(Mandatory)] [ValidateSet('Collected','Partial','NotCollected','Failed')] [string] $Status,
        [string] $Note = ''
    )
    $script:NRGCoverage[$Family] = "$Status|$Note"
}

function Get-NRGCoverage {
    [CmdletBinding()] param()
    $result = @{}
    foreach ($k in $script:NRGCoverage.Keys) {
        $parts = $script:NRGCoverage[$k] -split '\|', 2
        $result[$k] = [PSCustomObject]@{ Status = $parts[0]; Note = $parts[1] }
    }
    return $result
}

function Set-NRGRawData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Key,
        [Parameter(Mandatory)] $Data
    )
    $script:NRGRawData[$Key] = $Data
}

function Get-NRGRawData {
    [CmdletBinding()]
    param([string] $Key)
    if ($Key) { return $script:NRGRawData[$Key] }
    return $script:NRGRawData
}
