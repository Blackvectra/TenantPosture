#
# Get-NRGControlDefinitions.ps1
# Loads control + framework JSON definitions from Config/
#

function Get-NRGControlDefinitions {
    [CmdletBinding()] param()

    $controlsPath   = Join-Path $script:NRGModuleRoot 'Config\controls.json'
    $frameworksPath = Join-Path $script:NRGModuleRoot 'Config\frameworks.json'

    if (-not (Test-Path $controlsPath)) {
        throw "Control definitions missing: $controlsPath"
    }

    $controls = Get-Content $controlsPath -Raw | ConvertFrom-Json

    $frameworks = if (Test-Path $frameworksPath) {
        Get-Content $frameworksPath -Raw | ConvertFrom-Json
    } else { $null }

    return [PSCustomObject]@{
        Controls   = $controls
        Frameworks = $frameworks
    }
}

function Get-NRGControlById {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ControlId)

    $defs = Get-NRGControlDefinitions
    return ($defs.Controls | Where-Object { $_.ControlId -eq $ControlId } | Select-Object -First 1)
}

function Get-NRGFrameworkCitations {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ControlId)

    $control = Get-NRGControlById -ControlId $ControlId
    if (-not $control) { return @() }

    $citations = @()
    foreach ($fwKey in $control.Frameworks.PSObject.Properties.Name) {
        $values = $control.Frameworks.$fwKey
        if ($values) {
            $valStr = ($values -join ', ')
            $citations += "${fwKey}: $valStr"
        }
    }
    return $citations
}
