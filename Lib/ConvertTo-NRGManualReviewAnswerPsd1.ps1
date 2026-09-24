#Requires -Version 7.0
#
# ConvertTo-NRGManualReviewAnswerPsd1.ps1
# Dependencies: ConvertTo-NRGSSPPsd1String (Lib/ConvertTo-NRGSSPAnswerPsd1.ps1).
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Serializes ONE control's manual-review answer into PowerShell Data
#          Language text, mirroring ConvertTo-NRGSSPAnswerPsd1.ps1 but for
#          the controls.json manual-review answer shape (Status, Evidence,
#          Owner, NotApplicableReason, CompensatingControl, RiskAcceptance,
#          Poam) instead of the NIST 800-171 SSP one. Reuses
#          ConvertTo-NRGSSPPsd1String for scalar quoting/escaping rather than
#          duplicating it — that function is generic PowerShell Data
#          Language string quoting, nothing SSP-specific about it.
#
#          Same reason as the SSP serializer: Import-NRGManualReviewQuestionnaire.ps1
#          never re-serializes a WHOLE existing answers file (which would
#          discard its hand-written comments), only ever a single control's
#          block for the caller to place.
#
# Inputs:  -ControlId  the control id ('SPO-2.2'), used as the hashtable key.
#          -Answer     [ordered] hashtable: Status, Evidence, Owner,
#                       NotApplicableReason, CompensatingControl,
#                       RiskAcceptance, Poam (nested ordered hashtable:
#                       Weakness/Remedy/Owner/DueDate). A key with an empty
#                       value is OMITTED — a blank answer must render as
#                       nothing, never as `Field = ''`.
#          -Indent     base indentation level (each level = 4 spaces).
#
# Outputs: string — one `'<ControlId>' = @{ ... }` block, no trailing newline.
#
# Consumes: nothing. No Graph, no EXO, no network, no filesystem.
#

function ConvertTo-NRGManualReviewAnswerPsd1 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string] $ControlId,

        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary] $Answer,

        [Parameter(Mandatory = $false)]
        [int] $Indent = 2
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $pad0 = ' ' * (4 * $Indent)
    $pad1 = ' ' * (4 * ($Indent + 1))
    $pad2 = ' ' * (4 * ($Indent + 2))

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("$pad0" + (ConvertTo-NRGSSPPsd1String -Value $ControlId) + ' = @{')

    foreach ($field in @('Status', 'Evidence', 'Owner', 'NotApplicableReason', 'CompensatingControl', 'RiskAcceptance')) {
        if (-not $Answer.Contains($field)) { continue }
        $v = [string]$Answer[$field]
        if ([string]::IsNullOrWhiteSpace($v)) { continue }
        $lines.Add("$pad1$field = " + (ConvertTo-NRGSSPPsd1String -Value $v))
    }

    if ($Answer.Contains('Poam') -and $null -ne $Answer['Poam']) {
        $poam = $Answer['Poam']
        $poamLines = [System.Collections.Generic.List[string]]::new()
        foreach ($field in @('Weakness', 'Remedy', 'Owner', 'DueDate')) {
            if (-not $poam.Contains($field)) { continue }
            $v = [string]$poam[$field]
            if ([string]::IsNullOrWhiteSpace($v)) { continue }
            $poamLines.Add("$pad2$field = " + (ConvertTo-NRGSSPPsd1String -Value $v))
        }
        # An empty Poam block is omitted entirely, same rule as the SSP
        # serializer — `Poam = @{}` asserts a POA&M exists with nothing in
        # it, which is worse than not mentioning one.
        if ($poamLines.Count -gt 0) {
            $lines.Add("$pad1" + 'Poam = @{')
            $lines.AddRange($poamLines)
            $lines.Add("$pad1}")
        }
    }

    $lines.Add("$pad0}")
    return ($lines -join "`n")
}
