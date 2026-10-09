#Requires -Version 7.0
#
# ConvertTo-TPSSPAnswerPsd1.ps1
# Dependencies: none.
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Serializes ONE requirement's answer into the exact PowerShell Data
#          Language text Config/ssp/*.psd1 already uses, for
#          Import-TPSSPQuestionnaire.ps1 to write. Import-PowerShellDataFile
#          parses a .psd1 but discards every comment doing it — round-tripping
#          an EXISTING answers file through Import then re-serializing the
#          whole thing back out would silently delete the hand-written
#          explanations Config/ssp/example.psd1 is full of. This function
#          therefore only ever produces a single requirement's block; the
#          importer decides separately whether that block is safe to write
#          into a brand-new file or must be handed to the operator to paste
#          into an existing one by hand.
#
# Inputs:  -Id       the requirement id ('3.1.1'), used as the hashtable key.
#          -Answer   [ordered] hashtable: Status, ResponsibleRole, Narrative,
#                     NotApplicableReason, InheritedFrom, Poam (nested
#                     ordered hashtable: Weakness/Remedy/Owner/DueDate).
#                     A key with an empty/whitespace string value is OMITTED
#                     from the output — the same "omitting is honest" rule
#                     example.psd1 documents for a whole requirement applies
#                     per field: a blank answer must render as nothing, never
#                     as `Field = ''`, which a reader could mistake for a
#                     deliberate empty statement.
#          -Indent   base indentation level (each level = 4 spaces).
#
# Outputs: string — one `'<id>' = @{ ... }` block, no trailing newline.
#
# Consumes: nothing. No Graph, no EXO, no network, no filesystem.
#

function ConvertTo-TPSSPPsd1String {
    <#
        Quotes and escapes a scalar for PowerShell Data Language: single
        quotes only (a .psd1 is parsed as data, never expanded, so a double-
        quoted string with a stray '$' would be a needless second escaping
        rule to get right) and each embedded ' doubled per the language spec.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowNull()] [AllowEmptyString()]
        [string] $Value
    )
    Set-StrictMode -Version Latest
    if ($null -eq $Value) { $Value = '' }
    "'" + ($Value -replace "'", "''") + "'"
}

function ConvertTo-TPSSPAnswerPsd1 {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $true)]
        [string] $Id,

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
    $lines.Add("$pad0" + (ConvertTo-TPSSPPsd1String -Value $Id) + ' = @{')

    foreach ($field in @('Status', 'ResponsibleRole', 'Narrative', 'NotApplicableReason', 'InheritedFrom')) {
        if (-not $Answer.Contains($field)) { continue }
        $v = [string]$Answer[$field]
        if ([string]::IsNullOrWhiteSpace($v)) { continue }
        $lines.Add("$pad1$field = " + (ConvertTo-TPSSPPsd1String -Value $v))
    }

    if ($Answer.Contains('Poam') -and $null -ne $Answer['Poam']) {
        $poam = $Answer['Poam']
        $poamLines = [System.Collections.Generic.List[string]]::new()
        foreach ($field in @('Weakness', 'Remedy', 'Owner', 'DueDate')) {
            if (-not $poam.Contains($field)) { continue }
            $v = [string]$poam[$field]
            if ([string]::IsNullOrWhiteSpace($v)) { continue }
            $poamLines.Add("$pad2$field = " + (ConvertTo-TPSSPPsd1String -Value $v))
        }
        # An empty Poam block (every sub-field blank) is omitted entirely —
        # `Poam = @{}` asserts a POA&M exists with nothing in it, which is
        # worse than not mentioning one.
        if ($poamLines.Count -gt 0) {
            $lines.Add("$pad1" + 'Poam = @{')
            $lines.AddRange($poamLines)
            $lines.Add("$pad1}")
        }
    }

    $lines.Add("$pad0}")
    return ($lines -join "`n")
}
