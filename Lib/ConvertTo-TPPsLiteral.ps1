#Requires -Version 7.0
#
# ConvertTo-TPPsLiteral.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: The one rule for putting a value into a single-quoted PowerShell literal,
#   whether the literal lands in a generated .ps1 the engineer will RUN or in a
#   .psd1 data file Import-PowerShellDataFile will READ. PowerShell's tokenizer
#   treats U+2018..U+201B as single-quote characters even inside a '...' literal,
#   and U+2028/U+2029/U+0085 are not line terminators to it but are to editors,
#   so doubling the ASCII apostrophe alone is not enough: a curly quote (which
#   Word and phone keyboards substitute automatically) ends the literal early.
#   Also validates findings replayed from a results JSON before any publisher
#   sees them, because Add-TPFinding's parameter validation never ran on them.
# Data keys: none. Graph / cmdlets: none.

$script:TPCurlyQuoteCodePoints = @(0x2018, 0x2019, 0x201A, 0x201B)
$script:TPLineSeparatorCodePoints = @(0x0085, 0x2028, 0x2029)
$script:TPReplayedControlIdPattern = '^[A-Z]{2,8}-\d+\.\d+$'
$script:TPReplayedStates = @('Satisfied', 'Partial', 'Gap', 'NotApplicable', 'Error')
$script:TPReplayedSeverities = @('Critical', 'High', 'Medium', 'Low', 'Informational')

function Test-TPPsLiteralSafe {
    <#
    .SYNOPSIS
        True when the value can sit inside a single-quoted literal with only the
        ASCII apostrophe doubled: no curly quotes, no line breaks or separators,
        no NUL, no control or format characters.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] [AllowEmptyString()] [string] $Value)
    $v = [string]$Value
    foreach ($cp in ($script:TPCurlyQuoteCodePoints + $script:TPLineSeparatorCodePoints)) {
        if ($v.Contains([string][char]$cp)) { return $false }
    }
    if ($v -match '[\r\n\0]') { return $false }
    if ($v -match '[\p{Cf}\p{Cc}\p{Zl}\p{Zp}]' -or $v -match '\uDB40[\uDC00-\uDC7F]') { return $false }
    return $true
}

function ConvertTo-TPPsLiteral {
    <#
    .SYNOPSIS
        A value as a single-quoted literal for a generated SCRIPT, or $null when
        it cannot be quoted safely. A script line is withheld, never guessed at.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyString()] [string] $Value)
    $v = [string]$Value
    if (-not (Test-TPPsLiteralSafe -Value $v)) { return $null }
    return "'" + ($v -replace "'", "''") + "'"
}

function ConvertTo-TPPsd1String {
    <#
    .SYNOPSIS
        A value as a single-quoted literal for a DATA file. Data is kept, not
        withheld: curly quotes become the ASCII apostrophe (doubled), line
        separators and line breaks become one space, and control or format
        characters are dropped. The result always re-reads as the intended text
        through Import-PowerShellDataFile, which never executes anything.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyString()] [string] $Value)
    $v = [string]$Value
    foreach ($cp in $script:TPCurlyQuoteCodePoints) { $v = $v.Replace([string][char]$cp, "'") }
    foreach ($cp in $script:TPLineSeparatorCodePoints) { $v = $v.Replace([string][char]$cp, ' ') }
    $v = $v -replace '[\r\n]+', ' '
    $v = $v -replace '\uDB40[\uDC00-\uDC7F]', ''
    $v = $v -replace '[\p{Cf}\p{Cc}\p{Zl}\p{Zp}]', ''
    return "'" + ($v -replace "'", "''") + "'"
}

function Select-TPReplayedFinding {
    <#
    .SYNOPSIS
        Keeps only the findings from a replayed results file that Add-TPFinding
        would have accepted: a ControlId of the tool's shape, a known State and
        a known Severity. Anything else is dropped and named, because the
        publishers (and the generated remediation script) trust those fields.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Findings,
        [ref] $Dropped
    )
    $kept = [System.Collections.Generic.List[object]]::new()
    $bad  = [System.Collections.Generic.List[string]]::new()
    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $id  = [string](Get-TPObjectField -Item $f -Key 'ControlId' -Default '')
        $st  = [string](Get-TPObjectField -Item $f -Key 'State'     -Default '')
        $sev = [string](Get-TPObjectField -Item $f -Key 'Severity'  -Default '')
        $why = $null
        if ($id -cnotmatch $script:TPReplayedControlIdPattern) { $why = 'ControlId is not a control id' }
        elseif ($st -cnotin $script:TPReplayedStates)           { $why = "State '$st' is not a finding state" }
        elseif ($sev -cnotin $script:TPReplayedSeverities)      { $why = "Severity '$sev' is not a severity" }
        if ($why) {
            $shown = ($id -replace '[^\x20-\x7E]', '?')
            if ($shown.Length -gt 40) { $shown = $shown.Substring(0, 40) + '...' }
            $bad.Add("'$shown': $why")
            continue
        }
        $kept.Add($f)
    }
    if ($PSBoundParameters.ContainsKey('Dropped') -and $null -ne $Dropped) { $Dropped.Value = @($bad) }
    return [object[]]$kept.ToArray()
}

function Test-TPPsd1EntriesRoundTrip {
    <#
    .SYNOPSIS
        Proves a block of PSD1 entries re-reads as exactly the ids that were
        written, by parsing it with Import-PowerShellDataFile before the file
        is created. Throws, naming the problem, instead of writing a file that
        drops every answer or carries an entry nobody wrote.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $EntriesText,
        [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z]+$')] [string] $Block,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $ExpectedIds
    )
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-psd1-check-" + [guid]::NewGuid().ToString('N') + '.psd1')
    try {
        [System.IO.File]::WriteAllText($tmp, "@{`n    $Block = @{`n$EntriesText`n    }`n}`n", [System.Text.UTF8Encoding]::new($false))
        try { $d = Import-PowerShellDataFile -LiteralPath $tmp -ErrorAction Stop }
        catch { throw "The generated $Block entries do not parse as a PowerShell data file; nothing was written. $($_.Exception.Message)" }
        $got = @((Get-TPObjectField -Item $d -Key $Block -Default @{}).Keys | ForEach-Object { [string]$_ } | Sort-Object)
        $want = @($ExpectedIds | ForEach-Object { [string]$_ } | Sort-Object)
        $diff = @(Compare-Object -ReferenceObject $want -DifferenceObject $got)
        if ($diff.Count -gt 0) {
            $extra   = @($diff | Where-Object SideIndicator -eq '=>' | ForEach-Object InputObject)
            $missing = @($diff | Where-Object SideIndicator -eq '<=' | ForEach-Object InputObject)
            throw ("The generated $Block entries re-read with a different id set; nothing was written. Missing: {0}. Unexpected: {1}." -f (($missing -join ', '), ($extra -join ', ')))
        }
        return $true
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}
