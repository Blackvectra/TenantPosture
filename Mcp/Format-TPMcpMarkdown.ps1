#Requires -Version 7.0
#
# Format-TPMcpMarkdown.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose:  Renders a tool's answer as readable Markdown for a call that asks
#           for response_format = markdown (Start-TPMcpServer.ps1). The answer
#           is the same object the JSON text and structuredContent carry, after
#           Protect-TPMcpValue has pseudonymized and capped it: this file only
#           changes how it is laid out, never what it says.
# Consumes: the protected answer object. Every key and value goes through
#           ConvertTo-TPMarkdownSafe, the tool's one Markdown escape, so tenant
#           text (policy names, finding detail) can form no link, image, code
#           span, heading or HTML element.
# Graph scopes / cmdlets used: none. No network, no file write.

# A flat object (every value a scalar) renders as one table row.
function Test-TPMcpFlatRecord {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter()] [AllowNull()] [object] $Value)
    if ($Value -isnot [System.Collections.IDictionary]) { return $false }
    foreach ($k in @($Value.Keys)) {
        $v = $Value[$k]
        if ($v -is [System.Collections.IDictionary]) { return $false }
        if ($v -is [System.Collections.IEnumerable] -and $v -isnot [string]) {
            # A short list of scalars still fits in a cell.
            foreach ($x in @($v)) { if ($x -is [System.Collections.IDictionary] -or ($x -is [System.Collections.IEnumerable] -and $x -isnot [string])) { return $false } }
        }
    }
    return $true
}

function ConvertTo-TPMcpMarkdownScalar {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter()] [AllowNull()] [object] $Value)
    if ($null -eq $Value) { return '(none)' }
    if ($Value -is [bool]) { return $(if ($Value) { 'yes' } else { 'no' }) }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $parts = @($Value | ForEach-Object { ConvertTo-TPMcpMarkdownScalar -Value $_ })
        if ($parts.Count -eq 0) { return '(none)' }
        return ($parts -join ', ')
    }
    $text = ConvertTo-TPMarkdownSafe ([string]$Value)
    if ($text -eq '') { return '(empty)' }
    return $text
}

function Add-TPMcpMarkdownBlock {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Text.StringBuilder] $Builder,
        [Parameter()] [AllowNull()] [object] $Value,
        [Parameter(Mandatory)] [int] $Level
    )
    $h = '#' * [math]::Min(6, $Level)
    if ($Value -isnot [System.Collections.IDictionary]) {
        $null = $Builder.AppendLine((ConvertTo-TPMcpMarkdownScalar -Value $Value))
        return
    }
    # Scalars first, as a list; then each nested object or list under its own heading.
    $scalarKeys = @($Value.Keys | Where-Object { $v = $Value[$_]; -not ($v -is [System.Collections.IDictionary] -or ($v -is [System.Collections.IEnumerable] -and $v -isnot [string] -and @($v | Where-Object { $_ -is [System.Collections.IDictionary] }).Count -gt 0)) })
    foreach ($k in $scalarKeys) {
        $null = $Builder.AppendLine("- **$(ConvertTo-TPMarkdownSafe ([string]$k)):** $(ConvertTo-TPMcpMarkdownScalar -Value $Value[$k])")
    }
    if ($scalarKeys.Count) { $null = $Builder.AppendLine() }
    foreach ($k in @($Value.Keys)) {
        if ($k -in $scalarKeys) { continue }
        $v = $Value[$k]
        $null = $Builder.AppendLine("$h $(ConvertTo-TPMarkdownSafe ([string]$k))")
        $null = $Builder.AppendLine()
        if ($v -is [System.Collections.IDictionary]) {
            Add-TPMcpMarkdownBlock -Builder $Builder -Value $v -Level ($Level + 1)
            continue
        }
        $rows = @($v | Where-Object { $null -ne $_ })
        if ($rows.Count -gt 0 -and @($rows | Where-Object { -not (Test-TPMcpFlatRecord -Value $_) }).Count -eq 0) {
            # A list of flat records: one table, columns in first-seen order.
            $cols = [System.Collections.Generic.List[string]]::new()
            foreach ($r in $rows) { foreach ($c in @($r.Keys)) { if (-not $cols.Contains([string]$c)) { $cols.Add([string]$c) } } }
            $null = $Builder.AppendLine('| ' + (@($cols | ForEach-Object { ConvertTo-TPMarkdownSafe $_ }) -join ' | ') + ' |')
            $null = $Builder.AppendLine('|' + (@($cols | ForEach-Object { '---' }) -join '|') + '|')
            foreach ($r in $rows) {
                $null = $Builder.AppendLine('| ' + (@($cols | ForEach-Object { if ($r.Contains($_)) { ConvertTo-TPMcpMarkdownScalar -Value $r[$_] } else { '' } }) -join ' | ') + ' |')
            }
            $null = $Builder.AppendLine()
            continue
        }
        $n = 0
        foreach ($r in $rows) {
            $n++
            if ($r -is [System.Collections.IDictionary]) {
                $null = $Builder.AppendLine("$('#' * [math]::Min(6, $Level + 1)) $(ConvertTo-TPMarkdownSafe ([string]$k)) $n")
                $null = $Builder.AppendLine()
                Add-TPMcpMarkdownBlock -Builder $Builder -Value $r -Level ($Level + 2)
            } else {
                $null = $Builder.AppendLine("- $(ConvertTo-TPMcpMarkdownScalar -Value $r)")
            }
        }
        if ($rows.Count -eq 0) { $null = $Builder.AppendLine('(none)') }
        $null = $Builder.AppendLine()
    }
}

# The whole answer as Markdown, under the tool's title.
function ConvertTo-TPMcpMarkdown {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Title,
        [Parameter()] [AllowNull()] [object] $Value
    )
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("# $(ConvertTo-TPMarkdownSafe $Title)")
    $null = $sb.AppendLine()
    Add-TPMcpMarkdownBlock -Builder $sb -Value $Value -Level 2
    return $sb.ToString().TrimEnd()
}
