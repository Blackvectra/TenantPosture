#Requires -Version 7.0
#
# ConvertTo-TPMarkdownSafe.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: The one Markdown escape for tenant-derived text. Every Markdown
#   deliverable (summary, playbook, SSP, NIST matrix, improvement plan, device
#   guide and baseline, delta report, HIPAA view, tenant comparison, the two
#   incident-response reports) renders finding text an attacker in the tenant
#   can choose: a rule name, a policy name, an app name. A Markdown viewer that
#   allows raw HTML would run `<img onerror>`; any viewer that loads images
#   fetches `![](https://attacker/...)` the moment the file is previewed, which
#   tells the attacker the report was opened. So the structural characters of
#   Markdown and of HTML are escaped, not only the table pipe.
# Data keys: none. Graph / cmdlets: none.

function ConvertTo-TPMarkdownSafe {
    <#
    .SYNOPSIS
        Escapes a value for a Markdown table cell or paragraph: line breaks and
        tabs become one space; backslash, pipe, backtick, brackets, emphasis, heading, blockquote, image and HTML-tag characters are
        backslash-escaped (CommonMark lets any ASCII punctuation be escaped).
        The text reads exactly as written and can form no link, image, code
        span, heading, or HTML element.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyString()] [object] $Value)
    if ($null -eq $Value) { return '' }
    $s = [string]$Value
    if ([string]::IsNullOrEmpty($s)) { return '' }
    $s = $s -replace '[\r\n\t]+', ' '
    # Backslash first, so the escapes added below are not themselves escaped.
    $s = $s -replace '\\', '\\'
    # Parentheses are left alone: with the brackets escaped no link or image can
    # form, and control ids such as AC-2(3) and ordinary prose read as written.
    $s = $s -replace '([|`\[\]*_#>!<~])', '\$1'
    return $s
}
