#Requires -Version 7.0
<#
.SYNOPSIS
    Encodes a value for safe inclusion in HTML output.

.DESCRIPTION
    Wraps [System.Net.WebUtility]::HtmlEncode with null/empty handling appropriate
    for the publisher pipeline. All values flowing from Graph API responses, EXO
    cmdlets, DNS lookups, or any external source MUST be passed through this
    function before being interpolated into HTML strings.

    This is the single chokepoint for HTML output sanitization in the NRG
    Assessment publisher.

.NOTES
    Context safety:
      - Safe between tags:         <td>$encoded</td>
      - Safe in quoted attrs:      <a title="$encoded">
      - UNSAFE in unquoted attrs:  <a title=$encoded>          (do NOT use)
      - UNSAFE inside <script>:    <script>var x="$encoded"</script>  (do NOT use)
      - UNSAFE inside style:       <style>x: $encoded</style>          (do NOT use)
      - UNSAFE inside URL attrs:   <a href="$encoded">         (needs URL validation first)
#>
function ConvertTo-TPHtmlSafe {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [object] $Value
    )

    process {
        if ($null -eq $Value) { return '' }

        if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
            $flat = ($Value | ForEach-Object { [string]$_ }) -join ', '
            return [System.Net.WebUtility]::HtmlEncode($flat)
        }

        return [System.Net.WebUtility]::HtmlEncode([string]$Value)
    }
}

<#
.SYNOPSIS
    Validates a URL is safe to embed in an HTML href/src attribute.

.DESCRIPTION
    Returns the URL only if it parses as a valid absolute URI with an allowed
    scheme. Returns empty string otherwise — never returns user-controlled URLs
    that failed validation, to prevent javascript:, data:, vbscript:, and
    similar protocol-handler XSS.
#>
function ConvertTo-TPSafeUrl {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)]
        [AllowNull()]
        [AllowEmptyString()]
        [string] $Url,

        [string[]] $AllowedSchemes = @('https', 'mailto')
    )

    if ([string]::IsNullOrWhiteSpace($Url)) { return '' }

    try {
        $uri = [System.Uri]$Url
        if (-not $uri.IsAbsoluteUri) { return '' }
        if ($uri.Scheme -notin $AllowedSchemes) { return '' }
        return [System.Net.WebUtility]::HtmlEncode($uri.AbsoluteUri)
    } catch {
        return ''
    }
}
