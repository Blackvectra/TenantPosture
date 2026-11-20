#Requires -Version 7.0
#
# Protect-TPMcpOutput.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose:  What the local MCP server (Start-TPMcpServer.ps1) does to every value
#           before it leaves the process: identities replaced with stable
#           per-session pseudonyms (unless the operator passed
#           -IncludeIdentities), invisible format characters stripped, long
#           strings and long lists cut with a marker that says so.
# Consumes: nothing from module state; operates on values it is handed.
# Graph scopes / cmdlets used: none. No network, no file write.
#
# Anything this server returns is sent to the AI provider behind the client, so
# the default is to keep people out of it. The rule is deliberately simple and
# its limits are stated in docs/TP-MCP-SERVER.md:
#   1. Every email-shaped string (UPNs, mailbox and SMTP addresses, including
#      Exchange's "x@y" [SMTP:x@y] form) becomes user-<n>.
#   2. Every value held under an identity key in a finding's AffectedObjects
#      (DisplayName, UserPrincipalName, Mailbox, Recipient, ...) is learned as an
#      identity, and every later occurrence of it in ANY returned string (Detail,
#      CurrentValue, Reason) becomes the same user-<n>.
# The map lives for the life of the process only and is never written anywhere.

# Keys whose values in AffectedObjects name a person or a mailbox. `Name` is not
# among them: in this tool's findings it names policies and rules, not people.
function Get-TPMcpIdentityKeys {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @(
        'DisplayName', 'UserDisplayName', 'PrincipalDisplayName', 'UserPrincipalName', 'Upn', 'PrincipalName',
        'Mail', 'Email', 'EmailAddress', 'PrimarySmtpAddress', 'Address', 'Mailbox', 'User', 'Users', 'UserName',
        'Account', 'Accounts', 'Owner', 'Owners', 'Member', 'Members', 'Recipient', 'Recipients',
        'Sender', 'Senders', 'ForwardTo', 'ForwardingAddress', 'Holder', 'Holders', 'Operator'
    )
}

# A fresh pseudonym map for one server process.
function New-TPMcpPseudonymMap {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    return @{
        Map     = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        Names   = [System.Collections.Generic.List[string]]::new()
        Pattern = $null
        Next    = 1
    }
}

function Get-TPMcpEmailPattern {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return '(?<![A-Za-z0-9._%+''-])[A-Za-z0-9._%+''-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![A-Za-z0-9-])'
}

# The pseudonym for one identity string, minted on first sight.
function Get-TPMcpPseudonym {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [hashtable] $State,
        [Parameter(Mandatory)] [string] $Value
    )
    $key = $Value.Trim()
    $alias = $null
    if ($State.Map.TryGetValue($key, [ref]$alias)) { return $alias }
    $alias = 'user-' + $State.Next
    $State.Next++
    $State.Map[$key] = $alias
    return $alias
}

# Learn one display-name-like value. Email-shaped values need no learning (the
# pattern catches them); very short or numeric values are not learned, because
# replacing "IT" or "1" everywhere would destroy the text around them.
function Add-TPMcpIdentityName {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $State,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Value
    )
    if ([string]::IsNullOrWhiteSpace($Value)) { return }
    # The same removal the returned text gets, or a name would stop matching it.
    $v = (Remove-TPMcpFormatCharacters -Text $Value).Trim()
    if ($v.Length -lt 3 -or $v.Length -gt 256) { return }
    if ($v -match '\A[\d\s.:/-]+\z') { return }
    if ($v -match '\A[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\z') { return }
    if ($v -match '\A(user|group|role):') { return }
    if ($v -match '\Auser-\d+\z') { return }
    if ($v -cmatch ('\A(?:' + (Get-TPMcpEmailPattern) + ')\z')) { return }
    if ($State.Names.Contains($v)) { return }
    $State.Names.Add($v)
    $null = Get-TPMcpPseudonym -State $State -Value $v
    $State.Pattern = $null
}

# Walk AffectedObjects (any depth up to a bound) and learn every value held
# under an identity key.
function Import-TPMcpIdentities {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $State,
        [Parameter()] [AllowNull()] [object] $Value,
        [int] $Depth = 0,
        [switch] $UnderIdentityKey
    )
    if ($null -eq $Value -or $Depth -gt 8) { return }
    if ($Value -is [string]) {
        if ($UnderIdentityKey) { Add-TPMcpIdentityName -State $State -Value $Value }
        return
    }
    if ($Value -is [System.Collections.IDictionary]) {
        foreach ($k in @($Value.Keys)) {
            Import-TPMcpIdentities -State $State -Value $Value[$k] -Depth ($Depth + 1) -UnderIdentityKey:((Get-TPMcpIdentityKeys) -contains [string]$k)
        }
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        foreach ($item in $Value) { Import-TPMcpIdentities -State $State -Value $item -Depth ($Depth + 1) -UnderIdentityKey:$UnderIdentityKey }
        return
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        foreach ($p in $Value.PSObject.Properties) {
            Import-TPMcpIdentities -State $State -Value $p.Value -Depth ($Depth + 1) -UnderIdentityKey:((Get-TPMcpIdentityKeys) -contains [string]$p.Name)
        }
    }
}

# One string without its invisible format characters, judged by Unicode code
# point. A .NET regular expression reads UTF-16 code units, so \p{Cf} reaches
# the Basic Multilingual Plane only: a format character above it is stored as a
# surrogate pair, each half is category Cs, and \p{Cf} never matches it. That
# let the tag characters (U+E0020-U+E007F: one per ASCII character, drawn by
# nothing) through to the client. The pairs are therefore named: the whole tag
# block, and the other format characters above the plane.
# A surrogate half with no partner is not a character and goes in the SAME
# pass: left in, the two halves on either side of a removed character would
# close up into a pair this function had refused.
function Remove-TPMcpFormatCharacters {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Text)
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    $pattern = '\p{Cf}' +                           # every format character in the Basic Multilingual Plane
        '|\uDB40[\uDC00-\uDC7F]' +                  # U+E0000-U+E007F  tag characters, the whole block
        '|\uD804[\uDCBD\uDCCD]' +                   # U+110BD, U+110CD Kaithi number signs
        '|\uD80D[\uDC30-\uDC3F]' +                  # U+13430-U+1343F  Egyptian hieroglyph format controls
        '|\uD82F[\uDCA0-\uDCA3]' +                  # U+1BCA0-U+1BCA3  shorthand format controls
        '|\uD834[\uDD73-\uDD7A]' +                  # U+1D173-U+1D17A  musical symbol format controls
        '|[\uD800-\uDBFF](?![\uDC00-\uDFFF])' +     # a high surrogate with no low surrogate after it
        '|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]'      # a low surrogate with no high surrogate before it
    return ($Text -creplace $pattern, '')
}

# One string as it may leave the process.
function Protect-TPMcpText {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Text,
        [Parameter()] [AllowNull()] [hashtable] $State,
        [int] $MaxLength = 2000
    )
    if ([string]::IsNullOrEmpty($Text)) { return $Text }
    # Invisible format characters (bidirectional overrides, zero-width, BOM,
    # tag characters) could hide text from the person reading the answer.
    $t = Remove-TPMcpFormatCharacters -Text $Text
    if ($null -ne $State) {
        if ($null -eq $State.Pattern) {
            # ONE pass over the text with one pattern (addresses first, then the
            # learned names, longest first), so a pseudonym already inserted is
            # never rescanned and rewritten.
            $alts = [System.Collections.Generic.List[string]]::new()
            $alts.Add((Get-TPMcpEmailPattern))
            foreach ($n in @($State.Names | Sort-Object -Property Length -Descending)) {
                $alts.Add('(?<![\p{L}\p{N}])' + [regex]::Escape($n) + '(?![\p{L}\p{N}])')
            }
            $State.Pattern = [regex]::new('(?:' + ($alts -join ')|(?:') + ')',
                [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
        }
        $t = $State.Pattern.Replace($t, { param($m) Get-TPMcpPseudonym -State $State -Value $m.Value })
    }
    if ($MaxLength -gt 0 -and $t.Length -gt $MaxLength) {
        $t = $t.Substring(0, $MaxLength) + " [truncated: $($t.Length - $MaxLength) more characters]"
    }
    return $t
}

# A whole value as it may leave the process: every string through
# Protect-TPMcpText, dates as ISO 8601 text, lists cut at -MaxItems with a
# marker string, nesting cut at -MaxDepth. Dictionaries and objects become
# ordered hashtables; the key names are the tool's own and are kept, less any
# invisible format character: a key reaches the client like any other string,
# and a results file is input.
function Protect-TPMcpValue {
    [CmdletBinding()]
    param(
        [Parameter()] [AllowNull()] [object] $Value,
        [Parameter()] [AllowNull()] [hashtable] $State,
        [int] $MaxLength = 2000,
        [int] $MaxItems = 50,
        [int] $MaxDepth = 8,
        [int] $Depth = 0
    )
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) { return (Protect-TPMcpText -Text $Value -State $State -MaxLength $MaxLength) }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture) }
    if ($Value -is [datetimeoffset]) { return $Value.ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture) }
    if ($Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [single]) { return $Value }
    if ($Value -is [enum] -or $Value -is [guid] -or $Value -is [char]) { return (Protect-TPMcpText -Text ([string]$Value) -State $State -MaxLength $MaxLength) }
    if ($Depth -ge $MaxDepth) { return '[nested value not shown: depth limit]' }
    $next = $Depth + 1
    if ($Value -is [System.Collections.IDictionary]) {
        $out = [ordered]@{}
        foreach ($k in @($Value.Keys)) {
            $out[(Remove-TPMcpFormatCharacters -Text ([string]$k))] = Protect-TPMcpValue -Value $Value[$k] -State $State -MaxLength $MaxLength -MaxItems $MaxItems -MaxDepth $MaxDepth -Depth $next
        }
        return $out
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $out = [ordered]@{}
        foreach ($p in $Value.PSObject.Properties) {
            $out[(Remove-TPMcpFormatCharacters -Text ([string]$p.Name))] = Protect-TPMcpValue -Value $p.Value -State $State -MaxLength $MaxLength -MaxItems $MaxItems -MaxDepth $MaxDepth -Depth $next
        }
        return $out
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $list = [System.Collections.Generic.List[object]]::new()
        $n = 0
        foreach ($item in $Value) {
            $n++
            if ($MaxItems -gt 0 -and $n -gt $MaxItems) { continue }
            $list.Add((Protect-TPMcpValue -Value $item -State $State -MaxLength $MaxLength -MaxItems $MaxItems -MaxDepth $MaxDepth -Depth $next))
        }
        if ($MaxItems -gt 0 -and $n -gt $MaxItems) { $list.Add("[truncated: $($n - $MaxItems) more items not shown]") }
        return , $list.ToArray()
    }
    return (Protect-TPMcpText -Text ([string]$Value) -State $State -MaxLength $MaxLength)
}
