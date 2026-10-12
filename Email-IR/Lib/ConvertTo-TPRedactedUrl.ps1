#Requires -Version 7.0
#
# ConvertTo-TPRedactedUrl.ps1  (v4.14.x)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Data-minimization helpers for what the incident-response mode
#          writes. The mailbox collectors keep the URLs found in a message's
#          bodyPreview because a link is an indicator; the host and path are
#          the indicator, and a query string can carry a bearer credential
#          (a SharePoint or Azure Storage SAS `sig=`, an `access_token=`, a
#          password-reset `token=`), which the results JSON must not hold.
#          ConvertTo-TPRedactedUrl keeps the URL and replaces only the VALUE
#          of a credential-bearing parameter, and any userinfo before the
#          host, with [redacted]. ConvertTo-TPMaskedPhone keeps a registered
#          phone method recognizable on a call ("the number ending in 34")
#          without recording the number: the country code Microsoft prints
#          before the first space and the last two digits stay, every other
#          digit is `*`.
#
# Data keys: none (pure functions; called by Invoke-TPEmailCollectMailbox
#            and Invoke-TPEmailCollectUserSecurity before Set-TPRawData).
# Cmdlets:   none. No network.

# Parameter names whose value is a credential or a one-time secret. Compared
# case-insensitively after percent-decoding; a name ENDING in one of the
# suffixes below is redacted too (X-Amz-Signature, oauth_token, ...).
# Over-redaction costs an operator one parameter value; under-redaction
# writes a credential to disk, so the list errs wide.
$script:TPSensitiveUrlParameters = @(
    'sig', 'signature', 'token', 'access_token', 'id_token', 'refresh_token',
    'auth', 'authorization', 'auth_token', 'code', 'key', 'apikey', 'api_key',
    'secret', 'client_secret', 'password', 'pwd', 'passwd', 'pass', 'sas',
    'otp', 'session', 'sessionid', 'session_id', 'sid', 'ticket', 'hash',
    'credential', 'credentials', 'x-amz-signature', 'x-amz-credential',
    'x-amz-security-token', 'x-goog-signature', 'x-goog-credential',
    # one-time codes and authentication assertions carried by action links
    'oobcode', 'oob_code', 'nonce', 'assertion', 'samlresponse', 'saml_response',
    'jwt', 'bearer', 'pin', 'tan', 'mfa', 'totp', 'passcode', 'confirm', 'confirmation',
    'activation', 'invite', 'invitation', 'magic', 'login', 'verify', 'verification'
)
# A name ENDING in one of these is redacted too: oobCode, verificationCode,
# authKey, X-Amz-Signature, oauth_token, ... A benign name that happens to end
# the same way (zipcode, sortkey) loses one value; that is the accepted cost.
$script:TPSensitiveUrlParameterSuffixes = @('token', 'secret', 'password', 'passwd', 'signature', 'credential', 'code', 'key', 'nonce', 'assertion', 'otp', 'pin', 'ticket', 'session', 'auth')

function Test-TPSensitiveUrlParameterName {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Position = 0)] [AllowNull()] [AllowEmptyString()] [string] $Name
    )
    if ([string]::IsNullOrEmpty($Name)) { return $false }
    $decoded = $Name
    try { $decoded = [System.Uri]::UnescapeDataString($Name) } catch { $decoded = $Name }
    $n = $decoded.Trim().ToLowerInvariant()
    if ($n -in $script:TPSensitiveUrlParameters) { return $true }
    foreach ($suffix in $script:TPSensitiveUrlParameterSuffixes) {
        if ($n.Length -gt $suffix.Length -and $n.EndsWith($suffix, [System.StringComparison]::Ordinal)) { return $true }
    }
    return $false
}

# One k=v list, delimited by & or ; (some services accept both; a separator the
# split did not know hid `lang=en;token=SECRET` inside one benign pair): every
# pair whose name is sensitive has its value replaced, the delimiters are kept.
function Protect-TPUrlParameterList {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Text,
        [Parameter()] [int] $Depth = 0
    )
    if ([string]::IsNullOrEmpty($Text)) { return '' }
    $parts = [regex]::Split($Text, '([&;])')   # pairs and the delimiters between them, in order
    $sb = [System.Text.StringBuilder]::new()
    foreach ($part in $parts) {
        if ($part -eq '&' -or $part -eq ';') { [void]$sb.Append($part); continue }
        $eq = $part.IndexOf('=')
        if ($eq -lt 0) { [void]$sb.Append($part); continue }
        $name = $part.Substring(0, $eq)
        if (Test-TPSensitiveUrlParameterName -Name $name) { [void]$sb.Append($name).Append('=[redacted]'); continue }
        # A value that is itself a URL (a Safe Links or other rewriting wrapper
        # carries the destination in an ordinary parameter, percent-encoded)
        # is redacted the same way and put back in the form it arrived in.
        $value = $part.Substring($eq + 1)
        [void]$sb.Append($name).Append('=').Append((Protect-TPUrlParameterValue -Value $value -Depth $Depth))
    }
    return $sb.ToString()
}

# One parameter value: when it decodes to a URL, the URL is redacted (every
# rule of this file applies to it, nesting included, to a small depth) and
# re-encoded when it arrived encoded; any other value is returned as given.
function Protect-TPUrlParameterValue {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Value,
        [Parameter()] [int] $Depth = 0
    )
    if ([string]::IsNullOrEmpty($Value) -or $Depth -ge 4) { return $Value }
    $decoded = $Value
    try { $decoded = [System.Uri]::UnescapeDataString($Value.Replace('+', '%2B')) } catch { $decoded = $Value }
    if ($decoded -notmatch '^[A-Za-z][A-Za-z0-9+.-]*://') { return $Value }
    $inner = ConvertTo-TPRedactedUrl -Url $decoded -Depth ($Depth + 1)
    if ($inner -eq $decoded) { return $Value }
    if ($Value -ne $decoded) { return [System.Uri]::EscapeDataString($inner) }
    return $inner
}

function ConvertTo-TPRedactedUrl {
    <#
    .SYNOPSIS
        Returns the URL with the value of every credential-bearing parameter, and
        any userinfo before the host, replaced by [redacted]. Parameters are read
        in the query, and in the fragment as well: a hash-routed reset link
        (`#/reset?token=…`, whether or not an outer query precedes it) and an
        OAuth implicit-flow answer (`#access_token=…&id_token=…`) both carry the
        secret after the `#`. The scheme, host, path, ordinary parameters and the
        rest of the fragment are kept unchanged, so the link stays an indicator.
        Anything that is not a URL with parameters is returned as given.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)] [AllowNull()] [AllowEmptyString()] [string] $Url,
        [Parameter()] [int] $Depth = 0
    )
    if ([string]::IsNullOrEmpty($Url)) { return '' }
    # user:password@host — the regex the collectors use captures userinfo. The
    # LAST @ before the path, query or fragment is the authority delimiter (that
    # is how a browser reads a userinfo holding a second @, a mailbox address
    # before the password, say), so everything up to it is the userinfo.
    $out = [regex]::Replace($Url, '^(?<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?<userinfo>[^/?#\s]*@)', '${scheme}[redacted]@')
    # Split once into: everything before the first ? or # (never touched), the
    # query (after ? up to #), and the fragment (after #).
    $cut = [regex]::Match($out, '[?#]')
    if (-not $cut.Success) { return $out }
    $head = $out.Substring(0, $cut.Index)
    $rest = $out.Substring($cut.Index)
    $query = ''; $fragment = ''
    if ($rest.StartsWith('?')) {
        $h = $rest.IndexOf('#')
        if ($h -ge 0) { $query = $rest.Substring(1, $h - 1); $fragment = $rest.Substring($h + 1) }
        else { $query = $rest.Substring(1) }
        $hasQuery = $true
    } else {
        $fragment = $rest.Substring(1)
        $hasQuery = $false
    }
    $result = $head
    if ($hasQuery) { $result += '?' + (Protect-TPUrlParameterList -Text $query -Depth $Depth) }
    if ($rest.Contains('#')) {
        # Inside the fragment, parameters follow the first ? when there is one
        # (a hash route), else the whole fragment is the parameter list.
        $q = $fragment.IndexOf('?')
        if ($q -ge 0) { $fragment = $fragment.Substring(0, $q + 1) + (Protect-TPUrlParameterList -Text $fragment.Substring($q + 1) -Depth $Depth) }
        else { $fragment = Protect-TPUrlParameterList -Text $fragment -Depth $Depth }
        $result += '#' + $fragment
    }
    return $result
}

function ConvertTo-TPMaskedPhone {
    <#
    .SYNOPSIS
        Masks a phone number for the record while keeping it recognizable:
        the country code Microsoft Graph prints before the first space
        ("+1 2065550100" -> "+1 ********00") and the last two digits stay;
        every other digit becomes `*`. A number with no more than the kept
        digits is masked entirely.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Position = 0)] [AllowNull()] [AllowEmptyString()] [string] $PhoneNumber,
        [ValidateRange(0, 4)] [int] $KeepDigits = 2
    )
    if ([string]::IsNullOrEmpty($PhoneNumber)) { return '' }
    $countryCode = ''
    $national = $PhoneNumber
    $space = $PhoneNumber.IndexOf(' ')
    if ($PhoneNumber.StartsWith('+') -and $space -gt 0 -and $PhoneNumber.Substring(1, $space - 1) -match '^\d{1,3}$') {
        $countryCode = $PhoneNumber.Substring(0, $space + 1)
        $national = $PhoneNumber.Substring($space + 1)
    }
    $digitCount = 0
    foreach ($ch in $national.ToCharArray()) { if ([char]::IsDigit($ch)) { $digitCount++ } }
    $keepFrom = if ($digitCount -gt $KeepDigits) { $digitCount - $KeepDigits } else { $digitCount }
    $sb = [System.Text.StringBuilder]::new()
    $seen = 0
    foreach ($ch in $national.ToCharArray()) {
        if ([char]::IsDigit($ch)) {
            if ($seen -ge $keepFrom) { [void]$sb.Append($ch) } else { [void]$sb.Append('*') }
            $seen++
        } else {
            [void]$sb.Append($ch)
        }
    }
    return $countryCode + $sb.ToString()
}
