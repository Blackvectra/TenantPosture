#Requires -Version 7.0
#
# Test-NRGDomainName.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# The one definition of "a domain name this tool will act on". The web GUI's
# scan route, the run listing's labels and Invoke-NRGAssessment.ps1 -TenantDomain
# all answer the same question, and three private regexes had drifted: the scan
# route took anything of letters, digits, dots and hyphens, the entry point took
# "a..b.com", and the path guard refused any name with ".." in it, so a scan could
# be started for a folder the GUI could then never open.
#
# A name is accepted when it is a fully qualified hostname as DNS defines it
# (RFC 1035 sizes, RFC 1123 labels): at most 253 characters, at least two
# labels, each 1-63 letters, digits or hyphens that neither starts nor ends with
# a hyphen, and a final label of two or more letters. No trailing dot, no
# underscore, no whitespace, no internationalized (non-ASCII) form: an IDN is
# given in its xn-- form, which the labels already allow.
#
# Two properties follow from the shape and are tested, because the GUI turns an
# accepted name into a folder name: an accepted name never contains ".." and never
# starts with a dot or hyphen, so it is always a valid path segment too.
#
# The pattern is anchored with \A and \z, never ^ and $: in .NET `$` also matches
# before a final line feed, so "contoso.com`n" would pass a `$`-anchored check.
# It is applied case-sensitively (-cmatch; Options = None on an attribute): a
# case-insensitive [A-Za-z] class admits the Kelvin sign (U+212A).
#
# The entry point cannot call this function: a ValidatePattern attribute is
# evaluated while the parameters bind, before any module is loaded. It carries
# a copy of the pattern instead, and NRG.WebServer.Tests.ps1 fails if that copy
# differs from Get-NRGDomainNamePattern. Change both together.
#
# Consumed:  nothing. Reads no file, makes no call.
# Graph scopes / cmdlets used: none.

# The pattern, as a string, so a caller that needs the text (a ValidatePattern
# copy, a test) reads it from here and does not retype it.
function Get-NRGDomainNamePattern {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return '\A(?=.{1,253}\z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\z'
}

function Test-NRGDomainName {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Value)

    if ([string]::IsNullOrEmpty($Value)) { return $false }
    return ($Value -cmatch (Get-NRGDomainNamePattern))
}
