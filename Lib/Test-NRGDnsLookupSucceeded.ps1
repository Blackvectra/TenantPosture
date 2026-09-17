#Requires -Version 7.0
#
# Test-NRGDnsLookupSucceeded.ps1
# Dependencies: Get-NRGObjectField
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Answers "did the DNS lookup for this record type actually complete?" for one
# domain entry from the DNS collector.
#
# Sets:     nothing (pure function)
# Consumes: Data.Domains.<domain>.LookupStatus, set by
#           Invoke-NRGCollectDNSEmailRecords from Resolve-NRGDns -Outcome.
# Cmdlets:  none.
#
# WHY THIS EXISTS
# ---------------
# An ABSENT SPF / DMARC / MTA-STS / CAA record is a Gap — correctly, because a
# domain without SPF really can be spoofed. But `$d.SPF` is `$null` both when
# the domain has no SPF record AND when every resolver we asked failed, and the
# evaluator cannot tell those apart. Reporting the second as the first tells a
# client their email authentication is missing when it is not — a false finding
# delivered in the deliverable an MSP sells remediation from.
#
# This is the same ambiguity `SectionStatus` resolves for collector sections and
# `Get-NRGRecipientClass` resolves for recipients: an empty result is not
# evidence of absence unless you know the query succeeded.
#
# An ABSENT LookupStatus is treated as success, so result JSON replayed from a
# run before this field existed keeps its previous behaviour — the same
# compatibility rule SectionStatus uses.

function Test-NRGDnsLookupSucceeded {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        # One per-domain entry from Data.Domains.
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $Domain,

        # 'SPF' | 'DMARC' | 'MTASTS' | 'TLSRPT' | 'DNSSEC' | 'MX' | 'CAA'
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Record
    )

    Set-StrictMode -Version Latest

    if ($null -eq $Domain) { return $false }

    $map = Get-NRGObjectField -Item $Domain -Key 'LookupStatus' -Default $null
    if ($null -eq $map) { return $true }   # pre-change result JSON

    $state = Get-NRGObjectField -Item $map -Key $Record -Default $null
    if ($null -eq $state -or [string]::IsNullOrWhiteSpace([string]$state)) { return $true }

    # Only an explicit LookupFailed suppresses a verdict. 'Answered' and
    # 'NoRecord' are both real answers.
    return ([string]$state -ne 'LookupFailed')
}
