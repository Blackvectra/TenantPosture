#Requires -Version 7.0
#
# Get-TPClientRecord.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Purpose: The one reader of "which client record does this run use". A clients file is
#          { "clients": [ ... ] } (a bare array is accepted too); a record is chosen by its
#          TenantDomain. The entry point reads the declared EDR and awareness products, the
#          monitoring addresses, the baseline tier, the opt-in collectors and the routing domain
#          from it, so a run that reads a different file than the batch runner was given loses
#          every one of those without a word. Both runners now name the file explicitly.
#
#          Dot-sourced by Invoke-TPAssessment.ps1 and Invoke-TPBatchAssessment.ps1 before the
#          module import (so a bad file stops the run before anything connects) and loaded by
#          the module like every Lib file. It reads only through PSObject.Properties, because a
#          client record is operator-written and fields are optional.
#
# Inputs:  -Path (the clients file), -TenantDomain (the record to find; may be empty to check
#          only that the file is readable).
# Output:  [pscustomobject] Status (Found, NotListed, NoFile, Unreadable), Record, Path, Message.
# Cmdlets: Test-Path, Get-Content, ConvertFrom-Json.

# The one product-name rule for a declared EDR or awareness platform ('Cortex XDR', 'KnowBe4').
# Set-TPThirdPartyEdr and Set-TPThirdPartyAwareness carry the same character class in a
# parameter attribute, which cannot call a function; TP.BatchClientsFile.Tests.ps1 fails if the
# three differ. Anchored with \A and \z: a trailing line feed is not part of a product name.
function Get-TPProductNamePattern { '\A[A-Za-z0-9][A-Za-z0-9 .&()+/-]{1,59}\z' }

function Get-TPClientRecord {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [AllowNull()] [AllowEmptyString()] [string] $TenantDomain = ''
    )
    $make = {
        param($status, $record, $message)
        [pscustomobject]@{ Status = $status; Record = $record; Path = $Path; Message = $message }
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return (& $make 'NoFile' $null "There is no clients file at $Path.")
    }
    $raw = $null
    try {
        $raw = Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return (& $make 'Unreadable' $null "The clients file $Path is not valid JSON ($($_.Exception.Message)).")
    }
    if ($null -eq $raw) {
        return (& $make 'Unreadable' $null "The clients file $Path is empty.")
    }
    $list = if ($raw.PSObject.Properties['clients']) { @($raw.clients) } else { @($raw) }
    if ([string]::IsNullOrEmpty($TenantDomain)) { return (& $make 'NotListed' $null '') }
    $hit = @($list | Where-Object { $_ -and $_.PSObject.Properties['TenantDomain'] -and $_.TenantDomain -eq $TenantDomain }) | Select-Object -First 1
    if ($hit) { return (& $make 'Found' $hit '') }
    return (& $make 'NotListed' $null "No record for $TenantDomain in $Path.")
}
