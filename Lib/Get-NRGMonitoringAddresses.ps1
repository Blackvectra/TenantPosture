#Requires -Version 7.0
#
# Get-NRGMonitoringAddresses.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: The NRG monitoring addresses an assessment is told to look for, and
#          the check that an alert policy notifies one of them.
#
#          "Alert policies have recipients" and "alerts reach NRG" are different
#          claims: a policy can notify a departed admin's mailbox and read as
#          configured. DEF-3.4 and EXO-3.3 therefore compare each enabled
#          policy's recipients with an EXPLICIT configured list, never with a
#          guess and never with an address hardcoded in code. When no list is
#          configured the routing half of those controls is not assessed (the
#          recipients-exist half stays verified and is reported).
#
#          Configured, in precedence order: -MonitoringAddress on
#          Invoke-NRGAssessment.ps1, the client's MonitoringAddresses in
#          Config/clients.json, MonitoringAddresses in Config/branding.psd1.
#          An entry is an address (alerts@example.com) or a whole domain
#          (@example.com).
#
# Data keys set: Config-MonitoringAddresses.  Graph scopes / cmdlets: none.

function Test-NRGMonitoringAddressEntry {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] [AllowEmptyString()] [string] $Entry)
    if ([string]::IsNullOrWhiteSpace($Entry)) { return $false }
    return ($Entry.Trim() -match '^[^@\s,;]+@[^@\s,;]+\.[^@\s,;]+$') -or ($Entry.Trim() -match '^@[^@\s,;]+\.[^@\s,;]+$')
}

function Set-NRGMonitoringAddresses {
    <#
    .SYNOPSIS
        Records the configured monitoring addresses as raw data so evaluators
        (and a replayed results file) can read them. Entries that are not an
        address or an @domain are dropped and reported, never guessed at.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [AllowNull()] [string[]] $Addresses,
        [string] $Source = ''
    )
    $valid = [System.Collections.Generic.List[string]]::new()
    foreach ($a in @($Addresses)) {
        foreach ($tok in ([string]$a -split '[,;\s]+')) {
            if ([string]::IsNullOrWhiteSpace($tok)) { continue }
            if (Test-NRGMonitoringAddressEntry -Entry $tok) {
                $l = $tok.Trim().ToLowerInvariant()
                if (-not $valid.Contains($l)) { $valid.Add($l) }
            } else { Write-Warning "Ignoring monitoring address '$tok': use an address (alerts@example.com) or a domain (@example.com)." }
        }
    }
    if ($valid.Count -gt 0) {
        Set-NRGRawData -Key 'Config-MonitoringAddresses' -Data ([ordered]@{
            CollectorId = 'Config-MonitoringAddresses'
            CollectedAt = (Get-Date).ToString('o')
            Success     = $true
            Data        = [ordered]@{ Addresses = @($valid); Source = $Source }
        })
    }
    return @($valid)
}

function Get-NRGMonitoringAddresses {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    $raw = Get-NRGRawData -Key 'Config-MonitoringAddresses'
    if (-not $raw -or -not (Get-NRGObjectField -Item $raw -Key 'Success' -Default $false)) { return @() }
    return @(@(Get-NRGNestedProperty -Object $raw -Path 'Data.Addresses' -Default @()) | ForEach-Object { ([string]$_).ToLowerInvariant() } | Where-Object { $_ })
}

function Get-NRGAlertRouting {
    <#
    .SYNOPSIS
        Splits alert policies into those that notify a configured monitoring
        address and those that do not. A policy with no recipients at all is
        Unrouted too (and is reported separately by the evaluators).
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Policies,
        [AllowNull()] [AllowEmptyCollection()] [string[]] $Addresses
    )
    $addrs = @($Addresses | Where-Object { $_ })
    $routed = [System.Collections.Generic.List[object]]::new()
    $unrouted = [System.Collections.Generic.List[object]]::new()
    foreach ($p in @($Policies)) {
        if ($null -eq $p) { continue }
        $recips = @(@(Get-NRGObjectField -Item $p -Key 'NotifyUser' -Default @()) | ForEach-Object { ([string]$_).Trim().ToLowerInvariant() } | Where-Object { $_ })
        $hit = $false
        foreach ($r in $recips) {
            foreach ($a in $addrs) {
                if ($r -eq $a -or ($a.StartsWith('@') -and $r.EndsWith($a))) { $hit = $true; break }
            }
            if ($hit) { break }
        }
        if ($hit) { $routed.Add($p) } else { $unrouted.Add($p) }
    }
    return [ordered]@{ Configured = ($addrs.Count -gt 0); Routed = @($routed); Unrouted = @($unrouted) }
}
