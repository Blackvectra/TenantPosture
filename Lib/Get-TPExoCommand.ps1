#Requires -Version 7.0
#
# Get-TPExoCommand.ps1
# TenantPosture
# Author: Matthew Levorson
# Purpose: Resolve an Exchange cmdlet from a SPECIFIC session (Exchange Online
#          or Security & Compliance) when both are connected in one process.
#
# Sets:     nothing (pure lookup)
# Consumes: nothing
# Cmdlets:  Get-ConnectionInformation (ExchangeOnlineManagement 3.0+), Get-Module, Get-Command
#
# WHY
# ---
# Connect-ExchangeOnline and Connect-IPPSSession each load a temporary module,
# and several cmdlets exist in both (Get-AdminAuditLogConfig, Get-Recipient,
# Get-TenantAllowBlockListItems, ...). An unqualified call runs whichever
# session loaded LAST — Purview, in this tool's connection order. On a live
# tenant that produced:
#   * PVW-1.1 "Unified Audit Log disabled" (Critical) on every run with Purview:
#     Microsoft documents UnifiedAuditLogIngestionEnabled as ALWAYS False in
#     Security & Compliance PowerShell, even when auditing is on.
#   * Get-TenantAllowBlockListItems failing "Value cannot be null ...
#     exchangeConfigUnit" six times.
#   * Inbox-rule recipients unresolvable (2 without Purview, 13 with).
#
# Get-ConnectionInformation reports each connection's ModuleName (the temp
# module's folder) and IsEopSession ($true for Security & Compliance), which is
# enough to pick the right module. Source is 'Unknown' when the session cannot
# be pinned down while BOTH are connected — callers must not treat a value
# from an Unknown source as authoritative.

# Whether a Get-ConnectionInformation row is a Security & Compliance session.
# IsEopSession says so directly, but not every module version returns it; the
# connection name (ExchangeOnlineProtection_N) and endpoint
# (*.compliance.protection.outlook.com) identify it too. Reading only
# IsEopSession with a $false default filed the Purview session as Exchange
# Online, so every Security & Compliance-only section was skipped.
function Test-TPEopConnection {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] $Connection)
    if ([bool](Get-TPObjectField -Item $Connection -Key 'IsEopSession' -Default $false)) { return $true }
    if ([string](Get-TPObjectField -Item $Connection -Key 'Name' -Default '') -like 'ExchangeOnlineProtection*') { return $true }
    return ([string](Get-TPObjectField -Item $Connection -Key 'ConnectionUri' -Default '') -match '\.compliance\.protection\.outlook\.(com|us|cn)|ps\.compliance\.')
}

function Get-TPExoCommand {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Name,
        [ValidateSet('ExchangeOnline', 'SecurityCompliance')] [string] $Session = 'ExchangeOnline'
    )

    $wantEop = ($Session -eq 'SecurityCompliance')
    $conns = @()
    if (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) {
        try {
            $conns = @(Get-ConnectionInformation -ErrorAction Stop | Where-Object {
                [string](Get-TPObjectField -Item $_ -Key 'State' -Default '') -eq 'Connected'
            })
        } catch { $conns = @() }
    }

    foreach ($c in @($conns | Where-Object { (Test-TPEopConnection -Connection $_) -eq $wantEop })) {
        $modPath = [string](Get-TPObjectField -Item $c -Key 'ModuleName' -Default '')
        if (-not $modPath) { continue }
        $leaf = @($modPath -split '[\\/]' | Where-Object { $_ })[-1]
        $mods = @(Get-Module | Where-Object {
            $_.Name -eq $leaf -or $_.Name -eq $modPath -or
            ($_.Path -and ($_.Path -like "$modPath*" -or (Split-Path -Path $_.Path -Parent) -eq $modPath))
        })
        foreach ($m in $mods) {
            # The module's own export table — NOT Get-Command -Module, which
            # resolves the name first and so only ever finds the copy that
            # shadows it (the other session's), then filters it out.
            $cmd = $null
            if ($m.ExportedCommands -and $m.ExportedCommands.ContainsKey($Name)) { $cmd = $m.ExportedCommands[$Name] }
            if ($cmd) { return [pscustomobject]@{ Command = $cmd; Source = $Session } }
        }
    }

    # Fallback: plain resolution. Its source is only knowable when a single
    # kind of session is connected.
    $cmd = Get-Command -Name $Name -ErrorAction SilentlyContinue | Select-Object -First 1
    $kinds = @($conns | ForEach-Object { Test-TPEopConnection -Connection $_ } | Sort-Object -Unique)
    $source = if ($kinds.Count -eq 1) { if ($kinds[0]) { 'SecurityCompliance' } else { 'ExchangeOnline' } } else { 'Unknown' }
    return [pscustomobject]@{ Command = $cmd; Source = $source }
}
