#Requires -Version 7.0
#
# Get-TPStandards.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Read the operator-approved standards (Config/tp-standards.json, plus the
#          DMARC reporting address from the active profile) and
#          emit findings for controls whose expected state has several components.
#          A list holds only values the owner approved: the tool does not invent
#          NRG's standard. An empty list (PriorityUsers is one, deliberately)
#          means the component that needs it is reported as not assessed,
#          never as a pass.
#
# Data consumed: none.  Graph scopes / cmdlets: none (parsing only).

function Get-TPStandards {
    <#
    .SYNOPSIS
        Returns the approved lists from Config/tp-standards.json as string arrays
        (DmarcReportingAddresses, CommonAttachmentFileTypes, PriorityUsers,
        RequiredConditionalAccessTemplates, and the two distribution-list
        standards DistributionListMaxMembers and
        DistributionListMemberJoinRestriction). A missing or unreadable file yields
        empty lists, which means "not approved", never "nothing required is met".
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([string] $Path)

    $std = [ordered]@{ DmarcReportingAddresses = @(); CommonAttachmentFileTypes = @(); PriorityUsers = @(); RequiredConditionalAccessTemplates = @()
                       DistributionListMaxMembers = @(); DistributionListMemberJoinRestriction = @() }
    if (-not $Path) { $Path = Join-Path (Split-Path -Parent $PSScriptRoot) 'Config' 'tp-standards.json' }
    if (-not (Test-Path -LiteralPath $Path)) { return $std }
    try {
        $j = Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 10
    } catch { return $std }
    foreach ($k in @($std.Keys)) {
        $node = Get-TPObjectField -Item $j -Key $k -Default $null
        if ($null -eq $node) { continue }
        $vals = Get-TPObjectField -Item $node -Key 'Values' -Default $null
        $std[$k] = @(@($vals) | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim() })
    }
    # The DMARC reporting address is the practice's own, so the active profile
    # (DmarcReportingAddresses in Config/branding.psd1 or Config/profiles/
    # <name>.psd1) supplies it when it names one; the shared file ships none.
    $brand = if (Get-Variable -Name TPBrand -Scope Script -ErrorAction SilentlyContinue) { $script:TPBrand } else { $null }
    if ($brand) {
        $fromProfile = @(@(Get-TPObjectField -Item $brand -Key 'DmarcReportingAddresses' -Default @()) |
            Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim() })
        if ($fromProfile.Count -gt 0) { $std.DmarcReportingAddresses = $fromProfile }
    }
    return $std
}

function Add-TPExpectedStateFinding {
    <#
    .SYNOPSIS
        Emits one finding for a control whose expected state has several components.
        An established shortfall is always reported (Gap, or Partial when something
        else was also met); otherwise a component that could not be established
        leaves the control not assessed (NotApplicable) with the verified components
        kept in the Detail; Satisfied only when every component is supported.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ControlId,
        [Parameter(Mandatory)] $Control,
        [AllowNull()] $FrameworkIds,
        [AllowNull()] [string[]] $Verified,
        [AllowNull()] [string[]] $Shortfalls,
        [AllowNull()] [string[]] $NotEstablished,
        [string] $CurrentValue,
        [string] $RequiredValue,
        [AllowNull()] [object[]] $AffectedObjects,
        [string] $Instance,
        [string] $TitleSuffix,
        [ValidateSet('Auto', 'Gap')] [string] $ShortfallState = 'Auto',
        # A related setting another control owns. Shown first in the Detail so the reader sees it, but it
        # never enters the verdict (it is not a Verified, Shortfall or Not assessed component).
        [string] $Context
    )
    $v = @($Verified | Where-Object { $_ }); $s = @($Shortfalls | Where-Object { $_ }); $n = @($NotEstablished | Where-Object { $_ })
    $parts = @()
    if ($Context) { $parts += "Related (judged under another control, not part of this verdict): $Context" }
    if ($v.Count) { $parts += "Verified: $($v -join ' ')" }
    if ($s.Count) { $parts += "Shortfall: $($s -join ' ')" }
    if ($n.Count) { $parts += "Not assessed: $($n -join ' ')" }
    $p = @{
        ControlId = $ControlId; Category = $Control.Category; Title = "$($Control.Title)$TitleSuffix"; FrameworkIds = $FrameworkIds; Detail = ($parts -join ' ').Trim()
    }
    if ($CurrentValue)  { $p.CurrentValue  = $CurrentValue }
    if ($RequiredValue) { $p.RequiredValue = $RequiredValue }
    if ($Instance)      { $p.Instance = $Instance }
    if ($AffectedObjects -and @($AffectedObjects).Count) { $p.AffectedObjects = @($AffectedObjects) }
    # Literal -State values on purpose: Get-TPControlAutomationAudit derives what a verdict
    # helper can emit from its own Add-TPFinding calls.
    if ($s.Count) {
        if ($v.Count -and $ShortfallState -eq 'Auto') {
            Add-TPFinding @p -State 'Partial' -Severity 'Medium' -Remediation $Control.Remediation
        } else {
            Add-TPFinding @p -State 'Gap' -Severity $Control.Severity -Remediation $Control.Remediation
        }
    } elseif ($n.Count) {
        Add-TPFinding @p -State 'NotApplicable'
    } else {
        Add-TPFinding @p -State 'Satisfied' -Severity 'Informational'
    }
}
