#Requires -Version 7.0
#
# Set-TPEmergencyAccessApproval.ps1
# TenantPosture
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Apply a tenant's approved emergency-access record to the Conditional
#   Access coverage findings: a shortfall that consists only of principals every
#   qualifying policy excludes, every one of them on the current approval
#   record, is a permitted deviation and reads "Approved emergency-access
#   exceptions", naming them. The exclusion stays visible; nothing is silent.
#
# Data keys: none. Operates on the module findings list after evaluation (and on
#   the findings loaded by -FromResults). Reads
#   Config/baseline-exceptions/<tenant>.psd1 through Get-TPBaselineExceptions.
# Graph / cmdlets: none.
#
# Owner's decision (2026-10-15): judge whether an exclusion is appropriate, not
# whether one exists. An account's name alone establishes nothing; the record,
# approved and current, does. The rules:
#   - Only a finding whose shortfall is a shared exclusion qualifies. The coverage
#     verdict records the excluded principals as structured AffectedObjects
#     (Exclusion = SharedByEveryQualifyingPolicy); prose is never parsed.
#   - Every excluded principal must be on the record, approved and current
#     (Get-TPBaselineExceptions validates the dates). One principal that is not
#     keeps the finding Partial, with the record's answer for each principal
#     appended so the operator sees what remains.
#   - A group approval is honored and the finding says membership was not
#     resolved; a role exclusion is never approved.
#   - The original result stays in the Detail. Idempotent: a finding already
#     carrying the marker or the record note is left alone, so a republish does
#     not stack it.
#   - The satisfied finding says the accounts are outside the protection by
#     design: an approved exception is a permitted deviation, not coverage.

# The detail prefix of an approved finding and the AffectedObjects marker the
# coverage verdict writes. Change them together with Get-TPCACoverageVerdict.
$script:TPEmergencyAccessMarker        = 'Approved emergency-access exceptions:'
$script:TPEmergencyAccessRecordNote    = 'Approval record:'
$script:TPEmergencyAccessExclusionKind = 'SharedByEveryQualifyingPolicy'

function Set-TPEmergencyAccessApproval {
    <#
    .SYNOPSIS
        Rewrites a Partial Conditional Access coverage finding whose only shortfall
        is a shared exclusion of approved, current emergency-access principals to
        Satisfied, naming them; annotates one that is partly approved; leaves every
        other finding alone. Returns the number of findings rewritten to Satisfied.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        # The connected tenant's domain; the record is Config/baseline-exceptions/<slug>.psd1.
        [AllowNull()] [AllowEmptyString()] [ValidatePattern('^[A-Za-z0-9.\-]{0,253}$')] [string] $TenantDomain,
        # A record file read directly (tests); never both.
        [AllowNull()] [AllowEmptyString()] [string] $Path,
        # Findings to rewrite in place. Defaults to the module's findings;
        # -FromResults passes the findings it loaded from the results JSON.
        [object[]] $Findings,
        [datetime] $AsOf = (Get-Date)
    )
    Initialize-TPState
    $exc = if ($Path) { Get-TPBaselineExceptions -Path $Path -AsOf $AsOf }
           elseif ($TenantDomain) { Get-TPBaselineExceptions -TenantDomain $TenantDomain -AsOf $AsOf }
           else { $null }
    if (-not $exc -or -not $exc.Available) { return 0 }
    $approved = @{}
    foreach ($k in @($exc.EmergencyAccess.Keys)) { $approved[([string]$k).ToLowerInvariant()] = $exc.EmergencyAccess[$k] }
    $rejected = @{}
    foreach ($r in @($exc.EmergencyAccessRejected)) {
        $k = "$(([string](Get-TPObjectField -Item $r -Key 'Kind' -Default 'user')).ToLowerInvariant()):$(([string](Get-TPObjectField -Item $r -Key 'ObjectId' -Default '')).ToLowerInvariant())"
        if (-not $rejected.ContainsKey($k)) { $rejected[$k] = $r }
    }
    $targets = if ($PSBoundParameters.ContainsKey('Findings')) { @($Findings | Where-Object { $null -ne $_ }) } else { @($script:TPFindings) }
    $changed = 0
    foreach ($f in $targets) {
        if ([string](Get-TPObjectField -Item $f -Key 'State' -Default '') -ne 'Partial') { continue }
        $detail = [string](Get-TPObjectField -Item $f -Key 'Detail' -Default '')
        if ($detail -like "$script:TPEmergencyAccessMarker*" -or $detail -match [regex]::Escape($script:TPEmergencyAccessRecordNote)) { continue }
        $objs = @(Get-TPObjectField -Item $f -Key 'AffectedObjects' -Default @() | Where-Object { $null -ne $_ })
        if ($objs.Count -eq 0) { continue }
        $principals = @(); $onlyExclusions = $true
        foreach ($o in $objs) {
            $kind = [string](Get-TPObjectField -Item $o -Key 'Exclusion' -Default '')
            $p    = [string](Get-TPObjectField -Item $o -Key 'Principal' -Default '')
            if ($kind -ne $script:TPEmergencyAccessExclusionKind -or -not $p) { $onlyExclusions = $false; break }
            $principals += $p
        }
        if (-not $onlyExclusions -or $principals.Count -eq 0) { continue }
        $ok = @(); $no = @()
        foreach ($p in $principals) {
            $key = $p.ToLowerInvariant()
            if ($approved.ContainsKey($key)) { $ok += [pscustomobject]@{ Principal = $p; Entry = $approved[$key] } }
            elseif ($rejected.ContainsKey($key)) { $no += "$p ($([string](Get-TPObjectField -Item $rejected[$key] -Key 'Verdict' -Default 'not approved')))" }
            elseif ($key -like 'role:*') { $no += "$p (a role is never an emergency-access principal)" }
            else { $no += "$p (not on the approval record)" }
        }
        $label = {
            param($x)
            $e = $x.Entry
            $upn = [string](Get-TPObjectField -Item $e -Key 'UserPrincipalName' -Default '')
            $dn  = [string](Get-TPObjectField -Item $e -Key 'DisplayName' -Default '')
            if ($upn) { "$($x.Principal) ($upn)" } elseif ($dn) { "$($x.Principal) ($dn)" } else { [string]$x.Principal }
        }
        $okNames = @($ok | ForEach-Object { & $label $_ })
        if ($no.Count -gt 0) {
            # Partly approved: stays Partial, and says exactly what remains.
            $note = "$script:TPEmergencyAccessRecordNote $(if ($okNames.Count) { "approved emergency-access exception(s): $($okNames -join '; '). " })Not approved: $($no -join '; ')."
            $f.Detail = "$detail $note".Trim()
            continue
        }
        $approvals = @($ok | ForEach-Object { [string](Get-TPObjectField -Item $_.Entry -Key 'Verdict' -Default '') } | Where-Object { $_ } | Sort-Object -Unique)
        $groupNote = if (@($ok | Where-Object { $_.Principal -like 'group:*' }).Count -gt 0) { ' A group approval attests that the group holds only emergency-access accounts; the assessment did not resolve its membership.' } else { '' }
        $f.State    = 'Satisfied'
        $f.Severity = 'Informational'
        $f.Detail   = "$script:TPEmergencyAccessMarker $($ok.Count) principal(s) excluded from every qualifying policy are on this tenant's current approval record ($($approvals -join ' ')): $($okNames -join '; ').$groupNote The exclusion is a permitted deviation, not coverage: these accounts are outside the protection by design and stay listed. Result before the approval record was applied: Partial. $detail"
        $cv = [string](Get-TPObjectField -Item $f -Key 'CurrentValue' -Default '')
        $f.CurrentValue = $(if ($cv) { "$cv; approved emergency-access exceptions: $($ok.Count)" } else { "Approved emergency-access exceptions: $($ok.Count)" })
        $changed++
    }
    return $changed
}
