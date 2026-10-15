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
#   - The original result stays in the Detail, and the pass is re-derivable: a
#     finding already carrying the marker or the record note is restored to its
#     pre-approval result first and judged again against the CURRENT record, so
#     a republish (-FromResults) of an approved run reflects an approval that
#     has since lapsed, been removed, or been corrected, and never stacks text.
#   - An exclusion is approved only when it is the finding's only shortfall and
#     every component was established: Add-TPExpectedStateFinding records every
#     other shortfall and every unestablished component as a structured entry
#     beside the exclusions, and one such entry keeps the finding Partial
#     (annotated), whatever the record says about the principals.
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
        Satisfied, naming them; annotates one that is partly approved or has other
        shortfalls; restores and re-judges a finding an earlier run already
        rewrote; leaves every other finding alone. Returns the number of findings
        that are Satisfied with approved exceptions after the pass.
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
    # No record: approvals are not current, so an earlier run's approval is undone
    # below and nothing is approved.
    $approved = @{}; $rejected = @{}
    if ($exc -and $exc.Available) {
        foreach ($k in @($exc.EmergencyAccess.Keys)) { $approved[([string]$k).ToLowerInvariant()] = $exc.EmergencyAccess[$k] }
        foreach ($r in @($exc.EmergencyAccessRejected)) {
            $k = "$(([string](Get-TPObjectField -Item $r -Key 'Kind' -Default 'user')).ToLowerInvariant()):$(([string](Get-TPObjectField -Item $r -Key 'ObjectId' -Default '')).ToLowerInvariant())"
            if (-not $rejected.ContainsKey($k)) { $rejected[$k] = $r }
        }
    }
    $targets = if ($PSBoundParameters.ContainsKey('Findings')) { @($Findings | Where-Object { $null -ne $_ }) } else { @($script:TPFindings) }
    $markerRx = '(?s)^' + [regex]::Escape($script:TPEmergencyAccessMarker) + '.*? Result before the approval record was applied: Partial\. (.*)$'
    # The note this pass appends, in its own grammar only, so tenant text that
    # happens to contain the words (a policy named "Approval record: ...") is
    # never cut out of a finding.
    $noteRx   = '(?s)\s*' + [regex]::Escape($script:TPEmergencyAccessRecordNote) + ' (?:approved emergency-access exception\(s\): |Not approved: |The finding has ).*$'
    $approvedCount = 0
    foreach ($f in $targets) {
        # Only a finding that carries this pass's structured exclusions is ever
        # touched: every AffectedObjects entry must be an exclusion, another
        # shortfall or an unestablished component, and at least one an exclusion.
        $objs = @(Get-TPObjectField -Item $f -Key 'AffectedObjects' -Default @() | Where-Object { $null -ne $_ })
        if ($objs.Count -eq 0) { continue }
        $principals = @(); $otherShortfalls = @(); $notEstablished = @(); $recognized = $true
        foreach ($o in $objs) {
            $kind = [string](Get-TPObjectField -Item $o -Key 'Exclusion' -Default '')
            $p    = [string](Get-TPObjectField -Item $o -Key 'Principal' -Default '')
            $sf   = [string](Get-TPObjectField -Item $o -Key 'Shortfall' -Default '')
            $ne   = [string](Get-TPObjectField -Item $o -Key 'NotEstablished' -Default '')
            if ($kind -eq $script:TPEmergencyAccessExclusionKind -and $p) { if ($p -notin $principals) { $principals += $p } }
            elseif ($sf) { $otherShortfalls += $sf }
            elseif ($ne) { $notEstablished += $ne }
            else { $recognized = $false; break }
        }
        if (-not $recognized -or $principals.Count -eq 0) { continue }
        $state  = [string](Get-TPObjectField -Item $f -Key 'State' -Default '')
        $detail = [string](Get-TPObjectField -Item $f -Key 'Detail' -Default '')
        # Restore a finding an earlier run approved or annotated, then judge it again
        # against the current record (a republish of an approved run must reflect a
        # lapsed, removed or corrected approval).
        if ($state -eq 'Satisfied' -and $detail -like "$script:TPEmergencyAccessMarker*") {
            if ($detail -notmatch $markerRx) { continue }   # not this pass's shape; leave it
            $f.State    = 'Partial'
            $f.Severity = 'Medium'
            $f.Detail   = $Matches[1]
            $cv0 = [string](Get-TPObjectField -Item $f -Key 'CurrentValue' -Default '')
            $f.CurrentValue = ($cv0 -replace '(?:; |^)[Aa]pproved emergency-access exceptions: \d+$', '')
            $state = 'Partial'; $detail = [string]$f.Detail
        } elseif ($state -eq 'Partial' -and $detail -match $noteRx) {
            $f.Detail = ($detail -replace $noteRx, '')
            $detail = [string]$f.Detail
        }
        if ($state -ne 'Partial') { continue }
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
        if ($no.Count -gt 0 -or $otherShortfalls.Count -gt 0 -or $notEstablished.Count -gt 0) {
            # Not approvable as it stands: say exactly why, and only when the record
            # has something to say (a tenant with no record keeps the plain finding).
            # An approval never turns an incomplete assessment into a pass.
            if (-not ($exc -and $exc.Available)) { continue }
            $parts = @()
            if ($okNames.Count) { $parts += "approved emergency-access exception(s): $($okNames -join '; ')." }
            if ($no.Count) { $parts += "Not approved: $($no -join '; ')." }
            if ($otherShortfalls.Count) { $parts += "The finding has $($otherShortfalls.Count) other shortfall(s) besides the exclusion, so it stays Partial whatever the record says." }
            if ($notEstablished.Count) { $parts += "The finding has $($notEstablished.Count) component(s) that were not assessed, so an approval cannot make it a pass; it stays Partial." }
            $f.Detail = "$detail $script:TPEmergencyAccessRecordNote $($parts -join ' ')".Trim()
            continue
        }
        $approvals = @($ok | ForEach-Object { [string](Get-TPObjectField -Item $_.Entry -Key 'Verdict' -Default '') } | Where-Object { $_ } | Sort-Object -Unique)
        $groupNote = if (@($ok | Where-Object { $_.Principal -like 'group:*' }).Count -gt 0) { ' A group approval attests that the group holds only emergency-access accounts; the assessment did not resolve its membership.' } else { '' }
        $f.State    = 'Satisfied'
        $f.Severity = 'Informational'
        $f.Detail   = "$script:TPEmergencyAccessMarker $($ok.Count) principal(s) excluded from every qualifying policy are on this tenant's current approval record ($($approvals -join ' ')): $($okNames -join '; ').$groupNote The exclusion is a permitted deviation, not coverage: these accounts are outside the protection by design and stay listed. Result before the approval record was applied: Partial. $detail"
        $cv = [string](Get-TPObjectField -Item $f -Key 'CurrentValue' -Default '')
        $f.CurrentValue = $(if ($cv) { "$cv; approved emergency-access exceptions: $($ok.Count)" } else { "Approved emergency-access exceptions: $($ok.Count)" })
        $approvedCount++
    }
    return $approvedCount
}
