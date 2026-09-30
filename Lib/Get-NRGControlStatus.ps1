#Requires -Version 7.0
#
# Get-NRGControlStatus.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Look up specific controls (from a ticket, a work order, a client
#          request) in an assessment's findings and say, per control, whether
#          the configuration is in place, open, partly in place, or was not
#          assessed and why. An Error finding is Not assessed, never Open: a
#          failed check has not shown the control is unconfigured.
#
#          A VIEW, like Get-NRGAssessmentScope: it emits no findings, moves no
#          score and reads no tenant.
#
#          Three rules keep it honest:
#            * Only Satisfied is "In place". NotApplicable is never "fixed" -
#              a control the run could not read, that needs a license the
#              tenant lacks, or that has no programmatic check says nothing
#              about whether the ticket's work was done, and is reported under
#              its own reason.
#            * An ID with no finding is "No result", never a pass.
#            * Several findings under one ControlId (DNS emits one per domain)
#              resolve to the WORST state, by the same order the score uses.
#
# Inputs:  -Findings        finding objects from a run or a results JSON
#          -ControlId       control IDs (AAD-1.4) and/or workload prefixes
#                           (TMS), which expand to every control of that
#                           workload in -ControlCatalog
#          -ControlCatalog  Config/controls.json entries, for titles and prefix
#                           expansion (optional)
# Outputs: array of [ordered] rows: ControlId, Status, State, Severity, Title,
#          Reason, Detail
# Graph scopes / cmdlets: none.

function Get-NRGControlStatus {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [AllowNull()] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string[]] $ControlId,
        [AllowNull()] [AllowEmptyCollection()] [object[]] $ControlCatalog
    )

    $rank    = Get-NRGStateSeverityRank
    $catalog = @($ControlCatalog | Where-Object { $null -ne $_ })
    $titles  = @{}
    $workloadOf = @{}
    foreach ($c in $catalog) {
        $cid = [string](Get-NRGObjectField -Item $c -Key 'ControlId' -Default '')
        if (-not $cid) { continue }
        $titles[$cid] = $c
        $workloadOf[$cid] = $cid.Split('-')[0]
    }

    # Expand workload prefixes; keep the requested order, drop duplicates.
    $ids = [System.Collections.Generic.List[string]]::new()
    foreach ($raw in $ControlId) {
        foreach ($tok in ($raw -split '[,;\s]+')) {
            $t = $tok.Trim().ToUpperInvariant()
            if (-not $t) { continue }
            $expanded = @()
            if ($t -notmatch '-') {
                $expanded = @($workloadOf.Keys | Where-Object { $workloadOf[$_] -eq $t } |
                    Sort-Object { [int](($_ -split '-')[1].Split('.')[0]) }, { [int](($_ -split '-')[1].Split('.')[-1]) })
            }
            if ($expanded.Count -eq 0) { $expanded = @($t) }
            foreach ($e in $expanded) { if (-not $ids.Contains($e)) { $ids.Add($e) } }
        }
    }

    $worst = @{}
    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $cid = ([string](Get-NRGObjectField -Item $f -Key 'ControlId' -Default '')).ToUpperInvariant()
        if (-not $cid) { continue }
        $st = [string](Get-NRGObjectField -Item $f -Key 'State' -Default '')
        if (-not $worst.ContainsKey($cid) -or
            ($rank[$st] ?? 0) -gt ($rank[[string](Get-NRGObjectField -Item $worst[$cid] -Key 'State' -Default '')] ?? 0)) {
            $worst[$cid] = $f
        }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($id in $ids) {
        $meta  = if ($titles.ContainsKey($id)) { $titles[$id] } else { $null }
        $title = if ($meta) { [string](Get-NRGObjectField -Item $meta -Key 'Title' -Default '') } else { '' }
        $sev   = if ($meta) { [string](Get-NRGObjectField -Item $meta -Key 'Severity' -Default '') } else { '' }
        $state = ''; $detail = ''; $status = ''; $reason = ''
        if ($worst.ContainsKey($id)) {
            $f = $worst[$id]
            $state  = [string](Get-NRGObjectField -Item $f -Key 'State' -Default '')
            $detail = [string](Get-NRGObjectField -Item $f -Key 'Detail' -Default '')
            if (-not $title) { $title = [string](Get-NRGObjectField -Item $f -Key 'Title' -Default '') }
            if (-not $sev)   { $sev   = [string](Get-NRGObjectField -Item $f -Key 'Severity' -Default '') }
            switch ($state) {
                'Satisfied' { $status = 'In place';        $reason = 'The assessment found this configured.' }
                'Gap'       { $status = 'Open';            $reason = 'The assessment found this not configured.' }
                'Partial'   { $status = 'Partly in place'; $reason = 'Configured in part; the detail says what remains.' }
                'Error'     { $status = 'Not assessed';    $reason = 'The check errored, so the assessment did not establish whether this is configured.' }
                default {
                    $status = 'Not assessed'
                    $reason = if     ($detail -match 'upgrade opportunity')             { 'Not scored: the tenant is not licensed for it.' }
                              elseif ($detail -match 'Third-party EDR declared')        { 'Declared handled by a third-party EDR; not verified by this tool.' }
                              elseif ($detail -match 'requires manual verification')    { 'No programmatic check; confirm by hand.' }
                              else                                                      { 'The run could not assess it; not evidence either way.' }
                }
            }
        } elseif ($meta -or $catalog.Count -eq 0) {
            $status = 'No result'
            $reason = 'The run produced no finding for this control (skipped, quick scan, or replayed older results); not evidence either way.'
        } else {
            $status = 'Unknown control ID'
            $reason = 'Not in the control catalog and no finding carries it.'
        }
        $short = if ($detail.Length -gt 240) { $detail.Substring(0, 237) + '...' } else { $detail }
        $rows.Add([ordered]@{
            ControlId = $id
            Status    = $status
            State     = $state
            Severity  = $sev
            Title     = $title
            Reason    = $reason
            Detail    = $short
        })
    }
    return $rows.ToArray()
}
