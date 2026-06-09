#Requires -Version 7.0
#
# Publish-NRGMonthlyReport.ps1  (v4.11.1)
#
# Author: NRG Technology Services / NextLayerSec LLC — nrgtechservices.com
# Purpose: Generates a monthly client-facing security + HIPAA compliance
#          report — a recurring MSP deliverable distinct from the one-shot
#          assessment HTML. Renders a posture snapshot (score ring +
#          state counts), Work Completed / In Progress / Queued tables
#          with HIPAA safeguard citations, residual-risk statement with
#          license-gated-control callout, and a HIPAA defensibility note
#          documenting the §164.308(a)(1) ongoing risk-management process.
#
#          The Work-Completed / In-Progress / Queued state is read from
#          an operator-maintained delta file (Config/monthly-delta/
#          <tenant>-<YYYY-MM>.psd1). Each month's output JSON becomes the
#          next month's "PriorMonth" input — self-contained, no external
#          tracking system required.
#
# Inputs:  -Findings        Current assessment findings (Hashtable / PSObj).
#          -Metadata        $reportMetadata from the orchestrator. Reads:
#                             TenantDomain, AssessmentDate, ClientName,
#                             Brand, Maturity.
#          -DeltaPath       Path to the monthly delta .psd1 (what was newly
#                             completed / moved to progress / added to queue
#                             this period). See Config/monthly-delta/
#                             EXAMPLE-tenantname-2026-05.psd1 for shape.
#          -PriorMonthPath  Optional path to prior month's monthly-report
#                             JSON (carries forward InProgress + Queued
#                             items that weren't completed this period).
#                             Omit on first report (baseline period).
#          -OutputPath      Where to write the .html (sibling .json also
#                             written for next month's -PriorMonthPath).
#
# Outputs: <OutputPath>            HTML report
#          <OutputPath -replace '.html$', '.json'>  JSON state (next month's
#                                                    PriorMonth input).
#
# Cmdlets / helpers used:
#   Get-NRGCoverageScore  (score formula)
#   Get-NRGObjectField    (shape-agnostic field reader)
#   Get-NRGControlDefinitions (HIPAA citation lookup)
#   ConvertTo-NRGHtmlSafe (XSS prevention on all tenant-supplied strings)

function Publish-NRGMonthlyReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Findings,

        [Parameter(Mandatory = $true)]
        [hashtable] $Metadata,

        [Parameter(Mandatory = $true)]
        [ValidateScript({
            if ($_ -match '\.\.[\\/]') { throw "Path traversal not allowed in DeltaPath." }
            if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Delta file not found: $_" }
            return $true
        })]
        [string] $DeltaPath,

        [Parameter(Mandatory = $false)]
        [ValidateScript({
            if ($null -eq $_ -or '' -eq $_) { return $true }
            if ($_ -match '\.\.[\\/]') { throw "Path traversal not allowed in PriorMonthPath." }
            if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Prior-month file not found: $_" }
            return $true
        })]
        [string] $PriorMonthPath,

        [Parameter(Mandatory = $true)]
        [string] $OutputPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # ── Helpers ──────────────────────────────────────────────────────────────

    # XSS guard — use the module-scope helper if loaded, otherwise inline a
    # minimal escape. Publishers are loaded after Lib/ via the psm1 so the
    # canonical helper is normally available.
    $hx = if (Get-Command ConvertTo-NRGHtmlSafe -ErrorAction SilentlyContinue) {
        { param($s) ConvertTo-NRGHtmlSafe $s }
    } else {
        { param($s)
            if ($null -eq $s) { return '' }
            ([string]$s) -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' `
                         -replace '"','&quot;' -replace "'",'&#39;'
        }
    }

    # HIPAA citation lookup. Reads Config/controls.json once and indexes by
    # ControlId, then pulls the first HIPAA-prefixed FrameworkIds entry.
    # Returns a 2-line cite (e.g. "§164.308(a)(1)(ii)(A)\nRisk Analysis")
    # or '—' when the ControlId has no HIPAA citation or doesn't exist.
    $hipaaIndex = @{}
    if (Get-Command Get-NRGControlDefinitions -ErrorAction SilentlyContinue) {
        try {
            foreach ($c in (Get-NRGControlDefinitions)) {
                if (-not $c.ControlId) { continue }
                $hipaa = @($c.FrameworkIds | Where-Object { $_ -match '^HIPAA[-:]' })
                if ($hipaa.Count -gt 0) {
                    $hipaaIndex[$c.ControlId] = $hipaa[0]
                }
            }
        } catch {
            Write-Verbose "HIPAA citation lookup failed: $($_.Exception.Message). Citations will render as '—'."
        }
    }
    $getHipaaCite = {
        param([string] $cid)
        if (-not $cid -or -not $hipaaIndex.ContainsKey($cid)) { return '&mdash;' }
        # Citation format in controls.json: "HIPAA:164.308(a)(1)(ii)(A) Risk Analysis"
        # or "HIPAA-164.312(b)/Audit". Split on first space or slash for the
        # "§ + section" line and the "label" line.
        $raw = $hipaaIndex[$cid] -replace '^HIPAA[-:]\s*', ''
        $sec, $lbl = if ($raw -match '^(\S+?)[\s/]+(.+)$') { $matches[1], $matches[2] } else { $raw, '' }
        $secEsc = & $hx $sec
        $lblEsc = & $hx $lbl
        if ($lblEsc) { "&sect;$secEsc<br>$lblEsc" } else { "&sect;$secEsc" }
    }

    # Status pill renderer for the in-progress / queued / complete tables.
    $statusPill = {
        param([string] $state)
        switch ($state) {
            'Complete'    { '<span class="st st-done">Complete</span>' }
            'In Progress' { '<span class="st st-prog">In Progress</span>' }
            'Queued'      { '<span class="st st-queue">Queued</span>' }
            default       { "<span class=`"st`">$(& $hx $state)</span>" }
        }
    }

    # Row renderer — used by all three tables.
    $renderRow = {
        param([hashtable] $item, [string] $defaultStatus)
        $svc    = & $hx (Get-NRGObjectField -Item $item -Key 'Service' -Default '')
        $cid    = Get-NRGObjectField -Item $item -Key 'ControlId' -Default ''
        $cidEsc = if ($cid) { "<span class=`"cid`">$(& $hx $cid)</span>" } else { "<span class=`"cid`">&mdash;</span>" }
        $hipaa  = "<span class=`"hsg`">$(& $getHipaaCite $cid)</span>"
        $st     = Get-NRGObjectField -Item $item -Key 'Status' -Default $defaultStatus
        $pill   = & $statusPill ([string]$st)
        "<tr><td>$svc</td><td>$cidEsc</td><td>$hipaa</td><td>$pill</td></tr>"
    }

    # ── Load delta + prior-month ─────────────────────────────────────────────
    $delta = Import-PowerShellDataFile -LiteralPath $DeltaPath
    foreach ($req in 'Period','EntityType','TLP') {
        if (-not $delta.ContainsKey($req)) {
            throw "Delta file is missing required key '$req': $DeltaPath"
        }
    }
    # v4.11.3 (audit review item #3): enforce the same Period format here
    # that the prior-month validator below requires. Without this check
    # the delta could carry `Period = 'Q2 2026'`, month 1 succeeds, month
    # 2 reads the same string back as prior and the validator throws —
    # the tool would generate input it later rejects. Same regex on both
    # sides closes the round-trip.
    $deltaPeriodTrim = ([string]$delta['Period']).Trim()
    $deltaPeriodOk = $deltaPeriodTrim -and (
        $deltaPeriodTrim -match '^(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}$' -or
        $deltaPeriodTrim -match '^\d{4}-(0[1-9]|1[0-2])$'
    )
    if (-not $deltaPeriodOk) {
        throw "Delta file 'Period' must match 'Month YYYY' (e.g. 'May 2026') or 'YYYY-MM' (e.g. '2026-05'); got '$($delta['Period'])'. File: $DeltaPath"
    }

    $prior = $null
    if ($PriorMonthPath) {
        $prior = Get-Content -LiteralPath $PriorMonthPath -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable

        # v4.11.2 audit fix (M-2), v4.11.3 review follow-up:
        # Schema-validate the prior-month JSON before any of its fields render.
        # The file is operator-supplied (or disk-replaced on a shared
        # workstation) — without this check a tampered JSON could push
        # misleading "Score: 100" / arbitrary "Period: <text>" through the
        # trend note in next month's HIPAA-framed report. XSS is blocked by
        # $hx; content falsification is the real concern (compliance fraud).
        #
        # The v4.11.2 fix was bypassable: it guarded each check with
        # `if ($prior.Contains('Score'))` / `Contains('Period')`. An
        # attacker simply deleted the keys, both guards became false,
        # validation was skipped, and the downstream renderer's
        # Get-NRGObjectField -Default fallback fabricated a "0 → $score"
        # improvement arrow. v4.11.3 treats Score and Period as REQUIRED
        # when a prior file is supplied. Also tightens the Score type
        # check (`[int]` strict cast in try/catch, not lenient `-as [int]`
        # which would accept $true→1 and "42.5"→42), and accepts trailing/
        # leading whitespace in Period so a manually-edited prior JSON
        # with a stray space or newline doesn't falsely-reject.
        if ($prior -isnot [hashtable]) {
            throw "Prior-month JSON must deserialize to a hashtable; got [$($prior.GetType().FullName)]. File: $PriorMonthPath"
        }
        foreach ($req in 'Score','Period') {
            if (-not $prior.Contains($req)) {
                throw "Prior-month JSON is missing required key '$req'. File: $PriorMonthPath"
            }
        }
        # Strict integer-type check on Score — reject booleans, floats,
        # arrays, hashtables, strings that lenient -as[int] would coerce.
        $scoreVal = $prior['Score']
        if ($scoreVal -isnot [int] -and $scoreVal -isnot [long]) {
            throw "Prior-month JSON 'Score' must be a JSON integer (not boolean/float/string); got [$($scoreVal.GetType().Name)] '$scoreVal'. File: $PriorMonthPath"
        }
        if ($scoreVal -lt 0 -or $scoreVal -gt 100) {
            throw "Prior-month JSON 'Score' must be in [0,100]; got $scoreVal. File: $PriorMonthPath"
        }
        # Period: trim before matching so a stray edit doesn't break a
        # legitimate report. Accept "Month YYYY" or "YYYY-MM" (matches
        # both forms the publisher emits and the operator delta accepts).
        $periodStr = if ($prior['Period'] -is [string]) { $prior['Period'].Trim() } else { '' }
        $periodOk = $periodStr -and (
            $periodStr -match '^(January|February|March|April|May|June|July|August|September|October|November|December)\s+\d{4}$' -or
            $periodStr -match '^\d{4}-(0[1-9]|1[0-2])$'
        )
        if (-not $periodOk) {
            throw "Prior-month JSON 'Period' must match 'Month YYYY' or 'YYYY-MM'; got '$($prior['Period'])'. File: $PriorMonthPath"
        }
    }

    # Resolve the three table populations:
    #   WorkCompleted = delta.NewlyCompleted ++ (prior.InProgress ∩ delta.NewlyCompleted-marker)
    #   InProgress    = delta.MovedToProgress ++ (prior.InProgress \ items now completed)
    #   Queued        = delta.AddedToQueue    ++ (prior.Queued \ items now in progress)
    #
    # Simplest contract for v4.11.0: the delta file is authoritative — the
    # operator lists exactly what's complete / in progress / queued THIS
    # period. Prior-month carryover is purely informational (for the trend
    # note). If they want auto-carryover they can paste from prior month.
    $workCompleted = @($delta['NewlyCompleted']  | Where-Object { $_ })
    $inProgress    = @($delta['MovedToProgress'] | Where-Object { $_ })
    $queued        = @($delta['AddedToQueue']    | Where-Object { $_ })

    # ── Scores + counts ──────────────────────────────────────────────────────
    $cov = Get-NRGCoverageScore -Findings $Findings -ErrorHandling 'Gap'
    $score = $cov.Score
    $sat   = $cov.Satisfied
    $part  = $cov.Partial
    $gap   = $cov.Gap
    $na    = $cov.NA

    # Posture pill matches the orchestrator + Summary publisher (if/elseif
    # chain — never switch ($true), which has the fallthrough hazard the
    # v4.10.1 Playbook fix addressed).
    $postureLbl = if     ($score -ge 85) { 'Optimal'   }
                  elseif ($score -ge 65) { 'Strong'    }
                  elseif ($score -ge 40) { 'At Risk'   }
                  else                   { 'Critical Risk' }

    # Maturity-derived counters (preferred — single source of truth with
    # the assessment HTML's score ring). Fall back to inline derivation
    # when the Maturity helper output isn't in metadata.
    $mat = Get-NRGObjectField -Item $Metadata -Key 'Maturity'
    if ($mat) {
        $critOpen  = [int](Get-NRGObjectField -Item $mat -Key 'CriticalGaps' -Default 0)
        $highOpen  = [int](Get-NRGObjectField -Item $mat -Key 'HighGaps' -Default 0)
    } else {
        $critOpen = @($Findings | Where-Object { (Get-NRGObjectField -Item $_ -Key 'State') -eq 'Gap' -and (Get-NRGObjectField -Item $_ -Key 'Severity') -eq 'Critical' }).Count
        $highOpen = @($Findings | Where-Object { (Get-NRGObjectField -Item $_ -Key 'State') -eq 'Gap' -and (Get-NRGObjectField -Item $_ -Key 'Severity') -eq 'High' }).Count
    }
    $totalOpen = $gap

    # License-gated control count — findings with State='NotApplicable' and
    # a LicenseGated marker in the Detail. Best-effort; degrades gracefully.
    $licBlocked = @($Findings | Where-Object {
        (Get-NRGObjectField -Item $_ -Key 'State') -eq 'NotApplicable' -and
        (([string](Get-NRGObjectField -Item $_ -Key 'Detail' -Default '')) -match 'license|Entra ID P|Defender for Endpoint|E5')
    }).Count

    # Score ring geometry (matches the user's template: r=70, circumference 439.8)
    $circumference = 439.8
    $dashOffset    = [Math]::Round($circumference * (1 - $score / 100), 2)

    # Bar widths — proportional to total findings count
    $totalForBars = $sat + $part + $gap + $na
    if ($totalForBars -le 0) { $totalForBars = 1 }
    $wGap = [Math]::Min(100, [Math]::Round(100 * $gap  / $totalForBars))
    $wPar = [Math]::Min(100, [Math]::Round(100 * $part / $totalForBars))
    $wSat = [Math]::Min(100, [Math]::Round(100 * $sat  / $totalForBars))
    $wNa  = [Math]::Min(100, [Math]::Round(100 * $na   / $totalForBars))

    # ── Header strings ───────────────────────────────────────────────────────
    $brand = Get-NRGObjectField -Item $Metadata -Key 'Brand' -Default @{}
    $brandName  = & $hx (Get-NRGObjectField -Item $brand -Key 'CompanyName' -Default 'NRG Technology Services / NextLayerSec LLC')
    $tenant     = & $hx (Get-NRGObjectField -Item $Metadata -Key 'TenantDomain' -Default 'unknown')
    $clientNm   = & $hx (Get-NRGObjectField -Item $Metadata -Key 'ClientName' -Default $tenant)
    $assessDate = & $hx (Get-NRGObjectField -Item $Metadata -Key 'AssessmentDate' -Default (Get-Date -Format 'MMMM dd, yyyy'))
    $toolVer    = & $hx (Get-NRGObjectField -Item $Metadata -Key 'ToolVersion' -Default '')
    $period     = & $hx $delta['Period']
    $entity     = & $hx $delta['EntityType']
    $tlpRaw     = ([string]$delta['TLP']).ToUpper()
    $tlp        = & $hx "TLP:$tlpRaw"

    # Baseline-vs-trend note — first-month runs say "Baseline period",
    # subsequent runs compare against the prior month's score.
    $trendNote = if (-not $prior) {
        "<b>Baseline period.</b> This is the initial assessment establishing the security and compliance baseline. Of the $totalOpen open gaps, <b>$critOpen are critical</b> and <b>$highOpen are high-severity</b>, prioritized in the Phase 1 remediation roadmap. Trend comparison begins next reporting period."
    } else {
        $priorScore = [int](Get-NRGObjectField -Item $prior -Key 'Score' -Default 0)
        $delta_s    = $score - $priorScore
        $arrow      = if ($delta_s -gt 0) { "&#9650; +$delta_s" } elseif ($delta_s -lt 0) { "&#9660; $delta_s" } else { "&#9654; 0" }
        $priorPeriod = & $hx (Get-NRGObjectField -Item $prior -Key 'Period' -Default 'prior')
        "<b>Trend vs $priorPeriod.</b> Score this period: <b>$score</b> ($arrow). Open gaps: <b>$totalOpen</b> ($critOpen critical, $highOpen high). $($workCompleted.Count) item$(if($workCompleted.Count -ne 1){'s'}) completed this period."
    }

    # ── Render tables ────────────────────────────────────────────────────────
    $workCompletedRows = if ($workCompleted.Count -eq 0) {
        '<tr><td colspan="4" style="text-align:center;color:var(--mut);font-style:italic;padding:18px">No items completed this period</td></tr>'
    } else {
        ($workCompleted | ForEach-Object { & $renderRow $_ 'Complete' }) -join "`n"
    }
    $inProgressRows = if ($inProgress.Count -eq 0) {
        '<tr><td colspan="4" style="text-align:center;color:var(--mut);font-style:italic;padding:18px">No items in progress</td></tr>'
    } else {
        ($inProgress | ForEach-Object { & $renderRow $_ 'In Progress' }) -join "`n"
    }
    $queuedRows = if ($queued.Count -eq 0) {
        '<tr><td colspan="4" style="text-align:center;color:var(--mut);font-style:italic;padding:18px">No items queued</td></tr>'
    } else {
        ($queued | ForEach-Object { & $renderRow $_ 'Queued' }) -join "`n"
    }

    # License callout — only render if there are actual blocked controls
    $licCallout = if ($licBlocked -gt 0) {
        $cw = if ($licBlocked -eq 1) { 'control' } else { 'controls' }
        $vp = if ($licBlocked -eq 1) { 'cannot be remediated'      } else { 'cannot be remediated' }
        @"
        <div class="callout co-lic">
          <h4><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 7h16M4 12h16M4 17h10"/></svg>License-Blocked Controls</h4>
          <p>$licBlocked $cw $vp under the current license tier. A licensing upgrade proposal is available on request.</p>
        </div>
"@
    } else { '' }

    # ── Build the full HTML ──────────────────────────────────────────────────
    # Template is intentionally mirroring the operator-supplied design so the
    # visual identity stays consistent across MSP deliverables. CSS lives
    # inline (no external stylesheet) so the HTML file is self-contained
    # and emailable as a single attachment.
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Monthly Security &amp; HIPAA Compliance Report — $clientNm — $period</title>
<style>
  :root{
    --org:#e87722; --org2:#ea580c; --org3:#c2410c;
    --red:#dc2626; --red-d:#991b1b; --red-bg:#fef2f2; --red-bd:#fecaca;
    --teal:#128273;
    --grn:#166534; --grn-bg:#f0fdf4; --grn-bd:#bbf7d0;
    --amber:#ca8a04; --amber-bg:#fffbeb; --amber-bd:#fde68a;
    --ink:#1f2733; --mut:#6b7484; --bdr:#e8edf5;
    --bg:#f4f7fb; --card:#ffffff;
    --ff:'Segoe UI Variable Display','Segoe UI','Helvetica Neue',system-ui,sans-serif;
    --fm:'Segoe UI Mono','Consolas',monospace;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:var(--ff);background:var(--bg);color:var(--ink);line-height:1.5;font-size:14px;-webkit-font-smoothing:antialiased}
  .wrap{max-width:920px;margin:0 auto;padding:0 0 64px}
  .hdr{background:linear-gradient(135deg,#1f2733 0%,#2b3545 100%);color:#fff;padding:30px 40px 26px;position:relative;overflow:hidden}
  .hdr::after{content:'';position:absolute;top:0;right:0;width:280px;height:100%;background:linear-gradient(135deg,transparent,rgba(232,119,34,.18));pointer-events:none}
  .hdr-top{display:flex;justify-content:space-between;align-items:flex-start;position:relative;z-index:1}
  .doc-title{font-size:1.45rem;font-weight:700;letter-spacing:-.01em;line-height:1.2}
  .doc-sub{font-size:.85rem;color:#aeb8c7;margin-top:6px}
  .logo-t{font-weight:700;font-size:1.05rem;letter-spacing:.02em}
  .logo-t span{color:var(--org)}
  .ver-badge{font-family:var(--fm);font-size:.65rem;color:#aeb8c7;text-align:right;margin-top:4px}
  .meta-row{display:flex;gap:28px;margin-top:20px;position:relative;z-index:1;flex-wrap:wrap}
  .meta-row .m{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:#8b95a6}
  .meta-row .m b{display:block;font-size:.92rem;text-transform:none;letter-spacing:0;color:#fff;font-weight:600;margin-top:2px}
  .tlp{display:inline-block;background:var(--amber);color:#3a2e00;font-weight:700;font-size:.62rem;padding:3px 9px;border-radius:3px;letter-spacing:.07em;border:1px solid #b8860b}
  .cnt{padding:0 40px}
  .card{background:var(--card);border:1px solid var(--bdr);border-radius:10px;margin-top:22px;overflow:hidden;box-shadow:0 1px 3px rgba(31,39,51,.04)}
  .card-hd{padding:16px 22px;border-bottom:1px solid var(--bdr);display:flex;align-items:baseline;gap:12px}
  .sec-no{font-family:var(--fm);font-size:.78rem;color:var(--org2);font-weight:700}
  .card-label{font-size:1.02rem;font-weight:700;letter-spacing:-.01em}
  .card-sub{font-size:.74rem;color:var(--mut);margin-left:auto}
  .card-bd{padding:20px 22px}
  .snap{display:grid;grid-template-columns:170px 1fr;gap:26px;align-items:center}
  .score-ring{position:relative;width:150px;height:150px;margin:0 auto}
  .score-c{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
  .score-n{font-size:2.7rem;font-weight:800;line-height:1;color:var(--org2)}
  .score-s{font-size:.6rem;text-transform:uppercase;letter-spacing:.07em;color:var(--mut);margin-top:3px;text-align:center}
  .pill{margin-top:8px;background:var(--red-bg);color:var(--red-d);border:1px solid var(--red-bd);font-size:.66rem;font-weight:700;padding:3px 11px;border-radius:20px;letter-spacing:.04em}
  .bars{display:flex;flex-direction:column;gap:11px}
  .bar{display:grid;grid-template-columns:78px 1fr 38px;align-items:center;gap:12px}
  .bar-l{font-size:.78rem;color:var(--mut);font-weight:600}
  .bar-t{height:8px;background:#eef2f8;border-radius:5px;overflow:hidden}
  .bar-f{height:100%;border-radius:5px}
  .bar-n{font-size:.85rem;font-weight:700;text-align:right;font-variant-numeric:tabular-nums}
  .f-gap{background:var(--red)} .f-par{background:var(--org)} .f-sat{background:var(--grn)} .f-na{background:#9aa6b8}
  .baseline-note{margin-top:16px;padding:10px 14px;background:var(--bg);border-radius:7px;font-size:.78rem;color:var(--mut);border-left:3px solid var(--org)}
  table{width:100%;border-collapse:collapse;font-size:.82rem}
  th{text-align:left;font-size:.66rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);font-weight:700;padding:8px 12px;border-bottom:2px solid var(--bdr);background:#fafcff}
  td{padding:9px 12px;border-bottom:1px solid var(--bdr);vertical-align:top}
  tr:last-child td{border-bottom:none}
  .cid{font-family:var(--fm);font-size:.72rem;color:var(--teal);white-space:nowrap}
  .hsg{font-family:var(--fm);font-size:.72rem;color:var(--mut)}
  .st{display:inline-block;font-size:.64rem;font-weight:700;padding:2px 9px;border-radius:4px;white-space:nowrap}
  .st-done{background:var(--grn-bg);color:var(--grn);border:1px solid var(--grn-bd)}
  .st-prog{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber-bd)}
  .st-queue{background:#eef2ff;color:#3730a3;border:1px solid #c7d2fe}
  .callout{border-radius:9px;padding:16px 18px;margin-top:4px}
  .callout h4{font-size:.74rem;text-transform:uppercase;letter-spacing:.06em;margin-bottom:7px;display:flex;align-items:center;gap:7px}
  .callout p{font-size:.85rem;line-height:1.58}
  .co-risk{background:var(--red-bg);border:1px solid var(--red-bd)}
  .co-risk h4{color:var(--red-d)}
  .co-def{background:var(--grn-bg);border:1px solid var(--grn-bd)}
  .co-def h4{color:var(--grn)}
  .co-lic{background:var(--amber-bg);border:1px solid var(--amber-bd);margin-top:14px}
  .co-lic h4{color:var(--amber)}
  .ico{width:15px;height:15px;display:inline-block;vertical-align:-2px}
  .resid-grid{display:flex;gap:14px;margin-bottom:14px;flex-wrap:wrap}
  .resid{flex:1;min-width:120px;text-align:center;padding:13px;border-radius:8px;border:1px solid var(--bdr)}
  .resid .rn{font-size:1.8rem;font-weight:800;line-height:1}
  .resid .rl{font-size:.66rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);margin-top:4px}
  .resid.crit .rn{color:var(--red)} .resid.high .rn{color:var(--org2)} .resid.open .rn{color:var(--ink)}
  .ftr{margin:30px 40px 0;padding-top:18px;border-top:1px solid var(--bdr);display:flex;justify-content:space-between;align-items:center;font-size:.7rem;color:var(--mut);flex-wrap:wrap;gap:8px}
  .ftr b{color:var(--ink)}
  @media print{body{background:#fff}.card{box-shadow:none;break-inside:avoid}.hdr::after{display:none}}
  @media(max-width:640px){.snap{grid-template-columns:1fr}.cnt,.hdr,.ftr{padding-left:20px;padding-right:20px}.ftr{margin-left:20px;margin-right:20px}}
</style>
</head>
<body>
<div class="wrap">

  <div class="hdr">
    <div class="hdr-top">
      <div>
        <div class="doc-title">Monthly Security &amp; HIPAA Compliance Report</div>
        <div class="doc-sub">Managed Security Services &middot; Reporting Period: $period</div>
      </div>
      <div style="text-align:right">
        <div class="logo-t">$brandName</div>
        <div class="ver-badge">NRG-Assessment v$toolVer</div>
      </div>
    </div>
    <div class="meta-row">
      <div class="m">Client<b>$clientNm</b></div>
      <div class="m">Entity Type<b>$entity</b></div>
      <div class="m">Tenant<b>$tenant</b></div>
      <div class="m">Assessment Date<b>$assessDate</b></div>
      <div class="m">Classification<b><span class="tlp">$tlp</span></b></div>
    </div>
  </div>

  <div class="cnt">

    <div class="card">
      <div class="card-hd"><span class="sec-no">01</span><span class="card-label">Posture Snapshot</span>
        <span class="card-sub">$($Findings.Count) controls assessed &middot; $($cov.Scored) scored &middot; $na N/A</span></div>
      <div class="card-bd">
        <div class="snap">
          <div>
            <div class="score-ring">
              <svg width="150" height="150" viewBox="0 0 160 160">
                <circle fill="none" stroke="#eef2f8" stroke-width="11" cx="80" cy="80" r="70"/>
                <circle fill="none" stroke="var(--org2)" stroke-width="11" cx="80" cy="80" r="70" stroke-linecap="round" stroke-dasharray="$circumference" stroke-dashoffset="$dashOffset" transform="rotate(-90 80 80)"/>
              </svg>
              <div class="score-c">
                <div class="score-n">$score</div>
                <div class="score-s">Security Score<br>/ 100</div>
                <div class="pill">$postureLbl</div>
              </div>
            </div>
          </div>
          <div class="bars">
            <div class="bar"><span class="bar-l">Gaps</span><div class="bar-t"><div class="bar-f f-gap" style="width:$wGap%"></div></div><span class="bar-n">$gap</span></div>
            <div class="bar"><span class="bar-l">Partial</span><div class="bar-t"><div class="bar-f f-par" style="width:$wPar%"></div></div><span class="bar-n">$part</span></div>
            <div class="bar"><span class="bar-l">Satisfied</span><div class="bar-t"><div class="bar-f f-sat" style="width:$wSat%"></div></div><span class="bar-n">$sat</span></div>
            <div class="bar"><span class="bar-l">Not Applic.</span><div class="bar-t"><div class="bar-f f-na" style="width:$wNa%"></div></div><span class="bar-n">$na</span></div>
            <div class="baseline-note">$trendNote</div>
          </div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-hd"><span class="sec-no">02</span><span class="card-label">Work Completed This Period</span></div>
      <div class="card-bd" style="padding:0">
        <table>
          <thead><tr><th>Service / Action</th><th>Control</th><th>HIPAA Safeguard</th><th>Status</th></tr></thead>
          <tbody>
$workCompletedRows
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-hd"><span class="sec-no">03</span><span class="card-label">In Progress — Phase 1 Remediation</span>
        <span class="card-sub">Critical &amp; high-severity items underway</span></div>
      <div class="card-bd" style="padding:0">
        <table>
          <thead><tr><th>Item</th><th>Control</th><th>HIPAA Safeguard</th><th>Status</th></tr></thead>
          <tbody>
$inProgressRows
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-hd"><span class="sec-no">04</span><span class="card-label">Queued / Service Roadmap</span></div>
      <div class="card-bd" style="padding:0">
        <table>
          <thead><tr><th>Planned Service</th><th>Control</th><th>HIPAA Safeguard</th><th>Status</th></tr></thead>
          <tbody>
$queuedRows
          </tbody>
        </table>
      </div>
    </div>

    <div class="card">
      <div class="card-hd"><span class="sec-no">05</span><span class="card-label">Residual Risk Statement</span></div>
      <div class="card-bd">
        <div class="resid-grid">
          <div class="resid crit"><div class="rn">$critOpen</div><div class="rl">Critical Open</div></div>
          <div class="resid high"><div class="rn">$highOpen</div><div class="rl">High Open</div></div>
          <div class="resid open"><div class="rn">$totalOpen</div><div class="rl">Total Gaps Open</div></div>
        </div>
        <div class="callout co-risk">
          <h4><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>Accepted Residual Risk</h4>
          <p>As of this report, <b>$critOpen critical</b> and <b>$highOpen high-severity</b> gaps remain open. These constitute documented, accepted residual risk pending remediation per the agreed roadmap. Remediation pace is governed by the current service scope and budget; expanding scope accelerates closure of the remaining exposure. Risk ratings follow NIST RMF terminology.</p>
        </div>
$licCallout
      </div>
    </div>

    <div class="card">
      <div class="card-hd"><span class="sec-no">06</span><span class="card-label">HIPAA Defensibility Note</span></div>
      <div class="card-bd">
        <div class="callout co-def">
          <h4><svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>Compliance Posture &amp; Liability Position</h4>
          <p>This report documents the ongoing security risk-management process required under <b>&sect;164.308(a)(1)</b> of the HIPAA Security Rule. A maintained, dated remediation roadmap with tracked progress demonstrates good-faith, continuous compliance effort &mdash; a material factor in any breach investigation or OCR audit. Monthly delivery of this report establishes the documentation trail that protects both the covered entity and the Business Associate. Retain each monthly report as part of the compliance record.</p>
        </div>
      </div>
    </div>

  </div>

  <div class="ftr">
    <div>Prepared by <b>$brandName</b></div>
    <div>Generated from NRG-Assessment v$toolVer &middot; $assessDate &middot; <b>$tlp</b></div>
  </div>

</div>
</body>
</html>
"@

    # ── Emit HTML + JSON ─────────────────────────────────────────────────────
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Force -LiteralPath $outDir | Out-Null
    }
    # v4.11.3 (audit finding #1 deeper fix): self-harden via terminal helper.
    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $OutputPath -Content $html
    } else {
        $html | Out-File -LiteralPath $OutputPath -Encoding utf8 -NoNewline
    }

    # Sibling JSON — becomes next month's -PriorMonthPath input.
    $jsonOut = [ordered]@{
        Period          = $delta['Period']
        EntityType      = $delta['EntityType']
        TLP             = $delta['TLP']
        ClientName      = (Get-NRGObjectField -Item $Metadata -Key 'ClientName' -Default $tenant)
        TenantDomain    = (Get-NRGObjectField -Item $Metadata -Key 'TenantDomain' -Default 'unknown')
        AssessmentDate  = (Get-NRGObjectField -Item $Metadata -Key 'AssessmentDate' -Default (Get-Date -Format 'MMMM dd, yyyy'))
        Score           = $score
        Posture         = $postureLbl
        Counts          = [ordered]@{
            Satisfied = $sat; Partial = $part; Gap = $gap; NotApplicable = $na
            CriticalOpen = $critOpen; HighOpen = $highOpen; TotalOpen = $totalOpen
            LicenseBlocked = $licBlocked
        }
        WorkCompleted   = $workCompleted
        InProgress      = $inProgress
        Queued          = $queued
        GeneratedBy     = "NRG-Assessment v$toolVer"
        GeneratedAt     = (Get-Date -Format 'o')
    }
    $jsonPath = $OutputPath -replace '\.html?$', '.json'
    if ($jsonPath -eq $OutputPath) { $jsonPath = "$OutputPath.json" }
    # v4.11.3 (audit finding #1 deeper fix): self-harden via terminal helper.
    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $jsonPath -Content ($jsonOut | ConvertTo-Json -Depth 8)
    } else {
        $jsonOut | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $jsonPath -Encoding utf8
    }

    Write-Host "  [+] Monthly report: $OutputPath" -ForegroundColor Green
    Write-Host "  [+] Monthly state:  $jsonPath" -ForegroundColor Green
    return [pscustomobject]@{
        HtmlPath = $OutputPath
        JsonPath = $jsonPath
        Score    = $score
        Posture  = $postureLbl
    }
}
