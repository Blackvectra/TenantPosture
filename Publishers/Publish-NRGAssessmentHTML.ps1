#Requires -Version 7.0
#
# Publish-NRGAssessmentHTML.ps1  (v4.5.5)
# Premium client-deliverable HTML report. Self-contained, print-to-PDF ready.
#
# Sections: Header · Executive overview · Workload scorecards ·
#           Framework compliance matrix · License gap analysis ·
#           Priority actions · All findings by workload · Footer + CTA
#
# SECURITY: All tenant data passes through ConvertTo-NRGHtmlSafe.
#           All URLs pass through ConvertTo-NRGSafeUrl.
#           CSS color values validated against allowlist pattern.
#           MITRE IDs validated against ^T\d{4}(\.\d{3})?$
#           Fail-closed if security helpers not loaded.
#
# Author: Matthew Levorson — NRG Technology Services / NextLayerSec LLC
#

function Publish-NRGAssessmentHTML {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Metadata,
        [Parameter(Mandatory)] [object[]]  $Findings,
        [Parameter(Mandatory)] $Connections,
        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed in OutputPath.' }
            if ($_ -match '[<>"|?*]')   { throw 'Invalid characters in OutputPath.' }
            return $true
        })]
        [string] $OutputPath,
        [string] $ClientName = '',

        # Optional in-report downloads. Each item: @{ Label; FileName; Mime;
        # Content }. Rendered as CSP-safe <a download> data-URI buttons so the
        # single HTML can carry the remediation script, a CSV matrix, etc.,
        # instead of the run scattering a dozen sidecar files. Empty = no card.
        [object[]] $Attachments = @(),

        # Which frameworks the report presents. NRG runs NIST-only by default —
        # the tool still CITES every framework on every control and still scores
        # them, this only decides what the report puts in front of the reader.
        # Narrowing the report never narrows the assessment.
        [ValidateNotNullOrEmpty()]
        [string[]] $Frameworks = @('CIS','SCuBA','NIST','CMMC')
    )

    if (-not (Get-Command ConvertTo-NRGHtmlSafe -ErrorAction SilentlyContinue)) {
        throw 'ConvertTo-NRGHtmlSafe not loaded — refusing to generate report.'
    }
    if (-not (Get-Command ConvertTo-NRGSafeUrl -ErrorAction SilentlyContinue)) {
        throw 'ConvertTo-NRGSafeUrl not loaded — refusing to generate report.'
    }

    # ── Helpers ───────────────────────────────────────────────────────────────
    function Test-SafeColor { param([string]$v)
        if ([string]::IsNullOrWhiteSpace($v)) { return $false }
        if ($v -match '[;{}<>"' + "'" + '/\*\n\r]') { return $false }
        return ($v -match '^#[0-9a-fA-F]{3,8}$' -or $v -match '^[a-zA-Z]{3,20}$' -or
                $v -match '^(rgb|rgba|hsl|hsla)\([0-9,.\s%]+\)$')
    }
    function sc { param([string]$v,[string]$d) if (Test-SafeColor $v) { return $v }; return $d }
    function hx { param([AllowNull()][AllowEmptyString()][object]$s) ConvertTo-NRGHtmlSafe $s }

    function sBadge { param([string]$s)
        switch ($s) {
            'Satisfied'     { '<span class="b bp">&#10003; Pass</span>' }
            'Partial'       { '<span class="b bw">&#9679; Partial</span>' }
            'Gap'           { '<span class="b bg">&#10005; Gap</span>' }
            'NotApplicable' { '<span class="b bn">&mdash; N/A</span>' }
            default         { "<span class=`"b`">$(hx $s)</span>" }
        }
    }
    function svBadge { param([string]$s)
        switch ($s) {
            'Critical' { '<span class="sv svc">Critical</span>' }
            'High'     { '<span class="sv svh">High</span>' }
            'Medium'   { '<span class="sv svm">Medium</span>' }
            'Low'      { '<span class="sv svl">Low</span>' }
            default    { '<span class="sv svi">Info</span>' }
        }
    }
    function pct { param([int]$n,[int]$d) if ($d -gt 0) { [int]($n * 100 / $d) } else { 0 } }
    function scoreColor { param([int]$s)
        if ($s -ge 85) { '#059669' } elseif ($s -ge 65) { '#ca8a04' } elseif ($s -ge 40) { '#ea580c' } else { '#dc2626' }
    }

    # ── Brand (null-safe — brand object may not be present) ─────────────────
    $brand = if ($Metadata -and $null -ne $Metadata['Brand'] -and $null -ne $Metadata['Brand']) { $Metadata['Brand'] } else { @{} }
    $P  = sc ($brand['PrimaryColor'])   '#0f2544'
    $S  = sc ($brand['SecondaryColor']) '#e8621a'
    $A  = sc ($brand['AccentColor'])    '#3b7dd8'
    $co = if ($brand['CompanyName']) { $brand['CompanyName'] } else { 'NRG Technology Services / NextLayerSec LLC' }
    $ph = if ($brand['Phone']) { $brand['Phone'] } else { '' }
    $ws = if ($brand['Website']) { $brand['Website'] } else { 'nrgtechservices.com' }
    # Normalize the Website value to a bare host so the templates below can
    # consistently prepend `https://`. The branding config may store the full
    # URL (`https://www.nrgtechservices.com`) but the templates also assume bare-host.
    # Without this strip, the footer rendered
    # `<a href='https://https://www.nrgtechservices.com'>` which the browser parsed as
    # host=`https:` + path=`//nrgtechservices.com` — visible as `https://https//`
    # in the link text.
    $ws = $ws -replace '^https?://', ''
    $lu = if ($brand['LogoUrl']) { $brand['LogoUrl'] } else { '' }
    $clientDisplay = if ($ClientName) { $ClientName } else { $Metadata.TenantDomain }

    # ── Counts ────────────────────────────────────────────────────────────────
    # v4.10.1: tenant-wide score now from Get-NRGCoverageScore. -ErrorHandling Gap
    # preserves the historical HTML semantics (Error counted in denominator,
    # which deflates the score for collector failures). The maturity badge on
    # the same report still uses the canonical Error-Exclude rule (per
    # Get-NRGMaturityTier's documented rationale) — so a tenant with Error
    # findings will see the badge sit slightly above the ring, by design.
    $cov  = Get-NRGCoverageScore -Findings $Findings -ErrorHandling 'Gap'
    $sat  = $cov.Satisfied
    $part = $cov.Partial
    $gap  = $cov.Gap
    $na   = $cov.NA
    $scrd = $cov.Scored
    $sc2  = $cov.Score
    $pLbl = if ($sc2 -ge 85) {'Strong'} elseif ($sc2 -ge 65) {'Moderate'} elseif ($sc2 -ge 40) {'At Risk'} else {'Critical Risk'}
    $pCol = scoreColor $sc2
    $circ = 452.4
    $off  = [Math]::Round($circ * (1 - $sc2 / 100), 2)
    $crit = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -eq 'Critical' }).Count
    $high = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -eq 'High' }).Count
    $med  = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -eq 'Medium' }).Count
    $low  = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -eq 'Low' }).Count

    # ── Control definitions ───────────────────────────────────────────────────
    $cdefs = @{}
    try { foreach ($c in (Get-NRGControlDefinitions)) { $cdefs[$c.ControlId] = $c } } catch { }

    # ── Inventory findings (named objects) ───────────────────────────────────
    $invFindings = @($Findings | Where-Object {
        $_.State -eq 'Gap' -and
        $_.AffectedObjects -and @($_.AffectedObjects).Count -gt 0
    })

    # ── Workload scores ───────────────────────────────────────────────────────
    $wlNames  = @{AAD='Identity';EXO='Email';DNS='DNS Auth';DEF='Defender';SPO='SharePoint';TMS='Teams';INT='Intune';PVW='Purview';PPL='Power Platform'}
    $wlFull   = @{AAD='Identity & Access';EXO='Exchange Online';DNS='DNS Email Auth';DEF='Microsoft Defender';SPO='SharePoint / OneDrive';TMS='Microsoft Teams';INT='Intune & Endpoint';PVW='Purview / Compliance';PPL='Power Platform'}
    $wlOrder  = @('AAD','EXO','DEF','DNS','SPO','TMS','INT','PVW','PPL')
    # v4.10.1: per-workload + per-framework scores now go through the same
    # canonical helper as the tenant-wide score. -ErrorHandling Gap preserves
    # historical behavior. The grouping (workload prefix split) stays here
    # so we don't re-iterate findings per workload; we hand the filtered
    # group directly to the helper.
    $wlScores = @{}
    $Findings | Group-Object { ($_.ControlId -replace '-.*$','') } | ForEach-Object {
        $wl = $_.Name; $g = $_.Group
        $wcov = Get-NRGCoverageScore -Findings $g -ErrorHandling 'Gap'
        $wlScores[$wl] = @{
            Score  = $wcov.Score
            Gaps   = $wcov.Gap
            Scored = $wcov.Scored
        }
    }

    # ── Framework scores ──────────────────────────────────────────────────────
    # Scored for every framework regardless of what is displayed: the JSON
    # export and any later re-render need them, and a narrowed report must not
    # become a narrowed record.
    $fwScores = @{}
    foreach ($fw in @('CIS','SCuBA','NIST','CMMC')) {
        $fwScores[$fw] = (Get-NRGCoverageScore -Findings $Findings -FrameworkId $fw -ErrorHandling 'Gap').Score
    }
    # Displayed set, in canonical order, ignoring anything unrecognised.
    $fwShow = @(@('CIS','SCuBA','NIST','CMMC') | Where-Object { $_ -in $Frameworks })
    if ($fwShow.Count -eq 0) { $fwShow = @('NIST') }

    # ── License detection — suppress gaps the tenant already has licenses for ────
    # Detection is centralised in Lib/Get-NRGTenantLicenseProfile.ps1 so the
    # HTML, Markdown, remediation script, and playbook publishers all see the
    # same suppression set. v4.6.1 inlined the logic here and applied it only
    # to the "License Gap Analysis" card — every other site (Priority Actions,
    # per-finding rows, remediation script, playbook) still emitted
    # "Requires: M365 Business Premium" against tenants that already had BP.
    $licProfile = if (Get-Command Get-NRGTenantLicenseProfile -ErrorAction SilentlyContinue) {
        try { Get-NRGTenantLicenseProfile } catch { $null }
    } else { $null }

    # Compatibility aliases — preserve existing variable names referenced
    # elsewhere in this file. Falls back to $false when the helper is not
    # available (e.g. unit-test load of just the publisher).
    $hasBusinessPremium = if ($licProfile) { $licProfile.HasBusinessPremium } else { $false }
    $hasEntraP2         = if ($licProfile) { $licProfile.HasEntraP2 }         else { $false }
    # NB: assign the HashSet DIRECTLY, never as the output of an if-block. An
    # if/else expression ENUMERATES an IEnumerable result — an empty HashSet
    # would yield $null (then .Contains() below throws) and a non-empty one
    # would collapse to a plain case-sensitive string[]. Direct assignment
    # preserves the real OrdinalIgnoreCase HashSet.
    $suppressedLicReqs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if ($licProfile -and $licProfile.SuppressedLicenseRequirements) {
        $suppressedLicReqs = $licProfile.SuppressedLicenseRequirements
    }
    $tierLabel          = if ($licProfile) { $licProfile.TierLabel } else { 'Unknown' }

    # ── License groups (only show what the tenant actually needs) ─────────────
    $licGroups = @{}
    # Count both open Gaps that need a license AND license-gated NotApplicable
    # findings (controls an evaluator could not assess because the tenant lacks
    # the license — e.g. Safe Attachments without Defender for Office 365 P1).
    # The latter are deliberately kept out of the compliance score (NotApplicable)
    # but must still surface here as upgrade opportunities. They are recognised by
    # the "upgrade opportunity" marker the evaluators place in the detail, so
    # unrelated NotApplicable findings (data-not-collected, no-devices, etc.) are
    # never mis-counted as license gaps.
    foreach ($f in ($Findings | Where-Object { $_.State -eq 'Gap' -or ($_.State -eq 'NotApplicable' -and $_.Detail -match 'upgrade opportunity') })) {
        $ctrl = $cdefs[$f.ControlId]
        if ($ctrl -and $ctrl.LicenseRequirement -and
            $ctrl.LicenseRequirement -notmatch '^Included' -and
            -not $suppressedLicReqs.Contains($ctrl.LicenseRequirement)) {
            $lic = $ctrl.LicenseRequirement
            if (-not $licGroups.ContainsKey($lic)) { $licGroups[$lic] = 0 }
            $licGroups[$lic]++
        }
    }
    $totalBlocked = ($licGroups.Values | Measure-Object -Sum).Sum

    # ── Logo ──────────────────────────────────────────────────────────────────
    $ls = ''
    if ($lu) {
        if ($lu -match '^data:image/(png|jpe?g|svg\+xml|webp);base64,[A-Za-z0-9+/=]+$') { $ls = $lu } else { $ls = ConvertTo-NRGSafeUrl $lu }
    }
    $logoH = if ($ls) { "<img src='$ls' alt='$(hx $co)' class='logo'>" } else { "<span class='logo-t'>$(hx $co)</span>" }

    # ── Narrative ─────────────────────────────────────────────────────────────
    $narr = if ($crit -gt 0) {
        "Assessment identified <strong style='color:#dc2626'>$crit critical</strong> and <strong style='color:#ea580c'>$high high-severity</strong> gaps requiring immediate action."
    } elseif ($high -gt 0) {
        "No critical gaps. Assessment identified <strong style='color:#ea580c'>$high high-severity</strong> gaps to address in the near term."
    } elseif ($gap -gt 0) {
        "No critical or high-severity gaps. <strong>$gap medium/low severity</strong> items to resolve."
    } else { 'All assessed controls are satisfied. No gaps identified.' }

    # ── Connections ───────────────────────────────────────────────────────────
    $svcMap = @{Graph='Microsoft Graph';EXO='Exchange Online';IPPSSession='Purview/Compliance';Teams='Microsoft Teams';SharePoint='SharePoint Online'}
    $connHtml = ''
    # Check coverage data to supplement connection flags — Graph can have data even if flag is false
    $aadHasData = try { $gd = Get-NRGRawData -Key 'AAD-CAPolicies'; $gd -and $gd.Success } catch { $false }
    foreach ($svc in @('Graph','EXO','IPPSSession','Teams','SharePoint')) {
        $ok = if ($Connections -is [hashtable]) {
            $Connections.ContainsKey($svc) -and $Connections[$svc] -eq $true
        } else { $Connections.$svc -eq $true }
        # Override: if Graph flag is false but AAD data was collected, mark as connected
        if (-not $ok -and $svc -eq 'Graph' -and $aadHasData) { $ok = $true }
        $cls = if ($ok) { 'cok' } else { 'coff' }
        $ico = if ($ok) { '&#10003;' } else { '&#10005;' }
        $connHtml += "<div class='conn $cls'><span>$ico</span><span>$(hx $svcMap[$svc])</span></div>"
    }

    # ── Risk exposure HTML (PR #8 — Get-NRGAggregateRisk) ────────────────────
    # Translates open Gap/Partial findings into annualized loss expectancy.
    # Degrades to an empty $riskHtml if the risk-quantification module from
    # PR #8 is not loaded; the Executive Overview card still renders cleanly.
    $riskHtml = ''
    if (Get-Command Get-NRGAggregateRisk -CommandType Function -Module NRG-Assessment -ErrorAction SilentlyContinue) {
        try {
            $risk = Get-NRGAggregateRisk -Findings $Findings
            if ($risk.OpenGapAndPartialCount -gt 0) {
                $sevRows = ''
                foreach ($sev in @('Critical','High','Medium','Low')) {
                    if ($risk.BySeverity.ContainsKey($sev)) {
                        $b = $risk.BySeverity[$sev]
                        $range = '$' + ('{0:N0}' -f $b.Low) + ' – $' + ('{0:N0}' -f $b.High)
                        $sevRows += "<tr><td>$(hx $sev)</td><td style='text-align:right'>$($b.Count)</td><td style='text-align:right'>$(hx $range)</td></tr>"
                    }
                }
                $totalRange  = $risk.TotalRangeFormatted
                $midpoint    = $risk.TotalMidpointFormatted
                $riskHtml = @"
<div class="card mt" id="risk-exposure">
  <div class="card-hd">
    <div class="card-label">Estimated Annual Risk Exposure</div>
    <div class="card-sub">$(hx $risk.OpenGapAndPartialCount) open Gap and Partial findings, annualized loss expectancy bands</div>
  </div>
  <div class="ex-dash">
    <div class="score-wrap br">
      <div class="score-c" style="padding:8px 16px">
        <div class="score-n" style="font-size:1.9rem;line-height:1.1">$(hx $midpoint)</div>
        <div class="score-s">Midpoint estimate / year</div>
        <div class="posture-pill" style="margin-top:8px">$(hx $totalRange)</div>
      </div>
    </div>
    <div class="stat-col br" style="padding-left:20px">
      <table style="width:100%;border-collapse:collapse;font-size:.95rem">
        <thead>
          <tr style="border-bottom:1px solid #e4e9f2">
            <th style="text-align:left;padding:6px 4px">Severity</th>
            <th style="text-align:right;padding:6px 4px">Open</th>
            <th style="text-align:right;padding:6px 4px">Annual range</th>
          </tr>
        </thead>
        <tbody>$sevRows</tbody>
      </table>
    </div>
    <div class="conn-col" style="font-size:.85rem;color:#4a5568;line-height:1.5">
      <div class="conn-t">Methodology</div>
      <p style="margin:6px 0 0 0">SLE &times; ARO &mdash; SLE anchored to Verizon DBIR 2025 incident-cost medians and IBM Cost of a Data Breach 2024. ARO from Microsoft Digital Defense Report 2024. Bands, not point estimates.</p>
    </div>
  </div>
</div>
"@
            }
        } catch {
            # Risk calc failure must never break the rest of the report
            Write-Warning "Risk exposure calculation failed: $($_.Exception.Message)"
            $riskHtml = ''
        }
    }

    # ── Score-lift remediation roadmap (PR: Get-NRGRemediationRoadmap) ────────
    # Turns the grade into a guide: ranks the zero-license quick wins by exact
    # compliance-score points returned, with a running projected score. Degrades
    # to an empty $scoreRoadmapHtml if the helper isn't loaded or throws — the
    # rest of the report renders unchanged.
    $scoreRoadmapHtml = ''
    if (Get-Command Get-NRGRemediationRoadmap -CommandType Function -ErrorAction SilentlyContinue) {
        try {
            $rm = Get-NRGRemediationRoadmap -Findings $Findings
            if ($rm.QuickWinCount -gt 0) {
                $rows = ''
                foreach ($q in $rm.QuickWins) {
                    $sevCls = switch ($q.Severity) { 'Critical' {'svc'} 'High' {'svh'} 'Medium' {'svm'} default {'svl'} }
                    $rem    = if ($q.Remediation) { hx $q.Remediation } else { '' }
                    $rows += @"
<tr>
  <td style='text-align:center;font-weight:700;color:var(--mut)'>$($q.Rank)</td>
  <td><span class='mono'>$(hx $q.ControlId)</span> <span class='sv $sevCls' style='margin-left:4px'>$(hx $q.Severity)</span><div style='font-size:.82rem;color:var(--mut);margin-top:2px'>$(hx $q.Title)</div>$(if($rem){"<div style='font-size:.8rem;margin-top:4px'>$rem</div>"})</td>
  <td style='text-align:right;white-space:nowrap;font-weight:700;color:var(--pass)'>+$($q.ScoreLift)</td>
  <td style='text-align:right;white-space:nowrap;font-weight:700'>$($q.CumulativeScore)</td>
</tr>
"@
                }
                $unlockNote = if ($rm.LicenseUnlockCount -gt 0) {
                    "<div class='rm-lic-note'>&#128273; $($rm.LicenseUnlockCount) additional fix$(if($rm.LicenseUnlockCount -ne 1){'es'}) require a license upgrade first — see <strong>License Gap Analysis</strong> above. Those are not counted in the projection below because a license purchase changes the scoring denominator.</div>"
                } else { '' }
                $scoreRoadmapHtml = @"
<div class='card mt' id='score-roadmap'>
  <div class='card-hd'>
    <div><div class='card-label'>Prioritized Remediation Roadmap</div><div class='card-sub'>Zero-license quick wins ranked by exact compliance-score points returned</div></div>
    <div class='rm-proj'><span class='rm-proj-n'>$($rm.BaselineScore) &rarr; $($rm.ProjectedScoreAllQuickWins)</span><span class='rm-proj-s'>projected score</span></div>
  </div>
  <div class='rm-headline'>Completing these <strong>$($rm.QuickWinCount)</strong> configuration change$(if($rm.QuickWinCount -ne 1){'s'}) — all covered by the tenant's current licensing — raises the compliance score by <strong>+$($rm.QuickWinPointGain) point$(if($rm.QuickWinPointGain -ne 1){'s'})</strong>, from $($rm.BaselineScore) to $($rm.ProjectedScoreAllQuickWins).</div>
  $unlockNote
  <div style='overflow-x:auto'>
  <table class='rm-tbl' style='width:100%;border-collapse:collapse;font-size:.9rem;margin-top:10px'>
    <thead><tr style='border-bottom:2px solid var(--bdr);text-align:left'>
      <th style='padding:6px 8px;text-align:center'>#</th>
      <th style='padding:6px 8px'>Control &amp; fix</th>
      <th style='padding:6px 8px;text-align:right'>Score lift</th>
      <th style='padding:6px 8px;text-align:right'>Running score</th>
    </tr></thead>
    <tbody>$rows</tbody>
  </table>
  </div>
  <div class='rm-method'>Projection is exact: each fix moves a Gap or Partial to Satisfied in the same coverage formula that produces the score ring (Gap +1.0, Partial +0.5 of one control's weight). Quick wins do not change the scoring denominator, so the running score is arithmetic, not an estimate.</div>
</div>
"@
            }
        } catch {
            Write-Warning "Remediation roadmap render failed: $($_.Exception.Message)"
            $scoreRoadmapHtml = ''
        }
    }

    # ── Embedded downloads card (CSP-safe <a download> data-URIs) ────────────
    # Lets the single self-contained report CARRY the sidecar deliverables
    # (remediation script, CSV matrix, evidence JSON) instead of the run writing
    # a folder full of files. default-src 'none' does not block <a download>
    # navigations to data: URIs, so no script and no CSP change is needed.
    $attachHtml = ''
    if ($Attachments -and @($Attachments).Count -gt 0) {
        $btns = ''
        foreach ($a in $Attachments) {
            if ($null -eq $a) { continue }
            $label = [string](& { if ($a -is [System.Collections.IDictionary]) { $a['Label'] } else { $a.Label } })
            $fname = [string](& { if ($a -is [System.Collections.IDictionary]) { $a['FileName'] } else { $a.FileName } })
            $mime  = [string](& { if ($a -is [System.Collections.IDictionary]) { $a['Mime'] } else { $a.Mime } })
            $body  =         (& { if ($a -is [System.Collections.IDictionary]) { $a['Content'] } else { $a.Content } })
            if ([string]::IsNullOrWhiteSpace($fname) -or $null -eq $body) { continue }
            if ([string]::IsNullOrWhiteSpace($mime))  { $mime = 'application/octet-stream' }
            if ([string]::IsNullOrWhiteSpace($label)) { $label = $fname }
            $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes([string]$body))
            $btns += "<a class='dl-btn' download='$(hx $fname)' href='data:$(hx $mime);base64,$b64'>&#11015; $(hx $label)</a>"
        }
        if ($btns) {
            $attachHtml = @"
<div class='card mt' id='downloads'>
  <div class='card-hd'><div><div class='card-label'>Downloads</div><div class='card-sub'>Sidecar deliverables embedded in this report — no separate files needed</div></div></div>
  <div class='dl-row'>$btns</div>
</div>
"@
        }
    }

    # ── Workload scorecard HTML ───────────────────────────────────────────────
    $wlGrid = ''
    foreach ($wl in $wlOrder) {
        if (-not $wlScores.ContainsKey($wl)) { continue }
        $ws3  = $wlScores[$wl].Score
        $gps  = $wlScores[$wl].Gaps
        $lbl  = hx $(if ($wlNames[$wl]) { $wlNames[$wl] } else { $wl })
        $col  = scoreColor $ws3
        $ring = [Math]::Round(100.5 * (1 - $ws3/100), 2)
        # Show N/A when no controls scored (all NotApplicable) instead of 0/100
        $wlScored = $wlScores[$wl].Scored
        $wlNaOnly = ($wlScored -eq 0)
        $gapTxt = if ($gps -gt 0) { "<div class='wl-gap'>$gps gap$(if($gps -ne 1){'s'})</div>" } elseif ($wlNaOnly) { "<div class='wl-na'>— Not assessed</div>" } else { "<div class='wl-ok'>&#10003; Clean</div>" }
        $wlGrid += @"
<div class='wl-card'>
  <svg width='54' height='54' viewBox='0 0 36 36'>
    <circle cx='18' cy='18' r='16' fill='none' stroke='#e8edf5' stroke-width='3.5'/>
    <circle cx='18' cy='18' r='16' fill='none' stroke='$col' stroke-width='3.5' stroke-linecap='round'
      stroke-dasharray='100.5' stroke-dashoffset='$ring' transform='rotate(-90 18 18)'
      style='transition:stroke-dashoffset 1.2s ease .3s'/>
  </svg>
  <div class='wl-info'><div class='wl-name'>$lbl</div><div class='wl-score' style='color:$col'>$(if ($wlNaOnly) { '<span style="color:#94a3b8">—</span>' } else { "$ws3<span class=`'wl-den`'>/100</span>" })</div>$gapTxt</div>
</div>
"@
    }

    # ── Framework matrix HTML ────────────────────────────────────────────────
    $fwMeta = @{
        CIS   = @{Full='CIS M365 Foundations v6.0.1'; Bg='#1e40af'}
        SCuBA = @{Full='CISA SCuBA v1.7.1';            Bg='#0c4a6e'}
        NIST  = @{Full='NIST SP 800-53 Rev 5';         Bg='#4c1d95'}
        CMMC  = @{Full='CMMC 2.0 Level 2';             Bg='#134e4a'}
    }
    $fwHtml = ''
    foreach ($fw in $fwShow) {
        $fsc = $fwScores[$fw]; $col = scoreColor $fsc
        $fwHtml += "<div class='fw-card'><div class='fw-hd' style='background:$($fwMeta[$fw].Bg)'>$(hx $fw)</div><div class='fw-body'><div class='fw-sc' style='color:$col'>$fsc<span class='fw-den'>%</span></div><div class='fw-name'>$(hx $fwMeta[$fw].Full)</div></div></div>"
    }

    # ── NIST 800-53 control-family rollup ────────────────────────────────────
    # The single NIST percentage above answers "are we compliant"; it does not
    # answer "with what". A reader working an 800-53, FedRAMP, or CMMC
    # assessment needs the breakdown by control family, because that is the
    # unit their own documentation, POA&M, and auditor conversations are
    # organised around. Every other view in this report groups by M365
    # workload, which is the right lens for the engineer doing the fixing and
    # the wrong one for the compliance reader signing off.
    #
    # A finding citing controls in two families counts in both — see the
    # rationale in Lib/Get-NRGNISTFamilyCoverage.ps1. Family rows therefore do
    # not sum to the assessment total, and the column is labelled "Assessed"
    # rather than "Controls" to make that explicit.
    $nistHtml = ''
    $nistCov  = $null
    if (Get-Command Get-NRGNISTFamilyCoverage -ErrorAction SilentlyContinue) {
        try { $nistCov = Get-NRGNISTFamilyCoverage -Findings $Findings -ErrorHandling 'Gap' }
        catch { $nistCov = $null }
    }
    if ($nistCov -and $nistCov.FamilyCount -gt 0) {
        $nistRows = ''
        foreach ($fam in $nistCov.Families) {
            # A family assessed only through NotApplicable findings has no
            # denominator. Get-NRGCoverageScore returns 0 there, which would
            # render as a red 0% — a failing grade for a question the tool
            # never got to ask. Show an explicit dash instead.
            $famNotScored = ($fam.Scored -le 0)
            $fcol  = if ($famNotScored) { '#94a3b8' } else { scoreColor ([int]$fam.Score) }
            $fbar  = if ($famNotScored) { 0 } else { [int]$fam.Score }
            $scTxt = if ($famNotScored) { '&mdash;' } else { "$([int]$fam.Score)%" }
            # Resolve each 800-53 identifier to its official Rev 5 title. A bare
            # "AC-2, AC-3, AC-6" tells a reader which controls were exercised
            # only if they already know 800-53 by heart; the client reading this
            # report does not, and the whole point of the family view is that it
            # is the auditor's lens. Titles come from the same catalog the
            # standalone NIST matrix uses, so the two deliverables cannot drift.
            # An identifier with no catalog entry renders as the bare code
            # rather than an empty label — a missing title must not silently
            # delete the control from the row.
            $ctlList = (@($fam.NistControls) | ForEach-Object {
                $nid = [string]$_
                $nt  = if (Get-Command Get-NRGNISTControlTitle -ErrorAction SilentlyContinue) {
                    [string](Get-NRGNISTControlTitle -ControlId $nid)
                } else { '' }
                if ($nt -and $nt -ne $nid) {
                    "<span class='nf-cid'>$(hx $nid)</span> $(hx $nt)"
                } else {
                    "<span class='nf-cid'>$(hx $nid)</span>"
                }
            }) -join ' &middot; '
            $nistRows += @"
<tr>
  <td class='nf-id'>$(hx $fam.Family)</td>
  <td class='nf-nm'>$(hx $fam.Name)<div class='nf-ctl'>$ctlList</div></td>
  <td class='nf-n'>$($fam.Assessed)</td>
  <td class='nf-n nf-ok'>$($fam.Satisfied)</td>
  <td class='nf-n nf-pt'>$($fam.Partial)</td>
  <td class='nf-n nf-gp'>$($fam.Gap)</td>
  <td class='nf-n nf-er'>$($fam.Error)</td>
  <td class='nf-n nf-na'>$($fam.NA)</td>
  <td class='nf-sc'>
    <div class='nf-bar'><div class='nf-fill' style='width:$fbar%;background:$fcol'></div></div>
    <span style='color:$fcol'>$scTxt</span>
  </td>
</tr>
"@
        }
        $nistHtml = @"
<div class="card mt" id="nist-families">
  <div class="card-hd">
    <div><div class="card-label">NIST SP 800-53 Rev 5 &mdash; Control Family Coverage</div><div class="card-sub">$($nistCov.FamilyCount) families and $($nistCov.NistControlCount) 800-53 controls exercised by this assessment</div></div>
    <div class="nf-badge">$(hx $fwScores['NIST'])% overall</div>
  </div>
  <div class="nf-wrap">
    <table class="nf-tbl">
      <thead><tr>
        <th>Family</th><th>Name / 800-53 controls exercised</th>
        <th class='nf-n'>Assessed</th><th class='nf-n'>Met</th><th class='nf-n'>Partial</th>
        <th class='nf-n'>Gap</th><th class='nf-n'>Error</th><th class='nf-n'>N/A</th><th>Coverage</th>
      </tr></thead>
      <tbody>$nistRows</tbody>
    </table>
  </div>
  <div class="nf-note">A control mapped to more than one family is counted in each &mdash; family rows do not sum to the assessment total. Met + Partial + Gap + Error + N/A sums to Assessed on every row. <strong>N/A</strong> and <strong>Error</strong> are both excluded from the coverage percentage &mdash; N/A means this tool could not assess the control (missing license, data not collected) and Error means the evaluator threw before reaching a verdict. Neither is a control the tenant passed. A family showing &mdash; had no assessable control at all.</div>
</div>
"@
    }

    # ── NIST physical / device controls HTML ─────────────────────────────────
    # A tenant scan says a great deal about endpoint posture and nothing at all
    # about a locked server room, a certificate of destruction, or a returned
    # badge. Those are real 800-53 controls a client working an 800-53 or CMMC
    # assessment must satisfy, and omitting them silently is the dangerous
    # option: a reader seeing a clean family table would reasonably infer the
    # physical families were assessed and passed.
    #
    # So each row states its scope explicitly and, where the tool cannot see the
    # control, says so and names the evidence the assessor must collect instead.
    # Attested rows carry no verdict and contribute to no score.
    $physHtml = ''
    $physCov  = $null
    if (Get-Command Get-NRGNISTPhysicalPosture -ErrorAction SilentlyContinue) {
        try { $physCov = Get-NRGNISTPhysicalPosture -Findings $Findings }
        catch { $physCov = $null }
    }
    if ($physCov -and $physCov.Available -and @($physCov.Groups).Count -gt 0) {
        $statusMeta = @{
            'Met'                  = @{Cls='pv-met';  Txt='Met'}
            'Partial'              = @{Cls='pv-part'; Txt='Partial'}
            'Gap'                  = @{Cls='pv-gap';  Txt='Gap'}
            'Not assessed'         = @{Cls='pv-na';   Txt='Not assessed'}
            'Attestation required' = @{Cls='pv-att';  Txt='Attestation required'}
        }
        $scopeMeta = @{
            'Tenant'   = 'Evidenced by this assessment'
            'Hybrid'   = 'Partly evidenced &mdash; rest is off-tenant'
            'Attested' = 'Not visible from Microsoft 365'
        }
        $physGroups = ''
        foreach ($grp in $physCov.Groups) {
            $itemHtml = ''
            foreach ($it in $grp.Items) {
                $sm  = if ($statusMeta.ContainsKey($it.Status)) { $statusMeta[$it.Status] } else { @{Cls='pv-na'; Txt=$it.Status} }
                $sct = if ($scopeMeta.ContainsKey($it.Scope))   { $scopeMeta[$it.Scope]   } else { $it.Scope }

                # Evidence chips: the tool controls behind a Tenant/Hybrid row,
                # so a reader can trace the verdict back to a scored control
                # rather than taking the rollup on faith.
                $evHtml = ''
                foreach ($ev in @($it.Evidence)) {
                    $evCls = switch ($ev.State) {
                        'Satisfied' { 'ev-ok' }
                        'Partial'   { 'ev-pt' }
                        'Gap'       { 'ev-gp' }
                        default     { 'ev-na' }
                    }
                    $evHtml += "<span class='pv-ev $evCls'>$(hx $ev.ControlId)</span>"
                }

                $optHtml = ''
                foreach ($opt in @($it.Options)) { $optHtml += "<li>$(hx $opt)</li>" }

                $itemHtml += @"
<div class='pv-item'>
  <div class='pv-hd'>
    <div class='pv-cid'>$(hx $it.NistControl)</div>
    <div class='pv-ttl'>$(hx $it.NistTitle)<div class='pv-scope'>$sct</div></div>
    <span class='pv-st $($sm.Cls)'>$($sm.Txt)</span>
  </div>
  $(if ($it.DeviceAspect) { "<div class='pv-asp'>$(hx $it.DeviceAspect)</div>" })
  $(if ($evHtml) { "<div class='pv-evs'><span class='pv-lbl'>Evidence from this assessment</span>$evHtml</div>" })
  $(if ($it.OffTenantEvidence) { "<div class='pv-off'><span class='pv-lbl'>&#128203; Evidence the assessor must collect</span>$(hx $it.OffTenantEvidence)</div>" })
  $(if ($optHtml) { "<div class='pv-opt'><span class='pv-lbl'>&#9654; Implementation options</span><ul>$optHtml</ul></div>" })
</div>
"@
            }
            $physGroups += @"
<div class='pv-grp'>
  <div class='pv-gh'>$(hx $grp.Title)</div>
  $(if ($grp.Description) { "<div class='pv-gd'>$(hx $grp.Description)</div>" })
  $itemHtml
</div>
"@
        }
        $physHtml = @"
<div class="card mt" id="nist-physical">
  <div class="card-hd">
    <div><div class="card-label">NIST SP 800-53 &mdash; Physical, Media and Device Controls</div><div class="card-sub">$($physCov.TenantItems) evidenced from the tenant &middot; $($physCov.HybridItems) partly evidenced &middot; $($physCov.AttestedItems) not visible from Microsoft 365</div></div>
    <div class="pv-badge">$($physCov.AttestationCount) need off-tenant evidence</div>
  </div>
  <div class="pv-intro">A Microsoft 365 assessment can evidence endpoint posture &mdash; encryption, patch level, screen lock, endpoint protection, device identity &mdash; and it cannot see a locked server room, a certificate of destruction, or a returned badge. Those are still 800-53 controls, so they are listed here with the implementation options for each and the evidence an assessor has to collect directly. <strong>Nothing in this section is scored</strong>: rows marked <em>Attestation required</em> were never assessed by this tool and are not claimed as compliant.</div>
  $physGroups
</div>
"@
    }

    # ── Assessment scope and limitations ─────────────────────────────────────
    # Sits immediately under the score, because the score is meaningless
    # without it: a control that silently stopped producing a verdict is
    # excluded from the denominator, so the number goes UP when the tool goes
    # blind. This section is the only place that says so.
    $scopeHtml = ''
    if (Get-Command Get-NRGAssessmentScope -ErrorAction SilentlyContinue) {
        try {
            $scope = Get-NRGAssessmentScope -Findings $Findings -LicenseProfile $licProfile
        } catch {
            Write-Verbose "Assessment scope section skipped: $($_.Exception.Message)"
            $scope = $null
        }
        if ($scope -and $scope.Available) {
            $blindCount = $scope.CollectionIncomplete.Count + $scope.NoResult.Count
            $tiles = @(
                "<div class='scope-tile'><div class='scope-n'>$($scope.ScoredControls)</div><div class='scope-l'>Controls scored</div></div>"
                "<div class='scope-tile$(if($blindCount -gt 0){' warn'})'><div class='scope-n$(if($blindCount -gt 0){' warn'})'>$blindCount</div><div class='scope-l'>Could not be assessed</div></div>"
                "<div class='scope-tile'><div class='scope-n'>$($scope.NoProgrammaticCheck.Count)</div><div class='scope-l'>Manual review required</div></div>"
                "<div class='scope-tile'><div class='scope-n'>$($scope.LicenceBlocked.Count)</div><div class='scope-l'>Licence gated</div></div>"
            ) -join ''

            $limRows = ($scope.Limitations | ForEach-Object { "<li>$(hx $_)</li>" }) -join ''

            # The itemised lists are collapsed: the counts and the plain-language
            # limitations are what a client reads; the control ids are what the
            # engineer re-running the assessment needs.
            $detBlocks = ''
            foreach ($grp in @(
                @{ Label = 'Controls that could not be assessed — data did not collect'; Items = $scope.CollectionIncomplete }
                @{ Label = 'Controls that produced no result at all'; Items = $scope.NoResult }
                @{ Label = 'Controls with no automated test — manual review'; Items = $scope.NoProgrammaticCheck }
            )) {
                $items = @($grp.Items)
                if ($items.Count -eq 0) { continue }
                $ids = ($items | ForEach-Object { hx $_.ControlId }) -join ', '
                $detBlocks += "<details class='scope-det'><summary>$(hx $grp.Label) ($($items.Count))</summary><div class='scope-ids'>$ids</div></details>"
            }
            if (@($scope.CoverageIssues).Count -gt 0) {
                $covRows = ($scope.CoverageIssues | ForEach-Object { "$(hx $_.Family) — $(hx $_.Status): $(hx $_.Note)" }) -join '<br>'
                $detBlocks += "<details class='scope-det'><summary>Collectors that did not complete ($(@($scope.CoverageIssues).Count))</summary><div class='scope-ids'>$covRows</div></details>"
            }

            $scopeHtml = @"
<div class='card mt' id='scope'>
  <div class='card-hd'>
    <div><div class='card-label'>Assessment Scope and Limitations</div><div class='card-sub'>What this assessment covered, and what it did not</div></div>
    <div class='lic-badge'>$($scope.ScoredControls) of $($scope.TotalControls) scored</div>
  </div>
  <div class='scope-body'>
    <div class='scope-grid'>$tiles</div>
    <ul class='scope-lim'>$limRows</ul>
    $detBlocks
  </div>
</div>
"@
        }
    }

    # ── License card HTML ────────────────────────────────────────────────────
    $licCard = ''
    if ($licGroups.Count -gt 0) {
        $licRows = ($licGroups.GetEnumerator() | Sort-Object Name | ForEach-Object {
            "<div class='lic-row'><div class='lic-tier'>$(hx $_.Key)</div><div class='lic-cnt'>$($_.Value) control$(if($_.Value -ne 1){'s'}) blocked</div></div>"
        }) -join ''
        $licCard = @"
<div class='card mt' id='licensing'>
  <div class='card-hd'>
    <div><div class='card-label'>License Gap Analysis</div><div class='card-sub'>Gaps that require a license upgrade to remediate</div></div>
    <div class='lic-badge'>$totalBlocked blocked</div>
  </div>
  <div class='lic-body'>
    $(if (-not $hasBusinessPremium) { "<div class='lic-alert'><span class='lic-ico'>&#9888;</span><div>Upgrading to <strong>Microsoft 365 Business Premium</strong> resolves the majority of these gaps — including Safe Attachments, Safe Links, Conditional Access with device compliance, and Intune endpoint management. These are the controls most directly blocking ransomware and BEC attacks. Contact NRG for a licensing proposal.</div></div>" } elseif (-not $hasEntraP2) { "<div class='lic-alert'><span class='lic-ico'>&#9432;</span><div>The remaining license-gated controls require <strong>Microsoft Entra ID P2</strong> or <strong>Entra Suite</strong> — including Identity Protection risk-based CA policies and PIM governance features. Contact NRG for a licensing proposal.</div></div>" } else { "<div class='lic-alert'><span class='lic-ico'>&#9432;</span><div>The following controls require additional licensing beyond your current subscriptions. Contact NRG for a licensing assessment.</div></div>" })
    <div class='lic-rows'>$licRows</div>
  </div>
</div>
"@
    }

    # ── Priority actions HTML ────────────────────────────────────────────────
    $topGaps = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -in @('Critical','High') } |
        Sort-Object @{Expression={ if($_.Severity -eq 'Critical'){0}else{1} }},ControlId | Select-Object -First 8)
    $actsHtml = ''
    $n = 1
    foreach ($g in $topGaps) {
        $ctrl  = $cdefs[$g.ControlId]
        $bRisk = if ($ctrl -and $ctrl.BusinessRisk) { hx $ctrl.BusinessRisk } else { hx $g.Detail }
        $rem   = if ($ctrl -and $ctrl.Remediation)  { hx $ctrl.Remediation  } else { hx $g.Remediation }
        # Suppress the "Requires:" badge when the tenant already holds the
        # license. v4.6.1 always emitted this badge — see comment by
        # $licProfile above.
        $lic = if ($ctrl -and $ctrl.LicenseRequirement -and
                   $ctrl.LicenseRequirement -notmatch '^Included' -and
                   -not $suppressedLicReqs.Contains($ctrl.LicenseRequirement)) {
            "<div class='act-lic'>&#128273; Requires: $(hx $ctrl.LicenseRequirement)</div>"
        } else { '' }
        $cls   = if ($g.Severity -eq 'Critical') { 'ac' } else { 'ah' }
        $scls  = if ($g.Severity -eq 'Critical') { 'svc' } else { 'svh' }
        $actsHtml += @"
<div class='act $cls'>
  <div class='act-num'><div class='act-n'>$n</div><div class='act-cid'>$(hx $g.ControlId)</div><span class='sv $scls'>$(hx $g.Severity)</span></div>
  <div class='act-body'>
    <div class='act-t'>$(hx $g.Title)</div>
    $(if ($bRisk) { "<div class='act-risk'><span class='act-lbl rl'>&#9888; Why it matters</span>$bRisk</div>" })
    $(if ($rem)   { "<div class='act-rem'><span class='act-lbl bl'>&#9654; How to fix it</span>$rem</div>" })
    $lic
  </div>
</div>
"@
        $n++
    }

    # ── Findings by workload HTML ─────────────────────────────────────────────
    $findHtml = ''
    $Findings | Group-Object { ($_.ControlId -replace '-.*$','') } | Sort-Object {
        $idx = [array]::IndexOf($wlOrder, $_.Name); if ($idx -lt 0) { 99 } else { $idx }
    } | ForEach-Object {
        $wl  = $_.Name; $grp = $_.Group
        $wlL = hx $(if ($wlFull[$wl]) { $wlFull[$wl] } else { $wl })
        $wsc = if ($wlScores[$wl]) { $wlScores[$wl].Score } else { 0 }
        $wgp = if ($wlScores[$wl]) { $wlScores[$wl].Gaps  } else { 0 }
        $wc  = scoreColor $wsc
        $gBadge = if ($wgp -gt 0) { "<span class='wl-gbadge'>$wgp gap$(if($wgp -ne 1){'s'})</span>" } else { '' }

        $rows = ''
        foreach ($f in ($grp | Sort-Object @{Expression={
            switch ($_.State) {'Gap'{0};'Partial'{1};'Satisfied'{2};'NotApplicable'{3}}
        }}, ControlId)) {
            $rc    = switch ($f.State) {'Gap'{'rg'};'Partial'{'rw'};'Satisfied'{'rp'};'NotApplicable'{'rn'}}
            $t     = hx $f.Title
            $d     = hx $f.Detail
            $ctrl2 = $cdefs[$f.ControlId]
            $rem2  = if ($ctrl2 -and $ctrl2.Remediation) { hx $ctrl2.Remediation } else { hx $f.Remediation }
            $bRisk2= if ($ctrl2 -and $ctrl2.BusinessRisk) { hx $ctrl2.BusinessRisk } else { '' }
            $cv2   = hx $f.CurrentValue
            $rv2   = hx $f.RequiredValue
            # Suppress per-finding "Requires:" tag when license already held.
            $lic2 = if ($ctrl2 -and $ctrl2.LicenseRequirement -and
                        $ctrl2.LicenseRequirement -notmatch '^Included' -and
                        -not $suppressedLicReqs.Contains($ctrl2.LicenseRequirement)) {
                "<div class='ex-lic'>&#128273; $(hx $ctrl2.LicenseRequirement)</div>"
            } else { '' }
            $fwTags2 = ''
            if ($f.FrameworkIds -and @($f.FrameworkIds).Count -gt 0) {
                $fwTags2 = "<div class='ex-fw'>" + (($f.FrameworkIds | ForEach-Object { "<span class='fw-tag'>$(hx $_)</span>" }) -join '') + "</div>"
            }

            $exHtml = ''
            if ($f.State -in @('Gap','Partial') -and ($d -or $bRisk2 -or $rem2)) {
                $cvLine2 = if ($cv2 -and $rv2) { "<div class='ex-cv'><span class='ex-cvl'>Current:</span> $cv2 &rarr; <span class='ex-cvl'>Required:</span> $rv2</div>" } elseif ($cv2) { "<div class='ex-cv'><span class='ex-cvl'>Current:</span> $cv2</div>" } else { '' }
                $wb = if ($d)     { "<div class='ex-block'><div class='ex-lbl wlbl'>What the issue is</div><div class='ex-bd'>$d$cvLine2</div></div>" } else { '' }
                $yb = if ($bRisk2){ "<div class='ex-block'><div class='ex-lbl ylbl'>Why it matters</div><div class='ex-bd'>$bRisk2</div></div>" }   else { '' }
                $hb = if ($rem2)  { "<div class='ex-block'><div class='ex-lbl hlbl'>How to fix it</div><div class='ex-bd'>$rem2$lic2$fwTags2</div></div>" } else { '' }
                $exHtml = "<tr class='extr'><td colspan='3'><div class='exbody'>$wb$yb$hb</div></td></tr>"
            }

            $hasEx = $exHtml -ne ''
            $mico  = if ($hasEx) { '<span class="mico">&#9654;</span>' } else { '' }
            $ca    = if ($hasEx) { "class='fr $rc exp'" } else { "class='fr $rc'" }
            $prev  = if ($d -and $f.State -in @('Gap','Partial')) {
                $s2 = [string]$f.Detail; if ($s2.Length -gt 110) { hx($s2.Substring(0,107)) + '&hellip;' } else { $d }
            } elseif ($f.State -eq 'Satisfied' -and $f.CurrentValue) { $cv2 } else { '' }

            $rows += "<tr $ca><td class='td1'>$(sBadge $f.State)$(svBadge $f.Severity)</td><td class='td3'><div class='ftitle'>$t $mico</div>$(if($cv2 -and $f.State -in @('Gap','Partial')){"<div class='fcv'>$cv2</div>"})</td><td class='td4'>$prev</td></tr>$exHtml"
        }

        $findHtml += @"
<div class='card mt' id='wl-$wl'>
  <div class='card-hd'>
    <div class='card-hdl'><span class='card-label'>$wlL</span>$gBadge</div>
    <div class='wsc-pill' style='color:$wc;border-color:${wc}40;background:${wc}0e'>$wsc / 100</div>
  </div>
  <table class='ft'><thead><tr class='fth'><th style='width:148px'>Status</th><th>Control</th><th>Summary</th></tr></thead><tbody>$rows</tbody></table>
</div>
"@
    }

    # ── Named inventory findings section ─────────────────────────────────────
    $namedHtml = ''
    if ($invFindings.Count -gt 0) {
        $cards = ''
        foreach ($nf in $invFindings) {
            $ctrl3 = $cdefs[$nf.ControlId]
            $aoItems = @($nf.AffectedObjects)
            $aoRows  = ($aoItems | Select-Object -First 15 | ForEach-Object {
                # AffectedObjects can be a flat string (UPN, AppId) or an
                # [ordered] hashtable when evaluators surface multiple
                # fields per row (e.g. EXO-7.1 mailbox + forwarding target,
                # EXO-7.2 mailbox + rule name + recipients). hx => ConvertTo-
                # NRGHtmlSafe stringifies a hashtable to its type name and
                # loses the data, so render the dictionary case explicitly
                # as a key=value list joined with '; '.
                $obj = $_
                $rendered = if ($obj -is [System.Collections.IDictionary]) {
                    $kvs = @()
                    foreach ($entry in $obj.GetEnumerator()) {
                        $kvs += "$(hx $entry.Key)=$(hx ([string]$entry.Value))"
                    }
                    $kvs -join '; '
                } else {
                    hx ([string]$obj)
                }
                "<tr><td>$rendered</td></tr>"
            }) -join ''
            $moreNote = if ($aoItems.Count -gt 15) { "<tr><td style='color:var(--mut);font-style:italic;padding:6px 10px'>...and $($aoItems.Count - 15) more. Full list in remediation script.</td></tr>" } else { '' }
            $bRisk3 = if ($ctrl3 -and $ctrl3.BusinessRisk) { hx $ctrl3.BusinessRisk } else { hx $nf.Detail }
            $svcls3 = switch ($nf.Severity) { 'Critical' {'svc'} 'High' {'svh'} 'Medium' {'svm'} default {'svl'} }
            $cards += @"
<div class='named-card'>
  <div class='named-hd'>
    <div>
      <div class='named-t'>$(hx $nf.Title) <span class='sv $svcls3'>$(hx $nf.Severity)</span> <span class='ao-count'>$($aoItems.Count) affected</span></div>
      <div class='named-sub'>$bRisk3</div>
    </div>
    <div style='font-size:.7rem;color:var(--mut);text-align:right'>$(hx $nf.ControlId)</div>
  </div>
  <div class='named-body'>
    <table class='ao-table'><thead><tr><th>Name / Identifier</th></tr></thead>
    <tbody>$aoRows$moreNote</tbody></table>
  </div>
</div>
"@
        }
        $namedHtml = "<div class='card mt named-section' id='named'><div class='card-hd'><div><div class='card-label'>Named Findings</div><div class='card-sub'>Specific users, mailboxes, and applications requiring action</div></div><div style='font-size:.73rem;font-weight:700;color:var(--gap)'>$($invFindings.Count) items with named objects</div></div><div style='padding:14px 20px;display:flex;flex-direction:column;gap:0'>$cards</div></div>"
    }

    # ── Best practices & roadmap ──────────────────────────────────────────────
    $phase1Items = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -in @('Critical','High') } |
        Sort-Object @{Expression={ if($_.Severity -eq 'Critical'){0}else{1} }},ControlId | Select-Object -First 6)
    $phase2Items = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -eq 'Medium' } |
        Select-Object -First 5)
    $phase3Items = @($Findings | Where-Object { $_.State -in @('Gap','Partial') -and $_.Severity -eq 'Low' } |
        Select-Object -First 5)

    function rmItem { param($f,$cls)
        $t4    = hx $f.Title
        $cid4  = hx $f.ControlId
        "<div class='rm-item'><div class='rm-bullet $cls'>!</div><div><strong>$t4</strong> <span style='font-size:.7rem;color:var(--mut)'>($cid4)</span></div></div>"
    }

    $p1Html = ($phase1Items | ForEach-Object { rmItem $_ 'p1-bullet' }) -join ''
    $p2Html = ($phase2Items | ForEach-Object { rmItem $_ 'p2-bullet' }) -join ''
    $p3Html = ($phase3Items | ForEach-Object { rmItem $_ 'p3-bullet' }) -join ''

    $bpItems = @(
        @{ Title='Enable Multi-Factor Authentication for all users'; Detail='MFA is the single most impactful control — blocks 99.9% of automated attacks. Start with Authenticator app, enforce via CA policy.'; Effort='quick' },
        @{ Title='Block legacy authentication protocols'; Detail='Legacy auth cannot be protected by MFA. A single legacy auth login from any user bypasses all CA policies. Block via CA or disable org-wide.'; Effort='quick' },
        @{ Title='Configure Conditional Access baseline policies'; Detail='CA is the policy engine for Zero Trust. Minimum: require MFA for all users, block legacy auth, require compliant device for sensitive data.'; Effort='medium' },
        @{ Title='Review and offboard stale accounts'; Detail='Implement an offboarding checklist: disable account, revoke sessions, remove licenses, review forwarding rules, archive mailbox. Run quarterly audits.'; Effort='quick' },
        @{ Title='Deploy Microsoft Defender for Endpoint'; Detail='Endpoint visibility is the foundation of incident response. Without EDR, endpoint threats are invisible until data is gone.'; Effort='medium' },
        @{ Title='Implement DMARC at enforcement (p=reject)'; Detail='SPF and DKIM alone do not prevent spoofing. Only p=reject tells receiving servers to block messages that fail authentication. Non-trivial but critical for any client-facing domain.'; Effort='medium' },
        @{ Title='Establish PAM with PIM for privileged access'; Detail='Permanent admin accounts are always-on targets. PIM elevates admins on demand with MFA, justification, and time limits — significantly reducing the blast radius of a compromise.'; Effort='strategic' },
        @{ Title='Deploy sensitivity labels and DLP policies'; Detail='Data protection requires knowing what data you have. Labels + DLP provides classification, protection, and enforcement across email, SharePoint, Teams, and endpoints.'; Effort='strategic' },
        @{ Title='Create and test an incident response plan'; Detail='When a BEC or ransomware incident occurs, decisions made in the first 30 minutes determine the outcome. Having a playbook, a contact list, and a tested process cuts response time dramatically.'; Effort='strategic' }
    )

    $bpHtml = ($bpItems | ForEach-Object {
        $effortLabel = switch ($_.Effort) { 'quick' {'Quick Win (days)'} 'medium' {'Medium (weeks)'} 'strategic' {'Strategic (months)'} default {''} }
        $effortCls   = switch ($_.Effort) { 'quick' {'bp-quick'} 'medium' {'bp-medium'} 'strategic' {'bp-strategic'} default {''} }
        "<div class='bp-card'><div class='bp-t'>$(hx $_.Title)</div><div class='bp-d'>$(hx $_.Detail)</div><span class='bp-tag $effortCls'>$effortLabel</span></div>"
    }) -join ''

    $roadmapHtml = @"
<div class='card mt' id='roadmap'>
  <div class='card-hd'>
    <div class='card-label'>90-Day Security Roadmap</div>
    <div class='card-sub'>Prioritized remediation path based on this assessment's findings</div>
  </div>
  <div class='rm-phases'>
    <div class='rm-phase'>
      <div class='rm-ph-hd' style='color:#dc2626'>Phase 1 — Week 1-2</div>
      <div class='rm-ph-t'>Stop the Bleeding</div>
      $(if ($phase1Items.Count -gt 0) { $p1Html } else { "<div class='rm-item'><div class='rm-bullet p1-bullet'>&#10003;</div><div>No critical gaps found</div></div>" })
    </div>
    <div class='rm-phase' style='border-left:1px solid var(--bdr)'>
      <div class='rm-ph-hd' style='color:#ea580c'>Phase 2 — Week 2-4</div>
      <div class='rm-ph-t'>Close the Gaps</div>
      $(if ($phase2Items.Count -gt 0) { $p2Html } else { "<div class='rm-item'><div class='rm-bullet p2-bullet'>&#10003;</div><div>No medium gaps found</div></div>" })
    </div>
    <div class='rm-phase' style='border-left:1px solid var(--bdr)'>
      <div class='rm-ph-hd' style='color:#3b7dd8'>Phase 3 — Month 2-3</div>
      <div class='rm-ph-t'>Harden & Monitor</div>
      $(if ($phase3Items.Count -gt 0) { $p3Html } else { "<div class='rm-item'><div class='rm-bullet p3-bullet'>&#10003;</div><div>No low gaps remaining</div></div>" })
    </div>
  </div>
</div>

<div class='card mt' id='bestpractices'>
  <div class='card-hd'>
    <div class='card-label'>Security Best Practices</div>
    <div class='card-sub'>Recommendations beyond this assessment — the security journey for any M365 tenant</div>
  </div>
  <div class='bp-grid'>$bpHtml</div>
</div>
"@

    # ── Escaped strings ───────────────────────────────────────────────────────
    $cD = hx $clientDisplay; $tD = hx $Metadata.TenantDomain
    $dS = hx $Metadata.AssessmentDate; $op = hx $Metadata.Operator
    $co2 = hx $co; $ph2 = hx $ph; $ws2b = hx $ws; $vr = hx $Metadata.ToolVersion

    # ── Inline script content (v4.6.3 P2: hashed for CSP) ────────────────────
    # The inline <script> block is static — no operator/tenant data interpolation
    # — so its CSP hash is stable across runs. We compute it from the EXACT body
    # bytes (between <script> and </script>), then emit script-src 'sha256-...'
    # in the CSP and drop 'unsafe-inline'. Defense-in-depth against future
    # accidental injection via report variable interpolation.
    #
    # Handlers are wired here via addEventListener instead of inline onclick=
    # attributes. With strict CSP ('sha256-...' only) those inline handlers
    # would require 'unsafe-hashes' — which we deliberately do not allow.
    # Elements opt in via class='exp' (collapsible rows) or data-goto="<id>"
    # (nav links).
    $inlineScript = @"

document.querySelectorAll('.extr').forEach(function(r){r.style.display='none'});
document.querySelectorAll('[data-goto]').forEach(function(el){
  el.addEventListener('click',function(){
    var t=document.getElementById(el.getAttribute('data-goto'));
    if(t)t.scrollIntoView({behavior:'smooth',block:'start'});
  });
});
document.querySelectorAll('tr.exp').forEach(function(tr){
  tr.addEventListener('click',function(e){
    if(e.target&&e.target.closest&&e.target.closest('a,button,input,select,textarea'))return;
    var n=tr.nextElementSibling;
    if(n&&n.classList.contains('extr')){
      var s=n.style.display===''||n.style.display==='none';
      n.style.display=s?'table-row':'none';
      tr.classList.toggle('open',s);
    }
  });
});

"@
    $scriptHashBytes = [System.Text.Encoding]::UTF8.GetBytes($inlineScript)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $scriptHashB64 = [System.Convert]::ToBase64String($sha256.ComputeHash($scriptHashBytes))
    } finally {
        $sha256.Dispose()
    }
    $scriptCsp = "'sha256-$scriptHashB64'"

    # ── Assemble HTML ─────────────────────────────────────────────────────────
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';img-src https: data:;script-src $scriptCsp;connect-src 'none';base-uri 'none';form-action 'none';frame-ancestors 'none';object-src 'none'">
<meta name="referrer" content="no-referrer">
<title>M365 Security Assessment &mdash; $cD</title>
<style>
:root{--P:$P;--S:$S;--A:$A;--bg:#eef2f8;--card:#fff;--txt:#111827;--mut:#6b7280;--bdr:#e2e8f0;--pass:#059669;--warn:#ca8a04;--gap:#dc2626;--na:#9ca3af;--r:12px;--sh:0 1px 3px rgba(0,0,0,.05),0 4px 18px rgba(15,37,68,.08)}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:15px;scroll-behavior:smooth}
body{font-family:'Segoe UI Variable Display','Segoe UI','Helvetica Neue',system-ui,sans-serif;background:var(--bg);color:var(--txt);line-height:1.6;-webkit-font-smoothing:antialiased}
a{color:var(--A);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1180px;margin:0 auto}

.hdr{background:linear-gradient(138deg,$P 0%,#061325 100%);position:relative;overflow:hidden}
.hdr::before{content:'';position:absolute;inset:0;background-image:radial-gradient(circle at 80% 50%,rgba(232,98,26,.12) 0%,transparent 60%),radial-gradient(circle at 20% 80%,rgba(59,125,216,.08) 0%,transparent 50%);pointer-events:none}
.hdr-top{display:flex;align-items:flex-start;justify-content:space-between;padding:40px 52px 26px;gap:32px;position:relative}
.eye{font-size:.61rem;font-weight:700;text-transform:uppercase;letter-spacing:.18em;color:$S;margin-bottom:8px}
.hdr-client{font-size:2.2rem;font-weight:900;letter-spacing:-.04em;color:#fff;line-height:1;margin-bottom:10px}
.hdr-meta{display:flex;gap:22px;flex-wrap:wrap;font-size:.77rem;color:rgba(255,255,255,.42)}
.hdr-meta strong{color:rgba(255,255,255,.78);font-weight:600}
.hdr-right{flex-shrink:0;text-align:right;display:flex;flex-direction:column;align-items:flex-end;gap:10px}
.ver-badge{font-size:.61rem;background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.14);padding:3px 10px;border-radius:20px;color:rgba(255,255,255,.5);letter-spacing:.06em}
.logo{height:36px;filter:brightness(0) invert(1);opacity:.88}
.logo-t{font-size:1.05rem;font-weight:900;color:rgba(255,255,255,.88);letter-spacing:-.02em}
.hdr-nav{display:flex;padding:0 52px;border-top:1px solid rgba(255,255,255,.07);position:relative}
.nav-a{padding:11px 16px;font-size:.68rem;font-weight:700;color:rgba(255,255,255,.38);letter-spacing:.06em;cursor:pointer;border-bottom:2px solid transparent;transition:all .15s;text-transform:uppercase;user-select:none}
.nav-a:hover{color:rgba(255,255,255,.75);border-bottom-color:$S}
.abar{height:3px;background:linear-gradient(90deg,$S 0%,$A 55%,transparent 100%)}

.cnt{padding:28px 52px 56px}
.card{background:var(--card);border-radius:var(--r);box-shadow:var(--sh);overflow:hidden;border:1px solid var(--bdr)}
.mt{margin-top:22px}
.card-hd{padding:15px 24px 13px;border-bottom:1px solid var(--bdr);display:flex;align-items:center;justify-content:space-between;background:linear-gradient(to bottom,#fafbfd,#f4f7fb)}
.card-hdl{display:flex;align-items:center;gap:10px}
.card-label{font-size:.67rem;font-weight:800;text-transform:uppercase;letter-spacing:.12em;color:var(--P)}
.card-sub{font-size:.72rem;color:var(--mut)}

/* Exec dashboard */
.ex-dash{display:grid;grid-template-columns:192px 1fr 224px;min-height:196px}
.ex-dash>*{padding:24px 22px}
.br{border-right:1px solid var(--bdr)}
.score-wrap{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:10px}
.score-c{text-align:center}
.score-n{font-size:2.9rem;font-weight:900;color:var(--P);letter-spacing:-.05em;line-height:1}
.score-s{font-size:.58rem;color:var(--mut);text-transform:uppercase;letter-spacing:.07em;margin-top:2px}
.posture-pill{display:inline-block;margin-top:8px;padding:4px 14px;border-radius:20px;font-size:.67rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em;background:${pCol}18;color:$pCol;border:1.5px solid ${pCol}40}
.stat-col{display:flex;flex-direction:column;gap:10px;justify-content:center}
.sr{display:flex;align-items:center;gap:10px}
.sr-l{font-size:.63rem;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);min-width:58px;font-weight:700}
.sr-t{flex:1;height:5px;background:#e5eaf4;border-radius:3px;overflow:hidden}
.sr-f{height:100%;border-radius:3px}
.sr-n{font-size:.9rem;font-weight:800;min-width:24px;text-align:right}
.sg .sr-n,.sg .sr-f{color:var(--gap);background:var(--gap)}
.sw .sr-n,.sw .sr-f{color:var(--warn);background:var(--warn)}
.sp .sr-n,.sp .sr-f{color:var(--pass);background:var(--pass)}
.sna .sr-n,.sna .sr-f{color:var(--na);background:var(--na)}
.narr{font-size:.83rem;color:var(--txt);line-height:1.6;padding:11px 0 0;border-top:1px solid var(--bdr);margin-top:10px}
.sev-pills{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}
.sp2{display:flex;align-items:center;gap:5px;font-size:.7rem;font-weight:700;padding:4px 10px;border-radius:20px}
.spc{background:#fef2f2;color:#991b1b;border:1px solid #fecaca}
.sph{background:#fff7ed;color:#c2410c;border:1px solid #fed7aa}
.spm{background:#fefce8;color:#854d0e;border:1px solid #fde68a}
.spl{background:#f0fdf4;color:#166534;border:1px solid #bbf7d0}
.conn-col{display:flex;flex-direction:column;justify-content:center;gap:6px}
.conn-t{font-size:.61rem;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);font-weight:700;margin-bottom:4px}
.conn{display:flex;align-items:center;gap:7px;padding:5px 10px;border-radius:6px;font-size:.72rem;font-weight:600}
.cok{background:#f0fdf4;color:#166534;border:1px solid #bbf7d0}
.coff{background:#fef2f2;color:#991b1b;border:1px solid #fecaca}

/* Workload grid */
.wl-section{border-top:1px solid var(--bdr);padding:16px 24px 20px}
.wl-sec-t{font-size:.6rem;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);font-weight:700;margin-bottom:12px}
.wl-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px}
.wl-card{display:flex;align-items:center;gap:11px;padding:13px 14px;background:#f7f9fd;border-radius:9px;border:1px solid var(--bdr)}
.wl-info{flex:1;min-width:0}
.wl-name{font-size:.68rem;font-weight:700;color:var(--mut);text-transform:uppercase;letter-spacing:.05em;margin-bottom:2px}
.wl-score{font-size:1.4rem;font-weight:900;line-height:1}
.wl-den{font-size:.62rem;font-weight:600;color:var(--mut);margin-left:1px}
.wl-gap{font-size:.66rem;font-weight:700;color:var(--gap);margin-top:2px}
.wl-ok{font-size:.66rem;font-weight:700;color:var(--pass);margin-top:2px}.wl-na{color:#94a3b8;font-size:.65rem;font-weight:500;margin-top:2px}

/* Framework matrix */
.fw-grid{display:grid;grid-template-columns:repeat($($fwShow.Count),1fr);gap:0;background:var(--bdr)}
.fw-card{background:var(--card)}
.fw-hd{padding:9px 18px;font-size:.78rem;font-weight:900;color:#fff;letter-spacing:.05em}
.fw-body{padding:16px 18px;display:flex;flex-direction:column;gap:4px}
.fw-sc{font-size:2rem;font-weight:900;line-height:1}
.fw-den{font-size:.62rem;font-weight:600;color:var(--mut)}
.fw-name{font-size:.7rem;color:var(--mut);font-weight:600;line-height:1.4;margin-top:4px}
.nf-badge{font-size:.72rem;font-weight:800;background:#4c1d95;color:#fff;padding:4px 12px;border-radius:20px;letter-spacing:.02em}
.nf-wrap{overflow-x:auto}
.nf-tbl{width:100%;border-collapse:collapse;font-size:.78rem}
.nf-tbl th{text-align:left;padding:9px 14px;font-size:.63rem;font-weight:800;text-transform:uppercase;letter-spacing:.07em;color:var(--mut);background:var(--bg);border-bottom:1px solid var(--bdr);white-space:nowrap}
.nf-tbl td{padding:10px 14px;border-bottom:1px solid var(--bdr);vertical-align:top}
.nf-tbl tr:last-child td{border-bottom:none}
.nf-id{font-weight:900;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#4c1d95;white-space:nowrap}
.nf-nm{font-weight:600;min-width:220px}
.nf-ctl{font-size:.66rem;color:var(--mut);font-weight:500;margin-top:3px;line-height:1.6}
.nf-cid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;color:var(--ink)}
.nf-n{text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums;font-weight:700}
th.nf-n{text-align:right}
.nf-ok{color:#059669}
.nf-pt{color:#ca8a04}
.nf-gp{color:#dc2626}
.nf-er{color:#b91c1c}
.nf-na{color:#94a3b8}
.nf-sc{white-space:nowrap;font-weight:800;min-width:130px}
.nf-bar{display:inline-block;width:74px;height:7px;border-radius:4px;background:var(--bdr);overflow:hidden;vertical-align:middle;margin-right:8px}
.nf-fill{height:100%;border-radius:4px;transition:width 1s ease .3s}
.nf-note{padding:12px 18px;font-size:.7rem;color:var(--mut);line-height:1.6;border-top:1px solid var(--bdr);background:var(--bg)}
.pv-badge{font-size:.72rem;font-weight:800;background:#7c2d12;color:#fff;padding:4px 12px;border-radius:20px;white-space:nowrap}
.pv-intro{padding:14px 18px;font-size:.76rem;color:var(--txt);line-height:1.65;border-bottom:1px solid var(--bdr);background:var(--bg)}
.pv-grp{border-bottom:1px solid var(--bdr)}
.pv-grp:last-child{border-bottom:none}
.pv-gh{padding:11px 18px 3px;font-size:.8rem;font-weight:900;letter-spacing:-.01em}
.pv-gd{padding:0 18px 10px;font-size:.71rem;color:var(--mut);line-height:1.55}
.pv-item{padding:12px 18px;border-top:1px solid var(--bdr)}
.pv-hd{display:flex;align-items:flex-start;gap:12px}
.pv-cid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:900;font-size:.78rem;color:#4c1d95;min-width:62px;white-space:nowrap;padding-top:1px}
.pv-ttl{flex:1;font-size:.82rem;font-weight:700;line-height:1.35}
.pv-scope{font-size:.66rem;font-weight:600;color:var(--mut);margin-top:2px}
.pv-st{font-size:.63rem;font-weight:800;padding:3px 9px;border-radius:20px;white-space:nowrap;letter-spacing:.03em}
.pv-met{background:#d1fae5;color:#065f46}
.pv-part{background:#fef3c7;color:#92400e}
.pv-gap{background:#fee2e2;color:#991b1b}
.pv-na{background:#e5e7eb;color:#4b5563}
.pv-att{background:#ede9fe;color:#5b21b6}
.pv-asp{font-size:.75rem;color:var(--txt);line-height:1.6;margin:7px 0 0 74px}
.pv-evs,.pv-off,.pv-opt{margin:8px 0 0 74px;font-size:.73rem;line-height:1.6;color:var(--mut)}
.pv-lbl{display:block;font-size:.6rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);margin-bottom:3px}
.pv-ev{display:inline-block;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.66rem;font-weight:700;padding:2px 7px;border-radius:4px;margin:0 4px 4px 0}
.ev-ok{background:#d1fae5;color:#065f46}
.ev-pt{background:#fef3c7;color:#92400e}
.ev-gp{background:#fee2e2;color:#991b1b}
.ev-na{background:#e5e7eb;color:#4b5563}
.pv-opt ul{margin:0;padding-left:17px}
.pv-opt li{margin-bottom:3px}
@media(max-width:720px){.pv-asp,.pv-evs,.pv-off,.pv-opt{margin-left:0}}

/* License card */
.lic-body{padding:18px 24px;display:flex;flex-direction:column;gap:14px}
.lic-alert{display:flex;align-items:flex-start;gap:14px;padding:14px 18px;background:#fffbeb;border:1px solid #fde68a;border-radius:9px;font-size:.82rem;line-height:1.65;color:#374151}
.lic-ico{font-size:1.3rem;margin-top:1px;flex-shrink:0}
.scope-body{padding:18px 24px;display:flex;flex-direction:column;gap:16px}
.scope-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.scope-tile{padding:12px 14px;border:1px solid var(--bdr);border-radius:8px;background:#f8fafd}
.scope-tile.warn{background:#fffbeb;border-color:#fde68a}
.scope-n{font-size:1.35rem;font-weight:700;color:var(--txt);line-height:1.2}
.scope-n.warn{color:var(--warn)}
.scope-l{font-size:.7rem;font-weight:600;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin-top:3px}
.scope-lim{margin:0;padding-left:18px;font-size:.82rem;line-height:1.7;color:#374151}
.scope-lim li{margin-bottom:5px}
.scope-det{font-size:.78rem;line-height:1.6;color:#374151}
.scope-det summary{cursor:pointer;font-weight:600;color:var(--txt);font-size:.8rem;padding:6px 0}
.scope-ids{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.72rem;color:var(--mut);word-break:break-word;padding:4px 0 8px}
.lic-rows{display:flex;flex-direction:column;gap:7px}
.lic-row{display:flex;align-items:center;justify-content:space-between;padding:9px 16px;background:#f8fafd;border-radius:7px;border:1px solid var(--bdr)}
.lic-tier{font-size:.8rem;font-weight:600;color:var(--txt)}
.lic-cnt{font-size:.72rem;font-weight:700;color:var(--warn)}
.lic-badge{font-size:.77rem;font-weight:800;padding:4px 13px;background:#fff7ed;color:#c2410c;border:1px solid #fed7aa;border-radius:20px}

/* Priority actions */
.acts{padding:16px 20px;display:flex;flex-direction:column;gap:12px}
.act{display:flex;align-items:flex-start;gap:16px;padding:16px 18px;border-radius:10px;border-left:4px solid}
.ac{background:#fff7f7;border-color:var(--gap)}
.ah{background:#fffcf0;border-color:var(--warn)}
.act-num{display:flex;flex-direction:column;align-items:center;gap:5px;min-width:58px}
.act-n{font-size:1.5rem;font-weight:900;color:var(--mut);line-height:1}
.act-cid{font-size:.57rem;font-weight:700;color:var(--mut);letter-spacing:.04em;text-align:center}
.act-body{flex:1;min-width:0}
.act-t{font-weight:800;font-size:.91rem;color:var(--txt);line-height:1.3;margin-bottom:9px}
.act-lbl{display:block;font-size:.6rem;font-weight:900;text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px}
.rl{color:#b91c1c}.bl{color:#1d4ed8}
.act-risk{font-size:.79rem;color:#374151;line-height:1.55;padding:9px 13px;background:rgba(220,38,38,.04);border-radius:6px;border-left:2px solid #fca5a5;margin-bottom:8px}
.act-rem{font-size:.79rem;color:#1e3a8a;line-height:1.55;padding:9px 13px;background:rgba(29,78,216,.04);border-radius:6px;border-left:2px solid #93c5fd}
.act-lic{font-size:.71rem;font-weight:700;color:#b45309;margin-top:7px;padding:5px 10px;background:#fffbeb;border-radius:5px;border:1px solid #fde68a}

/* Findings */
.ft{width:100%;border-collapse:collapse;font-size:.82rem}
.fth th{padding:9px 14px;background:#f4f7fb;font-size:.6rem;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);font-weight:700;border-bottom:2px solid var(--bdr);text-align:left}
.fr{border-bottom:1px solid #eff2f8}.fr:last-of-type{border-bottom:none}
.fr td{padding:10px 14px;vertical-align:top}
.exp{cursor:pointer;transition:background .1s}.exp:hover{background:#f7f9fc}
.rg{border-left:3px solid var(--gap)}.rw{border-left:3px solid var(--warn)}.rp{border-left:3px solid var(--pass)}.rn{border-left:3px solid #d1d5db}
.td1{width:150px;vertical-align:top}.td1 .b,.td1 .sv{display:block;margin-bottom:4px}
.td3{font-weight:600;color:var(--txt);width:32%}.td4{color:var(--mut);font-size:.77rem}
.ftitle{font-weight:700;color:var(--txt);line-height:1.3;margin-bottom:2px}
.fcv{font-size:.7rem;color:var(--mut);font-style:italic;margin-top:2px}
.mico{font-size:.58rem;color:var(--mut);margin-left:5px;vertical-align:middle;display:inline-block;transition:transform .18s}
.exp.open .mico{transform:rotate(90deg)}
.extr td{background:#f8fafd;padding:0}
.exbody{border-top:1px solid #e6ecf5;display:grid;grid-template-columns:repeat(3,1fr)}
.ex-block{padding:15px 18px;border-right:1px solid #eaecf3}.ex-block:last-child{border-right:none}
.ex-lbl{font-size:.58rem;font-weight:900;text-transform:uppercase;letter-spacing:.1em;margin-bottom:7px;padding-bottom:5px;border-bottom:1px solid;display:block}
.wlbl{color:#374151;border-color:#d1d5db}.ylbl{color:#b91c1c;border-color:#fca5a5}.hlbl{color:#1d4ed8;border-color:#93c5fd}
.ex-bd{font-size:.79rem;color:#374151;line-height:1.6}
.ex-cv{font-size:.71rem;color:var(--mut);margin-top:6px;font-style:italic}.ex-cvl{font-weight:700;color:#374151}
.ex-lic{margin-top:7px;font-size:.7rem;font-weight:700;color:#b45309;padding:4px 9px;background:#fffbeb;border-radius:4px;border:1px solid #fde68a;display:inline-block}
.ex-fw{margin-top:7px;display:flex;flex-wrap:wrap;gap:4px}
.fw-tag{font-size:.61rem;padding:2px 7px;border-radius:4px;background:#eef2ff;color:#3730a3;font-weight:700;display:inline-block}
.ao-table{width:100%;border-collapse:collapse;margin-top:10px}
.ao-table th{font-size:.58rem;text-transform:uppercase;letter-spacing:.09em;color:var(--mut);font-weight:700;padding:5px 10px;background:#f4f7fb;border-bottom:1px solid var(--bdr);text-align:left}
.ao-table td{font-size:.79rem;padding:6px 10px;border-bottom:1px solid #eff2f8;color:#374151;font-family:'Segoe UI Mono','Consolas',monospace}
.ao-table tr:last-child td{border-bottom:none}
.ao-table tr:hover td{background:#f8fafd}
.ao-count{display:inline-block;background:#fef2f2;color:#991b1b;border:1px solid #fecaca;padding:2px 9px;border-radius:12px;font-size:.67rem;font-weight:700;margin-left:8px}
.ss-ring{display:flex;align-items:center;gap:14px;padding:16px 22px;background:#f8fafd;border-top:1px solid var(--bdr)}
.ss-label{font-size:.6rem;text-transform:uppercase;letter-spacing:.09em;color:var(--mut);font-weight:700;margin-bottom:3px}
.ss-val{font-size:1.4rem;font-weight:900;line-height:1}
.ss-sub{font-size:.7rem;color:var(--mut);margin-top:2px}
.named-section{margin-top:22px}
.named-card{background:var(--card);border-radius:var(--r);box-shadow:var(--sh);border:1px solid var(--bdr);overflow:hidden;margin-top:14px}
.named-hd{padding:12px 20px;background:linear-gradient(to right,#fff7f7,#fff);border-bottom:1px solid var(--bdr);display:flex;align-items:center;justify-content:space-between}
.named-t{font-size:.82rem;font-weight:800;color:#991b1b}
.named-sub{font-size:.73rem;color:var(--mut);margin-top:2px}
.named-body{padding:0}
.bp-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:14px;padding:20px 24px}
.bp-card{padding:16px 18px;background:#f8fafd;border-radius:9px;border:1px solid var(--bdr);border-left:3px solid var(--A)}
.bp-t{font-size:.82rem;font-weight:800;color:var(--txt);margin-bottom:5px}
.bp-d{font-size:.77rem;color:var(--mut);line-height:1.55}
.bp-tag{display:inline-block;margin-top:7px;padding:2px 9px;border-radius:12px;font-size:.64rem;font-weight:700}
.bp-quick{background:#f0fdf4;color:#166534;border:1px solid #bbf7d0}
.bp-medium{background:#fffbeb;color:#92400e;border:1px solid #fde68a}
.bp-strategic{background:#eef2ff;color:#3730a3;border:1px solid #c7d2fe}
.rm-phases{display:grid;grid-template-columns:repeat(3,1fr);gap:0;background:var(--bdr)}
.rm-phase{background:var(--card);padding:22px 20px}
.rm-ph-hd{font-size:.67rem;font-weight:800;text-transform:uppercase;letter-spacing:.1em;margin-bottom:3px}
.rm-ph-t{font-size:1rem;font-weight:900;color:var(--txt);margin-bottom:10px}
.mono{font-family:'Segoe UI Mono','Consolas',monospace;font-weight:700}
.rm-proj{text-align:right;white-space:nowrap}
.rm-proj-n{display:block;font-size:1.15rem;font-weight:900;color:var(--pass)}
.rm-proj-s{display:block;font-size:.63rem;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--mut)}
.rm-headline{font-size:.92rem;color:#374151;margin:4px 0 2px;line-height:1.5}
.rm-lic-note{font-size:.82rem;color:#374151;background:#fff8ec;border:1px solid #f3e2bd;border-radius:8px;padding:8px 12px;margin-top:10px}
.rm-method{font-size:.76rem;color:var(--mut);margin-top:10px;line-height:1.45}
.rm-tbl tbody tr{border-bottom:1px solid #eff2f8}
.dl-row{display:flex;flex-wrap:wrap;gap:10px}
.dl-btn{display:inline-flex;align-items:center;gap:6px;padding:9px 16px;border-radius:8px;background:var(--P);color:#fff;font-weight:700;font-size:.85rem;text-decoration:none;border:1px solid rgba(0,0,0,.08)}
.dl-btn:hover{filter:brightness(1.08)}
.rm-item{display:flex;gap:8px;margin-bottom:7px;font-size:.79rem;color:#374151;align-items:flex-start}
.rm-bullet{flex-shrink:0;width:18px;height:18px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:.62rem;font-weight:900;margin-top:1px}
.p1-bullet{background:#fef2f2;color:#991b1b}
.p2-bullet{background:#fff7ed;color:#c2410c}
.p3-bullet{background:#eef2ff;color:#3730a3}
.wl-gbadge{display:inline-block;padding:2px 9px;background:#fef2f2;color:#991b1b;border:1px solid #fecaca;border-radius:12px;font-size:.66rem;font-weight:700}
.wsc-pill{font-size:.72rem;font-weight:800;padding:3px 11px;border-radius:14px;border:1px solid;flex-shrink:0}

/* Badges */
.b{display:inline-block;padding:3px 10px;border-radius:5px;font-size:.67rem;font-weight:800;white-space:nowrap}
.bp{background:#f0fdf4;color:#166534;border:1px solid #bbf7d0}
.bw{background:#fffbeb;color:#92400e;border:1px solid #fde68a}
.bg{background:#fef2f2;color:#991b1b;border:1px solid #fecaca}
.bn{background:#f9fafb;color:#6b7280;border:1px solid #e5e7eb}
.sv{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.64rem;font-weight:800;white-space:nowrap}
.svc{background:var(--gap);color:#fff}.svh{background:#ea580c;color:#fff}.svm{background:var(--warn);color:#fff}.svl{background:#65a30d;color:#fff}.svi{background:#e5e7eb;color:#374151}

/* Footer */
.ftr{background:$P;color:rgba(255,255,255,.48);padding:24px 52px;display:grid;grid-template-columns:1fr auto;align-items:center;gap:32px;margin-top:36px}
.ftr-l{display:flex;flex-direction:column;gap:4px}
.ftr-co{font-size:.86rem;font-weight:700;color:#fff}
.ftr-contact{font-size:.73rem}
.ftr-contact a{color:rgba(255,255,255,.55);text-decoration:none}
.ftr-r{text-align:right}
.ftr-note{font-size:.7rem;color:rgba(255,255,255,.35);margin-top:4px}
.ftr-cta{display:inline-block;padding:9px 22px;background:$S;color:#fff;border-radius:7px;font-size:.75rem;font-weight:800;letter-spacing:.05em;text-transform:uppercase;text-decoration:none;margin-top:10px}
.ftr-cta:hover{opacity:.9;text-decoration:none}

@keyframes rfill{to{stroke-dashoffset:$off}}

@media print{
  *{-webkit-print-color-adjust:exact!important;print-color-adjust:exact!important}
  body{background:#fff;font-size:12px}.wrap{max-width:none}
  .cnt{padding:12px 28px 24px}.hdr-top{padding:20px 28px 14px}.ftr{padding:14px 28px;margin-top:16px}
  .card{box-shadow:none;break-inside:avoid;border:1px solid #dde3ec}
  .extr{display:table-row!important}.exp{cursor:default}
  .fw-grid{grid-template-columns:repeat($($fwShow.Count),1fr)!important}
  .wl-grid{grid-template-columns:repeat(auto-fill,minmax(130px,1fr))!important}
  .exbody{grid-template-columns:1fr 1fr 1fr!important}
  .hdr-nav{display:none}
}
</style>
</head>
<body>
<div class="wrap">

<div class="hdr">
  <div class="hdr-top">
    <div>
      <div class="eye">Microsoft 365 Security Assessment</div>
      <div class="hdr-client">$cD</div>
      <div class="hdr-meta">
        <span><strong>Date</strong> $dS</span>
        <span><strong>Tenant</strong> $tD</span>
        <span><strong>License Tier</strong> $(hx $tierLabel)</span>
        $(if($op){"<span><strong>Prepared by</strong> $op</span>"})
        <span><strong>Framework$(if ($fwShow.Count -ne 1) { 's' })</strong> $(hx (($fwShow | ForEach-Object { $fwMeta[$_].Full }) -join ' · '))</span>
      </div>
    </div>
    <div class="hdr-right">
      <div class="ver-badge">NRG-Assessment v$vr</div>
      $logoH
    </div>
  </div>
  <div class="hdr-nav">
    <span class="nav-a" data-goto="exec">Overview</span>
    $(if($scopeHtml){'<span class="nav-a" data-goto="scope">Scope &amp; Limits</span>'})
    <span class="nav-a" data-goto="fw-section">Frameworks</span>
    $(if($nistHtml){'<span class="nav-a" data-goto="nist-families">NIST 800-53</span>'})
    $(if($physHtml){'<span class="nav-a" data-goto="nist-physical">Physical &amp; Device</span>'})
    $(if($licGroups.Count -gt 0){'<span class="nav-a" data-goto="licensing">License Gaps</span>'})
    <span class="nav-a" data-goto="named">Named Findings</span>
    <span class="nav-a" data-goto="actions">Priority Actions</span>
    <span class="nav-a" data-goto="roadmap">Roadmap</span>
    <span class="nav-a" data-goto="findings">All Findings</span>
  </div>
</div>
<div class="abar"></div>

<div class="cnt">

<!-- OVERVIEW -->
<div class="card" id="exec">
  <div class="card-hd"><div class="card-label">Executive Overview</div><div class="card-sub">$($Findings.Count) controls assessed &middot; $scrd scored &middot; $na not applicable</div></div>
  <div class="ex-dash">
    <div class="score-wrap br">
      <svg width="136" height="136" viewBox="0 0 160 160">
        <circle fill="none" stroke="#e4e9f2" stroke-width="10" cx="80" cy="80" r="72" transform="rotate(-90 80 80)"/>
        <circle fill="none" stroke="$S" stroke-width="10" cx="80" cy="80" r="72"
          stroke-linecap="round" stroke-dasharray="$circ" stroke-dashoffset="$circ"
          transform="rotate(-90 80 80)" style="animation:rfill 1.4s cubic-bezier(.4,0,.2,1) .25s forwards"/>
      </svg>
      <div class="score-c">
        <div class="score-n">$sc2</div>
        <div class="score-s">Security Score / 100</div>
        <div class="posture-pill">$pLbl</div>
      </div>
    </div>
    <div class="stat-col br">
      <div class="sr sg"><span class="sr-l">Gaps</span><div class="sr-t"><div class="sr-f" style="width:$(pct $gap $scrd)%"></div></div><span class="sr-n">$gap</span></div>
      <div class="sr sw"><span class="sr-l">Partial</span><div class="sr-t"><div class="sr-f" style="width:$(pct $part $scrd)%"></div></div><span class="sr-n">$part</span></div>
      <div class="sr sp"><span class="sr-l">Satisfied</span><div class="sr-t"><div class="sr-f" style="width:$(pct $sat $scrd)%"></div></div><span class="sr-n">$sat</span></div>
      <div class="sr sna"><span class="sr-l">N/A</span><div class="sr-t"><div class="sr-f" style="width:$(pct $na $Findings.Count)%"></div></div><span class="sr-n">$na</span></div>
      <div class="narr">$narr
        <div class="sev-pills">
          $(if($crit -gt 0){"<span class='sp2 spc'>&#9679; $crit Critical</span>"})
          $(if($high -gt 0){"<span class='sp2 sph'>&#9679; $high High</span>"})
          $(if($med  -gt 0){"<span class='sp2 spm'>&#9679; $med Medium</span>"})
          $(if($low  -gt 0){"<span class='sp2 spl'>&#9679; $low Low</span>"})
        </div>
      </div>
    </div>
    <div class="conn-col">
      <div class="conn-t">Service Coverage</div>
      $connHtml
    </div>
  </div>
  <div class="wl-section">
    <div class="wl-sec-t">Score by Workload</div>
    <div class="wl-grid">$wlGrid</div>
  </div>
</div>

$scopeHtml

$riskHtml

<!-- FRAMEWORK COMPLIANCE -->
<div class="card mt" id="fw-section">
  <div class="card-hd"><div class="card-label">$(if ($fwShow.Count -eq 1) { "$(hx $fwMeta[$fwShow[0]].Full) Compliance" } else { 'Framework Compliance Matrix' })</div><div class="card-sub">$(hx ("Controls mapped to " + (($fwShow | ForEach-Object { $fwMeta[$_].Full }) -join ', ')))</div></div>
  <div class="fw-grid">$fwHtml</div>
</div>

<!-- NIST 800-53 CONTROL FAMILY ROLLUP -->
$nistHtml

<!-- NIST PHYSICAL / MEDIA / DEVICE CONTROLS -->
$physHtml

<!-- LICENSE GAPS -->
$licCard

<!-- PRIORITY ACTIONS -->
$(if($actsHtml){
"<div class='card mt' id='actions'>
  <div class='card-hd'><div><div class='card-label'>Priority Actions</div><div class='card-sub'>Critical and high-severity gaps requiring immediate attention</div></div><div style='font-size:.73rem;font-weight:700;color:var(--gap)'>$($topGaps.Count) items</div></div>
  <div class='acts'>$actsHtml</div>
</div>"
})

<!-- NAMED INVENTORY FINDINGS -->
$(if ($namedHtml) { "<div class='cnt' style='padding-top:0;padding-bottom:0'>$namedHtml</div>" })

<!-- SCORE-LIFT REMEDIATION ROADMAP -->
$scoreRoadmapHtml

<!-- EMBEDDED DOWNLOADS -->
$attachHtml

<!-- ROADMAP + BEST PRACTICES -->
<div class='cnt' style='padding-top:0'>$roadmapHtml</div>

<!-- ALL FINDINGS -->
<div id="findings">$findHtml</div>

</div><!-- /cnt -->

<div class="ftr">
  <div class="ftr-l">
    <div class="ftr-co">$co2</div>
    <div class="ftr-contact">$(if($ph2){"$ph2 &nbsp;&middot;&nbsp;"})$(if($ws2b){"<a href='https://$ws2b' target='_blank' rel='noopener noreferrer'>$ws2b</a>"})</div>
    <div class="ftr-note">Read-only assessment &mdash; no configuration changes were made to this tenant &middot; NRG-Assessment v$vr</div>
  </div>
  <div class="ftr-r">
    <div style="font-size:.73rem;color:rgba(255,255,255,.5)">Ready to remediate these findings?</div>
    <a class="ftr-cta" href="$(if($ws2b){"https://$ws2b"}else{'#'})" target="_blank" rel="noopener noreferrer">Contact NRG &rarr;</a>
    <div class="ftr-note">$dS</div>
  </div>
</div>

</div><!-- /wrap -->
<script>$inlineScript</script>
</body></html>
"@

    # ── CSP integrity self-check ───────────────────────────────────────────────
    # Re-derive the SHA-256 hash of the inline <script> body actually emitted into
    # $html and compare it to the hash baked into the CSP. If they differ — e.g.
    # because a future edit interpolated a $variable into $inlineScript — refuse
    # to write the file rather than ship a report whose buttons silently fail.
    $cspMatch = [regex]::Match($html, "script-src 'sha256-([A-Za-z0-9+/=]+)'")
    $scrMatch = [regex]::Match($html, '(?s)<script>(.*?)</script>')
    if (-not $cspMatch.Success -or -not $scrMatch.Success) {
        throw 'CSP integrity check: could not locate hashed script-src or inline <script> in generated HTML — refusing to write report.'
    }
    $declaredHash = $cspMatch.Groups[1].Value
    $sha256b = [System.Security.Cryptography.SHA256]::Create()
    try {
        $actualHash = [System.Convert]::ToBase64String($sha256b.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($scrMatch.Groups[1].Value)))
    } finally {
        $sha256b.Dispose()
    }
    if ($actualHash -ne $declaredHash) {
        throw ("CSP integrity check FAILED: declared SHA-256 '$declaredHash' does not match inline-script body hash '$actualHash'. Browser will block the script. Likely cause: a `$variable` was interpolated into `$inlineScript`, drifting the hash. Refusing to write report.")
    }

    # Publisher self-hardens via Set-NRGSensitiveFileContent: the file is
    # pre-created and its ACL applied BEFORE tenant data lands. Writing with a
    # bare Out-File lets the file inherit the parent directory ACL for the
    # duration of the write, which on a shared MSP workstation or a synced
    # OneDrive folder is a window in which a co-resident process can read CA
    # policies, admin UPNs, OAuth grants and DMARC records. Hardening travels
    # with the terminal write so no caller can forget it. The Out-File fallback
    # preserves behaviour if Lib/ has not been dot-sourced.
    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $OutputPath -Content $html
    } else {
        $html | Out-File -LiteralPath $OutputPath -Encoding utf8
        if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileAcl -Path $OutputPath -ErrorAction SilentlyContinue
        }
    }
}