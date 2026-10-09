#Requires -Version 7.0
#
# Publish-TPImprovementPlan.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: The NIST SP 800-53 Rev 5 improvement plan — what to do next, in
#          what order, and what it will cost to do it.
#
#          Every other deliverable in this repo reports a POSITION. This one
#          reports a ROUTE. Ordered steps, the exact projected coverage after
#          each, the 800-53 families each one moves, and what the change will
#          break — because a plan gets approved by someone accountable for the
#          disruption, not just for the score.
#
#          Organized into the two tracks the work actually splits into: things
#          that go in this week because nobody will notice, and things that
#          need a window. A license-blocked item is listed separately and never
#          given a projected number.
#
#          SINGLE FRAMEWORK, DELIBERATELY. This document names NIST 800-53 and
#          nothing else. A client working toward 800-53 should not have to read
#          their route out of a multi-framework document, and a plan that hedges
#          across four frameworks orders its steps for none of them. Same rule
#          as Publish-TPNISTMatrix, and a test greps for the other frameworks
#          and fails on any leak. Only the NIST control identifiers are
#          rendered — never the raw FrameworkIds, which carry every other
#          citation the control holds.
#
#          NOT A COMPLETION PLAN. Finishing every step closes what a Microsoft
#          365 tenant scan and an endpoint scan can observe, which is a subset
#          of 800-53. The plan states its own ceiling on the first page rather
#          than letting a reader infer that 100% means done.
#
# Inputs:  -Plan        output of Get-TPNISTImprovementPlan.
#          -OutputPath  .md path. HTML written alongside with the same base name.
#          -Metadata    tenant domain, assessment date, tool version.
#          -ClientName  optional; titles the plan.
#
# Consumes: the plan only. No Graph, no EXO, no network.
#


# "EXO-6.3 + EXO-7.3" for a step that closes controls reading the same
# setting (Config/control-links.json); the control ID alone otherwise.
function Get-TPPlanStepIds {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Step)
    $ids = @([string](Get-TPObjectField -Item $Step -Key 'ControlId' -Default '')) +
           @(@(Get-TPObjectField -Item $Step -Key 'LinkedControls' -Default @()) | ForEach-Object { [string]$_ } | Where-Object { $_ })
    return (@($ids | Where-Object { $_ } | Select-Object -Unique) -join ' + ')
}

function Publish-TPImprovementPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary] $Plan,

        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
            return $true
        })]
        [string] $OutputPath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [hashtable] $Metadata,

        [Parameter(Mandatory = $false)]
        [AllowNull()] [AllowEmptyString()]
        [string] $ClientName
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not $Plan['Available']) {
        Write-Warning 'No NIST-cited findings to plan against — improvement plan not generated.'
        return
    }

    function EscMd { param([object]$v) ([string]$v) -replace '\|', '\|' -replace '[\r\n]+', ' ' }
    function Esc   { param([object]$v) ConvertTo-TPHtmlSafe $v }

    $base   = $Plan['Baseline']
    $proj   = $Plan['Projected']
    $tracks = @($Plan['Tracks'])
    $fams   = @($Plan['Families'])
    $blocked = @($Plan['Blocked'])
    $ceiling = $Plan['Ceiling']

    $brand   = if ($script:TPBrand) { $script:TPBrand } else { @{} }
    $company = if ($brand['CompanyName']) { [string]$brand['CompanyName'] } else { 'NRG Technology Services' }

    $tenant  = [string](Get-TPObjectField -Item $Metadata -Key 'TenantDomain'   -Default '')
    $date    = [string](Get-TPObjectField -Item $Metadata -Key 'AssessmentDate' -Default (Get-Date -Format 'yyyy-MM-dd'))
    $version = [string](Get-TPObjectField -Item $Metadata -Key 'ToolVersion'    -Default '')

    $title = 'NIST 800-53 Improvement Plan'
    if ($ClientName)  { $title = "NIST 800-53 Improvement Plan — $ClientName" }
    elseif ($tenant)  { $title = "NIST 800-53 Improvement Plan — $tenant" }

    # ─────────────────────────────────────────────────────────────────────────
    # Markdown
    # ─────────────────────────────────────────────────────────────────────────
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("# $(EscMd $title)")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('**Framework:** NIST SP 800-53 Revision 5  ')
    if ($tenant)  { $null = $sb.AppendLine("**Tenant:** $(EscMd $tenant)  ") }
    $null = $sb.AppendLine("**Prepared by:** $(EscMd $company)  ")
    $null = $sb.AppendLine("**Date:** $(EscMd $date)  ")
    if ($version) { $null = $sb.AppendLine("**Tool version:** $(EscMd $version)  ") }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine("## Coverage today: $($base['Score'])% &rarr; after this plan: $($proj['Score'])%")
    $null = $sb.AppendLine()
    if ($proj['StepCount'] -eq 0) {
        $null = $sb.AppendLine('There is nothing to do. Every NIST-cited control that was assessed is already satisfied, or is blocked on a license. That is a real result, not an empty report.')
    } else {
        $null = $sb.AppendLine("**$($proj['StepCount']) steps, worth $($proj['PointGain']) points of NIST coverage.** $(if ($tracks.Count -gt 0 -and $tracks[0]['Count'] -gt 0) { "$($tracks[0]['Count']) of them change nothing a user will notice and can go in this week." } else { '' })")
    }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("Scored over **$($base['Scored'])** assessed controls carrying an 800-53 citation: $($base['Satisfied']) satisfied, $($base['Partial']) partial, $($base['Gap']) open. A partial control is worth half a point, so closing one returns half of what closing a gap does &mdash; which is why the order below is not simply worst-first.")
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('> **What this plan does not do.**  ')
    $null = $sb.AppendLine("> $(EscMd $ceiling['Note'])")
    $null = $sb.AppendLine()

    # ── Tracks ───────────────────────────────────────────────────────────────
    foreach ($t in $tracks) {
        if ($t['Count'] -eq 0) { continue }
        $null = $sb.AppendLine("## $(EscMd $t['Name']) &mdash; $($t['Count']) steps, +$($t['PointGain']) points")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("$(EscMd $t['Description'])")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine('| # | Control | What to do | Returns | Coverage after | Effort |')
        $null = $sb.AppendLine('|---:|---|---|---:|---:|---|')
        foreach ($s in @($t['Steps'])) {
            $null = $sb.AppendLine("| $($s['Rank']) | $(EscMd (Get-TPPlanStepIds $s)) | $(EscMd $s['Title']) | +$($s['ScoreLift']) | $($s['CumulativeScore'])% | $(EscMd $s['Effort']) |")
        }
        $null = $sb.AppendLine()
    }

    if ($proj['StepCount'] -gt 0) {
        $null = $sb.AppendLine('---')
        $null = $sb.AppendLine()
        $null = $sb.AppendLine('## The steps in detail')
        $null = $sb.AppendLine()

        foreach ($t in $tracks) {
            foreach ($s in @($t['Steps'])) {
                $null = $sb.AppendLine("### $($s['Rank']). $(EscMd (Get-TPPlanStepIds $s)) &mdash; $(EscMd $s['Title'])")
                $null = $sb.AppendLine()
                $null = $sb.AppendLine("_$(EscMd $t['Name']) &middot; $(EscMd $s['Severity']) &middot; currently $(EscMd $s['State']) &middot; returns $($s['ScoreLift']) points, taking coverage to $($s['CumulativeScore'])%_")
                $null = $sb.AppendLine()
                $null = $sb.AppendLine("**Satisfies.** $(EscMd (@($s['NistControls'] | ForEach-Object { "$_ $(Get-TPNISTControlTitle -ControlId $_)" }) -join '; '))")
                $null = $sb.AppendLine()
                if ($s['CurrentValue']) {
                    $null = $sb.AppendLine("**Currently.** $(EscMd $s['CurrentValue'])")
                    $null = $sb.AppendLine()
                }
                $null = $sb.AppendLine("**How.** $(EscMd $s['Remediation'])")
                $null = $sb.AppendLine()

                $im = $s['Impact']
                if ($im) {
                    $null = $sb.AppendLine("**What it will affect.** $(EscMd $im['Summary'])")
                    $null = $sb.AppendLine()
                    if ($im['Users'])      { $null = $sb.AppendLine("- _Users:_ $(EscMd $im['Users'])") }
                    if ($im['Admins'])     { $null = $sb.AppendLine("- _Administrators:_ $(EscMd $im['Admins'])") }
                    if ($im['Watchouts'])  { $null = $sb.AppendLine("- _Watch out for:_ $(EscMd $im['Watchouts'])") }
                    if ($im['Reversible']) { $null = $sb.AppendLine("- _Reversible:_ $(EscMd $im['Reversible'])") }
                    foreach ($k in @($im['Overrides'].Keys)) {
                        $null = $sb.AppendLine("- _$(EscMd $s['ControlId']) specifically &mdash; $(EscMd (Get-TPSSPImpactLabel $k)):_ $(EscMd $im['Overrides'][$k])")
                    }
                } else {
                    # Never "no impact". An unwritten impact statement must not
                    # read as a cleared change.
                    $null = $sb.AppendLine('**What it will affect.** _Operational impact not documented for this control. Assess the effect before scheduling &mdash; an undocumented impact is not the same as no impact._')
                }
                $null = $sb.AppendLine()
            }
        }
    }

    # ── Family movement ──────────────────────────────────────────────────────
    $null = $sb.AppendLine('---')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('## What moves, by 800-53 family')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('A control supporting two families counts in both, so these rows deliberately do not sum to the assessment total. Each family score uses that family as its own denominator.')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('| Family | | Assessed | Today | After | Movement |')
    $null = $sb.AppendLine('|---|---|---:|---:|---:|---:|')
    foreach ($f in ($fams | Sort-Object @{ Expression = { -$_['Movement'] } }, @{ Expression = { [string]$_['Family'] } })) {
        $mv = if ($f['Movement'] -gt 0) { "+$($f['Movement'])" } else { '&mdash;' }
        $null = $sb.AppendLine("| $(EscMd $f['Family']) | $(EscMd $f['Name']) | $($f['Assessed']) | $($f['ScoreBefore'])% | $($f['ScoreAfter'])% | $mv |")
    }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("This assessment reaches **$($ceiling['Families']) of the $($ceiling['TotalFamilies'])** 800-53 families, across **$($ceiling['NistControls'])** distinct 800-53 controls. The families absent from the table above are not passing &mdash; they were never assessed.")
    $null = $sb.AppendLine()

    # ── License-blocked ──────────────────────────────────────────────────────
    if ($blocked.Count -gt 0) {
        $null = $sb.AppendLine('---')
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("## Blocked on a license &mdash; $($blocked.Count) controls")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine('These cannot be configured until the license exists, so they carry **no projected score**. Buying a license changes the denominator, and a licensed-but-unconfigured control is still a gap &mdash; any number here would be a guess dressed as arithmetic. Treat the license as the entry fee and the configuration as the project.')
        $null = $sb.AppendLine()
        $null = $sb.AppendLine('| Control | What it would give you | Requires | Severity |')
        $null = $sb.AppendLine('|---|---|---|---|')
        foreach ($b in $blocked) {
            $null = $sb.AppendLine("| $(EscMd $b['ControlId']) | $(EscMd $b['Title']) | $(EscMd $b['LicenseReq']) | $(EscMd $b['Severity']) |")
        }
        $null = $sb.AppendLine()
    }

    $null = $sb.AppendLine('---')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("_Prepared by $(EscMd $company) from the assessment of $(EscMd $date). Projected coverage is arithmetic on the same formula the assessment scores with, not an estimate: closing a gap adds one to the numerator, closing a partial adds a half, and the denominator does not move because the control was already assessed. It assumes each step is completed and verified._")

    if (Get-Command Set-TPSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-TPSensitiveFileContent -Path $OutputPath -Content $sb.ToString()
    } else {
        $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8
    }

    # ─────────────────────────────────────────────────────────────────────────
    # HTML
    # ─────────────────────────────────────────────────────────────────────────
    $trackHtml = ''
    foreach ($t in $tracks) {
        if ($t['Count'] -eq 0) { continue }
        $cls = if ($t['Name'] -eq 'Do now') { 'now' } else { 'sched' }
        $rows = ''
        foreach ($s in @($t['Steps'])) {
            $rows += "<tr><td class='rk'>$($s['Rank'])</td><td class='cid'><a href='#s-$(Esc ($s['ControlId'] -replace '[^A-Za-z0-9]','-'))'>$(Esc (Get-TPPlanStepIds $s))</a></td><td class='ttl'>$(Esc $s['Title'])</td><td class='lift'>+$($s['ScoreLift'])</td><td class='cum'>$($s['CumulativeScore'])%</td><td class='eff'>$(Esc $s['Effort'])</td></tr>"
        }
        $trackHtml += @"
<div class="card">
  <div class="thd"><span class="tpill $cls">$(Esc $t['Name'])</span><span class="tnum">$($t['Count']) steps &middot; +$($t['PointGain']) points</span></div>
  <p class="lede">$(Esc $t['Description'])</p>
  <table><thead><tr><th></th><th>Control</th><th>What to do</th><th class="n">Returns</th><th class="n">Coverage after</th><th>Effort</th></tr></thead><tbody>$rows</tbody></table>
</div>
"@
    }

    $detail = ''
    foreach ($t in $tracks) {
        foreach ($s in @($t['Steps'])) {
            $cls = if ($t['Name'] -eq 'Do now') { 'now' } else { 'sched' }
            $nist = (@($s['NistControls'] | ForEach-Object {
                "<strong>$(Esc $_)</strong> $(Esc (Get-TPNISTControlTitle -ControlId $_))"
            }) -join ' &middot; ')

            $im = $s['Impact']
            $imHtml = ''
            if ($im) {
                $lines = ''
                if ($im['Users'])      { $lines += "<div class='ir'><span class='il'>Users</span>$(Esc $im['Users'])</div>" }
                if ($im['Admins'])     { $lines += "<div class='ir'><span class='il'>Admins</span>$(Esc $im['Admins'])</div>" }
                if ($im['Watchouts'])  { $lines += "<div class='ir wo'><span class='il'>Watch out</span>$(Esc $im['Watchouts'])</div>" }
                if ($im['Reversible']) { $lines += "<div class='ir'><span class='il'>Reversible</span>$(Esc $im['Reversible'])</div>" }
                foreach ($k in @($im['Overrides'].Keys)) {
                    $lines += "<div class='ir sp'><span class='il'>$(Esc $s['ControlId'])</span><em>$(Esc (Get-TPSSPImpactLabel $k)):</em> $(Esc $im['Overrides'][$k])</div>"
                }
                $imHtml = "<div class='imp'><div class='isum'>$(Esc $im['Summary'])</div>$lines</div>"
            } else {
                $imHtml = "<p class='note'>Operational impact not documented for this control. Assess the effect before scheduling &mdash; an undocumented impact is not the same as no impact.</p>"
            }

            $detail += @"
<div class='step' id='s-$(Esc ($s['ControlId'] -replace '[^A-Za-z0-9]','-'))'>
  <div class='step-hd'>
    <span class='srank'>$($s['Rank'])</span>
    <span class='scid'>$(Esc (Get-TPPlanStepIds $s))</span>
    <span class='stitle'>$(Esc $s['Title'])</span>
    <span class='tpill $cls'>$(Esc $t['Name'])</span>
  </div>
  <div class='smeta'>$(Esc $s['Severity']) &middot; currently $(Esc $s['State']) &middot; returns <strong>$($s['ScoreLift'])</strong> points, taking coverage to <strong>$($s['CumulativeScore'])%</strong> &middot; $(Esc $s['Effort'])</div>
  <div class='meta2'><span class='lbl2'>Satisfies</span>$nist</div>
  $(if ($s['CurrentValue']) { "<div class='blk'><div class='lbl'>Currently</div>$(Esc $s['CurrentValue'])</div>" })
  <div class='blk how'><div class='lbl'>How</div>$(Esc $s['Remediation'])</div>
  <div class='blk'><div class='lbl'>What it will affect</div>$imHtml</div>
</div>
"@
        }
    }

    $famRows = ''
    foreach ($f in ($fams | Sort-Object @{ Expression = { -$_['Movement'] } }, @{ Expression = { [string]$_['Family'] } })) {
        $mv = if ($f['Movement'] -gt 0) { "<span class='mv'>+$($f['Movement'])</span>" } else { "<span class='mv0'>&mdash;</span>" }
        $w  = [Math]::Max(0, [Math]::Min(100, [int]$f['ScoreBefore']))
        $wa = [Math]::Max(0, [Math]::Min(100, [int]$f['ScoreAfter']))
        $famRows += "<tr><td class='fid'>$(Esc $f['Family'])</td><td class='fname'>$(Esc $f['Name'])</td><td class='n'>$($f['Assessed'])</td><td class='bar'><span class='track'><span class='fill-a' style='width:$wa%'></span><span class='fill-b' style='width:$w%'></span></span></td><td class='n'>$($f['ScoreBefore'])%</td><td class='n'>$($f['ScoreAfter'])%</td><td class='n'>$mv</td></tr>"
    }

    $blockedHtml = ''
    if ($blocked.Count -gt 0) {
        $rows = ''
        foreach ($b in $blocked) {
            $rows += "<tr><td class='cid'>$(Esc $b['ControlId'])</td><td>$(Esc $b['Title'])</td><td class='lic'>$(Esc $b['LicenseReq'])</td><td class='es'>$(Esc $b['Severity'])</td></tr>"
        }
        $blockedHtml = @"
<div class="card">
  <h2>Blocked on a license &mdash; $($blocked.Count) controls</h2>
  <p class="lede">These cannot be configured until the license exists, so they carry <strong>no projected score</strong>. Buying a license changes the denominator, and a licensed-but-unconfigured control is still a gap &mdash; any number here would be a guess dressed as arithmetic. Treat the license as the entry fee and the configuration as the project.</p>
  <table><thead><tr><th>Control</th><th>What it would give you</th><th>Requires</th><th>Severity</th></tr></thead><tbody>$rows</tbody></table>
</div>
"@
    }

    $headline = if ($proj['StepCount'] -eq 0) {
        'There is nothing to do. Every NIST-cited control that was assessed is already satisfied, or is blocked on a license. That is a real result, not an empty report.'
    } else {
        "<strong>$($proj['StepCount']) steps, worth $($proj['PointGain']) points of NIST coverage.</strong>$(if ($tracks.Count -gt 0 -and $tracks[0]['Count'] -gt 0) { " $($tracks[0]['Count']) of them change nothing a user will notice and can go in this week." })"
    }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(Esc $title)</title>
<style>
*{box-sizing:border-box}
body{margin:0;font:15px/1.65 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#111827;background:#eef2f8}
.wrap{max-width:1060px;margin:0 auto;padding:0 20px 60px}
header{background:linear-gradient(138deg,#0f2544 0%,#061325 100%);color:#fff;padding:40px 0 34px}
.eyebrow{font-size:.66rem;letter-spacing:.18em;text-transform:uppercase;color:#e8621a;font-weight:700;margin-bottom:8px}
h1{margin:0 0 16px;font-size:1.85rem;letter-spacing:-.03em;line-height:1.15}
.meta{font-size:.83rem;color:rgba(255,255,255,.5)}
.meta strong{color:rgba(255,255,255,.85);font-weight:600}
.jump{display:flex;align-items:center;gap:18px;margin:6px 0 18px;flex-wrap:wrap}
.sc{text-align:center}
.sc b{display:block;font-size:2.6rem;font-weight:800;letter-spacing:-.04em;line-height:1}
.sc span{font-size:.6rem;text-transform:uppercase;letter-spacing:.1em;color:rgba(255,255,255,.45);font-weight:700}
.sc.now b{color:#fff}
.sc.then b{color:#4ade80}
.arrow{font-size:1.6rem;color:rgba(255,255,255,.3)}
.gain{background:rgba(74,222,128,.14);color:#4ade80;border-radius:20px;padding:5px 14px;font-size:.8rem;font-weight:800;letter-spacing:.02em}
.card{background:#fff;border-radius:12px;padding:22px 26px;margin:26px 0 22px;box-shadow:0 1px 3px rgba(0,0,0,.05),0 4px 18px rgba(15,37,68,.07)}
h2{font-size:1.25rem;letter-spacing:-.02em;margin:0 0 6px}
.lede{font-size:.93rem;line-height:1.7;margin:0 0 8px;max-width:82ch;color:#4b5563}
.warn{background:#fffbeb;border-left:4px solid #f59e0b;border-radius:0 8px 8px 0;padding:14px 18px;margin:16px 0 0;font-size:.9rem;line-height:1.7;max-width:86ch}
.thd{display:flex;align-items:center;gap:12px;margin-bottom:8px}
.tnum{font-size:.8rem;color:#6b7280;font-weight:600}
.tpill{display:inline-block;padding:3px 12px;border-radius:20px;font-size:.66rem;font-weight:800;letter-spacing:.04em;text-transform:uppercase}
.tpill.now{background:#d1fae5;color:#065f46}
.tpill.sched{background:#fef3c7;color:#92400e}
table{width:100%;border-collapse:collapse;font-size:.86rem;margin-top:12px}
th{text-align:left;font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:#6b7280;padding:6px 8px;border-bottom:2px solid #e2e8f0}
th.n,td.n{text-align:right}
td{padding:7px 8px;border-bottom:1px solid #eef2f8;vertical-align:top}
.rk{width:28px;color:#9ca3af;font-weight:700;font-variant-numeric:tabular-nums}
.cid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:800;white-space:nowrap;width:86px}
.cid a{color:#4c1d95;text-decoration:none}
.cid a:hover{text-decoration:underline}
.ttl{font-weight:600}
.lift{text-align:right;color:#065f46;font-weight:700;font-variant-numeric:tabular-nums;white-space:nowrap;width:64px}
.cum{text-align:right;font-weight:800;font-variant-numeric:tabular-nums;white-space:nowrap;width:96px}
.eff{color:#6b7280;font-size:.76rem;white-space:nowrap}
.lic{color:#92400e;font-size:.78rem}
.es{color:#6b7280;font-size:.76rem;white-space:nowrap}
.step{background:#fff;border-radius:12px;padding:18px 22px;margin-bottom:12px;box-shadow:0 1px 3px rgba(0,0,0,.05),0 4px 14px rgba(15,37,68,.05)}
.step-hd{display:flex;align-items:baseline;gap:11px;flex-wrap:wrap}
.srank{font-weight:900;color:#cbd5e1;font-size:1.1rem;font-variant-numeric:tabular-nums}
.scid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:900;color:#4c1d95;font-size:.92rem}
.stitle{font-weight:700;font-size:1rem;flex:1;min-width:200px}
.smeta{font-size:.76rem;color:#6b7280;margin:5px 0 11px}
.blk{margin-bottom:10px;line-height:1.65;font-size:.88rem}
.lbl{font-size:.6rem;font-weight:800;text-transform:uppercase;letter-spacing:.09em;color:#6b7280;margin-bottom:5px}
.how{background:#f8fafc;border-left:3px solid #3b7dd8;border-radius:0 8px 8px 0;padding:11px 15px}
.meta2{font-size:.79rem;color:#4b5563;line-height:1.6;margin:0 0 10px}
.lbl2{font-size:.58rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em;color:#9ca3af;margin-right:7px}
.imp{background:#fdf4ff;border-left:3px solid #a855f7;border-radius:0 8px 8px 0;padding:11px 15px}
.isum{font-weight:700;margin-bottom:6px;font-size:.9rem}
.ir{font-size:.83rem;line-height:1.6;margin-top:4px}
.ir.wo{color:#92400e}
.ir.sp{border-left:2px solid #e9d5ff;padding-left:9px;margin-top:6px}
.ir.sp .il{color:#7c3aed;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;text-transform:none;letter-spacing:0;font-size:.7rem}
.il{display:inline-block;min-width:84px;font-size:.58rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em;color:#9ca3af;vertical-align:top}
.note{color:#92400e;background:#fffbeb;border-radius:7px;padding:9px 13px;font-size:.82rem;margin:0;line-height:1.6}
.fid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:800;color:#4c1d95;white-space:nowrap;width:42px}
.fname{font-weight:600}
.bar{width:170px;vertical-align:middle}
.track{display:block;position:relative;height:8px;background:#eef2f8;border-radius:5px;overflow:hidden}
.fill-a{position:absolute;left:0;top:0;height:100%;background:#86efac;border-radius:5px}
.fill-b{position:absolute;left:0;top:0;height:100%;background:#0f2544;border-radius:5px}
.mv{color:#065f46;font-weight:800}
.mv0{color:#cbd5e1}
footer{color:#6b7280;font-size:.78rem;line-height:1.6;padding:0 4px;max-width:90ch}
@media print{
  body{background:#fff}
  header{background:#0f2544 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  .card,.step{box-shadow:none;border:1px solid #e2e8f0}
  .step,tr{page-break-inside:avoid}
}
</style></head><body>
<header><div class="wrap">
  <div class="eyebrow">NIST SP 800-53 Revision 5</div>
  <h1>$(Esc $title)</h1>
  <div class="jump">
    <div class="sc now"><b>$($base['Score'])%</b><span>Today</span></div>
    <div class="arrow">&rarr;</div>
    <div class="sc then"><b>$($proj['Score'])%</b><span>After this plan</span></div>
    $(if ($proj['PointGain'] -gt 0) { "<div class='gain'>+$($proj['PointGain']) points &middot; $($proj['StepCount']) steps</div>" })
  </div>
  <div class="meta">Prepared by <strong>$(Esc $company)</strong> &middot; $(Esc $date)$(if ($version) { " &middot; tool $(Esc $version)" }) &middot; scored over <strong>$($base['Scored'])</strong> assessed controls</div>
</div></header>

<div class="wrap">
  <div class="card">
    <h2>Where this comes from</h2>
    <p class="lede">$headline</p>
    <p class="lede">Of the $($base['Scored']) assessed controls carrying an 800-53 citation, $($base['Satisfied']) are satisfied, $($base['Partial']) are partial and $($base['Gap']) are open. A partial control is worth half a point, so closing one returns half of what closing a gap does &mdash; which is why the order below is not simply worst-first.</p>
    <div class="warn"><strong>What this plan does not do.</strong> $(Esc $ceiling['Note'])</div>
  </div>

  $trackHtml

  <div class="card">
    <h2>What moves, by 800-53 family</h2>
    <p class="lede">A control supporting two families counts in both, so these rows deliberately do not sum to the assessment total. Each family score uses that family as its own denominator. The dark bar is today; the light band behind it is where this plan takes it.</p>
    <table><thead><tr><th></th><th>Family</th><th class="n">Assessed</th><th></th><th class="n">Today</th><th class="n">After</th><th class="n">Move</th></tr></thead><tbody>$famRows</tbody></table>
    <p class="lede" style="margin-top:12px">This assessment reaches <strong>$($ceiling['Families']) of the $($ceiling['TotalFamilies'])</strong> 800-53 families, across <strong>$($ceiling['NistControls'])</strong> distinct 800-53 controls. The families absent from this table are not passing &mdash; they were never assessed.</p>
  </div>

  $blockedHtml

  $(if ($detail) { "<h2 style='margin:30px 4px 14px'>The steps in detail</h2>$detail" })

  <footer>Prepared by $(Esc $company) from the assessment of $(Esc $date). Projected coverage is arithmetic on the same formula the assessment scores with, not an estimate: closing a gap adds one to the numerator, closing a partial adds a half, and the denominator does not move because the control was already assessed. It assumes each step is completed and verified.</footer>
</div>
</body></html>
"@

    $htmlPath = [System.IO.Path]::ChangeExtension($OutputPath, '.html')
    if (Get-Command Set-TPSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-TPSensitiveFileContent -Path $htmlPath -Content $html
    } else {
        $html | Out-File -LiteralPath $htmlPath -Encoding utf8
    }
}
