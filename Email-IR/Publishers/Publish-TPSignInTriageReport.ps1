#Requires -Version 7.0
#
# Publish-TPSignInTriageReport.ps1  (v4.12.0)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Render the admin-scope sign-in triage report — HTML + Markdown.
#          Shows the ranked-user list up front, then sign-in IoC findings,
#          then (if deep-dived) per-user mailbox IR findings.
#
# Self-hardens via Set-TPSensitiveFileContent (v4.11.3 pattern).
# XSS guard via ConvertTo-TPHtmlSafe with inline fallback.

function Publish-TPSignInTriageReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Metadata,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $RankedUsers,
        [Parameter(Mandatory)] [string] $OutputPath,
        [string] $MarkdownPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $hx = if (Get-Command ConvertTo-TPHtmlSafe -ErrorAction SilentlyContinue) {
        { param($s) ConvertTo-TPHtmlSafe $s }
    } else {
        { param($s)
            if ($null -eq $s) { return '' }
            ([string]$s) -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' `
                         -replace '"','&quot;' -replace "'",'&#39;'
        }
    }

    # ── Counts + verdict ─────────────────────────────────────────────────────
    $byState = @{
        Critical  = @($Findings | Where-Object { $_.Severity -eq 'Critical' -and $_.State -eq 'Gap' })
        High      = @($Findings | Where-Object { $_.Severity -eq 'High'     -and $_.State -eq 'Gap' })
        Satisfied = @($Findings | Where-Object { $_.State -eq 'Satisfied' })
        Notes     = @($Findings | Where-Object { $_.State -eq 'NotApplicable' })
    }
    # The verdict describes indicators, never a confirmed compromise: every rule
    # here is a heuristic over sign-in metadata, and a Critical is the strongest
    # heuristic, not proof. "No strong indicators" is only allowed when the reads
    # behind it completed; otherwise the tenant is NOT cleared.
    $complete = $true
    # Get-TPObjectField, not .ContainsKey: the entry point passes an [ordered] dictionary.
    $cc = Get-TPObjectField -Item $Metadata -Key 'CollectionComplete' -Default $null
    if ($null -ne $cc) { $complete = [bool]$cc }
    $gaps = @(Get-TPObjectField -Item $Metadata -Key 'CollectionGaps' -Default @()) | Where-Object { $_ }
    $verdict = if ($byState.Critical.Count -gt 0) { 'CRITICAL INDICATORS — INVESTIGATE' }
               elseif ($byState.High.Count -gt 0) { 'SUSPECT ACTIVITY — REVIEW' }
               elseif (-not $complete) { 'NOT CLEARED — EVIDENCE INCOMPLETE' }
               else { 'NO STRONG INDICATORS IN THE EVENTS READ' }
    $verdictColor = if ($byState.Critical.Count -gt 0) { 'red' }
                    elseif ($byState.High.Count -gt 0 -or -not $complete) { 'amber' }
                    else { 'grn' }
    $incompleteNote = if (-not $complete) { " The evidence is also incomplete, so more indicators may exist: $(@($gaps) -join '; ')." } else { '' }
    $verdictBasis = if ($byState.Critical.Count -gt 0) { "Heuristic indicators, not a confirmed compromise. Verify each flagged account before acting.$incompleteNote" }
                    elseif ($byState.High.Count -gt 0 -and -not $complete) { "Review the flagged findings.$incompleteNote" }
                    elseif (-not $complete) { "Not cleared: $($gaps -join '; ')." }
                    else { 'Describes the sign-in events read in the window, not the whole tenant.' }
    $verdictIco = if ($verdictColor -eq 'grn') { '&#10003;' } else { '&#9888;' }

    # Header values (pre-compute then escape; avoids inline-if-in-arg parsing)
    $brand     = if ((Get-TPObjectField -Item $Metadata -Key 'Brand' -Default $null))         { (Get-TPObjectField -Item $Metadata -Key 'Brand' -Default $null) } else { @{} }
    $bnRaw     = if (Get-TPObjectField -Item $brand -Key 'CompanyName' -Default $null) { Get-TPObjectField -Item $brand -Key 'CompanyName' -Default '' } else { 'NRG Technology Services' }
    $adminRaw  = if ((Get-TPObjectField -Item $Metadata -Key 'ConnectedAdmin' -Default $null)){ (Get-TPObjectField -Item $Metadata -Key 'ConnectedAdmin' -Default $null) } else { 'unknown' }
    $tidRaw    = if ((Get-TPObjectField -Item $Metadata -Key 'TenantId' -Default $null))      { (Get-TPObjectField -Item $Metadata -Key 'TenantId' -Default $null) } else { 'unknown' }
    $assRaw    = if ((Get-TPObjectField -Item $Metadata -Key 'AssessmentDate' -Default $null)){ (Get-TPObjectField -Item $Metadata -Key 'AssessmentDate' -Default $null) } else { Get-Date -Format 'MMMM dd, yyyy HH:mm UTC' }
    $winRaw    = if ((Get-TPObjectField -Item $Metadata -Key 'WindowDays' -Default $null))    { (Get-TPObjectField -Item $Metadata -Key 'WindowDays' -Default $null) } else { 7 }
    $verRaw    = if ((Get-TPObjectField -Item $Metadata -Key 'ToolVersion' -Default $null))   { (Get-TPObjectField -Item $Metadata -Key 'ToolVersion' -Default $null) } else { '' }
    $divedCount = @((Get-TPObjectField -Item $Metadata -Key 'DeepDivedUsers' -Default $null)).Count

    $brandName = & $hx $bnRaw
    $admin     = & $hx $adminRaw
    $tenantId  = & $hx $tidRaw
    $assessed  = & $hx $assRaw
    $window    = & $hx ([string]$winRaw)
    $toolVer   = & $hx $verRaw

    # ── Ranked users table ───────────────────────────────────────────────────
    $rankedHtml = if ($RankedUsers.Count -eq 0) {
        '<p class="empty">No users met the IoC threshold for ranking.</p>'
    } else {
        $rows = foreach ($u in $RankedUsers) {
            $upn = & $hx $u.UserPrincipalName
            $dnRaw = if ($u.DisplayName) { $u.DisplayName } else { '—' }
            $dn  = & $hx $dnRaw
            $score = $u.Score
            $reasons = & $hx ($u.Reasons -join '; ')
            $scoreClass = if ($score -ge 70) { 'sev-crit' } elseif ($score -ge 40) { 'sev-high' } else { 'sev-med' }
            "<tr><td><b>$upn</b><br><span class=`"hsg`">$dn</span></td><td><span class=`"sev $scoreClass`">$score</span></td><td>$reasons</td></tr>"
        }
        "<table><thead><tr><th>User</th><th>IoC Score</th><th>Reasons</th></tr></thead><tbody>$(($rows -join "`n"))</tbody></table>"
    }

    # ── Sign-in findings (SIGNIN-*) vs mailbox findings (EMAIL-*) ───────────
    function FmtFinding {
        param($f, $hxRef)
        $sev = & $hxRef ([string]$f.Severity)
        $sevClass = switch ($f.Severity) {
            'Critical' { 'sev-crit' } 'High' { 'sev-high' } 'Medium' { 'sev-med' } default { 'sev-low' }
        }
        $stateClass = switch ($f.State) {
            'Gap' { 'st-gap' } 'Satisfied' { 'st-ok' } 'NotApplicable' { 'st-na' } default { 'st-info' }
        }
        $cid    = & $hxRef ([string]$f.ControlId)
        $title  = & $hxRef ([string]$f.Title)
        $detail = (& $hxRef ([string]$f.Detail)) -replace "`n",'<br>'
        $remed = if ($f.Remediation) { & $hxRef ([string]$f.Remediation) } else { $null }
        $remedHtml = if ($remed) { "<div class=`"remed`"><b>Recommended action:</b> $remed</div>" } else { '' }
        $subj = [string](Get-TPObjectField -Item $f -Key 'Subject' -Default '')
        $ev = Get-TPObjectField -Item $f -Key 'Evidence' -Default $null
        $subjHtml = ''
        if ($subj) {
            $miss = @(Get-TPObjectField -Item $ev -Key 'RequiredMissing' -Default @())
            $evLine = if ($ev -and $miss.Count -gt 0) { " Evidence incomplete: required source(s) not read: $(& $hxRef ($miss -join ', '))." } elseif ($ev) { ' Evidence: every required mailbox source was read.' } else { '' }
            $subjHtml = "<div class=`"subject`"><b>Account:</b> $(& $hxRef $subj).$evLine</div>"
        }
        @"
<div class="finding $stateClass">
  <div class="finding-hd"><span class="cid">$cid</span><span class="sev $sevClass">$sev</span><span class="finding-title">$title</span></div>
  <div class="finding-bd">$subjHtml<div class="detail">$detail</div>$remedHtml</div>
</div>
"@
    }

    $signinFindings = @($Findings | Where-Object { [string]$_.ControlId -like 'SIGNIN-*' })
    $emailFindings  = @($Findings | Where-Object { [string]$_.ControlId -like 'EMAIL-*' })

    $signinHtml = if ($signinFindings.Count -eq 0) { '<p class="empty">No sign-in findings.</p>' }
                  else { ($signinFindings | ForEach-Object { FmtFinding $_ $hx }) -join "`n" }
    $emailHtml  = if ($emailFindings.Count -eq 0) { '<p class="empty">No mailbox findings (deep-dive skipped or no flagged users).</p>' }
                  else { ($emailFindings | ForEach-Object { FmtFinding $_ $hx }) -join "`n" }

    # ── HTML ─────────────────────────────────────────────────────────────────
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; object-src 'none'; base-uri 'none';">
<title>Sign-In Triage Report — $tenantId</title>
<style>
:root{--ink:#1f2733;--mut:#6b7484;--bdr:#e8edf5;--bg:#f4f7fb;--card:#fff;--red:#dc2626;--red-d:#991b1b;--red-bg:#fef2f2;--red-bd:#fecaca;--amber:#ca8a04;--amber-bg:#fffbeb;--amber-bd:#fde68a;--grn:#166534;--grn-bg:#f0fdf4;--grn-bd:#bbf7d0;--blue:#1e40af;--blue-bg:#eff6ff;--blue-bd:#bfdbfe;--org:#e87722;--org2:#ea580c;--ff:'Segoe UI Variable Display','Segoe UI','Helvetica Neue',system-ui,sans-serif;--fm:'Segoe UI Mono','Consolas',monospace;}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--ff);background:var(--bg);color:var(--ink);line-height:1.5;font-size:14px}
.wrap{max-width:960px;margin:0 auto;padding:0 0 64px}
.hdr{background:linear-gradient(135deg,#1f2733 0%,#2b3545 100%);color:#fff;padding:30px 40px 26px;position:relative;overflow:hidden}
.hdr::after{content:'';position:absolute;top:0;right:0;width:280px;height:100%;background:linear-gradient(135deg,transparent,rgba(232,119,34,.18));pointer-events:none}
.hdr-top{display:flex;justify-content:space-between;align-items:flex-start;position:relative;z-index:1}
.doc-title{font-size:1.5rem;font-weight:700;letter-spacing:-.01em}
.doc-sub{font-size:.85rem;color:#aeb8c7;margin-top:6px}
.logo-t{font-weight:700;font-size:1.05rem}.logo-t b{color:var(--org)}
.ver{font-family:var(--fm);font-size:.65rem;color:#aeb8c7;margin-top:4px}
.meta{display:flex;gap:28px;margin-top:20px;position:relative;z-index:1;flex-wrap:wrap}
.meta .m{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:#8b95a6}
.meta .m b{display:block;font-size:.92rem;text-transform:none;letter-spacing:0;color:#fff;font-weight:600;margin-top:2px}
.verdict{margin:22px 40px 0;padding:22px 26px;border-radius:10px;display:flex;align-items:center;gap:24px}
.verdict.red{background:var(--red-bg);border:1px solid var(--red-bd)}
.verdict.amber{background:var(--amber-bg);border:1px solid var(--amber-bd)}
.verdict.grn{background:var(--grn-bg);border:1px solid var(--grn-bd)}
.verdict-ico{font-size:2.5rem;line-height:1}
.verdict.red .verdict-ico{color:var(--red-d)}.verdict.amber .verdict-ico{color:var(--amber)}.verdict.grn .verdict-ico{color:var(--grn)}
.verdict-lbl{font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;color:var(--mut);font-weight:700}
.verdict-val{font-size:1.7rem;font-weight:800;margin-top:2px}
.verdict-basis{font-size:.85rem;color:var(--mut);margin-top:4px}
.subject{font-size:.85rem;color:var(--mut);margin-bottom:6px}
.verdict.red .verdict-val{color:var(--red-d)}.verdict.amber .verdict-val{color:var(--amber)}.verdict.grn .verdict-val{color:var(--grn)}
.verdict-counts{margin-left:auto;display:flex;gap:18px}
.vc{text-align:center;min-width:60px}.vc .n{font-size:1.6rem;font-weight:800;line-height:1}
.vc .l{font-size:.62rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);margin-top:4px}
.vc.crit .n{color:var(--red)}.vc.high .n{color:var(--org2)}.vc.ok .n{color:var(--grn)}
.cnt{padding:0 40px}
.card{background:var(--card);border:1px solid var(--bdr);border-radius:10px;margin-top:22px;overflow:hidden;box-shadow:0 1px 3px rgba(31,39,51,.04)}
.card-hd{padding:16px 22px;border-bottom:1px solid var(--bdr);display:flex;align-items:baseline;gap:12px}
.sec-no{font-family:var(--fm);font-size:.78rem;color:var(--org2);font-weight:700}
.card-label{font-size:1.02rem;font-weight:700}
.card-bd{padding:18px 22px}
table{width:100%;border-collapse:collapse;font-size:.85rem}
th{text-align:left;padding:10px 12px;background:#fafcff;border-bottom:1px solid var(--bdr);font-size:.66rem;text-transform:uppercase;color:var(--mut);letter-spacing:.06em}
td{padding:10px 12px;border-bottom:1px solid var(--bdr);vertical-align:top}
.hsg{font-family:var(--fm);font-size:.72rem;color:var(--mut)}
.sev{font-size:.66rem;font-weight:700;text-transform:uppercase;padding:3px 10px;border-radius:4px;letter-spacing:.04em;display:inline-block;font-family:var(--fm)}
.sev-crit{background:var(--red-bg);color:var(--red-d);border:1px solid var(--red-bd)}
.sev-high{background:#fff7ed;color:var(--org2);border:1px solid #fdba74}
.sev-med{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber-bd)}
.sev-low{background:#eef2ff;color:#3730a3;border:1px solid #c7d2fe}
.finding{border-radius:8px;border:1px solid var(--bdr);margin-bottom:12px;background:#fff}
.finding.st-gap{border-left:4px solid var(--red)}
.finding.st-ok{border-left:4px solid var(--grn);opacity:.88}
.finding.st-na{border-left:4px solid var(--blue)}
.finding-hd{padding:10px 14px;display:flex;align-items:center;gap:10px;background:#fafcff}
.cid{font-family:var(--fm);font-size:.72rem;color:#475569;background:#e2e8f0;padding:2px 8px;border-radius:4px}
.finding-title{font-weight:600}
.finding-bd{padding:12px 14px}
.detail{font-family:var(--fm);font-size:.78rem;color:#334155;background:#f8fafc;padding:10px 12px;border-radius:6px;white-space:pre-wrap;line-height:1.55}
.remed{margin-top:10px;padding:10px 12px;background:var(--blue-bg);border:1px solid var(--blue-bd);border-radius:6px;font-size:.82rem}
.remed b{color:var(--blue)}
.empty{color:var(--mut);font-style:italic;font-size:.82rem;padding:8px 4px}
.ftr{margin:30px 40px 0;padding-top:18px;border-top:1px solid var(--bdr);display:flex;justify-content:space-between;font-size:.7rem;color:var(--mut);flex-wrap:wrap;gap:8px}
.ftr b{color:var(--ink)}
@media print{body{background:#fff}.card{box-shadow:none;break-inside:avoid}.hdr::after{display:none}}
@media(max-width:640px){.verdict{flex-wrap:wrap;margin-left:20px;margin-right:20px}.verdict-counts{margin-left:0;margin-top:14px}.cnt,.hdr,.ftr{padding-left:20px;padding-right:20px}}
</style>
</head>
<body>
<div class="wrap">
  <div class="hdr">
    <div class="hdr-top">
      <div>
        <div class="doc-title">Sign-In Triage — Admin-Scope Incident Response</div>
        <div class="doc-sub">Tenant-wide sign-in IoC analysis &middot; ranked-user list &middot; per-user mailbox deep-dive</div>
      </div>
      <div style="text-align:right">
        <div class="logo-t">$brandName</div>
        <div class="ver">TenantPosture v$toolVer</div>
      </div>
    </div>
    <div class="meta">
      <div class="m">Tenant<b>$tenantId</b></div>
      <div class="m">Admin<b>$admin</b></div>
      <div class="m">Assessed<b>$assessed</b></div>
      <div class="m">Window<b>$window day(s)</b></div>
      <div class="m">Deep-dived<b>$divedCount user(s)</b></div>
    </div>
  </div>

  <div class="verdict $verdictColor">
    <div class="verdict-ico">$verdictIco</div>
    <div>
      <div class="verdict-lbl">Verdict</div>
      <div class="verdict-val">$verdict</div>
      <div class="verdict-basis">$(& $hx $verdictBasis)</div>
    </div>
    <div class="verdict-counts">
      <div class="vc crit"><div class="n">$($byState.Critical.Count)</div><div class="l">Critical</div></div>
      <div class="vc high"><div class="n">$($byState.High.Count)</div><div class="l">High</div></div>
      <div class="vc ok"><div class="n">$($byState.Satisfied.Count)</div><div class="l">Clean</div></div>
    </div>
  </div>

  <div class="cnt">
    <div class="card">
      <div class="card-hd"><span class="sec-no">01</span><span class="card-label">Ranked Users by IoC Score</span></div>
      <div class="card-bd">$rankedHtml</div>
    </div>
    <div class="card">
      <div class="card-hd"><span class="sec-no">02</span><span class="card-label">Sign-In Log Findings (SIGNIN-*)</span></div>
      <div class="card-bd">$signinHtml</div>
    </div>
    <div class="card">
      <div class="card-hd"><span class="sec-no">03</span><span class="card-label">Per-User Mailbox Findings (EMAIL-*) — Deep-Dive</span></div>
      <div class="card-bd">$emailHtml</div>
    </div>
  </div>

  <div class="ftr">
    <div>Prepared by <b>$brandName</b> &middot; Admin-Scope Triage Mode</div>
    <div>Generated from TenantPosture v$toolVer &middot; $assessed</div>
  </div>
</div>
</body>
</html>
"@

    if (Get-Command Set-TPSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-TPSensitiveFileContent -Path $OutputPath -Content $html
    } else {
        $html | Out-File -LiteralPath $OutputPath -Encoding utf8
    }

    if ($MarkdownPath) {
        # Markdown injection guard. UPN, ranked-user Reasons, and finding
        # Title / Detail / Remediation all originate from Graph
        # (attacker-influenceable via sign-in attributes, risk-event labels,
        # display names). Without escaping, a pipe character breaks table
        # layout and backticks open arbitrary code blocks that some Markdown
        # renderers (Pandoc with --filter, MkDocs unsafe HTML) treat as raw
        # HTML — XSS vector at render time. Mirrors EscMd in
        # Publish-TPAssessmentSummary.
        $EscMd = {
            param([object] $v)
            if ($null -eq $v -or [string]::IsNullOrEmpty([string]$v)) { return '' }
            ([string]$v) -replace '\|', '\|' -replace '`', '\`' -replace '[\r\n]+', ' '
        }
        $md = "# Sign-In Triage Report — $(& $EscMd $tidRaw)`n`n"
        $md += "**Admin:** $(& $EscMd $adminRaw)  `n**Assessed:** $(& $EscMd $assRaw)  `n**Window:** $(& $EscMd ([string]$winRaw)) day(s)  `n"
        $md += "**Tool:** TenantPosture v$(& $EscMd $verRaw)  `n**Verdict:** **$verdict**  `n$(& $EscMd $verdictBasis)  `n`n"
        $md += "| Severity | Count |`n|---|---|`n| Critical | $($byState.Critical.Count) |`n| High | $($byState.High.Count) |`n| Clean | $($byState.Satisfied.Count) |`n`n"
        $md += "## Ranked Users`n`n"
        if ($RankedUsers.Count -eq 0) { $md += "_No users met the IoC threshold._`n`n" }
        else {
            $md += "| UPN | Score | Reasons |`n|---|---|---|`n"
            foreach ($u in $RankedUsers) {
                $md += "| $(& $EscMd $u.UserPrincipalName) | $($u.Score) | $(& $EscMd ($u.Reasons -join '; ')) |`n"
            }
            $md += "`n"
        }
        foreach ($section in @('Critical','High','Notes','Satisfied')) {
            $items = $byState.$section
            if ($items.Count -eq 0) { continue }
            $md += "## $section`n`n"
            foreach ($f in $items) {
                $fsubj = [string](Get-TPObjectField -Item $f -Key 'Subject' -Default '')
                $fev = Get-TPObjectField -Item $f -Key 'Evidence' -Default $null
                $md += "### $(& $EscMd $f.ControlId): $(& $EscMd $f.Title)$(if ($fsubj) { " — $(& $EscMd $fsubj)" })`n`n"
                if ($fsubj -and $fev) {
                    $fmiss = @(Get-TPObjectField -Item $fev -Key 'RequiredMissing' -Default @())
                    $md += "*Account $(& $EscMd $fsubj). $(if ($fmiss.Count -gt 0) { "Evidence incomplete: required source(s) not read: $(& $EscMd ($fmiss -join ', '))." } else { 'Every required mailbox source was read.' })*`n`n"
                }
                $md += "$(& $EscMd $f.Detail)`n`n"
                if ($f.Remediation) { $md += "**Action:** $(& $EscMd $f.Remediation)`n`n" }
            }
        }
        if (Get-Command Set-TPSensitiveFileContent -ErrorAction SilentlyContinue) {
            Set-TPSensitiveFileContent -Path $MarkdownPath -Content $md
        } else {
            $md | Out-File -LiteralPath $MarkdownPath -Encoding utf8
        }
    }
}
