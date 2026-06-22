#Requires -Version 7.0
#
# Publish-NRGEmailIncidentReport.ps1  (v4.12.0)
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Render the NRG Email Account Assessment incident report — HTML +
#          Markdown. Visual language matches the existing v4.11 monthly
#          report (cards, status pills, severity badge, callouts) so the
#          operator gets a consistent look across NRG deliverables.
#
# Inputs:  -Metadata        $reportMetadata from the orchestrator
#          -Findings        array of findings (Add-NRGFinding shape)
#          -OutputPath      HTML output path
#          -MarkdownPath    optional Markdown output path
#
# Outputs: HTML + Markdown. Both written via Set-NRGSensitiveFileContent
#          (publisher self-hardens — v4.11.3 altitude pattern).
#
# Security: all operator-supplied + Graph-derived strings flow through
#          ConvertTo-NRGHtmlSafe (with inline fallback). No body content
#          rendered — only subject lines, sender addresses, recipients,
#          URLs, and the operator's incident-response checklist.

function Publish-NRGEmailIncidentReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [hashtable] $Metadata,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]] $Findings,

        [Parameter(Mandatory = $true)]
        [string] $OutputPath,

        [Parameter(Mandatory = $false)]
        [string] $MarkdownPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # XSS guard
    $hx = if (Get-Command ConvertTo-NRGHtmlSafe -ErrorAction SilentlyContinue) {
        { param($s) ConvertTo-NRGHtmlSafe $s }
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
        Medium    = @($Findings | Where-Object { $_.Severity -eq 'Medium'   -and $_.State -eq 'Gap' })
        Satisfied = @($Findings | Where-Object { $_.State -eq 'Satisfied' })
        Notes     = @($Findings | Where-Object { $_.State -eq 'NotApplicable' })
    }
    $verdict = if ($byState.Critical.Count -gt 0) { 'LIKELY COMPROMISED' }
               elseif ($byState.High.Count -gt 0) { 'SUSPICIOUS — REVIEW' }
               else { 'NO STRONG IOCS' }
    $verdictColor = if ($byState.Critical.Count -gt 0) { 'red' }
                    elseif ($byState.High.Count -gt 0) { 'amber' }
                    else { 'grn' }
    $verdictIco = if ($verdictColor -eq 'grn') { '&#10003;' } else { '&#9888;' }

    # ── Header values (pre-compute then escape — avoids `& $hx (if ...)`
    #    which PS parses as command-style and fails) ─────────────────────────
    $brand     = if ($Metadata.Brand)             { $Metadata.Brand } else { @{} }
    $bnRaw     = if ($brand.CompanyName)          { $brand.CompanyName } else { 'NRG Technology Services' }
    $upnRaw    = if ($Metadata.UserPrincipalName) { $Metadata.UserPrincipalName } else { 'unknown' }
    $assRaw    = if ($Metadata.AssessmentDate)    { $Metadata.AssessmentDate    } else { Get-Date -Format 'MMMM dd, yyyy' }
    $winRaw    = if ($Metadata.WindowDays)        { $Metadata.WindowDays } else { 7 }
    $verRaw    = if ($Metadata.ToolVersion)       { $Metadata.ToolVersion } else { '' }
    $tidRaw    = if ($Metadata.TenantId)          { $Metadata.TenantId } else { 'unknown' }

    $brandName = & $hx $bnRaw
    $upn       = & $hx $upnRaw
    $assessed  = & $hx $assRaw
    $window    = & $hx ([string]$winRaw)
    $toolVer   = & $hx $verRaw
    $tenantId  = & $hx $tidRaw

    # ── Build findings sections ─────────────────────────────────────────────
    function FmtFindingHtml {
        param($f, $hxRef)
        $sev = & $hxRef ([string]$f.Severity)
        $sevClass = switch ($f.Severity) {
            'Critical' { 'sev-crit' }
            'High'     { 'sev-high' }
            'Medium'   { 'sev-med'  }
            default    { 'sev-low'  }
        }
        $stateClass = switch ($f.State) {
            'Gap'           { 'st-gap' }
            'Satisfied'     { 'st-ok'  }
            'NotApplicable' { 'st-na'  }
            default         { 'st-info' }
        }
        $cid    = & $hxRef ([string]$f.ControlId)
        $title  = & $hxRef ([string]$f.Title)
        $detail = & $hxRef ([string]$f.Detail)
        $detailHtml = $detail -replace "`n", '<br>'
        $remed = if ($f.Remediation) { & $hxRef ([string]$f.Remediation) } else { $null }
        $remedHtml = if ($remed) { "<div class=`"remed`"><b>Recommended action:</b> $remed</div>" } else { '' }

        # Affected-objects table (the EMAIL-2.1 recipient warn-list only —
        # InboxRule objects from EMAIL-1.1 are rendered by the Containment
        # Runbook, not here, so filter to objects that carry a Recipient).
        $affHtml = ''
        $aff = @($f.AffectedObjects | Where-Object { $_ -and $_.Recipient })
        if ($aff.Count -gt 0) {
            $rows = foreach ($o in $aff) {
                $recip = & $hxRef ([string]$o.Recipient)
                $scope = & $hxRef ([string]$o.Scope)
                $reason = & $hxRef ([string]$o.Reason)
                $scopeClass = if ($o.Scope -eq 'External') { 'sev-high' } else { 'sev-low' }
                "<tr><td>$recip</td><td><span class=`"sev $scopeClass`">$scope</span></td><td>$reason</td></tr>"
            }
            $affHtml = "<div class=`"affbox`"><b>Recipients to warn ($($aff.Count)):</b><table class=`"afftbl`"><thead><tr><th>Recipient</th><th>Scope</th><th>Why</th></tr></thead><tbody>$(($rows -join "`n"))</tbody></table></div>"
        }

        @"
<div class="finding $stateClass">
  <div class="finding-hd">
    <span class="cid">$cid</span>
    <span class="sev $sevClass">$sev</span>
    <span class="finding-title">$title</span>
  </div>
  <div class="finding-bd">
    <div class="detail">$detailHtml</div>
    $affHtml
    $remedHtml
  </div>
</div>
"@
    }

    $critHtml = ($byState.Critical  | ForEach-Object { FmtFindingHtml $_ $hx }) -join "`n"
    $highHtml = ($byState.High      | ForEach-Object { FmtFindingHtml $_ $hx }) -join "`n"
    $notesHtml = ($byState.Notes    | ForEach-Object { FmtFindingHtml $_ $hx }) -join "`n"
    $okHtml   = ($byState.Satisfied | ForEach-Object { FmtFindingHtml $_ $hx }) -join "`n"

    if (-not $critHtml)  { $critHtml = '<p class="empty">No critical IoCs.</p>' }
    if (-not $highHtml)  { $highHtml = '<p class="empty">No high-severity IoCs.</p>' }
    if (-not $notesHtml) { $notesHtml = '' }
    if (-not $okHtml)    { $okHtml = '<p class="empty">No checks satisfied.</p>' }

    # ── Recommended actions (verdict-conditional) ───────────────────────────
    $actions = if ($byState.Critical.Count -gt 0) {
        @(
            'Revoke all active sessions: <code>Revoke-MgUserSignInSession -UserId &lt;upn&gt;</code>'
            'For deep-dive auth: issue a <b>Temporary Access Pass (TAP)</b> in Microsoft Entra &rarr; Users &rarr; the user &rarr; Authentication methods &rarr; Add authentication method &rarr; Temporary Access Pass. Sign in as the user using that TAP, then run <code>Invoke-NRGEmailAssessment.ps1 -UserPrincipalName &lt;upn&gt;</code> from that session. TAPs are one-time-use, time-limited, and do not change the user&apos;s password.'
            'Force re-registration of MFA methods (clear existing methods if attacker added their own).'
            'Delete every inbox rule flagged above. Verify in Outlook > Rules > Manage Rules &amp; Alerts.'
            'Check server-side forwarding from an admin context: <code>Get-Mailbox &lt;upn&gt; | Select ForwardingSmtpAddress,DeliverToMailboxAndForward</code>'
            'Notify external recipients of attacker-sent mail during the compromise window (recipient list in the JSON export).'
            'Submit the identified phish URL + sender domain to Microsoft Defender Submissions for tenant-wide blocking.'
            'Search-and-purge (admin scope) any other users in the tenant who received the same phish: Defender Portal > Email &amp; collaboration > Explorer.'
            'Document the incident timeline using this report as the source of truth. HIPAA / BAA notification clocks may have started.'
        )
    } elseif ($byState.High.Count -gt 0) {
        @(
            'Validate each high-severity finding manually before acting.'
            'If the top phish candidate looks legitimate after review, no immediate action — but note that this user is being targeted.'
            'Consider proactive MFA re-registration if the user clicked any URL flagged here.'
        )
    } else {
        @(
            'No automatic action needed. If you ran this on suspicion, the suspicion does not appear to have a digital signal in the mailbox.'
            'Consider: phish may predate the 30-day inbox window, attacker may have used credential stuffing not phish, or attacker permanently deleted the phish from Recoverable Items (admin-scope eDiscovery search would catch this).'
        )
    }
    $actionsHtml = ($actions | ForEach-Object { "<li>$_</li>" }) -join "`n"

    # ── Containment & Recovery Runbook ──────────────────────────────────────
    # The operator's exact next-steps sequence, with tool-filled specifics:
    # the target UPN substituted into each command and the flagged inbox rules
    # (from EMAIL-1.1 InboxRule AffectedObjects) named with precise delete
    # commands. The tool stays read-only — it GENERATES these commands; the
    # operator runs them and issues the TAP in the Admin Center.
    $upnCmd = $upnRaw   # raw UPN for command substitution (escaped at render)

    # Pull flagged inbox rules out of the EMAIL-1.1 finding's AffectedObjects.
    $flaggedRules = foreach ($f in $Findings) {
        foreach ($o in @($f.AffectedObjects)) {
            if ($o -and $o.RuleType -eq 'InboxRule') { $o }
        }
    }
    $flaggedRules = @($flaggedRules)

    if ($flaggedRules.Count -gt 0) {
        $ruleLines = foreach ($r in $flaggedRules) {
            $rn  = & $hx ([string]$r.Name)
            $rwhy = & $hx ([string]$r.Reason)
            $delCmd = & $hx ("Remove-MgUserMailFolderMessageRule -UserId $upnCmd -MailFolderId Inbox -MessageRuleId $($r.Id)")
            "<li><b>$rn</b> <span class=`"rmut`">($rwhy)</span><br><code>$delCmd</code></li>"
        }
        $rulesBlock = "<p>Delete each attacker-created rule below. Confirm in <code>Get-MgUserMailFolderMessageRule -UserId $(& $hx $upnCmd) -MailFolderId Inbox</code> first, then remove:</p><ul class=`"rblist`">$(($ruleLines -join "`n"))</ul>"
    } else {
        $rulesBlock = "<p>No suspicious inbox rules were flagged (EMAIL-1.1). Still verify manually: <code>Get-MgUserMailFolderMessageRule -UserId $(& $hx $upnCmd) -MailFolderId Inbox</code> and delete anything the user did not create.</p>"
    }

    # Six-step sequence. Each step tagged with where it runs.
    $runbookSteps = @(
        @{ N=1; RunAt='admin-powershell'; Title='Sign out all active sessions'
           Body="Revoke every refresh + access token so the attacker is kicked out immediately.<br><code>$(& $hx "Revoke-MgUserSignInSession -UserId $upnCmd")</code>" }
        @{ N=2; RunAt='admin-portal'; Title='Re-require MFA (revoke current registration)'
           Body="In Microsoft Entra &rarr; Users &rarr; <b>$(& $hx $upnRaw)</b> &rarr; Authentication methods, <b>delete any method you do not recognize</b> (attacker may have added their own phone/authenticator). This forces re-registration at next sign-in." }
        @{ N=3; RunAt='admin-portal'; Title='Reset the password'
           Body="Reset from Microsoft Entra &rarr; Users &rarr; <b>$(& $hx $upnRaw)</b> &rarr; Reset password. Use a one-time password and require change at next sign-in. Do this <b>after</b> sessions are revoked so the new password is never live alongside an attacker session." }
        @{ N=4; RunAt='admin-powershell'; Title='Delete the rules the attacker created'
           Body=$rulesBlock }
        @{ N=5; RunAt='admin-portal'; Title='Re-enroll MFA'
           Body="Have the user re-register a trusted MFA method (Authenticator app preferred) via <code>https://aka.ms/mfasetup</code>, or issue a <b>Temporary Access Pass</b> (Entra &rarr; Users &rarr; <b>$(& $hx $upnRaw)</b> &rarr; Authentication methods &rarr; Add &rarr; Temporary Access Pass) so they can bootstrap a new method. Confirm only known methods remain." }
        @{ N=6; RunAt='on-user-device'; Title='Clear browser cache, history, and cookies'
           Body="On the user's device(s), clear cached credentials and stored session cookies in <b>every</b> browser used for email (Edge/Chrome/Firefox): Settings &rarr; Privacy &rarr; Clear browsing data &rarr; select Cookies + Cached files + Browsing history &rarr; All time. Token-theft attacks survive a password reset if a stolen session cookie is still cached." }
    )
    $whereLabel = @{ 'admin-powershell'='Admin · PowerShell'; 'admin-portal'='Admin · Entra Portal'; 'on-user-device'='On user device' }
    $whereClass = @{ 'admin-powershell'='rb-ps'; 'admin-portal'='rb-portal'; 'on-user-device'='rb-device' }
    $runbookHtml = foreach ($s in $runbookSteps) {
        $wlbl = $whereLabel[$s.RunAt]
        $wcls = $whereClass[$s.RunAt]
        @"
<div class="rbstep">
  <div class="rbnum">$($s.N)</div>
  <div class="rbbody">
    <div class="rbhd"><span class="rbtitle">$($s.Title)</span><span class="rbtag $wcls">$wlbl</span></div>
    <div class="rbtext">$($s.Body)</div>
  </div>
</div>
"@
    }
    $runbookHtml = $runbookHtml -join "`n"

    # ── HTML (single here-string, no inline conditionals in the template) ───
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; object-src 'none'; base-uri 'none';">
<title>Email Incident Report — $upn</title>
<style>
:root{
  --ink:#1f2733;--mut:#6b7484;--bdr:#e8edf5;--bg:#f4f7fb;--card:#fff;
  --red:#dc2626;--red-d:#991b1b;--red-bg:#fef2f2;--red-bd:#fecaca;
  --amber:#ca8a04;--amber-bg:#fffbeb;--amber-bd:#fde68a;
  --grn:#166534;--grn-bg:#f0fdf4;--grn-bd:#bbf7d0;
  --blue:#1e40af;--blue-bg:#eff6ff;--blue-bd:#bfdbfe;
  --org:#e87722;--org2:#ea580c;
  --ff:'Segoe UI Variable Display','Segoe UI','Helvetica Neue',system-ui,sans-serif;
  --fm:'Segoe UI Mono','Consolas',monospace;
}
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:var(--ff);background:var(--bg);color:var(--ink);line-height:1.5;font-size:14px;-webkit-font-smoothing:antialiased}
.wrap{max-width:960px;margin:0 auto;padding:0 0 64px}
.hdr{background:linear-gradient(135deg,#1f2733 0%,#2b3545 100%);color:#fff;padding:30px 40px 26px;position:relative;overflow:hidden}
.hdr::after{content:'';position:absolute;top:0;right:0;width:280px;height:100%;background:linear-gradient(135deg,transparent,rgba(232,119,34,.18));pointer-events:none}
.hdr-top{display:flex;justify-content:space-between;align-items:flex-start;position:relative;z-index:1}
.doc-title{font-size:1.5rem;font-weight:700;letter-spacing:-.01em}
.doc-sub{font-size:.85rem;color:#aeb8c7;margin-top:6px}
.logo-t{font-weight:700;font-size:1.05rem}
.logo-t b{color:var(--org)}
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
.verdict-val{font-size:1.7rem;font-weight:800;letter-spacing:-.02em;margin-top:2px}
.verdict.red .verdict-val{color:var(--red-d)}.verdict.amber .verdict-val{color:var(--amber)}.verdict.grn .verdict-val{color:var(--grn)}
.verdict-counts{margin-left:auto;display:flex;gap:18px}
.vc{text-align:center;min-width:60px}.vc .n{font-size:1.6rem;font-weight:800;line-height:1}
.vc .l{font-size:.62rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);margin-top:4px}
.vc.crit .n{color:var(--red)}.vc.high .n{color:var(--org2)}.vc.ok .n{color:var(--grn)}
.cnt{padding:0 40px}
.card{background:var(--card);border:1px solid var(--bdr);border-radius:10px;margin-top:22px;overflow:hidden;box-shadow:0 1px 3px rgba(31,39,51,.04)}
.card-hd{padding:16px 22px;border-bottom:1px solid var(--bdr);display:flex;align-items:baseline;gap:12px}
.sec-no{font-family:var(--fm);font-size:.78rem;color:var(--org2);font-weight:700}
.card-label{font-size:1.02rem;font-weight:700;letter-spacing:-.01em}
.card-bd{padding:18px 22px}
.finding{border-radius:8px;border:1px solid var(--bdr);margin-bottom:12px;background:#fff}
.finding.st-gap{border-left:4px solid var(--red)}
.finding.st-ok{border-left:4px solid var(--grn);opacity:.88}
.finding.st-na{border-left:4px solid var(--blue)}
.finding-hd{padding:10px 14px;display:flex;align-items:center;gap:10px;background:#fafcff}
.cid{font-family:var(--fm);font-size:.72rem;color:#475569;background:#e2e8f0;padding:2px 8px;border-radius:4px}
.sev{font-size:.64rem;font-weight:700;text-transform:uppercase;padding:2px 9px;border-radius:4px;letter-spacing:.04em}
.sev-crit{background:var(--red-bg);color:var(--red-d);border:1px solid var(--red-bd)}
.sev-high{background:#fff7ed;color:var(--org2);border:1px solid #fdba74}
.sev-med{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber-bd)}
.sev-low{background:#eef2ff;color:#3730a3;border:1px solid #c7d2fe}
.finding-title{font-weight:600}
.finding-bd{padding:12px 14px}
.detail{font-family:var(--fm);font-size:.78rem;color:#334155;background:#f8fafc;padding:10px 12px;border-radius:6px;white-space:pre-wrap;line-height:1.55}
.remed{margin-top:10px;padding:10px 12px;background:var(--blue-bg);border:1px solid var(--blue-bd);border-radius:6px;font-size:.82rem}
.affbox{margin-top:10px;padding:10px 12px;background:#fff7ed;border:1px solid #fdba74;border-radius:6px;font-size:.82rem}
.afftbl{width:100%;border-collapse:collapse;margin-top:8px;font-size:.78rem}
.afftbl th{text-align:left;padding:5px 8px;background:#fff;border-bottom:1px solid var(--bdr);font-size:.62rem;text-transform:uppercase;color:var(--mut)}
.afftbl td{padding:5px 8px;border-bottom:1px solid var(--bdr)}
.remed b{color:var(--blue)}
.empty{color:var(--mut);font-style:italic;font-size:.82rem;padding:8px 4px}
.actions{padding:18px 22px}.actions ol{padding-left:22px}
.actions li{padding:6px 0;font-size:.88rem;line-height:1.6}
.actions code{font-family:var(--fm);font-size:.78rem;background:#f1f5f9;padding:1px 6px;border-radius:3px}
.runbook{padding:8px 22px 18px}
.rbstep{display:flex;gap:16px;padding:14px 0;border-bottom:1px solid var(--bdr)}
.rbstep:last-child{border-bottom:none}
.rbnum{flex:0 0 32px;width:32px;height:32px;border-radius:50%;background:var(--org);color:#fff;font-weight:800;font-size:1rem;display:flex;align-items:center;justify-content:center}
.rbbody{flex:1;min-width:0}
.rbhd{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px}
.rbtitle{font-weight:700;font-size:.95rem}
.rbtag{font-size:.6rem;font-weight:700;text-transform:uppercase;letter-spacing:.04em;padding:2px 8px;border-radius:4px}
.rb-ps{background:#1f2733;color:#e2e8f0}
.rb-portal{background:var(--blue-bg);color:var(--blue);border:1px solid var(--blue-bd)}
.rb-device{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber-bd)}
.rbtext{font-size:.86rem;line-height:1.6;color:#334155}
.rbtext code{font-family:var(--fm);font-size:.76rem;background:#f1f5f9;padding:2px 7px;border-radius:3px;display:inline-block;margin-top:3px;word-break:break-all}
.rblist{list-style:none;padding:0;margin:8px 0 0}
.rblist li{padding:8px 0;border-top:1px dashed var(--bdr)}
.rblist li:first-child{border-top:none}
.rmut{color:var(--mut);font-size:.78rem;font-weight:400}
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
        <div class="doc-title">Email Account Assessment — Incident Response</div>
        <div class="doc-sub">Single-user mailbox investigation &middot; read-only delegated scope</div>
      </div>
      <div style="text-align:right">
        <div class="logo-t">$brandName</div>
        <div class="ver">NRG-Assessment v$toolVer</div>
      </div>
    </div>
    <div class="meta">
      <div class="m">Target User<b>$upn</b></div>
      <div class="m">Assessed<b>$assessed</b></div>
      <div class="m">Outbound Window<b>$window days</b></div>
      <div class="m">Tenant<b>$tenantId</b></div>
    </div>
  </div>

  <div class="verdict $verdictColor">
    <div class="verdict-ico">$verdictIco</div>
    <div>
      <div class="verdict-lbl">Verdict</div>
      <div class="verdict-val">$verdict</div>
    </div>
    <div class="verdict-counts">
      <div class="vc crit"><div class="n">$($byState.Critical.Count)</div><div class="l">Critical</div></div>
      <div class="vc high"><div class="n">$($byState.High.Count)</div><div class="l">High</div></div>
      <div class="vc ok"><div class="n">$($byState.Satisfied.Count)</div><div class="l">Clean</div></div>
    </div>
  </div>

  <div class="cnt">
    <div class="card">
      <div class="card-hd"><span class="sec-no">01</span><span class="card-label">Critical IoCs</span></div>
      <div class="card-bd">$critHtml</div>
    </div>
    <div class="card">
      <div class="card-hd"><span class="sec-no">02</span><span class="card-label">High-Severity IoCs</span></div>
      <div class="card-bd">$highHtml</div>
    </div>
    <div class="card">
      <div class="card-hd"><span class="sec-no">03</span><span class="card-label">Notes / Scope Limitations</span></div>
      <div class="card-bd">$notesHtml</div>
    </div>
    <div class="card">
      <div class="card-hd"><span class="sec-no">04</span><span class="card-label">Checks Satisfied</span></div>
      <div class="card-bd">$okHtml</div>
    </div>
    <div class="card">
      <div class="card-hd"><span class="sec-no">05</span><span class="card-label">Containment &amp; Recovery Runbook</span></div>
      <div class="runbook">$runbookHtml</div>
    </div>
    <div class="card">
      <div class="card-hd"><span class="sec-no">06</span><span class="card-label">Recommended Actions</span></div>
      <div class="actions"><ol>$actionsHtml</ol></div>
    </div>
  </div>

  <div class="ftr">
    <div>Prepared by <b>$brandName</b> &middot; Email Incident Response Mode</div>
    <div>Generated from NRG-Assessment v$toolVer &middot; $assessed</div>
  </div>
</div>
</body>
</html>
"@

    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $OutputPath -Content $html
    } else {
        $html | Out-File -LiteralPath $OutputPath -Encoding utf8
    }

    # ── Recipients warn-list CSV (response deliverable) ──────────────────────
    # Collect every AffectedObject (the EMAIL-2.1 recipient warn-list) and
    # write a recipients.csv next to the report so the operator can hand off
    # the notify-list. Self-hardened like the other outputs.
    #
    # CSV formula-injection guard: recipient strings come from mail the
    # ATTACKER sent (To/Cc/Bcc of outbound from the compromised account) and
    # this CSV is expected to be opened in Excel by the responder. A cell
    # beginning with = + - @ or a tab/CR is interpreted by Excel as a live
    # formula (DDE / =cmd| payloads), so neutralize with a leading apostrophe.
    $csvCell = {
        param($v)
        $s = [string]$v
        if ($s -match '^[=+\-@\t\r]') { "'" + $s } else { $s }
    }
    $allRecipients = foreach ($f in $Findings) {
        foreach ($o in @($f.AffectedObjects)) {
            if ($o -and $o.Recipient) {
                [pscustomobject]@{
                    Recipient   = & $csvCell $o.Recipient
                    Scope       = & $csvCell $o.Scope
                    Reason      = & $csvCell $o.Reason
                    SourceUser  = & $csvCell $upnRaw
                }
            }
        }
    }
    $allRecipients = @($allRecipients)
    if ($allRecipients.Count -gt 0) {
        $csvPath = Join-Path (Split-Path -Parent $OutputPath) 'recipients.csv'
        try {
            $csv = $allRecipients | ConvertTo-Csv -NoTypeInformation | Out-String
            if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
                Set-NRGSensitiveFileContent -Path $csvPath -Content $csv
            } else {
                $allRecipients | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding utf8
            }
            Write-Host "  [+] Recipients warn-list: $csvPath ($($allRecipients.Count) recipients)" -ForegroundColor Green
        } catch { Write-Warning "recipients.csv write failed: $($_.Exception.Message)" }
    }

    # ── Markdown summary ─────────────────────────────────────────────────────
    if ($MarkdownPath) {
        $md = "# Email Account Assessment — $upn`n`n"
        $md += "**Assessed:** $assessed  `n"
        $md += "**Tool:** NRG-Assessment v$toolVer  `n"
        $md += "**Window:** $window days outbound / 30 days inbox  `n"
        $md += "**Verdict:** **$verdict**  `n`n"
        $md += "| Severity | Count |`n|---|---|`n"
        $md += "| Critical | $($byState.Critical.Count) |`n"
        $md += "| High     | $($byState.High.Count) |`n"
        $md += "| Clean    | $($byState.Satisfied.Count) |`n`n"
        foreach ($section in @('Critical','High','Notes','Satisfied')) {
            $items = $byState.$section
            if ($items.Count -eq 0) { continue }
            $md += "## $section`n`n"
            foreach ($f in $items) {
                $md += "### $($f.ControlId): $($f.Title)`n`n"
                $md += "$($f.Detail)`n`n"
                if ($f.Remediation) { $md += "**Action:** $($f.Remediation)`n`n" }
            }
        }
        $md += "## Containment & Recovery Runbook`n`n"
        foreach ($s in $runbookSteps) {
            $wlbl = $whereLabel[$s.RunAt]
            $bodyMd = ([string]$s.Body) -replace '<br>',"`n" -replace '<[^>]+>','' -replace '&rarr;','->' -replace '&amp;','&' -replace '&lt;','<' -replace '&gt;','>'
            $md += "$($s.N). **$($s.Title)** _($wlbl)_`n`n   $($bodyMd -replace "`n","`n   ")`n`n"
        }
        $md += "## Recommended Actions`n`n"
        for ($i = 0; $i -lt $actions.Count; $i++) {
            $clean = $actions[$i] -replace '<code>','`' -replace '</code>','`' -replace '&amp;','&' -replace '&lt;','<' -replace '&gt;','>'
            $md += "$($i+1). $clean`n"
        }
        if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileContent -Path $MarkdownPath -Content $md
        } else {
            $md | Out-File -LiteralPath $MarkdownPath -Encoding utf8
        }
    }
}
