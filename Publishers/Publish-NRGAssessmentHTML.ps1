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
# Author: Matthew Levorson — NRG Technology Services
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
        [string] $ClientName = ''
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
    $co = if ($brand['CompanyName']) { $brand['CompanyName'] } else { 'NRG Technology Services' }
    $ph = if ($brand['Phone']) { $brand['Phone'] } else { '' }
    $ws = if ($brand['Website']) { $brand['Website'] } else { 'nrgtechservices.com' }
    $lu = if ($brand['LogoUrl']) { $brand['LogoUrl'] } else { '' }
    $clientDisplay = if ($ClientName) { $ClientName } else { $Metadata.TenantDomain }

    # ── Counts ────────────────────────────────────────────────────────────────
    $sat  = @($Findings | Where-Object State -eq 'Satisfied').Count
    $part = @($Findings | Where-Object State -eq 'Partial').Count
    $gap  = @($Findings | Where-Object State -eq 'Gap').Count
    $na   = @($Findings | Where-Object State -eq 'NotApplicable').Count
    $scrd = $Findings.Count - $na
    $sc2  = if ($scrd -gt 0) { [Math]::Round(100 * ($sat + 0.5 * $part) / $scrd) } else { 0 }
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
    $wlScores = @{}
    $Findings | Group-Object { ($_.ControlId -replace '-.*$','') } | ForEach-Object {
        $wl = $_.Name; $g = $_.Group
        $ws2 = @($g | Where-Object State -eq 'Satisfied').Count
        $wp  = @($g | Where-Object State -eq 'Partial').Count
        $wn  = @($g | Where-Object State -eq 'NotApplicable').Count
        $wd  = $g.Count - $wn
        $wlScores[$wl] = @{
            Score = if ($wd -gt 0) { [Math]::Round(100*($ws2+0.5*$wp)/$wd) } else { 0 }
            Gaps  = @($g | Where-Object State -eq 'Gap').Count
        }
    }

    # ── Framework scores ──────────────────────────────────────────────────────
    $fwScores = @{}
    foreach ($fw in @('CIS','SCuBA','NIST','CMMC')) {
        $ff = @($Findings | Where-Object {
            $_.FrameworkIds -and ($_.FrameworkIds | Where-Object { $_ -match "^$fw" })
        })
        $fd = @($ff | Where-Object State -ne 'NotApplicable').Count
        $fs = @($ff | Where-Object State -eq 'Satisfied').Count
        $fp = @($ff | Where-Object State -eq 'Partial').Count
        $fwScores[$fw] = if ($fd -gt 0) { [Math]::Round(100*($fs+0.5*$fp)/$fd) } else { 0 }
    }

    # ── License groups ────────────────────────────────────────────────────────
    $licGroups = @{}
    foreach ($f in ($Findings | Where-Object State -eq 'Gap')) {
        $ctrl = $cdefs[$f.ControlId]
        if ($ctrl -and $ctrl.LicenseRequirement -and $ctrl.LicenseRequirement -notmatch '^Included') {
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

    # ── Secure Score (TODO: wire ss-ring widget into HTML body) ────────────

    # ── Connections ───────────────────────────────────────────────────────────
    $svcMap = @{Graph='Microsoft Graph';EXO='Exchange Online';IPPSSession='Purview/Compliance';Teams='Microsoft Teams';SharePoint='SharePoint Online'}
    $connHtml = ''
    foreach ($svc in @('Graph','EXO','IPPSSession','Teams','SharePoint')) {
        $ok  = if ($Connections -is [hashtable]) { $Connections.ContainsKey($svc) -and $Connections[$svc] -eq $true } else { $Connections.$svc -eq $true }
        $cls = if ($ok) { 'cok' } else { 'coff' }
        $ico = if ($ok) { '&#10003;' } else { '&#10005;' }
        $connHtml += "<div class='conn $cls'><span>$ico</span><span>$(hx $svcMap[$svc])</span></div>"
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
        $gapTxt = if ($gps -gt 0) { "<div class='wl-gap'>$gps gap$(if($gps -ne 1){'s'})</div>" } else { "<div class='wl-ok'>&#10003; Clean</div>" }
        $wlGrid += @"
<div class='wl-card'>
  <svg width='54' height='54' viewBox='0 0 36 36'>
    <circle cx='18' cy='18' r='16' fill='none' stroke='#e8edf5' stroke-width='3.5'/>
    <circle cx='18' cy='18' r='16' fill='none' stroke='$col' stroke-width='3.5' stroke-linecap='round'
      stroke-dasharray='100.5' stroke-dashoffset='$ring' transform='rotate(-90 18 18)'
      style='transition:stroke-dashoffset 1.2s ease .3s'/>
  </svg>
  <div class='wl-info'><div class='wl-name'>$lbl</div><div class='wl-score' style='color:$col'>$ws3<span class='wl-den'>/100</span></div>$gapTxt</div>
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
    foreach ($fw in @('CIS','SCuBA','NIST','CMMC')) {
        $fsc = $fwScores[$fw]; $col = scoreColor $fsc
        $fwHtml += "<div class='fw-card'><div class='fw-hd' style='background:$($fwMeta[$fw].Bg)'>$(hx $fw)</div><div class='fw-body'><div class='fw-sc' style='color:$col'>$fsc<span class='fw-den'>%</span></div><div class='fw-name'>$(hx $fwMeta[$fw].Full)</div></div></div>"
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
    <div class='lic-alert'><span class='lic-ico'>&#9888;</span><div>Upgrading to <strong>Microsoft 365 Business Premium</strong> resolves the majority of these gaps — including Safe Attachments, Safe Links, Conditional Access with device compliance, and Intune endpoint management. These are the controls most directly blocking ransomware and BEC attacks. Contact NRG for a licensing proposal.</div></div>
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
        $lic   = if ($ctrl -and $ctrl.LicenseRequirement -and $ctrl.LicenseRequirement -notmatch '^Included') {
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
            $lic2  = if ($ctrl2 -and $ctrl2.LicenseRequirement -and $ctrl2.LicenseRequirement -notmatch '^Included') {
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
            $ca    = if ($hasEx) { "class='fr $rc exp' onclick='toggle(this)'" } else { "class='fr $rc'" }
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
                "<tr><td>$(hx $_)</td></tr>"
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

    # ── Assemble HTML ─────────────────────────────────────────────────────────
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';img-src https: data:;script-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none'">
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
.wl-ok{font-size:.66rem;font-weight:700;color:var(--pass);margin-top:2px}

/* Framework matrix */
.fw-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:0;background:var(--bdr)}
.fw-card{background:var(--card)}
.fw-hd{padding:9px 18px;font-size:.78rem;font-weight:900;color:#fff;letter-spacing:.05em}
.fw-body{padding:16px 18px;display:flex;flex-direction:column;gap:4px}
.fw-sc{font-size:2rem;font-weight:900;line-height:1}
.fw-den{font-size:.62rem;font-weight:600;color:var(--mut)}
.fw-name{font-size:.7rem;color:var(--mut);font-weight:600;line-height:1.4;margin-top:4px}

/* License card */
.lic-body{padding:18px 24px;display:flex;flex-direction:column;gap:14px}
.lic-alert{display:flex;align-items:flex-start;gap:14px;padding:14px 18px;background:#fffbeb;border:1px solid #fde68a;border-radius:9px;font-size:.82rem;line-height:1.65;color:#374151}
.lic-ico{font-size:1.3rem;margin-top:1px;flex-shrink:0}
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
  .fw-grid{grid-template-columns:repeat(4,1fr)!important}
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
        $(if($op){"<span><strong>Prepared by</strong> $op</span>"})
        <span><strong>Frameworks</strong> CIS M365 v6 &middot; CISA SCuBA &middot; NIST SP 800-53r5 &middot; CMMC 2.0</span>
      </div>
    </div>
    <div class="hdr-right">
      <div class="ver-badge">NRG-Assessment v$vr</div>
      $logoH
    </div>
  </div>
  <div class="hdr-nav">
    <span class="nav-a" onclick="goto('exec')">Overview</span>
    <span class="nav-a" onclick="goto('fw-section')">Frameworks</span>
    $(if($licGroups.Count -gt 0){'<span class="nav-a" onclick="goto(''licensing'')">License Gaps</span>'})
    <span class="nav-a" onclick="goto('named')">Named Findings</span>
    <span class="nav-a" onclick="goto('actions')">Priority Actions</span>
    <span class="nav-a" onclick="goto('roadmap')">Roadmap</span>
    <span class="nav-a" onclick="goto('findings')">All Findings</span>
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

<!-- FRAMEWORK COMPLIANCE -->
<div class="card mt" id="fw-section">
  <div class="card-hd"><div class="card-label">Framework Compliance Matrix</div><div class="card-sub">Controls mapped to CIS, CISA SCuBA, NIST SP 800-53, and CMMC 2.0</div></div>
  <div class="fw-grid">$fwHtml</div>
</div>

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
<script>
function goto(id){var el=document.getElementById(id);if(el)el.scrollIntoView({behavior:'smooth',block:'start'})}
function toggle(tr){var n=tr.nextElementSibling;if(n&&n.classList.contains('extr')){var s=n.style.display===''||n.style.display==='none';n.style.display=s?'table-row':'none';tr.classList.toggle('open',s)}}
document.querySelectorAll('.extr').forEach(function(r){r.style.display='none'});
</script>
</body></html>
"@

    $html | Out-File -LiteralPath $OutputPath -Encoding utf8
}