#
# Publish-NRGAssessmentHTML.ps1
# Client-deliverable HTML report — print-to-PDF ready, self-contained.
#
# Philosophy: A report is only useful if the client can act on it.
# Every gap shows three things:
#   WHAT  — the issue in plain language
#   WHY   — the business risk if not fixed (from controls.json BusinessRisk)
#   HOW   — specific steps to remediate with effort estimate and portal link
#
# Sections:
#   1. Executive Dashboard (score ring, category scores, narrative summary)
#   2. Priority Actions (top critical/high gaps with business impact + fix)
#   3. Findings by Category (What/Why/How expanded per finding)
#   4. Remediation Roadmap (grouped by effort — project plan)
#   5. Identity Inventory (users, MFA, admin roles, PIM)
#   6. Configuration Inventory (DNS, EXO, CA Policies, Defender)
#
# Author: Matthew Levorson, NRG Technology Services
#

function Publish-NRGAssessmentHTML {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]  $Metadata,
        [Parameter(Mandatory)] [object[]]   $Findings,
        [Parameter(Mandatory)] $Connections,
        [Parameter(Mandatory)] [string]     $OutputPath,
        [string] $ClientName = ''
    )

    $brand     = $Metadata.Brand
    $primary   = if ($brand.PrimaryColor)   { $brand.PrimaryColor }   else { '#1a3a6b' }
    $secondary = if ($brand.SecondaryColor) { $brand.SecondaryColor } else { '#e87722' }
    $accent    = if ($brand.AccentColor)    { $brand.AccentColor }    else { '#4a7ba6' }
    $company   = if ($brand.CompanyName)    { $brand.CompanyName }    else { 'NRG Technology Services' }
    $phone     = if ($brand.Phone)          { $brand.Phone }          else { '' }
    $website   = if ($brand.Website)        { $brand.Website }        else { '' }
    $logoUrl   = if ($brand.LogoUrl)        { $brand.LogoUrl }        else { '' }
    $clientDisplay = if ($ClientName) { $ClientName } else { $Metadata.TenantDomain }

    function hx { param([string]$s) if (-not $s) { return '' }; $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' }

    function sBadge { param([string]$s)
        switch ($s) {
            'Satisfied'     { '<span class="b bp">&#10003; Pass</span>' }
            'Partial'       { '<span class="b bw">&#9679; Partial</span>' }
            'Gap'           { '<span class="b bg">&#10005; Gap</span>' }
            'NotApplicable' { '<span class="b bn">&#8212; N/A</span>' }
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

    $ttpMap = @{
        'AAD-1.1'='T1078,T1110.003';'AAD-1.2'='T1111,T1621';'AAD-2.1'='T1078,T1110'
        'AAD-2.2'='T1078,T1110';'AAD-2.3'='T1621';'AAD-3.1'='T1078,T1110'
        'AAD-3.2'='T1078,T1110.001';'AAD-4.1'='T1078.004';'AAD-4.2'='T1078.002'
        'AAD-4.3'='T1078.004';'EXO-1.1'='T1114,T1114.002';'EXO-1.2'='T1078,T1114'
        'EXO-2.1'='T1566.001';'EXO-2.2'='T1114,T1078';'EXO-2.3'='T1114,T1078'
        'EXO-2.4'='T1213';'EXO-2.5'='T1078';'EXO-3.1'='T1078'
        'DEF-1.1'='T1566.001';'DEF-1.2'='T1566.001,T1204.002';'DEF-1.3'='T1566.002,T1189'
        'DNS-1.1'='T1566.001';'DNS-1.2'='T1566.001';'DNS-2.1'='T1557'
        'DNS-2.2'='T1557';'DNS-2.3'='T1557,T1584.002'
    }

    # Scoring
    $sat   = @($Findings | Where-Object State -eq 'Satisfied').Count
    $part  = @($Findings | Where-Object State -eq 'Partial').Count
    $gap   = @($Findings | Where-Object State -eq 'Gap').Count
    $na    = @($Findings | Where-Object State -eq 'NotApplicable').Count
    $total = $Findings.Count
    $scrd  = $total - $na
    $score = if ($scrd -gt 0) { [Math]::Round(100 * ($sat + 0.5 * $part) / $scrd) } else { 0 }
    $pLabel = if ($score -ge 85) { 'Strong' } elseif ($score -ge 65) { 'Moderate' } elseif ($score -ge 40) { 'Weak' } else { 'Critical Risk' }
    $pColor = if ($score -ge 85) { '#059669' } elseif ($score -ge 65) { '#d97706' } elseif ($score -ge 40) { '#ea580c' } else { '#dc2626' }
    $circ   = 452.4
    $offset = [Math]::Round($circ * (1 - $score / 100), 2)

    $critCount = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -eq 'Critical' }).Count
    $highCount = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -eq 'High' }).Count
    $narrativeSentence = if ($critCount -gt 0) {
        "This assessment identified <strong>$critCount critical</strong> and <strong>$highCount high-severity</strong> gaps requiring immediate attention."
    } elseif ($highCount -gt 0) {
        "No critical gaps identified. This assessment found <strong>$highCount high-severity</strong> gaps to address in the near term."
    } elseif ($gap -gt 0) {
        "No critical or high-severity gaps identified. There are <strong>$gap medium or low-severity</strong> gaps to work through."
    } else { "No gaps identified. The environment meets all assessed controls." }

    # Category scores
    $cScores = @{}
    $Findings | Group-Object Category | ForEach-Object {
        $cS = @($_.Group | Where-Object State -eq 'Satisfied').Count
        $cP = @($_.Group | Where-Object State -eq 'Partial').Count
        $cN = @($_.Group | Where-Object State -eq 'NotApplicable').Count
        $cD = $_.Group.Count - $cN
        $cScores[$_.Name] = if ($cD -gt 0) { [Math]::Round(100 * ($cS + 0.5 * $cP) / $cD) } else { 0 }
    }
    function catBar { param([string]$label,[string]$key)
        $s = if ($cScores.ContainsKey($key)) { $cScores[$key] } else { return '' }
        $c = if ($s -ge 85) { '#059669' } elseif ($s -ge 65) { '#d97706' } elseif ($s -ge 40) { '#ea580c' } else { '#dc2626' }
        "<div class=`"cbar`"><div class=`"cbar-hd`"><span class=`"cbar-lbl`">$label</span><span class=`"cbar-num`" style=`"color:$c`">$s</span></div><div class=`"cbar-track`"><div class=`"cbar-fill`" style=`"width:${s}%;background:$c`"></div></div></div>"
    }
    $wGap  = if ($scrd -gt 0) { [Math]::Round(100 * $gap  / $scrd) } else { 0 }
    $wPart = if ($scrd -gt 0) { [Math]::Round(100 * $part / $scrd) } else { 0 }
    $wSat  = if ($scrd -gt 0) { [Math]::Round(100 * $sat  / $scrd) } else { 0 }
    $wNA   = if ($total -gt 0) { [Math]::Round(100 * $na  / $total) } else { 0 }

    $allCatBars = ''
    foreach ($cn in ($cScores.Keys | Sort-Object)) { $allCatBars += catBar $cn $cn }

    # Connections
    $connHtml = ''
    $svcLabels = @{ Graph='Microsoft Graph'; EXO='Exchange Online'; IPPSSession='Purview / Compliance'; Teams='Microsoft Teams'; SharePoint='SharePoint Online' }
    foreach ($svc in @('Graph','EXO','IPPSSession','Teams','SharePoint')) {
        $ok  = if ($Connections -is [hashtable]) { $Connections.ContainsKey($svc) -and $Connections[$svc] -eq $true } else { $Connections.$svc -eq $true }
        $cls = if ($ok) { 'cok' } else { 'coff' }
        $ico = if ($ok) { '&#10003;' } else { '&#10005;' }
        $lbl = if ($svcLabels.ContainsKey($svc)) { $svcLabels[$svc] } else { $svc }
        $connHtml += "<div class=`"conn $cls`"><span>$ico</span><span>$lbl</span></div>"
    }

    # Priority actions
    $topGaps  = @($Findings | Where-Object { $_.State -eq 'Gap' -and $_.Severity -in @('Critical','High') } |
                  Sort-Object @{Expression={ switch ($_.Severity) { 'Critical' { 0 }; 'High' { 1 }; default { 2 } } }} | Select-Object -First 5)
    $actsHtml = ''
    $n = 1
    foreach ($g in $topGaps) {
        $ctrl   = Get-NRGControlById -ControlId $g.ControlId
        $bRisk  = if ($ctrl -and $ctrl.BusinessRisk) { hx $ctrl.BusinessRisk } else { hx $g.Detail }
        $rem    = hx $g.Remediation
        $cls    = if ($g.Severity -eq 'Critical') { 'ac' } else { 'ah' }
        $svCls  = if ($g.Severity -eq 'Critical') { 'svc' } else { 'svh' }
        $effort = if ($ctrl -and $ctrl.EffortLevel) { hx $ctrl.EffortLevel } else { '' }
        $riskDiv = if ($bRisk) { "<div class=`"act-risk`"><span class=`"act-risk-lbl`">Why it matters</span>$bRisk</div>" } else { '' }
        $remDiv  = if ($rem)   { "<div class=`"act-rem`"><span class=`"act-rem-lbl`">How to fix it</span>$rem</div>" } else { '' }
        $efSpan  = if ($effort) { "<span class=`"act-effort`">$effort</span>" } else { '' }
        $actsHtml += "<div class=`"act $cls`"><div class=`"act-num`"><span class=`"act-n`">$n</span><span class=`"sv $svCls`" style=`"margin-top:4px`">$($g.Severity)</span>$efSpan</div><div class=`"act-body`"><div class=`"act-t`">$(hx $g.Title)</div>$riskDiv$remDiv</div></div>"
        $n++
    }

    # Findings
    $findHtml = ''
    foreach ($cat in ($Findings | Group-Object Category | Sort-Object Name)) {
        $rows = ''
        foreach ($f in ($cat.Group | Sort-Object @{Expression={ switch ($_.State) { 'Gap' { 0 }; 'Partial' { 1 }; 'Satisfied' { 2 }; 'NotApplicable' { 3 } } }}, @{Expression='Title'})) {
            $rc    = switch ($f.State) { 'Gap' { 'rg' }; 'Partial' { 'rw' }; 'Satisfied' { 'rp' }; 'NotApplicable' { 'rn' } }
            $t     = hx $f.Title
            $d     = hx $f.Detail
            $rem   = hx $f.Remediation
            $rl    = hx $f.RemediationLink
            $cv    = hx $f.CurrentValue
            $rv    = hx $f.RequiredValue
            $ctrl  = Get-NRGControlById -ControlId $f.ControlId
            $bRisk = if ($ctrl -and $ctrl.BusinessRisk) { hx $ctrl.BusinessRisk } else { '' }
            $effort = if ($ctrl -and $ctrl.EffortLevel) { hx $ctrl.EffortLevel } else { '' }
            $ttpList = if ($ttpMap.ContainsKey($f.ControlId)) { ($ttpMap[$f.ControlId] -split ',') } else { @() }

            $exHtml = ''
            if ($f.State -in @('Gap','Partial') -and ($d -or $bRisk -or $rem)) {
                $whatBlock = ''
                if ($d) {
                    $cvLine = ''
                    if ($cv -and $rv) { $cvLine = "<div class=`"ex-cv`"><span class=`"ex-cvl`">Current:</span> $cv &rarr; <span class=`"ex-cvl`">Required:</span> $rv</div>" }
                    elseif ($cv)      { $cvLine = "<div class=`"ex-cv`"><span class=`"ex-cvl`">Current:</span> $cv</div>" }
                    $whatBlock = "<div class=`"ex-block`"><div class=`"ex-block-lbl what-lbl`">What the issue is</div><div class=`"ex-block-body`">$d$cvLine</div></div>"
                }
                $whyBlock = ''
                if ($bRisk) { $whyBlock = "<div class=`"ex-block`"><div class=`"ex-block-lbl why-lbl`">Why it matters</div><div class=`"ex-block-body`">$bRisk</div></div>" }
                $howBlock = ''
                if ($rem) {
                    $lnk = if ($rl) { " <a href=`"$rl`" target=`"_blank`" class=`"ex-lnk`">&#8599; Open portal</a>" } else { '' }
                    $efSpan2 = if ($effort) { "<span class=`"effort-tag`">$effort</span>" } else { '' }
                    $ttpHtml = ''
                    if ($ttpList.Count -gt 0) {
                        $ttpTags = ($ttpList | ForEach-Object { $t2=$_.Trim(); "<a href=`"https://attack.mitre.org/techniques/$($t2 -replace '\.','/') `" target=`"_blank`" class=`"ttp-tag`">$t2</a>" }) -join ''
                        $ttpHtml = "<div class=`"ex-ttp`">$ttpTags</div>"
                    }
                    $fwHtml = ''
                    if ($f.FrameworkIds -and $f.FrameworkIds.Count -gt 0) {
                        $fwTags = ($f.FrameworkIds | ForEach-Object { "<span class=`"fw-tag`">$(hx $_)</span>" }) -join ''
                        $fwHtml = "<div class=`"ex-fw`">$fwTags</div>"
                    }
                    $howBlock = "<div class=`"ex-block`"><div class=`"ex-block-lbl how-lbl`">How to fix it</div><div class=`"ex-block-body`">$rem$lnk $efSpan2$ttpHtml$fwHtml</div></div>"
                }
                $exHtml = "<tr class=`"extr`"><td colspan=`"3`"><div class=`"exbody`">$whatBlock$whyBlock$howBlock</div></td></tr>"
            }

            $hasEx     = $exHtml -ne ''
            $clickAttr = if ($hasEx) { "class=`"fr $rc exp`" onclick=`"toggle(this)`"" } else { "class=`"fr $rc`"" }
            $cvHint    = if ($cv -and $f.State -in @('Gap','Partial')) { $short = if ($cv.Length -gt 65) { $cv.Substring(0,62)+'...' } else { $cv }; "<div class=`"f-cv`">$short</div>" } else { '' }
            $dPreview  = if ($d -and $f.State -in @('Gap','Partial')) { if ($d.Length -gt 100) { $d.Substring(0,97)+'...' } else { $d } } elseif ($f.State -eq 'Satisfied' -and $cv) { $cv } else { '' }
            $moreIco   = if ($hasEx) { '<span class="more-ico">&#9654;</span>' } else { '' }

            $rows += "<tr $clickAttr><td class=`"td1`">$(sBadge $f.State)$(svBadge $f.Severity)</td><td class=`"td3`"><div class=`"f-title`">$t $moreIco</div>$cvHint</td><td class=`"td4`">$dPreview</td></tr>$exHtml"
        }

        $cKey    = $cat.Name
        $cScore  = if ($cScores.ContainsKey($cKey)) { $cScores[$cKey] } else { 0 }
        $cColor  = if ($cScore -ge 85) { '#059669' } elseif ($cScore -ge 65) { '#d97706' } elseif ($cScore -ge 40) { '#ea580c' } else { '#dc2626' }
        $cg      = @($cat.Group | Where-Object State -eq 'Gap').Count
        $cp2     = @($cat.Group | Where-Object State -eq 'Partial').Count
        $cSummary = ''
        $parts2 = @()
        if ($cg  -gt 0) { $parts2 += "<span style=`"color:var(--gap);font-weight:700`">$cg gap$(if($cg -gt 1){'s'})</span>" }
        if ($cp2 -gt 0) { $parts2 += "<span style=`"color:var(--warn);font-weight:700`">$cp2 partial$(if($cp2 -gt 1){'s'})</span>" }
        if ($parts2.Count -gt 0) { $cSummary = " &nbsp;&mdash;&nbsp; " + ($parts2 -join ', ') }

        $findHtml += "<div class=`"card mt`"><div class=`"card-hd`"><span><span class=`"card-title`">$(hx $cKey)</span>$cSummary</span><span class=`"cat-pill`" style=`"background:${cColor}18;color:$cColor;border-color:${cColor}3a`">$cScore / 100</span></div><table class=`"ft`"><thead><tr class=`"fth`"><th style=`"width:142px`">Status</th><th>Control</th><th>Summary</th></tr></thead><tbody>$rows</tbody></table></div>"
    }

    # Roadmap
    $roadmapHtml = ''
    $actionable  = @($Findings | Where-Object { $_.State -in @('Gap','Partial') -and $_.Remediation })
    if ($actionable.Count -gt 0) {
        $groups = [ordered]@{ 'Quick Win (< 30 min)'=@(); 'Standard (1-4 hrs)'=@(); 'Strategic (planning required)'=@() }
        foreach ($f in ($actionable | Sort-Object @{Expression={ switch ($_.Severity) { 'Critical' { 0 }; 'High' { 1 }; 'Medium' { 2 }; default { 3 } } }})) {
            $ctrl2  = Get-NRGControlById -ControlId $f.ControlId
            $effort = if ($ctrl2 -and $ctrl2.EffortLevel) { $ctrl2.EffortLevel } else { 'Standard (1-4 hrs)' }
            if ($groups.Contains($effort)) { $groups[$effort] += $f } else { $groups['Standard (1-4 hrs)'] += $f }
        }
        $rmRows = ''
        foreach ($grpKey in $groups.Keys) {
            $items  = $groups[$grpKey]
            if ($items.Count -eq 0) { continue }
            $efCls  = switch -Wildcard ($grpKey) { '*30 min*' { 'efq' }; '*1-4*' { 'efs' }; default { 'efx' } }
            $efIco  = switch -Wildcard ($grpKey) { '*30 min*' { '&#9889;' }; '*1-4*' { '&#9200;' }; default { '&#9881;' } }
            $rmRows += "<div class=`"rmg`"><div class=`"rmgl $efCls`">$efIco $(hx $grpKey) <span class=`"rm-cnt`">($($items.Count) item$(if($items.Count -gt 1){'s'}))</span></div>"
            foreach ($f in $items) {
                $ctrl3  = Get-NRGControlById -ControlId $f.ControlId
                $bRisk3 = if ($ctrl3 -and $ctrl3.BusinessRisk) { hx $ctrl3.BusinessRisk } else { hx $f.Detail }
                $rc3    = if ($f.State -eq 'Gap') { 'rmg-gap' } else { 'rmg-warn' }
                $lnk3   = if ($f.RemediationLink) { " <a href=`"$(hx $f.RemediationLink)`" target=`"_blank`" class=`"ex-lnk`">&#8599; Portal</a>" } else { '' }
                $whyDiv3 = if ($bRisk3) { "<div class=`"rmi-why`">$bRisk3</div>" } else { '' }
                $rmRows  += "<div class=`"rmi $rc3`"><div class=`"rmi-hd`">$(svBadge $f.Severity) <span class=`"rmi-t`">$(hx $f.Title)</span></div>$whyDiv3<div class=`"rmi-r`">$(hx $f.Remediation)$lnk3</div></div>"
            }
            $rmRows += "</div>"
        }
        $roadmapHtml = "<div class=`"card mt`"><div class=`"card-hd`"><span class=`"card-title`">Remediation Roadmap</span><span style=`"font-size:.72rem;color:var(--mut)`">Sorted by effort, then severity</span></div><div class=`"rm-wrap`">$rmRows</div></div>"
    }

    # Identity
    $identityHtml = ''
    $userRaw  = Get-NRGRawData -Key 'AAD-Users'
    $rolesRaw = Get-NRGRawData -Key 'AAD-Roles'
    $pimRaw   = Get-NRGRawData -Key 'AAD-PIM'
    if ($userRaw -and $userRaw.Success) {
        $allUsers       = @($userRaw.Data['Users'])
        $mfaReg         = @($userRaw.Data['MFARegistration'])
        $memberUsers    = @($allUsers | Where-Object { $_.UserType -ne 'Guest' })
        $enabledMembers = @($memberUsers | Where-Object { $_.AccountEnabled -eq $true })
        $guestUsers     = @($allUsers | Where-Object { $_.UserType -eq 'Guest' })
        $licensedUsers  = @($allUsers | Where-Object { $_.AssignedLicenses -and $_.AssignedLicenses.Count -gt 0 })
        $syncedUsers    = @($allUsers | Where-Object { $_.OnPremisesSyncEnabled -eq $true })
        $enabledUPNs    = @($enabledMembers | Select-Object -ExpandProperty UserPrincipalName)
        $mfaFiltered    = @($mfaReg | Where-Object { $_.UserPrincipalName -in $enabledUPNs -or $_.Id -in $enabledUPNs })
        if ($mfaFiltered.Count -eq 0) { $mfaFiltered = @($mfaReg) }
        $mfaRegistered  = @($mfaFiltered | Where-Object { $_.IsMfaRegistered -eq $true }).Count
        $mfaTotal       = $mfaFiltered.Count; if ($mfaTotal -eq 0) { $mfaTotal = $enabledMembers.Count }
        $mfaPct         = if ($mfaTotal -gt 0) { [Math]::Round(100 * $mfaRegistered / $mfaTotal) } else { 0 }
        $mfaColor       = if ($mfaPct -ge 95) { '#059669' } elseif ($mfaPct -ge 80) { '#d97706' } else { '#dc2626' }
        $mfaNotReg      = $mfaTotal - $mfaRegistered
        $mfaNote        = if ($mfaPct -lt 95) { "<br><span style=`"color:#dc2626;font-weight:700`">$mfaNotReg user$(if($mfaNotReg -gt 1){'s'}) without MFA registered.</span> Do not enforce an MFA Conditional Access policy until registration reaches 95%+ &mdash; it will lock out unregistered users." } else { '' }

        $statCardsHtml = "<div class=`"user-stats`"><div class=`"ustat`"><div class=`"ustat-n`">$($allUsers.Count)</div><div class=`"ustat-l`">Total Accounts</div></div><div class=`"ustat`"><div class=`"ustat-n`">$($enabledMembers.Count)</div><div class=`"ustat-l`">Enabled Members</div></div><div class=`"ustat`"><div class=`"ustat-n`">$($guestUsers.Count)</div><div class=`"ustat-l`">Guest Users</div></div><div class=`"ustat`"><div class=`"ustat-n`">$($licensedUsers.Count)</div><div class=`"ustat-l`">Licensed Users</div></div><div class=`"ustat`"><div class=`"ustat-n`">$($syncedUsers.Count)</div><div class=`"ustat-l`">On-prem Synced</div></div></div>"
        $mfaBarHtml     = "<div class=`"mfa-section`"><div class=`"mfa-header`"><span class=`"mfa-title`">MFA Registration</span><span class=`"mfa-pct`" style=`"color:$mfaColor`">$mfaPct%</span></div><div class=`"mfa-track`"><div class=`"mfa-fill`" style=`"width:${mfaPct}%;background:$mfaColor`"></div></div><div class=`"mfa-detail`">$mfaRegistered of $mfaTotal enabled member accounts have MFA registered.$mfaNote</div></div>"

        $adminRowsHtml = ''
        if ($rolesRaw -and $rolesRaw.Success) {
            $assignments = @($rolesRaw.Data['PermanentAssignments'])
            $defs        = @($rolesRaw.Data['RoleDefinitions'])
            $roleNameMap = @{}
            foreach ($def in $defs) { if ($def.Id) { $roleNameMap[$def.Id] = $def.DisplayName } }
            $privRoles = @('Global Administrator','Privileged Role Administrator','Exchange Administrator','Security Administrator','Compliance Administrator','User Administrator','SharePoint Administrator','Teams Service Administrator','Billing Administrator','Application Administrator','Hybrid Identity Administrator')
            $adminAssignments = @($assignments | Where-Object { $_.RoleDefinitionId -and $roleNameMap.ContainsKey($_.RoleDefinitionId) -and $roleNameMap[$_.RoleDefinitionId] -in $privRoles })
            foreach ($a in $adminAssignments) {
                $roleName    = if ($roleNameMap.ContainsKey($a.RoleDefinitionId)) { $roleNameMap[$a.RoleDefinitionId] } else { 'Unknown' }
                $user        = $allUsers | Where-Object { $_.Id -eq $a.PrincipalId } | Select-Object -First 1
                $displayName = if ($user -and $user.DisplayName) { hx $user.DisplayName } else { hx $a.PrincipalId }
                $upn         = if ($user -and $user.UserPrincipalName) { hx $user.UserPrincipalName } else { '&mdash;' }
                $licVal      = if ($user -and $user.AssignedLicenses -and $user.AssignedLicenses.Count -gt 0) { '<span class="iwarn">&#9888; Licensed</span>' } else { '<span class="igood">&#10003; Unlicensed</span>' }
                $syncVal     = if ($user -and $user.OnPremisesSyncEnabled -eq $true) { '<span class="ibad">&#9650; Synced</span>' } else { '<span class="igood">&#9729; Cloud-only</span>' }
                $enVal       = if ($user -and $user.AccountEnabled -eq $true) { '<span class="igood">Enabled</span>' } else { '<span class="ioff">Disabled</span>' }
                $lastSignIn  = '&mdash;'
                if ($user -and $user.SignInActivity -and $user.SignInActivity.LastSignInDateTime) {
                    try { $lastSignIn = ([datetime]$user.SignInActivity.LastSignInDateTime).ToString('yyyy-MM-dd') } catch {}
                }
                $rowClass = if ($roleName -eq 'Global Administrator') { 'adm-ga' } else { '' }
                $adminRowsHtml += "<tr class=`"$rowClass`"><td><span class=`"role-tag`">$(hx $roleName)</span></td><td class=`"adm-name`">$displayName</td><td class=`"adm-upn`">$upn</td><td>$licVal</td><td>$syncVal</td><td>$enVal</td><td class=`"adm-last`">$lastSignIn</td></tr>"
            }
        }
        $adminTableHtml = ''
        if ($adminRowsHtml) { $adminTableHtml = "<div class=`"subsec-title`">Privileged Role Assignments</div><div class=`"tscroll`"><table class=`"itbl adm-tbl`"><thead><tr><th>Role</th><th>Name</th><th>Username</th><th>Licensed</th><th>Account Type</th><th>Status</th><th>Last Sign-in</th></tr></thead><tbody>$adminRowsHtml</tbody></table></div>" }

        $pimHtml = ''
        if ($pimRaw -and $pimRaw.Success) {
            $eligible   = @($pimRaw.Data['EligibleSchedules'])
            $active     = @($pimRaw.Data['ActiveSchedules'])
            $pimColor   = if ($eligible.Count -gt 0) { '#059669' } else { '#dc2626' }
            $gaRoleId   = $null
            if ($rolesRaw -and $rolesRaw.Success) { $gaDef = @($rolesRaw.Data['RoleDefinitions']) | Where-Object { $_.DisplayName -eq 'Global Administrator' } | Select-Object -First 1; if ($gaDef) { $gaRoleId = $gaDef.Id } }
            $gaEligible = if ($gaRoleId) { @($eligible | Where-Object { $_.RoleDefinitionId -eq $gaRoleId }).Count } else { 0 }
            $gaActive   = if ($gaRoleId) { @($active   | Where-Object { $_.RoleDefinitionId -eq $gaRoleId }).Count } else { 0 }
            $pimHtml    = "<div class=`"subsec-title`">Privileged Identity Management (PIM)</div><div class=`"pim-grid`"><div class=`"pim-card`"><div class=`"pim-n`" style=`"color:$pimColor`">$($eligible.Count)</div><div class=`"pim-l`">Eligible (just-in-time)</div></div><div class=`"pim-card`"><div class=`"pim-n`" style=`"color:$(if($active.Count -gt 0){'#d97706'}else{'#059669'})`">$($active.Count)</div><div class=`"pim-l`">Permanent assignments</div></div><div class=`"pim-card`"><div class=`"pim-n`" style=`"color:$(if($gaEligible -gt 0){'#059669'}else{'#dc2626'})`">$gaEligible</div><div class=`"pim-l`">Global Admin via JIT</div></div><div class=`"pim-card`"><div class=`"pim-n`" style=`"color:$(if($gaActive -gt 2){'#dc2626'}elseif($gaActive -gt 0){'#d97706'}else{'#059669'})`">$gaActive</div><div class=`"pim-l`">Global Admin permanent</div></div></div>"
        }
        $identityHtml = "<div class=`"card mt`"><div class=`"card-hd`"><span class=`"card-title`">Identity Inventory</span></div><div class=`"inv-body`">$statCardsHtml$mfaBarHtml$adminTableHtml$pimHtml</div></div>"
    }

    # DNS
    $dnsInvHtml = ''
    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    if ($dnsData -and $dnsData.Success -and $dnsData.Data.Domains) {
        $dRows = ''
        foreach ($domain in ($dnsData.Data.Domains.Keys | Sort-Object)) {
            $d4   = $dnsData.Data.Domains[$domain]
            $spf  = if (-not $d4.SPF) { '<span class="ibad">&#10005; None</span>' } elseif ($d4.SPF -match '\-all') { '<span class="igood">&#10003; -all</span>' } elseif ($d4.SPF -match '~all') { '<span class="iwarn">&#9888; ~all</span>' } else { '<span class="iwarn">&#9888;</span>' }
            $dkim = if ($d4.DKIM.Selector1 -and $d4.DKIM.Selector2) { '<span class="igood">&#10003; Both</span>' } elseif ($d4.DKIM.Selector1 -or $d4.DKIM.Selector2) { '<span class="iwarn">&#9888; Partial</span>' } else { '<span class="ibad">&#10005;</span>' }
            $dmarc = if (-not $d4.DMARC) { '<span class="ibad">&#10005; None</span>' } elseif ($d4.DMARC -match 'p=reject') { '<span class="igood">&#10003; reject</span>' } elseif ($d4.DMARC -match 'p=quarantine') { '<span class="iwarn">&#9888; quarantine</span>' } else { '<span class="ibad">&#9888; none</span>' }
            $mtaM  = if ($d4.MTASTS -and $d4.MTASTS.Mode) { $d4.MTASTS.Mode } elseif ($d4.MTASTS -and $d4.MTASTS.TxtRecord) { 'present' } else { $null }
            $mta   = if ($mtaM -eq 'enforce') { '<span class="igood">&#10003; enforce</span>' } elseif ($mtaM -eq 'testing') { '<span class="iwarn">&#9888; testing</span>' } elseif ($mtaM) { "<span class=`"iwarn`">$mtaM</span>" } else { '<span class="ibad">&#10005;</span>' }
            $tls   = if ($d4.TLSRPT) { '<span class="igood">&#10003;</span>' } else { '<span class="ibad">&#10005;</span>' }
            $dsec  = if ($d4.DNSSEC) { '<span class="igood">&#10003;</span>' } else { '<span class="ibad">&#10005;</span>' }
            $dmarcTxt = if ($d4.DMARC) { $tt = if ($d4.DMARC.Length -gt 52) { $d4.DMARC.Substring(0,49)+'...' } else { $d4.DMARC }; "<code class=`"icode`">$(hx $tt)</code>" } else { '&mdash;' }
            $dRows += "<tr><td><strong>$(hx $domain)</strong></td><td>$spf</td><td>$dkim</td><td>$dmarc</td><td>$dmarcTxt</td><td>$mta</td><td>$tls</td><td>$dsec</td></tr>"
        }
        $dnsInvHtml = "<div class=`"card mt`"><div class=`"card-hd`"><span class=`"card-title`">DNS Email Security</span></div><div class=`"tscroll`"><table class=`"itbl`"><thead><tr><th>Domain</th><th>SPF</th><th>DKIM</th><th>DMARC</th><th>DMARC Record</th><th>MTA-STS</th><th>TLS-RPT</th><th>DNSSEC</th></tr></thead><tbody>$dRows</tbody></table></div></div>"
    }

    # EXO
    $exoInvHtml = ''
    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if ($exoData -and $exoData.Success) {
        $eRows = ''
        $o5=$exoData.Data.OrganizationConfig; $tr5=$exoData.Data.TransportConfig; $pr5=$exoData.Data.MailboxProtocols; $bp5=$exoData.Data.AuditBypass; $sm5=$exoData.Data.SharedMailboxes
        if ($o5) {
            $audV = if ($o5.AuditDisabled -eq $false) { '<span class="igood">&#10003; Enabled</span>' } else { '<span class="ibad">&#10005; Disabled</span>' }
            $lbV  = if ($o5.CustomerLockBoxEnabled -eq $true) { '<span class="igood">&#10003; Enabled</span>' } else { '<span class="ibad">&#10005; Disabled</span>' }
            $maV  = if ($o5.OAuth2ClientProfileEnabled -eq $true) { '<span class="igood">&#10003; Enabled</span>' } elseif ($o5.OAuth2ClientProfileEnabled -eq $false) { '<span class="ibad">&#10005; Disabled</span>' } else { '<span class="iwarn">Unknown</span>' }
            $eRows += "<tr><td>Mailbox Audit</td><td>$audV</td></tr><tr><td>Customer Lockbox</td><td>$lbV</td></tr><tr><td>Modern Authentication</td><td>$maV</td></tr>"
        }
        if ($tr5) { $smtpV = if ($tr5.SmtpClientAuthenticationDisabled -eq $true) { '<span class="igood">&#10003; Disabled</span>' } else { '<span class="ibad">&#10005; Enabled (risk)</span>' }; $eRows += "<tr><td>SMTP Client Authentication</td><td>$smtpV</td></tr>" }
        if ($pr5) {
            $p3V = if ($pr5.PopEnabled -eq 0) { '<span class="igood">&#10003; Disabled on all</span>' } else { "<span class=`"ibad`">&#10005; $($pr5.PopEnabled) enabled</span>" }
            $i4V = if ($pr5.ImapEnabled -eq 0) { '<span class="igood">&#10003; Disabled on all</span>' } else { "<span class=`"ibad`">&#10005; $($pr5.ImapEnabled) enabled</span>" }
            $eRows += "<tr><td>Total Mailboxes</td><td>$($pr5.TotalMailboxes)</td></tr><tr><td>POP3</td><td>$p3V</td></tr><tr><td>IMAP</td><td>$i4V</td></tr><tr><td>ActiveSync</td><td>$($pr5.ActiveSyncEnabled) mailboxes</td></tr>"
        }
        if ($bp5) { $byV = if ($bp5.BypassedCount -eq 0) { '<span class="igood">&#10003; None</span>' } else { "<span class=`"ibad`">&#10005; $($bp5.BypassedCount) bypassed</span>" }; $eRows += "<tr><td>Audit Bypass</td><td>$byV</td></tr>" }
        if ($sm5) { $siV = if ($sm5.SignInEnabled -eq 0) { '<span class="igood">&#10003; All disabled</span>' } else { "<span class=`"ibad`">&#10005; $($sm5.SignInEnabled) with sign-in</span>" }; $eRows += "<tr><td>Shared Mailboxes</td><td>$($sm5.Count) total</td></tr><tr><td>Shared Mailbox Sign-in</td><td>$siV</td></tr>" }
        $exoInvHtml = "<div class=`"card mt`" style=`"max-width:560px`"><div class=`"card-hd`"><span class=`"card-title`">Exchange Online Configuration</span></div><table class=`"itbl i2`"><thead><tr><th>Setting</th><th>Value</th></tr></thead><tbody>$eRows</tbody></table></div>"
    }

    # CA
    $caPolicyHtml = ''
    $caData = Get-NRGRawData -Key 'AAD-CAPolicies'
    if ($caData -and $caData.Success -and $caData.Data.Policies) {
        $caRows = ''
        foreach ($p6 in (@($caData.Data.Policies) | Sort-Object @{Expression={ switch ($_.State) { 'enabled' { 0 }; 'enabledForReportingButNotEnforced' { 1 }; 'disabled' { 2 } } }}, DisplayName)) {
            $stH = switch ($p6.State) { 'enabled' { '<span class="igood">&#10003; Enforced</span>' }; 'enabledForReportingButNotEnforced' { '<span class="iwarn">&#9680; Report-only</span>' }; 'disabled' { '<span class="ioff">&#8212; Disabled</span>' }; default { "<span class=`"iwarn`">$(hx $p6.State)</span>" } }
            $cp6 = @()
            if ($p6.Conditions.Users.IncludeUsers -contains 'All') { $cp6 += 'All users' } elseif ($p6.Conditions.Users.IncludeRoles.Count -gt 0) { $cp6 += "$($p6.Conditions.Users.IncludeRoles.Count) role(s)" }
            if ($p6.Conditions.Applications.IncludeApplications -contains 'All') { $cp6 += 'All cloud apps' }
            if ($p6.Conditions.ClientAppTypes -contains 'other') { $cp6 += 'Legacy auth' }
            if ($p6.Conditions.SignInRiskLevels.Count -gt 0) { $cp6 += "Sign-in risk: $($p6.Conditions.SignInRiskLevels -join '/')" }
            $condStr = if ($cp6.Count -gt 0) { $cp6 -join ' &bull; ' } else { '&mdash;' }
            $gp6 = @()
            if ($p6.GrantControls.BuiltInControls -contains 'mfa') { $gp6 += 'Require MFA' }
            if ($p6.GrantControls.BuiltInControls -contains 'block') { $gp6 += 'Block' }
            if ($p6.GrantControls.BuiltInControls -contains 'compliantDevice') { $gp6 += 'Compliant device' }
            if ($p6.GrantControls.AuthenticationStrength) { $gp6 += "Auth strength: $($p6.GrantControls.AuthenticationStrength.DisplayName)" }
            $grantStr = if ($gp6.Count -gt 0) { hx ($gp6 -join ' + ') } else { '&mdash;' }
            $rowCls = if ($p6.State -eq 'enabledForReportingButNotEnforced') { 'ca-ro' } elseif ($p6.State -eq 'disabled') { 'ca-dis' } else { '' }
            $caRows += "<tr class=`"$rowCls`"><td class=`"ca-n`">$(hx $p6.DisplayName)</td><td>$stH</td><td class=`"ca-c`">$condStr</td><td>$grantStr</td></tr>"
        }
        $caPolicyHtml = "<div class=`"card mt`"><div class=`"card-hd`"><span class=`"card-title`">Conditional Access Policies</span></div><div class=`"tscroll`"><table class=`"itbl`"><thead><tr><th>Policy Name</th><th style=`"width:130px`">State</th><th>Applies To</th><th>Enforcement</th></tr></thead><tbody>$caRows</tbody></table></div></div>"
    }

    # Defender
    $defInvHtml = ''
    $defData = Get-NRGRawData -Key 'Defender'
    if ($defData -and $defData.Success) {
        $dRows7 = ''
        if ($defData.Data['SafeAttachments'].Available) { foreach ($p7 in @($defData.Data['SafeAttachments'].Policies | Where-Object { -not $_.IsDefault })) { $en7 = if ($p7.Enable -eq $true) { '<span class="igood">&#10003; Enabled</span>' } else { '<span class="ioff">Disabled</span>' }; $dRows7 += "<tr><td><strong>$(hx $p7.Name)</strong> <span class=`"isub`">Safe Attachments</span></td><td>$en7</td><td>Action: $(hx $p7.Action)</td></tr>" } }
        if ($defData.Data['SafeLinks'].Available) { foreach ($p7 in @($defData.Data['SafeLinks'].Policies | Where-Object { -not $_.IsDefault })) { $en7 = if ($p7.EnableSafeLinksForEmail -eq $true) { '<span class="igood">&#10003; Enabled</span>' } else { '<span class="ioff">Disabled</span>' }; $ct7 = if ($p7.AllowClickThrough -eq $false) { '<span class="igood">Click-through blocked</span>' } else { '<span class="iwarn">Click-through allowed</span>' }; $dRows7 += "<tr><td><strong>$(hx $p7.Name)</strong> <span class=`"isub`">Safe Links</span></td><td>$en7</td><td>$ct7</td></tr>" } }
        if ($defData.Data['AntiPhishing'].Available) { foreach ($p7 in @($defData.Data['AntiPhishing'].Policies | Where-Object { -not $_.IsDefault })) { $en7 = if ($p7.Enabled) { '<span class="igood">&#10003; Enabled</span>' } else { '<span class="ioff">Disabled</span>' }; $mi7 = if ($p7.EnableMailboxIntelligence) { '<span class="igood">&#10003;</span>' } else { '<span class="ibad">&#10005;</span>' }; $dRows7 += "<tr><td><strong>$(hx $p7.Name)</strong> <span class=`"isub`">Anti-Phishing</span></td><td>$en7</td><td>Mailbox intel: $mi7 &nbsp; Threshold: $($p7.PhishThresholdLevel)</td></tr>" } }
        if ($dRows7) { $defInvHtml = "<div class=`"card mt`"><div class=`"card-hd`"><span class=`"card-title`">Defender for Office 365</span></div><table class=`"itbl`"><thead><tr><th>Policy</th><th style=`"width:110px`">Status</th><th>Configuration</th></tr></thead><tbody>$dRows7</tbody></table></div>" }
    }

    $tDom   = hx $Metadata.TenantDomain
    $cDisp  = hx $clientDisplay
    $dStr   = hx $Metadata.AssessmentDate
    $opStr  = hx $Metadata.Operator
    $cmpStr = hx $company
    $phStr  = hx $phone
    $wsStr  = hx $website
    $ver    = hx $Metadata.ToolVersion
    $logoH  = if ($logoUrl) { "<img src=`"$(hx $logoUrl)`" alt=`"$cmpStr`" class=`"logo`">" } else { "<span class=`"logo-t`">$cmpStr</span>" }

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>M365 Security Assessment &mdash; $cDisp</title>
<style>
:root{--P:$primary;--S:$secondary;--A:$accent;--bg:#edf0f6;--card:#fff;--txt:#18202e;--mut:#5a6478;--bdr:#dde3ec;--pass:#059669;--warn:#d97706;--gap:#dc2626;--na:#9ca3af;--r:10px;--sh:0 2px 14px rgba(26,58,107,.1),0 1px 3px rgba(0,0,0,.05)}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:15px;scroll-behavior:smooth}
body{font-family:'Segoe UI Variable Display','Segoe UI','Helvetica Neue',system-ui,sans-serif;background:var(--bg);color:var(--txt);line-height:1.65;-webkit-font-smoothing:antialiased}
a{color:var(--A);text-decoration:none}a:hover{text-decoration:underline}
.wrap{max-width:1160px;margin:0 auto}
.hdr{background:linear-gradient(135deg,var(--P) 0%,#0d2147 100%);color:#fff;padding:36px 48px 30px;position:relative;overflow:hidden}
.hdr::before{content:'';position:absolute;inset:0;background-image:radial-gradient(circle at 75% 20%,rgba(232,119,34,.14) 0%,transparent 50%),radial-gradient(circle at 25% 80%,rgba(74,123,166,.1) 0%,transparent 50%);pointer-events:none}
.hdr-inner{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;position:relative;z-index:1}
.logo{height:34px;filter:brightness(0) invert(1)}.logo-t{font-size:1.15rem;font-weight:800;letter-spacing:-.02em;color:rgba(255,255,255,.95)}
.hdr-eye{font-size:.62rem;text-transform:uppercase;letter-spacing:.15em;color:var(--S);font-weight:700;margin-bottom:7px}
.hdr-client{font-size:2rem;font-weight:900;letter-spacing:-.03em;color:#fff;line-height:1.05}
.hdr-meta{display:flex;gap:18px;flex-wrap:wrap;margin-top:10px;font-size:.77rem;color:rgba(255,255,255,.5)}
.hdr-meta strong{color:rgba(255,255,255,.82);font-weight:600}
.hdr-right{text-align:right;flex-shrink:0}
.ver{font-size:.62rem;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.18);padding:3px 9px;border-radius:20px;color:rgba(255,255,255,.6);letter-spacing:.05em;display:inline-block;margin-bottom:10px}
.abar{height:3px;background:linear-gradient(90deg,var(--S) 0%,var(--A) 55%,transparent 100%)}
.cnt{padding:26px 48px 48px}
.card{background:var(--card);border-radius:var(--r);box-shadow:var(--sh);overflow:hidden;border:1px solid var(--bdr)}
.mt{margin-top:20px}
.card-hd{padding:14px 22px 12px;border-bottom:1px solid var(--bdr);display:flex;align-items:center;justify-content:space-between;background:linear-gradient(to bottom,#fafbfd,#f4f6fa)}
.card-title{font-size:.68rem;font-weight:800;text-transform:uppercase;letter-spacing:.11em;color:var(--P)}
.cat-pill{font-size:.7rem;font-weight:700;padding:2px 9px;border-radius:20px;border:1px solid}
.dash{display:grid;grid-template-columns:200px 1fr 220px}
.dash>*{padding:24px 20px}
.dv{border-right:1px solid var(--bdr)}
.score-wrap{display:flex;flex-direction:column;align-items:center;justify-content:center}
.ring-trk{fill:none;stroke:#e4e9f2;stroke-width:10}
.ring-fill{fill:none;stroke:var(--S);stroke-width:10;stroke-linecap:round;stroke-dasharray:$circ;stroke-dashoffset:$circ;animation:rfill 1.4s cubic-bezier(.4,0,.2,1) .15s forwards}
@keyframes rfill{to{stroke-dashoffset:$offset}}
.score-c{text-align:center;margin-top:10px}
.score-n{font-size:2.6rem;font-weight:900;color:var(--P);letter-spacing:-.04em;line-height:1}
.score-s{font-size:.62rem;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}
.posture{display:inline-block;margin-top:8px;padding:4px 13px;border-radius:20px;font-size:.7rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em;background:${pColor}18;color:$pColor;border:1.5px solid ${pColor}3a}
.stats{display:flex;flex-direction:column;justify-content:center;gap:10px;padding-left:22px}
.narrative{font-size:.84rem;color:var(--txt);line-height:1.6;padding:10px 0 0;border-top:1px solid var(--bdr);margin-top:8px}
.sr{display:flex;align-items:center;gap:8px}
.sr-lbl{font-size:.64rem;text-transform:uppercase;letter-spacing:.07em;color:var(--mut);min-width:52px;font-weight:700}
.sr-track{flex:1;height:5px;background:#e8edf5;border-radius:3px;overflow:hidden}
.sr-fill{height:100%;border-radius:3px}
.sr-num{font-size:.9rem;font-weight:800;min-width:22px;text-align:right}
.sg .sr-num,.sg .sr-fill{color:var(--gap);background:var(--gap)}
.sw .sr-num,.sw .sr-fill{color:var(--warn);background:var(--warn)}
.sp .sr-num,.sp .sr-fill{color:var(--pass);background:var(--pass)}
.sn .sr-num,.sn .sr-fill{color:var(--na);background:var(--na)}
.cats{display:flex;flex-direction:column;gap:8px;justify-content:center}
.cats-t,.conn-t{font-size:.62rem;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);font-weight:700;margin-bottom:2px}
.cbar-hd{display:flex;justify-content:space-between;margin-bottom:2px}
.cbar-lbl{font-size:.73rem;font-weight:600;color:var(--txt)}.cbar-num{font-size:.73rem;font-weight:800}
.cbar-track{height:6px;background:#e4e9f2;border-radius:3px;overflow:hidden}.cbar-fill{height:100%;border-radius:3px}
.conn-grid{display:flex;flex-direction:column;gap:4px;margin-top:2px}
.conn{display:flex;align-items:center;gap:6px;padding:4px 8px;border-radius:5px;font-size:.73rem;font-weight:600}
.cok{background:#f0fdf4;color:#166534}.coff{background:#fef2f2;color:#991b1b}
.acts{padding:14px 20px;display:flex;flex-direction:column;gap:10px}
.act{display:flex;align-items:flex-start;gap:14px;padding:14px 16px;border-radius:8px;border-left:4px solid}
.ac{background:#fff8f8;border-color:var(--gap)}.ah{background:#fffbf0;border-color:var(--warn)}
.act-num{display:flex;flex-direction:column;align-items:center;gap:5px;min-width:52px}
.act-n{font-size:1.4rem;font-weight:900;color:var(--mut);line-height:1}
.act-effort{font-size:.58rem;font-weight:700;color:var(--mut);text-align:center;line-height:1.2;margin-top:4px}
.act-body{flex:1}
.act-t{font-weight:800;font-size:.9rem;color:var(--txt);line-height:1.3;margin-bottom:7px}
.act-risk{font-size:.78rem;color:#374151;line-height:1.5;margin-bottom:6px;padding:7px 11px;background:rgba(220,38,38,.04);border-radius:5px;border-left:2px solid #fca5a5}
.act-risk-lbl{font-weight:800;font-size:.62rem;text-transform:uppercase;letter-spacing:.06em;color:#b91c1c;display:block;margin-bottom:3px}
.act-rem{font-size:.78rem;color:#1d4ed8;line-height:1.5;padding:7px 11px;background:rgba(29,78,216,.04);border-radius:5px;border-left:2px solid #93c5fd}
.act-rem-lbl{font-weight:800;font-size:.62rem;text-transform:uppercase;letter-spacing:.06em;color:#1d4ed8;display:block;margin-bottom:3px}
.ft{width:100%;border-collapse:collapse;font-size:.83rem}
.fth th{padding:8px 12px;background:#f4f6fa;font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);font-weight:700;border-bottom:2px solid var(--bdr);text-align:left}
.fr{border-bottom:1px solid #f3f5f9}.fr:last-of-type{border-bottom:none}
.fr td{padding:9px 12px;vertical-align:top}
.exp{cursor:pointer}.exp:hover{background:#f9fafc}
.rg{border-left:3px solid var(--gap)}.rw{border-left:3px solid var(--warn)}
.rp{border-left:3px solid var(--pass)}.rn{border-left:3px solid #d1d5db}
.td1{width:142px;vertical-align:top}.td1 .b,.td1 .sv{display:block;margin-bottom:3px}
.td3{font-weight:600;color:var(--txt);width:30%}.td4{color:var(--mut);font-size:.78rem}
.f-title{font-weight:700;color:var(--txt);line-height:1.3;margin-bottom:2px}
.f-cv{font-size:.72rem;color:var(--mut);font-style:italic}
.more-ico{font-size:.6rem;color:var(--mut);margin-left:4px;vertical-align:middle;display:inline-block;transition:transform .2s}
.exp.open .more-ico{transform:rotate(90deg)}
.extr td{background:#f8fafd;padding:0}
.exbody{border-top:1px solid #eaecf3;display:grid;grid-template-columns:repeat(3,1fr)}
.ex-block{padding:14px 16px;border-right:1px solid #eaecf3}.ex-block:last-child{border-right:none}
.ex-block-lbl{font-size:.6rem;font-weight:900;text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px;padding-bottom:5px;border-bottom:1px solid}
.what-lbl{color:#374151;border-color:#d1d5db}.why-lbl{color:#b91c1c;border-color:#fca5a5}.how-lbl{color:#1d4ed8;border-color:#93c5fd}
.ex-block-body{font-size:.8rem;color:#374151;line-height:1.55}
.ex-cv{font-size:.73rem;color:var(--mut);margin-top:5px;font-style:italic}.ex-cvl{font-weight:700;color:#374151}
.ex-lnk{color:var(--A);font-weight:700;margin-left:6px;font-size:.73rem}
.effort-tag{display:inline-block;margin-top:5px;font-size:.62rem;font-weight:700;padding:2px 7px;border-radius:12px;background:#eef2ff;color:#3730a3;border:1px solid #c7d2fe}
.ex-ttp{margin-top:7px;display:flex;flex-wrap:wrap;gap:3px}
.ttp-tag{font-size:.63rem;padding:2px 6px;border-radius:3px;background:#fef2f2;color:#991b1b;font-weight:700;border:1px solid #fecaca;display:inline-block;text-decoration:none}
.ttp-tag:hover{background:#fee2e2}
.ex-fw{margin-top:5px;display:flex;flex-wrap:wrap;gap:3px}
.fw-tag{font-size:.63rem;padding:2px 6px;border-radius:3px;background:#eef2ff;color:#3730a3;font-weight:700;display:inline-block}
.b{display:inline-block;padding:3px 9px;border-radius:5px;font-size:.7rem;font-weight:800;white-space:nowrap;letter-spacing:.02em}
.bp{background:#f0fdf4;color:#166534;border:1px solid #bbf7d0}.bw{background:#fffbeb;color:#92400e;border:1px solid #fde68a}
.bg{background:#fef2f2;color:#991b1b;border:1px solid #fecaca}.bn{background:#f9fafb;color:#6b7280;border:1px solid #e5e7eb}
.sv{display:inline-block;padding:2px 7px;border-radius:4px;font-size:.67rem;font-weight:800;white-space:nowrap;letter-spacing:.03em}
.svc{background:var(--gap);color:#fff}.svh{background:#ea580c;color:#fff}.svm{background:var(--warn);color:#fff}.svl{background:#65a30d;color:#fff}.svi{background:#e5e7eb;color:#374151}
.rm-wrap{padding:6px 20px 20px;display:flex;flex-direction:column;gap:20px}
.rmgl{font-size:.68rem;font-weight:900;text-transform:uppercase;letter-spacing:.1em;padding:5px 0 8px;border-bottom:2px solid var(--bdr);margin-bottom:8px;display:flex;align-items:center;gap:7px}
.rm-cnt{font-weight:600;color:var(--mut)}.efq{color:#059669}.efs{color:#d97706}.efx{color:#7c3aed}
.rmi{padding:10px 13px;border-radius:6px;border-left:3px solid;margin-bottom:6px;background:#fafbfc}
.rmg-gap{border-color:var(--gap)}.rmg-warn{border-color:var(--warn)}
.rmi-hd{display:flex;align-items:center;gap:6px;margin-bottom:4px;flex-wrap:wrap}
.rmi-t{font-weight:700;font-size:.83rem;color:var(--txt)}
.rmi-why{font-size:.76rem;color:#6b7280;line-height:1.45;margin-bottom:4px;font-style:italic}
.rmi-r{font-size:.78rem;color:#1d4ed8;line-height:1.45}
.inv-body{padding:18px 22px;display:flex;flex-direction:column;gap:18px}
.subsec-title{font-size:.64rem;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);font-weight:800;margin-bottom:8px}
.user-stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}
.ustat{background:#f8fafd;border:1px solid var(--bdr);border-radius:8px;padding:12px 14px;text-align:center}
.ustat-n{font-size:1.6rem;font-weight:900;color:var(--P);letter-spacing:-.02em;line-height:1}
.ustat-l{font-size:.65rem;text-transform:uppercase;letter-spacing:.07em;color:var(--mut);font-weight:700;margin-top:3px}
.mfa-header{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:5px}
.mfa-title{font-size:.64rem;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);font-weight:800}
.mfa-pct{font-size:1.1rem;font-weight:900;letter-spacing:-.02em}
.mfa-track{height:10px;background:#e8edf5;border-radius:5px;overflow:hidden;margin-bottom:6px}
.mfa-fill{height:100%;border-radius:5px}.mfa-detail{font-size:.77rem;color:var(--mut);line-height:1.45}
.adm-tbl{}.adm-ga{background:#fff9f0}.adm-name{font-weight:600}
.adm-upn{font-size:.78rem;color:var(--mut);font-family:'Consolas','Courier New',monospace}.adm-last{font-size:.78rem;color:var(--mut)}
.role-tag{font-size:.65rem;font-weight:800;text-transform:uppercase;letter-spacing:.04em;padding:2px 7px;border-radius:4px;background:#eef2ff;color:#3730a3;white-space:nowrap}
.pim-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.pim-card{background:#f8fafd;border:1px solid var(--bdr);border-radius:8px;padding:12px 14px;text-align:center}
.pim-n{font-size:1.6rem;font-weight:900;letter-spacing:-.02em;line-height:1}
.pim-l{font-size:.65rem;text-transform:uppercase;letter-spacing:.07em;color:var(--mut);font-weight:700;margin-top:3px}
.tscroll{overflow-x:auto}
.itbl{width:100%;border-collapse:collapse;font-size:.8rem}
.itbl thead tr{background:#f4f6fa}
.itbl th{padding:8px 12px;text-align:left;font-size:.63rem;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);font-weight:700;border-bottom:2px solid var(--bdr)}
.itbl td{padding:8px 12px;border-bottom:1px solid #f3f5f9;vertical-align:middle}
.itbl tbody tr:last-child td{border-bottom:none}.itbl tbody tr:hover{background:#fafbfc}
.i2{max-width:480px}
.igood{color:#166534;font-weight:700}.iwarn{color:#92400e;font-weight:700}.ibad{color:#991b1b;font-weight:700}.ioff{color:var(--mut);font-weight:600}
.isub{font-size:.68rem;color:var(--mut);margin-left:6px}
.icode{font-family:'Cascadia Code','Consolas','Courier New',monospace;font-size:.72rem;color:#374151;background:#f3f4f6;padding:1px 5px;border-radius:3px}
.ca-n{font-weight:600;max-width:220px}.ca-c{font-size:.75rem;color:var(--mut)}.ca-ro{background:#fffdf0}.ca-dis{background:#fafafa;opacity:.7}
.ftr{background:var(--P);color:rgba(255,255,255,.55);padding:16px 48px;display:flex;justify-content:space-between;font-size:.74rem;flex-wrap:wrap;gap:8px;margin-top:32px}
.ftr strong{color:#fff}
@media print{
  *{-webkit-print-color-adjust:exact !important;print-color-adjust:exact !important}
  body{background:#fff;font-size:12px}.wrap{max-width:none}.cnt{padding:16px 28px 28px}.hdr{padding:20px 28px 16px}.ftr{padding:12px 28px;margin-top:18px}
  .card{box-shadow:none;break-inside:avoid;border:1px solid #dde3ec}
  .extr{display:table-row !important}.exp{cursor:default}
  .ring-fill{animation:none !important;stroke-dashoffset:$offset}
  .exbody{grid-template-columns:1fr 1fr 1fr}
}
</style>
</head>
<body>
<div class="wrap">
<div class="hdr">
  <div class="hdr-inner">
    <div>
      <div class="hdr-eye">Microsoft 365 Security Assessment</div>
      <div class="hdr-client">$cDisp</div>
      <div class="hdr-meta">
        <span><strong>Date</strong> $dStr</span>
        <span><strong>Tenant</strong> $tDom</span>
        $(if ($opStr) { "<span><strong>Prepared by</strong> $opStr</span>" })
      </div>
    </div>
    <div class="hdr-right"><div class="ver">NRG-Assessment v$ver</div>$logoH</div>
  </div>
</div>
<div class="abar"></div>
<div class="cnt">

<div class="card">
  <div class="dash">
    <div class="score-wrap dv">
      <svg width="132" height="132" viewBox="0 0 160 160">
        <circle class="ring-trk" cx="80" cy="80" r="72" transform="rotate(-90 80 80)"/>
        <circle class="ring-fill" cx="80" cy="80" r="72" transform="rotate(-90 80 80)"/>
      </svg>
      <div class="score-c">
        <div class="score-n">$score</div>
        <div class="score-s">/ 100</div>
        <div class="posture">$pLabel</div>
      </div>
    </div>
    <div class="stats dv">
      <div class="sr sg"><span class="sr-lbl">Gaps</span><div class="sr-track"><div class="sr-fill" style="width:${wGap}%"></div></div><span class="sr-num">$gap</span></div>
      <div class="sr sw"><span class="sr-lbl">Partial</span><div class="sr-track"><div class="sr-fill" style="width:${wPart}%"></div></div><span class="sr-num">$part</span></div>
      <div class="sr sp"><span class="sr-lbl">Satisfied</span><div class="sr-track"><div class="sr-fill" style="width:${wSat}%"></div></div><span class="sr-num">$sat</span></div>
      <div class="sr sn"><span class="sr-lbl">N/A</span><div class="sr-track"><div class="sr-fill" style="width:${wNA}%"></div></div><span class="sr-num">$na</span></div>
      <div class="narrative">$narrativeSentence</div>
    </div>
    <div class="cats">
      <div class="cats-t">Score by Category</div>
      $allCatBars
      <div class="conn-t" style="margin-top:12px">Service Connections</div>
      <div class="conn-grid">$connHtml</div>
    </div>
  </div>
</div>

$(if ($actsHtml) { "<div class=`"card mt`"><div class=`"card-hd`"><span class=`"card-title`">Priority Actions</span><span style=`"font-size:.73rem;color:var(--mut)`">Top critical and high-severity items requiring immediate attention</span></div><div class=`"acts`">$actsHtml</div></div>" })

$findHtml

$roadmapHtml

$identityHtml

$dnsInvHtml
$exoInvHtml
$caPolicyHtml
$defInvHtml

</div>
<div class="ftr">
  <span>Prepared by <strong>$cmpStr</strong>$(if ($phStr) { " &bull; $phStr" })$(if ($wsStr) { " &bull; $wsStr" })</span>
  <span>Read-only assessment &mdash; no configuration changes were made</span>
</div>
</div>
<script>
function toggle(tr){var n=tr.nextElementSibling;if(n&&n.classList.contains('extr')){var show=n.style.display==='none'||n.style.display==='';n.style.display=show?'table-row':'none';tr.classList.toggle('open',show)}}
document.querySelectorAll('.extr').forEach(function(r){r.style.display='none'});
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding utf8
}