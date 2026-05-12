#
# Publish-NRGAssessmentHTML.ps1
# Comprehensive premium HTML report — client-deliverable, print-to-PDF ready.
#
# Sections:
#   1. Executive Dashboard (score ring, category breakdown, stat bars, connections)
#   2. Assessment Scope (what was covered / not covered, scoring methodology)
#   3. Priority Actions (top 5 gap/critical/high)
#   4. Identity Inventory (user stats, MFA registration, admin accounts, PIM status)
#   5. Findings by Category (expandable rows, CurrentValue in collapsed, ATT&CK TTPs)
#   6. Remediation Roadmap (grouped by effort level)
#   7. DNS Email Security Inventory (all 8 columns)
#   8. Exchange Online Inventory
#   9. Conditional Access Policy Inventory
#   10. Defender for Office 365 Inventory
#
# Self-contained single file — no external dependencies, works fully offline.
# Print-optimised @media print CSS for clean PDF output.
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

    $brand = $Metadata.Brand

    # ── Brand ──────────────────────────────────────────────────────────────────
    $primary   = if ($brand.PrimaryColor)   { $brand.PrimaryColor }   else { '#1a3a6b' }
    $secondary = if ($brand.SecondaryColor) { $brand.SecondaryColor } else { '#e87722' }
    $accent    = if ($brand.AccentColor)    { $brand.AccentColor }    else { '#4a7ba6' }
    $company   = if ($brand.CompanyName)    { $brand.CompanyName }    else { 'NRG Technology Services' }
    $phone     = if ($brand.Phone)          { $brand.Phone }          else { '' }
    $website   = if ($brand.Website)        { $brand.Website }        else { '' }
    $logoUrl   = if ($brand.LogoUrl)        { $brand.LogoUrl }        else { '' }
    $clientDisplay = if ($ClientName) { $ClientName } else { $Metadata.TenantDomain }

    # ── HTML escape helper ─────────────────────────────────────────────────────
    function hx { param([string]$s) if (-not $s) { return '' }; $s -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;' }

    # ── State + severity badge functions ───────────────────────────────────────
    function sBadge {
        param([string]$s)
        switch ($s) {
            'Satisfied'     { '<span class="b bp">&#10003; Pass</span>' }
            'Partial'       { '<span class="b bw">&#9679; Partial</span>' }
            'Gap'           { '<span class="b bg">&#10005; Gap</span>' }
            'NotApplicable' { '<span class="b bn">&#8212; N/A</span>' }
            default         { "<span class=`"b`">$(hx $s)</span>" }
        }
    }
    function svBadge {
        param([string]$s)
        switch ($s) {
            'Critical' { '<span class="sv svc">Critical</span>' }
            'High'     { '<span class="sv svh">High</span>' }
            'Medium'   { '<span class="sv svm">Medium</span>' }
            'Low'      { '<span class="sv svl">Low</span>' }
            default    { '<span class="sv svi">Info</span>' }
        }
    }

    # ── ATT&CK TTP map ─────────────────────────────────────────────────────────
    # Inline map — avoids requiring controls.json schema change
    $ttpMap = @{
        'AAD-1.1' = @('T1078','T1110.003')
        'AAD-1.2' = @('T1111','T1621')
        'AAD-1.3' = @('T1078.004')
        'AAD-2.1' = @('T1078','T1110')
        'AAD-2.2' = @('T1078','T1110')
        'AAD-2.3' = @('T1621')
        'AAD-2.4' = @('T1078')
        'AAD-3.1' = @('T1078','T1110')
        'AAD-3.2' = @('T1078','T1110.001')
        'AAD-3.3' = @('T1078.004')
        'AAD-3.4' = @('T1078')
        'AAD-3.5' = @('T1078','T1566')
        'AAD-3.6' = @('T1078')
        'AAD-4.1' = @('T1078.004')
        'AAD-4.2' = @('T1078.002')
        'AAD-4.3' = @('T1078.004')
        'AAD-4.4' = @('T1078.004')
        'AAD-4.5' = @('T1078.004')
        'EXO-1.1' = @('T1114','T1114.002')
        'EXO-1.2' = @('T1078','T1114')
        'EXO-2.1' = @('T1566.001')
        'EXO-2.2' = @('T1114','T1078')
        'EXO-2.3' = @('T1114','T1078')
        'EXO-2.4' = @('T1213')
        'EXO-2.5' = @('T1078')
        'EXO-3.1' = @('T1078')
        'DEF-1.1' = @('T1566.001')
        'DEF-1.2' = @('T1566.001','T1204.002')
        'DEF-1.3' = @('T1566.002','T1189')
        'DNS-1.1' = @('T1566.001')
        'DNS-1.2' = @('T1566.001')
        'DNS-2.1' = @('T1557')
        'DNS-2.2' = @('T1557')
        'DNS-2.3' = @('T1557','T1584.002')
    }

    # ── Overall scoring ────────────────────────────────────────────────────────
    $sat   = @($Findings | Where-Object State -eq 'Satisfied').Count
    $part  = @($Findings | Where-Object State -eq 'Partial').Count
    $gap   = @($Findings | Where-Object State -eq 'Gap').Count
    $na    = @($Findings | Where-Object State -eq 'NotApplicable').Count
    $total = $Findings.Count
    $scrd  = $total - $na
    $score = if ($scrd -gt 0) { [Math]::Round(100 * ($sat + 0.5 * $part) / $scrd) } else { 0 }

    $pLabel = if ($score -ge 85) { 'Strong' } elseif ($score -ge 65) { 'Moderate' } elseif ($score -ge 40) { 'Weak' } else { 'Critical' }
    $pColor = if ($score -ge 85) { '#059669' } elseif ($score -ge 65) { '#d97706' } elseif ($score -ge 40) { '#ea580c' } else { '#dc2626' }

    # SVG ring r=72, circ=452.4
    $circ   = 452.4
    $offset = [Math]::Round($circ * (1 - $score / 100), 2)

    # ── Category scores ────────────────────────────────────────────────────────
    $cScores = @{}
    $Findings | Group-Object Category | ForEach-Object {
        $cS = @($_.Group | Where-Object State -eq 'Satisfied').Count
        $cP = @($_.Group | Where-Object State -eq 'Partial').Count
        $cN = @($_.Group | Where-Object State -eq 'NotApplicable').Count
        $cD = $_.Group.Count - $cN
        $cScores[$_.Name] = if ($cD -gt 0) { [Math]::Round(100 * ($cS + 0.5 * $cP) / $cD) } else { 0 }
    }
    function catBar {
        param([string]$label, [string]$key)
        $s = if ($cScores.ContainsKey($key)) { $cScores[$key] } else { 0 }
        $c = if ($s -ge 85) { '#059669' } elseif ($s -ge 65) { '#d97706' } elseif ($s -ge 40) { '#ea580c' } else { '#dc2626' }
        return "<div class=`"cbar`"><div class=`"cbar-hd`"><span class=`"cbar-lbl`">$label</span><span class=`"cbar-num`" style=`"color:$c`">$s</span></div><div class=`"cbar-track`"><div class=`"cbar-fill`" style=`"width:${s}%;background:$c`"></div></div></div>"
    }

    # ── Stat bar widths ────────────────────────────────────────────────────────
    $wGap  = if ($scrd -gt 0) { [Math]::Round(100 * $gap  / $scrd) } else { 0 }
    $wPart = if ($scrd -gt 0) { [Math]::Round(100 * $part / $scrd) } else { 0 }
    $wSat  = if ($scrd -gt 0) { [Math]::Round(100 * $sat  / $scrd) } else { 0 }
    $wNA   = if ($total -gt 0) { [Math]::Round(100 * $na  / $total) } else { 0 }

    # ── Connections ────────────────────────────────────────────────────────────
    $connHtml = ''
    foreach ($svc in @('Graph','EXO','IPPSSession','Teams','SharePoint')) {
        $ok = if ($Connections -is [hashtable]) { $Connections.ContainsKey($svc) -and $Connections[$svc] -eq $true } else { $Connections.$svc -eq $true }
        $cls = if ($ok) { 'cok' } else { 'coff' }
        $ico = if ($ok) { '&#10003;' } else { '&#10005;' }
        $connHtml += "<div class=`"conn $cls`"><span>$ico</span><span>$svc</span></div>"
    }

    # ── Priority actions ───────────────────────────────────────────────────────
    $topGaps = @($Findings | Where-Object {
        $_.State -eq 'Gap' -and $_.Severity -in @('Critical','High')
    } | Sort-Object @{Expression={ switch ($_.Severity) { 'Critical' { 0 }; 'High' { 1 }; default { 2 } } }} | Select-Object -First 5)

    $actsHtml = ''
    $n = 1
    foreach ($g in $topGaps) {
        $cls     = if ($g.Severity -eq 'Critical') { 'ac' } else { 'ah' }
        $t       = hx $g.Title
        $d       = hx $g.Detail
        $sv      = $g.Severity
        $actDDiv = if ($d) { "<div class=`"act-d`">$d</div>" } else { '' }
        $actsHtml += "<div class=`"act $cls`"><div class=`"act-n`">$n</div><div class=`"act-sv`">$sv</div><div class=`"act-body`"><div class=`"act-t`">$t</div>$actDDiv</div></div>"
        $n++
    }

    # ── Assessment scope ───────────────────────────────────────────────────────
    $coveredCount   = $scrd
    $uncoveredAreas = @('SharePoint Online','Microsoft Teams governance','Purview / Compliance Center','Microsoft Intune / Endpoint','Power Platform','Microsoft Sentinel')
    $coveredAreas   = @($Findings | Group-Object Category | Select-Object -ExpandProperty Name | Sort-Object)
    $coveredHtml = ($coveredAreas | ForEach-Object {
        $cat = $_
        $cnt = @($Findings | Where-Object { $_.Category -eq $cat }).Count
        "<div class=`"scope-item scope-covered`"><span class=`"scope-ico`">&#10003;</span><div><div class=`"scope-name`">$cat</div><div class=`"scope-cnt`">$cnt controls assessed</div></div></div>"
    }) -join ''
    $uncoveredHtml = ($uncoveredAreas | ForEach-Object {
        "<div class=`"scope-item scope-pending`"><span class=`"scope-ico`">&#9711;</span><div><div class=`"scope-name`">$(hx $_)</div><div class=`"scope-cnt`">Session 5+</div></div></div>"
    }) -join ''

    $scopeHtml = @"
      <div class="card mt">
        <div class="card-hd"><span class="card-title">Assessment Scope &amp; Methodology</span></div>
        <div class="scope-body">
          <div class="scope-col">
            <div class="scope-head">Assessed in this report</div>
            $coveredHtml
          </div>
          <div class="scope-col">
            <div class="scope-head">Not yet assessed</div>
            $uncoveredHtml
          </div>
          <div class="scope-col scope-method">
            <div class="scope-head">Scoring Methodology</div>
            <div class="method-formula">
              <div class="method-eq">Score = (Satisfied + 0.5 &times; Partial) &divide; (Total &minus; N/A) &times; 100</div>
            </div>
            <div class="method-rows">
              <div class="method-row"><span class="b bp" style="min-width:72px;text-align:center">Pass</span><span>Control fully meets the requirement</span></div>
              <div class="method-row"><span class="b bw" style="min-width:72px;text-align:center">Partial</span><span>Control partially met or config present but not enforced</span></div>
              <div class="method-row"><span class="b bg" style="min-width:72px;text-align:center">Gap</span><span>Control not in place — active security risk</span></div>
              <div class="method-row"><span class="b bn" style="min-width:72px;text-align:center">N/A</span><span>Cannot be evaluated in this environment</span></div>
            </div>
            <div class="method-scale">
              <div class="scale-item" style="color:#059669"><strong>85&ndash;100</strong> Strong</div>
              <div class="scale-item" style="color:#d97706"><strong>65&ndash;84</strong> Moderate</div>
              <div class="scale-item" style="color:#ea580c"><strong>40&ndash;64</strong> Weak</div>
              <div class="scale-item" style="color:#dc2626"><strong>0&ndash;39</strong> Critical</div>
            </div>
          </div>
        </div>
      </div>
"@

    # ── Identity Inventory ─────────────────────────────────────────────────────
    $identityHtml = ''
    $userRaw  = Get-NRGRawData -Key 'AAD-Users'
    $rolesRaw = Get-NRGRawData -Key 'AAD-Roles'
    $pimRaw   = Get-NRGRawData -Key 'AAD-PIM'

    if ($userRaw -and $userRaw.Success) {
        $allUsers = @($userRaw.Data['Users'])
        $mfaReg   = @($userRaw.Data['MFARegistration'])

        # User stats
        $memberUsers    = @($allUsers | Where-Object { $_.UserType -ne 'Guest' -and $_.UserType -ne 'guest' })
        $enabledMembers = @($memberUsers | Where-Object { $_.AccountEnabled -eq $true })
        $guestUsers     = @($allUsers | Where-Object { $_.UserType -eq 'Guest' -or $_.UserType -eq 'guest' })
        $licensedUsers  = @($allUsers | Where-Object { $_.AssignedLicenses -and $_.AssignedLicenses.Count -gt 0 })
        $syncedUsers    = @($allUsers | Where-Object { $_.OnPremisesSyncEnabled -eq $true })

        # MFA registration for enabled members
        $enabledUPNs  = @($enabledMembers | Select-Object -ExpandProperty UserPrincipalName)
        $mfaFiltered  = @($mfaReg | Where-Object { $_.UserPrincipalName -in $enabledUPNs -or $_.Id -in $enabledUPNs })
        # If filtered is empty (collector stored all), use all
        if ($mfaFiltered.Count -eq 0) { $mfaFiltered = @($mfaReg) }
        $mfaRegistered = @($mfaFiltered | Where-Object { $_.IsMfaRegistered -eq $true }).Count
        $mfaTotal      = $mfaFiltered.Count
        if ($mfaTotal -eq 0) { $mfaTotal = $enabledMembers.Count }
        $mfaPct        = if ($mfaTotal -gt 0) { [Math]::Round(100 * $mfaRegistered / $mfaTotal) } else { 0 }
        $mfaColor      = if ($mfaPct -ge 95) { '#059669' } elseif ($mfaPct -ge 80) { '#d97706' } else { '#dc2626' }
        $mfaNotReg     = $mfaTotal - $mfaRegistered

        # User stat cards
        $statCardsHtml = @"
        <div class="user-stats">
          <div class="ustat"><div class="ustat-n">$($allUsers.Count)</div><div class="ustat-l">Total Accounts</div></div>
          <div class="ustat"><div class="ustat-n">$($enabledMembers.Count)</div><div class="ustat-l">Enabled Members</div></div>
          <div class="ustat"><div class="ustat-n">$($guestUsers.Count)</div><div class="ustat-l">Guest Users</div></div>
          <div class="ustat"><div class="ustat-n">$($licensedUsers.Count)</div><div class="ustat-l">Licensed Users</div></div>
          <div class="ustat"><div class="ustat-n">$($syncedUsers.Count)</div><div class="ustat-l">On-prem Synced</div></div>
        </div>
"@

        # MFA registration bar
        $mfaBarHtml = @"
        <div class="mfa-section">
          <div class="mfa-header">
            <span class="mfa-title">MFA Registration</span>
            <span class="mfa-pct" style="color:$mfaColor">$mfaPct%</span>
          </div>
          <div class="mfa-track"><div class="mfa-fill" style="width:${mfaPct}%;background:$mfaColor"></div></div>
          <div class="mfa-detail">$mfaRegistered of $mfaTotal enabled member accounts have MFA registered. <span style="color:#dc2626;font-weight:700">$mfaNotReg unregistered</span> — do not enforce MFA CA policy until registration reaches 95%+.</div>
        </div>
"@

        # Admin accounts table
        $adminRowsHtml = ''
        if ($rolesRaw -and $rolesRaw.Success) {
            $assignments = @($rolesRaw.Data['RoleAssignments'])
            $defs        = @($rolesRaw.Data['RoleDefinitions'])

            $roleNameMap = @{}
            foreach ($def in $defs) {
                if ($def.Id) { $roleNameMap[$def.Id] = $def.DisplayName }
            }

            $privRoles = @('Global Administrator','Privileged Role Administrator','Exchange Administrator','Security Administrator','Compliance Administrator','User Administrator','SharePoint Administrator','Teams Service Administrator','Billing Administrator','Application Administrator','Hybrid Identity Administrator')

            $adminAssignments = @($assignments | Where-Object {
                $_.RoleDefinitionId -and
                $roleNameMap.ContainsKey($_.RoleDefinitionId) -and
                $roleNameMap[$_.RoleDefinitionId] -in $privRoles
            } | Sort-Object @{Expression={
                if ($_.RoleDefinitionId -and $roleNameMap.ContainsKey($_.RoleDefinitionId)) { $roleNameMap[$_.RoleDefinitionId] } else { '' }
            }})

            foreach ($a in $adminAssignments) {
                $roleName = if ($roleNameMap.ContainsKey($a.RoleDefinitionId)) { $roleNameMap[$a.RoleDefinitionId] } else { 'Unknown' }
                $user     = $allUsers | Where-Object { $_.Id -eq $a.PrincipalId } | Select-Object -First 1

                $displayName = if ($user -and $user.DisplayName) { hx $user.DisplayName } else { hx $a.PrincipalId }
                $upn         = if ($user -and $user.UserPrincipalName) { hx $user.UserPrincipalName } else { '&mdash;' }

                $isLicensed   = $user -and $user.AssignedLicenses -and $user.AssignedLicenses.Count -gt 0
                $isSynced     = $user -and $user.OnPremisesSyncEnabled -eq $true
                $isEnabled    = $user -and $user.AccountEnabled -eq $true

                $licVal  = if ($isLicensed) { '<span class="iwarn">&#9888; Licensed</span>' } else { '<span class="igood">&#10003; Unlicensed</span>' }
                $syncVal = if ($isSynced)   { '<span class="ibad">&#9650; Synced</span>' }   else { '<span class="igood">&#9729; Cloud-only</span>' }
                $enVal   = if ($isEnabled)  { '<span class="igood">Enabled</span>' }          else { '<span class="ioff">Disabled</span>' }

                $lastSignIn = '&mdash;'
                if ($user -and $user.SignInActivity) {
                    if ($user.SignInActivity.LastSignInDateTime) {
                        try { $lastSignIn = ([datetime]$user.SignInActivity.LastSignInDateTime).ToString('yyyy-MM-dd') } catch { $lastSignIn = '&mdash;' }
                    }
                }

                $rowClass = if ($roleName -eq 'Global Administrator') { 'adm-ga' } else { '' }
                $adminRowsHtml += "<tr class=`"$rowClass`"><td><span class=`"role-tag`">$(hx $roleName)</span></td><td class=`"adm-name`">$displayName</td><td class=`"adm-upn`">$upn</td><td>$licVal</td><td>$syncVal</td><td>$enVal</td><td class=`"adm-last`">$lastSignIn</td></tr>"
            }
        }

        $adminTableHtml = ''
        if ($adminRowsHtml) {
            $adminTableHtml = @"
        <div class="subsec-title">Privileged Role Assignments</div>
        <div class="tscroll">
        <table class="itbl adm-tbl">
          <thead><tr><th>Role</th><th>Display Name</th><th>UPN</th><th>Licensed</th><th>Account Type</th><th>Status</th><th>Last Sign-in</th></tr></thead>
          <tbody>$adminRowsHtml</tbody>
        </table>
        </div>
"@
        }

        # PIM status
        $pimHtml = ''
        if ($pimRaw -and $pimRaw.Success) {
            $eligible = @($pimRaw.Data['EligibleSchedules'])
            $active   = @($pimRaw.Data['ActiveSchedules'])
            $gaRoleId = $null
            if ($rolesRaw -and $rolesRaw.Success) {
                $gaDef    = @($rolesRaw.Data['RoleDefinitions']) | Where-Object { $_.DisplayName -eq 'Global Administrator' } | Select-Object -First 1
                if ($gaDef) { $gaRoleId = $gaDef.Id }
            }
            $gaEligible = if ($gaRoleId) { @($eligible | Where-Object { $_.RoleDefinitionId -eq $gaRoleId }).Count } else { 0 }
            $gaActive   = if ($gaRoleId) { @($active   | Where-Object { $_.RoleDefinitionId -eq $gaRoleId }).Count } else { 0 }
            $pimColor   = if ($eligible.Count -gt 0) { '#059669' } else { '#dc2626' }
            $pimStatus  = if ($eligible.Count -gt 0) { 'Configured' } else { 'Not configured' }

            $pimHtml = @"
        <div class="subsec-title">Privileged Identity Management (PIM)</div>
        <div class="pim-grid">
          <div class="pim-card"><div class="pim-n" style="color:$pimColor">$($eligible.Count)</div><div class="pim-l">Eligible (JIT) assignments</div></div>
          <div class="pim-card"><div class="pim-n" style="color:$(if($active.Count -gt 0){'#d97706'}else{'#059669'})">$($active.Count)</div><div class="pim-l">Active (permanent) assignments</div></div>
          <div class="pim-card"><div class="pim-n" style="color:$(if($gaEligible -gt 0){'#059669'}else{'#dc2626'})">$gaEligible</div><div class="pim-l">GA role — JIT eligible</div></div>
          <div class="pim-card"><div class="pim-n" style="color:$(if($gaActive -gt 2){'#dc2626'}elseif($gaActive -gt 0){'#d97706'}else{'#059669'})">$gaActive</div><div class="pim-l">GA role — permanent active</div></div>
        </div>
"@
        }

        $identityHtml = @"
      <div class="card mt">
        <div class="card-hd"><span class="card-title">Identity Inventory</span></div>
        <div class="inv-body">
          $statCardsHtml
          $mfaBarHtml
          $adminTableHtml
          $pimHtml
        </div>
      </div>
"@
    }

    # ── Findings sections ──────────────────────────────────────────────────────
    $findHtml = ''
    foreach ($cat in ($Findings | Group-Object Category | Sort-Object Name)) {
        $rows = ''
        foreach ($f in ($cat.Group | Sort-Object @{Expression={
            switch ($_.State) { 'Gap' { 0 }; 'Partial' { 1 }; 'Satisfied' { 2 }; 'NotApplicable' { 3 } }
        }}, @{Expression='Title'})) {

            $rc  = switch ($f.State) { 'Gap' { 'rg' }; 'Partial' { 'rw' }; 'Satisfied' { 'rp' }; 'NotApplicable' { 'rn' } }
            $t   = hx $f.Title
            $d   = hx $f.Detail
            $cv  = hx $f.CurrentValue
            $rv  = hx $f.RequiredValue
            $rem = hx $f.Remediation
            $rl  = hx $f.RemediationLink

            # ATT&CK TTPs
            $ttps = if ($ttpMap.ContainsKey($f.ControlId)) { $ttpMap[$f.ControlId] } else { @() }

            # Truncated current value for collapsed row
            $cvShort = ''
            if ($cv) {
                $cvShort = if ($cv.Length -gt 70) { $cv.Substring(0,67) + '...' } else { $cv }
            }

            # Expanded section
            $exHtml = ''
            if ($d -or $cv -or $rv -or $rem -or $ttps.Count -gt 0 -or $f.FrameworkIds.Count -gt 0) {
                $dp   = if ($d)   { "<p class=`"ex-d`">$d</p>" } else { '' }
                $cvr  = if ($cv)  { "<div class=`"ex-r`"><span class=`"ex-l`">Current</span><span class=`"ex-v`">$cv</span></div>" } else { '' }
                $rvr  = if ($rv)  { "<div class=`"ex-r`"><span class=`"ex-l`">Required</span><span class=`"ex-v`">$rv</span></div>" } else { '' }
                $remr = ''
                if ($rem) {
                    $lnk = if ($rl) { " <a href=`"$rl`" target=`"_blank`" class=`"ex-lnk`">&#8599; Open portal</a>" } else { '' }
                    $remr = "<div class=`"ex-r ex-rem`"><span class=`"ex-l`">Remediation</span><span class=`"ex-v`">$rem$lnk</span></div>"
                }
                $ttpHtml = ''
                if ($ttps.Count -gt 0) {
                    $ttpTags = ($ttps | ForEach-Object { "<a href=`"https://attack.mitre.org/techniques/$($_ -replace '\.','/')`" target=`"_blank`" class=`"ttp-tag`">$_</a>" }) -join ''
                    $ttpHtml = "<div class=`"ex-r`"><span class=`"ex-l`">ATT&amp;CK TTPs</span><span class=`"ex-v ttptags`">$ttpTags</span></div>"
                }
                $fwHtml = ''
                if ($f.FrameworkIds -and $f.FrameworkIds.Count -gt 0) {
                    $fwTags = ($f.FrameworkIds | ForEach-Object { "<span class=`"fw-tag`">$(hx $_)</span>" }) -join ''
                    $fwHtml = "<div class=`"ex-r`"><span class=`"ex-l`">Frameworks</span><span class=`"ex-v fwtags`">$fwTags</span></div>"
                }
                $exHtml = "<tr class=`"extr`"><td colspan=`"4`"><div class=`"exbody`">$dp$cvr$rvr$remr$ttpHtml$fwHtml</div></td></tr>"
            }

            $clickAttr = if ($exHtml) { "class=`"fr $rc exp`" onclick=`"toggle(this)`"" } else { "class=`"fr $rc`"" }

            # TTP mini-badges in collapsed row (gap/partial only, max 2)
            $ttpMini = ''
            if ($ttps.Count -gt 0 -and $f.State -in @('Gap','Partial')) {
                $shown = $ttps | Select-Object -First 2
                $ttpMini = ' ' + (($shown | ForEach-Object { "<span class=`"ttp-mini`">$_</span>" }) -join '')
            }

            # Pre-compute conditionals — inline if() with backtick-escaped quotes is not reliable inside here-string subexpressions
            $cvDiv = if ($cvShort) { "<div class=`"f-cv`">$cvShort</div>" } else { '' }
            $tdDet = if ($d) { $d } else { '&nbsp;' }

            $rows += @"
          <tr $clickAttr>
            <td class="td1">$(sBadge $f.State)</td>
            <td class="td2">$(svBadge $f.Severity)</td>
            <td class="td3"><div class="f-title">$t$ttpMini</div>$cvDiv</td>
            <td class="td4">$tdDet</td>
          </tr>
          $exHtml
"@
        }

        $cKey   = $cat.Name
        $cScore = if ($cScores.ContainsKey($cKey)) { $cScores[$cKey] } else { 0 }
        $cColor = if ($cScore -ge 85) { '#059669' } elseif ($cScore -ge 65) { '#d97706' } elseif ($cScore -ge 40) { '#ea580c' } else { '#dc2626' }

        $findHtml += @"
      <div class="card mt">
        <div class="card-hd">
          <span class="card-title">$(hx $cat.Name)</span>
          <span class="cat-pill" style="background:${cColor}18;color:$cColor;border-color:${cColor}3a">$cScore / 100</span>
        </div>
        <table class="ft">
          <thead><tr class="fth"><th style="width:92px">State</th><th style="width:82px">Severity</th><th>Control / Current Value</th><th>Detail</th></tr></thead>
          <tbody>$rows</tbody>
        </table>
      </div>
"@
    }

    # ── Remediation Roadmap ────────────────────────────────────────────────────
    $roadmapHtml = ''
    $actionable = @($Findings | Where-Object { $_.State -in @('Gap','Partial') -and $_.Remediation })
    if ($actionable.Count -gt 0) {
        $groups = [ordered]@{
            'Quick Win (< 30 min)'          = @()
            'Standard (1-4 hrs)'            = @()
            'Strategic (planning required)' = @()
        }
        foreach ($f in ($actionable | Sort-Object @{Expression={
            switch ($_.Severity) { 'Critical' { 0 }; 'High' { 1 }; 'Medium' { 2 }; default { 3 } }
        }})) {
            $ctrl   = Get-NRGControlById -ControlId $f.ControlId
            $effort = if ($ctrl -and $ctrl.EffortLevel) { $ctrl.EffortLevel } else { 'Standard (1-4 hrs)' }
            if ($groups.Contains($effort)) { $groups[$effort] += $f } else { $groups['Standard (1-4 hrs)'] += $f }
        }

        $rmRows = ''
        foreach ($grpKey in $groups.Keys) {
            $items = $groups[$grpKey]
            if ($items.Count -eq 0) { continue }
            $efCls = switch -Wildcard ($grpKey) { '*30 min*' { 'efq' }; '*1-4*' { 'efs' }; default { 'efx' } }
            $efIco = switch -Wildcard ($grpKey) { '*30 min*' { '&#9889;' }; '*1-4*' { '&#9200;' }; default { '&#9881;' } }
            $rmRows += "<div class=`"rmg`"><div class=`"rmgl $efCls`">$efIco $(hx $grpKey)</div>"
            foreach ($f in $items) {
                $rc2  = if ($f.State -eq 'Gap') { 'rmg-gap' } else { 'rmg-warn' }
                $lnk2 = if ($f.RemediationLink) { " <a href=`"$(hx $f.RemediationLink)`" target=`"_blank`" class=`"ex-lnk`">&#8599; Portal</a>" } else { '' }
                $ttps2 = if ($ttpMap.ContainsKey($f.ControlId)) { ($ttpMap[$f.ControlId] | ForEach-Object { "<span class=`"ttp-mini`">$_</span>" }) -join '' } else { '' }
                $rmRows += "<div class=`"rmi $rc2`"><div class=`"rmi-hd`">$(svBadge $f.Severity) <span class=`"rmi-t`">$(hx $f.Title)</span> $ttps2</div><div class=`"rmi-r`">$(hx $f.Remediation)$lnk2</div></div>"
            }
            $rmRows += "</div>"
        }
        $roadmapHtml = "<div class=`"card mt`"><div class=`"card-hd`"><span class=`"card-title`">Remediation Roadmap</span></div><div class=`"rm-wrap`">$rmRows</div></div>"
    }

    # ── DNS Inventory ──────────────────────────────────────────────────────────
    $dnsInvHtml = ''
    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    if ($dnsData -and $dnsData.Success -and $dnsData.Data.Domains) {
        $dRows = ''
        foreach ($domain in ($dnsData.Data.Domains.Keys | Sort-Object)) {
            $d = $dnsData.Data.Domains[$domain]
            $spf  = if (-not $d.SPF) { '<span class="ibad">&#10005; None</span>' } elseif ($d.SPF -match '\-all') { '<span class="igood">&#10003; -all</span>' } elseif ($d.SPF -match '~all') { '<span class="iwarn">~ ~all</span>' } else { '<span class="iwarn">&#9888;</span>' }
            $dkim = if ($d.DKIM.Selector1 -and $d.DKIM.Selector2) { '<span class="igood">&#10003; Both</span>' } elseif ($d.DKIM.Selector1 -or $d.DKIM.Selector2) { '<span class="iwarn">&#9888; Partial</span>' } else { '<span class="ibad">&#10005;</span>' }
            $dmarc = if (-not $d.DMARC) { '<span class="ibad">&#10005; None</span>' } elseif ($d.DMARC -match 'p=reject') { '<span class="igood">&#10003; reject</span>' } elseif ($d.DMARC -match 'p=quarantine') { '<span class="iwarn">~ quarantine</span>' } else { '<span class="ibad">&#9888; none</span>' }
            $mtaM = if ($d.MTASTS -and $d.MTASTS.Mode) { $d.MTASTS.Mode } elseif ($d.MTASTS -and $d.MTASTS.TxtRecord) { 'present' } else { $null }
            $mta  = if ($mtaM -eq 'enforce') { '<span class="igood">&#10003; enforce</span>' } elseif ($mtaM -eq 'testing') { '<span class="iwarn">~ testing</span>' } elseif ($mtaM -eq 'none') { '<span class="ibad">none</span>' } elseif ($mtaM) { "<span class=`"iwarn`">$mtaM</span>" } else { '<span class="ibad">&#10005;</span>' }
            $tls  = if ($d.TLSRPT) { '<span class="igood">&#10003;</span>' } else { '<span class="ibad">&#10005;</span>' }
            $dsec = if ($d.DNSSEC) { '<span class="igood">&#10003;</span>' } else { '<span class="ibad">&#10005;</span>' }
            $dmarcTxt = if ($d.DMARC) { $tt = if ($d.DMARC.Length -gt 52) { $d.DMARC.Substring(0,49)+'...' } else { $d.DMARC }; "<code class=`"icode`">$(hx $tt)</code>" } else { '&mdash;' }
            $dRows += "<tr><td><strong>$(hx $domain)</strong></td><td>$spf</td><td>$dkim</td><td>$dmarc</td><td>$dmarcTxt</td><td>$mta</td><td>$tls</td><td>$dsec</td></tr>"
        }
        $dnsInvHtml = "<div class=`"card mt`"><div class=`"card-hd`"><span class=`"card-title`">DNS Email Security</span></div><div class=`"tscroll`"><table class=`"itbl`"><thead><tr><th>Domain</th><th>SPF</th><th>DKIM</th><th>DMARC</th><th>DMARC Record</th><th>MTA-STS</th><th>TLS-RPT</th><th>DNSSEC</th></tr></thead><tbody>$dRows</tbody></table></div></div>"
    }

    # ── EXO Inventory ──────────────────────────────────────────────────────────
    $exoInvHtml = ''
    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if ($exoData -and $exoData.Success) {
        $eRows = ''
        $o = $exoData.Data.OrganizationConfig; $tr = $exoData.Data.TransportConfig
        $pr = $exoData.Data.MailboxProtocols;  $bp = $exoData.Data.AuditBypass; $sm = $exoData.Data.SharedMailboxes
        if ($o) {
            $audV = if ($o.AuditDisabled -eq $false) { '<span class="igood">&#10003; Enabled</span>' } else { '<span class="ibad">&#10005; Disabled</span>' }
            $lbV  = if ($o.CustomerLockBoxEnabled -eq $true) { '<span class="igood">&#10003; Enabled</span>' } else { '<span class="ibad">&#10005; Disabled</span>' }
            $maV  = if ($o.OAuth2ClientProfileEnabled -eq $true) { '<span class="igood">&#10003; Enabled</span>' } elseif ($o.OAuth2ClientProfileEnabled -eq $false) { '<span class="ibad">&#10005; Disabled</span>' } else { '<span class="iwarn">Unknown</span>' }
            $eRows += "<tr><td>Mailbox Audit</td><td>$audV</td></tr><tr><td>Customer Lockbox</td><td>$lbV</td></tr><tr><td>Modern Authentication (OAuth2)</td><td>$maV</td></tr>"
        }
        if ($tr) { $smtpV = if ($tr.SmtpClientAuthenticationDisabled -eq $true) { '<span class="igood">&#10003; Disabled</span>' } else { '<span class="ibad">&#10005; Enabled (risk)</span>' }; $eRows += "<tr><td>SMTP Client Authentication</td><td>$smtpV</td></tr>" }
        if ($pr) {
            $p3V = if ($pr.PopEnabled  -eq 0) { '<span class="igood">&#10003; 0 mailboxes</span>' } else { "<span class=`"ibad`">&#10005; $($pr.PopEnabled) mailboxes</span>" }
            $i4V = if ($pr.ImapEnabled -eq 0) { '<span class="igood">&#10003; 0 mailboxes</span>' } else { "<span class=`"ibad`">&#10005; $($pr.ImapEnabled) mailboxes</span>" }
            $eRows += "<tr><td>Total Mailboxes</td><td>$($pr.TotalMailboxes)</td></tr><tr><td>POP3</td><td>$p3V</td></tr><tr><td>IMAP</td><td>$i4V</td></tr><tr><td>ActiveSync</td><td>$($pr.ActiveSyncEnabled) mailboxes</td></tr>"
        }
        if ($bp) {
            $byV = if ($bp.BypassedCount -eq 0) { '<span class="igood">&#10003; None</span>' } else { "<span class=`"ibad`">&#10005; $($bp.BypassedCount) mailboxes</span>" }
            $eRows += "<tr><td>Audit Bypass</td><td>$byV</td></tr>"
        }
        if ($sm) {
            $siV = if ($sm.SignInEnabled -eq 0) { '<span class="igood">&#10003; All disabled</span>' } else { "<span class=`"ibad`">&#10005; $($sm.SignInEnabled) with sign-in enabled</span>" }
            $eRows += "<tr><td>Shared Mailboxes (total)</td><td>$($sm.Count)</td></tr><tr><td>Shared Mailbox Sign-in</td><td>$siV</td></tr>"
        }
        $exoInvHtml = "<div class=`"card mt`" style=`"max-width:560px`"><div class=`"card-hd`"><span class=`"card-title`">Exchange Online</span></div><table class=`"itbl i2`"><thead><tr><th>Setting</th><th>Value</th></tr></thead><tbody>$eRows</tbody></table></div>"
    }

    # ── CA Policy Inventory ────────────────────────────────────────────────────
    $caPolicyHtml = ''
    $caData = Get-NRGRawData -Key 'AAD-CAPolicies'
    if ($caData -and $caData.Success -and $caData.Data.Policies) {
        $caRows = ''
        foreach ($p in (@($caData.Data.Policies) | Sort-Object @{Expression={
            switch ($_.State) { 'enabled' { 0 }; 'enabledForReportingButNotEnforced' { 1 }; 'disabled' { 2 } }
        }}, DisplayName)) {
            $stH = switch ($p.State) {
                'enabled'                         { '<span class="igood">&#10003; Enforced</span>' }
                'enabledForReportingButNotEnforced' { '<span class="iwarn">&#9680; Report-only</span>' }
                'disabled'                        { '<span class="ioff">&#8212; Disabled</span>' }
                default                           { "<span class=`"iwarn`">$(hx $p.State)</span>" }
            }
            $cp = @()
            if ($p.Conditions.Users.IncludeUsers -contains 'All') { $cp += 'All users' }
            elseif ($p.Conditions.Users.IncludeRoles.Count -gt 0) { $cp += "$($p.Conditions.Users.IncludeRoles.Count) role(s)" }
            if ($p.Conditions.Applications.IncludeApplications -contains 'All') { $cp += 'All cloud apps' }
            if ($p.Conditions.ClientAppTypes -contains 'other') { $cp += 'Legacy auth' }
            if ($p.Conditions.SignInRiskLevels.Count -gt 0) { $cp += "Sign-in risk: $($p.Conditions.SignInRiskLevels -join '/')" }
            if ($p.Conditions.UserRiskLevels.Count -gt 0)   { $cp += "User risk: $($p.Conditions.UserRiskLevels -join '/')" }
            $condStr = if ($cp.Count -gt 0) { $cp -join ' &bull; ' } else { '&mdash;' }
            $gp = @()
            if ($p.GrantControls.BuiltInControls -contains 'mfa')             { $gp += 'Require MFA' }
            if ($p.GrantControls.BuiltInControls -contains 'block')           { $gp += 'Block' }
            if ($p.GrantControls.BuiltInControls -contains 'compliantDevice') { $gp += 'Compliant device' }
            if ($p.GrantControls.AuthenticationStrength)                      { $gp += "Auth strength: $($p.GrantControls.AuthenticationStrength.DisplayName)" }
            $grantStr = if ($gp.Count -gt 0) { hx ($gp -join ' + ') } else { '&mdash;' }
            $rowCls = if ($p.State -eq 'enabledForReportingButNotEnforced') { 'ca-ro' } elseif ($p.State -eq 'disabled') { 'ca-dis' } else { '' }
            $caRows += "<tr class=`"$rowCls`"><td class=`"ca-n`">$(hx $p.DisplayName)</td><td>$stH</td><td class=`"ca-c`">$condStr</td><td>$grantStr</td></tr>"
        }
        $caPolicyHtml = "<div class=`"card mt`"><div class=`"card-hd`"><span class=`"card-title`">Conditional Access Policies</span></div><div class=`"tscroll`"><table class=`"itbl`"><thead><tr><th>Policy Name</th><th style=`"width:110px`">State</th><th>Conditions</th><th>Grant</th></tr></thead><tbody>$caRows</tbody></table></div></div>"
    }

    # ── Defender Inventory ─────────────────────────────────────────────────────
    $defInvHtml = ''
    $defData = Get-NRGRawData -Key 'Defender'
    if ($defData -and $defData.Success) {
        $dRows = ''
        if ($defData.Data['SafeAttachments'].Available) {
            foreach ($p in @($defData.Data['SafeAttachments'].Policies | Where-Object { -not $_.IsDefault })) {
                $en  = if ($p.Enable -eq $true) { '<span class="igood">&#10003; Enabled</span>' } else { '<span class="ioff">Disabled</span>' }
                $act = hx $p.Action
                $dRows += "<tr><td><strong>$(hx $p.Name)</strong> <span class=`"isub`">Safe Attachments</span></td><td>$en</td><td>Action: $act</td></tr>"
            }
        }
        if ($defData.Data['SafeLinks'].Available) {
            foreach ($p in @($defData.Data['SafeLinks'].Policies | Where-Object { -not $_.IsDefault })) {
                $en  = if ($p.EnableSafeLinksForEmail -eq $true) { '<span class="igood">&#10003; Enabled</span>' } else { '<span class="ioff">Disabled</span>' }
                $ct  = if ($p.AllowClickThrough -eq $false) { '<span class="igood">Blocked</span>' } else { '<span class="iwarn">Allowed</span>' }
                $intl = if ($p.EnableForInternalSenders -eq $true) { '<span class="igood">&#10003;</span>' } else { '<span class="iwarn">&#10005;</span>' }
                $teams = if ($p.EnableSafeLinksForTeams -eq $true) { '<span class="igood">&#10003;</span>' } else { '<span class="iwarn">&#10005;</span>' }
                $dRows += "<tr><td><strong>$(hx $p.Name)</strong> <span class=`"isub`">Safe Links</span></td><td>$en</td><td>Click-through: $ct &nbsp; Internal senders: $intl &nbsp; Teams: $teams</td></tr>"
            }
        }
        if ($defData.Data['AntiPhishing'].Available) {
            foreach ($p in @($defData.Data['AntiPhishing'].Policies | Where-Object { -not $_.IsDefault })) {
                $en  = if ($p.Enabled) { '<span class="igood">&#10003; Enabled</span>' } else { '<span class="ioff">Disabled</span>' }
                $mi  = if ($p.EnableMailboxIntelligence -eq $true) { '<span class="igood">&#10003;</span>' } else { '<span class="ibad">&#10005;</span>' }
                $od  = if ($p.EnableOrganizationDomainsProtection -eq $true) { '<span class="igood">&#10003;</span>' } else { '<span class="ibad">&#10005;</span>' }
                $mip = if ($p.EnableMailboxIntelligenceProtection -eq $true) { '<span class="igood">&#10003;</span>' } else { '<span class="ibad">&#10005;</span>' }
                $dRows += "<tr><td><strong>$(hx $p.Name)</strong> <span class=`"isub`">Anti-Phishing</span></td><td>$en</td><td>Mailbox intel: $mi &nbsp; Org domain: $od &nbsp; Intel protection: $mip &nbsp; Threshold: $($p.PhishThresholdLevel)</td></tr>"
            }
        }
        if ($dRows) {
            $defInvHtml = "<div class=`"card mt`"><div class=`"card-hd`"><span class=`"card-title`">Defender for Office 365 Policies</span></div><table class=`"itbl`"><thead><tr><th>Policy</th><th style=`"width:110px`">Status</th><th>Configuration</th></tr></thead><tbody>$dRows</tbody></table></div>"
        }
    }

    # ── Escaped meta strings ───────────────────────────────────────────────────
    $tDom   = hx $Metadata.TenantDomain
    $cDisp  = hx $clientDisplay
    $dStr   = hx $Metadata.AssessmentDate
    $opStr  = hx $Metadata.Operator
    $cmpStr = hx $company
    $phStr  = hx $phone
    $wsStr  = hx $website
    $ver    = hx $Metadata.ToolVersion
    $logoH  = if ($logoUrl) { "<img src=`"$(hx $logoUrl)`" alt=`"$cmpStr`" class=`"logo`">" } else { "<span class=`"logo-t`">$cmpStr</span>" }
    $cbarI  = catBar 'Identity'       'Identity'
    $cbarE  = catBar 'Email Security' 'Email Security'
    $cbarD  = catBar 'Defender'       'Defender'

    # ── Assemble HTML ──────────────────────────────────────────────────────────
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
/* Header */
.hdr{background:linear-gradient(135deg,var(--P) 0%,#0d2147 100%);color:#fff;padding:36px 48px 30px;position:relative;overflow:hidden}
.hdr::before{content:'';position:absolute;inset:0;background-image:radial-gradient(circle at 75% 20%,rgba(232,119,34,.14) 0%,transparent 50%),radial-gradient(circle at 25% 80%,rgba(74,123,166,.1) 0%,transparent 50%);pointer-events:none}
.hdr-inner{display:flex;align-items:flex-start;justify-content:space-between;gap:24px;position:relative;z-index:1}
.logo{height:34px;filter:brightness(0) invert(1)}
.logo-t{font-size:1.15rem;font-weight:800;letter-spacing:-.02em;color:rgba(255,255,255,.95)}
.hdr-eye{font-size:.62rem;text-transform:uppercase;letter-spacing:.15em;color:var(--S);font-weight:700;margin-bottom:7px}
.hdr-client{font-size:2rem;font-weight:900;letter-spacing:-.03em;color:#fff;line-height:1.05}
.hdr-meta{display:flex;gap:18px;flex-wrap:wrap;margin-top:10px;font-size:.77rem;color:rgba(255,255,255,.5)}
.hdr-meta strong{color:rgba(255,255,255,.82);font-weight:600}
.hdr-right{text-align:right;flex-shrink:0}
.ver{font-size:.62rem;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.18);padding:3px 9px;border-radius:20px;color:rgba(255,255,255,.6);letter-spacing:.05em;display:inline-block;margin-bottom:10px}
.abar{height:3px;background:linear-gradient(90deg,var(--S) 0%,var(--A) 55%,transparent 100%)}
/* Layout */
.cnt{padding:26px 48px 48px}
.card{background:var(--card);border-radius:var(--r);box-shadow:var(--sh);overflow:hidden;border:1px solid var(--bdr)}
.mt{margin-top:20px}
.card-hd{padding:14px 22px 12px;border-bottom:1px solid var(--bdr);display:flex;align-items:center;justify-content:space-between;background:linear-gradient(to bottom,#fafbfd,#f4f6fa)}
.card-title{font-size:.68rem;font-weight:800;text-transform:uppercase;letter-spacing:.11em;color:var(--P)}
.cat-pill{font-size:.7rem;font-weight:700;padding:2px 9px;border-radius:20px;border:1px solid}
/* Dashboard */
.dash{display:grid;grid-template-columns:200px 1fr 220px}
.dash>*{padding:24px 20px}
.dv{border-right:1px solid var(--bdr)}
/* Score ring */
.score-wrap{display:flex;flex-direction:column;align-items:center;justify-content:center}
.ring-trk{fill:none;stroke:#e4e9f2;stroke-width:10}
.ring-fill{fill:none;stroke:var(--S);stroke-width:10;stroke-linecap:round;stroke-dasharray:$circ;stroke-dashoffset:$circ;animation:rfill 1.4s cubic-bezier(.4,0,.2,1) .15s forwards}
@keyframes rfill{to{stroke-dashoffset:$offset}}
.score-c{text-align:center;margin-top:10px}
.score-n{font-size:2.6rem;font-weight:900;color:var(--P);letter-spacing:-.04em;line-height:1}
.score-s{font-size:.62rem;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}
.posture{display:inline-block;margin-top:8px;padding:4px 13px;border-radius:20px;font-size:.7rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em;background:${pColor}18;color:$pColor;border:1.5px solid ${pColor}3a}
/* Stats */
.stats{display:flex;flex-direction:column;justify-content:center;gap:10px;padding-left:22px}
.sr{display:flex;align-items:center;gap:8px}
.sr-lbl{font-size:.64rem;text-transform:uppercase;letter-spacing:.07em;color:var(--mut);min-width:52px;font-weight:700}
.sr-track{flex:1;height:5px;background:#e8edf5;border-radius:3px;overflow:hidden}
.sr-fill{height:100%;border-radius:3px}
.sr-num{font-size:.9rem;font-weight:800;min-width:22px;text-align:right}
.sg .sr-num,.sg .sr-fill{color:var(--gap);background:var(--gap)}
.sw .sr-num,.sw .sr-fill{color:var(--warn);background:var(--warn)}
.sp .sr-num,.sp .sr-fill{color:var(--pass);background:var(--pass)}
.sn .sr-num,.sn .sr-fill{color:var(--na);background:var(--na)}
.st .sr-num{color:var(--txt)}
/* Cat bars */
.cats{display:flex;flex-direction:column;gap:8px;justify-content:center}
.cats-t,.conn-t{font-size:.62rem;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);font-weight:700;margin-bottom:2px}
.cbar-hd{display:flex;justify-content:space-between;margin-bottom:2px}
.cbar-lbl{font-size:.73rem;font-weight:600;color:var(--txt)}
.cbar-num{font-size:.73rem;font-weight:800}
.cbar-track{height:6px;background:#e4e9f2;border-radius:3px;overflow:hidden}
.cbar-fill{height:100%;border-radius:3px}
/* Connections */
.conn-grid{display:flex;flex-direction:column;gap:4px;margin-top:2px}
.conn{display:flex;align-items:center;gap:6px;padding:4px 8px;border-radius:5px;font-size:.73rem;font-weight:600}
.cok{background:#f0fdf4;color:#166534}
.coff{background:#fef2f2;color:#991b1b}
/* Scope */
.scope-body{display:grid;grid-template-columns:1fr 1fr 1.3fr;gap:0;padding:0}
.scope-col{padding:20px 22px;border-right:1px solid var(--bdr)}
.scope-col:last-child{border-right:none}
.scope-head{font-size:.64rem;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);font-weight:800;margin-bottom:12px}
.scope-item{display:flex;align-items:flex-start;gap:9px;margin-bottom:9px}
.scope-ico{font-size:.85rem;padding-top:1px;flex-shrink:0}
.scope-covered .scope-ico{color:var(--pass)}
.scope-pending .scope-ico{color:var(--mut)}
.scope-name{font-size:.8rem;font-weight:600;color:var(--txt)}
.scope-cnt{font-size:.7rem;color:var(--mut)}
.scope-method{}
.method-formula{background:#f8fafd;border:1px solid var(--bdr);border-radius:6px;padding:10px 14px;margin-bottom:12px;text-align:center}
.method-eq{font-size:.8rem;font-weight:700;color:var(--P);font-family:'Consolas','Courier New',monospace}
.method-rows{display:flex;flex-direction:column;gap:5px;margin-bottom:12px}
.method-row{display:flex;align-items:center;gap:9px;font-size:.75rem;color:var(--mut)}
.method-scale{display:flex;gap:10px;flex-wrap:wrap}
.scale-item{font-size:.73rem}
/* Priority actions */
.acts{padding:14px 20px;display:flex;flex-direction:column;gap:6px}
.act{display:flex;align-items:flex-start;gap:11px;padding:10px 13px;border-radius:7px;border-left:4px solid}
.ac{background:#fff5f5;border-color:var(--gap)}
.ah{background:#fffbf0;border-color:var(--warn)}
.act-n{font-size:.62rem;font-weight:900;color:var(--mut);min-width:14px;padding-top:2px}
.act-sv{font-size:.6rem;font-weight:900;text-transform:uppercase;padding:2px 6px;border-radius:3px;white-space:nowrap;flex-shrink:0;margin-top:2px}
.ac .act-sv{background:var(--gap);color:#fff}
.ah .act-sv{background:var(--warn);color:#fff}
.act-t{font-weight:700;font-size:.82rem;color:var(--txt);line-height:1.3}
.act-d{font-size:.74rem;color:var(--mut);margin-top:2px;line-height:1.4}
/* Identity inventory */
.inv-body{padding:18px 22px;display:flex;flex-direction:column;gap:18px}
.subsec-title{font-size:.64rem;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);font-weight:800;margin-bottom:8px}
.user-stats{display:grid;grid-template-columns:repeat(5,1fr);gap:10px}
.ustat{background:#f8fafd;border:1px solid var(--bdr);border-radius:8px;padding:12px 14px;text-align:center}
.ustat-n{font-size:1.6rem;font-weight:900;color:var(--P);letter-spacing:-.02em;line-height:1}
.ustat-l{font-size:.65rem;text-transform:uppercase;letter-spacing:.07em;color:var(--mut);font-weight:700;margin-top:3px}
/* MFA bar */
.mfa-section{}
.mfa-header{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:5px}
.mfa-title{font-size:.64rem;text-transform:uppercase;letter-spacing:.1em;color:var(--mut);font-weight:800}
.mfa-pct{font-size:1.1rem;font-weight:900;letter-spacing:-.02em}
.mfa-track{height:10px;background:#e8edf5;border-radius:5px;overflow:hidden;margin-bottom:6px}
.mfa-fill{height:100%;border-radius:5px;transition:width 1s ease .3s}
.mfa-detail{font-size:.77rem;color:var(--mut);line-height:1.45}
/* Admin table */
.adm-tbl{}
.adm-ga{background:#fff9f0}
.adm-name{font-weight:600}
.adm-upn{font-size:.78rem;color:var(--mut);font-family:'Consolas','Courier New',monospace}
.adm-last{font-size:.78rem;color:var(--mut)}
.role-tag{font-size:.65rem;font-weight:800;text-transform:uppercase;letter-spacing:.04em;padding:2px 7px;border-radius:4px;background:#eef2ff;color:#3730a3;white-space:nowrap}
/* PIM grid */
.pim-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}
.pim-card{background:#f8fafd;border:1px solid var(--bdr);border-radius:8px;padding:12px 14px;text-align:center}
.pim-n{font-size:1.6rem;font-weight:900;letter-spacing:-.02em;line-height:1}
.pim-l{font-size:.65rem;text-transform:uppercase;letter-spacing:.07em;color:var(--mut);font-weight:700;margin-top:3px}
/* Findings table */
.ft{width:100%;border-collapse:collapse;font-size:.83rem}
.fth th{padding:8px 12px;background:#f4f6fa;font-size:.62rem;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);font-weight:700;border-bottom:2px solid var(--bdr);text-align:left}
.fr{border-bottom:1px solid #f3f5f9}
.fr:last-of-type{border-bottom:none}
.fr td{padding:9px 12px;vertical-align:top}
.exp{cursor:pointer}
.exp:hover{background:#f9fafc}
.rg{border-left:3px solid var(--gap) !important}
.rw{border-left:3px solid var(--warn) !important}
.rp{border-left:3px solid var(--pass) !important}
.rn{border-left:3px solid #d1d5db !important}
.td1{width:90px}
.td2{width:80px}
.td3{font-weight:600;color:var(--txt)}
.td4{color:var(--mut);font-size:.77rem}
.f-title{font-weight:600;color:var(--txt);line-height:1.3;margin-bottom:2px}
.f-cv{font-size:.72rem;color:var(--mut);font-style:italic;line-height:1.3}
.extr td{background:#f8fafd;padding:0}
.exbody{padding:12px 16px;border-top:1px solid #eaecf3}
.ex-d{color:#374151;margin-bottom:8px;font-size:.82rem;line-height:1.55}
.ex-r{display:flex;gap:8px;margin-bottom:5px;font-size:.79rem;align-items:flex-start}
.ex-l{font-weight:800;color:#374151;min-width:84px;flex-shrink:0;font-size:.68rem;text-transform:uppercase;letter-spacing:.04em;padding-top:3px}
.ex-v{color:#4b5563;flex:1;line-height:1.45}
.ex-rem .ex-v{color:#1d4ed8}
.ex-lnk{color:var(--A);font-weight:700;margin-left:7px;font-size:.73rem}
/* ATT&CK tags */
.ttp-tag{font-size:.65rem;padding:2px 6px;border-radius:3px;background:#fef2f2;color:#991b1b;font-weight:700;border:1px solid #fecaca;display:inline-block;margin:1px;text-decoration:none}
.ttp-tag:hover{background:#fee2e2;text-decoration:none}
.ttp-mini{font-size:.62rem;padding:1px 5px;border-radius:3px;background:#fff1f0;color:#b91c1c;font-weight:700;border:1px solid #fecaca;display:inline-block;margin-left:4px;vertical-align:middle}
.ttptags{display:flex;flex-wrap:wrap;gap:3px}
/* Framework tags */
.fwtags{display:flex;flex-wrap:wrap;gap:3px}
.fw-tag{font-size:.64rem;padding:2px 6px;border-radius:3px;background:#eef2ff;color:#3730a3;font-weight:700;display:inline-block}
/* State/severity badges */
.b{display:inline-block;padding:3px 9px;border-radius:5px;font-size:.7rem;font-weight:800;white-space:nowrap;letter-spacing:.02em}
.bp{background:#f0fdf4;color:#166534;border:1px solid #bbf7d0}
.bw{background:#fffbeb;color:#92400e;border:1px solid #fde68a}
.bg{background:#fef2f2;color:#991b1b;border:1px solid #fecaca}
.bn{background:#f9fafb;color:#6b7280;border:1px solid #e5e7eb}
.sv{display:inline-block;padding:2px 7px;border-radius:4px;font-size:.67rem;font-weight:800;white-space:nowrap;letter-spacing:.03em}
.svc{background:var(--gap);color:#fff}
.svh{background:#ea580c;color:#fff}
.svm{background:var(--warn);color:#fff}
.svl{background:#65a30d;color:#fff}
.svi{background:#e5e7eb;color:#374151}
/* Roadmap */
.rm-wrap{padding:6px 20px 20px;display:flex;flex-direction:column;gap:18px}
.rmg{}
.rmgl{font-size:.68rem;font-weight:900;text-transform:uppercase;letter-spacing:.1em;padding:5px 0 8px;border-bottom:2px solid var(--bdr);margin-bottom:8px;display:flex;align-items:center;gap:7px}
.efq{color:#059669}.efs{color:#d97706}.efx{color:#7c3aed}
.rmi{padding:8px 12px;border-radius:6px;border-left:3px solid;margin-bottom:6px;background:#fafbfc}
.rmg-gap{border-color:var(--gap)}.rmg-warn{border-color:var(--warn)}
.rmi-hd{display:flex;align-items:center;gap:6px;margin-bottom:3px;flex-wrap:wrap}
.rmi-t{font-weight:700;font-size:.82rem;color:var(--txt)}
.rmi-r{font-size:.77rem;color:#374151;line-height:1.45;padding-left:2px}
/* Inventory */
.tscroll{overflow-x:auto}
.itbl{width:100%;border-collapse:collapse;font-size:.8rem}
.itbl thead tr{background:#f4f6fa}
.itbl th{padding:8px 12px;text-align:left;font-size:.63rem;text-transform:uppercase;letter-spacing:.08em;color:var(--mut);font-weight:700;border-bottom:2px solid var(--bdr)}
.itbl td{padding:8px 12px;border-bottom:1px solid #f3f5f9;vertical-align:middle}
.itbl tbody tr:last-child td{border-bottom:none}
.itbl tbody tr:hover{background:#fafbfc}
.i2{max-width:480px}
.igood{color:#166534;font-weight:700}.iwarn{color:#92400e;font-weight:700}.ibad{color:#991b1b;font-weight:700}.ioff{color:var(--mut);font-weight:600}
.isub{font-size:.68rem;color:var(--mut);margin-left:6px}
.icode{font-family:'Cascadia Code','Consolas','Courier New',monospace;font-size:.72rem;color:#374151;background:#f3f4f6;padding:1px 5px;border-radius:3px}
.ca-n{font-weight:600;max-width:220px}
.ca-c{font-size:.75rem;color:var(--mut)}
.ca-ro{background:#fffdf0}
.ca-dis{background:#fafafa;opacity:.7}
/* Footer */
.ftr{background:var(--P);color:rgba(255,255,255,.55);padding:16px 48px;display:flex;justify-content:space-between;font-size:.74rem;flex-wrap:wrap;gap:8px;margin-top:32px}
.ftr strong{color:#fff}
/* Print */
@media print{
  *{-webkit-print-color-adjust:exact !important;print-color-adjust:exact !important}
  body{background:#fff;font-size:12px}
  .wrap{max-width:none}
  .cnt{padding:16px 28px 28px}
  .hdr{padding:20px 28px 16px}
  .ftr{padding:12px 28px;margin-top:18px}
  .card{box-shadow:none;break-inside:avoid;border:1px solid #dde3ec}
  .extr{display:table-row !important}
  .exp{cursor:default}
  .dash{grid-template-columns:160px 1fr 200px}
  .scope-body{grid-template-columns:1fr 1fr 1fr}
  .user-stats{grid-template-columns:repeat(5,1fr)}
  .pim-grid{grid-template-columns:repeat(4,1fr)}
  .ring-fill{animation:none !important;stroke-dashoffset:$offset}
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
        $(if ($opStr) { "<span><strong>Operator</strong> $opStr</span>" })
      </div>
    </div>
    <div class="hdr-right">
      <div class="ver">NRG-Assessment v$ver</div>
      $logoH
    </div>
  </div>
</div>
<div class="abar"></div>

<div class="cnt">

<!-- Dashboard -->
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
      <div class="sr st"><span class="sr-lbl">Total</span><div class="sr-track"><div class="sr-fill" style="width:100%;background:#cbd5e1"></div></div><span class="sr-num">$total</span></div>
    </div>
    <div class="cats">
      <div class="cats-t">Score by Category</div>
$cbarI
$cbarE
$cbarD
      <div class="conn-t" style="margin-top:12px">Service Connections</div>
      <div class="conn-grid">$connHtml</div>
    </div>
  </div>
</div>

<!-- Scope + Methodology -->
$scopeHtml

<!-- Priority Actions -->
$(if ($actsHtml) { "<div class=`"card mt`"><div class=`"card-hd`"><span class=`"card-title`">Priority Actions</span></div><div class=`"acts`">$actsHtml</div></div>" })

<!-- Identity Inventory -->
$identityHtml

<!-- Findings -->
$findHtml

<!-- Remediation Roadmap -->
$roadmapHtml

<!-- DNS Inventory -->
$dnsInvHtml

<!-- EXO Inventory -->
$exoInvHtml

<!-- CA Policies -->
$caPolicyHtml

<!-- Defender -->
$defInvHtml

</div>

<div class="ftr">
  <span>Prepared by <strong>$cmpStr</strong>$(if ($phStr) { " &bull; $phStr" })$(if ($wsStr) { " &bull; $wsStr" })</span>
  <span>Read-only assessment &mdash; no configuration changes were made</span>
</div>

</div>
<script>
function toggle(tr){var n=tr.nextElementSibling;if(n&&n.classList.contains('extr')){n.style.display=n.style.display===''||n.style.display==='table-row'?'none':'table-row'}}
document.querySelectorAll('.extr').forEach(function(r){r.style.display='none'});
</script>
</body>
</html>
"@

    $html | Out-File -FilePath $OutputPath -Encoding utf8
}