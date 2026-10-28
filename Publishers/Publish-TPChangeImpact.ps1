#Requires -Version 7.0
#
# Publish-TPChangeImpact.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Render the change-impact model (Get-TPChangeImpact) as
#   <base>-change-impact.html / .md: what can be fixed now, what needs planning,
#   and what could break accounts, with the accounts named for each risky
#   change. Self-contained HTML in the shared report theme, plus Markdown.
#
# Rendering rules (pinned by TP.ChangeImpact.Tests.ps1):
#   - Every evidence block shows its status in words: Named, None found
#     (complete read), Not established (incomplete read), Not read. "None
#     found" always carries the sentence that it does not mean nothing breaks.
#   - At most -ShowAccounts accounts per block are printed; the rest are counted
#     and kept in the results JSON.
#   - No hour, day or week figure, no price, and nothing says "compliant".
#   - Every string is escaped for its format; the page loads nothing.
#
# Inputs:  -Model, -OutputPath (file path of the .html; the .md sits beside
#          it), -Brand (defaults to the loaded profile), -GeneratedAt (tests).
# Data consumed: the model only. Graph scopes / cmdlets used: none.

function Publish-TPChangeImpact {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [object] $Model,
        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
            return $true
        })]
        [string] $OutputPath,
        [AllowNull()] [object] $Brand,
        [string] $ToolVersion = '',
        [ValidateRange(1, 1000)] [int] $ShowAccounts = 25,
        [datetime] $GeneratedAt = [datetime]::UtcNow
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not (Get-Command ConvertTo-TPHtmlSafe -ErrorAction SilentlyContinue)) {
        throw 'ConvertTo-TPHtmlSafe is not loaded. Refusing to generate the change-impact report without HTML escaping.'
    }
    if ((Get-TPObjectField -Item $Model -Key 'Available' -Default $false) -ne $true) {
        throw "Change-impact report not generated: $([string](Get-TPObjectField -Item $Model -Key 'Note' -Default 'not available'))"
    }

    function EscMd { param([object] $v) ConvertTo-TPMarkdownSafe $v }   # one Markdown rule for the whole tool
    function Esc { param([object] $v) ConvertTo-TPHtmlSafe $v }

    if (-not $PSBoundParameters.ContainsKey('Brand')) {
        $Brand = if ((Get-Variable -Name TPBrand -Scope Script -ErrorAction SilentlyContinue)) { $script:TPBrand } else { $null }
    }
    if (-not $ToolVersion) { $ToolVersion = [string]$Model.ToolVersion }
    $theme = Get-TPReportTheme -Brand $Brand

    $htmlPath = if ($OutputPath -match '\.html\z') { $OutputPath } else { "$OutputPath.html" }
    $mdPath = [System.IO.Path]::ChangeExtension($htmlPath, '.md')
    $dir = Split-Path -Parent $htmlPath
    if ($dir) { $null = [System.IO.Directory]::CreateDirectory($dir) }

    $tenantText = if ($Model.TenantDomain) { $Model.TenantDomain } else { 'this tenant' }
    $sevTone = @{ Critical = 'Bad'; High = 'Warn'; Medium = 'Info'; Low = 'Neutral'; Informational = 'Neutral' }
    $statusText = @{ Named = 'Named'; NoneFound = 'None found'; NotEstablished = 'Not established'; NotRead = 'Not read' }
    $statusTone = @{ Named = 'Bad'; NoneFound = 'Good'; NotEstablished = 'Warn'; NotRead = 'Neutral' }
    $noneFoundCaveat = 'None found in what the tool read; this does not mean nothing can break.'
    $sum = $Model.Summary
    $tiers = [ordered]@{
        ImplementNow       = @{ Title = 'Implement now'; Id = 'implement-now' }
        NeedsPlanning      = @{ Title = 'Needs planning'; Id = 'needs-planning' }
        CouldBreakAccounts = @{ Title = 'Could break accounts'; Id = 'could-break-accounts' }
    }

    $accountName = {
        param($a)
        $parts = @(@([string]$a.DisplayName, [string]$a.UserPrincipalName) | Where-Object { $_ })
        if ($parts.Count -eq 2 -and $parts[0] -ne $parts[1]) { return "$($parts[0]) <$($parts[1])>" }
        if ($parts.Count -ge 1) { return $parts[0] }
        if ($a.ObjectId) { return "Object $($a.ObjectId)" }
        return 'Unnamed account'
    }

    # ── HTML pieces ──
    $blockHtml = {
        param($b)
        $st = [string]$b.Status
        $html = '<div class="tp-card" style="margin:10px 0"><div class="tp-card-head"><div class="tp-card-title">' + (Esc $b.Label) + '</div>' +
            (New-TPThemePill -Status $(if ($b.Role -eq 'MustExclude') { 'Info' } else { $statusTone[$st] }) -Text $(if ($b.Role -eq 'MustExclude' -and $st -eq 'Named') { "$($b.Count) to exclude" } elseif ($st -eq 'Named') { "$($b.Count) account(s)" } else { $statusText[$st] })) + '</div>'
        $accts = @($b.Accounts | Where-Object { $null -ne $_ } | Select-Object -First $ShowAccounts)
        if ($accts.Count) {
            $html += '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Account</th><th>What the run saw</th></tr></thead><tbody>'
            foreach ($a in $accts) { $html += '<tr><td class="tp-mono tp-small">' + (Esc (& $accountName $a)) + '</td><td class="tp-small">' + (Esc $a.Detail) + '</td></tr>' }
            $html += '</tbody></table></div>'
            $more = [int]$b.Count - $accts.Count
            if ($more -gt 0) { $html += '<p class="tp-note">' + (Esc "And $more more; the results file lists them.") + '</p>' }
        }
        if ($st -eq 'NoneFound' -and $b.Role -ne 'MustExclude') { $html += '<p class="tp-note">' + (Esc $noneFoundCaveat) + '</p>' }
        if ($b.Note) { $html += '<p class="tp-note">' + (Esc $b.Note) + '</p>' }
        return $html + '</div>'
    }
    $itemHead = {
        param($it)
        '<div class="tp-card-head"><div><span class="tp-mono">' + (Esc $it.ControlId) + '</span> <span class="tp-card-title">' + (Esc $it.Title) + '</span></div>' +
            (New-TPThemePill -Status $sevTone[[string]$it.Severity] -Text $it.Severity) + '</div>' +
            '<div class="tp-row tp-small"><span class="tp-chip">' + (Esc $it.State) + '</span><span class="tp-chip">Effort: ' + (Esc $it.Effort) + '</span></div>'
    }
    $simpleItem = {
        param($it)
        $html = '<li class="tp-card" style="list-style:none;margin:0 0 10px">' + (& $itemHead $it) + '<p class="tp-small">' + (Esc $it.ImpactSummary) + '</p>'
        if ($it.UsersNotice) { $html += '<p class="tp-small"><strong>Users notice:</strong> ' + (Esc $it.UsersNotice) + '</p>' }
        if ($it.Remediation) { $html += '<details><summary>What to change</summary><p class="tp-small">' + (Esc $it.Remediation) + '</p></details>' }
        return $html + '</li>'
    }
    $riskItem = {
        param($it)
        $html = '<div class="tp-card" style="margin:0 0 16px" id="' + (Esc ('ci-' + ($it.ControlId -replace '[^A-Za-z0-9-]', '-'))) + '">' + (& $itemHead $it)
        $html += '<p><strong>What can break:</strong> ' + (Esc $it.Why) + '</p>'
        $blocks = @($it.Evidence | Where-Object { $null -ne $_ })
        if ($blocks.Count -eq 0) { $html += '<p class="tp-note">The tool reads nothing that names the accounts this change affects.</p>' }
        foreach ($b in $blocks) { $html += & $blockHtml $b }
        if ($it.Unseen) { $html += '<p class="tp-small"><strong>Not visible to the tool:</strong> ' + (Esc $it.Unseen) + '</p>' }
        if ($null -ne $it.EmergencyAccess) {
            $html += '<p class="tp-small"><strong>Before turning it on:</strong> ' + (Esc $(if ($it.EmergencyAccess.Status -eq 'Named') { "exclude the $($it.EmergencyAccess.Count) emergency-access account(s) on record (listed at the end of this report)." } else { 'no emergency-access account is on record; confirm one exists and is excluded.' })) + '</p>'
        }
        if ($it.Reversible) { $html += '<p class="tp-small tp-muted"><strong>Reversible:</strong> ' + (Esc $it.Reversible) + '</p>' }
        if ($it.Remediation) { $html += '<details><summary>What to change</summary><p class="tp-small">' + (Esc $it.Remediation) + '</p></details>' }
        return $html + '</div>'
    }

    $sb = [System.Text.StringBuilder]::new()
    $chips = @("Assessed $($Model.AssessedAt)")
    if ($Model.RunScope -ne 'Full') { $chips += "$($Model.RunScope) run" }
    $null = $sb.Append((New-TPThemeMasthead -CompanyName $theme.CompanyName -Title 'What fixing it would break' -Subtitle "Change impact for ${tenantText}: what can be fixed now, what needs planning, and what could lock accounts out." -Chips $chips))

    $kpis = '<div class="tp-kpis">' +
        (New-TPThemeKpi -Label 'Implement now' -Value $sum.ImplementNow -Note 'Invisible to users' -PillHtml (New-TPThemePill -Status Good -Text 'Low risk')) +
        (New-TPThemeKpi -Label 'Needs planning' -Value $sum.NeedsPlanning -Note 'Someone will notice' -PillHtml (New-TPThemePill -Status Warn -Text 'Plan')) +
        (New-TPThemeKpi -Label 'Could break accounts' -Value $sum.CouldBreakAccounts -Note "$($sum.AccountsNamed) account(s) named" -PillHtml (New-TPThemePill -Status Bad -Text 'Evaluate')) +
        (New-TPThemeKpi -Label 'License decisions' -Value $sum.LicenseDecision -Note 'Not in the three lists') + '</div>'
    $summaryHtml = $kpis + '<div class="tp-banner tp-banner--info">' + (Esc $Model.Statement) + '</div>'
    if ($Model.ScopeNotice) { $summaryHtml += '<p class="tp-note">' + (Esc $Model.ScopeNotice) + '</p>' }
    $null = $sb.Append((New-TPThemeSection -Id 'summary' -Title 'Summary' -Kicker "Open items sorted by what fixing them disturbs" -BodyHtml $summaryHtml -First))

    foreach ($k in $tiers.Keys) {
        $items = @($Model[$k] | Where-Object { $null -ne $_ })
        $body = '<p class="tp-note">' + (Esc $Model.TierNotes[$k]) + '</p>'
        if ($items.Count -eq 0) { $body += '<p class="tp-note">Nothing in this list.</p>' }
        elseif ($k -eq 'CouldBreakAccounts') { foreach ($it in $items) { $body += & $riskItem $it } }
        else { $body += '<ul class="tp-list" style="padding:0">' + ((@($items | ForEach-Object { & $simpleItem $_ })) -join '') + '</ul>' }
        $null = $sb.Append((New-TPThemeSection -Id $tiers[$k].Id -Title $tiers[$k].Title -Kicker "$($items.Count) item(s)" -BodyHtml $body))
    }

    $lic = @($Model.LicenseDecision | Where-Object { $null -ne $_ })
    $licHtml = '<p class="tp-note">' + (Esc $Model.TierNotes.LicenseDecision) + '</p>'
    if ($lic.Count -eq 0) { $licHtml += '<p class="tp-note">No open item needs a license decision.</p>' }
    else {
        $licHtml += '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Control</th><th>Severity</th><th>Needs</th><th>Why it is here</th></tr></thead><tbody>'
        foreach ($it in $lic) { $licHtml += '<tr><td><span class="tp-mono">' + (Esc $it.ControlId) + '</span><div>' + (Esc $it.Title) + '</div></td><td>' + (New-TPThemePill -Status $sevTone[[string]$it.Severity] -Text $it.Severity) + '</td><td>' + (Esc $(if ($it.License) { $it.License } else { 'Not stated' })) + '</td><td class="tp-small">' + (Esc $it.Reason) + '</td></tr>' }
        $licHtml += '</tbody></table></div>'
    }
    $null = $sb.Append((New-TPThemeSection -Id 'license-decisions' -Title 'Needs a license decision' -Kicker "$($lic.Count) item(s)" -BodyHtml $licHtml))
    $null = $sb.Append((New-TPThemeSection -Id 'emergency-access' -Title 'Emergency-access accounts' -Kicker 'Exclude these from every new sign-in policy' -BodyHtml (& $blockHtml $Model.EmergencyAccess)))

    $null = $sb.Append((New-TPThemeFooter -GeneratedAt $GeneratedAt -ToolVersion $ToolVersion -CompanyName $theme.CompanyName -Note 'What the tool observed at the time shown'))
    $html = New-TPThemeDocument -Title "Change impact: $tenantText" -Theme $theme -BodyHtml $sb.ToString()

    # ── Markdown ──
    $md = [System.Text.StringBuilder]::new()
    $mdBlock = {
        param($b)
        $st = [string]$b.Status
        $head = if ($b.Role -eq 'MustExclude' -and $st -eq 'Named') { "$($b.Count) to exclude" } elseif ($st -eq 'Named') { "$($b.Count) account(s)" } else { $statusText[$st] }
        $null = $md.AppendLine("- **$(EscMd $b.Label)**: $(EscMd $head)")
        foreach ($a in @($b.Accounts | Where-Object { $null -ne $_ } | Select-Object -First $ShowAccounts)) {
            $null = $md.AppendLine("  - $(EscMd (& $accountName $a)): $(EscMd $a.Detail)")
        }
        $more = [int]$b.Count - [math]::Min([int]$b.Count, $ShowAccounts)
        if ($more -gt 0) { $null = $md.AppendLine("  - And $more more; the results file lists them.") }
        if ($st -eq 'NoneFound' -and $b.Role -ne 'MustExclude') { $null = $md.AppendLine("  - _$(EscMd $noneFoundCaveat)_") }
        if ($b.Note) { $null = $md.AppendLine("  - _$(EscMd $b.Note)_") }
    }
    $null = $md.AppendLine("# What fixing it would break: $(EscMd $tenantText)")
    $null = $md.AppendLine()
    $null = $md.AppendLine("$(EscMd $theme.CompanyName) &middot; assessed $(EscMd $Model.AssessedAt)")
    $null = $md.AppendLine()
    $null = $md.AppendLine("> $(EscMd $Model.Statement)")
    $null = $md.AppendLine()
    if ($Model.ScopeNotice) { $null = $md.AppendLine((EscMd $Model.ScopeNotice)); $null = $md.AppendLine() }
    $null = $md.AppendLine('| Implement now | Needs planning | Could break accounts | Accounts named | License decisions |')
    $null = $md.AppendLine('|---|---|---|---|---|')
    $null = $md.AppendLine("| $($sum.ImplementNow) | $($sum.NeedsPlanning) | $($sum.CouldBreakAccounts) | $($sum.AccountsNamed) | $($sum.LicenseDecision) |")
    foreach ($k in $tiers.Keys) {
        $items = @($Model[$k] | Where-Object { $null -ne $_ })
        $null = $md.AppendLine()
        $null = $md.AppendLine("## $($tiers[$k].Title)")
        $null = $md.AppendLine()
        $null = $md.AppendLine("_$(EscMd $Model.TierNotes[$k])_")
        $null = $md.AppendLine()
        if ($items.Count -eq 0) { $null = $md.AppendLine('Nothing in this list.'); continue }
        foreach ($it in $items) {
            if ($k -ne 'CouldBreakAccounts') {
                $null = $md.AppendLine("- ``$($it.ControlId)`` **$(EscMd $it.Title)** ($(EscMd $it.Severity), $(EscMd $it.State)). Effort: $(EscMd $it.Effort). $(EscMd $it.ImpactSummary)")
                continue
            }
            $null = $md.AppendLine("### ``$($it.ControlId)`` $(EscMd $it.Title)")
            $null = $md.AppendLine()
            $null = $md.AppendLine("$(EscMd $it.Severity), $(EscMd $it.State). Effort: $(EscMd $it.Effort).")
            $null = $md.AppendLine()
            $null = $md.AppendLine("**What can break:** $(EscMd $it.Why)")
            $null = $md.AppendLine()
            $blocks = @($it.Evidence | Where-Object { $null -ne $_ })
            if ($blocks.Count -eq 0) { $null = $md.AppendLine('The tool reads nothing that names the accounts this change affects.') }
            foreach ($b in $blocks) { & $mdBlock $b }
            if ($it.Unseen) { $null = $md.AppendLine(); $null = $md.AppendLine("**Not visible to the tool:** $(EscMd $it.Unseen)") }
            if ($null -ne $it.EmergencyAccess) {
                $null = $md.AppendLine()
                $null = $md.AppendLine("**Before turning it on:** $(EscMd $(if ($it.EmergencyAccess.Status -eq 'Named') { "exclude the $($it.EmergencyAccess.Count) emergency-access account(s) on record (listed at the end of this report)." } else { 'no emergency-access account is on record; confirm one exists and is excluded.' }))")
            }
            if ($it.Reversible) { $null = $md.AppendLine(); $null = $md.AppendLine("_Reversible: $(EscMd $it.Reversible)_") }
            $null = $md.AppendLine()
        }
    }
    $null = $md.AppendLine()
    $null = $md.AppendLine('## Needs a license decision')
    $null = $md.AppendLine()
    if ($lic.Count -eq 0) { $null = $md.AppendLine('No open item needs a license decision.') }
    else {
        $null = $md.AppendLine('| Control | Title | Severity | Needs | Why it is here |')
        $null = $md.AppendLine('|---|---|---|---|---|')
        foreach ($it in $lic) { $null = $md.AppendLine("| ``$($it.ControlId)`` | $(EscMd $it.Title) | $(EscMd $it.Severity) | $(EscMd $(if ($it.License) { $it.License } else { 'Not stated' })) | $(EscMd $it.Reason) |") }
    }
    $null = $md.AppendLine()
    $null = $md.AppendLine('## Emergency-access accounts')
    $null = $md.AppendLine()
    & $mdBlock $Model.EmergencyAccess
    $null = $md.AppendLine()
    $null = $md.AppendLine("_Generated $($GeneratedAt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture)) UTC by TenantPosture $(EscMd $ToolVersion)_")

    Set-TPSensitiveFileContent -Path $htmlPath -Content $html
    Set-TPSensitiveFileContent -Path $mdPath -Content $md.ToString()
    return [ordered]@{ Html = $htmlPath; Markdown = $mdPath }
}
