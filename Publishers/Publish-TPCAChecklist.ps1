#Requires -Version 7.0
#
# Publish-TPCAChecklist.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Render the Conditional Access checklist (Get-TPCAChecklist) as
#   <base>-ca-checklist.html / .md, and write the report-only policy files for
#   what is not met to <base>-ca-policies/ (one JSON per Microsoft template,
#   plus README.md saying how to import them).
#
# Rendering rules (pinned by TP.CAChecklist.Tests.ps1):
#   - Every row shows its status in words (Passed / Not met / Report-only /
#     Not assessed / Does not apply / Needs license) and the Maester test it
#     follows; nothing says "compliant".
#   - The policy files are report-only (state enabledForReportingButNotEnforced)
#     and the README says the tool created nothing in the tenant.
#   - Every string is escaped for its format; the page loads nothing.
#
# Inputs:  -Model, -OutputPath (file path of the .html), -TenantDomain,
#          -Brand, -ToolVersion, -GeneratedAt (tests), -NoPolicyFiles.
# Data consumed: the model only. Graph scopes / cmdlets used: none.

function Publish-TPCAChecklist {
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
        [AllowEmptyString()] [string] $TenantDomain = '',
        [AllowNull()] [object] $Brand,
        [string] $ToolVersion = '',
        [datetime] $GeneratedAt = [datetime]::UtcNow,
        [switch] $NoPolicyFiles
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not (Get-Command ConvertTo-TPHtmlSafe -ErrorAction SilentlyContinue)) {
        throw 'ConvertTo-TPHtmlSafe is not loaded. Refusing to generate the Conditional Access checklist without HTML escaping.'
    }
    if ((Get-TPObjectField -Item $Model -Key 'Available' -Default $false) -ne $true) {
        throw "Conditional Access checklist not generated: $([string](Get-TPObjectField -Item $Model -Key 'Note' -Default 'not available'))"
    }

    function EscMd { param([object] $v) ConvertTo-TPMarkdownSafe $v }   # one Markdown rule for the whole tool
    function Esc { param([object] $v) ConvertTo-TPHtmlSafe $v }

    if (-not $PSBoundParameters.ContainsKey('Brand')) {
        $Brand = if ((Get-Variable -Name TPBrand -Scope Script -ErrorAction SilentlyContinue)) { $script:TPBrand } else { $null }
    }
    $theme = Get-TPReportTheme -Brand $Brand
    $htmlPath = if ($OutputPath -match '\.html\z') { $OutputPath } else { "$OutputPath.html" }
    $mdPath = [System.IO.Path]::ChangeExtension($htmlPath, '.md')
    $dir = Split-Path -Parent $htmlPath
    if ($dir) { $null = [System.IO.Directory]::CreateDirectory($dir) }
    $policyDir = ($htmlPath -replace '-ca-checklist\.html\z', '') + '-ca-policies'
    if ($policyDir -eq $htmlPath) { $policyDir = [System.IO.Path]::ChangeExtension($htmlPath, $null) + '-policies' }

    $tenantText = if ($TenantDomain) { $TenantDomain } else { 'this tenant' }
    $tone = @{ Pass = 'Good'; Fail = 'Bad'; Staged = 'Warn'; NotAssessed = 'Neutral'; NotApplicable = 'Neutral'; NeedsLicense = 'Info' }
    $names = $Model.StatusNames
    $kinds = [ordered]@{
        Presence   = @{ Title = 'Recommended policies'; Id = 'presence'; Kicker = 'Is each policy Microsoft recommends in place and turned on?' }
        Hygiene    = @{ Title = 'Policy hygiene'; Id = 'hygiene'; Kicker = 'Are the policies that exist set up so they cannot lock you out or quietly stop applying?' }
        Simulation = @{ Title = 'What If simulation'; Id = 'simulation'; Kicker = "Microsoft's own evaluation of real sign-ins" }
    }
    $rows = @($Model.Rows | Where-Object { $null -ne $_ })
    $fixes = @($Model.Fixes | Where-Object { $null -ne $_ })
    $fileOf = @{}
    $i = 0
    foreach ($fx in $fixes) { $i++; $fileOf[[string]$fx.Key] = ('{0:00}-{1}.json' -f $i, ([string]$fx.Key -replace '[^a-z0-9-]', '')) }

    # ── HTML ──
    $sb = [System.Text.StringBuilder]::new()
    $chips = @("$($Model.PolicyCount) policies read", "$($Model.EnabledCount) on", "$($Model.ReportOnlyCount) report-only")
    $null = $sb.Append((New-TPThemeMasthead -CompanyName $theme.CompanyName -Title 'Conditional Access checklist' -Subtitle "How ${tenantText}'s Conditional Access compares with Microsoft's recommended policies, checked the way Maester checks them." -Chips $chips))

    $c = $Model.Counts
    $kpis = '<div class="tp-kpis">' +
        (New-TPThemeKpi -Label $names.Pass -Value $c.Pass -PillHtml (New-TPThemePill -Status Good -Text 'In place')) +
        (New-TPThemeKpi -Label $names.Fail -Value $c.Fail -PillHtml (New-TPThemePill -Status Bad -Text 'Fix')) +
        (New-TPThemeKpi -Label $names.Staged -Value $c.Staged -Note 'Exists, enforces nothing' -PillHtml (New-TPThemePill -Status Warn -Text 'Turn on')) +
        (New-TPThemeKpi -Label $names.NotAssessed -Value $c.NotAssessed -Note 'Data not read') +
        (New-TPThemeKpi -Label $names.NeedsLicense -Value $c.NeedsLicense) + '</div>'
    $intro = '<div class="tp-banner tp-banner--info">' + (Esc 'Each row follows a Maester test (the id is shown) and is judged on enabled policies only. A row passes when at least one enabled policy matches what Microsoft recommends; it does not mean every account is covered. The What If rows ask Entra itself for a sample of accounts.') + '</div>'
    foreach ($n in @($Model.Notes)) { $intro += '<p class="tp-note">' + (Esc $n) + '</p>' }
    $null = $sb.Append((New-TPThemeSection -Id 'summary' -Title 'Summary' -Kicker "$($rows.Count) checks" -BodyHtml ($kpis + $intro) -First))

    foreach ($k in $kinds.Keys) {
        $set = @($rows | Where-Object { $_.Kind -eq $k })
        if ($set.Count -eq 0) { continue }
        $body = '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Check</th><th>Result</th><th>What the run found</th></tr></thead><tbody>'
        foreach ($r in $set) {
            $detail = '<div class="tp-small">' + (Esc $r.Detail) + '</div>'
            $items = @($r.Items | Where-Object { $null -ne $_ })
            if ($items.Count) {
                $detail += '<details><summary>' + (Esc "$($items.Count) item(s)") + '</summary><ul class="tp-small">'
                foreach ($it in ($items | Select-Object -First 50)) {
                    $label = if ($it.DisplayName) { "$($it.DisplayName) ($($it.Kind) $($it.Id))" } else { "$($it.Kind) $($it.Id)" }
                    $extra = @()
                    $scenario = [string](Get-TPObjectField -Item $it -Key 'Scenario' -Default '')
                    if ($scenario) { $extra += "${scenario}: $([string](Get-TPObjectField -Item $it -Key 'Result' -Default ''))" }
                    $usedBy = @(Get-TPObjectField -Item $it -Key 'UsedBy' -Default @() | Where-Object { $_ })
                    if ($usedBy.Count) { $extra += 'in: ' + ($usedBy -join '; ') }
                    $detail += '<li>' + (Esc $label) + $(if ($extra.Count) { ' &#8212; ' + (@($extra | ForEach-Object { Esc $_ }) -join ' &#183; ') } else { '' }) + '</li>'
                }
                $detail += '</ul></details>'
            }
            if ($r.Status -eq 'Fail' -and $r.Template -and $fileOf.ContainsKey([string]$r.Template)) {
                $detail += '<div class="tp-small"><strong>Report-only policy:</strong> <span class="tp-mono">' + (Esc $fileOf[[string]$r.Template]) + '</span></div>'
            }
            $detail += '<div class="tp-small tp-muted">' + (Esc $r.Why) + ' <span class="tp-mono">' + (Esc $r.SourceUrl) + '</span></div>'
            $body += '<tr><td><span class="tp-mono">' + (Esc $r.Id) + '</span><div>' + (Esc $r.Title) + '</div></td><td>' + (New-TPThemePill -Status $tone[[string]$r.Status] -Text $r.StatusLabel) + '</td><td>' + $detail + '</td></tr>'
        }
        $body += '</tbody></table></div>'
        $null = $sb.Append((New-TPThemeSection -Id $kinds[$k].Id -Title $kinds[$k].Title -Kicker $kinds[$k].Kicker -BodyHtml $body))
    }

    $fixHtml = '<p class="tp-note">' + (Esc "Each file is one of Microsoft's Conditional Access templates as a report-only policy for this tenant. The tool created nothing: an administrator reviews each file, imports it (Entra admin center, Conditional Access, Policies, Upload policy file), watches its report-only results, and only then turns it on.") + '</p>'
    if ($fixes.Count -eq 0) { $fixHtml += '<p class="tp-note">No report-only policy is needed: every recommended policy with a template is in place or waiting in report-only mode.</p>' }
    else {
        $fixHtml += '<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>File</th><th>Policy</th><th>For</th><th>Before you turn it on</th></tr></thead><tbody>'
        foreach ($fx in $fixes) { $fixHtml += '<tr><td class="tp-mono tp-small">' + (Esc $fileOf[[string]$fx.Key]) + '</td><td>' + (Esc $fx.Title) + '</td><td class="tp-mono tp-small">' + (Esc (@($fx.Rows) -join ', ')) + '</td><td class="tp-small">' + (Esc $(if ($fx.Note) { $fx.Note } else { 'Review the report-only results first.' })) + '</td></tr>' }
        $fixHtml += '</tbody></table></div>'
    }
    $null = $sb.Append((New-TPThemeSection -Id 'policy-files' -Title 'Report-only policies to import' -Kicker "$($fixes.Count) file(s)" -BodyHtml $fixHtml))
    $null = $sb.Append((New-TPThemeFooter -GeneratedAt $GeneratedAt -ToolVersion $ToolVersion -CompanyName $theme.CompanyName -Note "Checks follow Maester ($($Model.MaesterReference))"))
    $html = New-TPThemeDocument -Title "Conditional Access checklist: $tenantText" -Theme $theme -BodyHtml $sb.ToString()

    # ── Markdown ──
    $md = [System.Text.StringBuilder]::new()
    $null = $md.AppendLine("# Conditional Access checklist: $(EscMd $tenantText)")
    $null = $md.AppendLine()
    $null = $md.AppendLine("$(EscMd $theme.CompanyName) &middot; $($Model.PolicyCount) policies read, $($Model.EnabledCount) on, $($Model.ReportOnlyCount) report-only")
    $null = $md.AppendLine()
    $null = $md.AppendLine('> Each row follows a Maester test (the id is shown) and is judged on enabled policies only. A row passes when at least one enabled policy matches what Microsoft recommends; it does not mean every account is covered.')
    $null = $md.AppendLine()
    foreach ($n in @($Model.Notes)) { $null = $md.AppendLine("- $(EscMd $n)") }
    $null = $md.AppendLine()
    $null = $md.AppendLine("| $($names.Pass) | $($names.Fail) | $($names.Staged) | $($names.NotAssessed) | $($names.NotApplicable) | $($names.NeedsLicense) |")
    $null = $md.AppendLine('|---|---|---|---|---|---|')
    $null = $md.AppendLine("| $($c.Pass) | $($c.Fail) | $($c.Staged) | $($c.NotAssessed) | $($c.NotApplicable) | $($c.NeedsLicense) |")
    foreach ($k in $kinds.Keys) {
        $set = @($rows | Where-Object { $_.Kind -eq $k })
        if ($set.Count -eq 0) { continue }
        $null = $md.AppendLine()
        $null = $md.AppendLine("## $($kinds[$k].Title)")
        $null = $md.AppendLine()
        $null = $md.AppendLine('| Check | Title | Result | What the run found |')
        $null = $md.AppendLine('|---|---|---|---|')
        foreach ($r in $set) {
            $found = [string]$r.Detail
            if ($r.Status -eq 'Fail' -and $r.Template -and $fileOf.ContainsKey([string]$r.Template)) { $found += " Report-only policy: $($fileOf[[string]$r.Template])." }
            $items = @($r.Items | Where-Object { $null -ne $_ })
            if ($items.Count) { $found += ' Items: ' + (@($items | Select-Object -First 10 | ForEach-Object { if ($_.DisplayName) { $_.DisplayName } else { "$($_.Kind) $($_.Id)" } }) -join '; ') + $(if ($items.Count -gt 10) { " and $($items.Count - 10) more" } else { '' }) + '.' }
            $null = $md.AppendLine("| ``$($r.Id)`` | $(EscMd $r.Title) | $(EscMd $r.StatusLabel) | $(EscMd $found) |")
        }
    }
    $null = $md.AppendLine()
    $null = $md.AppendLine('## Report-only policies to import')
    $null = $md.AppendLine()
    if ($fixes.Count -eq 0) { $null = $md.AppendLine('No report-only policy is needed.') }
    else { foreach ($fx in $fixes) { $null = $md.AppendLine("- ``$($fileOf[[string]$fx.Key])`` $(EscMd $fx.Title) (for $(EscMd (@($fx.Rows) -join ', ')))$(if ($fx.Note) { ': ' + (EscMd $fx.Note) })") } }
    $null = $md.AppendLine()
    $null = $md.AppendLine("_Generated $($GeneratedAt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture)) UTC by TenantPosture $(EscMd $ToolVersion). Checks follow Maester ($(EscMd $Model.MaesterReference))._")

    Set-TPSensitiveFileContent -Path $htmlPath -Content $html
    Set-TPSensitiveFileContent -Path $mdPath -Content $md.ToString()

    $written = [System.Collections.Generic.List[string]]::new()
    if (-not $NoPolicyFiles -and $fixes.Count -gt 0) {
        $null = [System.IO.Directory]::CreateDirectory($policyDir)
        foreach ($fx in $fixes) {
            $policy = $fx.Policy
            $policy['state'] = 'enabledForReportingButNotEnforced'
            $path = Join-Path $policyDir $fileOf[[string]$fx.Key]
            Set-TPSensitiveFileContent -Path $path -Content ($policy | ConvertTo-Json -Depth 20)
            $written.Add($path)
        }
        $readme = [System.Text.StringBuilder]::new()
        $null = $readme.AppendLine("# Report-only Conditional Access policies for $(EscMd $tenantText)")
        $null = $readme.AppendLine()
        $null = $readme.AppendLine('TenantPosture wrote these files. It created nothing in the tenant and never will: it is read-only.')
        $null = $readme.AppendLine()
        $null = $readme.AppendLine("Each file is one of Microsoft's Conditional Access templates, in report-only state, for a check in the Conditional Access checklist that was not met.")
        $null = $readme.AppendLine()
        $null = $readme.AppendLine('1. Read each file. Confirm the exclusions: the approved emergency access accounts (when the tenant has a record) and the Directory Synchronization Accounts role.')
        $null = $readme.AppendLine('2. Import it: Microsoft Entra admin center, Entra ID, Conditional Access, Policies, Upload policy file. Or POST it to /identity/conditionalAccess/policies with Policy.ReadWrite.ConditionalAccess.')
        $null = $readme.AppendLine('3. Leave it in report-only mode and review its results in the sign-in logs (Report-only tab) or the Conditional Access insights workbook.')
        $null = $readme.AppendLine('4. Turn it on only when the report-only results show nobody you need is blocked.')
        $null = $readme.AppendLine()
        foreach ($fx in $fixes) { $null = $readme.AppendLine("- ``$($fileOf[[string]$fx.Key])``: $(EscMd $fx.Title). Source: $(EscMd $fx.SourceUrl)$(if ($fx.Note) { '. ' + (EscMd $fx.Note) })") }
        foreach ($n in @($Model.Notes)) { $null = $readme.AppendLine(); $null = $readme.AppendLine("Note: $(EscMd $n)") }
        $readmePath = Join-Path $policyDir 'README.md'
        Set-TPSensitiveFileContent -Path $readmePath -Content $readme.ToString()
        $written.Add($readmePath)
    }
    return [ordered]@{ Html = $htmlPath; Markdown = $mdPath; PolicyFolder = $(if ($written.Count) { $policyDir } else { '' }); PolicyFiles = $written.ToArray() }
}
