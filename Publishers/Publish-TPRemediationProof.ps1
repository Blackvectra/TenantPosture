#Requires -Version 7.0
#
# Publish-TPRemediationProof.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Render the proof-of-fix model (Get-TPRemediationProof) as a
#   client-facing remediation certificate: a branded, printable
#   (print-to-PDF ready) HTML page and a Markdown copy, named
#   <tenant>-proof-<yyyyMMdd-HHmmss>.html / .md. Uses the shared report theme.
#
# Rendering rules (pinned by TP.RemediationProof.Tests.ps1):
#   - The statement of scope is on the page: only the listed controls, only
#     what the tool observed at the two run times.
#   - Not verifiable is never drawn as fixed; no wording says "compliant".
#   - The evidence block carries both run times (UTC), tool versions, the
#     SHA-256 of both results files and the exact selection patterns; never
#     the operator, the TenantId or a finding's Detail.
#   - Every string is escaped for its format; the page loads nothing.
#
# Inputs:  -Proof (Get-TPRemediationProof), -OutputPath (folder), -Brand
#          (defaults to the loaded profile), -GeneratedAt (tests).
# Data consumed: the model only. Graph scopes / cmdlets used: none.

function Publish-TPRemediationProof {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [object] $Proof,
        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
            return $true
        })]
        [string] $OutputPath,
        [AllowNull()] [object] $Brand,
        [string] $ToolVersion = '',
        [datetime] $GeneratedAt = [datetime]::UtcNow
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not (Get-Command ConvertTo-TPHtmlSafe -ErrorAction SilentlyContinue)) {
        throw 'ConvertTo-TPHtmlSafe is not loaded. Refusing to generate the proof of fix without HTML escaping.'
    }
    if ((Get-TPObjectField -Item $Proof -Key 'Available' -Default $false) -ne $true) {
        throw "Proof of fix not generated: $([string](Get-TPObjectField -Item $Proof -Key 'Note' -Default 'not available'))"
    }

    function EscMd { param([object] $v) ConvertTo-TPMarkdownSafe $v }   # one Markdown rule for the whole tool
    function Esc { param([object] $v) ConvertTo-TPHtmlSafe $v }

    if (-not $PSBoundParameters.ContainsKey('Brand')) {
        $Brand = if ((Get-Variable -Name TPBrand -Scope Script -ErrorAction SilentlyContinue)) { $script:TPBrand } else { $null }
    }
    if (-not $ToolVersion -and (Get-Variable -Name TPAssessmentVersion -Scope Script -ErrorAction SilentlyContinue)) { $ToolVersion = [string]$script:TPAssessmentVersion }
    $theme = Get-TPReportTheme -Brand $Brand

    $domain = [string](Get-TPObjectField -Item $Proof -Key 'TenantDomain' -Default '')
    $tag = if ($domain) { (($domain -split '\.')[0]) -replace '[^a-zA-Z0-9-]', '' } else { '' }
    if (-not $tag) { $tag = 'tenant' }
    if (Test-Path -LiteralPath $OutputPath -PathType Leaf) { throw "OutputPath is a file, not a folder: $OutputPath" }
    $null = [System.IO.Directory]::CreateDirectory($OutputPath)
    $stamp = $GeneratedAt.ToUniversalTime().ToString('yyyyMMdd-HHmmss', [cultureinfo]::InvariantCulture)
    $htmlPath = Join-Path $OutputPath "$tag-proof-$stamp.html"
    $mdPath   = Join-Path $OutputPath "$tag-proof-$stamp.md"

    $before = $Proof.Before
    $after = $Proof.After
    $rows = @($Proof.Controls)
    $counts = $Proof.Counts
    $tone = @{ 'Resolved' = 'Good'; 'Already met' = 'Good'; 'Improved' = 'Info'; 'Not resolved' = 'Warn'; 'Regressed' = 'Bad'; 'Not verifiable' = 'Neutral'; 'No earlier verdict' = 'Neutral' }
    $meaning = [ordered]@{
        'Resolved'           = 'Open (Gap or Partial) before, Satisfied after.'
        'Improved'           = 'A Gap before, Partial after: part of the expected state is now in place.'
        'Not resolved'       = 'The same open state before and after.'
        'Regressed'          = 'Satisfied before and open after, or Partial before and a Gap after.'
        'Not verifiable'     = 'The after run produced no verdict (not applicable, an error, or no finding). It is not shown as fixed.'
        'No earlier verdict' = 'The before run produced no verdict, so the change cannot be described.'
        'Already met'        = 'Satisfied before and after.'
    }
    $scopeText = {
        param($info)
        $parts = @()
        $parts += switch ($info.Scope) { 'Partial' { 'Partial run' } 'Quick' { 'Quick scan (Critical and High only)' } default { 'Full run' } }
        if (@($info.Include).Count) { $parts += '-ControlId ' + (@($info.Include) -join ', ') }
        if (@($info.Exclude).Count) { $parts += '-ExcludeControlId ' + (@($info.Exclude) -join ', ') }
        return ($parts -join '; ')
    }
    $tenantText = if ($domain) { $domain } else { 'tenant domain not recorded' }

    # ── HTML ──
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.Append((New-TPThemeMasthead -CompanyName $theme.CompanyName -Title 'Proof of fix' -Subtitle "Remediation certificate for $tenantText" -Chips @("Before $($before.RunTime)", "After $($after.RunTime)")))
    $pills = (@((Get-TPRemediationProofVerdictOrder) | Where-Object { [int]$counts[$_] -gt 0 } | ForEach-Object { New-TPThemePill -Status $tone[$_] -Text "$($counts[$_]) $_" })) -join ' '
    $null = $sb.Append('<div class="tp-kpis">' + (New-TPThemeKpi -Label 'Result' -Value $Proof.Headline -PillHtml ('<div class="tp-row">' + $pills + '</div>')) + '</div>')
    $null = $sb.Append('<div class="tp-banner tp-banner--info">' + (Esc $Proof.Statement) + '</div>')

    $tb = [System.Text.StringBuilder]::new('<div class="tp-table-wrap"><table class="tp-table"><thead><tr><th>Control</th><th>Before</th><th>After</th><th>Verdict</th></tr></thead><tbody>')
    foreach ($row in $rows) {
        $null = $tb.Append('<tr><td><span class="tp-mono">' + (Esc $row.ControlId) + '</span><div>' + (Esc $row.Title) + '</div><div class="tp-small tp-muted">' + (Esc $row.Severity) + '</div></td>')
        $null = $tb.Append('<td><strong>' + (Esc $row.BeforeState) + '</strong><div class="tp-small tp-muted">' + (Esc $row.BeforeValue) + '</div></td>')
        $null = $tb.Append('<td><strong>' + (Esc $row.AfterState) + '</strong><div class="tp-small tp-muted">' + (Esc $row.AfterValue) + '</div></td>')
        $null = $tb.Append('<td>' + (New-TPThemePill -Status $tone[[string]$row.Verdict] -Text $row.Verdict) + '</td></tr>')
    }
    $null = $tb.Append('</tbody></table></div>')
    $null = $sb.Append((New-TPThemeSection -Id 'controls' -Title 'Controls re-checked' -Kicker "$($rows.Count) control(s), each judged at its worst finding in each run" -BodyHtml $tb.ToString() -First))

    $ev = [System.Text.StringBuilder]::new('<div class="tp-grid">')
    foreach ($pair in @(@{ Name = 'Before'; Info = $before }, @{ Name = 'After'; Info = $after })) {
        $info = $pair.Info
        $null = $ev.Append('<div class="tp-card"><h3>' + (Esc $pair.Name) + ' run</h3><dl class="tp-kv">')
        $null = $ev.Append('<dt>Assessed</dt><dd>' + (Esc $info.RunTime) + '</dd>')
        $null = $ev.Append('<dt>Tool version</dt><dd>' + (Esc $(if ($info.ToolVersion) { $info.ToolVersion } else { 'Not recorded' })) + '</dd>')
        $null = $ev.Append('<dt>Scope</dt><dd>' + (Esc (& $scopeText $info)) + '</dd>')
        $null = $ev.Append('<dt>Results file</dt><dd class="tp-mono">' + (Esc $info.FileName) + '</dd>')
        $null = $ev.Append('<dt>SHA-256</dt><dd class="tp-mono">' + (Esc $(if ($info.Sha256) { $info.Sha256 } else { 'Not computed' })) + '</dd>')
        $null = $ev.Append('</dl></div>')
    }
    $null = $ev.Append('</div>')
    $patText = if (@($Proof.Patterns).Count) { 'Controls narrowed with -ControlId ' + (@($Proof.Patterns) -join ', ') + '.' } else { 'Controls compared: every control the after run covers that the before run also assessed.' }
    $null = $ev.Append('<p class="tp-note">' + (Esc $patText) + ' The SHA-256 values identify the exact results files this certificate was built from; anyone holding the files can recompute them.</p>')
    foreach ($n in @($Proof.Notes)) { $null = $ev.Append('<p class="tp-note">' + (Esc $n) + '</p>') }
    $null = $sb.Append((New-TPThemeSection -Id 'evidence' -Title 'Evidence' -BodyHtml $ev.ToString()))

    $how = '<ul class="tp-list tp-note">' + ((@($meaning.Keys | ForEach-Object { '<li><strong>' + (Esc $_) + '.</strong> ' + (Esc $meaning[$_]) + '</li>' })) -join '') + '</ul>'
    $null = $sb.Append((New-TPThemeSection -Id 'verdicts' -Title 'How each verdict is decided' -BodyHtml $how))
    $null = $sb.Append((New-TPThemeFooter -GeneratedAt $GeneratedAt -ToolVersion $ToolVersion -CompanyName $theme.CompanyName -Note 'Covers the listed controls only'))
    $html = New-TPThemeDocument -Title "Proof of fix: $tenantText" -Theme $theme -BodyHtml $sb.ToString()

    # ── Markdown ──
    $md = [System.Text.StringBuilder]::new()
    $null = $md.AppendLine("# Proof of fix: $(EscMd $tenantText)")
    $null = $md.AppendLine()
    $null = $md.AppendLine("$(EscMd $theme.CompanyName) &middot; generated $($GeneratedAt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture)) UTC")
    $null = $md.AppendLine()
    $null = $md.AppendLine("**$(EscMd $Proof.Headline)**")
    $null = $md.AppendLine()
    $null = $md.AppendLine("> $(EscMd $Proof.Statement)")
    $null = $md.AppendLine()
    $null = $md.AppendLine('| Verdict | Controls |')
    $null = $md.AppendLine('|---|---|')
    foreach ($v in (Get-TPRemediationProofVerdictOrder)) { $null = $md.AppendLine("| $(EscMd $v) | $($counts[$v]) |") }
    $null = $md.AppendLine()
    $null = $md.AppendLine('## Controls re-checked')
    $null = $md.AppendLine()
    $null = $md.AppendLine('| Control | Title | Severity | Before | After | Verdict |')
    $null = $md.AppendLine('|---|---|---|---|---|---|')
    foreach ($row in $rows) {
        $bText = $row.BeforeState + $(if ($row.BeforeValue) { ': ' + $row.BeforeValue } else { '' })
        $aText = $row.AfterState + $(if ($row.AfterValue) { ': ' + $row.AfterValue } else { '' })
        $null = $md.AppendLine("| ``$($row.ControlId)`` | $(EscMd $row.Title) | $(EscMd $row.Severity) | $(EscMd $bText) | $(EscMd $aText) | **$(EscMd $row.Verdict)** |")
    }
    $null = $md.AppendLine()
    $null = $md.AppendLine('## Evidence')
    $null = $md.AppendLine()
    $null = $md.AppendLine('| | Before | After |')
    $null = $md.AppendLine('|---|---|---|')
    $null = $md.AppendLine("| Assessed | $(EscMd $before.RunTime) | $(EscMd $after.RunTime) |")
    $null = $md.AppendLine("| Tool version | $(EscMd $before.ToolVersion) | $(EscMd $after.ToolVersion) |")
    $null = $md.AppendLine("| Scope | $(EscMd (& $scopeText $before)) | $(EscMd (& $scopeText $after)) |")
    $null = $md.AppendLine("| Results file | $(EscMd $before.FileName) | $(EscMd $after.FileName) |")
    $null = $md.AppendLine("| SHA-256 | ``$($before.Sha256)`` | ``$($after.Sha256)`` |")
    $null = $md.AppendLine()
    $null = $md.AppendLine((EscMd $patText))
    foreach ($n in @($Proof.Notes)) { $null = $md.AppendLine(); $null = $md.AppendLine("- $(EscMd $n)") }
    $null = $md.AppendLine()
    $null = $md.AppendLine('## How each verdict is decided')
    $null = $md.AppendLine()
    foreach ($k in $meaning.Keys) { $null = $md.AppendLine("- **$(EscMd $k).** $(EscMd $meaning[$k])") }
    $null = $md.AppendLine()
    $null = $md.AppendLine("_TenantPosture $(EscMd $ToolVersion)_")

    Set-TPSensitiveFileContent -Path $htmlPath -Content $html
    Set-TPSensitiveFileContent -Path $mdPath -Content $md.ToString()
    return [ordered]@{ Html = $htmlPath; Markdown = $mdPath }
}
