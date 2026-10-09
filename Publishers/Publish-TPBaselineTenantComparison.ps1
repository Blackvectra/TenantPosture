#Requires -Version 7.0
#
# Publish-TPBaselineTenantComparison.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Purpose: Render the tenant-versus-tenant NRG Security Baseline comparison
#   (Get-TPBaselineTenantComparison) as Markdown, a self-contained HTML page
#   and a CSV. INTERNAL working document: the default output names both
#   tenants. With an anonymized comparison the tenants are labeled A and B in
#   every output, file names included. No client-facing wording, no branding.
#
#   Touches nothing: no Graph, no Exchange Online, no network, no endpoint. It
#   renders the comparison model it is handed and writes three files.
#
# Rendering rules (pinned by TP.TenantComparison.Tests.ps1):
#   - Every string is escaped for its format: HTML-encoded in HTML, pipe /
#     bracket / angle-bracket escaped in Markdown, and prefixed in CSV when it
#     could be read as a spreadsheet formula.
#   - The page loads nothing (no script, no font, no stylesheet, no image) and
#     carries a Content-Security-Policy that forbids all of it.
#   - Nothing in the output says "compliant", scores a tenant, or says one
#     tenant is better than the other.
#   - Control IDs, titles, states, reason codes, tiers, versions, dates and
#     counts only: no finding Detail, exception text, UPN or object name.
#
# Inputs:  -Comparison  the model from Get-TPBaselineTenantComparison.
#          -OutputPath  a folder; created if absent.
#          -GeneratedAt optional; the time stamped on the files (tests).
# Returns: an ordered dictionary with the Markdown, Html and Csv paths.

function Publish-TPBaselineTenantComparison {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [object] $Comparison,

        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
            return $true
        })]
        [string] $OutputPath,

        [datetime] $GeneratedAt = (Get-Date)
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # Fail closed: this page is built from a file the operator did not write.
    if (-not (Get-Command ConvertTo-TPHtmlSafe -ErrorAction SilentlyContinue)) {
        throw 'ConvertTo-TPHtmlSafe is not loaded. Refusing to generate the comparison without HTML escaping.'
    }
    if ($null -eq $Comparison -or (Get-TPObjectField -Item $Comparison -Key 'Available' -Default $false) -ne $true) {
        $why = [string](Get-TPObjectField -Item $Comparison -Key 'Note' -Default 'The comparison is not available.')
        throw "Comparison not generated: $why"
    }

    function EscMd {
        param([object] $v)
        $t = [string]$v
        $t = $t -replace '[\r\n]+', ' '
        $t = $t -replace '\|', '\|'
        $t = $t -replace '<', '&lt;' -replace '>', '&gt;'
        $t = $t -replace '`', '\`'
        $t = $t -replace '\[', '\[' -replace '\]', '\]'
        return $t
    }
    function Esc { param([object] $v) ConvertTo-TPHtmlSafe $v }
    function CsvSafe {
        # A cell that starts with = + - @ tab or CR is read by a spreadsheet as
        # a formula. A leading apostrophe makes it text.
        param([object] $v)
        $t = [string]$v
        if ($t -match '^[=+\-@\t\r]') { return "'" + $t }
        return $t
    }

    $A = $Comparison.SideA
    $B = $Comparison.SideB
    $C = $Comparison.Counts
    $anon = [bool]$Comparison.Anonymized

    # ── Output folder and names ──
    if (Test-Path -LiteralPath $OutputPath -PathType Leaf) { throw "OutputPath is a file, not a folder: $OutputPath" }
    # [IO.Directory]::CreateDirectory, not New-Item -Path: New-Item -Path
    # interprets wildcards, so a folder name containing [ or ] would fail.
    $null = [System.IO.Directory]::CreateDirectory($OutputPath)
    $stamp = $GeneratedAt.ToString('yyyyMMdd-HHmmss', [cultureinfo]::InvariantCulture)
    $baseName = "NRG-BaselineComparison-$($A.FileTag)-vs-$($B.FileTag)-$stamp"
    $mdPath   = Join-Path $OutputPath "$baseName.md"
    $htmlPath = Join-Path $OutputPath "$baseName.html"
    $csvPath  = Join-Path $OutputPath "$baseName.csv"

    # ── Shared wording, written once so the two formats cannot drift ──
    $title = 'NRG Security Baseline: tenant comparison'
    $audience = if ($anon) {
        'Anonymized. The tenants are labeled A and B throughout, file names included.'
    } else {
        'Internal working document. It names both tenants and is not written for a client. Re-run with -Anonymize for a version that labels them A and B.'
    }
    $scopeSentence = 'This is a side-by-side of what each assessment observed against the NRG Security Baseline. It does not rate or rank either tenant, and a control that either run could not verify is never counted as a match.'
    $coverageNote = 'Evidence coverage and effectiveness coverage describe how much of the baseline each run could read. They do not measure how well either tenant meets it: a tenant that fails every control can have full evidence coverage.'
    $howToRead = @(
        'Satisfied and Failed are the observed states from each run''s NRG Security Baseline view. NotVerified, NotApplicable, LicenseBlocked and ThirdPartyHandled mean that run holds no verdict for the control, so it is listed as not comparable and is never counted as a match or a difference. Inconsistent means a row''s state contradicted its own reason code, and is treated the same way.',
        '"Same baseline posture" means the same observed state at both tenants. It includes controls that both tenants fail.',
        'An approved exception is a disposition shown beside the observed state. It never changes the observed state.',
        'Only controls required at both tenants are compared. A control required at only one tenant''s tier, or whose required tier or expected state differs between the two files, is listed as not compared.',
        'The comparison reads only the two results files. It connects to nothing and changes nothing.'
    )
    $stateWord = {
        param($state, $disp)
        if ($disp -eq 'ApprovedException') { return "$state (approved exception)" }
        return [string]$state
    }
    $freshText = {
        param($side)
        $f = $side.Freshness
        $t = "$($f.Current) current, $($f.Stale) stale, $($f.None) none"
        if ($f.NotRecorded -gt 0) { $t += ", $($f.NotRecorded) not recorded" }
        if ($f.Oldest) { $t += "; oldest $($f.Oldest)" }
        return $t
    }
    $tierText = { param($v) if ($v) { [string]$v } else { 'not recorded' } }
    $dateText = { param($v) if ($v) { [string]$v } else { 'not recorded' } }

    $causeLine = {
        param($by)
        $parts = @(foreach ($k in $by.Keys) { "$($by[$k]) $k" })
        if ($parts.Count -eq 0) { return 'none' }
        return ($parts -join ', ')
    }
    $basisText = {
        param($row)
        switch ($row.Basis) {
            'RequiredOnlyAtA'   { return "A only: $(& $tierText $row.RequiredTierA) tier" }
            'RequiredOnlyAtB'   { return "B only: $(& $tierText $row.RequiredTierB) tier" }
            'DefinitionDiffers' { return "Both, but the required tier or expected state differs (A: $(& $tierText $row.RequiredTierA), B: $(& $tierText $row.RequiredTierB))" }
            default             { return [string]$row.Basis }
        }
    }

    $licenseLines = @()
    $licenseDiffs = @($Comparison.LicenseDifferences)
    if ($licenseDiffs.Count -gt 0) { $licenseLines = $licenseDiffs }
    elseif ($A.License.Read -and $B.License.Read) { $licenseLines = @('The two tenants hold the same licensed capabilities among those the baseline checks.') }
    else { $licenseLines = @('Not stated: licensing was not read for one or both runs.') }

    $outcomeRows = @(
        , @('Satisfied at both tenants', $C.BothSatisfied)
        , @('Failed at both tenants', $C.BothFailed)
        , @('Satisfied at A, failed at B', $C.DiffersASatisfied)
        , @('Satisfied at B, failed at A', $C.DiffersBSatisfied)
        , @('Not comparable: a run did not verify the control', $C.NotComparable)
        , @('Required at only one tenant''s tier or version (not compared)', ($C.RequiredOnlyAtA + $C.RequiredOnlyAtB))
        , @('Required tier or expected state differs between the files (not compared)', $C.DefinitionDiffers)
    )

    # ═════════════════════════════════════════════════════════════════════════
    # Markdown
    # ═════════════════════════════════════════════════════════════════════════
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("# $title")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("> **$(EscMd $audience)**")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("A: $(EscMd $A.Name) &middot; B: $(EscMd $B.Name) &middot; generated $($GeneratedAt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture)) UTC")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('## Result')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**$(EscMd $Comparison.Headline)**")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine((EscMd $Comparison.HeadlineDetail))
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('| Result | Controls |')
    $null = $sb.AppendLine('|---|---:|')
    foreach ($o in $outcomeRows) { $null = $sb.AppendLine("| $(EscMd $o[0]) | $($o[1]) |") }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine((EscMd $scopeSentence))
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('## Basis of the comparison')
    $null = $sb.AppendLine()
    foreach ($w in @($Comparison.Warnings)) { $null = $sb.AppendLine("- **Warning.** $(EscMd $w)") }
    foreach ($n in @($Comparison.Notes)) { $null = $sb.AppendLine("- $(EscMd $n)") }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('## The two tenants')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('| | A | B |')
    $null = $sb.AppendLine('|---|---|---|')
    $null = $sb.AppendLine("| Tenant | $(EscMd $A.Name) | $(EscMd $B.Name) |")
    $null = $sb.AppendLine("| Run date (UTC) | $(EscMd (& $dateText $A.RunDate)) | $(EscMd (& $dateText $B.RunDate)) |")
    $null = $sb.AppendLine("| Target tier | $(EscMd (& $tierText $A.TargetTier)) | $(EscMd (& $tierText $B.TargetTier)) |")
    $null = $sb.AppendLine("| Baseline version | $(EscMd (& $tierText $A.BaselineVersion)) | $(EscMd (& $tierText $B.BaselineVersion)) |")
    $null = $sb.AppendLine("| Required controls | $($A.RequiredControls) | $($B.RequiredControls) |")
    $null = $sb.AppendLine("| Evidence freshness | $(EscMd (& $freshText $A)) | $(EscMd (& $freshText $B)) |")
    $null = $sb.AppendLine("| Licensed tier | $(EscMd $A.License.TierLabel) | $(EscMd $B.License.TierLabel) |")
    $null = $sb.AppendLine("| Evidence coverage | $(EscMd $A.EvidenceCoverage.Line) | $(EscMd $B.EvidenceCoverage.Line) |")
    $null = $sb.AppendLine("| Effectiveness coverage | $(EscMd $A.EffectivenessCoverage.Line) | $(EscMd $B.EffectivenessCoverage.Line) |")
    $null = $sb.AppendLine("| Approved exceptions among compared controls | $($A.ApprovedExceptionsCompared) | $($B.ApprovedExceptionsCompared) |")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine((EscMd $coverageNote))
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('## Licensing differences')
    $null = $sb.AppendLine()
    foreach ($l in $licenseLines) { $null = $sb.AppendLine("- $(EscMd $l)") }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('## Controls that differ')
    $null = $sb.AppendLine()
    if (@($Comparison.Differences).Count -eq 0) {
        $null = $sb.AppendLine('None: no control is satisfied at one tenant and failed at the other.')
    } else {
        $null = $sb.AppendLine('| Control | Title | Tier | A | B |')
        $null = $sb.AppendLine('|---|---|---|---|---|')
        foreach ($r in @($Comparison.Differences)) {
            $null = $sb.AppendLine("| ``$($r.ControlId)`` | $(EscMd $r.Title) | $(EscMd (& $tierText $r.RequiredTierA)) | $(EscMd (& $stateWord $r.StateA $r.DispositionA)) | $(EscMd (& $stateWord $r.StateB $r.DispositionB)) |")
        }
    }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('## Failed at both tenants')
    $null = $sb.AppendLine()
    if (@($Comparison.BothFailed).Count -eq 0) {
        $null = $sb.AppendLine('None.')
    } else {
        $null = $sb.AppendLine('| Control | Title | Tier | A | B |')
        $null = $sb.AppendLine('|---|---|---|---|---|')
        foreach ($r in @($Comparison.BothFailed)) {
            $null = $sb.AppendLine("| ``$($r.ControlId)`` | $(EscMd $r.Title) | $(EscMd (& $tierText $r.RequiredTierA)) | $(EscMd (& $stateWord $r.StateA $r.DispositionA)) | $(EscMd (& $stateWord $r.StateB $r.DispositionB)) |")
        }
    }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('## Satisfied at both tenants')
    $null = $sb.AppendLine()
    if (@($Comparison.BothSatisfied).Count -eq 0) {
        $null = $sb.AppendLine('None.')
    } else {
        $null = $sb.AppendLine('| Control | Title | Tier | A | B |')
        $null = $sb.AppendLine('|---|---|---|---|---|')
        foreach ($r in @($Comparison.BothSatisfied)) {
            $null = $sb.AppendLine("| ``$($r.ControlId)`` | $(EscMd $r.Title) | $(EscMd (& $tierText $r.RequiredTierA)) | $(EscMd (& $stateWord $r.StateA $r.DispositionA)) | $(EscMd (& $stateWord $r.StateB $r.DispositionB)) |")
        }
    }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('## Not comparable')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('Required at both tenants, but at least one run holds no verdict for the control. These are never counted as a match.')
    $null = $sb.AppendLine()
    if (@($Comparison.NotComparable).Count -eq 0) {
        $null = $sb.AppendLine('None.')
    } else {
        $null = $sb.AppendLine("What each run lacked: A: $(EscMd (& $causeLine $Comparison.NotComparableBy.A)). B: $(EscMd (& $causeLine $Comparison.NotComparableBy.B)).")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine('| Control | Title | Tier | A | A reason code | B | B reason code |')
        $null = $sb.AppendLine('|---|---|---|---|---|---|---|')
        foreach ($r in @($Comparison.NotComparable)) {
            $null = $sb.AppendLine("| ``$($r.ControlId)`` | $(EscMd $r.Title) | $(EscMd (& $tierText $r.RequiredTierA)) | $(EscMd (& $stateWord $r.StateA $r.DispositionA)) | ``$($r.ReasonCodeA)`` | $(EscMd (& $stateWord $r.StateB $r.DispositionB)) | ``$($r.ReasonCodeB)`` |")
        }
    }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('## Not compared')
    $null = $sb.AppendLine()
    if (@($Comparison.NotCompared).Count -eq 0) {
        $null = $sb.AppendLine('None: both tenants were assessed against the same set of controls.')
    } else {
        $null = $sb.AppendLine('Left out because only one tenant required the control (a lower tier or an older baseline version), or because its definition differs between the two files. The tier shown is the tier that required it.')
        $null = $sb.AppendLine()
        $null = $sb.AppendLine('| Control | Title | Why it is not compared |')
        $null = $sb.AppendLine('|---|---|---|')
        foreach ($r in @($Comparison.NotCompared)) {
            $null = $sb.AppendLine("| ``$($r.ControlId)`` | $(EscMd $r.Title) | $(EscMd (& $basisText $r)) |")
        }
    }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('## Reason codes used')
    $null = $sb.AppendLine()
    $legend = @($Comparison.ReasonCodes)
    if ($legend.Count -eq 0) {
        $null = $sb.AppendLine('None.')
    } else {
        $null = $sb.AppendLine('| Code | Meaning |')
        $null = $sb.AppendLine('|---|---|')
        foreach ($l in $legend) { $null = $sb.AppendLine("| ``$($l.Code)`` | $(EscMd $l.Meaning) |") }
    }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('## How to read this')
    $null = $sb.AppendLine()
    foreach ($h in $howToRead) { $null = $sb.AppendLine("- $(EscMd $h)") }
    $mdText = $sb.ToString()

    # ═════════════════════════════════════════════════════════════════════════
    # HTML: self-contained, no script, no external asset, escaped throughout
    # ═════════════════════════════════════════════════════════════════════════
    $chip = {
        param($state, $disp)
        $cls = switch -CaseSensitive ($state) {
            'Satisfied' { 'ok' }
            'Failed'    { 'bad' }
            default     { 'na' }
        }
        $extra = if ($disp -eq 'ApprovedException') { " <span class='exc'>approved exception</span>" } else { '' }
        return "<span class='chip $cls'>$(Esc $state)</span>$extra"
    }
    $thead = { param([string[]] $cols) '<thead><tr>' + (($cols | ForEach-Object { "<th scope='col'>$(Esc $_)</th>" }) -join '') + '</tr></thead>' }
    $stateTable = {
        param($rows)
        $h = "<table>$(& $thead @('Control', 'Title', 'Tier', 'A', 'B'))<tbody>"
        foreach ($r in $rows) {
            $h += "<tr><td class='id'>$(Esc $r.ControlId)</td><td>$(Esc $r.Title)</td><td>$(Esc (& $tierText $r.RequiredTierA))</td><td>$(& $chip $r.StateA $r.DispositionA)</td><td>$(& $chip $r.StateB $r.DispositionB)</td></tr>"
        }
        return $h + '</tbody></table>'
    }

    $outcomeHtml = "<table class='counts'>$(& $thead @('Result', 'Controls'))<tbody>"
    foreach ($o in $outcomeRows) { $outcomeHtml += "<tr><td>$(Esc $o[0])</td><td class='num'>$(Esc $o[1])</td></tr>" }
    $outcomeHtml += '</tbody></table>'

    $warnHtml = ''
    foreach ($w in @($Comparison.Warnings)) { $warnHtml += "<li class='warn'><strong>Warning.</strong> $(Esc $w)</li>" }
    foreach ($n in @($Comparison.Notes)) { $warnHtml += "<li>$(Esc $n)</li>" }

    $sideRows = @(
        , @('Tenant', $A.Name, $B.Name)
        , @('Run date (UTC)', (& $dateText $A.RunDate), (& $dateText $B.RunDate))
        , @('Target tier', (& $tierText $A.TargetTier), (& $tierText $B.TargetTier))
        , @('Baseline version', (& $tierText $A.BaselineVersion), (& $tierText $B.BaselineVersion))
        , @('Required controls', $A.RequiredControls, $B.RequiredControls)
        , @('Evidence freshness', (& $freshText $A), (& $freshText $B))
        , @('Licensed tier', $A.License.TierLabel, $B.License.TierLabel)
        , @('Evidence coverage', $A.EvidenceCoverage.Line, $B.EvidenceCoverage.Line)
        , @('Effectiveness coverage', $A.EffectivenessCoverage.Line, $B.EffectivenessCoverage.Line)
        , @('Approved exceptions among compared controls', $A.ApprovedExceptionsCompared, $B.ApprovedExceptionsCompared)
    )
    $sideHtml = "<table class='side'>$(& $thead @('', 'A', 'B'))<tbody>"
    foreach ($s in $sideRows) { $sideHtml += "<tr><th scope='row'>$(Esc $s[0])</th><td>$(Esc $s[1])</td><td>$(Esc $s[2])</td></tr>" }
    $sideHtml += '</tbody></table>'

    $licHtml = '<ul>' + (($licenseLines | ForEach-Object { "<li>$(Esc $_)</li>" }) -join '') + '</ul>'

    $diffHtml = if (@($Comparison.Differences).Count -eq 0) { '<p>None: no control is satisfied at one tenant and failed at the other.</p>' } else { & $stateTable @($Comparison.Differences) }
    $failHtml = if (@($Comparison.BothFailed).Count -eq 0) { '<p>None.</p>' } else { & $stateTable @($Comparison.BothFailed) }
    $okHtml   = if (@($Comparison.BothSatisfied).Count -eq 0) { '<p>None.</p>' } else { & $stateTable @($Comparison.BothSatisfied) }

    $ncHtml = '<p>Required at both tenants, but at least one run holds no verdict for the control. These are never counted as a match.</p>'
    if (@($Comparison.NotComparable).Count -eq 0) {
        $ncHtml += '<p>None.</p>'
    } else {
        $ncHtml += "<p>What each run lacked: A: $(Esc (& $causeLine $Comparison.NotComparableBy.A)). B: $(Esc (& $causeLine $Comparison.NotComparableBy.B)).</p>"
        $ncHtml += "<table>$(& $thead @('Control', 'Title', 'Tier', 'A', 'A reason code', 'B', 'B reason code'))<tbody>"
        foreach ($r in @($Comparison.NotComparable)) {
            $ncHtml += "<tr><td class='id'>$(Esc $r.ControlId)</td><td>$(Esc $r.Title)</td><td>$(Esc (& $tierText $r.RequiredTierA))</td><td>$(& $chip $r.StateA $r.DispositionA)</td><td><code>$(Esc $r.ReasonCodeA)</code></td><td>$(& $chip $r.StateB $r.DispositionB)</td><td><code>$(Esc $r.ReasonCodeB)</code></td></tr>"
        }
        $ncHtml += '</tbody></table>'
    }

    $ncoHtml = ''
    if (@($Comparison.NotCompared).Count -eq 0) {
        $ncoHtml = '<p>None: both tenants were assessed against the same set of controls.</p>'
    } else {
        $ncoHtml = '<p>Left out because only one tenant required the control (a lower tier or an older baseline version), or because its definition differs between the two files. The tier shown is the tier that required it.</p>'
        $ncoHtml += "<table>$(& $thead @('Control', 'Title', 'Why it is not compared'))<tbody>"
        foreach ($r in @($Comparison.NotCompared)) {
            $ncoHtml += "<tr><td class='id'>$(Esc $r.ControlId)</td><td>$(Esc $r.Title)</td><td>$(Esc (& $basisText $r))</td></tr>"
        }
        $ncoHtml += '</tbody></table>'
    }

    $legendHtml = if ($legend.Count -eq 0) { '<p>None.</p>' } else {
        $h = "<table>$(& $thead @('Code', 'Meaning'))<tbody>"
        foreach ($l in $legend) { $h += "<tr><td class='id'>$(Esc $l.Code)</td><td>$(Esc $l.Meaning)</td></tr>" }
        $h + '</tbody></table>'
    }
    $readHtml = '<ul>' + (($howToRead | ForEach-Object { "<li>$(Esc $_)</li>" }) -join '') + '</ul>'
    $generated = $GeneratedAt.ToUniversalTime().ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture)

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(Esc $title)</title>
<style>
*{box-sizing:border-box}
body{margin:0;font:15px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#111827;background:#f3f5f9}
.wrap{max-width:1040px;margin:0 auto;padding:28px 20px 60px}
h1{margin:0 0 6px;font-size:1.6rem;letter-spacing:-.02em}
h2{margin:0 0 8px;font-size:1.1rem}
.banner{background:#fff7e6;border:1px solid #f0d9a8;border-radius:8px;padding:10px 14px;margin:10px 0 16px;font-size:.9rem}
.meta{color:#4b5563;font-size:.86rem;margin-bottom:14px}
.card{background:#fff;border-radius:10px;padding:18px 22px;margin:16px 0;box-shadow:0 1px 3px rgba(0,0,0,.07)}
.headline{font-size:1.1rem;font-weight:700;margin:0 0 6px}
table{width:100%;border-collapse:collapse;font-size:.86rem;margin-top:10px}
th,td{padding:7px 9px;border-bottom:1px solid #e5e9f1;text-align:left;vertical-align:top}
th{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:#4b5563}
td.num{text-align:right;font-variant-numeric:tabular-nums}
td.id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;white-space:nowrap}
.side th[scope=row]{width:26%;text-transform:none;letter-spacing:0;font-size:.86rem;color:#111827}
.chip{display:inline-block;border-radius:12px;padding:1px 9px;font-size:.74rem;font-weight:700;border:1px solid transparent}
.ok{background:#dcfce7;color:#14532d;border-color:#86efac}
.bad{background:#fee2e2;color:#7f1d1d;border-color:#fca5a5}
.na{background:#eef0f4;color:#374151;border-color:#cbd2dc}
.exc{font-size:.72rem;color:#4b5563}
li.warn{color:#7c2d12}
ul{margin:6px 0 0;padding-left:20px}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.82rem}
@media print{body{background:#fff}.card{box-shadow:none;border:1px solid #d6dbe4;break-inside:avoid}}
</style></head><body><div class="wrap">
<h1>$(Esc $title)</h1>
<div class="banner"><strong>$(Esc $audience)</strong></div>
<div class="meta">A: $(Esc $A.Name) &middot; B: $(Esc $B.Name) &middot; generated $(Esc $generated) UTC</div>

<div class="card"><h2>Result</h2>
<p class="headline">$(Esc $Comparison.Headline)</p>
<p>$(Esc $Comparison.HeadlineDetail)</p>
$outcomeHtml
<p>$(Esc $scopeSentence)</p></div>

<div class="card"><h2>Basis of the comparison</h2><ul>$warnHtml</ul></div>

<div class="card"><h2>The two tenants</h2>
$sideHtml
<p>$(Esc $coverageNote)</p></div>

<div class="card"><h2>Licensing differences</h2>$licHtml</div>

<div class="card"><h2>Controls that differ</h2>$diffHtml</div>
<div class="card"><h2>Failed at both tenants</h2>$failHtml</div>
<div class="card"><h2>Satisfied at both tenants</h2>$okHtml</div>
<div class="card"><h2>Not comparable</h2>$ncHtml</div>
<div class="card"><h2>Not compared</h2>$ncoHtml</div>
<div class="card"><h2>Reason codes used</h2>$legendHtml</div>
<div class="card"><h2>How to read this</h2>$readHtml</div>
</div></body></html>
"@

    # ═════════════════════════════════════════════════════════════════════════
    # CSV: one row per control, compared or not, formula-safe
    # ═════════════════════════════════════════════════════════════════════════
    $csvRows = [System.Collections.Generic.List[object]]::new()
    foreach ($r in (@($Comparison.Differences) + @($Comparison.BothFailed) + @($Comparison.BothSatisfied) + @($Comparison.NotComparable))) {
        $csvRows.Add([pscustomobject][ordered]@{
            Section        = 'Compared'
            ControlId      = (CsvSafe $r.ControlId)
            Title          = (CsvSafe $r.Title)
            Classification = (CsvSafe $r.Classification)
            RequiredTierA  = (CsvSafe $r.RequiredTierA)
            RequiredTierB  = (CsvSafe $r.RequiredTierB)
            StateA         = (CsvSafe $r.StateA)
            ReasonCodeA    = (CsvSafe $r.ReasonCodeA)
            DispositionA   = (CsvSafe $r.DispositionA)
            StateB         = (CsvSafe $r.StateB)
            ReasonCodeB    = (CsvSafe $r.ReasonCodeB)
            DispositionB   = (CsvSafe $r.DispositionB)
        })
    }
    foreach ($r in @($Comparison.NotCompared)) {
        $csvRows.Add([pscustomobject][ordered]@{
            Section        = 'NotCompared'
            ControlId      = (CsvSafe $r.ControlId)
            Title          = (CsvSafe $r.Title)
            Classification = (CsvSafe $r.Basis)
            RequiredTierA  = (CsvSafe $r.RequiredTierA)
            RequiredTierB  = (CsvSafe $r.RequiredTierB)
            StateA         = ''
            ReasonCodeA    = ''
            DispositionA   = ''
            StateB         = ''
            ReasonCodeB    = ''
            DispositionB   = ''
        })
    }
    $csvText = (@($csvRows) | ConvertTo-Csv -NoTypeInformation) -join [Environment]::NewLine

    # ── Write: the files name tenants (unless anonymized), so they get the
    #    same access restriction as every other output.
    Set-TPSensitiveFileContent -Path $mdPath   -Content $mdText
    Set-TPSensitiveFileContent -Path $htmlPath -Content $html
    Set-TPSensitiveFileContent -Path $csvPath  -Content $csvText

    return [ordered]@{ Markdown = $mdPath; Html = $htmlPath; Csv = $csvPath }
}
