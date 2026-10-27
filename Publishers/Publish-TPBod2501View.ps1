#Requires -Version 7.0
#
# Publish-TPBod2501View.ps1
# TenantPosture
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
#
# Purpose: Renders the CISA BOD 25-01 required-configurations view
#          (Get-TPBod2501View) as Markdown plus a self-contained HTML page:
#          every Microsoft 365 policy CISA lists as required, what this
#          assessment's checks found for it, what they do not check, and the
#          independent ScubaGear result beside it when one was supplied.
#
# Data keys: none (consumes the view object). Graph / cmdlets: none.
#
# Rules (pinned by TP.Bod2501.Tests.ps1):
#   - Page one says this is a technical readiness view and not an attestation,
#     that BOD 25-01 binds federal civilian executive branch agencies, and that
#     ScubaGear is CISA's assessment tool whose output is what CISA expects;
#     it gives the count per status and names any product not assessed.
#   - No status and no sentence states that a requirement is fulfilled; the
#     strongest status is 'Tool-verified: met'.
#   - A disagreement with ScubaGear is flagged for review, never resolved in
#     favor of either result.
#   - Every finding's detail is shown, a passing one's included.
#   - Every value is escaped (Markdown through ConvertTo-TPMarkdownSafe, HTML
#     through ConvertTo-TPHtmlSafe); the HTML carries a Content-Security-Policy
#     that allows no script and no external resource.

function Publish-TPBod2501View {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary] $View,

        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
            return $true
        })]
        [string] $OutputPath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [hashtable] $Metadata
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not $View['Available']) {
        $why = [string](Get-TPObjectField -Item $View -Key 'UnavailableReason' -Default 'bod-25-01-required.json missing or empty')
        Write-Warning "BOD 25-01 view unavailable ($why): not generated."
        return
    }

    function EscMd { param([object]$v) ConvertTo-TPMarkdownSafe $v }   # one Markdown rule for the whole tool
    function Esc   { param([object]$v) ConvertTo-TPHtmlSafe $v }

    $st       = Get-TPBod2501StatusNames
    $differ   = Get-TPBod2501DifferLabel
    $policies = @($View['Policies'])
    $products = @($View['Products'])
    $sum      = $View['Summary']

    $brand   = if ($script:TPBrand) { $script:TPBrand } else { @{} }
    $company = if ($brand['CompanyName']) { [string]$brand['CompanyName'] } else { 'NRG Technology Services' }
    $tenant  = [string](Get-TPObjectField -Item $Metadata -Key 'TenantDomain'   -Default '')
    $date    = [string](Get-TPObjectField -Item $Metadata -Key 'AssessmentDate' -Default (Get-Date -Format 'yyyy-MM-dd'))

    $title = if ($tenant) { "BOD 25-01 Required Configurations: $tenant" } else { 'BOD 25-01 Required Configurations' }

    $notAssessedProducts = @($sum['ProductsNotAssessed'])
    $countText = (@($st.Values) | ForEach-Object { "$($sum['ByStatus'][$_]) $_" }) -join '; '
    $indepText =
        if ($View['IndependentSupplied']) { "ScubaGear results were supplied for this run and are shown beside each policy. $($sum['Differ']) policies are flagged '$differ'." }
        elseif ($View['IndependentError']) { "ScubaGear results were requested but not used: $($View['IndependentError'])" }
        else { 'No ScubaGear results were supplied for this run (-ScubaResultsPath), so no independent result is shown.' }

    $notice = @(
        'This is a technical readiness view, not an attestation. It shows which BOD 25-01 required configurations the checks in this Microsoft 365 assessment bear on and what they found. It is not a statement that any requirement of the directive is met, and it is not a substitute for the reporting the directive requires.'
        "CISA Binding Operational Directive 25-01 (issued $($View['DirectiveIssued'])) applies to federal civilian executive branch (FCEB) agencies. In scope: $($View['AppliesTo'])"
        'ScubaGear is CISA''s assessment tool for these configurations, and its output is what CISA expects an agency to run and report. This view does not replace it. Where both results are shown and they point in opposite directions, the policy is flagged for review; neither result is preferred.'
        "Policies: $($sum['Total']). $countText. $($sum['Equivalent']) have at least one check that judges the same requirement (Equivalent), $($sum['PartialOnly']) only checks that cover part of it, $($sum['NotCounted']) only citations that establish nothing about it, and $($sum['Uncited']) no check at all."
        $(if ($notAssessedProducts.Count -gt 0) { "Products this tool does not assess: $($notAssessedProducts -join ', '). Their required configurations need ScubaGear's results or manual evidence." } else { 'Every Microsoft 365 product on CISA''s list is one this tool reads; a policy no check covers still needs ScubaGear''s result or manual evidence.' })
        "Statuses report technical checks. '$($st.Met)' means every check that judges the same requirement passed this run; '$($st.Partly)' means only part of the requirement was checked, and the policy names what was not."
        $indepText
    )
    $sourceLine = "Required list: $(@($View['Source']) -join ', '), retrieved $($View['SourceRetrieved']). $($View['Basis']) Checked against ScubaGear $($View['ScubaGearVersion']); control relations from the ScubaGear alignment record checked $($View['AlignmentChecked'])."

    # ── Markdown ─────────────────────────────────────────────────────────────
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("# $(EscMd $title)")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**View:** $(EscMd $View['Framework'])  ")
    if ($tenant) { $null = $sb.AppendLine("**Tenant:** $(EscMd $tenant)  ") }
    $null = $sb.AppendLine("**Prepared by:** $(EscMd $company)  ")
    $null = $sb.AppendLine("**Date:** $(EscMd $date)  ")
    $null = $sb.AppendLine("**Required list retrieved:** $(EscMd $View['SourceRetrieved'])")
    $null = $sb.AppendLine()
    foreach ($n in $notice) { $null = $sb.AppendLine("> $(EscMd $n)"); $null = $sb.AppendLine('>') }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('## Summary')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('| Product | Policies | ' + ((@($st.Values) | ForEach-Object { EscMd $_ }) -join ' | ') + ' |')
    $null = $sb.AppendLine('|---|---:|' + ((@($st.Values) | ForEach-Object { '---:' }) -join '|') + '|')
    foreach ($p in $products) {
        $null = $sb.AppendLine("| $(EscMd $p['Name']) | $($p['Total']) | " + ((@($st.Values) | ForEach-Object { $p['ByStatus'][$_] }) -join ' | ') + ' |')
    }
    $null = $sb.AppendLine("| All | $($sum['Total']) | " + ((@($st.Values) | ForEach-Object { $sum['ByStatus'][$_] }) -join ' | ') + ' |')
    $null = $sb.AppendLine()

    foreach ($p in $products) {
        $null = $sb.AppendLine("## $(EscMd $p['Name'])")
        $null = $sb.AppendLine()
        foreach ($r in @($policies | Where-Object { $_['Product'] -eq $p['Key'] })) {
            $null = $sb.AppendLine("### $(EscMd $r['PolicyId'])")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("_$(EscMd $r['Statement'])_")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("**Status:** $(EscMd $r['Status'])  ")
            if ($r['IndependentResult']) { $null = $sb.AppendLine("**ScubaGear:** $(EscMd $r['IndependentResult'])  ") }
            elseif ($View['IndependentSupplied']) { $null = $sb.AppendLine('**ScubaGear:** not in the supplied results  ') }
            if ($r['ResultsDiffer']) { $null = $sb.AppendLine("**$(EscMd $differ)**  ") }
            $null = $sb.AppendLine("CISA date added or modified: $(EscMd $r['CisaDateAddedOrModified']); due: $(EscMd $r['CisaDueDate']).")
            $null = $sb.AppendLine()
            foreach ($nc in @($r['NotChecked'])) { $null = $sb.AppendLine("- Not checked: $(EscMd $nc)") }
            if (@($r['RelatedShortfalls']).Count -gt 0) {
                $null = $sb.AppendLine("- Other checks citing this policy report a shortfall: $(EscMd (@($r['RelatedShortfalls']) -join ', ')).")
            }
            foreach ($c in @($r['CitedNotCounted'])) {
                $null = $sb.AppendLine("- Cited by $(EscMd $c['ControlId']) [$(EscMd $c['Relation'])], not counted: $(EscMd $c['Note'])")
            }
            if (@($r['NotChecked']).Count -gt 0 -or @($r['RelatedShortfalls']).Count -gt 0 -or @($r['CitedNotCounted']).Count -gt 0) { $null = $sb.AppendLine() }
            if (@($r['Controls']).Count -gt 0) {
                $null = $sb.AppendLine('| Control | Relation | Result | Detail | Remediation |')
                $null = $sb.AppendLine('|---|---|---|---|---|')
                foreach ($c in @($r['Controls'])) {
                    $ev = @($c['Evidence'])
                    if ($ev.Count -eq 0) {
                        $nameText = EscMd ([string]$c['ControlId'] + ' ' + [string]$c['Title'])
                        $null = $sb.AppendLine('| ' + $nameText + ' | ' + (EscMd $c['Relation']) + ' | ' + (EscMd $c['State']) + ' | no finding this run |  |')
                    }
                    foreach ($e in $ev) {
                        $cidText = if ($e['Instance']) { "$($c['ControlId']) ($($e['Instance'])) $($c['Title'])" } else { "$($c['ControlId']) $($c['Title'])" }
                        $null = $sb.AppendLine("| $(EscMd $cidText) | $(EscMd $c['Relation']) | $(EscMd $e['State']) | $(EscMd $e['Detail']) | $(EscMd $c['Remediation']) |")
                    }
                }
                $null = $sb.AppendLine()
                foreach ($c in @($r['Controls'] | Where-Object { $_['Relation'] -ne 'Equivalent' })) {
                    $null = $sb.AppendLine("$(EscMd $c['ControlId']) relation: $(EscMd $c['Note'])")
                    $null = $sb.AppendLine()
                }
            }
        }
    }

    $manual = @($policies | Where-Object { $_['Status'] -in @($st.Manual, $st.ProductNotAssessed) })
    $null = $sb.AppendLine('## Needs ScubaGear results or manual evidence')
    $null = $sb.AppendLine()
    foreach ($r in $manual) { $null = $sb.AppendLine("- $(EscMd $r['PolicyId']): $(EscMd $r['Statement'])") }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('## The directive')
    $null = $sb.AppendLine()
    foreach ($a in @($View['RequiredActions'])) { $null = $sb.AppendLine("- $(EscMd $a)") }
    $null = $sb.AppendLine()
    if ($View['NotEncoded']) { $null = $sb.AppendLine((EscMd $View['NotEncoded'])); $null = $sb.AppendLine() }
    $null = $sb.AppendLine('---')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("_Prepared by $(EscMd $company). $(EscMd $sourceLine) $(EscMd $View['SourceNote'])_")

    if (Get-Command Set-TPSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-TPSensitiveFileContent -Path $OutputPath -Content $sb.ToString()
    } else {
        $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8
    }

    # ── HTML ─────────────────────────────────────────────────────────────────
    $cls = {
        param($s)
        if ($s -eq $st.Met) { 'ok' } elseif ($s -eq $st.Shortfall) { 'gap' } elseif ($s -eq $st.Partly) { 'part' } elseif ($s -eq $st.NotAssessed) { 'open' } else { 'att' }
    }
    $h = [System.Text.StringBuilder]::new()
    $null = $h.Append(@"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(Esc $title)</title>
<style>
*{box-sizing:border-box}
body{margin:0;font:15px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#111827;background:#eef2f8}
.wrap{max-width:1180px;margin:0 auto;padding:0 16px 60px}
header{background:#0f2544;color:#fff;padding:32px 0 20px}
h1{margin:0 0 6px;font-size:1.7rem}
.meta{font-size:.85rem;color:rgba(255,255,255,.75)}
.card{background:#fff;border-radius:12px;padding:20px 24px;margin:22px 0;box-shadow:0 1px 3px rgba(0,0,0,.06);overflow-x:auto}
.warn{background:#fffbeb;border-left:4px solid #f59e0b;padding:12px 16px;margin:10px 0;font-size:.92rem}
table{width:100%;border-collapse:collapse;font-size:.86rem;margin-top:10px}
th{text-align:left;font-size:.66rem;text-transform:uppercase;letter-spacing:.07em;color:#6b7280;padding:6px 8px;border-bottom:2px solid #e2e8f0}
td{padding:7px 8px;border-bottom:1px solid #eef2f8;vertical-align:top}
td.n{text-align:right;font-variant-numeric:tabular-nums}
.pid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;white-space:nowrap;color:#4c1d95}
.ok{color:#065f46;font-weight:700}.gap{color:#991b1b;font-weight:700}.part{color:#92400e;font-weight:700}.open{color:#6b7280;font-weight:700}.att{color:#1e3a8a;font-weight:700}
.differ{display:inline-block;margin-top:4px;padding:1px 8px;border-radius:999px;background:#fde68a;color:#78350f;font-size:.78rem;font-weight:700}
.small{font-size:.8rem;color:#4b5563}
@media print{body{background:#fff}.card{box-shadow:none;border:1px solid #e5e7eb}}
</style></head><body>
<header><div class="wrap"><h1>$(Esc $title)</h1>
<div class="meta">$(Esc $View['Framework']) &middot; Prepared by $(Esc $company) &middot; $(Esc $date) &middot; required list retrieved $(Esc $View['SourceRetrieved'])</div></div></header>
<div class="wrap">
<div class="card">
"@)
    foreach ($n in $notice) { $null = $h.Append("<div class=`"warn`">$(Esc $n)</div>") }
    $null = $h.Append('<table><tr><th>Product</th><th>Policies</th>')
    foreach ($s in @($st.Values)) { $null = $h.Append("<th>$(Esc $s)</th>") }
    $null = $h.Append('</tr>')
    foreach ($p in $products) {
        $null = $h.Append("<tr><td>$(Esc $p['Name'])</td><td class=`"n`">$($p['Total'])</td>")
        foreach ($s in @($st.Values)) { $null = $h.Append("<td class=`"n`">$($p['ByStatus'][$s])</td>") }
        $null = $h.Append('</tr>')
    }
    $null = $h.Append("<tr><td><b>All</b></td><td class=`"n`"><b>$($sum['Total'])</b></td>")
    foreach ($s in @($st.Values)) { $null = $h.Append("<td class=`"n`"><b>$($sum['ByStatus'][$s])</b></td>") }
    $null = $h.Append('</tr></table></div>')

    foreach ($p in $products) {
        $null = $h.Append("<div class=`"card`"><h2>$(Esc $p['Name'])</h2><table><tr><th>Policy</th><th>Requirement</th><th>Status</th><th>Checks in this assessment</th><th>ScubaGear</th></tr>")
        foreach ($r in @($policies | Where-Object { $_['Product'] -eq $p['Key'] })) {
            $ev = [System.Text.StringBuilder]::new()
            foreach ($c in @($r['Controls'])) {
                $null = $ev.Append("<div><span class=`"pid`">$(Esc $c['ControlId'])</span> $(Esc $c['Title']) <span class=`"small`">[$(Esc $c['Relation'])]</span>: <b>$(Esc $c['State'])</b>")
                foreach ($e in @($c['Evidence'])) {
                    $inst = if ($e['Instance']) { "$($e['Instance']): " } else { '' }
                    if ($e['Detail']) { $null = $ev.Append("<div class=`"small`">$(Esc "$inst$($e['State']). $($e['Detail'])")</div>") }
                }
                if ($c['Relation'] -ne 'Equivalent') { $null = $ev.Append("<div class=`"small`"><b>Relation:</b> $(Esc $c['Note'])</div>") }
                if ($c['Remediation']) { $null = $ev.Append("<div class=`"small`"><b>Remediation:</b> $(Esc $c['Remediation'])</div>") }
                $null = $ev.Append('</div>')
            }
            foreach ($nc in @($r['NotChecked'])) { $null = $ev.Append("<div class=`"small`"><b>Not checked:</b> $(Esc $nc)</div>") }
            if (@($r['RelatedShortfalls']).Count -gt 0) { $null = $ev.Append("<div class=`"small`">Other checks citing this policy report a shortfall: $(Esc (@($r['RelatedShortfalls']) -join ', ')).</div>") }
            foreach ($c in @($r['CitedNotCounted'])) { $null = $ev.Append("<div class=`"small`">Cited by $(Esc $c['ControlId']) [$(Esc $c['Relation'])], not counted: $(Esc $c['Note'])</div>") }
            if ($ev.Length -eq 0) { $null = $ev.Append('<span class="small">No check in this assessment bears on this policy.</span>') }
            $ind = if ($r['IndependentResult']) { Esc $r['IndependentResult'] } elseif ($View['IndependentSupplied']) { '<span class="small">not in the supplied results</span>' } else { '<span class="small">not supplied</span>' }
            if ($r['ResultsDiffer']) { $ind += "<div class=`"differ`">$(Esc $differ)</div>" }
            $null = $h.Append("<tr><td class=`"pid`">$(Esc $r['PolicyId'])</td><td>$(Esc $r['Statement'])<div class=`"small`">CISA date added or modified: $(Esc $r['CisaDateAddedOrModified']); due: $(Esc $r['CisaDueDate'])</div></td><td class=`"$(& $cls $r['Status'])`">$(Esc $r['Status'])</td><td>$($ev.ToString())</td><td>$ind</td></tr>")
        }
        $null = $h.Append('</table></div>')
    }

    $null = $h.Append('<div class="card"><h2>Needs ScubaGear results or manual evidence</h2><ul>')
    foreach ($r in $manual) { $null = $h.Append("<li><span class=`"pid`">$(Esc $r['PolicyId'])</span> $(Esc $r['Statement'])</li>") }
    $null = $h.Append('</ul><h2>The directive</h2><ul>')
    foreach ($a in @($View['RequiredActions'])) { $null = $h.Append("<li>$(Esc $a)</li>") }
    $null = $h.Append('</ul>')
    if ($View['NotEncoded']) { $null = $h.Append("<p class=`"small`">$(Esc $View['NotEncoded'])</p>") }
    $null = $h.Append("<p class=`"small`">Prepared by $(Esc $company). $(Esc $sourceLine) $(Esc $View['SourceNote'])</p></div>")
    $null = $h.Append('</div></body></html>')

    $htmlPath = [System.IO.Path]::ChangeExtension($OutputPath, '.html')
    if (Get-Command Set-TPSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-TPSensitiveFileContent -Path $htmlPath -Content $h.ToString()
    } else {
        $h.ToString() | Out-File -LiteralPath $htmlPath -Encoding utf8
    }
    Write-Verbose "BOD 25-01 view written: $OutputPath, $htmlPath"
}
