#Requires -Version 7.0
#
# Publish-TPDeviceGuide.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: NIST SP 800-53 Rev 5 device and endpoint GUIDE — reference material,
#          not an assessment.
#
#          This publisher touches no tenant and no endpoint. It reads
#          Config/nist-physical.json and Config/nist-800-53-catalog.json and
#          renders what 800-53 expects of devices — laptops, desktops, phones,
#          the media they hold and the rooms they sit in — with the concrete
#          ways to satisfy each control. It is the document you hand a client,
#          print for a technician, or work down during an on-site review.
#
#          It deliberately runs WITHOUT findings. A guide that requires a scan
#          first is not a guide, it is a report; and the point of this one is to
#          be usable before the tenant is connected, during the sales
#          conversation, and on a site with no laptop open.
#
#          -Findings is optional. When supplied, controls the assessment already
#          evidences are annotated with their verdict, so the same document can
#          double as a gap list after a run. The guide never changes what it
#          RECOMMENDS based on findings — only what it reports as already done.
#
# Inputs:  -OutputPath   .md path. The HTML is written alongside it with the
#                        same base name and an .html extension.
#          -Findings     optional; annotates controls with assessment verdicts.
#          -ClientName   optional; titles the document for a specific client.
#          -ConfigPath   optional override of nist-physical.json (tests).
#
# Consumes: Config/nist-physical.json, Config/nist-800-53-catalog.json.
#           No Graph. No EXO. No device access of any kind.
#

function Publish-TPDeviceGuide {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
            return $true
        })]
        [string] $OutputPath,

        [Parameter(Mandatory = $false)]
        [AllowNull()] [AllowEmptyCollection()]
        [object[]] $Findings,

        [Parameter(Mandatory = $false)]
        [AllowNull()] [AllowEmptyString()]
        [string] $ClientName,

        [Parameter(Mandatory = $false)]
        [string] $ConfigPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    function EscMd { param([object]$v) ([string]$v) -replace '\|', '\|' -replace '[\r\n]+', ' ' }
    function Esc   { param([object]$v) ConvertTo-TPHtmlSafe $v }

    # Strip nulls BEFORE counting. @($null).Count is 1, not 0 — so an omitted
    # -Findings made $annotate true and the guide printed
    # "Assessment result: Not assessed" against controls that no assessment had
    # ever looked at. A reference document asserting an assessment verdict it
    # never had is the one thing this file must not do.
    $findingList = @($Findings | Where-Object { $null -ne $_ })
    $annotate    = ($findingList.Count -gt 0)

    # The posture join gives us the same grouping and scope semantics the report
    # uses. With no findings every row simply carries no evidence, which is the
    # correct state for a document written before any assessment runs.
    $posture = if ($ConfigPath) {
        Get-TPNISTPhysicalPosture -Findings $findingList -ConfigPath $ConfigPath
    } else {
        Get-TPNISTPhysicalPosture -Findings $findingList
    }
    if (-not $posture.Available) {
        throw 'nist-physical.json could not be loaded — device guide not generated.'
    }
    $brand    = if ($script:TPBrand) { $script:TPBrand } else { @{} }
    $company  = if ($brand['CompanyName']) { [string]$brand['CompanyName'] } else { 'NRG Technology Services' }
    $client   = if ($ClientName) { $ClientName } else { '' }
    $date     = Get-Date -Format 'MMMM dd, yyyy'

    $totalItems   = @($posture.Groups | ForEach-Object { $_.Items }).Count
    $totalOptions = @($posture.Groups | ForEach-Object { $_.Items } | ForEach-Object { @($_.Options) }).Count

    $scopeBlurb = @{
        'Tenant'   = 'Microsoft 365 can evidence this control directly.'
        'Hybrid'   = 'Microsoft 365 evidences part of this control; the rest lives outside the tenant.'
        'Attested' = 'Not visible from Microsoft 365 under any configuration. Evidence must be collected and retained directly.'
    }

    # ─────────────────────────────────────────────────────────────────────────
    # Markdown
    # ─────────────────────────────────────────────────────────────────────────
    $sb = [System.Text.StringBuilder]::new()
    $title = if ($client) { "NIST SP 800-53 Rev 5 — Device and Endpoint Guide for $client" }
             else { 'NIST SP 800-53 Rev 5 — Device and Endpoint Guide' }
    $null = $sb.AppendLine("# $(EscMd $title)")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**Prepared by:** $(EscMd $company)  ")
    $null = $sb.AppendLine("**Date:** $(EscMd $date)  ")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("This is a **reference guide, not an assessment**. Nothing here was measured against your environment$(if ($annotate) { ' except where a control is explicitly marked with an assessment result' })  — it sets out what NIST SP 800-53 Revision 5 expects of the devices your people use, and the practical ways to satisfy each control.")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("$totalItems controls across $(@($posture.Groups).Count) areas, with $totalOptions implementation options. Most controls list more than one option on purpose: a business already standardized on a third-party endpoint suite, an existing badge system, or a managed print contract should be able to satisfy the control with what it has rather than being told to replace it.")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("### How to read this")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("| Marker | Meaning |")
    $null = $sb.AppendLine("|--------|---------|")
    $null = $sb.AppendLine("| **Tenant** | $(EscMd $scopeBlurb['Tenant']) |")
    $null = $sb.AppendLine("| **Hybrid** | $(EscMd $scopeBlurb['Hybrid']) |")
    $null = $sb.AppendLine("| **Attested** | $(EscMd $scopeBlurb['Attested']) |")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("An **Attested** control is not a lesser control. It is one where the evidence is a document, a photograph, a signed list, or a certificate — and an auditor will ask for it in exactly the same way they ask for a policy export.")
    $null = $sb.AppendLine()

    # Quick-reference checklist
    $null = $sb.AppendLine("## Quick reference")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("| # | Control | Area | Scope | Covers |")
    $null = $sb.AppendLine("|---|---------|------|-------|--------|")
    $i = 0
    foreach ($grp in $posture.Groups) {
        foreach ($it in $grp.Items) {
            $i++
            $null = $sb.AppendLine("| $i | **$(EscMd $it.NistControl)** $(EscMd $it.NistTitle) | $(EscMd $grp.Title) | $(EscMd $it.Scope) | $(EscMd $it.DeviceAspect) |")
        }
    }
    $null = $sb.AppendLine()

    foreach ($grp in $posture.Groups) {
        $null = $sb.AppendLine("## $(EscMd $grp.Title)")
        $null = $sb.AppendLine()
        if ($grp.Description) { $null = $sb.AppendLine("$(EscMd $grp.Description)"); $null = $sb.AppendLine() }

        foreach ($it in $grp.Items) {
            $null = $sb.AppendLine("### $(EscMd $it.NistControl) — $(EscMd $it.NistTitle)")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("**Scope:** $(EscMd $it.Scope) — $(EscMd $scopeBlurb[[string]$it.Scope])")
            $null = $sb.AppendLine()
            if ($it.DeviceAspect) {
                $null = $sb.AppendLine("**What it covers.** $(EscMd $it.DeviceAspect)")
                $null = $sb.AppendLine()
            }
            $null = $sb.AppendLine("**How to satisfy it — pick what fits the environment:**")
            $null = $sb.AppendLine()
            foreach ($opt in @($it.Options)) { $null = $sb.AppendLine("- $(EscMd $opt)") }
            $null = $sb.AppendLine()
            if ($it.OffTenantEvidence) {
                $null = $sb.AppendLine("**Evidence to keep.** $(EscMd $it.OffTenantEvidence)")
                $null = $sb.AppendLine()
            }
            if ($annotate -and @($it.Evidence).Count -gt 0) {
                $ev = (@($it.Evidence) | ForEach-Object { "$($_.ControlId) — $($_.State)" }) -join '; '
                $null = $sb.AppendLine("**Assessment result.** $(EscMd $it.Status). Based on: $(EscMd $ev)")
                $null = $sb.AppendLine()
            }
        }
    }

    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("_Reference guide only. Control text is derived from NIST SP 800-53 Revision 5; implementation options are $(EscMd $company) guidance and are not part of the publication. Nothing in this document was collected from a device._")

    if (Get-Command Set-TPSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-TPSensitiveFileContent -Path $OutputPath -Content $sb.ToString()
    } else {
        $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8
    }

    # ─────────────────────────────────────────────────────────────────────────
    # HTML — self-contained, printable. No external assets: this gets emailed,
    # opened offline, and printed on a site with no network.
    # ─────────────────────────────────────────────────────────────────────────
    $scopeCls = @{ 'Tenant' = 'sc-t'; 'Hybrid' = 'sc-h'; 'Attested' = 'sc-a' }

    $navHtml = ''
    foreach ($grp in $posture.Groups) {
        $navHtml += "<a href='#g-$(Esc $grp.Id)'>$(Esc $grp.Title)</a>"
    }

    $quickRows = ''
    $i = 0
    foreach ($grp in $posture.Groups) {
        foreach ($it in $grp.Items) {
            $i++
            $cls = if ($scopeCls.ContainsKey([string]$it.Scope)) { $scopeCls[[string]$it.Scope] } else { 'sc-a' }
            $quickRows += "<tr><td class='qn'>$i</td><td class='qc'>$(Esc $it.NistControl)</td><td class='qt'>$(Esc $it.NistTitle)</td><td class='qa'>$(Esc $grp.Title)</td><td><span class='sc $cls'>$(Esc $it.Scope)</span></td></tr>"
        }
    }

    $bodyHtml = ''
    foreach ($grp in $posture.Groups) {
        $items = ''
        foreach ($it in $grp.Items) {
            $cls = if ($scopeCls.ContainsKey([string]$it.Scope)) { $scopeCls[[string]$it.Scope] } else { 'sc-a' }
            $opts = ''
            foreach ($opt in @($it.Options)) { $opts += "<li>$(Esc $opt)</li>" }
            $items += @"
<div class='item'>
  <div class='item-hd'>
    <span class='cid'>$(Esc $it.NistControl)</span>
    <span class='ctitle'>$(Esc $it.NistTitle)</span>
    <span class='sc $cls'>$(Esc $it.Scope)</span>
  </div>
  $(if ($it.DeviceAspect) { "<p class='aspect'>$(Esc $it.DeviceAspect)</p>" })
  <div class='opts'><div class='lbl'>How to satisfy it &mdash; pick what fits</div><ul>$opts</ul></div>
  $(if ($it.OffTenantEvidence) { "<div class='ev'><div class='lbl'>Evidence to keep</div>$(Esc $it.OffTenantEvidence)</div>" })
  $(if ($annotate -and @($it.Evidence).Count -gt 0) {
      $ev = (@($it.Evidence) | ForEach-Object { "$($_.ControlId) &mdash; $($_.State)" }) -join '; '
      "<div class='res'><div class='lbl'>Assessment result</div><strong>$(Esc $it.Status)</strong>. Based on: $(Esc $ev)</div>"
   })
</div>
"@
        }
        $bodyHtml += @"
<section class='grp' id='g-$(Esc $grp.Id)'>
  <h2>$(Esc $grp.Title)</h2>
  $(if ($grp.Description) { "<p class='gdesc'>$(Esc $grp.Description)</p>" })
  $items
</section>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(Esc $title)</title>
<style>
*{box-sizing:border-box}
body{margin:0;font:15px/1.65 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#111827;background:#eef2f8}
.wrap{max-width:1000px;margin:0 auto;padding:0 20px 60px}
header{background:linear-gradient(138deg,#0f2544 0%,#061325 100%);color:#fff;padding:40px 0 0;margin-bottom:26px}
header .wrap{padding-bottom:0}
.eyebrow{font-size:.66rem;letter-spacing:.18em;text-transform:uppercase;color:#e8621a;font-weight:700;margin-bottom:8px}
h1{margin:0 0 10px;font-size:1.85rem;letter-spacing:-.03em;line-height:1.15}
.meta{font-size:.83rem;color:rgba(255,255,255,.55);margin-bottom:22px}
.meta strong{color:rgba(255,255,255,.85);font-weight:600}
nav{display:flex;flex-wrap:wrap;gap:2px;border-top:1px solid rgba(255,255,255,.08);padding-top:2px}
nav a{padding:10px 14px;font-size:.68rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:rgba(255,255,255,.42);text-decoration:none;border-bottom:2px solid transparent}
nav a:hover{color:#fff;border-bottom-color:#e8621a}
.card{background:#fff;border-radius:12px;padding:22px 26px;margin-bottom:22px;box-shadow:0 1px 3px rgba(0,0,0,.05),0 4px 18px rgba(15,37,68,.07)}
.lede{font-size:1rem;line-height:1.7}
.lede strong{color:#0f2544}
h2{font-size:1.25rem;letter-spacing:-.02em;margin:0 0 6px}
h3{margin:0}
table{width:100%;border-collapse:collapse;font-size:.82rem}
th{text-align:left;padding:9px 10px;font-size:.63rem;text-transform:uppercase;letter-spacing:.07em;color:#6b7280;background:#eef2f8;border-bottom:1px solid #e2e8f0}
td{padding:9px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top}
tr:last-child td{border-bottom:none}
.qn{color:#9ca3af;width:34px}
.qc{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:800;color:#4c1d95;white-space:nowrap}
.qt{font-weight:600}
.qa{color:#6b7280;white-space:nowrap}
.sc{display:inline-block;font-size:.62rem;font-weight:800;padding:3px 9px;border-radius:20px;white-space:nowrap;letter-spacing:.04em}
.sc-t{background:#d1fae5;color:#065f46}
.sc-h{background:#fef3c7;color:#92400e}
.sc-a{background:#ede9fe;color:#5b21b6}
.grp{margin-bottom:26px}
.grp>h2{padding:0 4px}
.gdesc{color:#6b7280;font-size:.88rem;margin:0 4px 14px;line-height:1.6}
.item{background:#fff;border-radius:12px;padding:18px 22px;margin-bottom:12px;box-shadow:0 1px 3px rgba(0,0,0,.05),0 4px 14px rgba(15,37,68,.05)}
.item-hd{display:flex;align-items:baseline;gap:11px;flex-wrap:wrap;margin-bottom:9px}
.cid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:900;color:#4c1d95;font-size:.92rem}
.ctitle{font-weight:700;font-size:1rem;flex:1;min-width:220px}
.aspect{margin:0 0 12px;line-height:1.65}
.lbl{font-size:.6rem;font-weight:800;text-transform:uppercase;letter-spacing:.09em;color:#6b7280;margin-bottom:5px}
.opts{background:#f8fafc;border-left:3px solid #3b7dd8;border-radius:0 8px 8px 0;padding:12px 16px;margin-bottom:10px}
.opts ul{margin:0;padding-left:18px}
.opts li{margin-bottom:5px;line-height:1.6}
.opts li:last-child{margin-bottom:0}
.ev{background:#fdf6ec;border-left:3px solid #e8621a;border-radius:0 8px 8px 0;padding:12px 16px;font-size:.9rem;line-height:1.6;margin-bottom:10px}
.res{background:#f5f3ff;border-left:3px solid #4c1d95;border-radius:0 8px 8px 0;padding:12px 16px;font-size:.9rem;line-height:1.6}
footer{color:#6b7280;font-size:.78rem;line-height:1.6;padding:0 4px}
@media print{
  body{background:#fff}
  header{background:#0f2544 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  nav{display:none}
  .card,.item{box-shadow:none;border:1px solid #e2e8f0;break-inside:avoid}
  .item{page-break-inside:avoid}
}
</style></head><body>
<header><div class="wrap">
  <div class="eyebrow">Reference guide &middot; not an assessment</div>
  <h1>$(Esc $title)</h1>
  <div class="meta">Prepared by <strong>$(Esc $company)</strong> &middot; $(Esc $date) &middot; <strong>$totalItems</strong> controls &middot; <strong>$totalOptions</strong> implementation options</div>
  <nav>$navHtml</nav>
</div></header>

<div class="wrap">
  <div class="card lede">
    <p style="margin-top:0">Nothing in this document was collected from a device$(if ($annotate) { ", except where a control carries an explicit assessment result" }). It sets out what <strong>NIST SP 800-53 Revision 5</strong> expects of the devices your people use &mdash; laptops, desktops, phones, the media they hold and the rooms they sit in &mdash; and the practical ways to satisfy each control.</p>
    <p>Most controls list more than one option deliberately. A business already standardized on a third-party endpoint suite, an existing badge system, or a managed disposal contract should be able to satisfy the control with what it already has, rather than being told to replace it.</p>
    <table style="margin-top:14px">
      <thead><tr><th style="width:110px">Marker</th><th>Meaning</th></tr></thead>
      <tbody>
        <tr><td><span class="sc sc-t">Tenant</span></td><td>$(Esc $scopeBlurb['Tenant'])</td></tr>
        <tr><td><span class="sc sc-h">Hybrid</span></td><td>$(Esc $scopeBlurb['Hybrid'])</td></tr>
        <tr><td><span class="sc sc-a">Attested</span></td><td>$(Esc $scopeBlurb['Attested'])</td></tr>
      </tbody>
    </table>
    <p style="margin-bottom:0"><strong>An Attested control is not a lesser control.</strong> It is one where the evidence is a document, a photograph, a signed list, or a certificate &mdash; and an auditor will ask for it in exactly the same way they ask for a policy export.</p>
  </div>

  <div class="card">
    <h2>Quick reference</h2>
    <table><thead><tr><th></th><th>Control</th><th>Title</th><th>Area</th><th>Scope</th></tr></thead>
    <tbody>$quickRows</tbody></table>
  </div>

  $bodyHtml

  <footer>Reference guide only. Control identifiers and titles are from NIST SP 800-53 Revision 5; the implementation options are $(Esc $company) guidance and are not part of the publication.</footer>
</div>
</body></html>
"@

    $htmlPath = [System.IO.Path]::ChangeExtension($OutputPath, '.html')
    if (Get-Command Set-TPSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-TPSensitiveFileContent -Path $htmlPath -Content $html
    } else {
        $html | Out-File -LiteralPath $htmlPath -Encoding utf8
    }
}
