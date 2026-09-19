#Requires -Version 7.0
#
# Publish-NRGDeviceBaseline.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: The managed device BUILD STANDARD — what every device gets, in the
#          order the work actually happens.
#
#          Distinct from Publish-NRGDeviceGuide, deliberately. The guide is
#          organized by 800-53 control and answers "what does the framework
#          require". This is organized by lifecycle stage and answers "what do I
#          do to this laptop, and in what order". A technician provisioning a
#          machine does not work AC-11 then SC-28; they image it, enroll it,
#          encrypt it, harden it, and hand it over. Same controls underneath,
#          sequenced for the person doing the work.
#
#          Leads with a one-page checklist — the part that gets printed and
#          worked down — and puts the reasoning underneath for the person who
#          has to justify a step or handle an exception.
#
#          Touches nothing: no Graph, no Exchange Online, no device access. It
#          renders Config/device-baseline.json and nothing else.
#
# Inputs:  -OutputPath   .md path. HTML written alongside with the same base name.
#          -ClientName   optional; titles the standard for a specific client.
#          -ConfigPath   optional override of device-baseline.json (tests).
#
# Consumes: Config/device-baseline.json. Optionally Config/controls.json, only
#           to render the title of a control named in VerifiedBy.
#

function Publish-NRGDeviceBaseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
            return $true
        })]
        [string] $OutputPath,

        [Parameter(Mandatory = $false)]
        [AllowNull()] [AllowEmptyString()]
        [string] $ClientName,

        [Parameter(Mandatory = $false)]
        [string] $ConfigPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    function EscMd { param([object]$v) ([string]$v) -replace '\|', '\|' -replace '[\r\n]+', ' ' }
    function Esc   { param([object]$v) ConvertTo-NRGHtmlSafe $v }

    $moduleRoot = if ($script:NRGModuleRoot) { $script:NRGModuleRoot }
                  elseif ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot }
                  else { (Get-Location).Path }
    $path = if ($ConfigPath) { $ConfigPath } else { Join-Path $moduleRoot 'Config' 'device-baseline.json' }

    if (-not (Test-Path -LiteralPath $path)) {
        throw "device-baseline.json not found at $path — device baseline not generated."
    }
    if (-not $ConfigPath) {
        $resolved     = [System.IO.Path]::GetFullPath($path)
        $resolvedRoot = [System.IO.Path]::GetFullPath($moduleRoot)
        if (-not $resolved.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "device-baseline.json resolved outside module root: $resolved"
        }
    }

    try {
        $cfg = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "device-baseline.json is not valid JSON — device baseline not generated: $($_.Exception.Message)"
    }

    $stages = @(Get-NRGObjectField -Item $cfg -Key 'stages' -Default @())
    if ($stages.Count -eq 0) { throw 'device-baseline.json contains no stages — device baseline not generated.' }

    $allItems = @(foreach ($s in $stages) { foreach ($i in @(Get-NRGObjectField -Item $s -Key 'Items' -Default @())) { $i } })
    $mandatory = @($allItems | Where-Object { $_.Mandatory }).Count

    # Control titles, only to make a VerifiedBy reference readable. Absent
    # controls.json simply means the bare ID renders — never a failure.
    $cdefs = @{}
    try { foreach ($c in (Get-NRGControlDefinitions)) { $cdefs[$c.ControlId] = [string]$c.Title } } catch { }

    $brand   = if ($script:NRGBrand) { $script:NRGBrand } else { @{} }
    $company = if ($brand['CompanyName']) { [string]$brand['CompanyName'] } else { 'NRG Technology Services' }
    $title   = [string](Get-NRGObjectField -Item $cfg -Key 'title'    -Default 'Managed Device Baseline')
    $sub     = [string](Get-NRGObjectField -Item $cfg -Key 'subtitle' -Default '')
    if ($ClientName) { $title = "$title — $ClientName" }
    $date = Get-Date -Format 'MMMM dd, yyyy'

    # ─────────────────────────────────────────────────────────────────────────
    # Markdown
    # ─────────────────────────────────────────────────────────────────────────
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("# $(EscMd $title)")
    $null = $sb.AppendLine()
    if ($sub) { $null = $sb.AppendLine("**$(EscMd $sub)**"); $null = $sb.AppendLine() }
    $null = $sb.AppendLine("**Standard owner:** $(EscMd $company)  ")
    $null = $sb.AppendLine("**Version:** $(EscMd ([string](Get-NRGObjectField -Item $cfg -Key 'version' -Default '1.0')))  ")
    $null = $sb.AppendLine("**Date:** $(EscMd $date)  ")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("$($allItems.Count) requirements across $($stages.Count) stages, of which **$mandatory are mandatory**. A device that misses a mandatory item is not a managed device — it is an unmanaged device with an asset tag.")
    $null = $sb.AppendLine()

    # The part that gets printed.
    $null = $sb.AppendLine("## Build checklist")
    $null = $sb.AppendLine()
    # Single-quoted: a backtick in a DOUBLE-quoted string is the escape
    # character, so the code-span markers were silently eaten (and `$ escaped
    # the interpolation outright).
    $null = $sb.AppendLine('Work top to bottom. `M` marks a mandatory item.')
    $null = $sb.AppendLine()
    foreach ($stage in $stages) {
        $null = $sb.AppendLine("**$(EscMd $stage.Title)**")
        $null = $sb.AppendLine()
        foreach ($it in @(Get-NRGObjectField -Item $stage -Key 'Items' -Default @())) {
            $flag = if ($it.Mandatory) { '**M**' } else { '&nbsp;&nbsp;' }
            $plat = @($it.AppliesTo) -join ', '
            $bt = [char]0x60
            $null = $sb.AppendLine("- [ ] $flag $bt$(EscMd $it.Id)$bt $(EscMd $it.Requirement) _( $(EscMd $plat) )_")
        }
        $null = $sb.AppendLine()
    }

    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("## The standard in detail")
    $null = $sb.AppendLine()

    foreach ($stage in $stages) {
        $null = $sb.AppendLine("### $(EscMd $stage.Title)")
        $null = $sb.AppendLine()
        if ($stage.Description) { $null = $sb.AppendLine("$(EscMd $stage.Description)"); $null = $sb.AppendLine() }

        foreach ($it in @(Get-NRGObjectField -Item $stage -Key 'Items' -Default @())) {
            $tag = if ($it.Mandatory) { 'Mandatory' } else { 'Recommended' }
            $null = $sb.AppendLine("#### $(EscMd $it.Id) — $(EscMd $it.Requirement)")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("_$tag &middot; applies to $(EscMd (@($it.AppliesTo) -join ', '))_")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("**Why.** $(EscMd $it.Why)")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("**How.** $(EscMd $it.How)")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("**Satisfies.** NIST $(EscMd ((@($it.Nist) | ForEach-Object { "$_ $(Get-NRGNISTControlTitle -ControlId $_)" }) -join '; '))")
            $null = $sb.AppendLine()
            $verified = @($it.VerifiedBy)
            if ($verified.Count -gt 0) {
                $vTxt = (@($verified | ForEach-Object {
                    if ($cdefs.ContainsKey([string]$_)) { "$_ ($($cdefs[[string]$_]))" } else { [string]$_ }
                }) -join '; ')
                $null = $sb.AppendLine("**Verified by the assessment.** $(EscMd $vTxt)")
            } else {
                $null = $sb.AppendLine("**Verified by the assessment.** Not checkable from the tenant — confirm during the build and retain the evidence.")
            }
            $null = $sb.AppendLine()
        }
    }

    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine()
    # Curly quotes rather than \" — a backslash is not a PowerShell escape
    # character, so \" terminated the string and broke the parse.
    $null = $sb.AppendLine("_$(EscMd $company) managed device standard. Items marked &ldquo;not checkable from the tenant&rdquo; are confirmed at build time and evidenced by the build record, not by a scan._")

    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $OutputPath -Content $sb.ToString()
    } else {
        $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8
    }

    # ─────────────────────────────────────────────────────────────────────────
    # HTML — self-contained and printable, with real checkboxes.
    # ─────────────────────────────────────────────────────────────────────────
    $checklist = ''
    foreach ($stage in $stages) {
        $rows = ''
        foreach ($it in @(Get-NRGObjectField -Item $stage -Key 'Items' -Default @())) {
            $mCls = if ($it.Mandatory) { 'm-yes' } else { 'm-no' }
            $mTxt = if ($it.Mandatory) { 'M' } else { '&middot;' }
            $rows += "<tr><td class='cb'><span class='box'></span></td><td class='mf'><span class='m $mCls'>$mTxt</span></td><td class='iid'>$(Esc $it.Id)</td><td class='ireq'>$(Esc $it.Requirement)</td><td class='ipl'>$(Esc (@($it.AppliesTo) -join ' &middot; '))</td></tr>"
        }
        $checklist += "<tr class='sh'><td colspan='5'>$(Esc $stage.Title)</td></tr>$rows"
    }

    $detail = ''
    foreach ($stage in $stages) {
        $items = ''
        foreach ($it in @(Get-NRGObjectField -Item $stage -Key 'Items' -Default @())) {
            $mCls = if ($it.Mandatory) { 'm-yes' } else { 'm-no' }
            $tag  = if ($it.Mandatory) { 'Mandatory' } else { 'Recommended' }
            $nist = (@($it.Nist) | ForEach-Object { "<strong>$(Esc $_)</strong> $(Esc (Get-NRGNISTControlTitle -ControlId $_))" }) -join ' &middot; '
            $verified = @($it.VerifiedBy)
            $vHtml = if ($verified.Count -gt 0) {
                (@($verified | ForEach-Object {
                    $t = if ($cdefs.ContainsKey([string]$_)) { " $($cdefs[[string]$_])" } else { '' }
                    "<span class='vc'>$(Esc $_)</span>$(Esc $t)"
                }) -join '; ')
            } else {
                "<em>Not checkable from the tenant &mdash; confirm during the build and retain the evidence.</em>"
            }
            $items += @"
<div class='item'>
  <div class='item-hd'>
    <span class='iid2'>$(Esc $it.Id)</span>
    <span class='ttl'>$(Esc $it.Requirement)</span>
    <span class='m $mCls'>$tag</span>
  </div>
  <div class='plat'>$(Esc (@($it.AppliesTo) -join ' &middot; '))</div>
  <div class='blk'><div class='lbl'>Why</div>$(Esc $it.Why)</div>
  <div class='blk how'><div class='lbl'>How</div>$(Esc $it.How)</div>
  <div class='meta2'><span class='lbl2'>Satisfies</span> $nist</div>
  <div class='meta2'><span class='lbl2'>Verified by</span> $vHtml</div>
</div>
"@
        }
        $detail += @"
<section class='stage' id='s-$(Esc $stage.Id)'>
  <h2>$(Esc $stage.Title)</h2>
  $(if ($stage.Description) { "<p class='sdesc'>$(Esc $stage.Description)</p>" })
  $items
</section>
"@
    }

    $nav = ''
    foreach ($stage in $stages) { $nav += "<a href='#s-$(Esc $stage.Id)'>$(Esc $stage.Title)</a>" }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(Esc $title)</title>
<style>
*{box-sizing:border-box}
body{margin:0;font:15px/1.65 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#111827;background:#eef2f8}
.wrap{max-width:1000px;margin:0 auto;padding:0 20px 60px}
header{background:linear-gradient(138deg,#0f2544 0%,#061325 100%);color:#fff;padding:40px 0 0}
header .wrap{padding-bottom:0}
.eyebrow{font-size:.66rem;letter-spacing:.18em;text-transform:uppercase;color:#e8621a;font-weight:700;margin-bottom:8px}
h1{margin:0 0 8px;font-size:1.85rem;letter-spacing:-.03em;line-height:1.15}
.sub{color:rgba(255,255,255,.72);font-size:1rem;margin-bottom:12px;max-width:62ch}
.meta{font-size:.83rem;color:rgba(255,255,255,.5);margin-bottom:22px}
.meta strong{color:rgba(255,255,255,.85);font-weight:600}
nav{display:flex;flex-wrap:wrap;gap:2px;border-top:1px solid rgba(255,255,255,.08);padding-top:2px}
nav a{padding:10px 13px;font-size:.66rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:rgba(255,255,255,.42);text-decoration:none;border-bottom:2px solid transparent}
nav a:hover{color:#fff;border-bottom-color:#e8621a}
.card{background:#fff;border-radius:12px;padding:22px 26px;margin:26px 0 22px;box-shadow:0 1px 3px rgba(0,0,0,.05),0 4px 18px rgba(15,37,68,.07)}
h2{font-size:1.25rem;letter-spacing:-.02em;margin:0 0 6px}
.lede{font-size:.95rem;line-height:1.7;margin:0 0 4px}
table{width:100%;border-collapse:collapse;font-size:.86rem;margin-top:12px}
td{padding:8px 8px;border-bottom:1px solid #eef2f8;vertical-align:middle}
tr.sh td{background:#0f2544;color:#fff;font-weight:800;font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;padding:8px 10px;border:none}
.cb{width:26px}
.box{display:inline-block;width:15px;height:15px;border:1.5px solid #94a3b8;border-radius:3px;vertical-align:middle}
.mf{width:28px}
.m{display:inline-block;font-size:.6rem;font-weight:900;border-radius:20px;text-align:center;letter-spacing:.03em}
td .m{width:19px;height:19px;line-height:19px}
.m-yes{background:#fee2e2;color:#991b1b}
.m-no{background:#e5e7eb;color:#6b7280}
.iid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:800;color:#4c1d95;white-space:nowrap;width:64px}
.ireq{font-weight:600}
.ipl{color:#6b7280;font-size:.76rem;white-space:nowrap;text-align:right}
.stage{margin-bottom:26px}
.stage>h2{padding:0 4px}
.sdesc{color:#6b7280;font-size:.88rem;margin:0 4px 14px;line-height:1.6;max-width:78ch}
.item{background:#fff;border-radius:12px;padding:18px 22px;margin-bottom:12px;box-shadow:0 1px 3px rgba(0,0,0,.05),0 4px 14px rgba(15,37,68,.05)}
.item-hd{display:flex;align-items:baseline;gap:11px;flex-wrap:wrap}
.iid2{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:900;color:#4c1d95;font-size:.9rem}
.ttl{font-weight:700;font-size:1rem;flex:1;min-width:220px}
.item-hd .m{padding:3px 10px;font-size:.62rem;font-weight:800}
.plat{font-size:.72rem;color:#6b7280;margin:2px 0 11px;letter-spacing:.02em}
.blk{margin-bottom:9px;line-height:1.65}
.how{background:#f8fafc;border-left:3px solid #3b7dd8;border-radius:0 8px 8px 0;padding:11px 15px}
.lbl{font-size:.6rem;font-weight:800;text-transform:uppercase;letter-spacing:.09em;color:#6b7280;margin-bottom:4px}
.meta2{font-size:.79rem;color:#4b5563;line-height:1.6;margin-top:7px}
.lbl2{font-size:.58rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em;color:#9ca3af;margin-right:7px}
.vc{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;color:#065f46;background:#d1fae5;padding:1px 6px;border-radius:4px;font-size:.74rem}
footer{color:#6b7280;font-size:.78rem;line-height:1.6;padding:0 4px}
@media print{
  body{background:#fff}
  header{background:#0f2544 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  nav{display:none}
  .card,.item{box-shadow:none;border:1px solid #e2e8f0}
  .item,tr{page-break-inside:avoid}
  .card{page-break-after:always}
}
</style></head><body>
<header><div class="wrap">
  <div class="eyebrow">Build standard</div>
  <h1>$(Esc $title)</h1>
  $(if ($sub) { "<div class='sub'>$(Esc $sub)</div>" })
  <div class="meta">Owner <strong>$(Esc $company)</strong> &middot; $(Esc $date) &middot; <strong>$($allItems.Count)</strong> requirements &middot; <strong>$mandatory</strong> mandatory</div>
  <nav>$nav</nav>
</div></header>

<div class="wrap">
  <div class="card">
    <h2>Build checklist</h2>
    <p class="lede">Work top to bottom. <span class="m m-yes" style="padding:2px 8px">M</span> marks a mandatory item &mdash; a device that misses one is not a managed device, it is an unmanaged device with an asset tag.</p>
    <table><tbody>$checklist</tbody></table>
  </div>

  $detail

  <footer>$(Esc $company) managed device standard. Items marked &ldquo;not checkable from the tenant&rdquo; are confirmed at build time and evidenced by the build record, not by a scan.</footer>
</div>
</body></html>
"@

    $htmlPath = [System.IO.Path]::ChangeExtension($OutputPath, '.html')
    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $htmlPath -Content $html
    } else {
        $html | Out-File -LiteralPath $htmlPath -Encoding utf8
    }
}
