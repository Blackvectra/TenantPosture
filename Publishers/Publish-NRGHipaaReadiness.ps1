#Requires -Version 7.0
#
# Publish-NRGHipaaReadiness.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Renders the HIPAA Security Rule readiness view (Get-NRGHipaaReadiness)
#          as Markdown plus a self-contained HTML page: every standard and
#          implementation specification, what this Microsoft 365 assessment
#          evidenced for it, and what needs documents, interviews or a
#          walkthrough instead.
#
# Data keys: none (consumes the posture object). Graph / cmdlets: none.
#
# Rules (pinned by NRG.HipaaReadiness.Tests.ps1):
#   - Page one says this is not a risk analysis (45 CFR 164.308(a)(1)(ii)(A))
#     and not a determination of HIPAA compliance, and that Addressable does
#     not mean optional.
#   - No row and no sentence says "compliant" or states that a requirement is
#     met. The strongest status is 'Mapped technical checks satisfied': the
#     checks mapped to the item passed, which is not proof they cover all of
#     it. Technical results and regulatory fulfillment are kept apart.
#   - Every finding's detail is shown, a passing one's included.
#   - The source snapshot date and catalog version are printed.
#   - A control citing an item it cannot evidence is shown as cited, not
#     counted, never as evidence.
#   - Every value is escaped; the HTML carries a Content-Security-Policy that
#     allows no script and no external resource.

function Publish-NRGHipaaReadiness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary] $Posture,

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

    if (-not $Posture['Available']) {
        Write-Warning 'HIPAA readiness view unavailable (hipaa-security-rule.json missing or empty): not generated.'
        return
    }

    function EscMd { param([object]$v) ([string]$v) -replace '\|', '\|' -replace '[\r\n]+', ' ' }
    function Esc   { param([object]$v) ConvertTo-NRGHtmlSafe $v }

    $st    = Get-NRGHipaaStatusNames
    $items = @($Posture['Items'])
    $sgs   = @($Posture['Safeguards'])
    $sum   = $Posture['Summary']

    $brand   = if ($script:NRGBrand) { $script:NRGBrand } else { @{} }
    $company = if ($brand['CompanyName']) { [string]$brand['CompanyName'] } else { 'NRG Technology Services' }
    $tenant  = [string](Get-NRGObjectField -Item $Metadata -Key 'TenantDomain'   -Default '')
    $date    = [string](Get-NRGObjectField -Item $Metadata -Key 'AssessmentDate' -Default (Get-Date -Format 'yyyy-MM-dd'))

    $title = if ($tenant) { "HIPAA Security Rule Readiness: $tenant" } else { 'HIPAA Security Rule Readiness' }

    $notice = @(
        'This is not a risk analysis (45 CFR 164.308(a)(1)(ii)(A)) and not a determination of HIPAA compliance. It lists every Security Rule standard and implementation specification and shows which ones this Microsoft 365 assessment produced evidence for.'
        "Evidence covers only the part of each item that lives in the Microsoft 365 tenant. $($sum['AttestationRequired']) of $($sum['Total']) items have no evidence from the tenant and need documents, interviews or a walkthrough; $($sum['NoTenantEvidence']) of them are documents, processes or organizational arrangements that tenant configuration cannot show at all."
        'Addressable does not mean optional (45 CFR 164.306(d)(3)). Each Addressable specification must be assessed. If it is reasonable and appropriate it must be implemented; if not, the regulation requires documenting why and implementing an equivalent alternative measure if that is reasonable and appropriate. Recommended practice: record the assessment and decision for every Addressable specification, including any alternative measure, with the organization''s Security Rule documentation (45 CFR 164.316(b)). The regulation expressly requires documenting why when the specification is not implemented.'
        'This catalog is the Security Rule currently in effect. It does not implement the Security Rule changes HHS proposed in its notice of proposed rulemaking; the existing rule remains in effect while that rulemaking continues.'
        "Statuses report technical checks, not regulatory fulfillment. '$($st.Satisfied)' means every check this tool maps to the item passed; a mapping shows the check bears on the item, not that it covers all of it. A standard is reviewed separately from its implementation specifications."
    )

    $sgOrder = @($sgs | ForEach-Object { [string]$_['Name'] })
    $attest = @($items | Where-Object { $_['MappedControls'] -eq 0 })
    $short  = @($items | Where-Object { $_['Status'] -eq $st.Shortfall })
    $tallyText = {
        param($t)
        $parts = @("$($t['Total']) in all")
        foreach ($k in @($t.Keys | Where-Object { $_ -ne 'Total' })) { if ($t[$k] -gt 0) { $parts += "$($t[$k]) $($k.ToLowerInvariant())" } }
        $parts -join ', '
    }
    $sourceLine = "Regulation text: $($Posture['Source']). Catalog version $($Posture['CatalogVersion']), eCFR issue $($Posture['SourceSnapshot']), retrieved $($Posture['SourceRetrieved'])." 

    # ── Markdown ─────────────────────────────────────────────────────────────
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("# $(EscMd $title)")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**Framework:** $(EscMd $Posture['Framework'])  ")
    if ($tenant) { $null = $sb.AppendLine("**Tenant:** $(EscMd $tenant)  ") }
    $null = $sb.AppendLine("**Assessed by:** $(EscMd $company)  ")
    $null = $sb.AppendLine("**Date:** $(EscMd $date)  ")
    $null = $sb.AppendLine("**Catalog:** version $(EscMd $Posture['CatalogVersion']), eCFR issue $(EscMd $Posture['SourceSnapshot'])")
    $null = $sb.AppendLine()
    foreach ($n in $notice) { $null = $sb.AppendLine("> $(EscMd $n)"); $null = $sb.AppendLine('>') }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('## Summary')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('| Items | Standards | Required | Addressable | Mapped to checks | Evidence collected | Attestation required | Checks satisfied | Satisfied, specifications open | Check shortfall | Not assessed |')
    $null = $sb.AppendLine('|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|')
    $null = $sb.AppendLine("| $($sum['Total']) | $($sum['Standards']) | $($sum['Required']) | $($sum['Addressable']) | $($sum['Mapped']) | $($sum['EvidenceCollected']) | $($sum['AttestationRequired']) | $($sum['ChecksSatisfied']) | $($sum['SpecificationsOpen']) | $($sum['Shortfall']) | $($sum['NotAssessed']) |")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('| Safeguard | Items | Mapped to checks | Evidence collected | Attestation required | Checks satisfied | Specifications open | Check shortfall | Not assessed |')
    $null = $sb.AppendLine('|---|---:|---:|---:|---:|---:|---:|---:|---:|')
    foreach ($s in $sgs) {
        $null = $sb.AppendLine("| $(EscMd $s['Name']) | $($s['Total']) | $($s['Mapped']) | $($s['EvidenceCollected']) | $($s['AttestationRequired']) | $($s['ChecksSatisfied']) | $($s['SpecificationsOpen']) | $($s['Shortfall']) | $($s['NotAssessed']) |")
    }
    $null = $sb.AppendLine()

    foreach ($sgName in $sgOrder) {
        $null = $sb.AppendLine("## $(EscMd $sgName) safeguards")
        $null = $sb.AppendLine()
        foreach ($r in @($items | Where-Object { $_['Safeguard'] -eq $sgName })) {
            $req = if ($r['Kind'] -eq 'Standard') { 'Standard' } else { [string]$r['Requirement'] }
            $null = $sb.AppendLine("### $(EscMd $r['Citation']) $(EscMd $r['Name']) ($(EscMd $req))")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("**Status:** $(EscMd $r['Status']) (confidence: $(EscMd $r['Confidence']))")
            $null = $sb.AppendLine()
            if ($r['Text']) { $null = $sb.AppendLine("_$(EscMd $r['Text'])_"); $null = $sb.AppendLine() }
            if ($r['TenantEvidence'] -eq 'None') {
                $null = $sb.AppendLine("Not shown by tenant configuration: $(EscMd $r['TenantEvidenceReason'])")
                $null = $sb.AppendLine()
            }
            if ($r['Specifications']) {
                $null = $sb.AppendLine("Implementation specifications, reviewed separately: $(EscMd (& $tallyText $r['Specifications'])).")
                $null = $sb.AppendLine()
            }
            if (@($r['CitedNotCounted']).Count -gt 0) {
                $null = $sb.AppendLine("Cited by $(EscMd (@($r['CitedNotCounted']) -join ', ')), not counted as evidence for this item.")
                $null = $sb.AppendLine()
            }
            if (@($r['Evidence']).Count -gt 0) {
                $null = $sb.AppendLine('| Control | Title | Result | Detail |')
                $null = $sb.AppendLine('|---|---|---|---|')
                foreach ($e in @($r['Evidence'])) {
                    $inst = [string](Get-NRGObjectField -Item $e -Key 'Instance' -Default '')
                    $cidText = if ($inst) { "$($e['ControlId']) ($inst)" } else { [string]$e['ControlId'] }
                    $null = $sb.AppendLine("| $(EscMd $cidText) | $(EscMd $e['Title']) | $(EscMd $e['State']) | $(EscMd $e['Detail']) |")
                }
                $null = $sb.AppendLine()
            }
        }
    }

    $null = $sb.AppendLine('## Needs documents, interviews or a walkthrough')
    $null = $sb.AppendLine()
    foreach ($r in $attest) { $null = $sb.AppendLine("- $(EscMd $r['Citation']) $(EscMd $r['Name'])") }
    $null = $sb.AppendLine()
    if (@($sum['OutsideSecurityRule']).Count -gt 0) {
        $null = $sb.AppendLine('## Citations outside the Security Rule')
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("These controls also cite Privacy Rule sections, which this view does not cover: $(EscMd (@($sum['OutsideSecurityRule']) -join '; ')).")
        $null = $sb.AppendLine()
    }
    $null = $sb.AppendLine('---')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("_Prepared by $(EscMd $company). $(EscMd $sourceLine) $(EscMd $Posture['Amendments'])_")

    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $OutputPath -Content $sb.ToString()
    } else {
        $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8
    }

    # ── HTML ─────────────────────────────────────────────────────────────────
    $cls = { param($s) if ($s -eq $st.Satisfied) { 'ok' } elseif ($s -eq $st.Shortfall) { 'gap' } elseif ($s -eq $st.NotAssessed -or $s -eq $st.SpecsOpen) { 'open' } else { 'att' } }
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
.wrap{max-width:1080px;margin:0 auto;padding:0 20px 60px}
header{background:#0f2544;color:#fff;padding:32px 0 20px}
h1{margin:0 0 6px;font-size:1.7rem}
.meta{font-size:.85rem;color:rgba(255,255,255,.7)}
.card{background:#fff;border-radius:12px;padding:20px 24px;margin:22px 0;box-shadow:0 1px 3px rgba(0,0,0,.06)}
.warn{background:#fffbeb;border-left:4px solid #f59e0b;padding:12px 16px;margin:10px 0;font-size:.92rem}
table{width:100%;border-collapse:collapse;font-size:.86rem;margin-top:10px}
th{text-align:left;font-size:.66rem;text-transform:uppercase;letter-spacing:.07em;color:#6b7280;padding:6px 8px;border-bottom:2px solid #e2e8f0}
td{padding:7px 8px;border-bottom:1px solid #eef2f8;vertical-align:top}
td.n{text-align:right;font-variant-numeric:tabular-nums}
.cit{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;white-space:nowrap;color:#4c1d95}
.std td{background:#f8fafc;font-weight:600}
.ok{color:#065f46;font-weight:700}.gap{color:#991b1b;font-weight:700}.open{color:#6b7280;font-weight:700}.att{color:#92400e;font-weight:700}
.small{font-size:.8rem;color:#4b5563}
@media print{body{background:#fff}.card{box-shadow:none;border:1px solid #e5e7eb}}
</style></head><body>
<header><div class="wrap"><h1>$(Esc $title)</h1>
<div class="meta">$(Esc $Posture['Framework']) &middot; Assessed by $(Esc $company) &middot; $(Esc $date) &middot; catalog version $(Esc $Posture['CatalogVersion']), eCFR issue $(Esc $Posture['SourceSnapshot'])</div></div></header>
<div class="wrap">
<div class="card">
"@)
    foreach ($n in $notice) { $null = $h.Append("<div class=`"warn`">$(Esc $n)</div>") }
    $null = $h.Append(@"
<table><tr><th>Items</th><th>Standards</th><th>Required</th><th>Addressable</th><th>Mapped to checks</th><th>Evidence collected</th><th>Attestation required</th><th>Checks satisfied</th><th>Satisfied, specifications open</th><th>Check shortfall</th><th>Not assessed</th></tr>
<tr><td class="n">$($sum['Total'])</td><td class="n">$($sum['Standards'])</td><td class="n">$($sum['Required'])</td><td class="n">$($sum['Addressable'])</td><td class="n">$($sum['Mapped'])</td><td class="n">$($sum['EvidenceCollected'])</td><td class="n">$($sum['AttestationRequired'])</td><td class="n">$($sum['ChecksSatisfied'])</td><td class="n">$($sum['SpecificationsOpen'])</td><td class="n">$($sum['Shortfall'])</td><td class="n">$($sum['NotAssessed'])</td></tr></table>
<table><tr><th>Safeguard</th><th>Items</th><th>Mapped to checks</th><th>Evidence collected</th><th>Attestation required</th><th>Checks satisfied</th><th>Specifications open</th><th>Check shortfall</th><th>Not assessed</th></tr>
"@)
    foreach ($s in $sgs) {
        $null = $h.Append("<tr><td>$(Esc $s['Name'])</td><td class=`"n`">$($s['Total'])</td><td class=`"n`">$($s['Mapped'])</td><td class=`"n`">$($s['EvidenceCollected'])</td><td class=`"n`">$($s['AttestationRequired'])</td><td class=`"n`">$($s['ChecksSatisfied'])</td><td class=`"n`">$($s['SpecificationsOpen'])</td><td class=`"n`">$($s['Shortfall'])</td><td class=`"n`">$($s['NotAssessed'])</td></tr>")
    }
    $null = $h.Append('</table></div>')

    foreach ($sgName in $sgOrder) {
        $null = $h.Append("<div class=`"card`"><h2>$(Esc $sgName) safeguards</h2><table><tr><th>Citation</th><th>Item</th><th>Type</th><th>Status</th><th>Evidence</th></tr>")
        foreach ($r in @($items | Where-Object { $_['Safeguard'] -eq $sgName })) {
            $req = if ($r['Kind'] -eq 'Standard') { 'Standard' } else { [string]$r['Requirement'] }
            $ev = [System.Text.StringBuilder]::new()
            foreach ($e in @($r['Evidence'])) {
                $inst = [string](Get-NRGObjectField -Item $e -Key 'Instance' -Default '')
                $cidText = if ($inst) { "$($e['ControlId']) ($inst)" } else { [string]$e['ControlId'] }
                $null = $ev.Append("<div><span class=`"cit`">$(Esc $cidText)</span> $(Esc $e['Title']): <b>$(Esc $e['State'])</b>")
                if ($e['Detail']) { $null = $ev.Append(" <span class=`"small`">$(Esc $e['Detail'])</span>") }
                $null = $ev.Append('</div>')
            }
            if ($r['TenantEvidence'] -eq 'None') { $null = $ev.Append("<div class=`"small`">Not shown by tenant configuration: $(Esc $r['TenantEvidenceReason'])</div>") }
            if ($r['Specifications']) { $null = $ev.Append("<div class=`"small`">Implementation specifications, reviewed separately: $(Esc (& $tallyText $r['Specifications'])).</div>") }
            if (@($r['CitedNotCounted']).Count -gt 0) { $null = $ev.Append("<div class=`"small`">Cited by $(Esc (@($r['CitedNotCounted']) -join ', ')), not counted as evidence for this item.</div>") }
            $rowCls = if ($r['Kind'] -eq 'Standard') { ' class="std"' } else { '' }
            $null = $h.Append("<tr$rowCls><td class=`"cit`">$(Esc $r['Citation'])</td><td>$(Esc $r['Name'])<div class=`"small`">$(Esc $r['Text'])</div></td><td>$(Esc $req)</td><td class=`"$(& $cls $r['Status'])`">$(Esc $r['Status'])<div class=`"small`">$(Esc $r['Confidence'])</div></td><td>$($ev.ToString())</td></tr>")
        }
        $null = $h.Append('</table></div>')
    }

    $null = $h.Append('<div class="card"><h2>Needs documents, interviews or a walkthrough</h2><ul>')
    foreach ($r in $attest) { $null = $h.Append("<li><span class=`"cit`">$(Esc $r['Citation'])</span> $(Esc $r['Name'])</li>") }
    $null = $h.Append('</ul>')
    if (@($sum['OutsideSecurityRule']).Count -gt 0) {
        $null = $h.Append("<p class=`"small`">These controls also cite Privacy Rule sections, which this view does not cover: $(Esc (@($sum['OutsideSecurityRule']) -join '; ')).</p>")
    }
    $null = $h.Append("<p class=`"small`">Prepared by $(Esc $company). $(Esc $sourceLine) $(Esc $Posture['Amendments'])</p></div>")
    $null = $h.Append('</div></body></html>')

    $htmlPath = [System.IO.Path]::ChangeExtension($OutputPath, '.html')
    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $htmlPath -Content $h.ToString()
    } else {
        $h.ToString() | Out-File -LiteralPath $htmlPath -Encoding utf8
    }
    Write-Verbose "HIPAA readiness written: $OutputPath, $htmlPath (shortfalls: $($short.Count))"
}
