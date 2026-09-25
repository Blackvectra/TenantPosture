#Requires -Version 7.0
#
# Publish-NRGNISTMatrix.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Standalone NIST SP 800-53 Rev 5 compliance matrix — a single-framework
#          deliverable for clients who are assessed against 800-53 and do not
#          want to read their posture out of a multi-framework report.
#
#          Deliberately additive. Publish-NRGComplianceMatrix keeps every
#          framework it has today (CIS, SCuBA, CMMC, ISO 27001, SOC 2, HIPAA,
#          PCI DSS, MITRE), and this publisher changes none of it. The same
#          findings, the same scores, one extra document organized the way an
#          800-53 reader works: by control, then by family.
#
#          Emits Markdown always, and XLSX when openpyxl is available. Markdown
#          is not a fallback of convenience — it is the form that pastes into a
#          ConnectWise ticket and diffs between runs. The XLSX is the artifact
#          an assessor works down while collecting evidence.
#
# Inputs:  -Metadata     tenant/report metadata (TenantDomain, AssessmentDate...).
#          -Findings     assessment findings.
#          -OutputPath   path to the .md to write. The XLSX is written alongside
#                        it with the same base name and an .xlsx extension.
#
# Sheets / sections:
#   1. Summary            overall 800-53 posture, families assessed, what is out of scope
#   2. Control Matrix     one row per (800-53 control x tool control) — the matrix proper
#   3. By Control         one row per 800-53 control, rolled up
#   4. By Family          one row per family, rolled up
#   5. Physical & Device  the 31 physical/media/device items, unscored, with options
#   6. Not Assessed       cited 800-53 controls where nothing was assessable, stated plainly
#
# Consumes: findings, Config/controls.json, Config/nist-800-53-catalog.json,
#           Config/nist-physical.json. No Graph, no EXO. Read-only.
#

function Publish-NRGNISTMatrix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Metadata,
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
            return $true
        })]
        [string] $OutputPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    function EscMd { param([object]$v) ([string]$v) -replace '\|', '\|' -replace '[\r\n]+', ' ' }

    $tenant = [string](Get-NRGObjectField -Item $Metadata -Key 'TenantDomain'   -Default 'Unknown tenant')
    $date   = [string](Get-NRGObjectField -Item $Metadata -Key 'AssessmentDate' -Default (Get-Date -Format 'MMMM dd, yyyy'))
    $ver    = [string](Get-NRGObjectField -Item $Metadata -Key 'ToolVersion'    -Default '')

    # Control definitions, for severity / remediation / business risk on each row.
    $cdefs = @{}
    try { foreach ($c in (Get-NRGControlDefinitions)) { $cdefs[$c.ControlId] = $c } } catch { }

    $cov     = Get-NRGNISTFamilyCoverage -Findings $Findings -ErrorHandling 'Gap'
    $overall = Get-NRGCoverageScore -Findings $Findings -FrameworkId 'NIST' -ErrorHandling 'Gap'

    # ── Build the matrix rows: one per (800-53 control x tool control) ────────
    # This is the shape an 800-53 reader expects. A tool control citing two NIST
    # controls appears under both, because it is evidence for both.
    $matrixRows = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $Findings) {
        if ($null -eq $f) { continue }
        $toolId = [string](Get-NRGObjectField -Item $f -Key 'ControlId' -Default '')
        $nistIds = @(Get-NRGNISTControlIdsFromFinding -Finding $f)
        if ($nistIds.Count -eq 0) { continue }
        $ctrl = if ($toolId -and $cdefs.ContainsKey($toolId)) { $cdefs[$toolId] } else { $null }
        foreach ($nid in $nistIds) {
            $matrixRows.Add([ordered]@{
                NistControl   = $nid
                NistTitle     = Get-NRGNISTControlTitle -ControlId $nid
                Family        = ($nid -split '-')[0]
                FamilyTitle   = Get-NRGNISTFamilyTitle -Family (($nid -split '-')[0])
                ToolControl   = $toolId
                Title         = [string](Get-NRGObjectField -Item $f -Key 'Title'  -Default '')
                State         = [string](Get-NRGObjectField -Item $f -Key 'State'  -Default '')
                Severity      = [string](Get-NRGObjectField -Item $f -Key 'Severity' -Default '')
                CurrentValue  = [string](Get-NRGObjectField -Item $f -Key 'CurrentValue'  -Default '')
                RequiredValue = [string](Get-NRGObjectField -Item $f -Key 'RequiredValue' -Default '')
                Detail        = [string](Get-NRGObjectField -Item $f -Key 'Detail' -Default '')
                Remediation   = if ($ctrl) { [string](Get-NRGObjectField -Item $ctrl -Key 'Remediation' -Default '') }
                                else { [string](Get-NRGObjectField -Item $f -Key 'Remediation' -Default '') }
                BusinessRisk  = if ($ctrl) { [string](Get-NRGObjectField -Item $ctrl -Key 'BusinessRisk' -Default '') } else { '' }
                LicenseReq    = if ($ctrl) { [string](Get-NRGObjectField -Item $ctrl -Key 'LicenseRequirement' -Default '') } else { '' }
            })
        }
    }

    # Sort: gaps first inside each control, controls in 800-53 order.
    $stateOrder = @{ 'Gap' = 0; 'Partial' = 1; 'Error' = 2; 'Satisfied' = 3; 'NotApplicable' = 4 }
    $sortedRows = @($matrixRows | Sort-Object `
        @{ Expression = { ($_.NistControl -split '-')[0] } },
        @{ Expression = { [int](($_.NistControl -replace '^[A-Z]{2}-(\d+).*$', '$1')) } },
        @{ Expression = { if ($_.NistControl -match '\((\d+)\)$') { [int]$Matches[1] } else { 0 } } },
        @{ Expression = { if ($stateOrder.ContainsKey($_.State)) { $stateOrder[$_.State] } else { 9 } } },
        @{ Expression = { $_.ToolControl } })

    # ── Physical / device posture ────────────────────────────────────────────
    $phys = $null
    if (Get-Command Get-NRGNISTPhysicalPosture -ErrorAction SilentlyContinue) {
        try { $phys = Get-NRGNISTPhysicalPosture -Findings $Findings } catch { $phys = $null }
    }

    # ── Not assessed: cited controls where nothing was assessable ────────────
    # Stated explicitly rather than omitted. A matrix that silently drops the
    # controls it could not evaluate reads as full coverage of a smaller scope,
    # which is the same false-clean-bill-of-health failure in document form.
    $notAssessed = @($cov.Controls | Where-Object { $_.Scored -le 0 })

    # ─────────────────────────────────────────────────────────────────────────
    # Markdown
    # ─────────────────────────────────────────────────────────────────────────
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("# NIST SP 800-53 Rev 5 — Compliance Matrix")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**Tenant:** $(EscMd $tenant)  ")
    $null = $sb.AppendLine("**Assessment date:** $(EscMd $date)  ")
    if ($ver) { $null = $sb.AppendLine("**Tool version:** $(EscMd $ver)  ") }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("This matrix covers NIST SP 800-53 Revision 5 only. It is generated from the same assessment run as the full report, which additionally cites CIS M365, CISA SCuBA, CMMC 2.0, ISO/IEC 27001, SOC 2, HIPAA, PCI DSS and MITRE ATT&CK.")
    $null = $sb.AppendLine()

    # Summary
    $null = $sb.AppendLine("## Summary")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("| Measure | Value |")
    $null = $sb.AppendLine("|---------|-------|")
    $null = $sb.AppendLine("| 800-53 posture score | **$($overall.Score)%** |")
    $null = $sb.AppendLine("| Controls met | $($overall.Satisfied) |")
    $null = $sb.AppendLine("| Partially met | $($overall.Partial) |")
    $null = $sb.AppendLine("| Gaps | $($overall.Gap) |")
    # Same rule as the XLSX summary: an omitted Error row leaves a reader
    # short of the finding count with no way to tell what the missing rows were.
    $null = $sb.AppendLine("| Errors (collection or evaluation failed) | $($overall.Error) |")
    $null = $sb.AppendLine("| Not assessable | $($overall.NA) |")
    $null = $sb.AppendLine("| Families exercised | $($cov.FamilyCount) of 20 |")
    $null = $sb.AppendLine("| 800-53 controls exercised | $($cov.NistControlCount) |")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("### Scope of this assessment")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("This is a Microsoft 365 tenant assessment. It evidences the 800-53 controls that a cloud tenant configuration can evidence, and it cannot evidence the rest. Specifically:")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("- The score above covers only the $($cov.NistControlCount) controls this tool exercises. It is **not** an 800-53 baseline completion percentage, and a Low, Moderate or High baseline contains many controls no tenant scan can reach.")
    $null = $sb.AppendLine("- The physical, media, maintenance and personnel families are addressed in their own section below, **unscored**, with the evidence an assessor must collect directly.")
    $null = $sb.AppendLine("- A tool control mapped to more than one 800-53 control appears under each. Rows therefore do not sum to the number of findings.")
    # Single-quoted: a backtick inside a DOUBLE-quoted PowerShell string is the
    # escape character, so `Not assessable` silently rendered as "Not assessable"
    # with the code formatting stripped.
    $null = $sb.AppendLine('- `Not assessable` rows are excluded from the score. They are controls this tool could not evaluate — a missing license, an unconnected service, a failed query — not controls the tenant passed.')
    $null = $sb.AppendLine()

    # By family
    $null = $sb.AppendLine("## Coverage by control family")
    $null = $sb.AppendLine()
    # The Error column is not decoration: without it Met + Partial + Gap + N/A
    # does not reach Assessed, and a reader who adds the row up and comes up
    # short has every reason to stop trusting the rest of the document.
    $null = $sb.AppendLine("| Family | Name | Assessed | Met | Partial | Gap | Error | N/A | Coverage |")
    $null = $sb.AppendLine("|--------|------|---------:|----:|--------:|----:|------:|----:|---------:|")
    foreach ($fam in $cov.Families) {
        $covTxt = if ($fam.Scored -gt 0) { "$([int]$fam.Score)%" } else { 'Not assessed' }
        $null = $sb.AppendLine("| $(EscMd $fam.Family) | $(EscMd $fam.Name) | $($fam.Assessed) | $($fam.Satisfied) | $($fam.Partial) | $($fam.Gap) | $($fam.Error) | $($fam.NA) | $covTxt |")
    }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("_Met + Partial + Gap + Error + N/A equals Assessed for each row. **Error** means the evaluator threw rather than reaching a verdict; unlike N/A it is counted as a failure in Coverage until re-run, and it is a defect to investigate, not a finding about the tenant._")
    $null = $sb.AppendLine()

    # By control
    $null = $sb.AppendLine("## Coverage by 800-53 control")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("| Control | Title | Met | Partial | Gap | Error | N/A | Coverage | Evidenced by |")
    $null = $sb.AppendLine("|---------|-------|----:|--------:|----:|------:|----:|---------:|--------------|")
    foreach ($c in $cov.Controls) {
        $covTxt = if ($c.Scored -gt 0) { "$([int]$c.Score)%" } else { 'Not assessed' }
        $title  = Get-NRGNISTControlTitle -ControlId $c.NistControl
        $null = $sb.AppendLine("| $(EscMd $c.NistControl) | $(EscMd $title) | $($c.Satisfied) | $($c.Partial) | $($c.Gap) | $($c.Error) | $($c.NA) | $covTxt | $(EscMd (@($c.ControlIds) -join ', ')) |")
    }
    $null = $sb.AppendLine()

    # The matrix proper
    $null = $sb.AppendLine("## Control matrix")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("One row per 800-53 control and the tenant control evidencing it. Gaps are listed first within each control.")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("| 800-53 | Title | Tenant control | Finding | Status | Severity | Current | Required |")
    $null = $sb.AppendLine("|--------|-------|----------------|---------|--------|----------|---------|----------|")
    foreach ($r in $sortedRows) {
        $null = $sb.AppendLine("| $(EscMd $r.NistControl) | $(EscMd $r.NistTitle) | $(EscMd $r.ToolControl) | $(EscMd $r.Title) | $(EscMd $r.State) | $(EscMd $r.Severity) | $(EscMd $r.CurrentValue) | $(EscMd $r.RequiredValue) |")
    }
    $null = $sb.AppendLine()

    # Not assessed
    if ($notAssessed.Count -gt 0) {
        $null = $sb.AppendLine("## Cited but not assessable this run")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine('These 800-53 controls are mapped by this tool, but every finding behind them came back `NotApplicable` — a missing license, an unconnected service, or a query that did not complete. They are **not** passes and **not** gaps. Re-running with the relevant service connected, or with the required license, is what turns them into a verdict.')
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("| Control | Title | Tool controls |")
        $null = $sb.AppendLine("|---------|-------|---------------|")
        foreach ($c in $notAssessed) {
            $null = $sb.AppendLine("| $(EscMd $c.NistControl) | $(EscMd (Get-NRGNISTControlTitle -ControlId $c.NistControl)) | $(EscMd (@($c.ControlIds) -join ', ')) |")
        }
        $null = $sb.AppendLine()
    }

    # Physical
    if ($phys -and $phys.Available -and @($phys.Groups).Count -gt 0) {
        $null = $sb.AppendLine("## Physical, media, maintenance and device controls")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("**Nothing in this section is scored.** A Microsoft 365 assessment can evidence endpoint posture and cannot see a locked server room, a certificate of destruction, or a returned badge. Rows marked _Attestation required_ were never assessed by this tool and are not claimed as compliant. $($phys.TenantItems) items are evidenced from the tenant, $($phys.HybridItems) partly, and $($phys.AttestedItems) not at all.")
        $null = $sb.AppendLine()
        foreach ($grp in $phys.Groups) {
            $null = $sb.AppendLine("### $(EscMd $grp.Title)")
            $null = $sb.AppendLine()
            foreach ($it in $grp.Items) {
                $null = $sb.AppendLine("**$(EscMd $it.NistControl) $(EscMd $it.NistTitle)** — _$(EscMd $it.Status)_ ($(EscMd $it.Scope))")
                $null = $sb.AppendLine()
                if ($it.DeviceAspect) { $null = $sb.AppendLine("$(EscMd $it.DeviceAspect)"); $null = $sb.AppendLine() }
                if (@($it.Evidence).Count -gt 0) {
                    $ev = (@($it.Evidence) | ForEach-Object { "$($_.ControlId) ($($_.State))" }) -join ', '
                    $null = $sb.AppendLine("- Evidence from this assessment: $(EscMd $ev)")
                }
                if ($it.OffTenantEvidence) { $null = $sb.AppendLine("- Evidence the assessor must collect: $(EscMd $it.OffTenantEvidence)") }
                foreach ($opt in @($it.Options)) { $null = $sb.AppendLine("- Option: $(EscMd $opt)") }
                $null = $sb.AppendLine()
            }
        }
    }

    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("_Generated by NRG-Assessment. Read-only assessment — no tenant configuration was modified._")

    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $OutputPath -Content $sb.ToString()
    } else {
        $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8
        if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileAcl -Path $OutputPath -ErrorAction SilentlyContinue
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # HTML — the NIST-only report. Self-contained, no external assets, print
    # styling. This is the artifact that goes to an 800-53 client instead of the
    # multi-framework report, so it deliberately mentions no other framework
    # anywhere on the page.
    # ─────────────────────────────────────────────────────────────────────────
    function Esc { param([object]$v) ConvertTo-NRGHtmlSafe $v }
    function ScoreCol { param([int]$n)
        if ($n -ge 85) { '#059669' } elseif ($n -ge 65) { '#ca8a04' } elseif ($n -ge 40) { '#ea580c' } else { '#dc2626' }
    }

    $famRows = ''
    foreach ($fam in $cov.Families) {
        $unscored = ($fam.Scored -le 0)
        $col = if ($unscored) { '#94a3b8' } else { ScoreCol ([int]$fam.Score) }
        $bar = if ($unscored) { 0 } else { [int]$fam.Score }
        $txt = if ($unscored) { 'Not assessed' } else { "$([int]$fam.Score)%" }
        $famRows += "<tr><td class='fid'>$(Esc $fam.Family)</td><td class='fnm'>$(Esc $fam.Name)<div class='fct'>$(Esc (@($fam.NistControls) -join ', '))</div></td>" +
                    "<td class='n'>$($fam.Assessed)</td><td class='n ok'>$($fam.Satisfied)</td><td class='n pt'>$($fam.Partial)</td>" +
                    "<td class='n gp'>$($fam.Gap)</td><td class='n er'>$($fam.Error)</td><td class='n na'>$($fam.NA)</td>" +
                    "<td class='sc'><div class='bar'><div class='fill' style='width:$bar%;background:$col'></div></div><span style='color:$col'>$txt</span></td></tr>"
    }

    $stateCls = @{ 'Satisfied'='s-ok'; 'Partial'='s-pt'; 'Gap'='s-gp'; 'NotApplicable'='s-na'; 'Error'='s-er' }
    $matrixRowsHtml = ''
    foreach ($r in $sortedRows) {
        $cls = if ($stateCls.ContainsKey([string]$r.State)) { $stateCls[[string]$r.State] } else { 's-na' }
        $matrixRowsHtml += "<tr><td class='fid'>$(Esc $r.NistControl)</td><td class='mt'>$(Esc $r.NistTitle)</td>" +
                           "<td class='tc'>$(Esc $r.ToolControl)</td><td>$(Esc $r.Title)</td>" +
                           "<td><span class='st $cls'>$(Esc $r.State)</span></td><td class='sv'>$(Esc $r.Severity)</td>" +
                           "<td class='cv'>$(Esc $r.CurrentValue)</td><td class='cv'>$(Esc $r.RequiredValue)</td></tr>"
    }

    $naRowsHtml = ''
    foreach ($c in $notAssessed) {
        $naRowsHtml += "<tr><td class='fid'>$(Esc $c.NistControl)</td><td>$(Esc (Get-NRGNISTControlTitle -ControlId $c.NistControl))</td><td class='tc'>$(Esc (@($c.ControlIds) -join ', '))</td></tr>"
    }

    $physHtmlSec = ''
    if ($phys -and $phys.Available -and @($phys.Groups).Count -gt 0) {
        $scopeCls = @{ 'Tenant'='p-t'; 'Hybrid'='p-h'; 'Attested'='p-a' }
        $physRowsHtml = ''
        foreach ($grp in $phys.Groups) {
            $physRowsHtml += "<tr class='gh'><td colspan='4'>$(Esc $grp.Title)</td></tr>"
            foreach ($it in $grp.Items) {
                $pc = if ($scopeCls.ContainsKey([string]$it.Scope)) { $scopeCls[[string]$it.Scope] } else { 'p-a' }
                $physRowsHtml += "<tr><td class='fid'>$(Esc $it.NistControl)</td><td>$(Esc $it.NistTitle)</td>" +
                                 "<td><span class='st $pc'>$(Esc $it.Scope)</span></td><td class='cv'>$(Esc $it.Status)</td></tr>"
            }
        }
        $physHtmlSec = @"
<div class="card">
  <div class="hd"><div class="lbl">Physical, Media and Device Controls</div>
  <div class="sub">$($phys.TenantItems) evidenced from the tenant &middot; $($phys.HybridItems) partly &middot; $($phys.AttestedItems) not visible from Microsoft 365</div></div>
  <div class="note"><strong>Nothing in this section is scored.</strong> A Microsoft 365 assessment cannot see a locked server room, a certificate of destruction, or a returned badge. Rows marked <em>Attestation required</em> were never assessed and are not claimed as compliant.</div>
  <div class="wrap"><table><thead><tr><th>800-53</th><th>Control</th><th>Scope</th><th>Status</th></tr></thead><tbody>$physRowsHtml</tbody></table></div>
</div>
"@
    }

    # The hero score stays white deliberately: the header is a dark purple
    # gradient, and the red end of the score palette reads badly on it.
    # Color carries the verdict in the family table below instead.
    $nistHtmlDoc = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NIST SP 800-53 Rev 5 — $(Esc $tenant)</title>
<style>
*{box-sizing:border-box}
body{margin:0;font:14px/1.6 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#111827;background:#eef2f8}
.wrapper{max-width:1200px;margin:0 auto;padding:0 20px 60px}
header{background:linear-gradient(138deg,#4c1d95 0%,#1e1035 100%);color:#fff;padding:38px 0 30px}
header .wrapper{padding-bottom:0}
.eyebrow{font-size:.64rem;letter-spacing:.2em;text-transform:uppercase;color:#c4b5fd;font-weight:700;margin-bottom:8px}
h1{margin:0 0 8px;font-size:1.9rem;letter-spacing:-.03em}
.meta{font-size:.82rem;color:rgba(255,255,255,.55)}
.meta strong{color:rgba(255,255,255,.9);font-weight:600}
.hero{display:flex;align-items:center;gap:26px;margin-top:22px;flex-wrap:wrap}
.big{font-size:3.4rem;font-weight:900;line-height:1;letter-spacing:-.04em}
.big span{font-size:1.1rem;font-weight:600;color:rgba(255,255,255,.5)}
.herotxt{font-size:.85rem;color:rgba(255,255,255,.72);max-width:52ch;line-height:1.6}
.card{background:#fff;border-radius:12px;margin:22px 0;box-shadow:0 1px 3px rgba(0,0,0,.05),0 4px 18px rgba(15,37,68,.07);overflow:hidden}
.hd{padding:16px 22px;border-bottom:1px solid #e2e8f0}
.lbl{font-weight:800;font-size:1.02rem;letter-spacing:-.01em}
.sub{font-size:.78rem;color:#6b7280;margin-top:3px}
.note{padding:12px 22px;font-size:.78rem;color:#4b5563;line-height:1.6;background:#f8fafc;border-bottom:1px solid #e2e8f0}
.wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:.8rem}
th{text-align:left;padding:9px 12px;font-size:.62rem;text-transform:uppercase;letter-spacing:.07em;color:#6b7280;background:#eef2f8;border-bottom:1px solid #e2e8f0;white-space:nowrap}
td{padding:8px 12px;border-bottom:1px solid #eef2f8;vertical-align:top}
tr:last-child td{border-bottom:none}
tr.gh td{background:#4c1d95;color:#fff;font-weight:800;font-size:.66rem;text-transform:uppercase;letter-spacing:.08em}
.fid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:800;color:#4c1d95;white-space:nowrap}
.fnm{font-weight:600;min-width:200px}
.fct{font-size:.66rem;color:#6b7280;font-weight:500;margin-top:3px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;line-height:1.5}
.mt{min-width:180px}
.tc{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;white-space:nowrap;color:#334155}
.cv{color:#6b7280;font-size:.75rem}
.sv{white-space:nowrap;font-size:.75rem}
.n{text-align:right;font-variant-numeric:tabular-nums;font-weight:700;white-space:nowrap}
th.n{text-align:right}
.ok{color:#059669}.pt{color:#ca8a04}.gp{color:#dc2626}.er{color:#b91c1c}.na{color:#94a3b8}
.sc{white-space:nowrap;font-weight:800;min-width:132px}
.bar{display:inline-block;width:72px;height:7px;border-radius:4px;background:#e2e8f0;overflow:hidden;vertical-align:middle;margin-right:8px}
.fill{height:100%;border-radius:4px}
.st{display:inline-block;font-size:.63rem;font-weight:800;padding:3px 9px;border-radius:20px;white-space:nowrap}
.s-ok{background:#d1fae5;color:#065f46}.s-pt{background:#fef3c7;color:#92400e}
.s-gp{background:#fee2e2;color:#991b1b}.s-na{background:#e5e7eb;color:#4b5563}.s-er{background:#fee2e2;color:#991b1b}
.p-t{background:#d1fae5;color:#065f46}.p-h{background:#fef3c7;color:#92400e}.p-a{background:#ede9fe;color:#5b21b6}
.scope{padding:16px 22px;font-size:.8rem;line-height:1.7;color:#374151}
.scope li{margin-bottom:6px}
footer{color:#6b7280;font-size:.76rem;padding:0 4px;line-height:1.6}
@media print{body{background:#fff}header{background:#4c1d95 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}.card{box-shadow:none;border:1px solid #e2e8f0;page-break-inside:auto}tr{page-break-inside:avoid}}
</style></head><body>
<header><div class="wrapper">
  <div class="eyebrow">NIST SP 800-53 Revision 5</div>
  <h1>Compliance Matrix</h1>
  <div class="meta"><strong>$(Esc $tenant)</strong> &middot; $(Esc $date)$(if ($ver) { " &middot; v$(Esc $ver)" })</div>
  <div class="hero">
    <div class="big">$($overall.Score)<span>%</span></div>
    <div class="herotxt">Coverage of the <strong>$($cov.NistControlCount)</strong> 800-53 controls this assessment exercises, across <strong>$($cov.FamilyCount)</strong> of 20 families. This is <strong>not</strong> an 800-53 baseline completion percentage &mdash; a Low, Moderate or High baseline contains many controls no tenant scan can reach.</div>
  </div>
</div></header>

<div class="wrapper">
  <div class="card">
    <div class="hd"><div class="lbl">Scope of this assessment</div></div>
    <div class="scope"><ul>
      <li>Microsoft 365 tenant configuration$(if ($phys) { ' and managed endpoint state' }). The score covers only what this tool exercises.</li>
      <li>Physical, media, maintenance and personnel controls appear below, <strong>unscored</strong>, with the evidence an assessor must collect directly.</li>
      <li>A tool control mapped to more than one 800-53 control appears under each, so rows do not sum to the finding count.</li>
      <li><strong>Not assessable</strong> rows are excluded from the score. They are controls this tool could not evaluate &mdash; missing license, unconnected service, failed query &mdash; <strong>not</strong> controls the tenant passed.</li>
    </ul></div>
  </div>

  <div class="card">
    <div class="hd"><div class="lbl">Coverage by control family</div>
    <div class="sub">Met + Partial + Gap + Error + N/A equals Assessed on every row</div></div>
    <div class="wrap"><table><thead><tr><th>Family</th><th>Name / controls exercised</th><th class="n">Assessed</th><th class="n">Met</th><th class="n">Partial</th><th class="n">Gap</th><th class="n">Error</th><th class="n">N/A</th><th>Coverage</th></tr></thead><tbody>$famRows</tbody></table></div>
  </div>

  <div class="card">
    <div class="hd"><div class="lbl">Control matrix</div>
    <div class="sub">One row per 800-53 control and the tenant control evidencing it &mdash; gaps first within each control</div></div>
    <div class="wrap"><table><thead><tr><th>800-53</th><th>Title</th><th>Tenant control</th><th>Finding</th><th>Status</th><th>Severity</th><th>Current</th><th>Required</th></tr></thead><tbody>$matrixRowsHtml</tbody></table></div>
  </div>

  $(if ($naRowsHtml) { @"
<div class="card">
  <div class="hd"><div class="lbl">Cited but not assessable this run</div></div>
  <div class="note">Every finding behind these controls returned <strong>NotApplicable</strong> &mdash; a missing license, an unconnected service, or a query that did not complete. They are <strong>not</strong> passes and <strong>not</strong> gaps. Re-running with the relevant service connected turns them into a verdict.</div>
  <div class="wrap"><table><thead><tr><th>800-53</th><th>Title</th><th>Tenant controls</th></tr></thead><tbody>$naRowsHtml</tbody></table></div>
</div>
"@ })

  $physHtmlSec

  <footer>NIST SP 800-53 Revision 5 only. Read-only assessment &mdash; no tenant configuration was modified.</footer>
</div>
</body></html>
"@

    $htmlOut = [System.IO.Path]::ChangeExtension($OutputPath, '.html')
    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $htmlOut -Content $nistHtmlDoc
    } else {
        $nistHtmlDoc | Out-File -LiteralPath $htmlOut -Encoding utf8
        if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileAcl -Path $htmlOut -ErrorAction SilentlyContinue
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # XLSX — best effort. A missing openpyxl must not fail the Markdown above.
    # ─────────────────────────────────────────────────────────────────────────
    $xlsxPath = [System.IO.Path]::ChangeExtension($OutputPath, '.xlsx')
    try {
        Publish-NRGNISTMatrixXlsx -Metadata $Metadata -Summary ([ordered]@{
                Overall     = $overall
                Coverage    = $cov
                MatrixRows  = $sortedRows
                NotAssessed = $notAssessed
                Physical    = $phys
            }) -OutputPath $xlsxPath
    } catch {
        Write-Warning "NIST matrix XLSX skipped: $($_.Exception.Message)"
    }
}

function Publish-NRGNISTMatrixXlsx {
    <#
        Renders the NIST-only workbook via the same embedded-Python + openpyxl
        approach as Publish-NRGComplianceMatrix: no Excel, no COM, and no tenant
        data interpolated into code — everything crosses the boundary as JSON.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Metadata,
        [Parameter(Mandatory)] [System.Collections.Specialized.OrderedDictionary] $Summary,
        [Parameter(Mandatory)] [string] $OutputPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $pythonCmd = $null
    foreach ($py in @('python3','python')) {
        try {
            $null = & $py -c 'import openpyxl' 2>&1
            if ($LASTEXITCODE -eq 0) { $pythonCmd = $py; break }
        } catch { }
    }
    if (-not $pythonCmd) {
        Write-Verbose 'openpyxl not available — NIST matrix XLSX skipped (Markdown was still written).'
        return
    }

    $cov     = $Summary.Coverage
    $overall = $Summary.Overall

    $physRows = @()
    if ($Summary.Physical -and $Summary.Physical.Available) {
        $physRows = @(foreach ($grp in $Summary.Physical.Groups) {
            foreach ($it in $grp.Items) {
                @{
                    Group       = [string]$grp.Title
                    NistControl = [string]$it.NistControl
                    NistTitle   = [string]$it.NistTitle
                    Scope       = [string]$it.Scope
                    Status      = [string]$it.Status
                    Aspect      = [string]$it.DeviceAspect
                    Evidence    = [string](@($it.Evidence | ForEach-Object { "$($_.ControlId) ($($_.State))" }) -join ', ')
                    Collect     = [string]$it.OffTenantEvidence
                    Options     = [string](@($it.Options) -join "`n")
                }
            }
        })
    }

    $payload = @{
        Metadata = @{
            TenantDomain   = [string](Get-NRGObjectField -Item $Metadata -Key 'TenantDomain'   -Default 'Unknown')
            AssessmentDate = [string](Get-NRGObjectField -Item $Metadata -Key 'AssessmentDate' -Default (Get-Date -Format 'yyyy-MM-dd'))
            ToolVersion    = [string](Get-NRGObjectField -Item $Metadata -Key 'ToolVersion'    -Default '')
        }
        Overall = @{
            Score = $overall.Score; Satisfied = $overall.Satisfied; Partial = $overall.Partial
            # Error crosses the boundary too. It was omitted here, which is why
            # the XLSX Summary sheet could not name it and left a reader adding
            # met+partial+gaps+N/A to a total short of the finding count.
            Gap = $overall.Gap; Error = $overall.Error; NA = $overall.NA; Scored = $overall.Scored
            FamilyCount = $cov.FamilyCount; ControlCount = $cov.NistControlCount
        }
        Families = @($cov.Families | ForEach-Object {
            @{
                Family = [string]$_.Family; Name = [string]$_.Name; Assessed = $_.Assessed
                Satisfied = $_.Satisfied; Partial = $_.Partial; Gap = $_.Gap
                Error = $_.Error; NA = $_.NA
                Scored = $_.Scored; Score = $_.Score
                NistControls = [string](@($_.NistControls) -join ', ')
            }
        })
        Controls = @($cov.Controls | ForEach-Object {
            @{
                NistControl = [string]$_.NistControl
                NistTitle   = [string](Get-NRGNISTControlTitle -ControlId $_.NistControl)
                Family = [string]$_.Family; FamilyName = [string]$_.FamilyName
                Assessed = $_.Assessed; Satisfied = $_.Satisfied; Partial = $_.Partial
                Gap = $_.Gap; Error = $_.Error; NA = $_.NA; Scored = $_.Scored; Score = $_.Score
                ControlIds = [string](@($_.ControlIds) -join ', ')
            }
        })
        Matrix = @($Summary.MatrixRows | ForEach-Object {
            @{
                NistControl = [string]$_.NistControl; NistTitle = [string]$_.NistTitle
                Family = [string]$_.Family; FamilyTitle = [string]$_.FamilyTitle
                ToolControl = [string]$_.ToolControl; Title = [string]$_.Title
                State = [string]$_.State; Severity = [string]$_.Severity
                CurrentValue = [string]$_.CurrentValue; RequiredValue = [string]$_.RequiredValue
                Remediation = [string]$_.Remediation; BusinessRisk = [string]$_.BusinessRisk
                LicenseReq = [string]$_.LicenseReq; Detail = [string]$_.Detail
            }
        })
        NotAssessed = @($Summary.NotAssessed | ForEach-Object {
            @{
                NistControl = [string]$_.NistControl
                NistTitle   = [string](Get-NRGNISTControlTitle -ControlId $_.NistControl)
                ControlIds  = [string](@($_.ControlIds) -join ', ')
            }
        })
        Physical = $physRows
    }

    $outputDir = Split-Path -Parent $OutputPath
    if (-not $outputDir -or -not (Test-Path -LiteralPath $outputDir)) {
        $outputDir = [System.IO.Path]::GetTempPath()
    }
    $base    = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
    if ([string]::IsNullOrWhiteSpace($base)) { $base = 'nist-matrix' }
    $tmpJson = Join-Path $outputDir "$base-nist-input.json"
    $pyTmp   = Join-Path $outputDir "$base-nist-helper.py"

    try {
        # Co-located with the output (already an ACL-hardened directory) and
        # hardened as it is written, rather than staged through a shared TEMP.
        if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileContent -Path $tmpJson -Content ($payload | ConvertTo-Json -Depth 6 -Compress)
        } else {
            $payload | ConvertTo-Json -Depth 6 -Compress | Out-File -LiteralPath $tmpJson -Encoding utf8
            if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
                Set-NRGSensitiveFileAcl -Path $tmpJson -ErrorAction SilentlyContinue
            }
        }

        $pyScript = @'
import json, sys
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

with open(sys.argv[1], encoding='utf-8') as fh:
    d = json.load(fh)

meta = d['Metadata']
NAVY, ORANGE, WHITE, PURPLE = '0F2544', 'E8621A', 'FFFFFF', '4C1D95'
GREY, INK, MUTED = 'F1F5F9', '111827', '6B7280'
STATE_BG = {'Satisfied':'D1FAE5','Partial':'FEF3C7','Gap':'FEE2E2','NotApplicable':'E5E7EB','Error':'FEE2E2'}
STATE_FG = {'Satisfied':'065F46','Partial':'92400E','Gap':'991B1B','NotApplicable':'4B5563','Error':'991B1B'}
SEV_FG   = {'Critical':'991B1B','High':'B91C1C','Medium':'B45309','Low':'4B5563','Informational':'4B5563'}
# Excel reads a leading =, +, -, @ as a formula. Tenant strings are data.
LEAD = ('=', '+', '-', '@')

def safe(v):
    if v is None: return ''
    if isinstance(v, (int, float)): return v
    s = str(v)
    return ("'" + s) if s[:1] in LEAD else s

def thin(ws, r, c):
    side = Side(style='thin', color='E2E8F0')
    ws.cell(row=r, column=c).border = Border(left=side, right=side, top=side, bottom=side)

def sheet(title, columns, rows, state_key='State'):
    ws = wb.create_sheet(title)
    ws.sheet_view.showGridLines = False
    ws.freeze_panes = 'A3'
    ws.merge_cells(f'A1:{get_column_letter(len(columns))}1')
    banner = ws['A1']
    banner.value = f'{title} — {meta["TenantDomain"]} — NIST SP 800-53 Rev 5'
    banner.font = Font(name='Arial', bold=True, size=11, color=WHITE)
    banner.fill = PatternFill('solid', fgColor=NAVY)
    banner.alignment = Alignment(horizontal='center', vertical='center')
    ws.row_dimensions[1].height = 26
    for j, (name, width) in enumerate(columns, 1):
        c = ws.cell(row=2, column=j, value=name)
        c.font = Font(name='Arial', bold=True, size=9, color=WHITE)
        c.fill = PatternFill('solid', fgColor=ORANGE)
        c.alignment = Alignment(horizontal='center', vertical='center', wrap_text=True)
        ws.column_dimensions[get_column_letter(j)].width = width
    ws.row_dimensions[2].height = 20
    for i, row in enumerate(rows, 3):
        st = str(row.get(state_key, '') or '')
        bg = STATE_BG.get(st, '')
        longest = max((len(str(row.get(n, '') or '')) for n, _ in columns), default=0)
        ws.row_dimensions[i].height = max(15, min(90, 11 + longest / 7))
        for j, (name, _) in enumerate(columns, 1):
            val = row.get(name, '')
            fg = INK
            if name == state_key: fg = STATE_FG.get(st, INK)
            elif name == 'Severity': fg = SEV_FG.get(str(val), INK)
            c = ws.cell(row=i, column=j, value=safe(val))
            if isinstance(c.value, str): c.data_type = 's'
            c.font = Font(name='Arial', size=9, color=fg, bold=(name == state_key))
            if bg: c.fill = PatternFill('solid', fgColor=bg)
            c.alignment = Alignment(horizontal='left', vertical='top', wrap_text=True)
            thin(ws, i, j)
    if rows:
        ws.auto_filter.ref = f'A2:{get_column_letter(len(columns))}{len(rows) + 2}'
    return ws

wb = Workbook()

# ── Summary ──────────────────────────────────────────────────────────────────
ws = wb.active
ws.title = 'Summary'
ws.sheet_view.showGridLines = False
ws.column_dimensions['A'].width = 34
ws.column_dimensions['B'].width = 58
ws.merge_cells('A1:B1')
t = ws['A1']
t.value = 'NIST SP 800-53 Rev 5 — Compliance Matrix'
t.font = Font(name='Arial', bold=True, size=14, color=WHITE)
t.fill = PatternFill('solid', fgColor=NAVY)
t.alignment = Alignment(horizontal='center', vertical='center')
ws.row_dimensions[1].height = 34

o = d['Overall']
rows = [
    ('Tenant', meta['TenantDomain']),
    ('Assessment date', meta['AssessmentDate']),
    ('Tool version', meta['ToolVersion']),
    ('', ''),
    ('800-53 posture score', f"{o['Score']}%"),
    ('Controls met', o['Satisfied']),
    ('Partially met', o['Partial']),
    ('Gaps', o['Gap']),
    # Errors are scored as failures and sit in the denominator, so naming them
    # is not optional: without this row a reader adds met+partial+gaps+N/A,
    # comes up short of the finding count, and cannot tell whether the missing
    # rows were passes or failures.
    ('Errors (collection or evaluation failed)', o['Error']),
    ('Not assessable (excluded from score)', o['NA']),
    ('Families exercised', f"{o['FamilyCount']} of 20"),
    ('800-53 controls exercised', o['ControlCount']),
    ('', ''),
    ('Scope', 'Microsoft 365 tenant configuration only.'),
    ('', 'The score covers the controls this tool exercises. It is NOT an 800-53 baseline completion percentage — a Low/Moderate/High baseline contains many controls no tenant scan can reach.'),
    ('', 'Physical, media, maintenance and personnel controls are on the "Physical & Device" sheet, UNSCORED, with the evidence an assessor must collect directly.'),
    ('', 'A tool control mapped to several 800-53 controls appears under each, so rows do not sum to the finding count.'),
    ('', '"Not assessable" means this tool could not evaluate the control — missing license, unconnected service, failed query. It does NOT mean the tenant passed.'),
]
r = 3
for label, value in rows:
    a = ws.cell(row=r, column=1, value=safe(label))
    a.font = Font(name='Arial', bold=True, size=10, color=INK)
    a.alignment = Alignment(horizontal='left', vertical='top')
    b = ws.cell(row=r, column=2, value=safe(value))
    b.font = Font(name='Arial', size=10, color=INK if label else MUTED)
    b.alignment = Alignment(horizontal='left', vertical='top', wrap_text=True)
    if label == '800-53 posture score':
        b.font = Font(name='Arial', bold=True, size=14, color=PURPLE)
    if not label and value:
        ws.row_dimensions[r].height = max(15, min(60, 11 + len(str(value)) / 7))
    r += 1

# ── Control Matrix ───────────────────────────────────────────────────────────
sheet('Control Matrix',
      [('800-53', 11), ('Title', 40), ('Family', 9), ('Tenant Control', 14),
       ('Finding', 38), ('State', 14), ('Severity', 11), ('Current', 26),
       ('Required', 26), ('Remediation', 46), ('Business Risk', 40), ('License', 26)],
      [{'800-53': m['NistControl'], 'Title': m['NistTitle'], 'Family': m['Family'],
        'Tenant Control': m['ToolControl'], 'Finding': m['Title'], 'State': m['State'],
        'Severity': m['Severity'], 'Current': m['CurrentValue'], 'Required': m['RequiredValue'],
        'Remediation': m['Remediation'], 'Business Risk': m['BusinessRisk'],
        'License': m['LicenseReq']} for m in d['Matrix']])

# ── By Control ───────────────────────────────────────────────────────────────
sheet('By Control',
      [('800-53', 11), ('Title', 46), ('Family', 9), ('Family Name', 30),
       ('Assessed', 10), ('Met', 8), ('Partial', 9), ('Gap', 8), ('Error', 8), ('N/A', 8),
       ('Coverage', 13), ('Evidenced By', 40)],
      [{'800-53': c['NistControl'], 'Title': c['NistTitle'], 'Family': c['Family'],
        'Family Name': c['FamilyName'], 'Assessed': c['Assessed'], 'Met': c['Satisfied'],
        'Partial': c['Partial'], 'Gap': c['Gap'], 'Error': c['Error'], 'N/A': c['NA'],
        'Coverage': (f"{c['Score']}%" if c['Scored'] > 0 else 'Not assessed'),
        'Evidenced By': c['ControlIds']} for c in d['Controls']],
      state_key='__none__')

# ── By Family ────────────────────────────────────────────────────────────────
sheet('By Family',
      [('Family', 9), ('Name', 40), ('Assessed', 10), ('Met', 8), ('Partial', 9),
       ('Gap', 8), ('Error', 8), ('N/A', 8), ('Coverage', 13), ('800-53 Controls', 52)],
      [{'Family': f['Family'], 'Name': f['Name'], 'Assessed': f['Assessed'],
        'Met': f['Satisfied'], 'Partial': f['Partial'], 'Gap': f['Gap'],
        'Error': f['Error'], 'N/A': f['NA'],
        'Coverage': (f"{f['Score']}%" if f['Scored'] > 0 else 'Not assessed'),
        '800-53 Controls': f['NistControls']} for f in d['Families']],
      state_key='__none__')

# ── Physical & Device ────────────────────────────────────────────────────────
if d['Physical']:
    sheet('Physical & Device',
          [('Group', 26), ('800-53', 11), ('Control', 34), ('Scope', 11), ('Status', 21),
           ('Device Aspect', 52), ('Tenant Evidence', 30), ('Evidence to Collect', 52),
           ('Implementation Options', 64)],
          [{'Group': p['Group'], '800-53': p['NistControl'], 'Control': p['NistTitle'],
            'Scope': p['Scope'], 'Status': p['Status'], 'Device Aspect': p['Aspect'],
            'Tenant Evidence': p['Evidence'], 'Evidence to Collect': p['Collect'],
            'Implementation Options': p['Options']} for p in d['Physical']],
          state_key='__none__')

# ── Not Assessed ─────────────────────────────────────────────────────────────
if d['NotAssessed']:
    sheet('Not Assessed',
          [('800-53', 11), ('Title', 46), ('Tool Controls', 34), ('Why', 62)],
          [{'800-53': n['NistControl'], 'Title': n['NistTitle'], 'Tool Controls': n['ControlIds'],
            'Why': 'Every finding behind this control returned NotApplicable — missing license, '
                   'unconnected service, or a query that did not complete. Not a pass and not a gap.'}
           for n in d['NotAssessed']],
          state_key='__none__')

wb.save(sys.argv[2])
print(f'NIST matrix XLSX saved: {sys.argv[2]}')
'@

        if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileContent -Path $pyTmp -Content $pyScript
        } else {
            $pyScript | Out-File -LiteralPath $pyTmp -Encoding utf8
        }

        $out = & $pythonCmd $pyTmp $tmpJson $OutputPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "openpyxl helper failed: $out"
        }
        if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileAcl -Path $OutputPath -ErrorAction SilentlyContinue
        }
    } finally {
        # The JSON carries tenant findings — remove it whether or not the render
        # succeeded, rather than leaving it beside the deliverable.
        foreach ($t in @($tmpJson, $pyTmp)) {
            if (Test-Path -LiteralPath $t) { Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue }
        }
    }
}
