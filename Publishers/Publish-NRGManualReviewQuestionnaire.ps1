#Requires -Version 7.0
#
# Publish-NRGManualReviewQuestionnaire.ps1
# Dependencies: Get-NRGManualReviewItems, python3/python + reportlab
#               (optional, for the fillable PDF).
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Renders the controls.json manual-review questionnaire — the
#          NoProgrammaticCheck and CollectionIncomplete buckets from
#          Get-NRGAssessmentScope.ps1, turned into a fillable client
#          document. Mirrors Publish-NRGSSPQuestionnaire.ps1's shape and
#          honesty rules exactly, for the OTHER catalog this tool scores
#          against: controls.json controls instead of NIST 800-171
#          requirements. Import-NRGManualReviewQuestionnaire.ps1 is the
#          other half — it reads a filled copy back into
#          Config/manual-review/<client-slug>.psd1.
#
#          A SEPARATE document from the SSP questionnaire, not merged into
#          it, and deliberately so: a controls.json ControlId ('SPO-2.2')
#          and a NIST 800-171 requirement id ('3.5.3') are different
#          catalogs with different shapes, and forcing them into one item
#          list would mean inventing a unified id scheme neither source
#          data actually has. Both documents share the same generator/
#          importer PATTERN (Markdown + HTML always, best-effort fillable
#          PDF via the same embedded Python + reportlab approach, a
#          companion manifest JSON, the same never-overwrite-an-existing-
#          answers-file rule) without sharing a data model.
#
#          STATUS VOCABULARY is intentionally different from the SSP
#          questionnaire's, because "what does compliance status mean for a
#          control with literally no automated check" is a different
#          question from "is this 800-171 requirement implemented": it adds
#          'Compensating control' (an alternative control satisfies the
#          intent) and 'Risk accepted' (a named owner accepted the gap, with
#          an expiration) as first-class outcomes, matching how an MSP
#          actually dispositions an unassessable finding.
#
# Inputs:  -Scope       the [ordered] hashtable from Get-NRGAssessmentScope.
#          -Answers     optional prior answers (Get-NRGManualReviewAnswers),
#                       so a review shows prior answers for re-attestation.
#          -Metadata    hashtable: TenantDomain, Date (or similar; only
#                       -Date is read).
#          -OutputPath  .md path; .html/.pdf/.manifest.json are written
#                       alongside it with the same base name.
#          -Workload    optional filter to one workload (e.g. 'SPO'), so a
#                       questionnaire can go to the person who owns it.
#          -ClientName  used only to title the document.
#
# Consumes: Get-NRGManualReviewItems output. No Graph, no EXO, no network.
#

function Publish-NRGManualReviewQuestionnaire {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary] $Scope,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object] $Answers,

        [Parameter(Mandatory)]
        [hashtable] $Metadata,

        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
            return $true
        })]
        [string] $OutputPath,

        [Parameter(Mandatory = $false)]
        [AllowNull()] [AllowEmptyString()]
        [string] $Workload,

        [Parameter(Mandatory = $false)]
        [AllowNull()] [AllowEmptyString()]
        [string] $ClientName
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $items = @(Get-NRGManualReviewItems -Scope $Scope -Workload $Workload -Answers $Answers)

    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        $null = [System.IO.Directory]::CreateDirectory($outDir)
    }

    $title = if ($ClientName) { "Manual Review Questionnaire — $ClientName" } else { 'Manual Review Questionnaire' }
    $generatedAt = [string]$Metadata['Date']
    if (-not $generatedAt) { $generatedAt = (Get-Date).ToString('yyyy-MM-dd') }

    $bucketLabel = @{
        NoProgrammaticCheck  = 'No automated test exists'
        CollectionIncomplete = 'Data could not be collected this run'
    }

    # ── Markdown — guaranteed ────────────────────────────────────────────────
    $md = [System.Text.StringBuilder]::new()
    [void]$md.AppendLine("# $title")
    [void]$md.AppendLine()
    [void]$md.AppendLine("Generated $generatedAt")
    [void]$md.AppendLine()
    if ($items.Count -eq 0) {
        [void]$md.AppendLine('Every control this run could reach either has an automated verdict or was already answered here. There is nothing left to ask.')
    } else {
        [void]$md.AppendLine("$($items.Count) control(s) need a written answer. For each: state Status (Fully implemented / Partially implemented / Not implemented / Not applicable / Not assessed / Compensating control / Risk accepted), who owns it, and what proves it — name the evidence and where it lives.")
        [void]$md.AppendLine()
        foreach ($it in $items) {
            [void]$md.AppendLine("## $($it['ControlId']) — $($it['Title'])")
            [void]$md.AppendLine()
            [void]$md.AppendLine("*$($bucketLabel[[string]$it['Bucket']]) — $($it['Workload']) / $($it['Severity'])*")
            [void]$md.AppendLine()
            if ($it['Question']) { [void]$md.AppendLine($it['Question']); [void]$md.AppendLine() }
            if ($it['BusinessRisk']) { [void]$md.AppendLine("*Why it matters: $($it['BusinessRisk'])*"); [void]$md.AppendLine() }
            [void]$md.AppendLine("*Tool note: $($it['Reason'])*")
            [void]$md.AppendLine()
            [void]$md.AppendLine('- Status: ______________________')
            [void]$md.AppendLine('- Owner: ______________________')
            [void]$md.AppendLine('- Evidence (what exists, what proves it, where it lives): ')
            [void]$md.AppendLine('  ______________________________________________________________')
            [void]$md.AppendLine('- If Not applicable, why: ______________________')
            [void]$md.AppendLine('- If Compensating control, describe it: ______________________')
            [void]$md.AppendLine('- If Risk accepted, by whom and until when: ______________________')
            [void]$md.AppendLine('- If not fully in place — gap: ______________________')
            [void]$md.AppendLine('- Remediation action / owner / target date: ______________________')
            [void]$md.AppendLine()
        }
    }
    [System.IO.File]::WriteAllText($OutputPath, $md.ToString(), [System.Text.UTF8Encoding]::new($false))

    # ── HTML — mirrors the Markdown, self-contained, printable ──────────────
    $htmlPath = [System.IO.Path]::ChangeExtension($OutputPath, '.html')
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('<!DOCTYPE html><html><head><meta charset="utf-8">')
    [void]$sb.AppendLine("<title>$(ConvertTo-NRGHtmlSafe($title))</title>")
    [void]$sb.AppendLine('<style>body{font-family:Segoe UI,Arial,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#111827}')
    [void]$sb.AppendLine('h1{color:#0F2544} h2{color:#0F2544;border-top:1px solid #E2E8F0;padding-top:1rem;margin-top:2rem}')
    [void]$sb.AppendLine('.meta{color:#6B7280;font-size:.85rem} .bucket{color:#92400E;font-style:italic;font-size:.9rem} .risk{color:#4B5563;font-style:italic;font-size:.9rem}')
    [void]$sb.AppendLine('label{display:block;margin-top:.6rem;font-weight:600;font-size:.9rem}')
    [void]$sb.AppendLine('input[type=text],textarea,select{width:100%;box-sizing:border-box;padding:.35rem;font-family:inherit;font-size:.9rem;border:1px solid #CBD5E1;border-radius:4px}')
    [void]$sb.AppendLine('@media print{input,textarea,select{border:1px solid #999}}</style></head><body>')
    [void]$sb.AppendLine("<h1>$(ConvertTo-NRGHtmlSafe($title))</h1>")
    [void]$sb.AppendLine("<p class=`"meta`">Generated $generatedAt</p>")
    if ($items.Count -eq 0) {
        [void]$sb.AppendLine('<p>Every control this run could reach either has an automated verdict or was already answered here. There is nothing left to ask.</p>')
    } else {
        [void]$sb.AppendLine("<p>$($items.Count) control(s) need a written answer. This page is printable/fillable in a browser but is NOT re-imported by the tool — use the companion PDF for a round trip back into the answers file.</p>")
        $statusOptions = @('', 'Fully implemented', 'Partially implemented', 'Not implemented', 'Not applicable', 'Not assessed', 'Compensating control', 'Risk accepted')
        foreach ($it in $items) {
            $cid = ConvertTo-NRGHtmlSafe([string]$it['ControlId'])
            [void]$sb.AppendLine("<h2>$cid — $(ConvertTo-NRGHtmlSafe([string]$it['Title']))</h2>")
            [void]$sb.AppendLine("<p class=`"bucket`">$(ConvertTo-NRGHtmlSafe($bucketLabel[[string]$it['Bucket']])) — $(ConvertTo-NRGHtmlSafe([string]$it['Workload'])) / $(ConvertTo-NRGHtmlSafe([string]$it['Severity']))</p>")
            if ($it['Question']) { [void]$sb.AppendLine("<p>$(ConvertTo-NRGHtmlSafe([string]$it['Question']))</p>") }
            if ($it['BusinessRisk']) { [void]$sb.AppendLine("<p class=`"risk`">Why it matters: $(ConvertTo-NRGHtmlSafe([string]$it['BusinessRisk']))</p>") }
            [void]$sb.AppendLine("<p class=`"meta`">Tool note: $(ConvertTo-NRGHtmlSafe([string]$it['Reason']))</p>")
            [void]$sb.AppendLine('<label>Status</label><select>')
            foreach ($opt in $statusOptions) {
                $sel = if ($opt -and $opt -eq $it['CurrentStatus']) { ' selected' } else { '' }
                $label = if ($opt) { ConvertTo-NRGHtmlSafe($opt) } else { '-- select --' }
                [void]$sb.AppendLine("<option$sel>$label</option>")
            }
            [void]$sb.AppendLine('</select>')
            [void]$sb.AppendLine("<label>Owner</label><input type=`"text`" value=`"$(ConvertTo-NRGHtmlSafe([string]$it['CurrentOwner']))`">")
            [void]$sb.AppendLine("<label>Evidence (what exists, what proves it, where it lives)</label><textarea rows=`"3`">$(ConvertTo-NRGHtmlSafe([string]$it['CurrentEvidence']))</textarea>")
            [void]$sb.AppendLine("<label>If Not applicable, why</label><input type=`"text`" value=`"$(ConvertTo-NRGHtmlSafe([string]$it['CurrentNaReason']))`">")
            [void]$sb.AppendLine("<label>If Compensating control, describe it</label><input type=`"text`" value=`"$(ConvertTo-NRGHtmlSafe([string]$it['CurrentCompensating']))`">")
            [void]$sb.AppendLine("<label>If Risk accepted, by whom and until when</label><input type=`"text`" value=`"$(ConvertTo-NRGHtmlSafe([string]$it['CurrentRiskAcceptance']))`">")
            [void]$sb.AppendLine("<label>Gap (if not fully in place)</label><input type=`"text`" value=`"$(ConvertTo-NRGHtmlSafe([string]$it['CurrentPoamWeakness']))`">")
            [void]$sb.AppendLine("<label>Remediation action</label><input type=`"text`" value=`"$(ConvertTo-NRGHtmlSafe([string]$it['CurrentPoamRemedy']))`">")
            [void]$sb.AppendLine("<label>Remediation owner</label><input type=`"text`" value=`"$(ConvertTo-NRGHtmlSafe([string]$it['CurrentPoamOwner']))`">")
            [void]$sb.AppendLine("<label>Target date</label><input type=`"text`" value=`"$(ConvertTo-NRGHtmlSafe([string]$it['CurrentPoamDueDate']))`">")
        }
    }
    [void]$sb.AppendLine('</body></html>')
    [System.IO.File]::WriteAllText($htmlPath, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))

    if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileAcl -Path $OutputPath -ErrorAction SilentlyContinue
        Set-NRGSensitiveFileAcl -Path $htmlPath -ErrorAction SilentlyContinue
    }

    if ($items.Count -eq 0) { return }

    # ── PDF + manifest — best effort ─────────────────────────────────────────
    try {
        Publish-NRGManualReviewQuestionnairePdf -Items $items -Title $title -GeneratedAt $generatedAt -OutputPath $OutputPath
    } catch {
        Write-Warning "Manual-review questionnaire PDF skipped: $($_.Exception.Message)"
    }
}

function Publish-NRGManualReviewQuestionnairePdf {
    <#
        The fillable artifact. Manifest is written directly from PowerShell —
        it needs no Python round trip, only the PDF's AcroForm rendering does.
        Same field-naming-by-position rule as the SSP questionnaire PDF: a
        ControlId like 'AAD-15.1' is not a safe AcroForm field name fragment
        either (dashes are fine, but staying consistent with the SSP
        generator's proven pattern avoids re-discovering an edge case).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Items,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $GeneratedAt,
        [Parameter(Mandatory)] [string] $OutputPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $pythonCmd = $null
    foreach ($py in @('python3', 'python')) {
        try {
            $null = & $py -c 'import reportlab' 2>&1
            if ($LASTEXITCODE -eq 0) { $pythonCmd = $py; break }
        } catch { }
    }
    if (-not $pythonCmd) {
        Write-Verbose 'reportlab not available — manual-review questionnaire PDF skipped (Markdown and HTML were still written).'
        return
    }

    $pdfPath      = [System.IO.Path]::ChangeExtension($OutputPath, '.pdf')
    $manifestPath = [System.IO.Path]::ChangeExtension($OutputPath, '.manifest.json')
    $outDir  = Split-Path -Parent $OutputPath
    if (-not $outDir -or -not (Test-Path -LiteralPath $outDir)) { $outDir = [System.IO.Path]::GetTempPath() }
    $base    = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
    if ([string]::IsNullOrWhiteSpace($base)) { $base = 'manual-review-questionnaire' }
    $tmpJson = Join-Path $outDir "$base-input.json"
    $pyTmp   = Join-Path $outDir "$base-helper.py"

    $manifestItems = [System.Collections.Generic.List[object]]::new()
    $payloadItems  = [System.Collections.Generic.List[object]]::new()
    $idx = 0
    foreach ($it in $Items) {
        $idx++
        $manifestItems.Add([ordered]@{ Index = $idx; ControlId = [string]$it['ControlId']; Bucket = [string]$it['Bucket'] })
        $payloadItems.Add(@{
            Index = $idx
            ControlId = [string]$it['ControlId']
            Title = [string]$it['Title']
            Question = [string]$it['Question']
            BusinessRisk = [string]$it['BusinessRisk']
            Reason = [string]$it['Reason']
            CurrentStatus = [string]$it['CurrentStatus']
            CurrentEvidence = [string]$it['CurrentEvidence']
            CurrentOwner = [string]$it['CurrentOwner']
            CurrentNaReason = [string]$it['CurrentNaReason']
            CurrentCompensating = [string]$it['CurrentCompensating']
            CurrentRiskAcceptance = [string]$it['CurrentRiskAcceptance']
            CurrentPoamWeakness = [string]$it['CurrentPoamWeakness']
            CurrentPoamRemedy = [string]$it['CurrentPoamRemedy']
            CurrentPoamOwner = [string]$it['CurrentPoamOwner']
            CurrentPoamDueDate = [string]$it['CurrentPoamDueDate']
        })
    }

    $manifest = [ordered]@{
        GeneratedAt = $GeneratedAt
        Title       = $Title
        ToolVersion = '4.12.1'
        Items       = $manifestItems.ToArray()
    }

    try {
        if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileContent -Path $manifestPath -Content ($manifest | ConvertTo-Json -Depth 6)
        } else {
            $manifest | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $manifestPath -Encoding utf8
        }

        $payload = @{ ClientName = $Title; GeneratedAt = $GeneratedAt; Items = $payloadItems.ToArray() }
        if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileContent -Path $tmpJson -Content ($payload | ConvertTo-Json -Depth 6 -Compress)
        } else {
            $payload | ConvertTo-Json -Depth 6 -Compress | Out-File -LiteralPath $tmpJson -Encoding utf8
        }

        $pyScript = @'
import json, sys, textwrap
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter

with open(sys.argv[1], encoding='utf-8') as fh:
    d = json.load(fh)

items = d['Items']
PAGE_W, PAGE_H = letter
MARGIN = 42
c = canvas.Canvas(sys.argv[2], pagesize=letter)
form = c.acroForm

# Same reportlab gotcha as the SSP questionnaire generator: AcroForm.choice()
# crashes on an empty-string default value (see reportlab/pdfbase/acroform.py
# _textfield — the /Opt appearance dict is only built on the truthy-value
# branch). A real sentinel option, never '', is the workaround.
STATUS_OPTIONS = ['-- not answered --', 'Fully implemented', 'Partially implemented',
                   'Not implemented', 'Not applicable', 'Not assessed',
                   'Compensating control', 'Risk accepted']

y = PAGE_H - MARGIN

def wrap(text, width_chars):
    if not text:
        return ['']
    out = []
    for line in text.splitlines() or ['']:
        out.extend(textwrap.wrap(line, width_chars) or [''])
    return out

def need(h):
    global y
    if y - h < MARGIN:
        c.showPage()
        y = PAGE_H - MARGIN

def header(title):
    global y
    c.setFont('Helvetica-Bold', 14)
    c.drawString(MARGIN, y, title)
    y -= 22

header(d.get('ClientName', 'Manual Review Questionnaire'))
c.setFont('Helvetica', 9)
c.drawString(MARGIN, y, f"Generated {d.get('GeneratedAt','')}")
y -= 20
c.setFont('Helvetica', 8)
c.setFillColorRGB(0.4, 0.4, 0.4)
for line in wrap('Fill in every field you can. Leave Status unanswered rather than guessing '
                  '-- a blank is honest, a wrong answer becomes a false statement in a client '
                  'deliverable. Name the actual evidence and where it lives.', 110):
    c.drawString(MARGIN, y, line)
    y -= 10
c.setFillColorRGB(0, 0, 0)
y -= 10

def field_row(label, fname, value, h=14, multiline=False, choice=None):
    global y
    need(h + 6)
    c.setFont('Helvetica', 9)
    c.drawString(MARGIN, y, label)
    fx = MARGIN + 175
    fw = PAGE_W - MARGIN - fx
    if choice is not None:
        form.choice(name=fname, tooltip=label, value=value or choice[0], options=choice,
                    x=fx, y=y - 4, width=fw, height=h, borderStyle='inset', forceBorder=True)
    else:
        form.textfield(name=fname, tooltip=label, value=value or '',
                        x=fx, y=y - h + 9, width=fw, height=h,
                        fieldFlags='multiline' if multiline else '',
                        borderStyle='inset', forceBorder=True)
    y -= (h + 6)

for it in items:
    idx = it['Index']
    need(190)
    c.setFont('Helvetica-Bold', 11)
    c.drawString(MARGIN, y, f"Q{idx}. {it['ControlId']} — {it.get('Title','')}")
    y -= 15
    c.setFont('Helvetica', 9)
    for line in wrap(it.get('Question', ''), 100):
        need(12)
        c.drawString(MARGIN, y, line)
        y -= 12
    risk = it.get('BusinessRisk', '')
    if risk:
        y -= 2
        c.setFont('Helvetica-Oblique', 8)
        for line in wrap(f"Why it matters: {risk}", 105):
            need(11)
            c.drawString(MARGIN, y, line)
            y -= 11
    y -= 3
    need(18)
    c.setFont('Helvetica', 8)
    c.setFillColorRGB(0.4, 0.4, 0.4)
    c.drawString(MARGIN, y, f"Tool note: {it.get('Reason','')}"[:115])
    c.setFillColorRGB(0, 0, 0)
    y -= 16

    status_val = it.get('CurrentStatus') or ''
    if status_val not in STATUS_OPTIONS:
        status_val = ''
    field_row('Status:', f'q{idx}_status', status_val, h=14, choice=STATUS_OPTIONS)
    field_row('Evidence (what/who/where it lives):', f'q{idx}_evidence',
              it.get('CurrentEvidence', ''), h=36, multiline=True)
    field_row('Owner:', f'q{idx}_owner', it.get('CurrentOwner', ''), h=14)
    field_row('If Not applicable, why:', f'q{idx}_nareason', it.get('CurrentNaReason', ''), h=14)
    field_row('If Compensating control, describe it:', f'q{idx}_compensating', it.get('CurrentCompensating', ''), h=14)
    field_row('If Risk accepted, by whom/until when:', f'q{idx}_riskaccept', it.get('CurrentRiskAcceptance', ''), h=14)
    field_row('Gap (if not fully in place):', f'q{idx}_poamweakness', it.get('CurrentPoamWeakness', ''), h=14)
    field_row('Remediation action:', f'q{idx}_poamremedy', it.get('CurrentPoamRemedy', ''), h=14)
    field_row('Remediation owner:', f'q{idx}_poamowner', it.get('CurrentPoamOwner', ''), h=14)
    field_row('Target date:', f'q{idx}_poamdue', it.get('CurrentPoamDueDate', ''), h=14)
    need(16)
    c.setStrokeColorRGB(0.85, 0.85, 0.85)
    c.line(MARGIN, y, PAGE_W - MARGIN, y)
    y -= 14

c.save()
print('Manual review questionnaire PDF saved:', sys.argv[2])
'@

        if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileContent -Path $pyTmp -Content $pyScript
        } else {
            $pyScript | Out-File -LiteralPath $pyTmp -Encoding utf8
        }

        $out = & $pythonCmd $pyTmp $tmpJson $pdfPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "reportlab helper failed: $out"
        }
        if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileAcl -Path $pdfPath -ErrorAction SilentlyContinue
            Set-NRGSensitiveFileAcl -Path $manifestPath -ErrorAction SilentlyContinue
        }
    } finally {
        foreach ($t in @($tmpJson, $pyTmp)) {
            if (Test-Path -LiteralPath $t) { Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue }
        }
    }
}
