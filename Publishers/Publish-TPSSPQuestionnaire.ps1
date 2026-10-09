#Requires -Version 7.0
#
# Publish-TPSSPQuestionnaire.ps1
# Dependencies: Get-TPSSPQuestionnaireItems, python3/python + reportlab
#               (optional, for the fillable PDF).
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Renders the SSP posture's unanswered/attested-only requirements as
#          a CLIENT QUESTIONNAIRE — the manual-evidence half of a System
#          Security Plan that Get-TPSSPPosture cannot fill in by itself.
#          Import-TPSSPQuestionnaire.ps1 is the other half: it reads a
#          FILLED copy of the PDF this emits and turns it back into a
#          Config/ssp/<client-slug>.psd1 answers file.
#
#          THREE OUTPUTS, TWO GUARANTEES.
#            Markdown and HTML are always written — a printable list an
#            operator can hand-carry or read aloud on a call, matching the
#            no-Python-required guarantee every other publisher in this tool
#            makes. Neither is meant to be re-imported; they are read/print
#            copies only.
#
#            The PDF is BEST EFFORT, via an embedded Python + reportlab
#            AcroForm script, same pattern as Publish-TPSSPXlsx's embedded
#            openpyxl script. A missing Python or reportlab skips the PDF
#            with a warning — Markdown and HTML were still written. The PDF
#            is the only one of the three that is actually FILLABLE and
#            IMPORTABLE: it carries real AcroForm fields a client fills in
#            Acrobat/Preview/a browser and emails back, and its companion
#            manifest JSON is what lets the importer map each field back to
#            the requirement it answers.
#
#          FIELD NAMING. AcroForm field names cannot safely contain '.', and
#          NIST 800-171 requirement IDs are dotted ('3.5.3'). Fields are
#          therefore named by POSITION (q<N>_status, q<N>_narrative, ...)
#          where N is this item's 1-based index in THIS questionnaire's item
#          list, and the manifest JSON is the only place that maps N back to
#          a requirement ID. The manifest is not optional decoration — without
#          it the importer cannot resolve a single answer.
#
#          WHAT IS ASKED, AND WHY THOSE FIELDS ONLY. The field set matches
#          Config/ssp/*.psd1's existing answer shape (Status, Narrative,
#          ResponsibleRole, NotApplicableReason, InheritedFrom, Poam) exactly
#          — no new top-level concepts invented for this questionnaire. Where
#          a fuller evidence trail is wanted (what proves it, where it lives,
#          when it was last reviewed, who accepted a residual risk) the
#          question text asks for that content INSIDE Narrative/Poam.Remedy,
#          the same way Config/ssp/example.psd1's own worked examples already
#          write it ("Certificates are filed against the asset tag in the
#          asset register."). A parallel set of Evidence/EvidenceLocation/
#          LastReviewed fields that nothing downstream renders would be dead
#          weight, not a feature.
#
#          QUESTION TEXT. The NIST requirement Statement verbatim — see
#          Get-TPSSPQuestionnaireItems.ps1 for why it is never paraphrased.
#
# Inputs:  -Posture     the [ordered] hashtable from Get-TPSSPPosture.
#          -Metadata    hashtable: SystemName, TenantDomain, Company, Date.
#          -OutputPath  .md path; .html/.pdf/.manifest.json are written
#                       alongside it with the same base name.
#          -Family      optional filter to one 800-171 family (e.g. '3.9'),
#                       so a questionnaire can go to the person who actually
#                       owns that domain instead of everyone getting all 110.
#          -ClientName  used only to title the document.
#
# Consumes: Get-TPSSPQuestionnaireItems output. No Graph, no EXO, no network.
#

function Publish-TPSSPQuestionnaire {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary] $Posture,

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
        [string] $Family,

        [Parameter(Mandatory = $false)]
        [AllowNull()] [AllowEmptyString()]
        [string] $ClientName
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $items = @(Get-TPSSPQuestionnaireItems -Posture $Posture -Family $Family)

    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        $null = [System.IO.Directory]::CreateDirectory($outDir)
    }

    $title = if ($ClientName) { "SSP Questionnaire — $ClientName" } else { 'SSP Questionnaire' }
    $baseline = [string](Get-TPObjectField -Item $Posture -Key 'Baseline' -Default 'NIST SP 800-171 Rev 2')
    $generatedAt = [string]$Metadata['Date']
    if (-not $generatedAt) { $generatedAt = (Get-Date).ToString('yyyy-MM-dd') }

    # ── Markdown — guaranteed ────────────────────────────────────────────────
    $md = [System.Text.StringBuilder]::new()
    [void]$md.AppendLine("# $title")
    [void]$md.AppendLine()
    [void]$md.AppendLine("$baseline — generated $generatedAt")
    [void]$md.AppendLine()
    if ($items.Count -eq 0) {
        [void]$md.AppendLine('Every requirement in this SSP is either tool-verified or already answered. There is nothing left to ask.')
    } else {
        [void]$md.AppendLine("$($items.Count) requirement(s) need a written answer. For each: state Status (Implemented / Partially implemented / Planned / Not implemented / Not applicable / Inherited), who owns it, and what proves it — name the evidence and where it lives directly in the narrative.")
        [void]$md.AppendLine()
        foreach ($it in $items) {
            [void]$md.AppendLine("## $($it['Id']) — $($it['FamilyTitle'])")
            [void]$md.AppendLine()
            [void]$md.AppendLine($it['Question'])
            [void]$md.AppendLine()
            [void]$md.AppendLine("*Current: $(if ($it['CurrentStatus']) { $it['CurrentStatus'] } else { '(not yet answered)' }) — confidence: $($it['Confidence'])*")
            [void]$md.AppendLine()
            [void]$md.AppendLine('- Status: ______________________')
            [void]$md.AppendLine('- Responsible role/owner: ______________________')
            [void]$md.AppendLine('- Narrative (what exists, who owns it, what proves it, where the evidence lives): ')
            [void]$md.AppendLine('  ______________________________________________________________')
            [void]$md.AppendLine('- If Not applicable, why: ______________________')
            [void]$md.AppendLine('- If Inherited, from whom: ______________________')
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
    [void]$sb.AppendLine("<title>$(ConvertTo-TPHtmlSafe($title))</title>")
    [void]$sb.AppendLine('<style>body{font-family:Segoe UI,Arial,sans-serif;max-width:860px;margin:2rem auto;padding:0 1rem;color:#111827}')
    [void]$sb.AppendLine('h1{color:#0F2544} h2{color:#0F2544;border-top:1px solid #E2E8F0;padding-top:1rem;margin-top:2rem}')
    [void]$sb.AppendLine('.meta{color:#6B7280;font-size:.85rem} .cur{color:#92400E;font-style:italic;font-size:.9rem}')
    [void]$sb.AppendLine('label{display:block;margin-top:.6rem;font-weight:600;font-size:.9rem}')
    [void]$sb.AppendLine('input[type=text],textarea,select{width:100%;box-sizing:border-box;padding:.35rem;font-family:inherit;font-size:.9rem;border:1px solid #CBD5E1;border-radius:4px}')
    [void]$sb.AppendLine('@media print{input,textarea,select{border:1px solid #999}}</style></head><body>')
    [void]$sb.AppendLine("<h1>$(ConvertTo-TPHtmlSafe($title))</h1>")
    [void]$sb.AppendLine("<p class=`"meta`">$(ConvertTo-TPHtmlSafe($baseline)) — generated $generatedAt</p>")
    if ($items.Count -eq 0) {
        [void]$sb.AppendLine('<p>Every requirement in this SSP is either tool-verified or already answered. There is nothing left to ask.</p>')
    } else {
        [void]$sb.AppendLine("<p>$($items.Count) requirement(s) need a written answer. This page is printable/fillable in a browser but is NOT re-imported by the tool — use the companion PDF for a round trip back into the answers file.</p>")
        $statusOptions = @('', 'Implemented', 'Partially implemented', 'Planned', 'Not implemented', 'Not applicable', 'Inherited')
        foreach ($it in $items) {
            $id = ConvertTo-TPHtmlSafe([string]$it['Id'])
            [void]$sb.AppendLine("<h2>$id — $(ConvertTo-TPHtmlSafe([string]$it['FamilyTitle']))</h2>")
            [void]$sb.AppendLine("<p>$(ConvertTo-TPHtmlSafe([string]$it['Question']))</p>")
            $curStatus = if ($it['CurrentStatus']) { [string]$it['CurrentStatus'] } else { '(not yet answered)' }
            [void]$sb.AppendLine("<p class=`"cur`">Current: $(ConvertTo-TPHtmlSafe($curStatus)) — confidence: $(ConvertTo-TPHtmlSafe([string]$it['Confidence']))</p>")
            [void]$sb.AppendLine('<label>Status</label><select>')
            foreach ($opt in $statusOptions) {
                $sel = if ($opt -and $opt -eq $it['CurrentStatus']) { ' selected' } else { '' }
                $label = if ($opt) { ConvertTo-TPHtmlSafe($opt) } else { '-- select --' }
                [void]$sb.AppendLine("<option$sel>$label</option>")
            }
            [void]$sb.AppendLine('</select>')
            [void]$sb.AppendLine("<label>Responsible role/owner</label><input type=`"text`" value=`"$(ConvertTo-TPHtmlSafe([string]$it['CurrentRole']))`">")
            [void]$sb.AppendLine("<label>Narrative (what exists, who owns it, what proves it, where the evidence lives)</label><textarea rows=`"3`">$(ConvertTo-TPHtmlSafe([string]$it['CurrentNarrative']))</textarea>")
            [void]$sb.AppendLine("<label>If Not applicable, why</label><input type=`"text`" value=`"$(ConvertTo-TPHtmlSafe([string]$it['CurrentNaReason']))`">")
            [void]$sb.AppendLine("<label>If Inherited, from whom</label><input type=`"text`" value=`"$(ConvertTo-TPHtmlSafe([string]$it['CurrentInheritedFrom']))`">")
            [void]$sb.AppendLine("<label>Gap (if not fully in place)</label><input type=`"text`" value=`"$(ConvertTo-TPHtmlSafe([string]$it['CurrentPoamWeakness']))`">")
            [void]$sb.AppendLine("<label>Remediation action</label><input type=`"text`" value=`"$(ConvertTo-TPHtmlSafe([string]$it['CurrentPoamRemedy']))`">")
            [void]$sb.AppendLine("<label>Remediation owner</label><input type=`"text`" value=`"$(ConvertTo-TPHtmlSafe([string]$it['CurrentPoamOwner']))`">")
            [void]$sb.AppendLine("<label>Target date</label><input type=`"text`" value=`"$(ConvertTo-TPHtmlSafe([string]$it['CurrentPoamDueDate']))`">")
        }
    }
    [void]$sb.AppendLine('</body></html>')
    [System.IO.File]::WriteAllText($htmlPath, $sb.ToString(), [System.Text.UTF8Encoding]::new($false))

    if (Get-Command Set-TPSensitiveFileAcl -ErrorAction SilentlyContinue) {
        Set-TPSensitiveFileAcl -Path $OutputPath -ErrorAction SilentlyContinue
        Set-TPSensitiveFileAcl -Path $htmlPath -ErrorAction SilentlyContinue
    }

    if ($items.Count -eq 0) { return }

    # ── PDF + manifest — best effort ─────────────────────────────────────────
    try {
        Publish-TPSSPQuestionnairePdf -Items $items -Title $title -Baseline $baseline `
            -GeneratedAt $generatedAt -OutputPath $OutputPath
    } catch {
        Write-Warning "SSP questionnaire PDF skipped: $($_.Exception.Message)"
    }
}

function Publish-TPSSPQuestionnairePdf {
    <#
        The fillable artifact. Manifest is written directly from PowerShell —
        it needs no Python round trip, only the PDF's AcroForm rendering does.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Items,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $Baseline,
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
        Write-Verbose 'reportlab not available — SSP questionnaire PDF skipped (Markdown and HTML were still written).'
        return
    }

    $pdfPath      = [System.IO.Path]::ChangeExtension($OutputPath, '.pdf')
    $manifestPath = [System.IO.Path]::ChangeExtension($OutputPath, '.manifest.json')
    $outDir  = Split-Path -Parent $OutputPath
    if (-not $outDir -or -not (Test-Path -LiteralPath $outDir)) { $outDir = [System.IO.Path]::GetTempPath() }
    $base    = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
    if ([string]::IsNullOrWhiteSpace($base)) { $base = 'ssp-questionnaire' }
    $tmpJson = Join-Path $outDir "$base-questionnaire-input.json"
    $pyTmp   = Join-Path $outDir "$base-questionnaire-helper.py"

    # Manifest: the ONLY place that maps a field's positional index back to a
    # requirement ID. Written before the PDF so a PDF-generation failure still
    # leaves a manifest an operator can see was attempted, and because the
    # payload fed to Python is built from the identical indexed list.
    $manifestItems = [System.Collections.Generic.List[object]]::new()
    $payloadItems  = [System.Collections.Generic.List[object]]::new()
    $idx = 0
    foreach ($it in $Items) {
        $idx++
        $manifestItems.Add([ordered]@{ Index = $idx; Id = [string]$it['Id']; Family = [string]$it['Family'] })
        $payloadItems.Add(@{
            Index = $idx
            Id = [string]$it['Id']
            FamilyTitle = [string]$it['FamilyTitle']
            Question = [string]$it['Question']
            Confidence = [string]$it['Confidence']
            CurrentStatus = [string]$it['CurrentStatus']
            CurrentNarrative = [string]$it['CurrentNarrative']
            CurrentRole = [string]$it['CurrentRole']
            CurrentNaReason = [string]$it['CurrentNaReason']
            CurrentInheritedFrom = [string]$it['CurrentInheritedFrom']
            CurrentPoamWeakness = [string]$it['CurrentPoamWeakness']
            CurrentPoamRemedy = [string]$it['CurrentPoamRemedy']
            CurrentPoamOwner = [string]$it['CurrentPoamOwner']
            CurrentPoamDueDate = [string]$it['CurrentPoamDueDate']
        })
    }

    $manifest = [ordered]@{
        GeneratedAt = $GeneratedAt
        Title       = $Title
        Baseline    = $Baseline
        ToolVersion = '4.12.1'
        Items       = $manifestItems.ToArray()
    }

    try {
        if (Get-Command Set-TPSensitiveFileContent -ErrorAction SilentlyContinue) {
            Set-TPSensitiveFileContent -Path $manifestPath -Content ($manifest | ConvertTo-Json -Depth 6)
        } else {
            $manifest | ConvertTo-Json -Depth 6 | Out-File -LiteralPath $manifestPath -Encoding utf8
        }

        $payload = @{ ClientName = $Title; GeneratedAt = $GeneratedAt; Baseline = $Baseline; Items = $payloadItems.ToArray() }
        if (Get-Command Set-TPSensitiveFileContent -ErrorAction SilentlyContinue) {
            Set-TPSensitiveFileContent -Path $tmpJson -Content ($payload | ConvertTo-Json -Depth 6 -Compress)
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

# A choice field crashes inside reportlab's pdfform module when given an
# empty default value (it only builds the /Opt appearance dict on the
# truthy-value branch — see reportlab/pdfbase/acroform.py _textfield). A
# real sentinel option, never '', is the workaround.
STATUS_OPTIONS = ['-- not answered --', 'Implemented', 'Partially implemented',
                   'Planned', 'Not implemented', 'Not applicable', 'Inherited']

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

header(d.get('ClientName', 'SSP Questionnaire'))
c.setFont('Helvetica', 9)
c.drawString(MARGIN, y, f"{d.get('Baseline','')} — generated {d.get('GeneratedAt','')}")
y -= 20
c.setFont('Helvetica', 8)
c.setFillColorRGB(0.4, 0.4, 0.4)
for line in wrap('Fill in every field you can. Leave Status unanswered rather than guessing '
                  '-- a blank is honest, a wrong answer becomes a false statement in a signed '
                  'compliance document. Name the actual evidence and where it lives in the '
                  'Narrative field.', 110):
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
    need(170)
    c.setFont('Helvetica-Bold', 11)
    c.drawString(MARGIN, y, f"Q{idx}. {it['Id']} — {it.get('FamilyTitle','')}")
    y -= 15
    c.setFont('Helvetica', 9)
    for line in wrap(it.get('Question', ''), 100):
        need(12)
        c.drawString(MARGIN, y, line)
        y -= 12
    y -= 3
    need(18)
    c.setFont('Helvetica', 8)
    c.setFillColorRGB(0.4, 0.4, 0.4)
    cur = it.get('CurrentStatus') or '(not yet answered)'
    c.drawString(MARGIN, y, f"Current: {cur} — confidence {it.get('Confidence','')}")
    c.setFillColorRGB(0, 0, 0)
    y -= 16

    status_val = it.get('CurrentStatus') or ''
    if status_val not in STATUS_OPTIONS:
        status_val = ''
    field_row('Status:', f'q{idx}_status', status_val, h=14, choice=STATUS_OPTIONS)
    field_row('Narrative (what/who/evidence/where it lives):', f'q{idx}_narrative',
              it.get('CurrentNarrative', ''), h=36, multiline=True)
    field_row('Responsible role/owner:', f'q{idx}_role', it.get('CurrentRole', ''), h=14)
    field_row('If Not applicable, why:', f'q{idx}_nareason', it.get('CurrentNaReason', ''), h=14)
    field_row('If Inherited, from whom:', f'q{idx}_inheritedfrom', it.get('CurrentInheritedFrom', ''), h=14)
    field_row('Gap (if not fully in place):', f'q{idx}_poamweakness', it.get('CurrentPoamWeakness', ''), h=14)
    field_row('Remediation action:', f'q{idx}_poamremedy', it.get('CurrentPoamRemedy', ''), h=14)
    field_row('Remediation owner:', f'q{idx}_poamowner', it.get('CurrentPoamOwner', ''), h=14)
    field_row('Target date:', f'q{idx}_poamdue', it.get('CurrentPoamDueDate', ''), h=14)
    need(16)
    c.setStrokeColorRGB(0.85, 0.85, 0.85)
    c.line(MARGIN, y, PAGE_W - MARGIN, y)
    y -= 14

c.save()
print('SSP questionnaire PDF saved:', sys.argv[2])
'@

        if (Get-Command Set-TPSensitiveFileContent -ErrorAction SilentlyContinue) {
            Set-TPSensitiveFileContent -Path $pyTmp -Content $pyScript
        } else {
            $pyScript | Out-File -LiteralPath $pyTmp -Encoding utf8
        }

        $out = & $pythonCmd $pyTmp $tmpJson $pdfPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "reportlab helper failed: $out"
        }
        if (Get-Command Set-TPSensitiveFileAcl -ErrorAction SilentlyContinue) {
            Set-TPSensitiveFileAcl -Path $pdfPath -ErrorAction SilentlyContinue
            Set-TPSensitiveFileAcl -Path $manifestPath -ErrorAction SilentlyContinue
        }
    } finally {
        foreach ($t in @($tmpJson, $pyTmp)) {
            if (Test-Path -LiteralPath $t) { Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue }
        }
    }
}
