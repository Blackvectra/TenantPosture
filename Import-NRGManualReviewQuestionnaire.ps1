#Requires -Version 7.0
<#
.SYNOPSIS
    Reads a FILLED manual-review questionnaire PDF (from
    Publish-NRGManualReviewQuestionnaire) and turns the answers into a
    Config/manual-review/<client-slug>.psd1 answers file. Connects to
    nothing — no sign-in, no Graph, no EXO, no network.

.DESCRIPTION
    The controls.json counterpart to Import-NRGSSPQuestionnaire.ps1: a client
    fills in the AcroForm fields in the PDF Publish-NRGManualReviewQuestionnaire
    generated and emails it back; this script reads those field values (via
    an embedded Python + pypdf helper) and writes a real answers file.

    HONESTY GATES. A blank/unset Status is omitted for that control entirely
    — never coerced into a guessed status. 'Not applicable' with no reason,
    'Compensating control' with no description, and 'Risk accepted' with no
    named acceptance are each REJECTED for that one control (not the whole
    file) and reported as follow-up items, the same pattern
    Import-NRGSSPQuestionnaire.ps1 uses for its own two required-field
    statuses.

    NEVER OVERWRITES AN EXISTING ANSWERS FILE, for the same reason
    Import-NRGSSPQuestionnaire.ps1 doesn't: Import-PowerShellDataFile
    discards comments on parse. An existing file gets a separate paste-in
    snippet instead.

.PARAMETER PdfPath
    Path to the filled questionnaire PDF.

.PARAMETER ManifestPath
    Path to the companion manifest JSON. Defaults to the PDF's own path with
    .pdf replaced by .manifest.json.

.PARAMETER ClientName
    The client this answers file is for — resolved to
    Config/manual-review/<slug>.psd1 the same way Get-NRGManualReviewAnswers
    -ClientName does.

.EXAMPLE
    .\Import-NRGManualReviewQuestionnaire.ps1 -PdfPath .\output\example.com-manual-review-filled.pdf -ClientName example.com

.NOTES
    Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
    Exit codes: 0 success (including "nothing usable to import"), 1 bad
    input, 4 fatal error (Python/pypdf unavailable, PDF unreadable).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed in -PdfPath.' }
        if (-not (Test-Path -LiteralPath $_)) { throw "PDF not found: $_" }
        return $true
    })]
    [string] $PdfPath,

    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed in -ManifestPath.' }
        return $true
    })]
    [string] $ManifestPath,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string] $ClientName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$STATUS_VALUES = @('Fully implemented', 'Partially implemented', 'Not implemented', 'Not applicable', 'Not assessed', 'Compensating control', 'Risk accepted')

try {
    Import-Module (Join-Path $PSScriptRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

    if (-not $ManifestPath) {
        $dir  = Split-Path -Parent $PdfPath
        $base = [System.IO.Path]::GetFileNameWithoutExtension($PdfPath)
        $ManifestPath = if ($dir) { Join-Path $dir "$base.manifest.json" } else { "$base.manifest.json" }
    }
    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        throw "Manifest not found: $ManifestPath — it is written alongside the PDF by Publish-NRGManualReviewQuestionnaire and is required to map form fields back to control IDs."
    }

    $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    $indexToId = @{}
    foreach ($m in @(Get-NRGObjectField -Item $manifest -Key 'Items' -Default @())) {
        $i = [int](Get-NRGObjectField -Item $m -Key 'Index' -Default 0)
        $id = [string](Get-NRGObjectField -Item $m -Key 'ControlId' -Default '')
        if ($i -gt 0 -and $id) { $indexToId[$i] = $id }
    }
    if ($indexToId.Count -eq 0) {
        throw "Manifest at $ManifestPath names no items — nothing to import."
    }

    # ── Read the PDF's AcroForm field values via Python + pypdf ─────────────
    $pythonCmd = $null
    foreach ($py in @('python3', 'python')) {
        try {
            $null = & $py -c 'import pypdf' 2>&1
            if ($LASTEXITCODE -eq 0) { $pythonCmd = $py; break }
        } catch { }
    }
    if (-not $pythonCmd) {
        $prevEap = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        Write-Error "pypdf not available (tried python3/python). Install it with 'pip install pypdf' and re-run. Nothing was written."
        $ErrorActionPreference = $prevEap
        exit 4
    }

    $tmpOut = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "nrg-mrq-import-$([guid]::NewGuid().ToString('N')).json")
    $pyTmp  = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "nrg-mrq-import-$([guid]::NewGuid().ToString('N')).py")
    $fieldValues = $null
    try {
        $pyScript = @'
import json, sys
from pypdf import PdfReader

reader = PdfReader(sys.argv[1])
fields = reader.get_fields() or {}
out = {}
for name, f in fields.items():
    v = f.get('/V')
    out[name] = '' if v is None else str(v)
with open(sys.argv[2], 'w', encoding='utf-8') as fh:
    json.dump(out, fh)
'@
        $pyScript | Out-File -LiteralPath $pyTmp -Encoding utf8
        $out = & $pythonCmd $pyTmp $PdfPath $tmpOut 2>&1
        if ($LASTEXITCODE -ne 0) { throw "pypdf read failed: $out" }
        $fieldValues = Get-Content -LiteralPath $tmpOut -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    } finally {
        foreach ($t in @($tmpOut, $pyTmp)) {
            if (Test-Path -LiteralPath $t) { Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue }
        }
    }

    $fieldMap = @{}
    foreach ($p in $fieldValues.PSObject.Properties) { $fieldMap[$p.Name] = [string]$p.Value }

    # ── Build one answer per control, applying the honesty gates ────────────
    $accepted      = [ordered]@{}
    $needsFollowUp = [System.Collections.Generic.List[string]]::new()
    $unanswered    = 0

    foreach ($idx in ($indexToId.Keys | Sort-Object)) {
        $cid = $indexToId[$idx]
        $get = { param($suffix) if ($fieldMap.ContainsKey("q${idx}_$suffix")) { $fieldMap["q${idx}_$suffix"].Trim() } else { '' } }

        $status = & $get 'status'
        if ($status -eq '-- not answered --') { $status = '' }
        $evidence    = & $get 'evidence'
        $owner       = & $get 'owner'
        $naReason    = & $get 'nareason'
        $compensating = & $get 'compensating'
        $riskAccept  = & $get 'riskaccept'
        $poamWeak    = & $get 'poamweakness'
        $poamRemedy  = & $get 'poamremedy'
        $poamOwner   = & $get 'poamowner'
        $poamDue     = & $get 'poamdue'

        if (-not $status) {
            if ($evidence -or $poamWeak -or $poamRemedy) {
                $ans = [ordered]@{}
                if ($evidence) { $ans['Evidence'] = $evidence }
                if ($owner) { $ans['Owner'] = $owner }
                if ($poamWeak -or $poamRemedy -or $poamOwner -or $poamDue) {
                    $ans['Poam'] = [ordered]@{ Weakness = $poamWeak; Remedy = $poamRemedy; Owner = $poamOwner; DueDate = $poamDue }
                }
                $accepted[$cid] = $ans
            } else {
                $unanswered++
            }
            continue
        }

        if ($status -notin $STATUS_VALUES) {
            $needsFollowUp.Add("$cid — Status field contains an unrecognized value ('$status'); left unanswered rather than guessed. Valid values: $($STATUS_VALUES -join ', ').")
            continue
        }
        if ($status -eq 'Not applicable' -and -not $naReason) {
            $needsFollowUp.Add("$cid — Status is 'Not applicable' but no reason was given. Ask the client why, then re-submit.")
            continue
        }
        if ($status -eq 'Compensating control' -and -not $compensating) {
            $needsFollowUp.Add("$cid — Status is 'Compensating control' but nothing describes it. Ask the client what the alternative control is, then re-submit.")
            continue
        }
        if ($status -eq 'Risk accepted' -and -not $riskAccept) {
            $needsFollowUp.Add("$cid — Status is 'Risk accepted' but no accepting owner/expiration was given. A risk acceptance with no named owner is not a decision anyone made — ask the client, then re-submit.")
            continue
        }

        $ans = [ordered]@{ Status = $status }
        if ($owner) { $ans['Owner'] = $owner }
        if ($evidence) { $ans['Evidence'] = $evidence }
        if ($status -eq 'Not applicable') { $ans['NotApplicableReason'] = $naReason }
        if ($status -eq 'Compensating control') { $ans['CompensatingControl'] = $compensating }
        if ($status -eq 'Risk accepted') { $ans['RiskAcceptance'] = $riskAccept }
        if ($poamWeak -or $poamRemedy -or $poamOwner -or $poamDue) {
            $ans['Poam'] = [ordered]@{ Weakness = $poamWeak; Remedy = $poamRemedy; Owner = $poamOwner; DueDate = $poamDue }
        }
        $accepted[$cid] = $ans
    }

    if ($accepted.Count -eq 0) {
        Write-Host ''
        Write-Host "  [!] Nothing usable to import — $unanswered control(s) left blank, $($needsFollowUp.Count) rejected pending follow-up." -ForegroundColor Yellow
        foreach ($n in $needsFollowUp) { Write-Host "      - $n" -ForegroundColor Yellow }
        exit 0
    }

    # ── Resolve the target file ──────────────────────────────────────────────
    $slug = ConvertTo-NRGSSPClientSlug -ClientName $ClientName
    if (-not $slug) { throw "-ClientName '$ClientName' slugs to an empty string — cannot resolve an answers file." }
    $mrDir = Join-Path $PSScriptRoot 'Config' 'manual-review'
    if (-not (Test-Path -LiteralPath $mrDir)) { $null = [System.IO.Directory]::CreateDirectory($mrDir) }
    $targetPath = Join-Path $mrDir "$slug.psd1"

    $entries = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $accepted.Keys) {
        $entries.Add((ConvertTo-NRGManualReviewAnswerPsd1 -ControlId $id -Answer $accepted[$id] -Indent 2))
    }
    $entriesText = ($entries -join "`n`n")

    Write-Host ''
    if (-not (Test-Path -LiteralPath $targetPath)) {
        $header = @"
# Manual-review answers — $ClientName
#
# Created by Import-NRGManualReviewQuestionnaire.ps1 from a filled
# questionnaire on $(Get-Date -Format 'yyyy-MM-dd'). Read with
# Import-PowerShellDataFile: data only, never executed. See
# Config/ssp/example.psd1 for the STATUS VALUES pattern this file follows
# (Not applicable requires NotApplicableReason; Compensating control
# requires CompensatingControl; Risk accepted requires RiskAcceptance).
#
# A Status set here is the client's attestation for a control this tool
# could not verify itself, not something the assessment confirmed.

@{

    Controls = @{

$entriesText

    }
}
"@
        [System.IO.File]::WriteAllText($targetPath, $header, [System.Text.UTF8Encoding]::new($false))
        Write-Host "  [+] Created $targetPath with $($accepted.Count) answered control(s)." -ForegroundColor Green
    } else {
        $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
        $snippetPath = "$targetPath.import-$stamp.psd1.txt"
        $snippetHeader = @"
# $($accepted.Count) control answer(s) imported from $PdfPath on $(Get-Date -Format 'yyyy-MM-dd').
#
# $targetPath already exists and was NOT modified — re-serializing it would
# discard its hand-written comments. Paste the block(s) below inside the
# EXISTING file's `Controls = @{ ... }` block, replacing any prior entry
# for the same control id.

$entriesText
"@
        [System.IO.File]::WriteAllText($snippetPath, $snippetHeader, [System.Text.UTF8Encoding]::new($false))
        Write-Host "  [+] $targetPath already exists — wrote $($accepted.Count) answer(s) to:" -ForegroundColor Green
        Write-Host "      $snippetPath" -ForegroundColor Green
        Write-Host "      Paste its contents into the existing file's Controls block by hand." -ForegroundColor Yellow
    }

    if ($unanswered -gt 0) {
        Write-Host "  [i] $unanswered control(s) were left blank on the form — no change made for those." -ForegroundColor DarkGray
    }
    if ($needsFollowUp.Count -gt 0) {
        Write-Host ''
        Write-Host "  [!] $($needsFollowUp.Count) control(s) need follow-up before they can be recorded:" -ForegroundColor Yellow
        foreach ($n in $needsFollowUp) { Write-Host "      - $n" -ForegroundColor Yellow }
    }
    Write-Host ''
    exit 0

} catch {
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    Write-Error "Manual-review questionnaire import failed: $($_.Exception.Message)"
    $ErrorActionPreference = $prevEap
    exit 4
}
