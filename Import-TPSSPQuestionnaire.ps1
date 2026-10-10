#Requires -Version 7.0
<#
.SYNOPSIS
    Reads a FILLED SSP questionnaire PDF (from Publish-TPSSPQuestionnaire)
    and turns the answers into a Config/ssp/<client-slug>.psd1 answers file.
    Connects to nothing — no sign-in, no Graph, no EXO, no network.

.DESCRIPTION
    This is the round trip half of the questionnaire feature: a client fills
    in the AcroForm fields in the PDF Publish-TPSSPQuestionnaire generated
    and emails it back; this script reads those field values (via an
    embedded Python + pypdf helper) and writes a real answers file
    Get-TPSSPAnswers/Get-TPSSPPosture will pick up on the next run.

    HONESTY GATES, NOT A DUMB FIELD COPY. A blank/unset Status field is
    omitted for that requirement entirely — never coerced into a guessed
    status. 'Not applicable' with no reason, or 'Inherited' with no named
    provider, is REJECTED for that one requirement (not the whole file):
    those two statuses each require a specific justification per
    Config/ssp/example.psd1's own documented rules, and accepting one
    without it would write an unenforceable claim into a document a client
    signs. Rejected requirements are listed at the end as "needs follow-up",
    never silently dropped without a trace.

    NEVER OVERWRITES AN EXISTING ANSWERS FILE. Import-PowerShellDataFile
    parses a .psd1 but discards every comment doing it, and the existing
    Config/ssp/*.psd1 convention is full of hand-written explanation. Fully
    re-serializing an existing file would delete that. So:
      - No answers file exists yet for this client -> this script WRITES ONE,
        with the same explanatory header Config/ssp/example.psd1 carries.
      - An answers file already exists -> this script writes a SEPARATE
        "*.import-<timestamp>.psd1.txt" snippet containing only the answered
        requirements' hashtable entries, ready to paste inside the existing
        file's `Requirements = @{ ... }` block, and says so on the console.
        It never touches the existing file.

.PARAMETER PdfPath
    Path to the filled questionnaire PDF.

.PARAMETER ManifestPath
    Path to the companion manifest JSON Publish-TPSSPQuestionnaire wrote
    alongside the PDF. Defaults to the PDF's own path with .pdf replaced by
    .manifest.json.

.PARAMETER ClientName
    The client this answers file is for — resolved to Config/ssp/<slug>.psd1
    the same way Get-TPSSPAnswers -ClientName does (via
    ConvertTo-TPSSPClientSlug), so the file this writes is the one the next
    assessment run actually reads.

.EXAMPLE
    .\Import-TPSSPQuestionnaire.ps1 -PdfPath .\output\example.com-ssp-questionnaire-filled.pdf -ClientName example.com

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

$STATUS_VALUES = @('Implemented', 'Partially implemented', 'Planned', 'Not implemented', 'Not applicable', 'Inherited')

try {
    Import-Module (Join-Path $PSScriptRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

    if (-not $ManifestPath) {
        $dir  = Split-Path -Parent $PdfPath
        $base = [System.IO.Path]::GetFileNameWithoutExtension($PdfPath)
        $ManifestPath = if ($dir) { Join-Path $dir "$base.manifest.json" } else { "$base.manifest.json" }
    }
    if (-not (Test-Path -LiteralPath $ManifestPath)) {
        throw "Manifest not found: $ManifestPath — it is written alongside the PDF by Publish-TPSSPQuestionnaire and is required to map form fields back to requirement IDs."
    }

    $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    $indexToId = @{}
    foreach ($m in @(Get-TPObjectField -Item $manifest -Key 'Items' -Default @())) {
        $i = [int](Get-TPObjectField -Item $m -Key 'Index' -Default 0)
        $id = [string](Get-TPObjectField -Item $m -Key 'Id' -Default '')
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
        Write-Error "pypdf not available (tried python3/python). Install it with 'pip install pypdf' and re-run. Nothing was written."
        exit 4
    }

    $tmpOut = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "tp-ssp-import-$([guid]::NewGuid().ToString('N')).json")
    $pyTmp  = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "tp-ssp-import-$([guid]::NewGuid().ToString('N')).py")
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

    # ── Build one answer per requirement, applying the honesty gates ────────
    $accepted     = [ordered]@{}
    $needsFollowUp = [System.Collections.Generic.List[string]]::new()
    $unanswered   = 0

    foreach ($idx in ($indexToId.Keys | Sort-Object)) {
        $reqId = $indexToId[$idx]
        $get = { param($suffix) if ($fieldMap.ContainsKey("q${idx}_$suffix")) { $fieldMap["q${idx}_$suffix"].Trim() } else { '' } }

        $status = & $get 'status'
        if ($status -eq '-- not answered --') { $status = '' }
        $narrative  = & $get 'narrative'
        $role       = & $get 'role'
        $naReason   = & $get 'nareason'
        $inheritedFrom = & $get 'inheritedfrom'
        $poamWeak   = & $get 'poamweakness'
        $poamRemedy = & $get 'poamremedy'
        $poamOwner  = & $get 'poamowner'
        $poamDue    = & $get 'poamdue'

        if (-not $status) {
            # No status supplied for this requirement. Other fields (a
            # narrative note with no status set) are still worth capturing
            # rather than discarding, but never as a Status claim.
            if ($narrative -or $poamWeak -or $poamRemedy) {
                $ans = [ordered]@{}
                if ($narrative) { $ans['Narrative'] = $narrative }
                if ($role) { $ans['ResponsibleRole'] = $role }
                if ($poamWeak -or $poamRemedy -or $poamOwner -or $poamDue) {
                    $ans['Poam'] = [ordered]@{ Weakness = $poamWeak; Remedy = $poamRemedy; Owner = $poamOwner; DueDate = $poamDue }
                }
                $accepted[$reqId] = $ans
            } else {
                $unanswered++
            }
            continue
        }

        if ($status -notin $STATUS_VALUES) {
            $needsFollowUp.Add("$reqId — Status field contains an unrecognized value ('$status'); left unanswered rather than guessed. Valid values: $($STATUS_VALUES -join ', ').")
            continue
        }
        if ($status -eq 'Not applicable' -and -not $naReason) {
            $needsFollowUp.Add("$reqId — Status is 'Not applicable' but no reason was given. Not applicable REQUIRES a reason (Config/ssp/example.psd1's own rule) — ask the client why, then re-submit.")
            continue
        }
        if ($status -eq 'Inherited' -and -not $inheritedFrom) {
            $needsFollowUp.Add("$reqId — Status is 'Inherited' but no provider was named. Inherited REQUIRES naming who satisfies it — ask the client, then re-submit.")
            continue
        }

        $ans = [ordered]@{ Status = $status }
        if ($role) { $ans['ResponsibleRole'] = $role }
        if ($narrative) { $ans['Narrative'] = $narrative }
        if ($status -eq 'Not applicable') { $ans['NotApplicableReason'] = $naReason }
        if ($status -eq 'Inherited') { $ans['InheritedFrom'] = $inheritedFrom }
        if ($poamWeak -or $poamRemedy -or $poamOwner -or $poamDue) {
            $ans['Poam'] = [ordered]@{ Weakness = $poamWeak; Remedy = $poamRemedy; Owner = $poamOwner; DueDate = $poamDue }
        }
        $accepted[$reqId] = $ans
    }

    if ($accepted.Count -eq 0) {
        Write-Host ''
        Write-Host "  [!] Nothing usable to import — $unanswered requirement(s) left blank, $($needsFollowUp.Count) rejected pending follow-up." -ForegroundColor Yellow
        foreach ($n in $needsFollowUp) { Write-Host "      - $n" -ForegroundColor Yellow }
        exit 0
    }

    # ── Resolve the target file ──────────────────────────────────────────────
    $slug = ConvertTo-TPSSPClientSlug -ClientName $ClientName
    if (-not $slug) { throw "-ClientName '$ClientName' slugs to an empty string — cannot resolve an answers file." }
    $sspDir = Join-Path $PSScriptRoot 'Config' 'ssp'
    if (-not (Test-Path -LiteralPath $sspDir)) { $null = [System.IO.Directory]::CreateDirectory($sspDir) }
    $targetPath = Join-Path $sspDir "$slug.psd1"

    $entries = [System.Collections.Generic.List[string]]::new()
    foreach ($id in $accepted.Keys) {
        $entries.Add((ConvertTo-TPSSPAnswerPsd1 -Id $id -Answer $accepted[$id] -Indent 2))
    }
    $entriesText = ($entries -join "`n`n")
    # Re-read before writing: a curly quote or stray character in a client answer
    # must not produce a file that drops every answer or carries an entry nobody wrote.
    $null = Test-TPPsd1EntriesRoundTrip -EntriesText $entriesText -Block 'Requirements' -ExpectedIds @($accepted.Keys)

    Write-Host ''
    if (-not (Test-Path -LiteralPath $targetPath)) {
        $header = @"
# SSP answers — $ClientName
#
# Created by Import-TPSSPQuestionnaire.ps1 from a filled questionnaire on
# $(Get-Date -Format 'yyyy-MM-dd'). Read with Import-PowerShellDataFile: data
# only, never executed. See Config/ssp/example.psd1 for the full field
# reference and the STATUS VALUES rules (Not applicable requires
# NotApplicableReason; Inherited requires InheritedFrom).
#
# A Status set here OVERRIDES what the assessment derived, and is stamped as
# client-attested wherever it renders. It never counts as tool-verified.

@{

    System = @{
        Name = $((ConvertTo-TPSSPPsd1String -Value $ClientName))
    }

    Inherited = @{}

    Requirements = @{

$entriesText

    }
}
"@
        [System.IO.File]::WriteAllText($targetPath, $header, [System.Text.UTF8Encoding]::new($false))
        Write-Host "  [+] Created $targetPath with $($accepted.Count) answered requirement(s)." -ForegroundColor Green
    } else {
        $stamp = (Get-Date).ToUniversalTime().ToString('yyyyMMddHHmmss')
        $snippetPath = "$targetPath.import-$stamp.psd1.txt"
        $snippetHeader = @"
# $($accepted.Count) requirement answer(s) imported from $PdfPath on $(Get-Date -Format 'yyyy-MM-dd').
#
# $targetPath already exists and was NOT modified — re-serializing it would
# discard its hand-written comments (Import-PowerShellDataFile parses data
# only and drops them). Paste the block(s) below inside the EXISTING file's
# `Requirements = @{ ... }` block, replacing any prior entry for the same
# requirement id.

$entriesText
"@
        [System.IO.File]::WriteAllText($snippetPath, $snippetHeader, [System.Text.UTF8Encoding]::new($false))
        Write-Host "  [+] $targetPath already exists — wrote $($accepted.Count) answer(s) to:" -ForegroundColor Green
        Write-Host "      $snippetPath" -ForegroundColor Green
        Write-Host "      Paste its contents into the existing file's Requirements block by hand." -ForegroundColor Yellow
    }

    if ($unanswered -gt 0) {
        Write-Host "  [i] $unanswered requirement(s) were left blank on the form — no change made for those." -ForegroundColor DarkGray
    }
    if ($needsFollowUp.Count -gt 0) {
        Write-Host ''
        Write-Host "  [!] $($needsFollowUp.Count) requirement(s) need follow-up before they can be recorded:" -ForegroundColor Yellow
        foreach ($n in $needsFollowUp) { Write-Host "      - $n" -ForegroundColor Yellow }
    }
    Write-Host ''
    exit 0

} catch {
    # Write-Error under $ErrorActionPreference = 'Stop' (set above) escalates
    # to a terminating error and would abort BEFORE the `exit 4` below ever
    # runs, exiting with PowerShell's default unhandled-error code (1)
    # instead of this script's documented one. Scope 'Continue' to just this
    # one call so the intended exit code is actually reached.
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    Write-Error "SSP questionnaire import failed: $($_.Exception.Message)"
    $ErrorActionPreference = $prevEap
    exit 4
}
