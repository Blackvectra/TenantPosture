#Requires -Version 7.0
<#
.SYNOPSIS
    Generates the NIST SP 800-53 Rev 5 device and endpoint guide. Reference
    material — connects to nothing.

.DESCRIPTION
    This script does not sign in, does not query Microsoft Graph, does not read
    Exchange Online, and does not touch a single endpoint. It renders
    Config/nist-physical.json into a printable guide covering what 800-53
    expects of devices, with the practical options for satisfying each control.

    That independence is the point. The guide is usable before a tenant is
    connected, during a sales conversation, and on a site with nothing open.

    Output is a Markdown file and a self-contained HTML file with no external
    assets, so it opens offline and prints cleanly.

.PARAMETER OutputPath
    Where to write the guide. Defaults to .\output\nist-device-guide.md, with
    the HTML written alongside it.

.PARAMETER ClientName
    Optional. Titles the document for a specific client.

.PARAMETER ResultsPath
    Optional path to a prior assessment's -results.json. When supplied, the
    controls that assessment already evidences are annotated with their verdict,
    so the same guide doubles as a gap list. The RECOMMENDATIONS never change
    based on this — only what is reported as already done.

.EXAMPLE
    .\New-NRGDeviceGuide.ps1
    Writes .\output\nist-device-guide.md and .html.

.EXAMPLE
    .\New-NRGDeviceGuide.ps1 -ClientName 'Example Client' -OutputPath .\out\guide.md

.EXAMPLE
    .\New-NRGDeviceGuide.ps1 -ResultsPath .\output\client\20260825-results.json
    Same guide, with the tenant-evidenced controls annotated.

.NOTES
    Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
    Exit codes: 0 success, 4 fatal error.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        return $true
    })]
    [string] $OutputPath,

    [Parameter(Mandatory = $false)]
    [ValidateLength(0, 120)]
    [string] $ClientName,

    [Parameter(Mandatory = $false)]
    [ValidateScript({
        if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
        if (-not (Test-Path -LiteralPath $_)) { throw "Results file not found: $_" }
        return $true
    })]
    [string] $ResultsPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

try {
    Import-Module (Join-Path $PSScriptRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

    if (-not $OutputPath) {
        $outDir = Join-Path $PSScriptRoot 'output'
        if (-not (Test-Path -LiteralPath $outDir)) {
            # [IO.Directory]::CreateDirectory, not New-Item -Path: New-Item has no
            # -LiteralPath overload at all, and its -Path DOES interpret wildcards,
            # so a directory name containing [ or ] fails outright. The .NET call
            # takes the string literally and is idempotent.
            $null = [System.IO.Directory]::CreateDirectory($outDir)
        }
        $OutputPath = Join-Path $outDir 'nist-device-guide.md'
    } else {
        $outDir = Split-Path -Parent $OutputPath
        if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
            # [IO.Directory]::CreateDirectory, not New-Item -Path: New-Item has no
            # -LiteralPath overload at all, and its -Path DOES interpret wildcards,
            # so a directory name containing [ or ] fails outright. The .NET call
            # takes the string literally and is idempotent.
            $null = [System.IO.Directory]::CreateDirectory($outDir)
        }
    }

    # Optional annotation from a prior run. Read-only, and a malformed or
    # unreadable file degrades to "no annotations" rather than failing the
    # guide — the guide's value does not depend on it.
    $findings = @()
    if ($ResultsPath) {
        try {
            $results  = Get-Content -LiteralPath $ResultsPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
            $findings = @(Get-NRGObjectField -Item $results -Key 'Findings' -Default @())
            Write-Host "  [i] Annotating with $($findings.Count) findings from $ResultsPath" -ForegroundColor Cyan
        } catch {
            Write-Warning "Could not read findings from $ResultsPath — generating the guide without annotations: $($_.Exception.Message)"
            $findings = @()
        }
    }

    Publish-NRGDeviceGuide -OutputPath $OutputPath -Findings $findings -ClientName $ClientName

    $htmlPath = [System.IO.Path]::ChangeExtension($OutputPath, '.html')
    Write-Host ''
    Write-Host '  NIST SP 800-53 device and endpoint guide' -ForegroundColor Green
    Write-Host "  [+] Markdown: $OutputPath" -ForegroundColor Green
    if (Test-Path -LiteralPath $htmlPath) {
        Write-Host "  [+] HTML:     $htmlPath" -ForegroundColor Green
    }
    Write-Host '  Reference material only — this script connected to nothing.' -ForegroundColor DarkGray
    Write-Host ''
    exit 0

} catch {
    Write-Error "Device guide generation failed: $($_.Exception.Message)"
    exit 4
}
