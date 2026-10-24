#Requires -Version 7.0
<#
.SYNOPSIS
    Builds a small, data-only output folder for a dynamic scan of the -Web GUI.

.DESCRIPTION
    The DAST job (.github/workflows/dast.yml) starts Lib/Start-TPWebServer.ps1
    against this folder and points OWASP ZAP at it, so every route has something
    to serve: a flat command-line run with its report and report site, a
    GUI-layout run under a tenant folder, and a clients.json the run index joins
    labels to. Nothing here is tenant data; the HTML carries the shapes the real
    publishers emit (an inline <style>, a logo <img>, a CSV with a byte-order
    mark) so the scanner sees the headers and policies the real pages get.

    It connects to nothing and writes only under -Path.

    TenantPosture — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Data: writes <Path>/output and <Path>/Config/clients.json. No network.

.PARAMETER Path
    The work folder. Created if absent; existing files are overwritten.

.OUTPUTS
    The output folder path (what Start-TPWebServer -OutputRoot takes).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$out = Join-Path $Path 'output'
$put = {
    param([string] $File, [string] $Value)
    $null = New-Item -ItemType Directory -Path (Split-Path -Parent $File) -Force
    Set-Content -LiteralPath $File -Value $Value -Encoding utf8
}

# A report page as Publish-TPAssessmentHTML shapes it: self-contained, an inline
# stylesheet, the recorded logo, a findings table. The scanner's content checks
# run against this, so it should look like a page, not a marker.
$report = @'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TenantPosture assessment: scan-tenant.onmicrosoft.com</title>
<style>
  body { font-family: system-ui, sans-serif; margin: 2rem; color: #1a1a1a; }
  table { border-collapse: collapse; } td, th { border: 1px solid #ccc; padding: .3rem .6rem; }
  .gap { color: #b00020; } .ok { color: #1b5e20; }
</style>
</head>
<body>
<header><img src="https://cdn.example/logo.png" alt="logo" width="120"> <h1>Security assessment</h1></header>
<p>Tenant scan-tenant.onmicrosoft.com, assessed 2026-10-16. Score 71%.</p>
<table>
<tr><th>Control</th><th>State</th><th>Detail</th></tr>
<tr><td>AAD-1.1</td><td class="ok">Satisfied</td><td>Legacy authentication is blocked for all users.</td></tr>
<tr><td>AAD-6.2</td><td class="gap">Gap</td><td>Users can consent to any app permission.</td></tr>
</table>
</body>
</html>
'@

$site = @'
<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>{0}</title>
<style>body {{ font-family: system-ui, sans-serif; margin: 2rem; }} nav a {{ margin-right: 1rem; }}</style>
</head>
<body>
<nav><a href="index.html">Overview</a> <a href="AAD.html">Identity</a> <a href="ActionPlan.csv">Action plan</a></nav>
<h1>{0}</h1>
<p>{1}</p>
</body>
</html>
'@

# Flat command-line run: results JSON (Metadata records the INITIAL domain, as
# Connect-TPServices does), the report, and the report site beside it.
$id = 'SCANTENANT-20261016-110000'
& $put (Join-Path $out "$id-results.json") (@{
    Metadata = [ordered]@{
        TenantDomain = 'scan-tenant.onmicrosoft.com'
        TenantId     = '11111111-2222-3333-4444-555555555555'
        ToolVersion  = '4.14.3'
        Brand        = @{ LogoUrl = 'https://cdn.example/logo.png' }
    }
    RawData  = @{}
    Findings = @()
} | ConvertTo-Json -Depth 5)
& $put (Join-Path $out "$id-assessment.html") $report
$siteDir = Join-Path $out "$id-report"
& $put (Join-Path $siteDir 'index.html') ($site -f 'Overview', 'Two of four scored controls are satisfied.')
& $put (Join-Path $siteDir 'AAD.html')   ($site -f 'Identity', 'AAD-6.2 is a gap: users can consent to any app permission.')
# The action plan is written with a UTF-8 byte-order mark for Excel; the route
# must send it as bytes, so the fixture carries the mark and non-ASCII text.
[System.IO.File]::WriteAllLines((Join-Path $siteDir 'ActionPlan.csv'),
    @('Control,State,Owner', "AAD-6.2,Gap,Jos$([char]0xE9) M$([char]0xFC)ller"),
    [System.Text.UTF8Encoding]::new($true))

# A GUI-layout run under the client's own domain folder.
$gui = 'CONTOSO-20261016-100000'
& $put (Join-Path $out 'contoso.example' "$gui-results.json") '{"Metadata":{"TenantDomain":"contoso.onmicrosoft.com","ToolVersion":"4.14.3"},"RawData":{},"Findings":[]}'
& $put (Join-Path $out 'contoso.example' "$gui-assessment.html") $report

# The client registry the run index joins labels to (by tenant id, then routing domain).
& $put (Join-Path $Path 'Config' 'clients.json') (@{ clients = @(
    [ordered]@{ ClientName = 'Scan Tenant'; TenantDomain = 'scan-tenant.example'; TenantId = '11111111-2222-3333-4444-555555555555'; DelegatedOrg = 'scan-tenant.onmicrosoft.com'; DnsDomains = @('scan-tenant.example'); Active = $true }
    [ordered]@{ ClientName = 'Contoso';     TenantDomain = 'contoso.example';     TenantId = '';                                      DelegatedOrg = 'contoso.onmicrosoft.com';     DnsDomains = @('contoso.example');     Active = $true }
) } | ConvertTo-Json -Depth 4)

Write-Output $out
