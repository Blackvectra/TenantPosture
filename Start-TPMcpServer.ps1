#Requires -Version 7.0
<#
.SYNOPSIS
    Start-TPMcpServer.ps1 — TenantPosture
    NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: A local, read-only Model Context Protocol server over the tool's
             saved assessment results, so an AI assistant (Claude Code, Claude
             Desktop) can answer questions about past runs.

.DESCRIPTION
    Off by default: it runs only when the operator registers it with an AI
    client, which starts it as a child process and talks to it over standard
    input and output (JSON-RPC 2.0, one message per line).

    CONNECTS TO NOTHING: no sign-in, no Graph, no Exchange, no network of any
    kind, and it writes nothing to disk. It reads the results files under the
    output folder, addressed by (folder, id) through Resolve-TPWebRunPath, the
    same guard the web GUI uses; no tool argument is ever a path. Incident-
    response outputs (Email-IR mailbox folders, IR-Triage) are never served.

    Everything it returns goes to the AI provider behind the client, so by
    default every UPN, mailbox address and display name is replaced with a
    stable pseudonym (user-1, user-2, ...) for the life of the process.
    -IncludeIdentities turns that off. RawData, the Exceptions array, the
    tenant ID, the operator's account and file paths are never returned.
    docs/TP-MCP-SERVER.md describes the tools and the limits of the redaction.

    Data keys consumed: none live. Files: <OutputRoot>/*-results.json and
    <OutputRoot>/<folder>/*-results.json; Config/clients.json (run labels),
    controls.json, benchmark-mappings.json, operational-impact.json,
    tp-baseline.json.
    Graph scopes / cmdlets: none.

.PARAMETER OutputRoot
    The output folder to serve. Defaults to <script folder>\output, the folder
    the assessment and the web GUI write to.
.PARAMETER IncludeIdentities
    Return UPNs, mailbox addresses and display names as recorded instead of
    pseudonyms. Only when the operator accepts sending them to the AI provider.

.EXAMPLE
    claude mcp add tenantposture -- pwsh -NoProfile -File C:\Tools\TenantPosture\Start-TPMcpServer.ps1
#>
[CmdletBinding()]
param(
    [string] $OutputRoot = '',
    [switch] $IncludeIdentities
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$WarningPreference     = 'SilentlyContinue'
$InformationPreference = 'SilentlyContinue'
$VerbosePreference     = 'SilentlyContinue'

# Standard output carries protocol messages and nothing else. The raw stream is
# kept for the protocol writer, and the console's text writer is pointed at
# standard error, so anything else that prints (a module's host output, a
# stray value) cannot corrupt a message.
$utf8      = [System.Text.UTF8Encoding]::new($false)
$protocolOut = [System.IO.StreamWriter]::new([Console]::OpenStandardOutput(), $utf8)
$protocolOut.AutoFlush = $false
[Console]::SetOut([Console]::Error)
$protocolIn = [System.IO.StreamReader]::new([Console]::OpenStandardInput(), $utf8)

$scriptDir = $PSScriptRoot
if (-not $OutputRoot) { $OutputRoot = Join-Path $scriptDir 'output' }
$OutputRoot = [System.IO.Path]::GetFullPath($OutputRoot)

try {
    # The psm1, not the manifest: the manifest declares the Graph modules as
    # required and this server needs none of them.
    Import-Module (Join-Path $scriptDir 'TenantPosture.psm1') -Force -ErrorAction Stop 3>$null 4>$null 5>$null 6>$null
    # The web GUI's run index and path guard: the only place a tool argument
    # becomes a path. They are not exported by the module, so they are loaded
    # here, as the web server loads them into its route runspaces.
    . (Join-Path $scriptDir 'Lib' 'Test-TPDomainName.ps1')
    . (Join-Path $scriptDir 'Lib' 'Resolve-TPWebRunPath.ps1')
    . (Join-Path $scriptDir 'Lib' 'Get-TPWebRunIndex.ps1')
    . (Join-Path $scriptDir 'Mcp' 'Protect-TPMcpOutput.ps1')
    . (Join-Path $scriptDir 'Mcp' 'Read-TPMcpRun.ps1')
    . (Join-Path $scriptDir 'Mcp' 'Invoke-TPMcpTool.ps1')
    . (Join-Path $scriptDir 'Mcp' 'Invoke-TPMcpProtocol.ps1')
} catch {
    [Console]::Error.WriteLine("tenantposture-mcp: could not start: $($_.Exception.Message)")
    exit 4
}

$module = Get-Module TenantPosture
$ctx = @{
    OutputRoot        = $OutputRoot
    ClientsFile       = (Join-Path $scriptDir 'Config' 'clients.json')
    IncludeIdentities = [bool]$IncludeIdentities
    Pseudo            = $(if ($IncludeIdentities) { $null } else { New-TPMcpPseudonymMap })
    RunCache          = @{}
    SummaryCache      = @{}
    MetaCache         = [hashtable]::Synchronized(@{})
    Benchmarks        = $null
    StateRank         = (& $module { Get-TPStateSeverityRank })
    ToolVersion       = [string]$TPAssessmentVersion
    ProtocolVersion   = (Get-TPMcpSupportedVersions)[0]
    Initialized       = $false
}

[Console]::Error.WriteLine("tenantposture-mcp: serving $(if ($IncludeIdentities) { 'with identities' } else { 'with pseudonymized identities' }); read-only; waiting on standard input.")
try {
    Start-TPMcpLoop -Ctx $ctx -Reader $protocolIn -Writer $protocolOut
} finally {
    $protocolOut.Flush()
}
exit 0
