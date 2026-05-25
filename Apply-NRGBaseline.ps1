#Requires -Version 7.0
#
# Apply-NRGBaseline.ps1  (v4.6.1)
# Interactive WRITE-MODE deployment tool for NRG-Assessment remediations.
#
# NRG Technology Services | NextLayerSec LLC
# Author: Matthew Levorson
#
# ============================================================================
# WARNING: THIS TOOL MODIFIES TENANT CONFIGURATION.
# ============================================================================
# Unlike Invoke-NRGAssessment (read-only) and Publish-NRGRemediationScript
# (generates a static .ps1 deliverable), this tool ACTUALLY APPLIES changes
# to a live production Microsoft 365 tenant.
#
# Safety bars:
#   * SupportsShouldProcess + ConfirmImpact='High' (free -WhatIf / -Confirm)
#   * Per-control idempotency re-read (no write if already compliant)
#   * Rollback log written for every applied change (before-state captured)
#   * Auth gate — refuses to run if required service is not connected
#   * Filters input findings to State = Gap / Partial only
#
# Apply functions are top-level script functions, NOT module exports — they are
# dot-sourced from Apply/Apply-NRG*.ps1 at script start. This matches the
# Invoke-NRGAssessment.ps1 convention (also a top-level orchestrator script).
#
# Usage:
#   .\Apply-NRGBaseline.ps1 -ResultsPath .\output\contoso-20260524-results.json -WhatIf
#   .\Apply-NRGBaseline.ps1 -ResultsPath .\output\contoso-20260524-results.json -ControlIds 'EXO-1.1','EXO-1.2'
#   .\Apply-NRGBaseline.ps1 -ResultsPath .\output\contoso-20260524-results.json -Force
#

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'FromFile')]
param(
    # Not Mandatory — the block below auto-detects the newest results JSON
    # under .\output\ when -ResultsPath is omitted. The empty-prompt UX in
    # v4.6.1 ("ResultsPath:" with no hint) led operators to type "Downloads"
    # and crash. HelpMessage gives PowerShell's prompt useful context if the
    # auto-detect path fails (no files in .\output\).
    [Parameter(Mandatory = $false, ParameterSetName = 'FromFile',
        HelpMessage = 'Path to results.json from a prior Invoke-NRGAssessment run. Defaults to the newest match in ./output/.')]
    [string] $ResultsPath,

    [Parameter(Mandatory, ParameterSetName = 'FromObjects')]
    [object[]] $Findings,

    # Scope: apply only these control IDs. Default = all v1-supported controls
    # with State Gap or Partial in the input.
    [string[]] $ControlIds,

    # Override default Reports/ output directory
    [string] $ReportsPath,

    # Skip per-control confirmation prompts (still logs everything).
    # ShouldProcess still fires for -WhatIf.
    [switch] $Force,

    # Alias for -WhatIf with verbose markdown preview output.
    [switch] $DryRun
)

# OWASP ASVS V16.4.1 — strict mode at the entry point. Write-mode tool runs
# the same hardening as the assessor — property access on $null, uninitialized
# variables, and indexing past array end all throw rather than silently coerce
# to $null and produce a wrong remediation.
Set-StrictMode -Version Latest

# OWASP ASVS V11.2.2 — TLS 1.2 minimum
[System.Net.ServicePointManager]::SecurityProtocol =
    [System.Net.SecurityProtocolType]::Tls12 -bor
    [System.Net.SecurityProtocolType]::Tls13

$env:MSAL_ALLOW_BROKER        = '0'
$env:MSAL_DISABLE_TOKENBROKER = '1'
$env:MSAL_DISABLE_WAM         = '1'

$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

# ── DryRun forces WhatIf ─────────────────────────────────────────────────────
if ($DryRun -and -not $WhatIfPreference) {
    $WhatIfPreference = $true
}

# ── Pre-banner version probe ────────────────────────────────────────────────
# Same pattern as Invoke-NRGAssessment.ps1 — read ModuleVersion from the
# manifest so the banner can't drift from the .psd1 / .psm1 single source.
$applyVersion = 'unknown'
try {
    $manifestData = Import-PowerShellDataFile -LiteralPath (Join-Path $scriptDir 'NRG-Assessment.psd1') -ErrorAction Stop
    if ($manifestData.ModuleVersion) { $applyVersion = [string]$manifestData.ModuleVersion }
} catch { }

# ── Banner ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================" -ForegroundColor Red
Write-Host " NRG-Assessment v$applyVersion — Apply-NRGBaseline (WRITE MODE)" -ForegroundColor Red
Write-Host " NRG Technology Services | NextLayerSec LLC"                   -ForegroundColor Red
Write-Host "================================================================" -ForegroundColor Red
if ($WhatIfPreference) {
    Write-Host " MODE: WhatIf / DryRun — NO changes will be made"          -ForegroundColor Yellow
} elseif ($Force) {
    Write-Host " MODE: Force — prompts skipped, changes WILL be applied"   -ForegroundColor Yellow
} else {
    Write-Host " MODE: Interactive — each change requires confirmation"    -ForegroundColor Yellow
}
Write-Host ""

# ── Dot-source the shared Lib helpers we need (ACL hardening) ───────────────
# Apply-NRGBaseline is a top-level orchestrator and does not Import-Module
# NRG-Assessment, so any Lib helper it depends on must be dot-sourced here.
# Set-NRGSensitiveFileAcl is required to harden the rollback log + results
# files (tenant inventory + change history — same sensitivity tier as the
# assessor baseline JSON).
$aclHelperPath = Join-Path $scriptDir 'Lib' 'Set-NRGSensitiveFileAcl.ps1'
if (Test-Path -LiteralPath $aclHelperPath) {
    . $aclHelperPath
} else {
    Write-Warning "Set-NRGSensitiveFileAcl.ps1 not found at $aclHelperPath — output files will not be ACL-hardened."
}

# ── Dot-source the Apply functions ──────────────────────────────────────────
$applyDir = Join-Path $scriptDir 'Apply'
if (-not (Test-Path -LiteralPath $applyDir)) {
    throw "Apply directory not found: $applyDir"
}
$applyScripts = @(Get-ChildItem -LiteralPath $applyDir -Filter 'Apply-NRG*.ps1' -File -ErrorAction Stop)
Write-Host "[-] Loading $($applyScripts.Count) apply function(s)..." -ForegroundColor Cyan
foreach ($s in $applyScripts) {
    . $s.FullName
    Write-Verbose "  Loaded: $($s.Name)"
}
Write-Host "  [+] Loaded" -ForegroundColor Green

# ── Dispatch table: ControlId -> Apply function ─────────────────────────────
# Adding a new control = add a line here + drop a file into Apply/.
$script:NRGApplyDispatch = @{
    'AAD-1.1' = @{ Function = 'Apply-NRGAADLegacyAuth';   RequiredService = 'Graph' }
    'AAD-2.1' = @{ Function = 'Apply-NRGAADMFA';          RequiredService = 'Graph' }
    'EXO-1.1' = @{ Function = 'Apply-NRGEXOMailboxAudit'; RequiredService = 'EXO'   }
    'EXO-1.2' = @{ Function = 'Apply-NRGEXOSmtpAuth';     RequiredService = 'EXO'   }
    'EXO-1.3' = @{ Function = 'Apply-NRGEXOAutoForward';  RequiredService = 'EXO'   }
    'DEF-1.1' = @{ Function = 'Apply-NRGDefenderPreset';  RequiredService = 'EXO'   }
}

# ── Load findings ───────────────────────────────────────────────────────────
$loadedFindings = @()
if ($PSCmdlet.ParameterSetName -eq 'FromFile') {
    # ── Auto-detect newest results JSON when -ResultsPath was not supplied ──
    # The mandatory-prompt UX in v4.6.1 had zero hint text and operators typed
    # plausible-looking nonsense ("Downloads") which crashed the script. Scan
    # ./output/*-results.json (the same path Invoke-NRGAssessment writes to)
    # and pick the newest. If the folder is empty, fall through to the clearer
    # error message below.
    if ([string]::IsNullOrWhiteSpace($ResultsPath)) {
        $defaultOutput = Join-Path $scriptDir 'output'
        $candidate = Get-ChildItem -Path $defaultOutput -Filter '*-results.json' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($candidate) {
            $ResultsPath = $candidate.FullName
            Write-Host "[-] Using latest results: $ResultsPath  (override with -ResultsPath)" -ForegroundColor Cyan
        } else {
            throw "No -ResultsPath supplied and no ./output/*-results.json found. Run Invoke-NRGAssessment first or pass -ResultsPath explicitly."
        }
    }
    if (-not (Test-Path -LiteralPath $ResultsPath)) {
        throw "Results file not found: $ResultsPath"
    }
    # OWASP A01 — refuse traversal sequences
    if ($ResultsPath -match '\.\.[\\/]') {
        throw "ResultsPath rejected: contains '..[/\\]' traversal sequence."
    }
    Write-Host "[-] Loading results from: $ResultsPath" -ForegroundColor Cyan
    try {
        $raw = Get-Content -LiteralPath $ResultsPath -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Failed to parse results JSON: $($_.Exception.Message)"
    }
    if (-not $raw.Findings) {
        throw "Results file contains no Findings array."
    }
    $loadedFindings = @($raw.Findings)
    Write-Host "  [+] Loaded $($loadedFindings.Count) findings" -ForegroundColor Green
} else {
    $loadedFindings = @($Findings)
    Write-Host "[-] Using $($loadedFindings.Count) findings from -Findings parameter" -ForegroundColor Cyan
}

# ── Filter: Gap/Partial only ────────────────────────────────────────────────
$actionable = @($loadedFindings | Where-Object { $_.State -eq 'Gap' -or $_.State -eq 'Partial' })
Write-Host "  [+] $($actionable.Count) findings in Gap/Partial state" -ForegroundColor Green

# ── Filter: ControlIds scope (if provided) ──────────────────────────────────
if ($ControlIds -and $ControlIds.Count -gt 0) {
    $beforeCount = $actionable.Count
    $actionable = @($actionable | Where-Object { $ControlIds -contains $_.ControlId })
    Write-Host "  [+] -ControlIds filter: $beforeCount -> $($actionable.Count)" -ForegroundColor Green
}

# ── Split: actionable vs no-remediation ─────────────────────────────────────
$dispatchable = @($actionable | Where-Object { $script:NRGApplyDispatch.ContainsKey($_.ControlId) })
$noRemediation = @($actionable | Where-Object { -not $script:NRGApplyDispatch.ContainsKey($_.ControlId) })

Write-Host ""
Write-Host "[-] Dispatchable in v1: $($dispatchable.Count)" -ForegroundColor Cyan
Write-Host "    No remediation available (manual): $($noRemediation.Count)" -ForegroundColor DarkYellow

# ── Auth gate: confirm required services are connected ──────────────────────
function Test-NRGServiceConnected {
    param([string]$Service)
    switch ($Service) {
        'Graph' {
            $ctx = $null
            try { $ctx = Get-MgContext -ErrorAction SilentlyContinue } catch { }
            return [bool]$ctx
        }
        'EXO' {
            # EXO V3 exposes Get-ConnectionInformation; fall back to Get-OrganizationConfig presence
            if (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) {
                $info = $null
                try { $info = Get-ConnectionInformation -ErrorAction SilentlyContinue } catch { }
                return [bool]($info | Where-Object { $_.State -eq 'Connected' -or $_.TokenStatus -eq 'Active' })
            }
            return [bool](Get-Command Get-OrganizationConfig -ErrorAction SilentlyContinue)
        }
        'Teams' {
            return [bool](Get-Command Get-CsTenant -ErrorAction SilentlyContinue)
        }
        'IPPSSession' {
            # IPPS shares the EXO session model
            return [bool](Get-Command Get-ComplianceSearch -ErrorAction SilentlyContinue)
        }
        'SPO' {
            return [bool](Get-Command Get-SPOTenant -ErrorAction SilentlyContinue)
        }
    }
    return $false
}

$requiredServices = @($dispatchable | ForEach-Object { $script:NRGApplyDispatch[$_.ControlId].RequiredService } | Sort-Object -Unique)
$missingServices = @{}
foreach ($svc in $requiredServices) {
    if (-not (Test-NRGServiceConnected -Service $svc)) {
        $controls = @($dispatchable | Where-Object { $script:NRGApplyDispatch[$_.ControlId].RequiredService -eq $svc } | Select-Object -ExpandProperty ControlId)
        $missingServices[$svc] = $controls
    }
}

if ($missingServices.Count -gt 0 -and -not $WhatIfPreference) {
    Write-Host ""
    Write-Host "[!] Required services are not connected:" -ForegroundColor Red
    foreach ($svc in $missingServices.Keys) {
        $ctrls = $missingServices[$svc] -join ', '
        Write-Host "    $svc — needed for: $ctrls" -ForegroundColor Red
    }
    throw "One or more required services are not connected. Run Connect-NRGServices first, OR re-run with -WhatIf to preview without connecting."
} elseif ($missingServices.Count -gt 0 -and $WhatIfPreference) {
    Write-Warning "Required services not connected (Graph/EXO). Continuing in -WhatIf mode — real run will require Connect-NRGServices."
}

# ── Reports directory ───────────────────────────────────────────────────────
if (-not $ReportsPath) { $ReportsPath = Join-Path $scriptDir 'Reports' }
if ($ReportsPath -match '\.\.[\\/]') {
    throw "ReportsPath rejected: contains '..[/\\]' traversal sequence."
}
if (-not (Test-Path -LiteralPath $ReportsPath)) {
    # -WhatIf:$false — Reports/ is local audit storage, not a tenant change.
    # Without this, New-Item respects $WhatIfPreference and skips the mkdir,
    # then the subsequent WriteAllText fails with "path not found".
    New-Item -LiteralPath $ReportsPath -ItemType Directory -Force -WhatIf:$false | Out-Null
}
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$rollbackPath = Join-Path $ReportsPath "apply-$ts-rollback.json"
$resultsJsonPath = Join-Path $ReportsPath "apply-$ts-results.json"
$resultsMdPath = Join-Path $ReportsPath "apply-$ts-results.md"

# ── DryRun preview (markdown to console) ────────────────────────────────────
if ($DryRun -or $WhatIfPreference) {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host " DryRun / WhatIf preview — planned changes:"                       -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Yellow
    foreach ($f in $dispatchable) {
        $fn = $script:NRGApplyDispatch[$f.ControlId].Function
        Write-Host ""
        Write-Host "  [$($f.ControlId)] $($f.Title)" -ForegroundColor Cyan
        Write-Host "      State    : $($f.State) / $($f.Severity)" -ForegroundColor Gray
        Write-Host "      Apply fn : $fn" -ForegroundColor Gray
        Write-Host "      Service  : $($script:NRGApplyDispatch[$f.ControlId].RequiredService)" -ForegroundColor Gray
    }
    if ($noRemediation.Count -gt 0) {
        Write-Host ""
        Write-Host "  Manual remediation required (not in v1):" -ForegroundColor DarkYellow
        foreach ($f in $noRemediation) {
            Write-Host "    - [$($f.ControlId)] $($f.Title)" -ForegroundColor DarkYellow
        }
    }
    Write-Host ""
}

# ── Execute apply functions ─────────────────────────────────────────────────
$applyResults = [System.Collections.Generic.List[object]]::new()
$rollbackEntries = [System.Collections.Generic.List[object]]::new()

# When -Force is set, suppress per-control prompts by overriding ConfirmPreference.
# This still leaves -WhatIf working (WhatIfPreference is independent).
$savedConfirmPreference = $ConfirmPreference
if ($Force) {
    $ConfirmPreference = 'None'
}

try {
    foreach ($finding in $dispatchable) {
        $cid = $finding.ControlId
        $fnName = $script:NRGApplyDispatch[$cid].Function

        if (-not (Get-Command $fnName -ErrorAction SilentlyContinue)) {
            $applyResults.Add([PSCustomObject]@{
                ControlId = $cid
                Action    = "(dispatch error)"
                Status    = 'Failed'
                Before    = $null
                After     = $null
                Error     = "Apply function '$fnName' not found in session — did Apply/$fnName.ps1 dot-source correctly?"
                Timestamp = (Get-Date).ToString('o')
            })
            Write-Host "  [!] $cid : dispatch error — $fnName not loaded" -ForegroundColor Red
            continue
        }

        Write-Host ""
        Write-Host "[-] Applying $cid via $fnName..." -ForegroundColor Cyan

        # Forward our own -WhatIf / -Confirm to the apply function
        $invokeParams = @{ Finding = $finding }
        if ($WhatIfPreference) { $invokeParams['WhatIf'] = $true }
        if ($Force)            { $invokeParams['Confirm'] = $false }

        $r = $null
        try {
            $r = & $fnName @invokeParams
        } catch {
            $r = [PSCustomObject]@{
                ControlId = $cid
                Action    = "(apply function threw)"
                Status    = 'Failed'
                Before    = $null
                After     = $null
                Error     = $_.Exception.Message
                Timestamp = (Get-Date).ToString('o')
            }
        }

        if ($r) {
            $applyResults.Add($r)
            $color = switch ($r.Status) {
                'Applied'          { 'Green' }
                'AlreadyCompliant' { 'DarkGreen' }
                'Skipped'          { 'Yellow' }
                'Failed'           { 'Red' }
                default            { 'Gray' }
            }
            Write-Host "    Status: $($r.Status)" -ForegroundColor $color
            if ($r.Error) {
                Write-Host "    Error : $($r.Error)" -ForegroundColor Red
            }

            if ($r.Status -eq 'Applied') {
                $rollbackEntries.Add([PSCustomObject]@{
                    Timestamp = $r.Timestamp
                    ControlId = $r.ControlId
                    Action    = $r.Action
                    Before    = $r.Before
                    After     = $r.After
                    ApplyFunction = $fnName
                    ReverseHint = "To reverse: see Before state above and run the inverse cmdlet manually."
                })
            }
        }
    }
} finally {
    $ConfirmPreference = $savedConfirmPreference
}

# ── Add no-remediation entries to result set so they appear in the report ──
foreach ($f in $noRemediation) {
    $applyResults.Add([PSCustomObject]@{
        ControlId = $f.ControlId
        Action    = '(no apply function — manual remediation required)'
        Status    = 'NoRemediationAvailable'
        Before    = $null
        After     = $null
        Error     = $null
        Timestamp = (Get-Date).ToString('o')
    })
}

# ── Write rollback log ──────────────────────────────────────────────────────
if ($rollbackEntries.Count -gt 0) {
    $rollbackJson = @{
        Metadata = @{
            ToolVersion  = '4.6.1'
            GeneratedAt  = (Get-Date).ToString('o')
            ResultsPath  = if ($PSCmdlet.ParameterSetName -eq 'FromFile') { $ResultsPath } else { '(in-memory findings)' }
            EntryCount   = $rollbackEntries.Count
        }
        Entries = @($rollbackEntries)
    } | ConvertTo-Json -Depth 12
    # Local report file — always write, not gated by WhatIfPreference (this is
    # the apply tool's own audit trail, not a tenant change).
    [System.IO.File]::WriteAllText($rollbackPath, $rollbackJson, [System.Text.UTF8Encoding]::new($false))
    # Sensitive: rollback log contains tenant config Before/After per applied
    # change. Restrict ACL to current user + SYSTEM + Administrators (same
    # protection class as the assessor baseline). No-op on non-Windows.
    if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileAcl -Path $rollbackPath
    }
}

# ── Write results JSON + Markdown ───────────────────────────────────────────
$summary = @{
    Applied          = @($applyResults | Where-Object Status -eq 'Applied').Count
    AlreadyCompliant = @($applyResults | Where-Object Status -eq 'AlreadyCompliant').Count
    Skipped          = @($applyResults | Where-Object Status -eq 'Skipped').Count
    Failed           = @($applyResults | Where-Object Status -eq 'Failed').Count
    NoRemediation    = @($applyResults | Where-Object Status -eq 'NoRemediationAvailable').Count
    Total            = $applyResults.Count
}

$resultsJson = @{
    Metadata = @{
        ToolVersion = '4.6.1'
        GeneratedAt = (Get-Date).ToString('o')
        Mode        = if ($WhatIfPreference) { 'WhatIf' } elseif ($Force) { 'Force' } else { 'Interactive' }
        ResultsPath = if ($PSCmdlet.ParameterSetName -eq 'FromFile') { $ResultsPath } else { '(in-memory findings)' }
    }
    Summary  = $summary
    Results  = @($applyResults)
} | ConvertTo-Json -Depth 12
[System.IO.File]::WriteAllText($resultsJsonPath, $resultsJson, [System.Text.UTF8Encoding]::new($false))
# Sensitive: results JSON contains tenant findings + Before/After values.
if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
    Set-NRGSensitiveFileAcl -Path $resultsJsonPath
}

# Build markdown report
$md = [System.Text.StringBuilder]::new()
[void]$md.AppendLine("# NRG Apply-Baseline Results")
[void]$md.AppendLine("")
[void]$md.AppendLine("**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')  ")
[void]$md.AppendLine("**Mode:** $(if ($WhatIfPreference) { 'WhatIf' } elseif ($Force) { 'Force' } else { 'Interactive' })  ")
[void]$md.AppendLine("**Tool version:** 4.6.1")
[void]$md.AppendLine("")
[void]$md.AppendLine("## Summary")
[void]$md.AppendLine("")
[void]$md.AppendLine("| Status                 | Count |")
[void]$md.AppendLine("|------------------------|-------|")
[void]$md.AppendLine("| Applied                | $($summary.Applied) |")
[void]$md.AppendLine("| AlreadyCompliant       | $($summary.AlreadyCompliant) |")
[void]$md.AppendLine("| Skipped                | $($summary.Skipped) |")
[void]$md.AppendLine("| Failed                 | $($summary.Failed) |")
[void]$md.AppendLine("| NoRemediationAvailable | $($summary.NoRemediation) |")
[void]$md.AppendLine("| **Total**              | **$($summary.Total)** |")
[void]$md.AppendLine("")
[void]$md.AppendLine("## Details")
[void]$md.AppendLine("")
foreach ($r in $applyResults) {
    [void]$md.AppendLine("### $($r.ControlId) — $($r.Status)")
    [void]$md.AppendLine("")
    [void]$md.AppendLine("- **Action:** $($r.Action)")
    [void]$md.AppendLine("- **Timestamp:** $($r.Timestamp)")
    if ($r.Error) {
        [void]$md.AppendLine("- **Error:** ``$($r.Error -replace '`','\`')``")
    }
    if ($r.Before) {
        [void]$md.AppendLine("- **Before:** ``$((ConvertTo-Json $r.Before -Depth 5 -Compress) -replace '`','\`')``")
    }
    if ($r.After) {
        [void]$md.AppendLine("- **After:** ``$((ConvertTo-Json $r.After -Depth 5 -Compress) -replace '`','\`')``")
    }
    [void]$md.AppendLine("")
}
[System.IO.File]::WriteAllText($resultsMdPath, $md.ToString(), [System.Text.UTF8Encoding]::new($false))
# Sensitive: results MD includes tenant config Before/After per change.
if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
    Set-NRGSensitiveFileAcl -Path $resultsMdPath
}

# ── Final summary to console ────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Apply-NRGBaseline complete"                                      -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Applied                $($summary.Applied)"                     -ForegroundColor Green
Write-Host "  AlreadyCompliant       $($summary.AlreadyCompliant)"            -ForegroundColor DarkGreen
Write-Host "  Skipped                $($summary.Skipped)"                     -ForegroundColor Yellow
Write-Host "  Failed                 $($summary.Failed)"                      -ForegroundColor Red
Write-Host "  NoRemediationAvailable $($summary.NoRemediation)"               -ForegroundColor DarkYellow
Write-Host "  Total                  $($summary.Total)"                       -ForegroundColor White
Write-Host ""
Write-Host "  Results (JSON)  : $resultsJsonPath"                             -ForegroundColor White
Write-Host "  Results (MD)    : $resultsMdPath"                               -ForegroundColor White
if ($rollbackEntries.Count -gt 0) {
    Write-Host "  Rollback log    : $rollbackPath"                            -ForegroundColor White
    Write-Host "                    KEEP THIS FILE — required to reverse changes." -ForegroundColor Yellow
} else {
    Write-Host "  Rollback log    : (no changes applied — log not written)"   -ForegroundColor DarkGray
}
Write-Host ""

if ($noRemediation.Count -gt 0) {
    Write-Warning "Manual remediation required for the following controls (no v1 apply function):"
    foreach ($f in $noRemediation) {
        Write-Warning "  $($f.ControlId) — $($f.Title)"
    }
}

if ($summary.Failed -gt 0) {
    exit 4
} else {
    exit 0
}
