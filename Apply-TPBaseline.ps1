#Requires -Version 7.0
#
# Apply-TPBaseline.ps1  (v4.6.3)
# Interactive WRITE-MODE deployment tool for TenantPosture remediations.
#
# NRG Technology Services | NextLayerSec LLC
# Author: Matthew Levorson
#
# ============================================================================
# WARNING: THIS TOOL MODIFIES TENANT CONFIGURATION.
# ============================================================================
# Unlike Invoke-TPAssessment (read-only) and Publish-TPRemediationScript
# (generates a static .ps1 deliverable), this tool ACTUALLY APPLIES changes
# to a live production Microsoft 365 tenant.
#
# Safety bars:
#   * SupportsShouldProcess + ConfirmImpact='High' (free -WhatIf / -Confirm)
#   * Per-control idempotency re-read (no write if already compliant)
#   * Rollback log flushed JSON-lines per applied change (interrupt-safe audit)
#   * Tenant-ID pin: results.json Metadata.TenantId must match connected Graph
#     session before any apply executes — prevents Tenant-B-apply-to-Tenant-A.
#   * Auth gate — refuses to run if required service is not connected
#   * Filters input findings to State = Gap / Partial only
#   * Path-traversal guard on Apply/*.ps1 dot-source (mirrors psm1 loader)
#
# Apply functions are top-level script functions, NOT module exports — they are
# dot-sourced from Apply/Apply-NRG*.ps1 at script start. This matches the
# Invoke-TPAssessment.ps1 convention (also a top-level orchestrator script).
#
# -Force semantics:
#   -Force skips the per-finding -Confirm prompt and sets ConfirmPreference='None'
#   for the duration of the loop. It DOES NOT:
#     * promote any CA policy from report-only to enabled
#     * bypass the tenant-ID pin / break-glass / path-traversal safety checks
#     * override -WhatIf (WhatIfPreference remains independent)
#   In short: -Force = "don't ask, just run the same safe path interactively".
#
# Usage:
#   .\Apply-TPBaseline.ps1 -ResultsPath .\output\contoso-20260524-results.json -WhatIf
#   .\Apply-TPBaseline.ps1 -ResultsPath .\output\contoso-20260524-results.json -ControlIds 'EXO-1.1','EXO-1.2'
#   .\Apply-TPBaseline.ps1 -ResultsPath .\output\contoso-20260524-results.json -Force
#

[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'FromFile')]
param(
    # Not Mandatory — the block below auto-detects the newest results JSON
    # under .\output\ when -ResultsPath is omitted. The empty-prompt UX in
    # v4.6.1 ("ResultsPath:" with no hint) led operators to type "Downloads"
    # and crash. HelpMessage gives PowerShell's prompt useful context if the
    # auto-detect path fails (no files in .\output\).
    [Parameter(Mandatory = $false, ParameterSetName = 'FromFile',
        HelpMessage = 'Path to results.json from a prior Invoke-TPAssessment run. Defaults to the newest match in ./output/.')]
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
    [switch] $DryRun,

    # Enforce Authenticode signatures on every Apply-NRG*.ps1 file before
    # any of them runs. Default: $false — emit Write-Warning per unsigned
    # script and continue. Strict mode ($true): refuse to dispatch if any
    # Apply-NRG* file has Status != 'Valid' (NotSigned, HashMismatch,
    # UntrustedRoot, Expired, Error all block).
    #
    # The default is soft so the v4.6.5 transition doesn't break existing
    # operators who haven't generated or trusted a code-signing cert yet.
    # Once Build/Sign-Release.ps1 has run with an in-house self-signed cert
    # (Build/New-TPCodeSigningCert.ps1 creates one), flipping this on
    # gives you tamper detection on every apply run.
    #
    # Future default: $true once a release pipeline reliably ships signed
    # artifacts. Track via the v4.6.x polish roadmap.
    [switch] $RequireSignedCode
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
# Same pattern as Invoke-TPAssessment.ps1 — read ModuleVersion from the
# manifest so the banner can't drift from the .psd1 / .psm1 single source.
$applyVersion = 'unknown'
try {
    $manifestData = Import-PowerShellDataFile -LiteralPath (Join-Path $scriptDir 'TenantPosture.psd1') -ErrorAction Stop
    if ($manifestData.ModuleVersion) { $applyVersion = [string]$manifestData.ModuleVersion }
} catch { }

# ── Banner ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================" -ForegroundColor Red
Write-Host " TenantPosture v$applyVersion — Apply-TPBaseline (WRITE MODE)" -ForegroundColor Red
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
# Apply-TPBaseline is a top-level orchestrator and does not Import-Module
# TenantPosture, so any Lib helper it depends on must be dot-sourced here.
# Set-TPSensitiveFileAcl is required to harden the rollback log + results
# files (tenant inventory + change history — same sensitivity tier as the
# assessor baseline JSON).
$aclHelperPath = Join-Path $scriptDir 'Lib' 'Set-TPSensitiveFileAcl.ps1'
if (Test-Path -LiteralPath $aclHelperPath) {
    . $aclHelperPath
} else {
    Write-Warning "Set-TPSensitiveFileAcl.ps1 not found at $aclHelperPath — output files will not be ACL-hardened."
}

# Break-glass exclusion helper (H7) — looked up by AAD CA-creating Apply
# functions before writing a policy body, to prevent tenant-wide lockout if
# a future operator promotes the report-only policy to enabled via portal.
$bgHelperPath = Join-Path $scriptDir 'Lib' 'Get-TPBreakGlassExclusions.ps1'
if (Test-Path -LiteralPath $bgHelperPath) {
    . $bgHelperPath
} else {
    Write-Warning "Get-TPBreakGlassExclusions.ps1 not found at $bgHelperPath — CA policies will be created with empty exclusion lists."
}

# ── Dot-source the Apply functions ──────────────────────────────────────────
# OWASP A01: a shared-MSP-workstation attacker could drop Apply-NRG-pwn.ps1
# into Apply/ via a malicious symlink or junction, then dot-source-time
# arbitrary code execution occurs the next time the operator runs the apply
# tool. Mirror the psm1 loader's StartsWith() guard — resolve each candidate
# path and refuse anything that escapes the Apply/ root.
$applyDir = Join-Path $scriptDir 'Apply'
if (-not (Test-Path -LiteralPath $applyDir)) {
    throw "Apply directory not found: $applyDir"
}
$resolvedApplyDir = [System.IO.Path]::GetFullPath($applyDir)
$applyScripts = @(Get-ChildItem -LiteralPath $applyDir -Filter 'Apply-NRG*.ps1' -File -ErrorAction Stop)
Write-Host "[-] Loading $($applyScripts.Count) apply function(s)..." -ForegroundColor Cyan

# Authenticode signature preflight. Soft by default (warns and continues),
# hard when -RequireSignedCode was passed (refuses to dispatch). Test-NRG-
# SignatureStatus was loaded by the TenantPosture module import above and
# distinguishes NotSigned / HashMismatch / UntrustedRoot / Expired so the
# warning text is useful instead of "Signature: Invalid."
if (Get-Command Test-TPSignatureStatus -ErrorAction SilentlyContinue) {
    $sigResults = foreach ($s in $applyScripts) {
        Test-TPSignatureStatus -Path $s.FullName
    }
    $unsigned = @($sigResults | Where-Object { $_.Status -ne 'Valid' -and $_.Status -ne 'Unsupported' })
    if ($unsigned.Count -gt 0) {
        if ($RequireSignedCode) {
            Write-Host '' -ForegroundColor Red
            Write-Host '  [X] Signature check FAILED — -RequireSignedCode is set' -ForegroundColor Red
            foreach ($u in $unsigned) {
                Write-Host "      $($u.Path): $($u.Status) — $($u.StatusMessage)" -ForegroundColor Red
            }
            throw "Refusing to dispatch $($unsigned.Count) unsigned/invalid Apply-NRG*.ps1 file(s). Sign with Build/Sign-Release.ps1 or drop -RequireSignedCode to run in soft-warning mode."
        } else {
            foreach ($u in $unsigned) {
                Write-Warning "Unsigned/invalid Apply script: $([System.IO.Path]::GetFileName($u.Path)) — $($u.Status). Pass -RequireSignedCode to refuse dispatch on this state. (To sign: Build/New-TPCodeSigningCert.ps1 -SaveThumbprintForBuild ; Build/Sign-Release.ps1)"
            }
        }
    } else {
        $signedCount = @($sigResults | Where-Object Status -eq 'Valid').Count
        if ($signedCount -gt 0) {
            Write-Host "  [+] All $signedCount Apply-NRG*.ps1 files have valid Authenticode signatures" -ForegroundColor Green
        }
    }
}

$loadedCount = 0
foreach ($s in $applyScripts) {
    $resolvedFile = [System.IO.Path]::GetFullPath($s.FullName)
    if (-not $resolvedFile.StartsWith($resolvedApplyDir, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Warning "Skipping file outside Apply/ root (path traversal?): $($s.FullName)"
        continue
    }
    . $resolvedFile
    $loadedCount++
    Write-Verbose "  Loaded: $($s.Name)"
}
Write-Host "  [+] Loaded $loadedCount" -ForegroundColor Green

# ── Dispatch table: ControlId -> Apply function ─────────────────────────────
# Adding a new control = add a line here + drop a file into Apply/.
$script:TPApplyDispatch = @{
    'AAD-1.1' = @{ Function = 'Apply-TPAADLegacyAuth';   RequiredService = 'Graph' }
    'AAD-2.1' = @{ Function = 'Apply-TPAADMFA';          RequiredService = 'Graph' }
    'EXO-1.1' = @{ Function = 'Apply-TPEXOMailboxAudit'; RequiredService = 'EXO'   }
    'EXO-1.2' = @{ Function = 'Apply-TPEXOSmtpAuth';     RequiredService = 'EXO'   }
    'EXO-1.3' = @{ Function = 'Apply-TPEXOAutoForward';  RequiredService = 'EXO'   }
    'DEF-1.1' = @{ Function = 'Apply-TPDefenderPreset';  RequiredService = 'EXO'   }
}

# ── Load findings ───────────────────────────────────────────────────────────
$loadedFindings = @()
if ($PSCmdlet.ParameterSetName -eq 'FromFile') {
    # ── Auto-detect newest results JSON when -ResultsPath was not supplied ──
    # The mandatory-prompt UX in v4.6.1 had zero hint text and operators typed
    # plausible-looking nonsense ("Downloads") which crashed the script. Scan
    # ./output/*-results.json (the same path Invoke-TPAssessment writes to)
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
            throw "No -ResultsPath supplied and no ./output/*-results.json found. Run Invoke-TPAssessment first or pass -ResultsPath explicitly."
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
        # CWE-502 hardening — explicit -Depth caps deserialization at a
        # realistic-but-bounded depth so a hostile or corrupt baseline JSON
        # (recursive bomb) cannot exhaust memory at parse time. The matching
        # write side uses -Depth 10.
        $raw = Get-Content -LiteralPath $ResultsPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20 -ErrorAction Stop
    } catch {
        throw "Failed to parse results JSON: $($_.Exception.Message)"
    }
    if (-not $raw.Findings) {
        throw "Results file contains no Findings array."
    }
    $loadedFindings = @($raw.Findings)
    Write-Host "  [+] Loaded $($loadedFindings.Count) findings" -ForegroundColor Green

    # ── Tenant-ID pin ───────────────────────────────────────────────────────
    # H6: results.json must be pinned to the connected Graph (and EXO) session.
    # An operator with two tenant connections open could otherwise apply
    # Tenant B's remediations to Tenant A. Skip in -WhatIf mode (no harm —
    # nothing is being written — and -WhatIf is the documented preview path
    # that doesn't require a real connection).
    $resultsTenantId     = $null
    $resultsTenantDomain = $null
    if ($raw.PSObject.Properties.Match('Metadata').Count -gt 0 -and $raw.Metadata) {
        if ($raw.Metadata.PSObject.Properties.Match('TenantId').Count -gt 0) {
            $resultsTenantId = [string]$raw.Metadata.TenantId
        }
        if ($raw.Metadata.PSObject.Properties.Match('TenantDomain').Count -gt 0) {
            $resultsTenantDomain = [string]$raw.Metadata.TenantDomain
        }
    }

    if (-not $WhatIfPreference) {
        if ([string]::IsNullOrWhiteSpace($resultsTenantId)) {
            throw "Results JSON has no TenantId — refusing to apply against an unverified target."
        }

        # Graph context check
        $mgCtx = $null
        try { $mgCtx = Get-MgContext -ErrorAction SilentlyContinue } catch { }
        if (-not $mgCtx -or [string]::IsNullOrWhiteSpace($mgCtx.TenantId)) {
            throw "Graph session not connected — cannot verify tenant pin. Run Connect-TPServices first."
        }
        if ($mgCtx.TenantId -ne $resultsTenantId) {
            throw "Tenant mismatch: results.json was generated for $resultsTenantId, connected Graph session is $($mgCtx.TenantId). Refusing to apply to wrong tenant."
        }
        Write-Host "  [+] Tenant pin: Graph $($mgCtx.TenantId) matches results.json" -ForegroundColor Green

        # EXO context check (best-effort — only fires if EOM is loaded and a
        # session is open; the auth gate further below handles the "not
        # connected at all" case for EXO-dependent controls).
        if (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) {
            $exoInfo = $null
            try { $exoInfo = @(Get-ConnectionInformation -ErrorAction SilentlyContinue) } catch { }
            $exoActive = @($exoInfo | Where-Object { $_.State -eq 'Connected' -or $_.TokenStatus -eq 'Active' })
            if ($exoActive.Count -gt 0) {
                $exoTenantId = $null
                foreach ($p in 'TenantId','TenantID','TenantGuid') {
                    if ($exoActive[0].PSObject.Properties.Match($p).Count -gt 0 -and $exoActive[0].$p) {
                        $exoTenantId = [string]$exoActive[0].$p
                        break
                    }
                }
                if ($exoTenantId -and $exoTenantId -ne $resultsTenantId) {
                    throw "Tenant mismatch (EXO): results.json TenantId $resultsTenantId, EXO session TenantId $exoTenantId. Refusing to apply."
                }
                # If EXO exposes Organization (the .onmicrosoft.com routing domain)
                # and results carry TenantDomain, surface a warning on mismatch
                # but do not block — TenantDomain in results may be primary, EXO
                # always reports the routing domain.
                if ($resultsTenantDomain -and $exoActive[0].PSObject.Properties.Match('Organization').Count -gt 0) {
                    $exoOrg = [string]$exoActive[0].Organization
                    if ($exoOrg -and -not (
                        $exoOrg -eq $resultsTenantDomain -or
                        $resultsTenantDomain.StartsWith(($exoOrg -split '\.')[0], [StringComparison]::OrdinalIgnoreCase)
                    )) {
                        Write-Warning "EXO Organization '$exoOrg' does not obviously match results.json TenantDomain '$resultsTenantDomain'. TenantId pin matched, so proceeding — verify this is intentional."
                    }
                }
                Write-Host "  [+] Tenant pin: EXO session matches results.json" -ForegroundColor Green
            }
        }
    } else {
        if ([string]::IsNullOrWhiteSpace($resultsTenantId)) {
            Write-Warning "Results JSON has no TenantId (skipped under -WhatIf, but real run will be refused)."
        }
    }
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
    # M-ControlIds typo: warn on any -ControlIds value that doesn't appear in
    # the actionable Gap/Partial set. Silently dropping a typo'd ID let the
    # operator believe the apply ran when it actually no-op'd. We compare
    # against the actionable set (post Gap/Partial filter) — an ID that exists
    # in results.json but is Satisfied / NotApplicable is still worth surfacing
    # because the operator clearly expected it to be a remediation target.
    $loadedIds     = @($loadedFindings | ForEach-Object { $_.ControlId } | Sort-Object -Unique)
    $actionableIds = @($actionable     | ForEach-Object { $_.ControlId } | Sort-Object -Unique)
    foreach ($cid in $ControlIds) {
        if ($actionableIds -notcontains $cid) {
            if ($loadedIds -contains $cid) {
                Write-Warning "ControlId '$cid' was found in results.json but is not in Gap/Partial state — nothing to apply."
            } else {
                Write-Warning "ControlId '$cid' requested but not found in results.json — typo?"
            }
        }
    }
    $actionable = @($actionable | Where-Object { $ControlIds -contains $_.ControlId })
    Write-Host "  [+] -ControlIds filter: $beforeCount -> $($actionable.Count)" -ForegroundColor Green
}

# ── Split: actionable vs no-remediation ─────────────────────────────────────
$dispatchable = @($actionable | Where-Object { $script:TPApplyDispatch.ContainsKey($_.ControlId) })
$noRemediation = @($actionable | Where-Object { -not $script:TPApplyDispatch.ContainsKey($_.ControlId) })

Write-Host ""
Write-Host "[-] Dispatchable in v1: $($dispatchable.Count)" -ForegroundColor Cyan
Write-Host "    No remediation available (manual): $($noRemediation.Count)" -ForegroundColor DarkYellow

# ── Auth gate: confirm required services are connected ──────────────────────
function Test-TPServiceConnected {
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

$requiredServices = @($dispatchable | ForEach-Object { $script:TPApplyDispatch[$_.ControlId].RequiredService } | Sort-Object -Unique)
$missingServices = @{}
foreach ($svc in $requiredServices) {
    if (-not (Test-TPServiceConnected -Service $svc)) {
        $controls = @($dispatchable | Where-Object { $script:TPApplyDispatch[$_.ControlId].RequiredService -eq $svc } | Select-Object -ExpandProperty ControlId)
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
    throw "One or more required services are not connected. Run Connect-TPServices first, OR re-run with -WhatIf to preview without connecting."
} elseif ($missingServices.Count -gt 0 -and $WhatIfPreference) {
    Write-Warning "Required services not connected (Graph/EXO). Continuing in -WhatIf mode — real run will require Connect-TPServices."
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
    [void][System.IO.Directory]::CreateDirectory($ReportsPath)
}
# H5: filename uniqueness. yyyyMMdd-HHmmss alone collides under two
# concurrent invocations within the same second (same operator, two MSP
# tenants in parallel; or scheduled tasks). Append PID + short GUID so the
# rollback log of one invocation can never overwrite another's.
$ts        = Get-Date -Format 'yyyyMMdd-HHmmss'
$uniqTag   = "$PID-$([guid]::NewGuid().ToString('N').Substring(0,8))"
# H4: rollback log is now JSON-lines (.jsonl) flushed per applied change so a
# Ctrl-C mid-loop still leaves a complete audit trail of changes already
# committed to the tenant. After the loop we ALSO emit the consolidated
# .json document for human reading, but the .jsonl is the authoritative
# interrupt-safe record.
$rollbackJsonlPath = Join-Path $ReportsPath "apply-$ts-$uniqTag-rollback.jsonl"
$rollbackPath      = Join-Path $ReportsPath "apply-$ts-$uniqTag-rollback.json"
$resultsJsonPath   = Join-Path $ReportsPath "apply-$ts-$uniqTag-results.json"
$resultsMdPath     = Join-Path $ReportsPath "apply-$ts-$uniqTag-results.md"

# ── JSONL rollback helper (interrupt-safe append) ───────────────────────────
function Add-TPRollbackJsonl {
    param(
        [Parameter(Mandatory)] [object] $Entry,
        [Parameter(Mandatory)] [string] $Path
    )
    $line = (ConvertTo-Json -InputObject $Entry -Depth 8 -Compress) + "`n"
    # First write creates the file. ACL it ONCE on creation so subsequent
    # appends inherit the same restricted ACL (Win) or are no-op (Linux).
    $created = -not (Test-Path -LiteralPath $Path)
    [System.IO.File]::AppendAllText($Path, $line, [System.Text.UTF8Encoding]::new($false))
    if ($created -and (Get-Command Set-TPSensitiveFileAcl -ErrorAction SilentlyContinue)) {
        try { Set-TPSensitiveFileAcl -Path $Path } catch {
            Write-Warning "Failed to ACL rollback jsonl '$Path': $($_.Exception.Message)"
        }
    }
}

# ── DryRun preview (markdown to console) ────────────────────────────────────
if ($DryRun -or $WhatIfPreference) {
    Write-Host ""
    Write-Host "================================================================" -ForegroundColor Yellow
    Write-Host " DryRun / WhatIf preview — planned changes:"                       -ForegroundColor Yellow
    Write-Host "================================================================" -ForegroundColor Yellow
    foreach ($f in $dispatchable) {
        $fn = $script:TPApplyDispatch[$f.ControlId].Function
        Write-Host ""
        Write-Host "  [$($f.ControlId)] $($f.Title)" -ForegroundColor Cyan
        Write-Host "      State    : $($f.State) / $($f.Severity)" -ForegroundColor Gray
        Write-Host "      Apply fn : $fn" -ForegroundColor Gray
        Write-Host "      Service  : $($script:TPApplyDispatch[$f.ControlId].RequiredService)" -ForegroundColor Gray
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
        $fnName = $script:TPApplyDispatch[$cid].Function

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
                $rbEntry = [PSCustomObject]@{
                    Timestamp     = $r.Timestamp
                    ControlId     = $r.ControlId
                    Action        = $r.Action
                    Before        = $r.Before
                    After         = $r.After
                    ApplyFunction = $fnName
                    ReverseHint   = "To reverse: see Before state above and run the inverse cmdlet manually."
                    # H7: surface any break-glass warning the apply function
                    # attached to the result so it lands in the rollback log,
                    # not just in the console transcript that may scroll off.
                    Notes         = if ($r.PSObject.Properties.Match('Notes').Count -gt 0) { $r.Notes } else { $null }
                }
                $rollbackEntries.Add($rbEntry)
                # H4: flush IMMEDIATELY — do not wait for end-of-loop. If the
                # operator hits Ctrl-C between this apply and the next, the
                # change to the tenant is real and the audit trail must exist.
                try {
                    Add-TPRollbackJsonl -Entry $rbEntry -Path $rollbackJsonlPath
                } catch {
                    Write-Warning "Failed to persist rollback entry for $cid : $($_.Exception.Message)"
                }
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
    # H4 ROLLBACK PERSISTENCE: at this point each entry has already been
    # flushed individually to $rollbackJsonlPath via Add-TPRollbackJsonl. The
    # consolidated .json document below is purely for human reading — the
    # .jsonl is the authoritative interrupt-safe record.
    $rollbackJson = @{
        Metadata = @{
            ToolVersion  = $applyVersion
            GeneratedAt  = (Get-Date).ToString('o')
            ResultsPath  = if ($PSCmdlet.ParameterSetName -eq 'FromFile') { $ResultsPath } else { '(in-memory findings)' }
            EntryCount   = $rollbackEntries.Count
            JsonlPath    = $rollbackJsonlPath
        }
        Entries = @($rollbackEntries)
    } | ConvertTo-Json -Depth 12
    # Local report file — always write, not gated by WhatIfPreference (this is
    # the apply tool's own audit trail, not a tenant change).
    #
    # TOCTOU fix (v4.6.3 P2): Set-TPSensitiveFileContent pre-creates the file
    # and ACL-hardens it BEFORE writing the JSON. Previously a co-resident
    # process on a shared MSP workstation could read tenant Before/After data
    # in the small window between WriteAllText and Set-Acl.
    if (Get-Command Set-TPSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-TPSensitiveFileContent -Path $rollbackPath -Content $rollbackJson
    } else {
        [System.IO.File]::WriteAllText($rollbackPath, $rollbackJson, [System.Text.UTF8Encoding]::new($false))
        if (Get-Command Set-TPSensitiveFileAcl -ErrorAction SilentlyContinue) {
            Set-TPSensitiveFileAcl -Path $rollbackPath
        }
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
        ToolVersion = $applyVersion
        GeneratedAt = (Get-Date).ToString('o')
        Mode        = if ($WhatIfPreference) { 'WhatIf' } elseif ($Force) { 'Force' } else { 'Interactive' }
        ResultsPath = if ($PSCmdlet.ParameterSetName -eq 'FromFile') { $ResultsPath } else { '(in-memory findings)' }
    }
    Summary  = $summary
    Results  = @($applyResults)
} | ConvertTo-Json -Depth 12
# TOCTOU fix (v4.6.3 P2) — see rollback write above.
if (Get-Command Set-TPSensitiveFileContent -ErrorAction SilentlyContinue) {
    Set-TPSensitiveFileContent -Path $resultsJsonPath -Content $resultsJson
} else {
    [System.IO.File]::WriteAllText($resultsJsonPath, $resultsJson, [System.Text.UTF8Encoding]::new($false))
    if (Get-Command Set-TPSensitiveFileAcl -ErrorAction SilentlyContinue) {
        Set-TPSensitiveFileAcl -Path $resultsJsonPath
    }
}

# Build markdown report
$md = [System.Text.StringBuilder]::new()
[void]$md.AppendLine("# NRG Apply-Baseline Results")
[void]$md.AppendLine("")
[void]$md.AppendLine("**Generated:** $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')  ")
[void]$md.AppendLine("**Mode:** $(if ($WhatIfPreference) { 'WhatIf' } elseif ($Force) { 'Force' } else { 'Interactive' })  ")
[void]$md.AppendLine("**Tool version:** $applyVersion")
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
# TOCTOU fix (v4.6.3 P2) — see rollback write above.
if (Get-Command Set-TPSensitiveFileContent -ErrorAction SilentlyContinue) {
    Set-TPSensitiveFileContent -Path $resultsMdPath -Content ($md.ToString())
} else {
    [System.IO.File]::WriteAllText($resultsMdPath, $md.ToString(), [System.Text.UTF8Encoding]::new($false))
    if (Get-Command Set-TPSensitiveFileAcl -ErrorAction SilentlyContinue) {
        Set-TPSensitiveFileAcl -Path $resultsMdPath
    }
}

# ── Final summary to console ────────────────────────────────────────────────
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Apply-TPBaseline complete"                                      -ForegroundColor Cyan
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
    Write-Host "  Rollback (jsonl): $rollbackJsonlPath"                       -ForegroundColor White
    Write-Host "  Rollback (json) : $rollbackPath"                            -ForegroundColor White
    Write-Host "                    KEEP THESE FILES — required to reverse changes." -ForegroundColor Yellow
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
