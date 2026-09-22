#Requires -Version 7.0
#
# Publish-NRGRemediationScript.ps1  (v4.5.5)
# Generates a tenant-specific remediation PowerShell script from Gap findings.
#
# Output: <tenant>-remediation.ps1
#   - SupportsShouldProcess — safe to run with -WhatIf first
#   - Gap findings only — no changes proposed for Satisfied/Partial
#   - Grouped by workload
#   - Each section: description, business risk, exact command, validation
#   - Header warns: review before running, test in non-prod first
#
# SECURITY: Remediation strings are sourced from controls.json, which is
#   content-validated at load time. Tenant values (TenantDomain, Operator,
#   AssessmentDate, ToolVersion) ARE interpolated into the generated script —
#   into single-quoted PowerShell literals via EscPs1Literal, which doubles
#   embedded quotes, and into comment lines with newlines stripped so a value
#   cannot terminate the comment and inject code. Any new interpolation site
#   must go through the same two helpers.
#

function Publish-NRGRemediationScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Metadata,
        [Parameter(Mandatory)] [object[]]  $Findings,
        [Parameter(Mandatory)] [string]    $OutputPath
    )

    # Escape a value for safe inclusion inside a single-quoted PowerShell
    # literal in the GENERATED script. Without this, a tenant display name like
    # "John's Mailbox" breaks out of '...' and becomes injectable code that the
    # engineer would execute. OWASP A03 / ASVS V5.1.3.
    function EscPs1Literal([object]$v) {
        if ($null -eq $v) { return '' }
        return ([string]$v) -replace "'", "''"
    }

    # Escape a value for safe inclusion inside a single-line PowerShell comment
    # in the GENERATED script. Strips CR/LF so a value containing a newline
    # cannot terminate the comment and start a new code line. We also drop the
    # single quote to keep the value harmless if a future change moves the
    # value into a literal context.
    function EscPs1Comment([object]$v) {
        if ($null -eq $v) { return '' }
        return ([string]$v) -replace '[\r\n]+', ' '
    }

    # Raw values
    # Get-NRGObjectField, not dot-access-then-??: StrictMode throws on a missing
    # key before ?? can apply. Operator is absent from the -FromResults metadata.
    $clientRaw  = [string](Get-NRGObjectField -Item $Metadata -Key 'TenantDomain'   -Default 'UnknownTenant')
    $dateRaw    = [string](Get-NRGObjectField -Item $Metadata -Key 'AssessmentDate' -Default (Get-Date -Format 'yyyy-MM-dd'))
    $versionRaw = [string](Get-NRGObjectField -Item $Metadata -Key 'ToolVersion'    -Default '4.5.5')
    $opUPNRaw   = [string](Get-NRGObjectField -Item $Metadata -Key 'Operator'       -Default 'admin')

    # For interpolation into single-quoted PowerShell literals in the generated
    # script. A tenant value like "John's Mailbox" must be doubled to 'John''s
    # Mailbox' so it does not break out of the literal.
    # v4.11.1: dropped unused $date/$version/$opUPN escape assignments
    # (left over from a header block that was removed in an earlier refactor).
    $client = EscPs1Literal $clientRaw

    # For interpolation into PowerShell comment lines in the generated script.
    # Strip newlines so a value cannot terminate the comment and inject code.
    $clientC  = EscPs1Comment $clientRaw
    $dateC    = EscPs1Comment $dateRaw
    $versionC = EscPs1Comment $versionRaw
    $opUPNC   = EscPs1Comment $opUPNRaw

    # Tenant stem used in -EXAMPLE help (unquoted in `.\stem-remediation.ps1`).
    # Strip everything but file-name-safe characters to keep the help line valid
    # and prevent injection via tenant names containing spaces, quotes, etc.
    $clientStem = ($clientRaw -replace '\..*$','') -replace '[^A-Za-z0-9_\-]',''
    if ([string]::IsNullOrEmpty($clientStem)) { $clientStem = 'tenant' }

    # Load control definitions
    $controls = @{}
    try {
        foreach ($c in (Get-NRGControlDefinitions)) { $controls[$c.ControlId] = $c }
    } catch { }

    # Tenant license profile — used to suppress "# REQUIRES: ..." comments on
    # gaps whose license the tenant already holds. v4.6.1 emitted the comment
    # unconditionally from controls.json LicenseRequirement, which mis-led
    # operators on Business Premium tenants into thinking BP wasn't detected.
    $licProfile = if (Get-Command Get-NRGTenantLicenseProfile -ErrorAction SilentlyContinue) {
        try { Get-NRGTenantLicenseProfile } catch { $null }
    } else { $null }

    $sevOrder = @{ 'Critical'=0; 'High'=1; 'Medium'=2; 'Low'=3; 'Informational'=4 }
    $gaps = @($Findings | Where-Object { $_.State -eq 'Gap' }) |
            Sort-Object { $sevOrder[$_.Severity] ?? 99 }, ControlId

    $sb = [System.Text.StringBuilder]::new()

    # Header. NOTE: lines below are inside a PowerShell comment-help block in
    # the generated script. We use the *Comment-escaped* variants ($clientC etc.)
    # so a tenant value containing CR/LF cannot terminate the comment block.
    $null = $sb.AppendLine("#Requires -Version 7.0")
    $null = $sb.AppendLine("<#")
    $null = $sb.AppendLine(".SYNOPSIS")
    $null = $sb.AppendLine("    NRG-Assessment Remediation Script — $clientC")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine(".DESCRIPTION")
    $null = $sb.AppendLine("    Auto-generated remediation script for $clientC M365 security gaps.")
    $null = $sb.AppendLine("    Generated: $dateC by NRG-Assessment v$versionC")
    $null = $sb.AppendLine("    Operator:  $opUPNC")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("    IMPORTANT: Review every command before running.")
    $null = $sb.AppendLine("    Test with -WhatIf first. Run during a maintenance window.")
    $null = $sb.AppendLine("    Some commands require specific module versions and admin roles.")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine(".PARAMETER WhatIf")
    $null = $sb.AppendLine("    Preview every change without making it. Strongly recommended for the first run.")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine(".PARAMETER Phase")
    $null = $sb.AppendLine("    Run only a specific phase: 1 (Critical+High), 2 (Medium), 3 (Low). Default: all.")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine(".PARAMETER Workload")
    $null = $sb.AppendLine("    Run only a specific workload: AAD, EXO, DNS, DEF, SPO, TMS, INT, PVW, PPL")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine(".EXAMPLE")
    $null = $sb.AppendLine("    # Preview Phase 1 changes (no writes)")
    $null = $sb.AppendLine("    .\$clientStem-remediation.ps1 -Phase 1 -WhatIf")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("    # Apply Phase 1 AAD changes only")
    $null = $sb.AppendLine("    .\$clientStem-remediation.ps1 -Phase 1 -Workload AAD")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine(".NOTES")
    $null = $sb.AppendLine("    Generated by NRG-Assessment v$versionC")
    $null = $sb.AppendLine("    NRG Technology Services / NextLayerSec LLC")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("    Controls with a built-in Apply-* function dispatch through the NRG")
    $null = $sb.AppendLine("    module and write to the tenant (subject to -WhatIf / -Confirm).")
    $null = $sb.AppendLine("    Controls without an Apply-* function are emitted as manual instructions —")
    $null = $sb.AppendLine("    no fake success messages, no silent no-ops.")
    $null = $sb.AppendLine("#>")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("[CmdletBinding(SupportsShouldProcess)]")
    $null = $sb.AppendLine("param(")
    $null = $sb.AppendLine("    [ValidateSet('1','2','3','all')]")
    $null = $sb.AppendLine("    [string] `$Phase = 'all',")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("    [ValidateSet('AAD','EXO','DNS','DEF','SPO','TMS','INT','PVW','PPL','all')]")
    $null = $sb.AppendLine("    [string] `$Workload = 'all'")
    $null = $sb.AppendLine(")")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("Set-StrictMode -Version Latest")
    $null = $sb.AppendLine("`$ErrorActionPreference = 'Stop'")
    $null = $sb.AppendLine("")

    # Summary comment
    $null = $sb.AppendLine("# ═══════════════════════════════════════════════════════════════════")
    $null = $sb.AppendLine("# ASSESSMENT SUMMARY — $clientC — $dateC")
    $null = $sb.AppendLine("# ═══════════════════════════════════════════════════════════════════")
    $phase1Gaps = @($gaps | Where-Object { $_.Severity -in @('Critical','High') })
    $phase2Gaps = @($gaps | Where-Object { $_.Severity -eq 'Medium' })
    $phase3Gaps = @($gaps | Where-Object { $_.Severity -eq 'Low' })
    $null = $sb.AppendLine("# Total gaps:  $($gaps.Count)")
    $null = $sb.AppendLine("# Phase 1 (Critical+High): $($phase1Gaps.Count)")
    $null = $sb.AppendLine("# Phase 2 (Medium):        $($phase2Gaps.Count)")
    $null = $sb.AppendLine("# Phase 3 (Low):           $($phase3Gaps.Count)")
    $null = $sb.AppendLine("# ═══════════════════════════════════════════════════════════════════")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("# Load the NRG module so Apply-NRG* functions resolve.")
    $null = $sb.AppendLine("`$scriptDir = Split-Path -Parent `$MyInvocation.MyCommand.Path")
    $null = $sb.AppendLine("`$moduleSearch = @(")
    $null = $sb.AppendLine("    (Join-Path `$scriptDir 'NRG-Assessment.psd1'),")
    $null = $sb.AppendLine("    (Join-Path (Split-Path -Parent `$scriptDir) 'NRG-Assessment.psd1')")
    $null = $sb.AppendLine(")")
    $null = $sb.AppendLine("`$nrgModule = `$moduleSearch | Where-Object { Test-Path -LiteralPath `$_ } | Select-Object -First 1")
    $null = $sb.AppendLine("if (-not `$nrgModule) {")
    $null = $sb.AppendLine("    Write-Error 'NRG-Assessment.psd1 not found alongside this script. Place this remediation script in the NRG-Assessment-Tool repo root (or its sibling) and re-run.'")
    $null = $sb.AppendLine("    return")
    $null = $sb.AppendLine("}")
    $null = $sb.AppendLine("Import-Module `$nrgModule -Force -ErrorAction Stop")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("# Load the matching assessment JSON FIRST so Apply-* dispatches can pass")
    $null = $sb.AppendLine("# the original Finding object (every Apply-NRG* function takes -Finding [object]).")
    $null = $sb.AppendLine("# The JSON sits next to this script: <baseName>-results.json where this")
    $null = $sb.AppendLine("# script's basename is <baseName>-remediation.")
    $null = $sb.AppendLine("# Running this BEFORE Connect-NRGServices means a missing/corrupt JSON")
    $null = $sb.AppendLine("# fails fast without paying the Graph/EXO authentication cost.")
    $null = $sb.AppendLine("`$scriptBase  = [System.IO.Path]::GetFileNameWithoutExtension(`$MyInvocation.MyCommand.Path)")
    $null = $sb.AppendLine("`$resultsBase = `$scriptBase -replace '-remediation`$',''")
    $null = $sb.AppendLine("`$resultsJson = Join-Path `$scriptDir (`"`$resultsBase-results.json`")")
    $null = $sb.AppendLine("if (-not (Test-Path -LiteralPath `$resultsJson)) {")
    $null = $sb.AppendLine("    Write-Error (`"Assessment results not found at `" + `$resultsJson + `". This script needs the original -results.json from the same run to pass Finding objects into Apply-* functions.`")")
    $null = $sb.AppendLine("    return")
    $null = $sb.AppendLine("}")
    $null = $sb.AppendLine("try {")
    $null = $sb.AppendLine("    `$assessment = Get-Content -LiteralPath `$resultsJson -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop")
    $null = $sb.AppendLine("} catch {")
    $null = $sb.AppendLine("    Write-Error (`"Failed to parse `" + `$resultsJson + `": `" + `$_.Exception.Message + `". The JSON may be truncated or corrupt; re-run Invoke-NRGAssessment to regenerate.`")")
    $null = $sb.AppendLine("    return")
    $null = $sb.AppendLine("}")
    $null = $sb.AppendLine("if (`$null -eq `$assessment -or -not `$assessment.PSObject.Properties['Findings'] -or `$null -eq `$assessment.Findings) {")
    $null = $sb.AppendLine("    Write-Error (`"Findings array missing from `" + `$resultsJson + `". The results JSON is the wrong shape; re-run Invoke-NRGAssessment to regenerate.`")")
    $null = $sb.AppendLine("    return")
    $null = $sb.AppendLine("}")
    $null = $sb.AppendLine("`$findingsByCtrl = @{}")
    $null = $sb.AppendLine("`$findingIndex = 0")
    $null = $sb.AppendLine("foreach (`$fnd in `$assessment.Findings) {")
    $null = $sb.AppendLine("    `$findingIndex++")
    $null = $sb.AppendLine("    if (`$null -eq `$fnd -or -not `$fnd.PSObject.Properties['ControlId'] -or [string]::IsNullOrWhiteSpace([string]`$fnd.ControlId)) {")
    $null = $sb.AppendLine("        Write-Error (`"Finding #`" + `$findingIndex + `" in `" + `$resultsJson + `" is missing a non-empty ControlId. The results JSON may be truncated, corrupt, or the wrong shape; re-run Invoke-NRGAssessment to regenerate.`")")
    $null = $sb.AppendLine("        return")
    $null = $sb.AppendLine("    }")
    $null = $sb.AppendLine("    `$findingsByCtrl[`$fnd.ControlId] = `$fnd")
    $null = $sb.AppendLine("}")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("# Authenticate. The Apply-* dispatch needs whichever services the gaps")
    $null = $sb.AppendLine("# touch — Connect-NRGServices figures that out and reuses any existing")
    $null = $sb.AppendLine("# session. Edit the -UserPrincipalName if you'd rather pin to a different")
    $null = $sb.AppendLine("# operator account.")
    $null = $sb.AppendLine("Connect-NRGServices -UserPrincipalName '$opUPNC' -ErrorAction Stop | Out-Null")
    $null = $sb.AppendLine("")

    # Phase-based section header helper
    function PhaseHeader { param($n, $sev, $count)
        $lines = @()
        $lines += ""
        $lines += "# ─────────────────────────────────────────────────────────────────────"
        $lines += "# PHASE $n — $sev ($count items)"
        $lines += "# ─────────────────────────────────────────────────────────────────────"
        $lines += ""
        return $lines
    }

    function Write-GapBlock {
        param([object]$f, [hashtable]$controlDefs, [string]$phaseNum, [string]$clientLiteral, [object]$licenseProfile)
        $lines = @()
        $ctrl  = $controlDefs[$f.ControlId]
        $remedy = if ($ctrl -and $ctrl.Remediation) { $ctrl.Remediation } else { '# No automated remediation available — see portal guidance.' }
        $bizRisk = if ($ctrl -and $ctrl.BusinessRisk) { $ctrl.BusinessRisk } else { $f.Detail }

        # Comment-safe forms (strip newlines so values cannot break out of a
        # single-line PowerShell comment in the generated script).
        $ctrlIdC    = EscPs1Comment $f.ControlId
        $titleC     = EscPs1Comment $f.Title
        $sevC       = EscPs1Comment $f.Severity
        $bizRiskC   = EscPs1Comment $bizRisk
        $currValC   = EscPs1Comment $f.CurrentValue
        $categoryC  = EscPs1Comment $f.Category
        $licReqC    = if ($ctrl -and $ctrl.LicenseRequirement) { EscPs1Comment $ctrl.LicenseRequirement } else { '' }

        # Single-quoted-literal-safe forms (double any ' so values cannot break
        # out of a '...'  PowerShell literal in the generated script).
        $ctrlIdL    = EscPs1Literal $f.ControlId
        # v4.11.1: dropped unused $titleL (the Title was rendered via the
        # raw $f.Title interpolation downstream, not via this escaped form).
        # Workload prefix: strip everything after the first hyphen+digit (per the
        # original logic) and then strip to safe charset — defense in depth.
        $workloadL  = ([string]$f.ControlId) -replace '-\d.*$',''
        $workloadL  = $workloadL -replace "[^A-Za-z0-9_]", ''

        # Emit "# REQUIRES: ..." ONLY when the tenant does NOT already hold
        # the license. v4.6.1 emitted this unconditionally, which produced
        # "# REQUIRES: M365 Business Premium" comments on Business Premium
        # tenants — misleading the operator into thinking the tool had not
        # detected their license. The license profile is computed once at the
        # top of the publisher and threaded through here.
        $licHeld = $false
        if ($ctrl -and $ctrl.LicenseRequirement) {
            $licHeld = if ($licenseProfile -and $licenseProfile.SuppressedLicenseRequirements) {
                [bool]$licenseProfile.SuppressedLicenseRequirements.Contains($ctrl.LicenseRequirement)
            } else { $false }
        }
        $licReq = if ($ctrl -and $ctrl.LicenseRequirement -and
                      $ctrl.LicenseRequirement -notmatch '^Included' -and
                      -not $licHeld) {
            "# REQUIRES: $licReqC"
        } else { $null }

        # Dispatch table — controls with a built-in Apply-* function. Must stay
        # in lockstep with $script:NRGApplyDispatch in Apply-NRGBaseline.ps1.
        # Adding a new dispatch entry there + adding the line here is the full
        # set of changes needed when a new Apply-* script lands.
        $dispatch = @{
            'AAD-1.1' = 'Apply-NRGAADLegacyAuth'
            'AAD-2.1' = 'Apply-NRGAADMFA'
            'EXO-1.1' = 'Apply-NRGEXOMailboxAudit'
            'EXO-1.2' = 'Apply-NRGEXOSmtpAuth'
            'EXO-1.3' = 'Apply-NRGEXOAutoForward'
            'DEF-1.1' = 'Apply-NRGDefenderPreset'
        }
        $applyFn = $dispatch[$f.ControlId]

        $lines += "# ── $ctrlIdC`: $titleC [$sevC]"
        $lines += "# Risk: $bizRiskC"
        if ($f.CurrentValue) { $lines += "# Current: $currValC" }
        if ($licReq) { $lines += $licReq }
        $lines += "# Phase: $phaseNum | Category: $categoryC"
        $lines += ""

        $lines += "if (`$Phase -in @('$phaseNum','all') -and `$Workload -in @('$workloadL','all')) {"

        if ($applyFn) {
            # Mapped to an Apply-* script — dispatch through the module.
            # SupportsShouldProcess on the outer script means -WhatIf and
            # -Confirm flow through to the Apply-* function automatically.
            $lines += "    Write-Host '  -> $ctrlIdL ($applyFn)' -ForegroundColor Cyan"
            # Look up the finding object from the loaded JSON — Apply-* requires
            # -Finding [object] (mandatory). Falling back to a synthetic object
            # would mask the real finding state from the Apply function's logic.
            $lines += "    `$fnd = `$findingsByCtrl['$ctrlIdL']"
            $lines += "    if (-not `$fnd) {"
            $lines += "        Write-Host '     [!] finding not in results.json — skipping' -ForegroundColor Yellow"
            $lines += "    } else {"
            $lines += "        try {"
            $lines += "            $applyFn -Finding `$fnd -ErrorAction Stop"
            $lines += "            Write-Host '     [+] applied' -ForegroundColor Green"
            $lines += "        } catch {"
            $lines += "            Write-Host (`"     [!] failed: `" + `$_.Exception.Message) -ForegroundColor Red"
            $lines += "        }"
            $lines += "    }"
        } else {
            # No Apply-* mapping — emit instruction as a comment block so the
            # operator sees what to do without the script claiming success.
            # No fake "[+] Applied" Write-Host. Print the instruction so it
            # shows up in the run log.
            $lines += "    Write-Host '  -> $ctrlIdL (manual)' -ForegroundColor Yellow"
            foreach ($remedyLine in ($remedy -split '\r?\n')) {
                $trimmed = $remedyLine.Trim()
                if (-not $trimmed) { continue }
                $safe = EscPs1Literal $trimmed
                $lines += "    Write-Host '     $safe' -ForegroundColor Gray"
            }
            $lines += "    Write-Host '     (manual remediation — no Apply-* function for this control yet)' -ForegroundColor DarkGray"
        }

        $lines += "}"
        $lines += ""
        return $lines
    }

    # Phase 1
    foreach ($line in (PhaseHeader -n 1 -sev 'CRITICAL + HIGH — Address Immediately' -count $phase1Gaps.Count)) {
        $null = $sb.AppendLine($line)
    }
    foreach ($f in $phase1Gaps) {
        foreach ($line in (Write-GapBlock -f $f -controlDefs $controls -phaseNum '1' -clientLiteral $client -licenseProfile $licProfile)) {
            $null = $sb.AppendLine($line)
        }
    }

    # Phase 2
    foreach ($line in (PhaseHeader -n 2 -sev 'MEDIUM — Address Within 30 Days' -count $phase2Gaps.Count)) {
        $null = $sb.AppendLine($line)
    }
    foreach ($f in $phase2Gaps) {
        foreach ($line in (Write-GapBlock -f $f -controlDefs $controls -phaseNum '2' -clientLiteral $client -licenseProfile $licProfile)) {
            $null = $sb.AppendLine($line)
        }
    }

    # Phase 3
    foreach ($line in (PhaseHeader -n 3 -sev 'LOW — Hardening Pass' -count $phase3Gaps.Count)) {
        $null = $sb.AppendLine($line)
    }
    foreach ($f in $phase3Gaps) {
        foreach ($line in (Write-GapBlock -f $f -controlDefs $controls -phaseNum '3' -clientLiteral $client -licenseProfile $licProfile)) {
            $null = $sb.AppendLine($line)
        }
    }

    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("Write-Host ''")
    $null = $sb.AppendLine("Write-Host 'Remediation script complete.' -ForegroundColor Cyan")
    $null = $sb.AppendLine("Write-Host 'Re-run NRG-Assessment to validate changes.' -ForegroundColor Cyan")

    # Publisher self-hardens via Set-NRGSensitiveFileContent: the file is
    # pre-created and its ACL applied BEFORE tenant data lands. Writing with a
    # bare Out-File lets the file inherit the parent directory ACL for the
    # duration of the write, which on a shared MSP workstation or a synced
    # OneDrive folder is a window in which a co-resident process can read CA
    # policies, admin UPNs, OAuth grants and DMARC records. Hardening travels
    # with the terminal write so no caller can forget it. The Out-File fallback
    # preserves behavior if Lib/ has not been dot-sourced.
    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $OutputPath -Content $sb.ToString()
    } else {
        $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8
        if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileAcl -Path $OutputPath -ErrorAction SilentlyContinue
        }
    }
}
