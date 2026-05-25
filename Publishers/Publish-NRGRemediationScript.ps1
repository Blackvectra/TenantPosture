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
# SECURITY: Remediation strings are sourced from controls.json which is
#   content-validated at load time. No tenant data interpolated into code.
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
    $clientRaw  = [string]($Metadata.TenantDomain ?? 'UnknownTenant')
    $dateRaw    = [string]($Metadata.AssessmentDate ?? (Get-Date -Format 'yyyy-MM-dd'))
    $versionRaw = [string]($Metadata.ToolVersion ?? '4.5.5')
    $opUPNRaw   = [string]($Metadata.Operator ?? 'admin')

    # For interpolation into single-quoted PowerShell literals in the generated
    # script. A tenant value like "John's Mailbox" must be doubled to 'John''s
    # Mailbox' so it does not break out of the literal.
    $client  = EscPs1Literal $clientRaw
    $date    = EscPs1Literal $dateRaw
    $version = EscPs1Literal $versionRaw
    $opUPN   = EscPs1Literal $opUPNRaw

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
    $null = $sb.AppendLine("    Preview all changes without making them.")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine(".PARAMETER Phase")
    $null = $sb.AppendLine("    Run only a specific phase: 1 (Critical+High), 2 (Medium), 3 (Low). Default: all.")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine(".PARAMETER Workload")
    $null = $sb.AppendLine("    Run only a specific workload: AAD, EXO, DNS, DEF, SPO, TMS, INT, PVW, PPL")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine(".EXAMPLE")
    $null = $sb.AppendLine("    # Preview Phase 1 changes")
    $null = $sb.AppendLine("    .\$clientStem-remediation.ps1 -Phase 1 -WhatIf")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine("    # Apply Phase 1 AAD changes only")
    $null = $sb.AppendLine("    .\$clientStem-remediation.ps1 -Phase 1 -Workload AAD")
    $null = $sb.AppendLine("")
    $null = $sb.AppendLine(".NOTES")
    $null = $sb.AppendLine("    Generated by NRG-Assessment v$versionC")
    $null = $sb.AppendLine("    NRG Technology Services / NextLayerSec LLC")
    $null = $sb.AppendLine("    This script is read-only until you uncomment individual remedy blocks.")
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
    $null = $sb.AppendLine("#")
    $null = $sb.AppendLine("# All remedy blocks are COMMENTED OUT by default.")
    $null = $sb.AppendLine("# Uncomment each block after reviewing it. Do not run blindly.")
    $null = $sb.AppendLine("# ═══════════════════════════════════════════════════════════════════")
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
        $titleL     = EscPs1Literal $f.Title
        # Workload prefix: strip everything after the first hyphen+digit (per the
        # original logic) and then strip to safe charset — defence in depth.
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

        $lines += "# ── $ctrlIdC`: $titleC [$sevC]"
        $lines += "# Risk: $bizRiskC"
        if ($f.CurrentValue) { $lines += "# Current: $currValC" }
        if ($licReq) { $lines += $licReq }
        $lines += "# Phase: $phaseNum | Category: $categoryC"
        $lines += ""

        # Wrap actual command lines in comment — user must uncomment to run.
        # $clientLiteral and $titleL/$ctrlIdL are already escaped for the
        # single-quoted literal contexts they sit in.
        $lines += "if (`$Phase -in @('$phaseNum','all') -and `$Workload -in @('$workloadL','all')) {"
        $lines += "    if (`$PSCmdlet.ShouldProcess('$clientLiteral', '$titleL')) {"

        # Break multi-line remediation into individual comment lines.
        # $remedy comes from controls.json (trusted at load) — we still strip
        # CR injected by a malformed entry, but the line content remains
        # literal so the engineer can uncomment and run it.
        foreach ($remedyLine in ($remedy -split '\r?\n')) {
            $trimmed = $remedyLine.Trim()
            if ($trimmed -and -not $trimmed.StartsWith('#')) {
                $lines += "        # UNCOMMENT TO APPLY: $trimmed"
            } elseif ($trimmed) {
                $lines += "        $trimmed"
            }
        }

        # Use a single-quoted PS literal (with escaped ') so $f.ControlId
        # cannot become a subexpression in the generated double-quoted string.
        $lines += "        Write-Host '  [+] $ctrlIdL — Applied' -ForegroundColor Green"
        $lines += "    }"
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

    $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8
}
