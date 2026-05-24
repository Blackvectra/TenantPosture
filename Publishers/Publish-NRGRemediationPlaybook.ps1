#Requires -Version 7.0
#
# Publish-NRGRemediationPlaybook.ps1  (v4.5.5)
# Generates a phased, client-ready remediation playbook from assessment findings.
#
# Output: Two documents
#   <tenant>-playbook.md      — Engineer-facing: copy-paste PowerShell, portal links, time estimates
#   <tenant>-executive.md     — Executive-facing: business language, priority table, ROI framing
#
# Phase structure:
#   Phase 1 (Week 1-2):   Critical + High gaps — immediate action required
#   Phase 2 (Week 2-4):   Medium gaps — address in next sprint
#   Phase 3 (Month 2-3):  Low gaps + hardening improvements
#
# SECURITY: All tenant data escaped before output (OWASP A10 / ASVS V5.1.3)
#

function Publish-NRGRemediationPlaybook {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Metadata,
        [Parameter(Mandatory)] [object[]]  $Findings,
        [Parameter(Mandatory)] [hashtable] $Connections,
        [Parameter(Mandatory)] [string]    $OutputPath,
        [Parameter(Mandatory)] [string]    $ExecutivePath
    )

    if (-not (Get-Command ConvertTo-NRGHtmlSafe -ErrorAction SilentlyContinue)) {
        throw "Refusing to generate playbook without ConvertTo-NRGHtmlSafe loaded."
    }

    # Helper: escape for Markdown (prevents table/header injection)
    # All tenant-sourced strings (control titles, details, branding, etc.) pass
    # through this before interpolation into Markdown. Without it, a value like
    # "| evil | injected" would break out of a table row, and backticks could
    # break out of inline code spans. OWASP A03 / ASVS V5.1.3.
    function EscMd([object]$v) {
        if ($null -eq $v -or [string]::IsNullOrEmpty([string]$v)) { return '' }
        $safe = ConvertTo-NRGHtmlSafe -Value ([string]$v)
        $safe = $safe -replace '\|', '\|' -replace '`', '\`'
        return $safe
    }

    $client    = EscMd ($Metadata.TenantDomain ?? 'Client')
    $date      = EscMd ($Metadata.AssessmentDate ?? (Get-Date -Format 'MMMM dd, yyyy'))
    $version   = EscMd ($Metadata.ToolVersion ?? '4.5.5')

    # Load control definitions for remediation text and license requirements
    $controls = @{}
    try {
        $allCtrls = Get-NRGControlDefinitions
        foreach ($c in $allCtrls) { $controls[$c.ControlId] = $c }
    } catch { }

    # Gap findings only, sorted by severity priority
    $sevOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Informational' = 4 }
    $gaps     = @($Findings | Where-Object { $_.State -eq 'Gap' }) |
                Sort-Object { $sevOrder[$_.Severity] ?? 99 }, Category, ControlId

    $phase1 = @($gaps | Where-Object { $_.Severity -in @('Critical','High') })
    $phase2 = @($gaps | Where-Object { $_.Severity -eq 'Medium' })
    $phase3 = @($gaps | Where-Object { $_.Severity -eq 'Low' })
    $partials = @($Findings | Where-Object { $_.State -eq 'Partial' }) |
                Sort-Object { $sevOrder[$_.Severity] ?? 99 }

    # ── ENGINEER PLAYBOOK ─────────────────────────────────────────────────────
    $sb = [System.Text.StringBuilder]::new()

    $null = $sb.AppendLine("# M365 Security Remediation Playbook")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**Client:** $client  ")
    $null = $sb.AppendLine("**Assessment Date:** $date  ")
    $null = $sb.AppendLine("**Prepared by:** NRG Technology Services  ")
    $null = $sb.AppendLine("**Tool Version:** NRG-Assessment v$version  ")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("> This playbook contains the specific remediation steps for every gap identified in the $client security assessment. Steps are ordered by priority. Each section includes the exact command to run, the portal location, estimated time, and how to validate the fix.")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine()

    # Summary table
    $null = $sb.AppendLine("## Summary")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("| Phase | Items | Severity | Estimated Time |")
    $null = $sb.AppendLine("|-------|-------|----------|----------------|")
    $p1Time = [int]($phase1.Count * 0.5) + 1
    $p2Time = [int]($phase2.Count * 0.5) + 1
    $p3Time = [int]($phase3.Count * 0.5) + 1
    $null = $sb.AppendLine("| Phase 1 — Immediate | $($phase1.Count) items | Critical + High | ~$p1Time hours |")
    $null = $sb.AppendLine("| Phase 2 — Near-term | $($phase2.Count) items | Medium | ~$p2Time hours |")
    $null = $sb.AppendLine("| Phase 3 — Hardening | $($phase3.Count) items | Low | ~$p3Time hours |")
    $null = $sb.AppendLine("| **Total gaps** | **$($gaps.Count)** | | **~$($p1Time+$p2Time+$p3Time) hours** |")
    $null = $sb.AppendLine()

    # License upgrade callout
    $upgradeNeeded = @($gaps | Where-Object {
        $c = $controls[$_.ControlId]
        $c -and $c.LicenseRequirement -and
        $c.LicenseRequirement -notmatch '^Included'
    })
    if ($upgradeNeeded.Count -gt 0) {
        $licenseGroups = $upgradeNeeded | ForEach-Object {
            $controls[$_.ControlId].LicenseRequirement
        } | Sort-Object -Unique
        $null = $sb.AppendLine("### ⚠️ License Upgrades Required")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("$($upgradeNeeded.Count) of the gaps below require a license upgrade to remediate:")
        $null = $sb.AppendLine()
        foreach ($lic in $licenseGroups) {
            $count = @($upgradeNeeded | Where-Object { $controls[$_.ControlId].LicenseRequirement -eq $lic }).Count
            $null = $sb.AppendLine("- **$(EscMd $lic)** — $count control(s)")
        }
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("Controls marked with 🔑 below require a license upgrade. Contact NRG to discuss licensing options.")
        $null = $sb.AppendLine()
    }

    # Helper to build a finding section
    function Write-FindingSection {
        param([object]$f, [int]$num, [hashtable]$controlDefs)
        $lines = [System.Collections.Generic.List[string]]::new()
        $ctrl  = $controlDefs[$f.ControlId]
        $licFlag = if ($ctrl -and $ctrl.LicenseRequirement -and $ctrl.LicenseRequirement -notmatch '^Included') { ' 🔑' } else { '' }
        $licNote = if ($ctrl -and $ctrl.LicenseRequirement -and $ctrl.LicenseRequirement -notmatch '^Included') { "  > **Requires:** $(EscMd $ctrl.LicenseRequirement)  " } else { '' }

        $lines.Add("### $num. $(EscMd $f.ControlId) — $(EscMd $f.Title)$licFlag")
        $lines.Add("")
        if ($licNote) { $lines.Add($licNote); $lines.Add("") }
        $lines.Add("**Risk:** $(EscMd $f.Detail)")
        $lines.Add("")
        if ($f.CurrentValue) { $lines.Add("**Current state:** ``$(EscMd $f.CurrentValue)``  ") }
        if ($f.RequiredValue) { $lines.Add("**Required state:** ``$(EscMd $f.RequiredValue)``  ") }
        $lines.Add("")

        # Remediation
        $remedy = if ($ctrl -and $ctrl.Remediation) { $ctrl.Remediation } elseif ($f.Remediation) { $f.Remediation } else { '' }
        if ($remedy) {
            $lines.Add("**Remediation:**  ")
            $lines.Add("")
            # If it looks like PowerShell, wrap in code block. We keep the
            # remediation text literal inside the fence (it's meant to be
            # copy-paste runnable), but neutralize any embedded triple-backtick
            # sequence that would break out of the fence.
            if ($remedy -match 'Set-|New-|Enable-|Connect-|Get-|\$') {
                $safeRemedy = ([string]$remedy) -replace '```', "``'``'``"
                $lines.Add('```powershell')
                $lines.Add($safeRemedy)
                $lines.Add('```')
            } else {
                $lines.Add((EscMd $remedy))
            }
            $lines.Add("")
        }

        # Framework citations
        if ($f.FrameworkIds -and @($f.FrameworkIds).Count -gt 0) {
            $citations = ($f.FrameworkIds | ForEach-Object { EscMd $_ }) -join ' · '
            $lines.Add("**Frameworks:** $citations  ")
            $lines.Add("")
        }

        # Estimated time
        $estTime = switch ($f.Severity) {
            'Critical' { '15–30 min' }
            'High'     { '15–30 min' }
            'Medium'   { '15–45 min' }
            'Low'      { '10–20 min' }
            default    { '15–30 min' }
        }
        $lines.Add("**Estimated time:** $estTime  ")
        $lines.Add("")
        $lines.Add("---")
        $lines.Add("")
        return $lines
    }

    # Phase 1
    if ($phase1.Count -gt 0) {
        $null = $sb.AppendLine("## Phase 1 — Immediate Action (Week 1–2)")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("> These $($phase1.Count) items are Critical or High severity. Address these first — they represent the highest risk to the $client tenant.")
        $null = $sb.AppendLine()
        $n = 1
        foreach ($f in $phase1) {
            foreach ($line in (Write-FindingSection -f $f -num $n -controlDefs $controls)) {
                $null = $sb.AppendLine($line)
            }
            $n++
        }
    }

    # Phase 2
    if ($phase2.Count -gt 0) {
        $null = $sb.AppendLine("## Phase 2 — Near-Term Improvements (Week 2–4)")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("> These $($phase2.Count) Medium-severity items should be addressed after Phase 1 is complete.")
        $null = $sb.AppendLine()
        $n = 1
        foreach ($f in $phase2) {
            foreach ($line in (Write-FindingSection -f $f -num $n -controlDefs $controls)) {
                $null = $sb.AppendLine($line)
            }
            $n++
        }
    }

    # Phase 3
    if ($phase3.Count -gt 0) {
        $null = $sb.AppendLine("## Phase 3 — Hardening (Month 2–3)")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("> These $($phase3.Count) Low-severity items complete the hardening pass after higher-priority items are resolved.")
        $null = $sb.AppendLine()
        $n = 1
        foreach ($f in $phase3) {
            foreach ($line in (Write-FindingSection -f $f -num $n -controlDefs $controls)) {
                $null = $sb.AppendLine($line)
            }
            $n++
        }
    }

    # Partial findings — already partially fixed, guidance to complete
    if ($partials.Count -gt 0) {
        $null = $sb.AppendLine("## Partial Configurations — Complete These")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine("| Control | Current State | Required |")
        $null = $sb.AppendLine("|---------|--------------|---------|")
        foreach ($f in ($partials | Select-Object -First 20)) {
            $null = $sb.AppendLine("| $(EscMd $f.ControlId) — $(EscMd $f.Title) | $(EscMd ($f.CurrentValue ?? 'See report')) | $(EscMd ($f.RequiredValue ?? 'See report')) |")
        }
        $null = $sb.AppendLine()
    }

    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine("*Remediation playbook generated by NRG-Assessment v$version · NRG Technology Services · $date*  ")
    $null = $sb.AppendLine("*All remediation steps should be tested in a non-production environment or during a maintenance window.*")

    $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8

    # ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
    $sat     = @($Findings | Where-Object State -eq 'Satisfied').Count
    $partial = @($Findings | Where-Object State -eq 'Partial').Count
    $gap     = @($Findings | Where-Object State -eq 'Gap').Count
    $na      = @($Findings | Where-Object State -eq 'NotApplicable').Count
    $total   = $Findings.Count
    $scored  = $sat + $partial + $gap
    $score   = if ($scored -gt 0) { [int](($sat + ($partial * 0.5)) / $scored * 100) } else { 0 }
    $posture = switch ($true) {
        { $score -ge 85 } { 'Strong' }
        { $score -ge 65 } { 'Moderate' }
        { $score -ge 40 } { 'At Risk' }
        default            { 'Critical Risk' }
    }

    $exec = [System.Text.StringBuilder]::new()
    $null = $exec.AppendLine("# Microsoft 365 Security Assessment — Executive Summary")
    $null = $exec.AppendLine()
    $null = $exec.AppendLine("**Organization:** $client  ")
    $null = $exec.AppendLine("**Date:** $date  ")
    $null = $exec.AppendLine("**Prepared by:** NRG Technology Services  ")
    $null = $exec.AppendLine()
    $null = $exec.AppendLine("---")
    $null = $exec.AppendLine()
    $null = $exec.AppendLine("## Overall Security Posture: $posture ($score/100)")
    $null = $exec.AppendLine()
    $null = $exec.AppendLine("NRG Technology Services conducted a read-only security assessment of the $client Microsoft 365 environment on $date. The assessment evaluated $total security controls across identity, email security, data protection, collaboration tools, and endpoint management.")
    $null = $exec.AppendLine()
    $null = $exec.AppendLine("| Result | Count | Meaning |")
    $null = $exec.AppendLine("|--------|-------|---------|")
    $null = $exec.AppendLine("| ✅ Meets Requirement | $sat | Control is properly configured |")
    $null = $exec.AppendLine("| ⚠️ Partially Met | $partial | Control exists but needs improvement |")
    $null = $exec.AppendLine("| ❌ Gap Identified | $gap | Control is missing or misconfigured |")
    $null = $exec.AppendLine("| — Not Applicable | $na | Control does not apply to this environment |")
    $null = $exec.AppendLine()

    # Top 5 most critical findings in business language
    $topFindings = @($phase1 | Select-Object -First 5)
    if ($topFindings.Count -gt 0) {
        $null = $exec.AppendLine("## Highest Priority Issues")
        $null = $exec.AppendLine()
        $null = $exec.AppendLine("The following issues represent the most immediate risk to $client and should be addressed within the next two weeks:")
        $null = $exec.AppendLine()
        $n = 1
        foreach ($f in $topFindings) {
            $ctrl = $controls[$f.ControlId]
            $bizRisk = if ($ctrl -and $ctrl.BusinessRisk) { $ctrl.BusinessRisk } else { $f.Detail }
            $null = $exec.AppendLine("**$n. $(EscMd $f.Title)**  ")
            $null = $exec.AppendLine("$(EscMd $bizRisk)  ")
            $null = $exec.AppendLine("")
            $n++
        }
    }

    # Licensing section
    if ($upgradeNeeded.Count -gt 0) {
        $null = $exec.AppendLine("## License Upgrade Opportunity")
        $null = $exec.AppendLine()
        $null = $exec.AppendLine("$($upgradeNeeded.Count) of the identified gaps cannot be remediated with the current license tier. Upgrading to M365 Business Premium would immediately resolve the most critical of these, including Safe Attachments, Safe Links, and Conditional Access with Intune device compliance — the controls most directly protecting against ransomware and business email compromise.")
        $null = $exec.AppendLine()
        $null = $exec.AppendLine("NRG Technology Services can provide a licensing upgrade proposal as a follow-up to this assessment.")
        $null = $exec.AppendLine()
    }

    # Recommended next steps
    $null = $exec.AppendLine("## Recommended Next Steps")
    $null = $exec.AppendLine()
    $null = $exec.AppendLine("1. **Phase 1 Remediation (Week 1–2)** — Address the $($phase1.Count) Critical and High severity gaps identified in the attached remediation playbook. NRG Technology Services can implement these changes as a managed service engagement.")
    $null = $exec.AppendLine("2. **Phase 2 Remediation (Week 2–4)** — Address the $($phase2.Count) Medium severity items.")
    $null = $exec.AppendLine("3. **License Review** — Review M365 Business Premium licensing to address the $($upgradeNeeded.Count) controls currently blocked by the current license tier.")
    $null = $exec.AppendLine("4. **Reassessment** — Schedule a follow-up assessment in 90 days to validate remediation and track improvement.")
    $null = $exec.AppendLine()
    $null = $exec.AppendLine("---")
    $null = $exec.AppendLine("*This assessment was conducted using read-only access to the $client Microsoft 365 environment. No changes were made. Assessment framework: CIS M365 Foundations Benchmark v6.0.1, CISA SCuBA, NIST SP 800-53 Rev 5.*  ")
    $null = $exec.AppendLine("*NRG Technology Services · Matthew Levorson, Security Engineer · $date*")

    $exec.ToString() | Out-File -LiteralPath $ExecutivePath -Encoding utf8
}
