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
        [Parameter(Mandatory)] [string]    $ExecutivePath,
        [string]                           $HtmlOutputPath
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
        # Markdown-safe only: escape characters that break table or code-span
        # structure. Do NOT HTML-escape — that produced visible `&gt;` and
        # `&#39;` in playbook/executive output. XSS escaping belongs at the
        # markdown→HTML render boundary, not in the markdown source.
        $safe = [string]$v
        $safe = $safe -replace '\|', '\|' -replace '`', '\`' -replace '[\r\n]+', ' '
        return $safe
    }

    # Get-NRGObjectField, not dot-access-then-??: see Publish-NRGAssessmentSummary.
    $client    = EscMd ([string](Get-NRGObjectField -Item $Metadata -Key 'TenantDomain'   -Default 'Client'))
    $date      = EscMd ([string](Get-NRGObjectField -Item $Metadata -Key 'AssessmentDate' -Default (Get-Date -Format 'MMMM dd, yyyy')))
    $fallbackVer = if ($script:NRGAssessmentVersion) { [string]$script:NRGAssessmentVersion } else { 'unknown' }
    $version   = EscMd ([string](Get-NRGObjectField -Item $Metadata -Key 'ToolVersion'    -Default $fallbackVer))

    # Load control definitions for remediation text and license requirements
    $controls = @{}
    try {
        $allCtrls = Get-NRGControlDefinitions
        foreach ($c in $allCtrls) { $controls[$c.ControlId] = $c }
    } catch { }

    # Tenant license profile — suppress 🔑 / "Requires:" annotations and the
    # License Upgrades Required callout when the tenant already owns the
    # license. v4.6.1 emitted these unconditionally from controls.json
    # LicenseRequirement and counted held licenses as "upgrades required".
    $licProfile = if (Get-Command Get-NRGTenantLicenseProfile -ErrorAction SilentlyContinue) {
        try { Get-NRGTenantLicenseProfile } catch { $null }
    } else { $null }
    # The finding goes along: a Security Defaults verdict whose remaining fix
    # needs no license (Test-NRGSecurityDefaultsLicenseFree) is not an upgrade.
    $licHeld = {
        param($req, $cid, $finding)
        return [bool](Test-NRGLicenseRequirementMet -LicenseRequirement $req -LicenseProfile $licProfile -ControlId $cid -Finding $finding)
    }

    # Gap findings only, sorted by severity priority
    $sevOrder = @{ 'Critical' = 0; 'High' = 1; 'Medium' = 2; 'Low' = 3; 'Informational' = 4 }
    # The whole pipeline sits inside @(): Sort-Object over zero or one object returns
    # $null or a bare object, and StrictMode throws on `.Count` of either.
    $gaps     = @(@($Findings | Where-Object { $_.State -eq 'Gap' }) |
                Sort-Object { $sevOrder[$_.Severity] ?? 99 }, Category, ControlId)

    $phase1 = @($gaps | Where-Object { $_.Severity -in @('Critical','High') })
    $phase2 = @($gaps | Where-Object { $_.Severity -eq 'Medium' })
    $phase3 = @($gaps | Where-Object { $_.Severity -eq 'Low' })
    $partials = @(@($Findings | Where-Object { $_.State -eq 'Partial' }) |
                Sort-Object { $sevOrder[$_.Severity] ?? 99 })

    # ── ENGINEER PLAYBOOK ─────────────────────────────────────────────────────
    $sb = [System.Text.StringBuilder]::new()

    $null = $sb.AppendLine("# M365 Security Remediation Playbook")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**Client:** $client  ")
    $null = $sb.AppendLine("**Assessment Date:** $date  ")
    $null = $sb.AppendLine("**Prepared by:** NRG Technology Services / NextLayerSec LLC  ")
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

    # Contents — operator-friendly navigation. GitHub / VS Code / Pandoc all
    # honor heading-anchor links of the form #section-name in lowercase with
    # spaces→hyphens.
    $null = $sb.AppendLine("## Contents")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("- [Phase 1 — Immediate Action (Week 1–2)](#phase-1--immediate-action-week-12) — $($phase1.Count) Critical + High")
    $null = $sb.AppendLine("- [Phase 2 — Near-Term Improvements (Week 2–4)](#phase-2--near-term-improvements-week-24) — $($phase2.Count) Medium")
    $null = $sb.AppendLine("- [Phase 3 — Hardening (Month 2–3)](#phase-3--hardening-month-23) — $($phase3.Count) Low")
    $null = $sb.AppendLine("- [Partial Configurations — Complete These](#partial-configurations--complete-these)")
    $null = $sb.AppendLine()

    # Quick action checklist — every Phase 1 item as a one-line ticket the
    # operator can copy into a tracker. Surfaces what to do without forcing
    # them to scroll through 28 templated sections first.
    if ($phase1.Count -gt 0) {
        $null = $sb.AppendLine("## Phase 1 Checklist (copy to tracker)")
        $null = $sb.AppendLine()
        foreach ($f in $phase1) {
            $null = $sb.AppendLine("- [ ] **$(EscMd $f.ControlId)** — $(EscMd $f.Title)")
        }
        $null = $sb.AppendLine()
    }

    # License upgrade callout — only count gaps whose license is NOT already
    # held. v4.6.1 ignored the tenant's actual licenses and listed every
    # license-tagged gap as "needs upgrade".
    $upgradeNeeded = @($gaps | Where-Object {
        $c = $controls[$_.ControlId]
        $c -and $c.LicenseRequirement -and
        $c.LicenseRequirement -notmatch '^Included' -and
        -not (& $licHeld $c.LicenseRequirement $_.ControlId $_)
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
        param([object]$f, [int]$num, [hashtable]$controlDefs, [object]$licenseProfile)
        $lines = [System.Collections.Generic.List[string]]::new()
        $ctrl  = $controlDefs[$f.ControlId]
        # Suppress license badge + note when the tenant already holds the
        # license. The 🔑 marker should mean "this gap requires a license you
        # do not have" — on a BP tenant it must not show for BP-gated controls.
        $needsLicUpgrade = $false
        if ($ctrl -and $ctrl.LicenseRequirement -and $ctrl.LicenseRequirement -notmatch '^Included') {
            $needsLicUpgrade = -not (Test-NRGLicenseRequirementMet -LicenseRequirement $ctrl.LicenseRequirement -LicenseProfile $licenseProfile -ControlId $f.ControlId -Finding $f)
        }
        $licFlag = if ($needsLicUpgrade) { ' 🔑' } else { '' }
        $licNote = if ($needsLicUpgrade) { "  > **Requires:** $(EscMd $ctrl.LicenseRequirement)  " } else { '' }

        $lines.Add("### $num. $(EscMd $f.ControlId) — $(EscMd $f.Title)$licFlag")
        $lines.Add("")
        if ($licNote) { $lines.Add($licNote); $lines.Add("") }
        $lines.Add("**Risk:** $(EscMd $f.Detail)")
        $lines.Add("")
        if ($f.CurrentValue) { $lines.Add("**Current state:** ``$(EscMd $f.CurrentValue)``  ") }
        if ($f.RequiredValue) { $lines.Add("**Required state:** ``$(EscMd $f.RequiredValue)``  ") }
        $lines.Add("")

        # Remediation. The finding's own when it carries one for its state
        # (Security Defaults: the move to Conditional Access), else the
        # control's (Get-NRGFindingRemediation). The Security Defaults
        # transition is prose, so it is written as a paragraph and only the
        # control-specific step after it goes through the code-fence test.
        $remedy = Get-NRGFindingRemediation -Finding $f -Control $ctrl
        $sdLead = [string]$script:NRGSecurityDefaultsTransition
        if ($remedy -and $sdLead -and $remedy.StartsWith($sdLead, [System.StringComparison]::Ordinal)) {
            $lines.Add("**Before anything else:** $(EscMd $sdLead)  ")
            $lines.Add("")
            $remedy = ($remedy.Substring($sdLead.Length) -replace '^\s*For this control:\s*', '').Trim()
        }
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

        # Framework citations and per-item estimated time intentionally omitted —
        # citations belong in the audit-evidence artifact (assessment.md), and
        # the phase summary table at the top of the playbook already shows
        # aggregate time per phase. Per-item repetition added wall-of-text
        # noise that made the playbook hostile to read during remediation.
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
            foreach ($line in (Write-FindingSection -f $f -num $n -controlDefs $controls -licenseProfile $licProfile)) {
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
            foreach ($line in (Write-FindingSection -f $f -num $n -controlDefs $controls -licenseProfile $licProfile)) {
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
            foreach ($line in (Write-FindingSection -f $f -num $n -controlDefs $controls -licenseProfile $licProfile)) {
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
    $null = $sb.AppendLine("*Remediation playbook generated by NRG-Assessment v$version · NRG Technology Services / NextLayerSec LLC · $date*  ")
    $null = $sb.AppendLine("*All remediation steps should be tested in a non-production environment or during a maintenance window.*")

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

    # ── EXECUTIVE SUMMARY ─────────────────────────────────────────────────────
    # v4.10.1: pulled from the canonical helper. -ErrorHandling Gap preserves
    # the historical Playbook semantics (Error in the denominator).
    $cov     = Get-NRGCoverageScore -Findings $Findings -ErrorHandling 'Gap'
    $sat     = $cov.Satisfied
    $partial = $cov.Partial
    $gap     = $cov.Gap
    $na      = $cov.NA
    $total   = $cov.Total
    $score   = $cov.Score
    # v4.10.1: rewritten from `switch ($true)` to if/elseif. Switch had the
    # same fallthrough hazard the Summary publisher fixed earlier — all
    # matching arms accumulate, so $posture was secretly an array (e.g.
    # @('Strong','Moderate','At Risk') for any score >= 85). Visible bug
    # in the executive markdown for any tenant scoring above 40.
    $posture = if     ($score -ge 85) { 'Strong'   }
               elseif ($score -ge 65) { 'Moderate' }
               elseif ($score -ge 40) { 'At Risk'  }
               else                   { 'Critical Risk' }

    $exec = [System.Text.StringBuilder]::new()
    $null = $exec.AppendLine("# Microsoft 365 Security Assessment — Executive Summary")
    $null = $exec.AppendLine()
    $null = $exec.AppendLine("**Organization:** $client  ")
    $null = $exec.AppendLine("**Date:** $date  ")
    $null = $exec.AppendLine("**Prepared by:** NRG Technology Services / NextLayerSec LLC  ")
    $null = $exec.AppendLine()
    $null = $exec.AppendLine("---")
    $null = $exec.AppendLine()
    $null = $exec.AppendLine("## Overall Security Posture: $posture ($score/100)")
    $null = $exec.AppendLine()

    # Bottom-line one-liner — what the score actually means for the business.
    $bottomLine = switch ($posture) {
        'Strong'        { "Posture is strong. Continue current operations; reassess in 12 months." }
        'Moderate'      { "Several gaps weaken otherwise-sound controls. Address Phase 1 items within 30 days to materially reduce risk." }
        'At Risk'       { "Tenant is exposed to common attack patterns (BEC, ransomware staging, credential theft). Phase 1 remediation should begin this week." }
        'Critical Risk' { "Tenant is one credential compromise away from a material incident. Phase 1 remediation is urgent." }
        default         { '' }
    }
    if ($bottomLine) {
        $null = $exec.AppendLine("**Bottom line.** $bottomLine")
        $null = $exec.AppendLine()
    }

    $null = $exec.AppendLine("NRG Technology Services / NextLayerSec LLC conducted a read-only security assessment of the $client Microsoft 365 environment on $date. The assessment evaluated $total security controls across identity, email security, data protection, collaboration tools, and endpoint management.")
    $null = $exec.AppendLine()
    $null = $exec.AppendLine("| Result | Count | Meaning |")
    $null = $exec.AppendLine("|--------|-------|---------|")
    $null = $exec.AppendLine("| ✅ Meets Requirement | $sat | Control is properly configured |")
    $null = $exec.AppendLine("| ⚠️ Partially Met | $partial | Control exists but needs improvement |")
    $null = $exec.AppendLine("| ❌ Gap Identified | $gap | Control is missing or misconfigured |")
    $null = $exec.AppendLine("| — Not scored | $na | Does not apply to this environment, or could not be assessed (unlicensed, not readable, or a manual check). Each says which in the full report |")
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
            # Surface current state where the evaluator captured it — gives the
            # exec recipient a one-line "how bad is it right now" anchor before
            # the business-risk explanation.
            if ($f.CurrentValue) {
                $null = $exec.AppendLine("*Current state:* $(EscMd $f.CurrentValue)  ")
            }
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
        $null = $exec.AppendLine("NRG Technology Services / NextLayerSec LLC can provide a licensing upgrade proposal as a follow-up to this assessment.")
        $null = $exec.AppendLine()
    }

    # Recommended next steps
    $null = $exec.AppendLine("## Recommended Next Steps")
    $null = $exec.AppendLine()
    $null = $exec.AppendLine("1. **Phase 1 Remediation (Week 1–2)** — Address the $($phase1.Count) Critical and High severity gaps identified in the attached remediation playbook. NRG Technology Services / NextLayerSec LLC can implement these changes as a managed service engagement.")
    $null = $exec.AppendLine("2. **Phase 2 Remediation (Week 2–4)** — Address the $($phase2.Count) Medium severity items.")
    # Step 3 — only emitted when a license upgrade actually unlocks gaps. On a
    # tenant that already owns BP / E5, $upgradeNeeded is empty and step 3 is
    # skipped (the previous behavior stated "0 controls currently blocked").
    if ($upgradeNeeded.Count -gt 0) {
        $null = $exec.AppendLine("3. **License Review** — Review licensing to address the $($upgradeNeeded.Count) control(s) currently blocked by the current license tier.")
        $null = $exec.AppendLine("4. **Reassessment** — Schedule a follow-up assessment in 90 days to validate remediation and track improvement.")
    } else {
        $null = $exec.AppendLine("3. **Reassessment** — Schedule a follow-up assessment in 90 days to validate remediation and track improvement.")
    }
    $null = $exec.AppendLine()
    $null = $exec.AppendLine("---")
    $null = $exec.AppendLine("*This assessment was conducted using read-only access to the $client Microsoft 365 environment. No changes were made. Assessment framework: CIS M365 Foundations Benchmark v6.0.1, CISA SCuBA, NIST SP 800-53 Rev 5.*  ")
    $null = $exec.AppendLine("*NRG Technology Services / NextLayerSec LLC · $date*")

    # Publisher self-hardens via Set-NRGSensitiveFileContent: the file is
    # pre-created and its ACL applied BEFORE tenant data lands. Writing with a
    # bare Out-File lets the file inherit the parent directory ACL for the
    # duration of the write, which on a shared MSP workstation or a synced
    # OneDrive folder is a window in which a co-resident process can read CA
    # policies, admin UPNs, OAuth grants and DMARC records. Hardening travels
    # with the terminal write so no caller can forget it. The Out-File fallback
    # preserves behavior if Lib/ has not been dot-sourced.
    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $ExecutivePath -Content $exec.ToString()
    } else {
        $exec.ToString() | Out-File -LiteralPath $ExecutivePath -Encoding utf8
        if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileAcl -Path $ExecutivePath -ErrorAction SilentlyContinue
        }
    }

    # HTML playbook — same data, render-friendly format. Operator opens in a
    # browser, can ctrl-F per ControlId, can print to PDF for client delivery.
    # Strict CSP via meta + Trusted Types; CSS inlined; no external assets so
    # the file is self-contained and works offline.
    if ($HtmlOutputPath) {
        # Build deterministic HTML — no JS framework, no external fonts. The
        # only inline script is the simple Trusted Types policy declaration
        # required by the CSP.
        function EscHtml([object]$v) {
            if ($null -eq $v) { return '' }
            return ([string]$v) `
                -replace '&', '&amp;' `
                -replace '<', '&lt;'  `
                -replace '>', '&gt;'  `
                -replace '"', '&quot;' `
                -replace "'", '&#39;'
        }

        $html = [System.Text.StringBuilder]::new()
        $null = $html.AppendLine('<!doctype html>')
        $null = $html.AppendLine('<html lang="en"><head><meta charset="utf-8">')
        $null = $html.AppendLine('<meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''; img-src data:; base-uri ''none''; form-action ''none''; frame-ancestors ''none''; require-trusted-types-for ''script''">')
        $titleSafe = EscHtml "$client — Remediation Playbook"; $null = $html.AppendLine("<title>$titleSafe</title>")
        $null = $html.AppendLine('<style>')
        $null = $html.AppendLine('  *{box-sizing:border-box} body{font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif;color:#111;background:#fafafa;margin:0;padding:0}')
        $null = $html.AppendLine('  .wrap{max-width:980px;margin:0 auto;padding:32px 24px}')
        $null = $html.AppendLine('  h1{font-size:28px;margin:0 0 6px}  h2{font-size:22px;margin:36px 0 14px;padding-top:12px;border-top:2px solid #e3e6ea}  h3{font-size:17px;margin:24px 0 8px}')
        $null = $html.AppendLine('  .meta{color:#5a6470;font-size:14px;margin-bottom:24px}')
        $null = $html.AppendLine('  table{border-collapse:collapse;width:100%;margin:8px 0 18px;font-size:14px}  th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e3e6ea;vertical-align:top}  th{background:#f3f5f7;font-weight:600}')
        $null = $html.AppendLine('  .toc a{display:block;padding:4px 0;color:#1a3a6b;text-decoration:none}  .toc a:hover{text-decoration:underline}')
        $null = $html.AppendLine('  .item{background:#fff;border:1px solid #e3e6ea;border-left:4px solid #ccc;border-radius:6px;padding:14px 18px;margin:10px 0}')
        $null = $html.AppendLine('  .item.critical{border-left-color:#c0392b}  .item.high{border-left-color:#e67e22}  .item.medium{border-left-color:#f1c40f}  .item.low{border-left-color:#3498db}')
        $null = $html.AppendLine('  .item .head{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:6px}  .item .cid{font-family:ui-monospace,Menlo,Consolas,monospace;color:#5a6470;font-size:13px}  .item .title{font-weight:600;font-size:16px}  .item .sev{font-size:11px;letter-spacing:.5px;text-transform:uppercase;color:#fff;background:#888;border-radius:3px;padding:2px 7px}  .item .sev.critical{background:#c0392b}  .item .sev.high{background:#e67e22}  .item .sev.medium{background:#b8860b}  .item .sev.low{background:#3498db}')
        $null = $html.AppendLine('  .item .lic{font-size:12px;background:#fff3cd;border:1px solid #ffe69c;color:#856404;padding:6px 10px;border-radius:4px;margin:6px 0;display:inline-block}')
        $null = $html.AppendLine('  .item .row{margin:6px 0}  .item .row b{display:inline-block;min-width:120px;color:#5a6470;font-weight:600}')
        $null = $html.AppendLine('  pre{background:#1f2937;color:#e6edf3;padding:10px 12px;border-radius:6px;overflow-x:auto;font-size:13px;line-height:1.45;margin:8px 0}')
        $null = $html.AppendLine('  code{background:#eef1f4;padding:2px 5px;border-radius:3px;font-size:90%}')
        $null = $html.AppendLine('  .phase-hdr{background:#1a3a6b;color:#fff;padding:14px 18px;border-radius:6px;margin:28px 0 14px}  .phase-hdr h2{margin:0;color:#fff;border:none;padding:0}')
        $null = $html.AppendLine('  .checklist li{margin:3px 0;list-style:none;padding-left:24px;position:relative}  .checklist li:before{content:"☐";position:absolute;left:0;color:#5a6470}')
        $null = $html.AppendLine('  @media print{body{background:#fff} .wrap{max-width:none;padding:14px} .item{break-inside:avoid;border-radius:0}}')
        $null = $html.AppendLine('</style></head><body><div class="wrap">')
        $null = $html.AppendLine('<script nonce="" type="application/javascript">if(window.trustedTypes&&trustedTypes.createPolicy){trustedTypes.createPolicy("default",{createHTML:s=>s})}</script>')

        $null = $html.AppendLine("<h1>M365 Security Remediation Playbook</h1>")
        $null = $html.AppendLine("<div class=`"meta`"><b>Client:</b> $(EscHtml $client) &middot; <b>Assessment Date:</b> $(EscHtml $date) &middot; <b>Tool:</b> NRG-Assessment v$(EscHtml $version)</div>")

        # Summary table
        $null = $html.AppendLine("<h2>Summary</h2>")
        $null = $html.AppendLine("<table><tr><th>Phase</th><th>Items</th><th>Severity</th><th>Estimated Time</th></tr>")
        $null = $html.AppendLine("<tr><td>Phase 1 &mdash; Immediate</td><td>$($phase1.Count)</td><td>Critical + High</td><td>~$p1Time hours</td></tr>")
        $null = $html.AppendLine("<tr><td>Phase 2 &mdash; Near-term</td><td>$($phase2.Count)</td><td>Medium</td><td>~$p2Time hours</td></tr>")
        $null = $html.AppendLine("<tr><td>Phase 3 &mdash; Hardening</td><td>$($phase3.Count)</td><td>Low</td><td>~$p3Time hours</td></tr>")
        $null = $html.AppendLine("<tr><td><b>Total gaps</b></td><td><b>$($gaps.Count)</b></td><td></td><td><b>~$($p1Time+$p2Time+$p3Time) hours</b></td></tr>")
        $null = $html.AppendLine("</table>")

        # TOC
        $null = $html.AppendLine("<h2>Contents</h2><div class=`"toc`">")
        $null = $html.AppendLine("<a href=`"#phase1`">Phase 1 &mdash; Immediate Action ($($phase1.Count) items)</a>")
        $null = $html.AppendLine("<a href=`"#phase2`">Phase 2 &mdash; Near-Term Improvements ($($phase2.Count) items)</a>")
        $null = $html.AppendLine("<a href=`"#phase3`">Phase 3 &mdash; Hardening ($($phase3.Count) items)</a>")
        $null = $html.AppendLine("</div>")

        # Phase 1 quick checklist
        if ($phase1.Count -gt 0) {
            $null = $html.AppendLine("<h2>Phase 1 Checklist</h2><ul class=`"checklist`">")
            foreach ($f in $phase1) {
                $null = $html.AppendLine("<li><b>$(EscHtml $f.ControlId)</b> &mdash; $(EscHtml $f.Title)</li>")
            }
            $null = $html.AppendLine("</ul>")
        }

        # Item renderer
        function Render-HtmlItem {
            param([object]$f, [hashtable]$controlDefs, [object]$licenseProfile, [scriptblock]$Esc)
            $ctrl = $controlDefs[$f.ControlId]
            $sevClass = ([string]$f.Severity).ToLower()
            $needsLic = $false
            if ($ctrl -and $ctrl.LicenseRequirement -and $ctrl.LicenseRequirement -notmatch '^Included') {
                $needsLic = -not (Test-NRGLicenseRequirementMet -LicenseRequirement $ctrl.LicenseRequirement -LicenseProfile $licenseProfile -ControlId $f.ControlId -Finding $f)
            }
            $bizRisk = if ($ctrl -and $ctrl.BusinessRisk) { $ctrl.BusinessRisk } elseif ($f.Detail) { $f.Detail } else { '' }
            $remedy  = Get-NRGFindingRemediation -Finding $f -Control $ctrl

            $out = @()
            $out += "<div class=`"item $sevClass`" id=`"$(& $Esc $f.ControlId)`">"
            $out += "<div class=`"head`"><span class=`"cid`">$(& $Esc $f.ControlId)</span><span class=`"title`">$(& $Esc $f.Title)</span><span class=`"sev $sevClass`">$(& $Esc $f.Severity)</span></div>"
            if ($needsLic) {
                $out += "<div class=`"lic`">&#128273; Requires: $(& $Esc $ctrl.LicenseRequirement)</div>"
            }
            if ($bizRisk)        { $out += "<div class=`"row`"><b>Risk</b> $(& $Esc $bizRisk)</div>" }
            if ($f.CurrentValue) { $out += "<div class=`"row`"><b>Current state</b> <code>$(& $Esc $f.CurrentValue)</code></div>" }
            if ($f.RequiredValue){ $out += "<div class=`"row`"><b>Required state</b> <code>$(& $Esc $f.RequiredValue)</code></div>" }
            if ($remedy) {
                if ($remedy -match 'Set-|New-|Enable-|Connect-|Get-|\$') {
                    $out += "<div class=`"row`"><b>Remediation</b></div><pre>$(& $Esc $remedy)</pre>"
                } else {
                    $out += "<div class=`"row`"><b>Remediation</b> $(& $Esc $remedy)</div>"
                }
            }
            $out += "</div>"
            return $out
        }
        $escFn = { param($v) EscHtml $v }

        $null = $html.AppendLine("<div class=`"phase-hdr`" id=`"phase1`"><h2>Phase 1 &mdash; Immediate Action (Week 1&ndash;2)</h2></div>")
        foreach ($f in $phase1) { foreach ($l in (Render-HtmlItem -f $f -controlDefs $controls -licenseProfile $licProfile -Esc $escFn)) { $null = $html.AppendLine($l) } }

        if ($phase2.Count -gt 0) {
            $null = $html.AppendLine("<div class=`"phase-hdr`" id=`"phase2`"><h2>Phase 2 &mdash; Near-Term Improvements (Week 2&ndash;4)</h2></div>")
            foreach ($f in $phase2) { foreach ($l in (Render-HtmlItem -f $f -controlDefs $controls -licenseProfile $licProfile -Esc $escFn)) { $null = $html.AppendLine($l) } }
        }
        if ($phase3.Count -gt 0) {
            $null = $html.AppendLine("<div class=`"phase-hdr`" id=`"phase3`"><h2>Phase 3 &mdash; Hardening (Month 2&ndash;3)</h2></div>")
            foreach ($f in $phase3) { foreach ($l in (Render-HtmlItem -f $f -controlDefs $controls -licenseProfile $licProfile -Esc $escFn)) { $null = $html.AppendLine($l) } }
        }

        $null = $html.AppendLine("<hr><div class=`"meta`">Generated by NRG-Assessment v$(EscHtml $version) &middot; $(EscHtml $date)</div>")
        $null = $html.AppendLine('</div></body></html>')

        # Publisher self-hardens via Set-NRGSensitiveFileContent: the file is
            # pre-created and its ACL applied BEFORE tenant data lands. Writing with a
            # bare Out-File lets the file inherit the parent directory ACL for the
            # duration of the write, which on a shared MSP workstation or a synced
            # OneDrive folder is a window in which a co-resident process can read CA
            # policies, admin UPNs, OAuth grants and DMARC records. Hardening travels
            # with the terminal write so no caller can forget it. The Out-File fallback
            # preserves behavior if Lib/ has not been dot-sourced.
        if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileContent -Path $HtmlOutputPath -Content $html.ToString()
        } else {
            $html.ToString() | Out-File -LiteralPath $HtmlOutputPath -Encoding utf8
            if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
                Set-NRGSensitiveFileAcl -Path $HtmlOutputPath -ErrorAction SilentlyContinue
            }
        }
        if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileAcl -Path $HtmlOutputPath -ErrorAction SilentlyContinue
        }
    }
}
