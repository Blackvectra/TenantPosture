#
# Publish-NRGAssessmentSummary.ps1
# Generates a Markdown summary report from findings.
#
# This is the v4 baseline publisher - clean output, NRG-branded, suitable as a
# starting point for clients. Full HTML/Word publishers come in later sessions.
#

function Publish-NRGAssessmentSummary {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable]  $Metadata,
        [Parameter(Mandatory)] [object[]]   $Findings,
        [Parameter(Mandatory)] $Connections,
        [Parameter(Mandatory)] [string]     $OutputPath
    )

    $brand = $Metadata.Brand
    $sb = [System.Text.StringBuilder]::new()

    # Header
    [void]$sb.AppendLine("# Microsoft 365 Security Assessment")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("**Prepared for:** $($Metadata.TenantDomain)")
    [void]$sb.AppendLine("**Report Date:** $($Metadata.AssessmentDate)")
    [void]$sb.AppendLine("**Prepared by:** $($brand.CompanyName)")
    [void]$sb.AppendLine("**Tool Version:** NRG-Assessment v$($Metadata.ToolVersion)")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("---")
    [void]$sb.AppendLine("")

    # Summary counts
    $satisfied = @($Findings | Where-Object State -eq 'Satisfied').Count
    $partial   = @($Findings | Where-Object State -eq 'Partial').Count
    $gap       = @($Findings | Where-Object State -eq 'Gap').Count
    $na        = @($Findings | Where-Object State -eq 'NotApplicable').Count
    $total     = $Findings.Count

    $scoreNum  = if ($total - $na -gt 0) { [Math]::Round(100 * ($satisfied + 0.5 * $partial) / ($total - $na)) } else { 0 }

    $posture = if ($scoreNum -ge 85) { '🟢 Strong'
               } elseif ($scoreNum -ge 65) { '🟡 Moderate'
               } elseif ($scoreNum -ge 40) { '🟠 Weak'
               } else { '🔴 Critical' }

    [void]$sb.AppendLine("## 1. Executive Summary")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("### Overall Posture: $posture")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Metric | Value |")
    [void]$sb.AppendLine("|---|---|")
    [void]$sb.AppendLine("| NRG Composite Score | **$scoreNum / 100** |")
    [void]$sb.AppendLine("| Controls Satisfied | $satisfied |")
    [void]$sb.AppendLine("| Partial | $partial |")
    [void]$sb.AppendLine("| Gaps | $gap |")
    [void]$sb.AppendLine("| Not Applicable | $na |")
    [void]$sb.AppendLine("| Total | $total |")
    [void]$sb.AppendLine("")

    # Top actions
    $topGaps = @($Findings | Where-Object {
        $_.State -eq 'Gap' -and $_.Severity -in @('Critical','High')
    } | Sort-Object @{Expression={
        switch ($_.Severity) { 'Critical' { 0 }; 'High' { 1 }; default { 2 } }
    }} | Select-Object -First 5)

    if ($topGaps.Count -gt 0) {
        [void]$sb.AppendLine("### Top 5 Priority Actions")
        [void]$sb.AppendLine("")
        $i = 1
        foreach ($g in $topGaps) {
            $sevEmoji = if ($g.Severity -eq 'Critical') { '🔴' } else { '🟠' }
            [void]$sb.AppendLine("$i. $sevEmoji **$($g.Severity)** — $($g.Title)")
            $i++
        }
        [void]$sb.AppendLine("")
    }

    # Connection status
    [void]$sb.AppendLine("### Service Connections")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("| Service | Connected |")
    [void]$sb.AppendLine("|---|---|")
    foreach ($svc in @('Graph','EXO','IPPSSession','Teams','SharePoint')) {
        $connected = if ($Connections -is [hashtable]) {
            $Connections.ContainsKey($svc) -and $Connections[$svc] -eq $true
        } else {
            $Connections.$svc -eq $true
        }
        $status = if ($connected) { '✓' } else { '✗' }
        [void]$sb.AppendLine("| $svc | $status |")
    }
    [void]$sb.AppendLine("")

    [void]$sb.AppendLine("---")
    [void]$sb.AppendLine("")

    # Findings detail
    [void]$sb.AppendLine("## 2. Findings")
    [void]$sb.AppendLine("")

    $byCategory = $Findings | Group-Object Category | Sort-Object Name
    foreach ($cat in $byCategory) {
        [void]$sb.AppendLine("### $($cat.Name)")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("| State | Severity | Control | Detail |")
        [void]$sb.AppendLine("|---|---|---|---|")
        foreach ($f in ($cat.Group | Sort-Object @{Expression={
            switch ($_.State) { 'Gap' { 0 }; 'Partial' { 1 }; 'Satisfied' { 2 }; 'NotApplicable' { 3 } }
        }}, @{Expression='Title'})) {
            $stateEmoji = switch ($f.State) {
                'Satisfied'     { '🟢 Pass' }
                'Partial'       { '🟡 Partial' }
                'Gap'           { '🔴 Gap' }
                'NotApplicable' { '⬜ N/A' }
            }
            $detail = ($f.Detail -replace '\|','\\|' -replace '[\r\n]+',' ')
            [void]$sb.AppendLine("| $stateEmoji | $($f.Severity) | $($f.Title) | $detail |")
        }
        [void]$sb.AppendLine("")
    }

    # ── Configuration Inventory ──────────────────────────────────────────────
    [void]$sb.AppendLine("---")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("## 3. Configuration Inventory")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("Data collected during this assessment. Use as your reference baseline.")
    [void]$sb.AppendLine("")

    # DNS Email Security
    $dnsData = Get-NRGRawData -Key 'DNS-EmailRecords'
    if ($dnsData -and $dnsData.Success -and $dnsData.Data.Domains) {
        [void]$sb.AppendLine("### DNS Email Security")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("| Domain | SPF | DKIM | DMARC Policy | DMARC Record | MTA-STS |")
        [void]$sb.AppendLine("|---|---|---|---|---|---|")
        foreach ($domain in $dnsData.Data.Domains.Keys | Sort-Object) {
            $d = $dnsData.Data.Domains[$domain]

            # SPF
            $spfStatus = if (-not $d.SPF) { '✗ None' }
                         elseif ($d.SPF -match '\-all') { '✓ -all' }
                         elseif ($d.SPF -match '~all') { '~ ~all' }
                         else { '⚠ Present' }

            # DKIM
            $dkimStatus = if ($d.DKIM.Selector1 -and $d.DKIM.Selector2) { '✓ Both selectors' }
                          elseif ($d.DKIM.Selector1 -or $d.DKIM.Selector2) { '⚠ Partial' }
                          else { '✗ None' }

            # DMARC
            $dmarcPolicy = if (-not $d.DMARC) { '✗ None' }
                           elseif ($d.DMARC -match 'p=reject') { '✓ reject' }
                           elseif ($d.DMARC -match 'p=quarantine') { '~ quarantine' }
                           else { '⚠ none' }
            $dmarcRecord = if ($d.DMARC) { $d.DMARC -replace '\|','\|' } else { '—' }
            if ($dmarcRecord.Length -gt 60) { $dmarcRecord = $dmarcRecord.Substring(0,57) + '...' }

            # MTA-STS
            $mtaStatus = if ($d.MTASTS.Mode) { $d.MTASTS.Mode }
                         elseif ($d.MTASTS.TxtRecord) { 'present' }
                         else { '—' }

            [void]$sb.AppendLine("| $domain | $spfStatus | $dkimStatus | $dmarcPolicy | $dmarcRecord | $mtaStatus |")
        }
        [void]$sb.AppendLine("")
    }

    # EXO Configuration
    $exoData = Get-NRGRawData -Key 'EXO-MailboxConfig'
    if ($exoData -and $exoData.Success) {
        [void]$sb.AppendLine("### Exchange Online Configuration")
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("| Setting | Value |")
        [void]$sb.AppendLine("|---|---|")

        $orgCfg = $exoData.Data.OrganizationConfig
        if ($orgCfg) {
            $audit = if ($orgCfg.AuditDisabled -eq $false) { '✓ Enabled' } else { '✗ Disabled' }
            [void]$sb.AppendLine("| Mailbox Audit | $audit |")

            $custLock = if ($orgCfg.CustomerLockBoxEnabled -eq $true) { '✓ Enabled' } else { '✗ Disabled' }
            [void]$sb.AppendLine("| Customer Lockbox | $custLock |")
        }

        $transport = $exoData.Data.TransportConfig
        if ($transport) {
            $smtpAuth = if ($transport.SmtpClientAuthenticationDisabled -eq $true) { '✓ Disabled' } else { '✗ Enabled (risk)' }
            [void]$sb.AppendLine("| SMTP Client Auth | $smtpAuth |")
        }

        $protocols = $exoData.Data.MailboxProtocols
        if ($protocols) {
            [void]$sb.AppendLine("| Total Mailboxes | $($protocols.TotalMailboxes) |")
            [void]$sb.AppendLine("| POP3 Enabled | $($protocols.PopEnabled) mailboxes |")
            [void]$sb.AppendLine("| IMAP Enabled | $($protocols.ImapEnabled) mailboxes |")
            [void]$sb.AppendLine("| ActiveSync Enabled | $($protocols.ActiveSyncEnabled) mailboxes |")
        }

        $bypass = $exoData.Data.AuditBypass
        if ($bypass) {
            $bypassVal = if ($bypass.BypassedCount -eq 0) { '✓ None' } else { "✗ $($bypass.BypassedCount) mailboxes" }
            [void]$sb.AppendLine("| Audit Bypass | $bypassVal |")
        }

        $shared = $exoData.Data.SharedMailboxes
        if ($shared) {
            [void]$sb.AppendLine("| Shared Mailboxes | $($shared.Count) |")
        }

        [void]$sb.AppendLine("")
    }

    # ── Footer ────────────────────────────────────────────────────────────────
    [void]$sb.AppendLine("---")
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("*Prepared by $($brand.CompanyName) | $($brand.Phone) | $($brand.Website)*")
    [void]$sb.AppendLine("*Read-only assessment — no configuration changes were made*")

    $sb.ToString() | Out-File -FilePath $OutputPath -Encoding utf8
}
