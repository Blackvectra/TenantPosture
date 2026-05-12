#
# Test-NRGControlPurview.ps1
# Evaluates Microsoft Purview (Compliance) controls.
#
# Controls:
#   PVW-1.1  Unified audit log enabled
#   PVW-1.2  Audit log retention configured
#   PVW-2.1  DLP policy covers Exchange email
#   PVW-2.2  DLP policy covers SharePoint and OneDrive
#   PVW-2.3  DLP policy covers Microsoft Teams
#   PVW-3.1  Retention policy for Exchange email configured
#   PVW-3.2  Retention policy for SharePoint/OneDrive configured
#   PVW-4.1  Sensitivity labels published to users
#
# Reads: Get-NRGRawData -Key 'Purview'
#
# NIST SP 800-53: AU-2, AU-9, AU-12, SI-12, MP-6
# MITRE ATT&CK:   T1114, T1530, T1048
#

function Test-NRGControlPurview {
    [CmdletBinding()] param()

    $raw = Get-NRGRawData -Key 'Purview'

    if (-not $raw -or -not $raw.Success) {
        $detail = if ($raw) { "Collector failed: $($raw.Exceptions -join '; ')" } else { 'Purview collector did not run.' }
        foreach ($id in @('PVW-1.1','PVW-1.2','PVW-2.1','PVW-2.2','PVW-2.3','PVW-3.1','PVW-3.2','PVW-4.1')) {
            $ctrl = Get-NRGControlById -ControlId $id
            Add-NRGFinding -ControlId $id -State 'NotApplicable' `
                -Category 'Purview' -Title ($ctrl.Title) -Detail $detail
        }
        return
    }

    $audit     = $raw.Data['AuditConfig']
    $dlp       = @($raw.Data['DLPPolicies'])
    $retention = @($raw.Data['RetentionPolicies'])
    $labels    = @($raw.Data['Labels'])

    #--------------------------------------------------------------------------
    # PVW-1.1  Unified audit log enabled
    # AU-2, AU-12 | T1114
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'PVW-1.1'
    if ($audit) {
        $auditEnabled = $audit.UnifiedAuditLogIngestionEnabled -eq $true
        if ($auditEnabled) {
            Add-NRGFinding -ControlId 'PVW-1.1' -State 'Satisfied' `
                -Category 'Purview' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue 'Unified audit log: enabled' `
                -RequiredValue 'UnifiedAuditLogIngestionEnabled = true'
        } else {
            Add-NRGFinding -ControlId 'PVW-1.1' -State 'Gap' `
                -Category 'Purview' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail 'The unified audit log is disabled. All M365 user and admin activity is not being recorded. Incident response and forensics are impossible without this data.' `
                -CurrentValue 'Unified audit log: disabled' `
                -RequiredValue 'UnifiedAuditLogIngestionEnabled = true' `
                -Remediation 'Purview compliance portal > Audit > Turn on auditing. Or: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-1.1')
        }
    } else {
        Add-NRGFinding -ControlId 'PVW-1.1' -State 'NotApplicable' `
            -Category 'Purview' -Title $ctrl.Title -Detail 'Audit config data not available. Verify IPPSSession connected.'
    }

    #--------------------------------------------------------------------------
    # PVW-1.2  Audit log retention configured (≥ 90 days)
    # AU-9, AU-11 | T1114
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'PVW-1.2'
    if ($audit) {
        # Default M365 E3 retains 90 days. E5/A5 retain 1 year (365 days).
        # Check if a custom audit retention policy extends this.
        $adminRetentionDays = $audit.AdminAuditLogAgeLimit
        $retDays = 0
        if ($adminRetentionDays) {
            try {
                # Format may be "90.00:00:00" (TimeSpan) or just a number
                if ($adminRetentionDays -is [timespan]) {
                    $retDays = [int]$adminRetentionDays.TotalDays
                } elseif ($adminRetentionDays -match '(\d+)\.') {
                    $retDays = [int]$Matches[1]
                } elseif ($adminRetentionDays -match '^\d+$') {
                    $retDays = [int]$adminRetentionDays
                }
            } catch { $retDays = 0 }
        }

        if ($retDays -ge 365) {
            Add-NRGFinding -ControlId 'PVW-1.2' -State 'Satisfied' `
                -Category 'Purview' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue "Audit retention: $retDays days" `
                -RequiredValue '90 days minimum, 365 days recommended'
        } elseif ($retDays -ge 90) {
            Add-NRGFinding -ControlId 'PVW-1.2' -State 'Partial' `
                -Category 'Purview' -Title $ctrl.Title -Severity 'Medium' `
                -Detail "Audit log retains $retDays days — meets minimum. Recommend extending to 365 days (requires Microsoft 365 E5 or Audit Premium add-on)." `
                -CurrentValue "Audit retention: $retDays days" `
                -RequiredValue '365 days (Audit Premium recommended)' `
                -Remediation 'Microsoft 365 E5 or Microsoft Purview Audit (Premium) add-on required for 1-year retention. Enable via Purview compliance portal > Audit > Audit retention policies.'
        } elseif ($retDays -gt 0) {
            Add-NRGFinding -ControlId 'PVW-1.2' -State 'Gap' `
                -Category 'Purview' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail "Audit log retention is only $retDays days — below the 90-day minimum. Forensic investigations for incidents detected late will have no log data." `
                -CurrentValue "Audit retention: $retDays days" `
                -RequiredValue '90 days minimum' `
                -Remediation 'Purview compliance portal > Audit > Audit retention policies > Create policy for 90+ days.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-1.2')
        } else {
            # Couldn't determine exact days — treat as partial
            Add-NRGFinding -ControlId 'PVW-1.2' -State 'Partial' `
                -Category 'Purview' -Title $ctrl.Title -Severity 'Medium' `
                -Detail 'Could not determine exact audit retention period. Verify manually via Purview compliance portal > Audit > Audit retention policies.' `
                -CurrentValue 'Retention period indeterminate' `
                -RequiredValue '90 days minimum'
        }
    } else {
        Add-NRGFinding -ControlId 'PVW-1.2' -State 'NotApplicable' `
            -Category 'Purview' -Title $ctrl.Title -Detail 'Audit config data not available.'
    }

    #--------------------------------------------------------------------------
    # PVW-2.1  DLP policy covers Exchange email
    # SI-12, MP-6 | T1048, T1114
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'PVW-2.1'
    $dlpExchange = @($dlp | Where-Object {
        $_.Workload -match 'Exchange' -or
        $_.ExchangeLocation -or
        ($_.Locations -and ($_.Locations | Where-Object { $_.Workload -eq 'Exchange' }))
    })
    if ($dlpExchange.Count -gt 0) {
        $names = ($dlpExchange | Select-Object -ExpandProperty Name -First 3) -join ', '
        Add-NRGFinding -ControlId 'PVW-2.1' -State 'Satisfied' `
            -Category 'Purview' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue "$($dlpExchange.Count) DLP policy(ies) cover Exchange: $names" `
            -RequiredValue 'At least one enabled DLP policy covering Exchange'
    } elseif ($dlp.Count -gt 0) {
        Add-NRGFinding -ControlId 'PVW-2.1' -State 'Gap' `
            -Category 'Purview' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail "DLP policies exist ($($dlp.Count) total) but none cover Exchange email. Sensitive data (PII, credit card, SSN) can be emailed externally without control." `
            -CurrentValue 'No Exchange DLP policy' `
            -RequiredValue 'DLP policy covering Exchange with sensitive information types' `
            -Remediation 'Purview compliance portal > Data loss prevention > Create policy > Include Exchange email as a location.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-2.1')
    } else {
        Add-NRGFinding -ControlId 'PVW-2.1' -State 'Gap' `
            -Category 'Purview' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'No DLP policies found. Sensitive data can be freely shared via email without detection or prevention.' `
            -CurrentValue 'No DLP policies configured' `
            -RequiredValue 'DLP policy covering Exchange with sensitive information types' `
            -Remediation 'Purview compliance portal > Data loss prevention > Create policy from built-in templates (Financial, PII, HIPAA, etc.). Include Exchange.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-2.1')
    }

    #--------------------------------------------------------------------------
    # PVW-2.2  DLP policy covers SharePoint and OneDrive
    # SI-12 | T1530
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'PVW-2.2'
    $dlpSPO = @($dlp | Where-Object {
        $_.Workload -match 'SharePoint' -or $_.Workload -match 'OneDrive' -or
        $_.SharePointLocation -or $_.OneDriveLocation
    })
    if ($dlpSPO.Count -gt 0) {
        Add-NRGFinding -ControlId 'PVW-2.2' -State 'Satisfied' `
            -Category 'Purview' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue "$($dlpSPO.Count) DLP policy(ies) cover SharePoint/OneDrive" `
            -RequiredValue 'At least one DLP policy covering SharePoint/OneDrive'
    } else {
        Add-NRGFinding -ControlId 'PVW-2.2' -State 'Gap' `
            -Category 'Purview' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'No DLP policy covers SharePoint or OneDrive. Sensitive files can be shared externally without detection or blocking.' `
            -CurrentValue 'No SharePoint/OneDrive DLP policy' `
            -RequiredValue 'DLP policy covering SharePoint and OneDrive' `
            -Remediation 'Purview compliance portal > Data loss prevention > Create or edit policy > Add SharePoint and OneDrive as locations.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-2.2')
    }

    #--------------------------------------------------------------------------
    # PVW-2.3  DLP policy covers Microsoft Teams
    # SI-12 | T1048
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'PVW-2.3'
    $dlpTeams = @($dlp | Where-Object {
        $_.Workload -match 'Teams' -or $_.TeamsLocation
    })
    if ($dlpTeams.Count -gt 0) {
        Add-NRGFinding -ControlId 'PVW-2.3' -State 'Satisfied' `
            -Category 'Purview' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue "$($dlpTeams.Count) DLP policy(ies) cover Teams" `
            -RequiredValue 'At least one DLP policy covering Teams'
    } else {
        Add-NRGFinding -ControlId 'PVW-2.3' -State 'Gap' `
            -Category 'Purview' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'No DLP policy covers Microsoft Teams. Sensitive data sent via Teams chat or channel messages is not monitored or blocked.' `
            -CurrentValue 'No Teams DLP policy' `
            -RequiredValue 'DLP policy covering Teams chat and channel messages' `
            -Remediation 'Purview compliance portal > Data loss prevention > Create or edit policy > Add Teams chat and channel messages as a location.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-2.3')
    }

    #--------------------------------------------------------------------------
    # PVW-3.1  Retention policy for Exchange email configured
    # AU-11, SI-12 | T1485
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'PVW-3.1'
    $retExchange = @($retention | Where-Object {
        $_.ExchangeLocation -or $_.Workload -match 'Exchange' -or
        ($_.Locations -and ($_.Locations | Where-Object { $_.Workload -eq 'Exchange' }))
    })
    if ($retExchange.Count -gt 0) {
        Add-NRGFinding -ControlId 'PVW-3.1' -State 'Satisfied' `
            -Category 'Purview' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue "$($retExchange.Count) retention policy(ies) cover Exchange" `
            -RequiredValue 'At least one retention policy covering Exchange email'
    } else {
        Add-NRGFinding -ControlId 'PVW-3.1' -State 'Gap' `
            -Category 'Purview' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'No retention policy covers Exchange email. Email can be permanently deleted by users, creating legal hold and eDiscovery risks.' `
            -CurrentValue 'No Exchange retention policy' `
            -RequiredValue 'Retention policy covering Exchange with appropriate duration (1-7 years typically)' `
            -Remediation 'Purview compliance portal > Data lifecycle management > Retention policies > Create policy for Exchange email.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-3.1')
    }

    #--------------------------------------------------------------------------
    # PVW-3.2  Retention policy for SharePoint/OneDrive configured
    # AU-11, SI-12 | T1485
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'PVW-3.2'
    $retSPO = @($retention | Where-Object {
        $_.SharePointLocation -or $_.OneDriveLocation -or $_.Workload -match 'SharePoint'
    })
    if ($retSPO.Count -gt 0) {
        Add-NRGFinding -ControlId 'PVW-3.2' -State 'Satisfied' `
            -Category 'Purview' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue "$($retSPO.Count) retention policy(ies) cover SharePoint/OneDrive" `
            -RequiredValue 'At least one retention policy covering SharePoint/OneDrive'
    } else {
        Add-NRGFinding -ControlId 'PVW-3.2' -State 'Gap' `
            -Category 'Purview' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'No retention policy covers SharePoint or OneDrive. Documents can be permanently deleted by users, creating legal hold and eDiscovery risks.' `
            -CurrentValue 'No SharePoint/OneDrive retention policy' `
            -RequiredValue 'Retention policy covering SharePoint sites and OneDrive accounts' `
            -Remediation 'Purview compliance portal > Data lifecycle management > Retention policies > Create policy for SharePoint and OneDrive.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-3.2')
    }

    #--------------------------------------------------------------------------
    # PVW-4.1  Sensitivity labels published to users
    # AC-16, MP-3 | T1530
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'PVW-4.1'
    $publishedLabels = @($labels | Where-Object { $_.IsPublished -eq $true -or $_.LabelActionRequiredOnLogin })
    if ($publishedLabels.Count -gt 0) {
        $names = ($publishedLabels | Select-Object -ExpandProperty DisplayName -First 3) -join ', '
        Add-NRGFinding -ControlId 'PVW-4.1' -State 'Satisfied' `
            -Category 'Purview' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue "$($publishedLabels.Count) sensitivity label(s) published: $names" `
            -RequiredValue 'At least one published sensitivity label policy'
    } elseif ($labels.Count -gt 0) {
        Add-NRGFinding -ControlId 'PVW-4.1' -State 'Partial' `
            -Category 'Purview' -Title $ctrl.Title -Severity 'Medium' `
            -Detail "$($labels.Count) sensitivity label(s) exist but none are published to users. Labels exist in the system but users cannot apply them to documents." `
            -CurrentValue "$($labels.Count) unpublished labels" `
            -RequiredValue 'Sensitivity labels published to all or target users via label policy' `
            -Remediation 'Purview compliance portal > Information protection > Label policies > Publish labels to users and groups.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-4.1')
    } else {
        Add-NRGFinding -ControlId 'PVW-4.1' -State 'Gap' `
            -Category 'Purview' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'No sensitivity labels configured. Documents cannot be classified or protected. No encryption, watermarking, or access control policies are enforced at the data layer.' `
            -CurrentValue 'No sensitivity labels' `
            -RequiredValue 'Published sensitivity labels covering at least Confidential and Internal classification' `
            -Remediation 'Purview compliance portal > Information protection > Labels > Create labels (Public, Internal, Confidential, Highly Confidential). Publish via label policy.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PVW-4.1')
    }
}
