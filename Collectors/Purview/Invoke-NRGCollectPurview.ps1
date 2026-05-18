#Requires -Version 7.0
#
# Invoke-NRGCollectPurview.ps1
# Collects Purview audit retention, DLP policy state, and retention configuration.
#
# READ-ONLY. Uses IPPS session (already established by Connect-NRGServices) for
# DLP and retention. Audit retention queried via Get-AdminAuditLogConfig.
#
# Required session: IPPSSession (Connect-IPPSSession).
#
# NIST SP 800-53: AU-11 (audit retention), MP-7 (media use), AC-4 (info flow)
# MITRE ATT&CK:   T1562.008 (Impair Defenses: Disable Cloud Logs), T1530 (Cloud Storage)
#

function Invoke-NRGCollectPurview {
    [CmdletBinding()] param()
    $result = @{
        Success = $false
        Data    = @{
            AuditConfig         = $null
            UnifiedAuditEnabled = $false
            DLPPolicies         = @()
            RetentionPolicies   = @()
            SensitivityLabels   = @()
        }
    }

    try {
        # Audit configuration
        if (Get-Command Get-AdminAuditLogConfig -ErrorAction SilentlyContinue) {
            try {
                $audit = Get-AdminAuditLogConfig -ErrorAction Stop
                if ($audit) {
                    $result.Data.AuditConfig = @{
                        UnifiedAuditLogIngestionEnabled = [bool]$audit.UnifiedAuditLogIngestionEnabled
                        AdminAuditLogEnabled            = [bool]$audit.AdminAuditLogEnabled
                        AdminAuditLogAgeLimit           = [string]$audit.AdminAuditLogAgeLimit
                    }
                    $result.Data.UnifiedAuditEnabled = [bool]$audit.UnifiedAuditLogIngestionEnabled
                }
            } catch {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Purview-Audit' -Message $_.Exception.Message
                }
            }
        }

        # DLP policies
        if (Get-Command Get-DlpCompliancePolicy -ErrorAction SilentlyContinue) {
            try {
                $dlp = Get-DlpCompliancePolicy -ErrorAction Stop
                if ($dlp) {
                    $result.Data.DLPPolicies = @($dlp | ForEach-Object {
                        @{
                            Name       = $_.Name
                            Enabled    = ($_.Mode -eq 'Enable')
                            Mode       = [string]$_.Mode
                            Workloads  = if ($_.Workload) { ($_.Workload -split ',') } else { @() }
                        }
                    })
                }
            } catch {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Purview-DLP' -Message $_.Exception.Message
                }
            }
        }

        # Retention policies
        if (Get-Command Get-RetentionCompliancePolicy -ErrorAction SilentlyContinue) {
            try {
                $ret = Get-RetentionCompliancePolicy -ErrorAction Stop
                if ($ret) {
                    $result.Data.RetentionPolicies = @($ret | ForEach-Object {
                        @{
                            Name      = $_.Name
                            Enabled   = [bool]$_.Enabled
                            Workloads = if ($_.Workload) { ($_.Workload -split ',') } else { @() }
                        }
                    })
                }
            } catch {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Purview-Retention' -Message $_.Exception.Message
                }
            }
        }

        # Sensitivity labels
        if (Get-Command Get-Label -ErrorAction SilentlyContinue) {
            try {
                $labels = Get-Label -ErrorAction Stop
                if ($labels) {
                    $result.Data.SensitivityLabels = @($labels | ForEach-Object {
                        @{
                            Name        = $_.Name
                            DisplayName = $_.DisplayName
                            IsValid     = [bool]$_.IsValid
                        }
                    })
                }
            } catch {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Purview-Labels' -Message $_.Exception.Message
                }
            }
        }

        $result.Success = $true
    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'Purview-Collector' -Message $_.Exception.Message
        }
    }

    Set-NRGRawData -Key 'Purview' -Data $result
}
