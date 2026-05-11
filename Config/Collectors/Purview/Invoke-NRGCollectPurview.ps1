#
# Invoke-NRGCollectPurview.ps1
# Collects Microsoft Purview (Compliance) settings via IPPSSession.
#
# Requires: IPPSSession connection (Connect-IPPSSession)
#
# Data keys stored:
#   Purview.AuditConfig       — Get-AdminAuditLogConfig
#   Purview.DLPPolicies       — Get-DlpCompliancePolicy
#   Purview.RetentionPolicies — Get-RetentionCompliancePolicy
#   Purview.Labels            — Get-Label (sensitivity labels)
#   Purview.InsiderRisk       — Get-InsiderRiskPolicy (graceful skip if not licensed)
#
# NIST SP 800-53: AU-2, AU-9, AU-12, SI-12, MP-6
# MITRE ATT&CK:   T1114, T1530, T1048
#

function Invoke-NRGCollectPurview {
    [CmdletBinding()] param()

    $result = @{
        Source     = 'Purview'
        Timestamp  = (Get-Date -Format 'o')
        Success    = $false
        Data       = @{}
        Exceptions = @()
    }

    try {
        # ── Audit log configuration ────────────────────────────────────────────
        try {
            $audit = Get-AdminAuditLogConfig -ErrorAction Stop
            $result.Data['AuditConfig'] = $audit
        } catch {
            $result.Exceptions += "AuditConfig: $($_.Exception.Message)"
            $result.Data['AuditConfig'] = $null
        }

        # ── DLP compliance policies ────────────────────────────────────────────
        try {
            $dlp = @(Get-DlpCompliancePolicy -ErrorAction Stop)
            $result.Data['DLPPolicies'] = $dlp
        } catch {
            $result.Exceptions += "DLPPolicies: $($_.Exception.Message)"
            $result.Data['DLPPolicies'] = @()
        }

        # ── Retention policies ─────────────────────────────────────────────────
        try {
            $ret = @(Get-RetentionCompliancePolicy -ErrorAction Stop)
            $result.Data['RetentionPolicies'] = $ret
        } catch {
            $result.Exceptions += "RetentionPolicies: $($_.Exception.Message)"
            $result.Data['RetentionPolicies'] = @()
        }

        # ── Sensitivity labels ─────────────────────────────────────────────────
        try {
            $labels = @(Get-Label -ErrorAction Stop)
            $result.Data['Labels'] = $labels
        } catch {
            $result.Exceptions += "Labels: $($_.Exception.Message)"
            $result.Data['Labels'] = @()
        }

        # ── Insider risk policies (P2 / E5 — graceful skip) ───────────────────
        try {
            $irp = @(Get-InsiderRiskPolicy -ErrorAction Stop)
            $result.Data['InsiderRisk'] = $irp
            $result.Data['InsiderRiskAvailable'] = $true
        } catch {
            # InsiderRiskManagement.Read scope or E5 license may be absent — not an error
            $result.Data['InsiderRisk'] = @()
            $result.Data['InsiderRiskAvailable'] = $false
        }

        # ── Communication compliance ───────────────────────────────────────────
        try {
            $cc = @(Get-SupervisoryReviewPolicyV2 -ErrorAction Stop)
            $result.Data['CommCompliance'] = $cc
            $result.Data['CommComplianceAvailable'] = $true
        } catch {
            $result.Data['CommCompliance'] = @()
            $result.Data['CommComplianceAvailable'] = $false
        }

        $result.Success = $true

    } catch {
        $result.Exceptions += $_.Exception.Message
        Register-NRGException -Source 'Invoke-NRGCollectPurview' -Message $_.Exception.Message
    }

    Set-NRGRawData -Key 'Purview' -Data $result
    return $result
}
