#Requires -Version 7.0
#
# Apply-NRGDefenderPreset.ps1  (v4.6.1)
# Remediates DEF-1.1: Enable Defender for Office 365 Standard preset policy.
#
# NRG Technology Services | NextLayerSec LLC
# Author: Matthew Levorson
#
# CONSUMES : Finding object for ControlId 'DEF-1.1'
# REQUIRES : ExchangeOnlineManagement (preset cmdlets ship in EOM, scope SC RBAC).
# CMDLETS  : Get-EOPProtectionPolicyRule, Get-ATPProtectionPolicyRule,
#            Enable-EOPProtectionPolicyRule, Enable-ATPProtectionPolicyRule
# SAFETY   : ShouldProcess gate, idempotency re-read.
#
# CHANGE   : Enable the BUILT-IN 'Standard Preset Security Policy' rules. These
#            rules exist in every tenant but ship disabled. This script does NOT
#            create new policies — it flips State to Enabled on the existing rules.
#
# SCOPE OF 'Standard' PRESET (controlled by Microsoft, NOT by this script):
#   - Anti-spam, anti-malware, anti-phish (EOP rule)
#   - Safe Attachments, Safe Links (ATP rule, requires Defender for Office 365 P1+)
#
# RECIPIENT SCOPE:
#   We DO NOT modify the policy's user/group/domain inclusion conditions. If the
#   tenant has the preset rules configured but scoped to zero recipients, this
#   script enables them but the policy is still inert. Operator MUST configure
#   recipient scope in Defender portal: Email & Collaboration -> Policies & rules
#   -> Threat policies -> Preset Security Policies.
#

function Apply-NRGDefenderPreset {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        [Parameter(Mandatory)] [object] $Finding
    )

    $controlId = 'DEF-1.1'
    $result = [ordered]@{
        ControlId = $controlId
        Action    = "Enable 'Standard Preset Security Policy' EOP + ATP rules"
        Status    = 'Pending'
        Before    = $null
        After     = $null
        Error     = $null
        Timestamp = (Get-Date).ToString('o')
    }

    try {
        # ── 1. Read current state of preset rules ────────────────────────────
        $eopRule = $null
        $atpRule = $null
        $eopReadErr = $null
        $atpReadErr = $null

        try {
            $eopRule = Get-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -ErrorAction Stop
        } catch {
            $eopReadErr = $_.Exception.Message
        }
        try {
            $atpRule = Get-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -ErrorAction Stop
        } catch {
            $atpReadErr = $_.Exception.Message
        }

        if (-not $eopRule -and -not $atpRule) {
            $result.Status = 'Failed'
            $result.Error  = "Neither EOP nor ATP preset rule found. EOP error: $eopReadErr. ATP error: $atpReadErr."
            return [PSCustomObject]$result
        }

        $result.Before = [PSCustomObject]@{
            EOPRule = if ($eopRule) { [PSCustomObject]@{ Name=$eopRule.Name; State=$eopRule.State } } else { [PSCustomObject]@{ Note = "Not present: $eopReadErr" } }
            ATPRule = if ($atpRule) { [PSCustomObject]@{ Name=$atpRule.Name; State=$atpRule.State } } else { [PSCustomObject]@{ Note = "Not present: $atpReadErr (Defender for Office 365 P1+ required)" } }
        }

        $eopEnabled = $eopRule -and $eopRule.State -eq 'Enabled'
        $atpPresentAndEnabled = $atpRule -and $atpRule.State -eq 'Enabled'
        $atpAbsent = -not $atpRule  # acceptable on EOP-only tenants

        # Compliance: EOP enabled, AND (ATP enabled OR ATP simply not present)
        if ($eopEnabled -and ($atpPresentAndEnabled -or $atpAbsent)) {
            $result.Status = 'AlreadyCompliant'
            $result.After  = $result.Before
            return [PSCustomObject]$result
        }

        $target = "Defender Standard Preset Security Policy (EOP + ATP rules)"
        $action = 'Enable EOP and ATP preset rules. Recipient scope is NOT modified — operator must configure inclusion in Defender portal.'
        if (-not $PSCmdlet.ShouldProcess($target, $action)) {
            $result.Status = 'Skipped'
            return [PSCustomObject]$result
        }

        $errors = @()
        if ($eopRule -and $eopRule.State -ne 'Enabled') {
            try {
                Enable-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -ErrorAction Stop | Out-Null
            } catch {
                $errors += "EOP enable failed: $($_.Exception.Message)"
            }
        }
        if ($atpRule -and $atpRule.State -ne 'Enabled') {
            try {
                Enable-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -ErrorAction Stop | Out-Null
            } catch {
                $errors += "ATP enable failed: $($_.Exception.Message)"
            }
        }

        # Re-read for After
        $eopAfter = $null; $atpAfter = $null
        try { $eopAfter = Get-EOPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -ErrorAction Stop } catch {}
        try { $atpAfter = Get-ATPProtectionPolicyRule -Identity 'Standard Preset Security Policy' -ErrorAction Stop } catch {}

        $result.After = [PSCustomObject]@{
            EOPRule = if ($eopAfter) { [PSCustomObject]@{ Name=$eopAfter.Name; State=$eopAfter.State } } else { $null }
            ATPRule = if ($atpAfter) { [PSCustomObject]@{ Name=$atpAfter.Name; State=$atpAfter.State } } else { $null }
            Note    = 'Recipient scope must still be configured in Defender portal for the rules to affect any users.'
        }

        if ($errors.Count -gt 0) {
            $result.Status = 'Failed'
            $result.Error  = ($errors -join '; ')
        } else {
            $result.Status = 'Applied'
        }
    } catch {
        $result.Status = 'Failed'
        $result.Error  = $_.Exception.Message
    }

    return [PSCustomObject]$result
}
