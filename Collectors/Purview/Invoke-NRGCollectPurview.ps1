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
            # DLP RULES, not policies. Sensitive information types are defined on
            # the rule (ContentContainsSensitiveInformation), never on the parent
            # policy — Get-DlpCompliancePolicy exposes no SIT field at all. DEF-4.2
            # previously read $policy.SensitiveInfoTypes, which does not exist, so
            # it could only ever throw under StrictMode or report a false Gap.
            DLPRules            = @()
            RetentionPolicies   = @()
            SensitivityLabels   = @()
            # Alert POLICY configuration (Get-ProtectionAlert), not fired alerts.
            # EXO-ConnectionFilter separately collects /security/alerts_v2, which
            # is the list of alerts that have triggered — a different question
            # from whether anyone is configured to be told when they do.
            ProtectionAlerts    = @()
            # Per-section outcome: an empty list means "no alert policies
            # configured" (or "no DLP policies", "no retention policies", etc.)
            # only when the query actually ran. Without a status entry per
            # section, a failed query and a genuinely empty tenant are
            # indistinguishable and the evaluators would report a confident
            # Gap/Partial either way — see CLAUDE.md "Empty is not clean".
            # Read by PVW-4.2 / 2.6 / 4.3 / 4.4 / 2.2 / 2.3. These evaluators
            # existed before anything collected their data, so they could
            # never produce a verdict (PVW-4.3 even scored a false Partial —
            # "labels defined but none published" — from the missing list).
            AuditRetentionPolicies  = @()
            AutoLabelPolicies       = @()
            LabelPolicies           = @()
            RetentionLabels         = @()
            CommCompliancePolicies  = @()
            InformationBarriersMode = $null
            SectionStatus       = @{
                AuditConfig       = 'NotRun'
                DLPPolicies       = 'NotRun'
                DLPRules          = 'NotRun'
                RetentionPolicies = 'NotRun'
                SensitivityLabels = 'NotRun'
                ProtectionAlerts  = 'NotRun'
                AuditRetentionPolicies  = 'NotRun'
                AutoLabelPolicies       = 'NotRun'
                LabelPolicies           = 'NotRun'
                RetentionLabels         = 'NotRun'
                CommCompliancePolicies  = 'NotRun'
                InformationBarriersMode = 'NotRun'
            }
        }
    }

    try {
        # Audit configuration
        # Must run in the EXCHANGE ONLINE session: Microsoft documents
        # UnifiedAuditLogIngestionEnabled as always False in Security &
        # Compliance PowerShell, and an unqualified call here resolves to the
        # Purview session (connected last). See Lib/Get-NRGExoCommand.ps1.
        $auditCmd = Get-NRGExoCommand -Name 'Get-AdminAuditLogConfig' -Session ExchangeOnline
        if ($auditCmd.Command) {
            try {
                $audit = & $auditCmd.Command -ErrorAction Stop
                if ($audit) {
                    $result.Data.AuditConfig = @{
                        UnifiedAuditLogIngestionEnabled = [bool](Get-NRGObjectField -Item $audit -Key 'UnifiedAuditLogIngestionEnabled' -Default $false)
                        AdminAuditLogEnabled            = [bool](Get-NRGObjectField -Item $audit -Key 'AdminAuditLogEnabled' -Default $false)
                        AdminAuditLogAgeLimit           = [string](Get-NRGObjectField -Item $audit -Key 'AdminAuditLogAgeLimit' -Default '')
                        # ExchangeOnline / SecurityCompliance / Unknown. A False
                        # read from anything but ExchangeOnline is not evidence.
                        Source                          = $auditCmd.Source
                    }
                    $result.Data.UnifiedAuditEnabled = $result.Data.AuditConfig.UnifiedAuditLogIngestionEnabled
                }
                $result.Data.SectionStatus.AuditConfig = 'Collected'
            } catch {
                $result.Data.SectionStatus.AuditConfig = 'Failed'
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
                $result.Data.SectionStatus.DLPPolicies = 'Collected'
            } catch {
                $result.Data.SectionStatus.DLPPolicies = 'Failed'
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Purview-DLP' -Message $_.Exception.Message
                }
            }
        }

        # DLP rules — carries the sensitive information types (DEF-4.2).
        if (Get-Command Get-DlpComplianceRule -ErrorAction SilentlyContinue) {
            try {
                $rules = Get-DlpComplianceRule -ErrorAction Stop
                $result.Data.DLPRules = @($rules | ForEach-Object {
                    $r = $_
                    # ContentContainsSensitiveInformation is an array of hashtables,
                    # each naming one SIT. Read every field through Get-NRGObjectField:
                    # rule shape varies by workload and StrictMode is active.
                    $sits = @(Get-NRGObjectField -Item $r -Key 'ContentContainsSensitiveInformation' -Default @())
                    $sitNames = @($sits | ForEach-Object {
                        $one = $_
                        $n = Get-NRGObjectField -Item $one -Key 'name' -Default ''
                        if (-not $n) { $n = Get-NRGObjectField -Item $one -Key 'Name' -Default '' }
                        if ($n) { [string]$n }
                    } | Where-Object { $_ })
                    @{
                        Name             = [string](Get-NRGObjectField -Item $r -Key 'Name'             -Default '')
                        ParentPolicyName = [string](Get-NRGObjectField -Item $r -Key 'ParentPolicyName' -Default '')
                        Disabled         = [bool]  (Get-NRGObjectField -Item $r -Key 'Disabled'         -Default $false)
                        SensitiveInfoTypes = @($sitNames)
                    }
                })
                $result.Data.SectionStatus.DLPRules = 'Collected'
            } catch {
                $result.Data.SectionStatus.DLPRules = 'Failed'
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Purview-DLPRules' -Message $_.Exception.Message
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
                $result.Data.SectionStatus.RetentionPolicies = 'Collected'
            } catch {
                $result.Data.SectionStatus.RetentionPolicies = 'Failed'
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
                $result.Data.SectionStatus.SensitivityLabels = 'Collected'
            } catch {
                $result.Data.SectionStatus.SensitivityLabels = 'Failed'
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Purview-Labels' -Message $_.Exception.Message
                }
            }
        }

        # Alert policies (Purview / Defender alert configuration).
        # NotifyUser is the list of recipients emailed when the policy fires; an
        # enabled policy with an empty NotifyUser raises an alert nobody is told
        # about, which is the failure mode DEF-3.4 exists to catch.
        if (Get-Command Get-ProtectionAlert -ErrorAction SilentlyContinue) {
            try {
                $alerts = Get-ProtectionAlert -ErrorAction Stop
                # Read every field through Get-NRGObjectField rather than direct
                # property access. Set-StrictMode -Version Latest is active
                # module-wide, and under it referencing a property the object
                # does not have THROWS before a ?? default can apply. The exact
                # shape of Get-ProtectionAlert output is not guaranteed across
                # tenants and module versions, so a single missing field would
                # otherwise abort the whole section and silently disable
                # DEF-3.4 / DEF-4.3 / EXO-3.4.
                $result.Data.ProtectionAlerts = @($alerts | ForEach-Object {
                    $a = $_
                    @{
                        Name         = [string](Get-NRGObjectField -Item $a -Key 'Name'       -Default '')
                        Category     = [string](Get-NRGObjectField -Item $a -Key 'Category'   -Default '')
                        Severity     = [string](Get-NRGObjectField -Item $a -Key 'Severity'   -Default '')
                        Disabled     = [bool]  (Get-NRGObjectField -Item $a -Key 'Disabled'   -Default $false)
                        NotifyUser   = @(       Get-NRGObjectField -Item $a -Key 'NotifyUser' -Default @())
                        ThreatType   = [string](Get-NRGObjectField -Item $a -Key 'ThreatType' -Default '')
                        Operation    = @(       Get-NRGObjectField -Item $a -Key 'Operation'  -Default @())
                    }
                })
                $result.Data.SectionStatus.ProtectionAlerts = 'Collected'
            } catch {
                $result.Data.SectionStatus.ProtectionAlerts = 'Failed'
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Purview-ProtectionAlerts' -Message $_.Exception.Message
                }
            }
        }

        # ── Security & Compliance sections added in v4.14.0 ──────────────────
        # Each runs only when its cmdlet resolves to the Security & Compliance
        # session (Get-SupervisoryReviewPolicyV2 also exists, non-functional,
        # in Exchange Online), and records Collected / Failed on its own so a
        # failed query is never read as "none configured".
        $scc = {
            param([string] $Section, [string] $Cmdlet, [scriptblock] $Project)
            $cmd = Get-NRGExoCommand -Name $Cmdlet -Session SecurityCompliance
            if (-not $cmd.Command -or $cmd.Source -eq 'ExchangeOnline') { return }
            try {
                $rows = @(& $cmd.Command -ErrorAction Stop)
                & $Project $rows
                $result.Data.SectionStatus[$Section] = 'Collected'
            } catch {
                $result.Data.SectionStatus[$Section] = 'Failed'
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source "Purview-$Section" -Message $_.Exception.Message
                }
            }
        }

        # Audit log retention policies (PVW-4.2). RetentionDuration is an enum
        # (ThreeMonths/SixMonths/NineMonths/TwelveMonths/TenYears); anything
        # else maps to $null days and never counts toward long-term retention.
        # The default policy is not returned by this cmdlet (Microsoft docs).
        & $scc 'AuditRetentionPolicies' 'Get-UnifiedAuditLogRetentionPolicy' {
            param($rows)
            $days = @{ ThreeMonths = 90; SixMonths = 180; NineMonths = 270; TwelveMonths = 365; TenYears = 3650 }
            $result.Data.AuditRetentionPolicies = @($rows | Where-Object { $_ } | ForEach-Object {
                $dur = [string](Get-NRGObjectField -Item $_ -Key 'RetentionDuration' -Default '')
                @{
                    Name              = [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '')
                    RetentionDuration = $dur
                    RetentionDays     = $(if ($days.ContainsKey($dur)) { $days[$dur] } else { $null })
                    RecordTypes       = @(Get-NRGObjectField -Item $_ -Key 'RecordTypes' -Default @())
                }
            })
        }

        # Auto-labeling policies (PVW-2.6). Mode: Enable / TestWithNotifications
        # / TestWithoutNotifications / Disable / PendingDeletion.
        & $scc 'AutoLabelPolicies' 'Get-AutoSensitivityLabelPolicy' {
            param($rows)
            $result.Data.AutoLabelPolicies = @($rows | Where-Object { $_ } | ForEach-Object {
                @{
                    Name = [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '')
                    Mode = [string](Get-NRGObjectField -Item $_ -Key 'Mode' -Default '')
                }
            })
        }

        # Sensitivity label publishing policies (PVW-4.3).
        & $scc 'LabelPolicies' 'Get-LabelPolicy' {
            param($rows)
            $result.Data.LabelPolicies = @($rows | Where-Object { $_ } | ForEach-Object {
                @{
                    Name   = [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '')
                    Labels = @(Get-NRGObjectField -Item $_ -Key 'Labels' -Default @())
                }
            })
        }

        # Retention labels (PVW-4.4). IsRecordLabel marks a records label;
        # Regulatory marks a regulatory record.
        & $scc 'RetentionLabels' 'Get-ComplianceTag' {
            param($rows)
            $result.Data.RetentionLabels = @($rows | Where-Object { $_ } | ForEach-Object {
                @{
                    Name          = [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '')
                    IsRecordLabel = [bool](Get-NRGObjectField -Item $_ -Key 'IsRecordLabel' -Default $false)
                    Regulatory    = [bool](Get-NRGObjectField -Item $_ -Key 'Regulatory' -Default $false)
                }
            })
        }

        # Communication compliance policies (PVW-2.2).
        & $scc 'CommCompliancePolicies' 'Get-SupervisoryReviewPolicyV2' {
            param($rows)
            $result.Data.CommCompliancePolicies = @($rows | Where-Object { $_ } | ForEach-Object {
                @{
                    Name    = [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '')
                    Enabled = Get-NRGObjectField -Item $_ -Key 'Enabled' -Default $null
                }
            })
        }

        # Information barriers mode (PVW-2.3): Legacy / SingleSegment / MultiSegment.
        & $scc 'InformationBarriersMode' 'Get-PolicyConfig' {
            param($rows)
            $mode = [string](Get-NRGObjectField -Item @($rows)[0] -Key 'InformationBarrierMode' -Default '')
            if (-not $mode) { throw 'Get-PolicyConfig returned no InformationBarrierMode.' }
            $result.Data.InformationBarriersMode = $mode
        }

        $result.Success = $true
    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'Purview-Collector' -Message $_.Exception.Message
        }
    }

    Set-NRGRawData -Key 'Purview' -Data $result
}
