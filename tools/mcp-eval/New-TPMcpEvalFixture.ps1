#Requires -Version 7.0
<#
.SYNOPSIS
    Builds the fixed output folder the MCP server's evaluation questions are
    asked against (tools/mcp-eval/tenantposture-eval.xml).

.DESCRIPTION
    Five assessment runs of three made-up tenants, in the shapes
    Invoke-TPAssessment.ps1 writes:
      contoso.example   three runs (2026-09-02, 2026-10-01, 2026-10-28), GUI layout
      fabrikam.example  one run (2026-10-15), GUI layout
      NORTHWIND         one run (2025-06-12), the flat command-line layout, with
                        70 findings so a full answer needs paging
    The data never changes, so every answer in the evaluation file stays the
    same. Nothing here is tenant data. TP.McpServer.Tests.ps1 builds this folder,
    asks the real server each question's path and checks the recorded answer.

    It connects to nothing and writes only under -Path.

    TenantPosture — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Data: writes <Path>/output. No network. Graph scopes / cmdlets: none.

.PARAMETER Path
    The work folder. Created if absent; existing fixture files are overwritten.

.OUTPUTS
    The output folder path (what Start-TPMcpServer.ps1 -OutputRoot takes).

.EXAMPLE
    $out = ./tools/mcp-eval/New-TPMcpEvalFixture.ps1 -Path ./mcp-eval-work
    claude mcp add tenantposture-eval -- pwsh -NoProfile -File ./Start-TPMcpServer.ps1 -OutputRoot $out
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$out = Join-Path $Path 'output'
$put = {
    param([string] $File, $Object)
    $null = [System.IO.Directory]::CreateDirectory((Split-Path -Parent $File))
    Set-Content -LiteralPath $File -Value ($Object | ConvertTo-Json -Depth 20) -Encoding utf8
}
$finding = {
    param([string] $Id, [string] $State, [string] $Severity, [string] $Title, [string] $Detail = '', [string] $Instance = '')
    [ordered]@{
        ControlId = $Id; State = $State; Category = 'Fixture'; Title = $Title; Severity = $Severity
        Detail = $(if ($Detail) { $Detail } else { "$Title`: $State." }); CurrentValue = ''; RequiredValue = ''; Remediation = 'See the control.'
        AffectedObjects = @(); Instance = $Instance; FrameworkIds = @('NIST:AC-2')
        Timestamp = '2026-01-01T00:00:00.0000000+00:00'
    }
}
$row = {
    param([string] $Id, [string] $Title, [string] $Observed, [string] $Status, [string] $Code)
    [ordered]@{
        ControlId = $Id; Title = $Title; RequiredTier = 'Minimum'; Owner = 'MSP'; ExpectedState = 'As the baseline states.'; SlaClass = 'Standard'
        ObservedState = $Observed; ObservedFindingState = ''; Constraint = 'None'; Disposition = 'Normal'
        EffectivenessState = 'Unknown'; EffectivenessCapability = 'NotCollected'; EffectivenessDetail = ''
        DependsOn = @(); DependencyState = 'None'; EvidenceSource = 'Fixture'; EvidenceTimestamp = ''; EvidenceFreshness = 'Current'
        FreshnessClass = 'Weekly'; NotVerifiedCause = ''; ReasonCode = $Code; Reason = "Recorded as $Code."; Detail = ''
        ExceptionSummary = ''; BaselineStatus = $Status
    }
}
$meta = {
    param([string] $Domain, [string] $TenantId, [string] $Time, [int] $Score, [string] $Label)
    [ordered]@{
        TenantDomain = $Domain; TenantId = $TenantId; AssessmentTime = $Time
        AssessmentDate = ([datetime]::Parse($Time, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind)).ToUniversalTime().ToString('MMMM dd, yyyy', [cultureinfo]::InvariantCulture)
        ToolVersion = '4.14.3'; QuickScan = $false; BaselineVersion = '2.0'; TargetTier = 'Minimum'
        Maturity = [ordered]@{ Tier = 3; Label = $Label; ObservedLabel = $Label; Score = $Score; EvidenceComplete = $true; Qualification = '' }
    }
}
$baseline = {
    param([object[]] $Rows)
    $count = { param($s) @($Rows | Where-Object { $_.BaselineStatus -eq $s }).Count }
    [ordered]@{
        Available = $true; BaselineVersion = '2.0'; TargetTier = 'Minimum'
        Summary = [ordered]@{ RequiredControls = $Rows.Count; Satisfied = (& $count 'Satisfied'); Failed = (& $count 'Failed'); NotVerified = (& $count 'NotVerified'); NotApplicable = 0; LicenseBlocked = 0; ApprovedException = 0 }
        Controls = $Rows
    }
}
$contosoId = '6f1d2c3b-0000-4000-8000-00000000c0c0'

# ── contoso.example: three runs ──
& $put (Join-Path $out 'contoso.example' 'CONTOSO-20260902-090000-results.json') ([ordered]@{
    Metadata = (& $meta 'contoso.onmicrosoft.com' $contosoId '2026-09-02T09:00:00.0000000+00:00' 48 'Developing')
    Findings = @(
        (& $finding 'AAD-1.1' 'Satisfied' 'Critical' 'Legacy Authentication Blocked')
        (& $finding 'AAD-1.2' 'Gap' 'Critical' 'MFA Required for All Users')
        (& $finding 'AAD-1.3' 'Partial' 'Critical' 'Phishing-Resistant MFA Required for Admins')
        (& $finding 'DEF-2.1' 'Gap' 'Low' 'Preset Security Policies Applied')
        (& $finding 'EXO-1.1' 'NotApplicable' 'High' 'Mailbox Audit Logging Enabled' 'EXO-MailboxConfig was not collected; not assessed.')
        (& $finding 'DNS-1.1' 'Gap' 'High' 'SPF Record Published' 'No SPF record.' 'contoso.example')
        (& $finding 'DNS-1.1' 'Satisfied' 'High' 'SPF Record Published' 'SPF present.' 'contoso.net')
    )
    RawData = [ordered]@{ 'EXO-MailboxConfig' = [ordered]@{ CollectorId = 'EXO-MailboxConfig'; Success = $false; Data = [ordered]@{} } }
    Coverage = [ordered]@{ 'EXO-MailboxConfig' = [ordered]@{ Status = 'Failed'; Note = 'Exchange Online did not connect.' } }
    Exceptions = @()
    BaselineCompliance = (& $baseline @(
        (& $row 'AAD-1.1' 'Legacy Authentication Blocked' 'Satisfied' 'Satisfied' 'Satisfied')
        (& $row 'AAD-1.2' 'MFA Required for All Users' 'Failed' 'Failed' 'ControlFailed')
        (& $row 'EXO-1.1' 'Mailbox Audit Logging Enabled' 'NotVerified' 'NotVerified' 'CollectorUnavailable')
    ))
})
& $put (Join-Path $out 'contoso.example' 'CONTOSO-20261001-090000-results.json') ([ordered]@{
    Metadata = (& $meta 'contoso.onmicrosoft.com' $contosoId '2026-10-01T09:00:00.0000000+00:00' 55 'Defined')
    Findings = @(
        (& $finding 'AAD-1.1' 'Satisfied' 'Critical' 'Legacy Authentication Blocked')
        (& $finding 'AAD-1.2' 'Partial' 'Critical' 'MFA Required for All Users')
        (& $finding 'AAD-1.3' 'Partial' 'Critical' 'Phishing-Resistant MFA Required for Admins')
        (& $finding 'DEF-2.1' 'Partial' 'Low' 'Preset Security Policies Applied')
        (& $finding 'EXO-1.1' 'Satisfied' 'High' 'Mailbox Audit Logging Enabled')
        (& $finding 'DNS-1.1' 'Gap' 'High' 'SPF Record Published' 'No SPF record.' 'contoso.example')
    )
    RawData = [ordered]@{}; Coverage = [ordered]@{}; Exceptions = @()
})
& $put (Join-Path $out 'contoso.example' 'CONTOSO-20261028-090000-results.json') ([ordered]@{
    Metadata = (& $meta 'contoso.onmicrosoft.com' $contosoId '2026-10-28T09:00:00.0000000+00:00' 62 'Defined')
    Findings = @(
        (& $finding 'AAD-1.1' 'Satisfied' 'Critical' 'Legacy Authentication Blocked')
        (& $finding 'AAD-1.2' 'Partial' 'Critical' 'MFA Required for All Users')
        (& $finding 'AAD-1.3' 'Gap' 'Critical' 'Phishing-Resistant MFA Required for Admins')
        (& $finding 'PVW-1.1' 'NotApplicable' 'Critical' 'Unified Audit Log Enabled' 'Purview was not collected; not assessed.')
        (& $finding 'DEF-2.1' 'Satisfied' 'Low' 'Preset Security Policies Applied')
        (& $finding 'EXO-1.1' 'Gap' 'High' 'Mailbox Audit Logging Enabled')
        (& $finding 'INT-1.1' 'Gap' 'High' 'Device Compliance Policies Configured')
        (& $finding 'SPO-1.1' 'Satisfied' 'High' 'External Sharing Restricted')
        (& $finding 'DNS-1.1' 'Gap' 'High' 'SPF Record Published' 'No SPF record.' 'contoso.example')
        (& $finding 'DNS-1.1' 'Gap' 'High' 'SPF Record Published' 'SPF ends in +all.' 'contoso.net')
        (& $finding 'DNS-1.1' 'Satisfied' 'High' 'SPF Record Published' 'SPF present.' 'contoso.org')
    )
    RawData = [ordered]@{}; Coverage = [ordered]@{}; Exceptions = @()
    BaselineCompliance = (& $baseline @(
        (& $row 'AAD-1.1' 'Legacy Authentication Blocked' 'Satisfied' 'Satisfied' 'Satisfied')
        (& $row 'AAD-1.2' 'MFA Required for All Users' 'Failed' 'Failed' 'ControlFailed')
        (& $row 'AAD-1.3' 'Phishing-Resistant MFA Required for Admins' 'Failed' 'Failed' 'ControlFailed')
        (& $row 'EXO-1.1' 'Mailbox Audit Logging Enabled' 'Failed' 'Failed' 'ControlFailed')
        (& $row 'SPO-1.1' 'External Sharing Restricted' 'Satisfied' 'Satisfied' 'Satisfied')
        (& $row 'PVW-1.1' 'Unified Audit Log Enabled' 'NotVerified' 'NotVerified' 'CollectorUnavailable')
        (& $row 'TMS-1.1' 'External Federation Access Restricted' 'NotVerified' 'NotVerified' 'SkippedByOperator')
        (& $row 'CIS-1.3.6' 'Customer lockbox' 'NotVerified' 'NotVerified' 'ManualVerificationRequired')
    ))
    ChangeImpact = [ordered]@{
        Available = $true; Note = ''; RunScope = 'Full'; ScopeNotice = ''
        Summary = [ordered]@{ ImplementNow = 1; NeedsPlanning = 2; CouldBreakAccounts = 1; LicenseDecision = 0; AccountsNamed = 3 }
        ImplementNow = @([ordered]@{ ControlId = 'EXO-1.1'; Title = 'Mailbox Audit Logging Enabled'; Severity = 'High'; State = 'Gap' })
        NeedsPlanning = @(
            [ordered]@{ ControlId = 'AAD-1.2'; Title = 'MFA Required for All Users'; Severity = 'Critical'; State = 'Partial' }
            [ordered]@{ ControlId = 'INT-1.1'; Title = 'Device Compliance Policies Configured'; Severity = 'High'; State = 'Gap' })
        CouldBreakAccounts = @([ordered]@{ ControlId = 'AAD-1.3'; Title = 'Phishing-Resistant MFA Required for Admins'; Severity = 'Critical'; State = 'Gap'
            Why = 'Administrators without a phishing-resistant method are locked out of admin roles.'
            Evidence = @([ordered]@{ Type = 'AdminsWithoutPhishResistant'; Label = 'Administrators without a phishing-resistant method'; Role = 'WouldBreak'; Status = 'Named'; Complete = $true; Count = 3; NotShown = 0; Note = ''
                Accounts = @(
                    [ordered]@{ DisplayName = 'Avery Admin'; UserPrincipalName = 'avery.admin@contoso.example'; ObjectId = 'a0000000-0000-4000-8000-000000000001'; Detail = 'Global Administrator; Authenticator only.' }
                    [ordered]@{ DisplayName = 'Blake Admin'; UserPrincipalName = 'blake.admin@contoso.example'; ObjectId = 'a0000000-0000-4000-8000-000000000002'; Detail = 'Exchange Administrator; SMS only.' }
                    [ordered]@{ DisplayName = 'Casey Admin'; UserPrincipalName = 'casey.admin@contoso.example'; ObjectId = 'a0000000-0000-4000-8000-000000000003'; Detail = 'Security Administrator; no method.' }) }) })
        LicenseDecision = @()
        EmergencyAccess = [ordered]@{ Type = 'EmergencyAccess'; Label = 'Emergency-access accounts to exclude'; Role = 'MustExclude'; Status = 'NotRead'; Complete = $false; Count = 0; Accounts = @(); NotShown = 0; Note = 'None on record.' }
    }
})

# ── fabrikam.example: one run ──
& $put (Join-Path $out 'fabrikam.example' 'FABRIKAM-20261015-140000-results.json') ([ordered]@{
    Metadata = (& $meta 'fabrikam.onmicrosoft.com' '6f1d2c3b-0000-4000-8000-00000000fab0' '2026-10-15T14:00:00.0000000+00:00' 41 'Developing')
    Findings = @(
        (& $finding 'AAD-1.1' 'Gap' 'Critical' 'Legacy Authentication Blocked')
        (& $finding 'AAD-1.2' 'Gap' 'Critical' 'MFA Required for All Users')
        (& $finding 'SPO-1.1' 'Error' 'High' 'External Sharing Restricted' 'The check failed while reading the SharePoint settings.')
        (& $finding 'TMS-1.1' 'Satisfied' 'Medium' 'External Federation Access Restricted')
    )
    RawData = [ordered]@{}; Coverage = [ordered]@{}; Exceptions = @()
})

# ── NORTHWIND: one older flat run with 70 findings ──
$nw = [System.Collections.Generic.List[object]]::new()
foreach ($i in 1..15) { $nw.Add((& $finding ('AAD-9.{0}' -f $i) 'Gap' 'Medium' "Identity check $i")) }
foreach ($i in 1..10) { $nw.Add((& $finding ('DEF-9.{0}' -f $i) 'Satisfied' 'Medium' "Defender check $i")) }
foreach ($i in 1..20) { $nw.Add((& $finding ('TMS-9.{0}' -f $i) 'Satisfied' 'Low' "Teams check $i")) }
foreach ($i in 1..25) { $nw.Add((& $finding ('EXO-9.{0}' -f $i) 'Gap' 'Medium' "Exchange check $i")) }
& $put (Join-Path $out 'NORTHWIND-20250612-080000-results.json') ([ordered]@{
    Metadata = (& $meta 'northwind.onmicrosoft.com' '6f1d2c3b-0000-4000-8000-0000000000a0' '2025-06-12T08:00:00.0000000+00:00' 55 'Defined')
    Findings = $nw.ToArray()
    RawData = [ordered]@{}; Coverage = [ordered]@{}; Exceptions = @()
})

return $out
