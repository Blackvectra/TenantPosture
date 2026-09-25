#Requires -Version 7.0
#
# NRG.SharePointSettings.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# SPO-1.2 .. SPO-1.5 each scored a DIFFERENT setting than the control's
# title, description and citations name (SPO-1.2 "Default Sharing Link Not
# Anonymous" scored legacy auth, and so on) — a false statement on every run.
# Also pinned: guest/link controls do not score a tenant whose external
# sharing is disabled; sync restriction needs the restriction flag (a
# disabled restriction keeps its domain GUIDs); reauthentication needs email
# attestation; a missing retention value is not "0 days".

Describe 'SharePoint settings are read for the control that names them' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        function script:Set-Spo([hashtable] $Graph = @{}, $Shell = $null) {
            $ts = @{
                IsLegacyAuthProtocolsEnabled = $false; IsUnmanagedSyncAppForTenantRestricted = $false
                SharingCapability = 'externalUserAndGuestSharing'; AllowedDomainGuidsForSyncApp = @()
                DeletedUserPersonalSiteRetentionPeriodInDays = 365
            }
            foreach ($k in $Graph.Keys) { $ts[$k] = $Graph[$k] }
            Set-NRGRawData -Key 'SharePoint' -Data ([ordered]@{ CollectorId = 'SharePoint'; CollectedAt = '2026-09-25T00:00:00Z'; Success = $true
                Data = @{ TenantSettings = $ts; TenantSettingsSPO = $Shell; ExternalSharing = $ts.SharingCapability } })
        }
        function script:Verdict([string] $Fn, [string] $Cid) {
            Clear-NRGState
            & $Fn | Out-Null
            @(Get-NRGFindings | Where-Object ControlId -eq $Cid)[0]
        }
        function script:Run([string] $Fn, [string] $Cid, [hashtable] $Graph = @{}, $Shell = $null) {
            Clear-NRGState; Set-Spo -Graph $Graph -Shell $Shell
            & $Fn | Out-Null
            @(Get-NRGFindings | Where-Object ControlId -eq $Cid)[0]
        }
    }

    Context 'SPO-1.2 .. SPO-1.5 read their own settings' {
        It 'SPO-1.3 (legacy auth) is decided by IsLegacyAuthProtocolsEnabled' {
            (Run 'Test-NRGControlSharePoint' 'SPO-1.3' @{ IsLegacyAuthProtocolsEnabled = $true }).State  | Should -Be 'Gap'
            (Run 'Test-NRGControlSharePoint' 'SPO-1.3' @{ IsLegacyAuthProtocolsEnabled = $false }).State | Should -Be 'Satisfied'
        }
        It 'SPO-1.2 (default link not Anyone) is decided by the default link type, not legacy auth' {
            (Run 'Test-NRGControlSharePoint' 'SPO-1.2' @{ IsLegacyAuthProtocolsEnabled = $false } @{ DefaultSharingLinkType = 'AnonymousAccess' }).State | Should -Be 'Gap'
            (Run 'Test-NRGControlSharePoint' 'SPO-1.2' @{} @{ DefaultSharingLinkType = 'Internal' }).State | Should -Be 'Satisfied'
            (Run 'Test-NRGControlSharePoint' 'SPO-1.2' @{ SharingCapability = 'externalUserSharingOnly' }).State | Should -Be 'Satisfied' -Because 'Anyone links are off, so the default cannot be Anyone'
            (Run 'Test-NRGControlSharePoint' 'SPO-1.2').State | Should -Be 'NotApplicable' -Because 'Anyone links on and the link type was not read'
        }
        It 'SPO-1.4 (guest expiration) is decided by ExternalUserExpirationRequired' {
            (Run 'Test-NRGControlSharePoint' 'SPO-1.4' @{} @{ ExternalUserExpirationRequired = $false; ExternalUserExpireInDays = 0 }).State | Should -Be 'Gap'
            (Run 'Test-NRGControlSharePoint' 'SPO-1.4' @{} @{ ExternalUserExpirationRequired = $true; ExternalUserExpireInDays = 60 }).State | Should -Be 'Satisfied'
            (Run 'Test-NRGControlSharePoint' 'SPO-1.4').State | Should -Be 'NotApplicable'
        }
        It 'SPO-1.5 (unmanaged devices) is decided by ConditionalAccessPolicy' {
            (Run 'Test-NRGControlSharePoint' 'SPO-1.5' @{} @{ ConditionalAccessPolicy = 'AllowFullAccess' }).State    | Should -Be 'Gap'
            (Run 'Test-NRGControlSharePoint' 'SPO-1.5' @{} @{ ConditionalAccessPolicy = 'AllowLimitedAccess' }).State | Should -Be 'Satisfied'
            (Run 'Test-NRGControlSharePoint' 'SPO-1.5').State | Should -Be 'NotApplicable'
        }
        It 'SPO-1.1 does not give half credit for an unreadable sharing value' {
            (Run 'Test-NRGControlSharePoint' 'SPO-1.1' @{ SharingCapability = '' }).State | Should -Be 'NotApplicable'
        }
    }

    Context 'guest and link controls on a tenant with external sharing disabled' {
        It 'SPO-2.2 / 2.6 / 2.7 / 3.4 do not raise gaps about links or guests that cannot exist' {
            $shell = @{ RequireAnonymousLinksExpireInDays = 0; EmailAttestationRequired = $false; EmailAttestationReAuthDays = 0; ExternalUserExpirationRequired = $false; ExternalUserExpireInDays = 0 }
            foreach ($p in @(@('Test-NRGControlSPOLinkExpiration','SPO-2.2'), @('Test-NRGControlSPOEmailAttestation','SPO-2.6'),
                             @('Test-NRGControlSPOReauth','SPO-2.7'), @('Test-NRGControlSPOGuestExpiry','SPO-3.4'))) {
                (Run $p[0] $p[1] @{ SharingCapability = 'disabled' } $shell).State | Should -Be 'NotApplicable' -Because $p[1]
            }
        }
        It 'SPO-2.2 applies only when Anyone links are enabled' {
            (Run 'Test-NRGControlSPOLinkExpiration' 'SPO-2.2' @{ SharingCapability = 'externalUserSharingOnly' } @{ RequireAnonymousLinksExpireInDays = 0 }).State | Should -Be 'NotApplicable'
            (Run 'Test-NRGControlSPOLinkExpiration' 'SPO-2.2' @{} @{ RequireAnonymousLinksExpireInDays = 0 }).State | Should -Be 'Gap'
        }
    }

    Context 'sync restriction and reauthentication read the switch that governs them' {
        It 'SPO-2.1 / SPO-2.8 do not pass on a leftover domain list with the restriction off' {
            $g = @{ IsUnmanagedSyncAppForTenantRestricted = $false; AllowedDomainGuidsForSyncApp = @('11111111-1111-1111-1111-111111111111') }
            (Run 'Test-NRGControlSPOOneDriveSync' 'SPO-2.1' $g).State | Should -Be 'Gap'
            (Run 'Test-NRGControlSPODomainSync'   'SPO-2.8' $g).State | Should -Be 'Gap'
            $g.IsUnmanagedSyncAppForTenantRestricted = $true
            (Run 'Test-NRGControlSPOOneDriveSync' 'SPO-2.1' $g).State | Should -Be 'Satisfied'
            (Run 'Test-NRGControlSPODomainSync'   'SPO-2.8' $g).State | Should -Be 'Satisfied'
        }
        It 'SPO-2.7 needs email attestation on; a leftover day count is not reauthentication' {
            (Run 'Test-NRGControlSPOReauth' 'SPO-2.7' @{} @{ EmailAttestationRequired = $false; EmailAttestationReAuthDays = 30 }).State | Should -Be 'Gap'
            (Run 'Test-NRGControlSPOReauth' 'SPO-2.7' @{} @{ EmailAttestationRequired = $true;  EmailAttestationReAuthDays = 30 }).State | Should -Be 'Satisfied'
            (Run 'Test-NRGControlSPOReauth' 'SPO-2.7' @{} @{ EmailAttestationRequired = $true;  EmailAttestationReAuthDays = 90 }).State | Should -Be 'Partial'
        }
    }

    Context 'departed-user OneDrive retention' {
        It 'a retention value Graph did not return is not "0 days"' {
            $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Collectors/SharePoint/Invoke-NRGCollectSharePoint.ps1') -Raw
            $src | Should -Match '\$retentionDays = \$null'
            $src | Should -Not -Match 'catch \{ \$retentionDays = 0 \}'
        }
    }
}
