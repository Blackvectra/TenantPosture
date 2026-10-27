#Requires -Version 7.0
#
# TP.SharePointSettings.Tests.ps1
# TenantPosture
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
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

        function script:Set-Spo([hashtable] $Graph = @{}, $Shell = $null) {
            $ts = @{
                IsLegacyAuthProtocolsEnabled = $false; IsUnmanagedSyncAppForTenantRestricted = $false
                SharingCapability = 'externalUserAndGuestSharing'; AllowedDomainGuidsForSyncApp = @()
                DeletedUserPersonalSiteRetentionPeriodInDays = 365
            }
            foreach ($k in $Graph.Keys) { $ts[$k] = $Graph[$k] }
            Set-TPRawData -Key 'SharePoint' -Data ([ordered]@{ CollectorId = 'SharePoint'; CollectedAt = '2026-09-25T00:00:00Z'; Success = $true
                Data = @{ TenantSettings = $ts; TenantSettingsSPO = $Shell; ExternalSharing = $ts.SharingCapability } })
        }
        function script:Verdict([string] $Fn, [string] $Cid) {
            Clear-TPState
            & $Fn | Out-Null
            @(Get-TPFindings | Where-Object ControlId -eq $Cid)[0]
        }
        function script:Run([string] $Fn, [string] $Cid, [hashtable] $Graph = @{}, $Shell = $null) {
            Clear-TPState; Set-Spo -Graph $Graph -Shell $Shell
            & $Fn | Out-Null
            @(Get-TPFindings | Where-Object ControlId -eq $Cid)[0]
        }
    }

    Context 'SPO-1.2 .. SPO-1.5 read their own settings' {
        It 'SPO-1.3 (legacy auth) is decided by IsLegacyAuthProtocolsEnabled' {
            (Run 'Test-TPControlSharePoint' 'SPO-1.3' @{ IsLegacyAuthProtocolsEnabled = $true }).State  | Should -Be 'Gap'
            (Run 'Test-TPControlSharePoint' 'SPO-1.3' @{ IsLegacyAuthProtocolsEnabled = $false }).State | Should -Be 'Satisfied'
        }
        It 'SPO-1.2 (default link not Anyone) is decided by the default link type, not legacy auth' {
            (Run 'Test-TPControlSharePoint' 'SPO-1.2' @{ IsLegacyAuthProtocolsEnabled = $false } @{ DefaultSharingLinkType = 'AnonymousAccess' }).State | Should -Be 'Gap'
            (Run 'Test-TPControlSharePoint' 'SPO-1.2' @{} @{ DefaultSharingLinkType = 'Internal' }).State | Should -Be 'Satisfied'
            (Run 'Test-TPControlSharePoint' 'SPO-1.2').State | Should -Be 'NotApplicable' -Because 'Anyone links on and the link type was not read'
        }
        It 'SPO-1.2 passes only what CIS v7.0.0 7.2.7 passes: DefaultSharingLinkType Direct or Internal, whatever the sharing capability' {
            foreach ($cap in @('disabled','existingExternalUserSharingOnly','externalUserSharingOnly','externalUserAndGuestSharing')) {
                (Run 'Test-TPControlSharePoint' 'SPO-1.2' @{ SharingCapability = $cap } @{ DefaultSharingLinkType = 'Direct' }).State   | Should -Be 'Satisfied' -Because "$cap with Direct"
                (Run 'Test-TPControlSharePoint' 'SPO-1.2' @{ SharingCapability = $cap } @{ DefaultSharingLinkType = 'Internal' }).State | Should -Be 'Satisfied' -Because "$cap with Internal"
                (Run 'Test-TPControlSharePoint' 'SPO-1.2' @{ SharingCapability = $cap } @{ DefaultSharingLinkType = 'AnonymousAccess' }).State | Should -Be 'Gap' -Because "$cap with AnonymousAccess fails 7.2.7"
                (Run 'Test-TPControlSharePoint' 'SPO-1.2' @{ SharingCapability = $cap } @{ DefaultSharingLinkType = 'None' }).State | Should -Be 'Gap' -Because "$cap with None fails 7.2.7"
            }
        }
        It 'SPO-1.2 does not pass from Anyone links being off: the link type unread is not assessed' {
            $f = Run 'Test-TPControlSharePoint' 'SPO-1.2' @{ SharingCapability = 'externalUserSharingOnly' }
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'IncludeSharePointShell'
            (Run 'Test-TPControlSharePoint' 'SPO-1.2' @{ SharingCapability = 'disabled' } @{ DefaultSharingLinkType = '' }).State | Should -Be 'NotApplicable'
            (Run 'Test-TPControlSharePoint' 'SPO-1.2' @{} @{ DefaultSharingLinkType = 'Teammates' }).State | Should -Be 'NotApplicable' -Because 'an unrecognized value is not judged'
        }
        It 'SPO-1.2 cites CIS Microsoft 365 v7.0.0 7.2.7' {
            (Get-TPControlById -ControlId 'SPO-1.2').References.CIS | Should -Be '7.2.7'
        }
        It 'SPO-1.4 (guest expiration) is decided by ExternalUserExpirationRequired' {
            (Run 'Test-TPControlSharePoint' 'SPO-1.4' @{} @{ ExternalUserExpirationRequired = $false; ExternalUserExpireInDays = 0 }).State | Should -Be 'Gap'
            (Run 'Test-TPControlSharePoint' 'SPO-1.4' @{} @{ ExternalUserExpirationRequired = $true; ExternalUserExpireInDays = 30 }).State | Should -Be 'Satisfied'
            (Run 'Test-TPControlSharePoint' 'SPO-1.4' @{} @{ ExternalUserExpirationRequired = $true; ExternalUserExpireInDays = 60 }).State | Should -Be 'Partial' -Because 'CIS Microsoft 365 Foundations v7.0.0 7.2.9 requires 30 days'
            (Run 'Test-TPControlSharePoint' 'SPO-1.4').State | Should -Be 'NotApplicable'
        }
        It 'SPO-1.5 (unmanaged devices) is decided by ConditionalAccessPolicy' {
            (Run 'Test-TPControlSharePoint' 'SPO-1.5' @{} @{ ConditionalAccessPolicy = 'AllowFullAccess' }).State    | Should -Be 'Gap'
            (Run 'Test-TPControlSharePoint' 'SPO-1.5' @{} @{ ConditionalAccessPolicy = 'AllowLimitedAccess' }).State | Should -Be 'Satisfied'
            (Run 'Test-TPControlSharePoint' 'SPO-1.5').State | Should -Be 'NotApplicable'
        }
        It 'SPO-1.1 does not give half credit for an unreadable sharing value' {
            (Run 'Test-TPControlSharePoint' 'SPO-1.1' @{ SharingCapability = '' }).State | Should -Be 'NotApplicable'
        }
    }

    Context 'guest and link controls on a tenant with external sharing disabled' {
        It 'SPO-2.2 / 2.6 / 2.7 / 3.4 do not raise gaps about links or guests that cannot exist' {
            $shell = @{ RequireAnonymousLinksExpireInDays = 0; EmailAttestationRequired = $false; EmailAttestationReAuthDays = 0; ExternalUserExpirationRequired = $false; ExternalUserExpireInDays = 0 }
            foreach ($p in @(@('Test-TPControlSPOLinkExpiration','SPO-2.2'), @('Test-TPControlSPOEmailAttestation','SPO-2.6'),
                             @('Test-TPControlSPOReauth','SPO-2.7'), @('Test-TPControlSPOGuestExpiry','SPO-3.4'))) {
                (Run $p[0] $p[1] @{ SharingCapability = 'disabled' } $shell).State | Should -Be 'NotApplicable' -Because $p[1]
            }
        }
        It 'SPO-2.2 applies only when Anyone links are enabled' {
            (Run 'Test-TPControlSPOLinkExpiration' 'SPO-2.2' @{ SharingCapability = 'externalUserSharingOnly' } @{ RequireAnonymousLinksExpireInDays = 0 }).State | Should -Be 'NotApplicable'
            (Run 'Test-TPControlSPOLinkExpiration' 'SPO-2.2' @{} @{ RequireAnonymousLinksExpireInDays = 0 }).State | Should -Be 'Gap'
        }
    }

    Context 'sync restriction and reauthentication read the switch that governs them' {
        It 'SPO-2.1 / SPO-2.8 do not pass on a leftover domain list with the restriction off' {
            $g = @{ IsUnmanagedSyncAppForTenantRestricted = $false; AllowedDomainGuidsForSyncApp = @('11111111-1111-1111-1111-111111111111') }
            (Run 'Test-TPControlSPOOneDriveSync' 'SPO-2.1' $g).State | Should -Be 'Gap'
            (Run 'Test-TPControlSPODomainSync'   'SPO-2.8' $g).State | Should -Be 'Gap'
            $g.IsUnmanagedSyncAppForTenantRestricted = $true
            (Run 'Test-TPControlSPOOneDriveSync' 'SPO-2.1' $g).State | Should -Be 'Satisfied'
            (Run 'Test-TPControlSPODomainSync'   'SPO-2.8' $g).State | Should -Be 'Satisfied'
        }
        It 'SPO-2.7 needs email attestation on; a leftover day count is not reauthentication' {
            (Run 'Test-TPControlSPOReauth' 'SPO-2.7' @{} @{ EmailAttestationRequired = $false; EmailAttestationReAuthDays = 30 }).State | Should -Be 'Gap'
            (Run 'Test-TPControlSPOReauth' 'SPO-2.7' @{} @{ EmailAttestationRequired = $true;  EmailAttestationReAuthDays = 15 }).State | Should -Be 'Satisfied'
            (Run 'Test-TPControlSPOReauth' 'SPO-2.7' @{} @{ EmailAttestationRequired = $true;  EmailAttestationReAuthDays = 30 }).State | Should -Be 'Partial' -Because 'CIS Microsoft 365 Foundations v7.0.0 7.2.10 requires 15 days or fewer'
            (Run 'Test-TPControlSPOReauth' 'SPO-2.7' @{} @{ EmailAttestationRequired = $true;  EmailAttestationReAuthDays = 90 }).State | Should -Be 'Partial'
        }
    }

    Context 'departed-user OneDrive retention' {
        It 'a retention value Graph did not return is not "0 days"' {
            $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Collectors/SharePoint/Invoke-TPCollectSharePoint.ps1') -Raw
            $src | Should -Match '\$retentionDays = \$null'
            $src | Should -Not -Match 'catch \{ \$retentionDays = 0 \}'
        }
    }

    Context 'SharePoint Online Management Shell (opt-in child process)' {
        It 'is off unless -IncludeSharePointShell is given, and is imported the way PowerShell 7 requires' {
            # Microsoft: in PowerShell 7 the module "must" be imported with
            # -UseWindowsPowerShell, which starts powershell.exe. MSP machines
            # can block that with an ASR rule, so it is opt-in.
            $entry = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
            $entry | Should -Match '\[switch\] \$IncludeSharePointShell'
            $entry | Should -Match "if \(-not \`$IncludeSharePointShell -or \`$SkipSharePoint\) \{ \`$connectParams\['SkipSharePoint'\] = \`$true \}"
            $connect = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Connect-TPServices.ps1') -Raw
            $connect | Should -Match "PSEdition -eq 'Core'"
            $connect | Should -Match 'Import-Module \$spoTarget -UseWindowsPowerShell'
        }
        It 'a control that needs the shell says how to get it' {
            Clear-TPState
            Set-TPRawData -Key 'SharePoint' -Data @{ Success = $true; Data = @{ SectionStatus = @{ TenantSettings = 'Collected' }; TenantSettings = @{ SharingCapability = 'ExternalUserAndGuestSharing' } } }
            Test-TPControlSharePoint 3>$null | Out-Null
            $f = @(Get-TPFindings | Where-Object ControlId -eq 'SPO-1.4')[0]
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '-IncludeSharePointShell'
        }
    }

    # A Get-SPOTenant property the installed module did not return is stored
    # as $null. It used to be a dot-read that threw under StrictMode (losing
    # every shell setting) and a ?? $false / ?? 0 default the evaluators scored.
    Context 'a shell property that was not returned is not read, never $false or 0' {
        It 'each shell control reports not assessed, naming the property, instead of scoring it' {
            $full = @{ RequireAnonymousLinksExpireInDays = 30; EmailAttestationRequired = $true; EmailAttestationReAuthDays = 15
                       NotifyOwnersWhenItemsReshared = $true; ExternalUserExpirationRequired = $true; ExternalUserExpireInDays = 60
                       EnableAutoExpirationVersionTrim = $true; MajorVersionLimit = 500 }
            foreach ($case in @(
                    @{ Fn = 'Test-TPControlSharePoint';             Cid = 'SPO-1.4'; Key = 'ExternalUserExpireInDays' },
                    @{ Fn = 'Test-TPControlSPOLinkExpiration';      Cid = 'SPO-2.2'; Key = 'RequireAnonymousLinksExpireInDays' },
                    @{ Fn = 'Test-TPControlSPOEmailAttestation';    Cid = 'SPO-2.6'; Key = 'EmailAttestationRequired' },
                    @{ Fn = 'Test-TPControlSPOReauth';              Cid = 'SPO-2.7'; Key = 'EmailAttestationReAuthDays' },
                    @{ Fn = 'Test-TPControlSPOSharingNotifications'; Cid = 'SPO-3.2'; Key = 'NotifyOwnersWhenItemsReshared' },
                    @{ Fn = 'Test-TPControlSPOGuestExpiry';         Cid = 'SPO-3.4'; Key = 'ExternalUserExpirationRequired' })) {
                $shell = $full.Clone(); $shell[$case.Key] = $null
                $f = Run $case.Fn $case.Cid @{} $shell
                $f.State  | Should -Be 'NotApplicable' -Because "$($case.Cid) with $($case.Key) not returned"
                $f.Detail | Should -Match ([regex]::Escape($case.Key))
            }
        }
        It 'SPO-3.3: unread auto-trim is not "off"; a limit of 100 or more passes either way' {
            (Run 'Test-TPControlSPOVersionHistory' 'SPO-3.3' @{} @{ EnableAutoExpirationVersionTrim = $null; MajorVersionLimit = 50 }).State  | Should -Be 'NotApplicable'
            (Run 'Test-TPControlSPOVersionHistory' 'SPO-3.3' @{} @{ EnableAutoExpirationVersionTrim = $null; MajorVersionLimit = 500; ExpireVersionsAfterDays = 0 }).State | Should -Be 'Satisfied'
            (Run 'Test-TPControlSPOVersionHistory' 'SPO-3.3' @{} @{ EnableAutoExpirationVersionTrim = $false; MajorVersionLimit = $null }).State | Should -Be 'NotApplicable'
        }
        It 'the collector keeps every property it can read when the module lacks a newer one' {
            $mod = Get-Module 'TenantPosture'
            $origGraph = & $mod { ${function:Invoke-TPGraphRequest} }
            & $mod {
                Set-Item -Path 'function:script:Get-SPOTenant' -Value {
                    # An older module: no EnableAutoExpirationVersionTrim at all.
                    [pscustomobject]@{ RequireAnonymousLinksExpireInDays = 30; EmailAttestationRequired = $false; EmailAttestationReAuthDays = 30
                                       NotifyOwnersWhenItemsReshared = $true; ExternalUserExpirationRequired = $true; ExternalUserExpireInDays = 60
                                       DefaultSharingLinkType = 'Internal'; ConditionalAccessPolicy = 'AllowFullAccess'; MajorVersionLimit = 500; ExpireVersionsAfterDays = 0 }
                }
                Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value { throw 'no Graph in this test' }
            }
            try {
                Clear-TPState
                Invoke-TPCollectSharePoint 3>$null | Out-Null
                $sh = (Get-TPRawData -Key 'SharePoint').Data.TenantSettingsSPO
                $sh | Should -Not -BeNullOrEmpty -Because 'one missing property must not lose the whole block'
                $sh['NotifyOwnersWhenItemsReshared'] | Should -BeExactly $true
                $sh['EmailAttestationRequired']      | Should -BeExactly $false
                $sh['MajorVersionLimit']             | Should -Be 500
                $null -eq $sh['EnableAutoExpirationVersionTrim'] | Should -BeTrue -Because 'not returned is not read, never $false'
            } finally {
                & $mod { param($o)
                    Remove-Item -Path 'function:script:Get-SPOTenant' -ErrorAction SilentlyContinue
                    Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value $o
                } $origGraph
            }
        }
    }

    # CIS Microsoft 365 v7.0.0 SharePoint / OneDrive recommendations no earlier
    # control read (SPO-5.x, Evaluators/Test-TPControlCollabCis.ps1).
    Context 'CIS v7 SharePoint settings (SPO-5.1 .. SPO-5.7)' {
        It 'SPO-5.1 (7.3.1) / SPO-5.2 (7.2.2): True passes, False is a Gap, no shell or not returned is not assessed' {
            foreach ($p in @(@('Test-TPControlSPOInfectedFileDownload','SPO-5.1','DisallowInfectedFileDownload'), @('Test-TPControlSPOB2BIntegration','SPO-5.2','EnableAzureADB2BIntegration'))) {
                (Run $p[0] $p[1] @{} @{ $p[2] = $true }).State  | Should -Be 'Satisfied' -Because $p[1]
                (Run $p[0] $p[1] @{} @{ $p[2] = $false }).State | Should -Be 'Gap' -Because $p[1]
                $f = Run $p[0] $p[1]
                $f.State  | Should -Be 'NotApplicable'
                $f.Detail | Should -Match '-IncludeSharePointShell'
                $f = Run $p[0] $p[1] @{} @{ $p[2] = $null }
                $f.State  | Should -Be 'NotApplicable'
                $f.Detail | Should -Match ([regex]::Escape($p[2]))
                @($f.FrameworkIds).Count | Should -BeGreaterThan 0
            }
        }
        It 'SPO-5.3 (7.2.4): Disabled passes; guest-only levels are part-way; Anyone is a Gap; SharePoint sharing off passes from Graph alone' {
            (Run 'Test-TPControlSPOOneDriveSharing' 'SPO-5.3' @{} @{ OneDriveSharingCapability = 'Disabled' }).State                        | Should -Be 'Satisfied'
            (Run 'Test-TPControlSPOOneDriveSharing' 'SPO-5.3' @{} @{ OneDriveSharingCapability = 'ExistingExternalUserSharingOnly' }).State  | Should -Be 'Partial'
            (Run 'Test-TPControlSPOOneDriveSharing' 'SPO-5.3' @{} @{ OneDriveSharingCapability = 'ExternalUserAndGuestSharing' }).State      | Should -Be 'Gap'
            (Run 'Test-TPControlSPOOneDriveSharing' 'SPO-5.3' @{ SharingCapability = 'disabled' }).State | Should -Be 'Satisfied' -Because 'OneDrive cannot be more permissive than SharePoint'
            (Run 'Test-TPControlSPOOneDriveSharing' 'SPO-5.3').State | Should -Be 'NotApplicable' -Because 'sharing on and the shell not connected'
            (Run 'Test-TPControlSPOOneDriveSharing' 'SPO-5.3' @{} @{ OneDriveSharingCapability = $null }).State | Should -Be 'NotApplicable'
        }
        It 'SPO-5.4 (7.2.5): reads Graph isResharingByExternalUsersEnabled; not returned is not assessed, never a pass' {
            (Run 'Test-TPControlSPOGuestResharing' 'SPO-5.4' @{ IsResharingByExternalUsersEnabled = $false }).State | Should -Be 'Satisfied'
            (Run 'Test-TPControlSPOGuestResharing' 'SPO-5.4' @{ IsResharingByExternalUsersEnabled = $true }).State  | Should -Be 'Gap'
            (Run 'Test-TPControlSPOGuestResharing' 'SPO-5.4' @{ IsResharingByExternalUsersEnabled = $null }).State  | Should -Be 'NotApplicable'
        }
        It 'SPO-5.5 (7.2.6): an allow list naming a domain passes, a block list or none is a Gap, an empty allow list is not assessed' {
            (Run 'Test-TPControlSPODomainAllowList' 'SPO-5.5' @{ SharingDomainRestrictionMode = 'allowList'; SharingAllowedDomainList = @('partner.example') }).State | Should -Be 'Satisfied'
            (Run 'Test-TPControlSPODomainAllowList' 'SPO-5.5' @{ SharingDomainRestrictionMode = 'blockList'; SharingBlockedDomainList = @('bad.example') }).State   | Should -Be 'Gap'
            (Run 'Test-TPControlSPODomainAllowList' 'SPO-5.5' @{ SharingDomainRestrictionMode = 'none' }).State | Should -Be 'Gap'
            (Run 'Test-TPControlSPODomainAllowList' 'SPO-5.5' @{ SharingDomainRestrictionMode = 'allowList'; SharingAllowedDomainList = @() }).State | Should -Be 'NotApplicable'
            (Run 'Test-TPControlSPODomainAllowList' 'SPO-5.5' @{ SharingDomainRestrictionMode = '' }).State | Should -Be 'NotApplicable'
            (Run 'Test-TPControlSPODomainAllowList' 'SPO-5.5' @{ SharingCapability = 'disabled'; SharingDomainRestrictionMode = 'none' }).State | Should -Be 'Satisfied'
        }
        It 'SPO-5.6 (7.2.8): a group sharing with authenticated guests passes; Anyone-only groups or none is a Gap' {
            (Run 'Test-TPControlSPOSharingGroups' 'SPO-5.6' @{} @{ WhoCanShareAuthenticatedGuestAllowListCount = 1; WhoCanShareAnonymousAllowListCount = 0 }).State | Should -Be 'Satisfied'
            $f = Run 'Test-TPControlSPOSharingGroups' 'SPO-5.6' @{} @{ WhoCanShareAuthenticatedGuestAllowListCount = 0; WhoCanShareAnonymousAllowListCount = 2 }
            $f.State  | Should -Be 'Gap'
            $f.Detail | Should -Match 'share with Anyone'
            (Run 'Test-TPControlSPOSharingGroups' 'SPO-5.6' @{ SharingCapability = 'disabled' }).State | Should -Be 'Satisfied'
            $f = Run 'Test-TPControlSPOSharingGroups' 'SPO-5.6' @{} @{ WhoCanShareAuthenticatedGuestAllowListCount = $null }
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'WhoCanShareAuthenticatedGuestAllowList\b'
        }
        It 'SPO-5.7 (7.2.11): View passes, Edit is a Gap, anything else is not assessed' {
            (Run 'Test-TPControlSPODefaultLinkPermission' 'SPO-5.7' @{} @{ DefaultLinkPermission = 'View' }).State | Should -Be 'Satisfied'
            (Run 'Test-TPControlSPODefaultLinkPermission' 'SPO-5.7' @{} @{ DefaultLinkPermission = 'Edit' }).State | Should -Be 'Gap'
            (Run 'Test-TPControlSPODefaultLinkPermission' 'SPO-5.7' @{} @{ DefaultLinkPermission = 'None' }).State | Should -Be 'NotApplicable'
        }
        It 'the collector reads the new shell values from Get-SPOTenant; an empty group list is 0 and an absent one is not read' {
            $mod = Get-Module 'TenantPosture'
            $origGraph = & $mod { ${function:Invoke-TPGraphRequest} }
            & $mod {
                Set-Item -Path 'function:script:Get-SPOTenant' -Value {
                    # No WhoCanShareAnonymousAllowList: an older module.
                    [pscustomobject]@{ DisallowInfectedFileDownload = $true; EnableAzureADB2BIntegration = $false; OneDriveSharingCapability = 'Disabled'
                                       DefaultLinkPermission = 'Edit'; WhoCanShareAuthenticatedGuestAllowList = @() }
                }
                Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value { throw 'no Graph in this test' }
            }
            try {
                Clear-TPState
                Invoke-TPCollectSharePoint 3>$null | Out-Null
                $sh = (Get-TPRawData -Key 'SharePoint').Data.TenantSettingsSPO
                $sh['DisallowInfectedFileDownload'] | Should -BeExactly $true
                $sh['EnableAzureADB2BIntegration']  | Should -BeExactly $false
                $sh['OneDriveSharingCapability']    | Should -Be 'Disabled'
                $sh['DefaultLinkPermission']        | Should -Be 'Edit'
                $sh['WhoCanShareAuthenticatedGuestAllowListCount'] | Should -Be 0
                $null -eq $sh['WhoCanShareAnonymousAllowListCount'] | Should -BeTrue -Because 'not returned is not read'
                Test-TPControlSPOSharingGroups | Out-Null
                @(Get-TPFindings | Where-Object ControlId -eq 'SPO-5.6')[0].State | Should -Be 'NotApplicable' -Because 'an empty group list with the sharing capability unread cannot tell sharing off from open'
            } finally {
                & $mod { param($o)
                    Remove-Item -Path 'function:script:Get-SPOTenant' -ErrorAction SilentlyContinue
                    Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value $o
                } $origGraph
            }
        }
    }
}
