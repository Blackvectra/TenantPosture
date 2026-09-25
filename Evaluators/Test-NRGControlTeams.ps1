#Requires -Version 7.0
#
# Test-NRGControlTeams.ps1
# NRG Technology Services / NextLayerSec LLC — Author: Matthew Levorson
# Evaluates Microsoft Teams controls. Reads: Get-NRGRawData -Key 'Teams'
# (TMS-1.5 and TMS-3.4 read 'Purview'; TMS-1.6 reads the Entra guest-invite
# setting from AAD-IdentityGovernance / AAD-AuthPolicies).
#
# Controls: TMS-1.1 through TMS-4.4 (22 controls).
#   Config/controls.json is authoritative — each control's EvaluatorFunction
#   names the function in this file that scores it.
#
# Every setting is read as collected: a property the Teams module did not
# return is $null and reported "not assessed", never defaulted to the secure
# or the insecure value. Settings Microsoft has retired or that the platform
# enforces on its own are reported as such rather than scored.
#

# The collected section, or $null when it was not collected.
function Get-NRGTeamsSection {
    [CmdletBinding()]
    param([AllowNull()] $Teams, [Parameter(Mandatory)] [string] $Name)
    if (-not $Teams -or -not $Teams.Success) { return $null }
    if (-not (Test-NRGSectionCollected $Teams $Name)) { return $null }
    return (Get-NRGNestedProperty -Object $Teams -Path "Data.$Name" -Default $null)
}

# Federation mode from Get-CsTenantFederationConfiguration:
#   Disabled  — no external (federated) access at all
#   AllowList — only the listed domains
#   BlockList — every domain except the listed ones
#   Open      — every domain
# $null when AllowFederatedUsers was not returned.
function Get-NRGTeamsFederationMode {
    [CmdletBinding()]
    param([AllowNull()] $Federation)
    if (-not $Federation) { return $null }
    $on = Get-NRGObjectField -Item $Federation -Key 'AllowFederatedUsers' -Default $null
    if ($null -eq $on) { return $null }
    if (-not [bool]$on) { return 'Disabled' }
    if (@(Get-NRGObjectField -Item $Federation -Key 'AllowedDomains' -Default @() | Where-Object { $_ }).Count -gt 0) { return 'AllowList' }
    if (@(Get-NRGObjectField -Item $Federation -Key 'BlockedDomains' -Default @() | Where-Object { $_ }).Count -gt 0) { return 'BlockList' }
    return 'Open'
}

# Third-party storage connectors in the Teams client (TMS-2.3, SPO-2.5).
# Egnyte is reported only by newer MicrosoftTeams modules; when absent it is
# named as unchecked rather than assumed off.
function Get-NRGTeamsStorageProviderState {
    [CmdletBinding()]
    param([AllowNull()] $ClientConfiguration)
    $core = [ordered]@{ Dropbox = 'AllowDropBox'; Box = 'AllowBox'; 'Google Drive' = 'AllowGoogleDrive'; ShareFile = 'AllowShareFile' }
    $enabled = @(); $unread = @(); $checked = @()
    foreach ($k in $core.Keys) {
        $v = Get-NRGObjectField -Item $ClientConfiguration -Key $core[$k] -Default $null
        if ($null -eq $v) { $unread += $k } else { $checked += $k; if ([bool]$v) { $enabled += $k } }
    }
    $note = ''
    $eg = Get-NRGObjectField -Item $ClientConfiguration -Key 'AllowEgnyte' -Default $null
    if ($null -eq $eg) { $note = ' Egnyte was not reported by this MicrosoftTeams module version and was not checked.' }
    else { $checked += 'Egnyte'; if ([bool]$eg) { $enabled += 'Egnyte' } }
    return @{ Enabled = $enabled; Unread = $unread; Checked = $checked; Note = $note }
}

function Test-NRGControlTeams {
    [CmdletBinding()] param()
    $raw = Get-NRGRawData -Key 'Teams'
    if (-not $raw -or -not $raw.Success) {
        foreach ($cid in @('TMS-1.1','TMS-1.3','TMS-1.2','TMS-1.4','TMS-1.6')) {
            $c = Get-NRGControlById -ControlId $cid
            if ($c) {
                Add-NRGFinding -ControlId $cid -State 'NotApplicable' `
                    -Category 'Teams' -Title $c.Title -FrameworkIds (Get-NRGFrameworkCitations -ControlId $cid) `
                    -Detail 'Teams collector did not run.'
            }
        }
        return
    }

    $fed  = Get-NRGTeamsSection -Teams $raw -Name 'FederationConfig'
    $meet = Get-NRGTeamsSection -Teams $raw -Name 'MeetingPolicy'
    $mcfg = Get-NRGTeamsSection -Teams $raw -Name 'MeetingConfiguration'
    $cli  = Get-NRGTeamsSection -Teams $raw -Name 'ClientConfiguration'

    # TMS-1.1 — External federation
    $c = Get-NRGControlById -ControlId 'TMS-1.1'
    if ($c) {
        $cit  = Get-NRGFrameworkCitations -ControlId 'TMS-1.1'
        $mode = Get-NRGTeamsFederationMode -Federation $fed
        if (-not $mode) {
            Add-NRGFinding -ControlId 'TMS-1.1' -State 'NotApplicable' -Category 'Teams' -Title $c.Title -FrameworkIds $cit `
                -Detail 'Federation configuration (AllowFederatedUsers) was not collected; not assessed.'
        } elseif ($mode -in @('Disabled','AllowList')) {
            $cv = if ($mode -eq 'Disabled') { 'External federation: disabled' } else { "Federation restricted to $(@($fed.AllowedDomains).Count) allowlisted domain(s)" }
            Add-NRGFinding -ControlId 'TMS-1.1' -State 'Satisfied' -Category 'Teams' -Title $c.Title -Severity 'Informational' -FrameworkIds $cit -CurrentValue $cv
        } elseif ($mode -eq 'BlockList') {
            Add-NRGFinding -ControlId 'TMS-1.1' -State 'Partial' -Category 'Teams' -Title $c.Title -Severity 'Medium' -FrameworkIds $cit `
                -Detail "Federation is open to every domain except $(@($fed.BlockedDomains).Count) blocked domain(s). Any other Teams tenant can reach users in this tenant." `
                -CurrentValue 'Blocklist mode' -RequiredValue 'Allow-list of trusted domains, or federation disabled' -Remediation $c.Remediation
        } else {
            Add-NRGFinding -ControlId 'TMS-1.1' -State 'Gap' -Category 'Teams' -Title $c.Title -Severity $c.Severity -FrameworkIds $cit `
                -Detail 'Federation is enabled with no allow-list — any Teams tenant can communicate with users in this tenant.' `
                -CurrentValue 'Allow all external domains' -RequiredValue 'Allow-list of trusted domains, or federation disabled' -Remediation $c.Remediation
        }
    }

    # TMS-1.3 — Anonymous meeting join. Blocked org-wide by
    # DisableAnonymousJoin or per policy by AllowAnonymousUsersToJoinMeeting.
    # Allowed but held in the lobby is part-way; admitted straight in is the Gap.
    $c = Get-NRGControlById -ControlId 'TMS-1.3'
    if ($c) {
        $cit   = Get-NRGFrameworkCitations -ControlId 'TMS-1.3'
        $orgNo = Get-NRGObjectField -Item $mcfg -Key 'DisableAnonymousJoin' -Default $null
        $join  = Get-NRGObjectField -Item $meet -Key 'AllowAnonymousUsersToJoinMeeting' -Default $null
        $admit = [string](Get-NRGObjectField -Item $meet -Key 'AutoAdmittedUsers' -Default '')
        if ($orgNo -eq $true) {
            Add-NRGFinding -ControlId 'TMS-1.3' -State 'Satisfied' -Category 'Teams' -Title $c.Title -Severity 'Informational' -FrameworkIds $cit -CurrentValue 'Anonymous join: blocked organization-wide (DisableAnonymousJoin)'
        } elseif ($join -eq $false) {
            Add-NRGFinding -ControlId 'TMS-1.3' -State 'Satisfied' -Category 'Teams' -Title $c.Title -Severity 'Informational' -FrameworkIds $cit -CurrentValue 'Anonymous join: blocked by the global meeting policy'
        } elseif ($null -eq $join -or $null -eq $orgNo -or -not $admit) {
            Add-NRGFinding -ControlId 'TMS-1.3' -State 'NotApplicable' -Category 'Teams' -Title $c.Title -FrameworkIds $cit `
                -Detail 'The anonymous-join settings (meeting policy, organization meeting configuration, lobby) were not all collected; not assessed.'
        } elseif ($admit -eq 'Everyone') {
            Add-NRGFinding -ControlId 'TMS-1.3' -State 'Gap' -Category 'Teams' -Title $c.Title -Severity $c.Severity -FrameworkIds $cit `
                -Detail 'Anonymous users can join meetings and everyone bypasses the lobby, so an unauthenticated attendee with the link is admitted without anyone letting them in.' `
                -CurrentValue 'AllowAnonymousUsersToJoinMeeting = True; AutoAdmittedUsers = Everyone' -RequiredValue 'AllowAnonymousUsersToJoinMeeting = False' -Remediation $c.Remediation
        } else {
            Add-NRGFinding -ControlId 'TMS-1.3' -State 'Partial' -Category 'Teams' -Title $c.Title -Severity 'Medium' -FrameworkIds $cit `
                -Detail "Anonymous users can join meetings, but wait in the lobby until admitted (AutoAdmittedUsers = $admit)." `
                -CurrentValue 'AllowAnonymousUsersToJoinMeeting = True' -RequiredValue 'AllowAnonymousUsersToJoinMeeting = False' -Remediation $c.Remediation
        }
    }

    # TMS-1.2 — Teams consumer (personal account) access
    $c = Get-NRGControlById -ControlId 'TMS-1.2'
    if ($c) {
        $cit = Get-NRGFrameworkCitations -ControlId 'TMS-1.2'
        $consumer = Get-NRGObjectField -Item $fed -Key 'AllowTeamsConsumer' -Default $null
        $inbound  = Get-NRGObjectField -Item $fed -Key 'AllowTeamsConsumerInbound' -Default $null
        if ($consumer -eq $false) {
            Add-NRGFinding -ControlId 'TMS-1.2' -State 'Satisfied' -Category 'Teams' -Title $c.Title -Severity 'Informational' -FrameworkIds $cit -CurrentValue 'Consumer Teams: blocked'
        } elseif ($null -eq $consumer -or $null -eq $inbound) {
            Add-NRGFinding -ControlId 'TMS-1.2' -State 'NotApplicable' -Category 'Teams' -Title $c.Title -FrameworkIds $cit `
                -Detail 'AllowTeamsConsumer / AllowTeamsConsumerInbound were not collected; not assessed.'
        } elseif ($inbound -eq $false) {
            Add-NRGFinding -ControlId 'TMS-1.2' -State 'Partial' -Category 'Teams' -Title $c.Title -Severity 'Medium' -FrameworkIds $cit `
                -Detail 'Users can start chats with personal (consumer) Teams accounts, but consumer accounts cannot start a conversation with them.' `
                -CurrentValue 'AllowTeamsConsumer = True; AllowTeamsConsumerInbound = False' -RequiredValue 'AllowTeamsConsumer = False' -Remediation $c.Remediation
        } else {
            Add-NRGFinding -ControlId 'TMS-1.2' -State 'Gap' -Category 'Teams' -Title $c.Title -Severity $c.Severity -FrameworkIds $cit `
                -Detail 'Personal (consumer) Teams accounts can find and message users in this tenant — an unverified identity reaching staff directly, outside email filtering.' `
                -CurrentValue 'AllowTeamsConsumer = True; AllowTeamsConsumerInbound = True' -RequiredValue 'AllowTeamsConsumer = False' -Remediation $c.Remediation
        }
    }

    # TMS-1.4 — External participants cannot take or request screen control
    $c = Get-NRGControlById -ControlId 'TMS-1.4'
    if ($c) {
        $cit = Get-NRGFrameworkCitations -ControlId 'TMS-1.4'
        $give = Get-NRGObjectField -Item $meet -Key 'AllowExternalParticipantGiveRequestControl' -Default $null
        if ($null -eq $give) {
            Add-NRGFinding -ControlId 'TMS-1.4' -State 'NotApplicable' -Category 'Teams' -Title $c.Title -FrameworkIds $cit `
                -Detail 'AllowExternalParticipantGiveRequestControl was not collected; not assessed.'
        } elseif (-not [bool]$give) {
            Add-NRGFinding -ControlId 'TMS-1.4' -State 'Satisfied' -Category 'Teams' -Title $c.Title -Severity 'Informational' -FrameworkIds $cit -CurrentValue 'External participants cannot give or request control'
        } else {
            Add-NRGFinding -ControlId 'TMS-1.4' -State 'Gap' -Category 'Teams' -Title $c.Title -Severity $c.Severity -FrameworkIds $cit `
                -Detail 'External participants can give or request control of a shared screen, so a participant from outside the organization can operate a presenter''s desktop once control is accepted.' `
                -CurrentValue 'AllowExternalParticipantGiveRequestControl = True' -RequiredValue 'AllowExternalParticipantGiveRequestControl = False' -Remediation $c.Remediation
        }
    }

    # TMS-1.5 is scored by Test-NRGControlTeamsRecordingRetention (Purview).

    # TMS-1.6 — Guest access controlled: off in Teams, or on with invitations
    # limited to admins and the Guest Inviter role (Entra allowInvitesFrom).
    $c = Get-NRGControlById -ControlId 'TMS-1.6'
    if ($c) {
        $cit = Get-NRGFrameworkCitations -ControlId 'TMS-1.6'
        $guest = Get-NRGObjectField -Item $cli -Key 'AllowGuestUser' -Default $null
        $invites = ''
        foreach ($src in @(@{ K = 'AAD-IdentityGovernance'; P = 'Data.ExternalCollab.AllowInvitesFrom' }, @{ K = 'AAD-AuthPolicies'; P = 'Data.AuthorizationPolicy.AllowInvitesFrom' })) {
            $r = Get-NRGRawData -Key $src.K
            if ($r -and $r.Success) {
                $v = [string](Get-NRGNestedProperty -Object $r -Path $src.P -Default '')
                if ($v -and $v -ne 'unknown') { $invites = $v; break }
            }
        }
        if ($null -eq $guest) {
            Add-NRGFinding -ControlId 'TMS-1.6' -State 'NotApplicable' -Category 'Teams' -Title $c.Title -FrameworkIds $cit -Detail 'AllowGuestUser (Teams client configuration) was not collected; not assessed.'
        } elseif (-not [bool]$guest) {
            Add-NRGFinding -ControlId 'TMS-1.6' -State 'Satisfied' -Category 'Teams' -Title $c.Title -Severity 'Informational' -FrameworkIds $cit -CurrentValue 'Teams guest access: off'
        } elseif (-not $invites) {
            Add-NRGFinding -ControlId 'TMS-1.6' -State 'NotApplicable' -Category 'Teams' -Title $c.Title -FrameworkIds $cit `
                -Detail 'Teams guest access is on, but who may invite guests (Entra allowInvitesFrom) was not collected; not assessed.'
        } elseif ($invites -in @('none','adminsAndGuestInviters')) {
            Add-NRGFinding -ControlId 'TMS-1.6' -State 'Satisfied' -Category 'Teams' -Title $c.Title -Severity 'Informational' -FrameworkIds $cit `
                -CurrentValue "Teams guest access on; invitations limited ($invites)"
        } elseif ($invites -eq 'adminsGuestInvitersAndAllMembers') {
            Add-NRGFinding -ControlId 'TMS-1.6' -State 'Partial' -Category 'Teams' -Title $c.Title -Severity 'Medium' -FrameworkIds $cit `
                -Detail 'Teams guest access is on and every member can invite guests (guests themselves cannot).' `
                -CurrentValue "AllowGuestUser = True; allowInvitesFrom = $invites" -RequiredValue 'Invitations limited to admins and the Guest Inviter role, or Teams guest access off' -Remediation $c.Remediation
        } else {
            Add-NRGFinding -ControlId 'TMS-1.6' -State 'Gap' -Category 'Teams' -Title $c.Title -Severity $c.Severity -FrameworkIds $cit `
                -Detail "Teams guest access is on and invitations are open to everyone, including existing guests (allowInvitesFrom = $invites)." `
                -CurrentValue "AllowGuestUser = True; allowInvitesFrom = $invites" -RequiredValue 'Invitations limited to admins and the Guest Inviter role, or Teams guest access off' -Remediation $c.Remediation
        }
    }
}

# ── TMS-1.5 Recording Storage in Organization ────────────────────────────────
# Meeting recordings are always saved to the organizer's OneDrive (or the
# channel's SharePoint site); what the control asks is whether an
# organization retention policy governs them there.
function Test-NRGControlTeamsRecordingRetention {
    [CmdletBinding()] param()
    $cid = 'TMS-1.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success -or -not (Test-NRGSectionCollected $pvw 'RetentionPolicies')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category 'Teams' -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'Purview retention policies were not collected, so whether a retention policy covers the OneDrive and SharePoint locations holding meeting recordings was not assessed.'
        return
    }
    $enabled = @(@(Get-NRGObjectField -Item $pvw.Data -Key 'RetentionPolicies' -Default @()) | Where-Object { (Get-NRGObjectField -Item $_ -Key 'Enabled' -Default $false) -eq $true })
    $wl = { param($p) @(Get-NRGObjectField -Item $p -Key 'Workloads' -Default @() | ForEach-Object { [string]$_ }) }
    $od = @($enabled | Where-Object { @(& $wl $_) -match 'OneDrive' })
    $sp = @($enabled | Where-Object { @(& $wl $_) -contains 'SharePoint' })
    if ($od.Count -gt 0 -and $sp.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category 'Teams' -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'Enabled retention policies cover both OneDrive (meeting recordings) and SharePoint (channel meeting recordings).'
    } elseif ($od.Count -gt 0 -or $sp.Count -gt 0) {
        $missing = if ($od.Count -eq 0) { 'OneDrive, where meeting recordings are saved' } else { 'SharePoint, where channel meeting recordings are saved' }
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category 'Teams' -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "An enabled retention policy covers one of the recording locations but not $missing." `
            -RequiredValue 'Enabled retention policies covering OneDrive and SharePoint' -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category 'Teams' -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No enabled retention policy covers OneDrive or SharePoint, so meeting recordings can be deleted by their owner with nothing retained.' `
            -RequiredValue 'Enabled retention policies covering OneDrive and SharePoint' -Remediation $ctrl.Remediation
    }
}

# ── TMS-2.1 Skype User Contact Disabled ──────────────────────────────────────
function Test-NRGControlTeamsSkype {
    [CmdletBinding()] param()
    $cid = 'TMS-2.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    # Microsoft ended Skype consumer interoperability with Teams on May 5,
    # 2025 and AllowPublicUsers can no longer be used, so there is no longer
    # a path for a Skype user to reach the tenant and nothing to score.
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
        -Detail 'Retired by Microsoft: Skype consumer interoperability with Teams ended on May 5, 2025 and the AllowPublicUsers setting no longer has any effect. Personal-account access is assessed under TMS-1.2.'
}

# ── TMS-2.2 Unverified App Publisher Blocked ─────────────────────────────────
function Test-NRGControlTeamsUnverifiedApps {
    [CmdletBinding()] param()
    $cid = 'TMS-2.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    # Teams app availability is now managed per app in the Teams admin
    # center (app-centric management) and org-wide app settings; neither is
    # read by this tool. It used to look for a section no collector wrote.
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
        -Detail 'Requires manual verification: Teams app availability (Teams admin center > Teams apps > Manage apps and Org-wide app settings) is not read by this assessment. Confirm third-party apps are limited to reviewed, verified publishers.'
}

# ── TMS-2.3 Third-Party App Storage Disabled ─────────────────────────────────
function Test-NRGControlTeams3PStorage {
    [CmdletBinding()] param()
    $cid = 'TMS-2.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $tms = Get-NRGRawData -Key 'Teams'
    $cli = Get-NRGTeamsSection -Teams $tms -Name 'ClientConfiguration'
    if (-not $cli) { Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Teams client configuration was not collected; not assessed.'; return }
    $st = Get-NRGTeamsStorageProviderState -ClientConfiguration $cli
    if ($st.Unread.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "The Teams client configuration did not report $($st.Unread -join ', '); not assessed."
    } elseif ($st.Enabled.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Third-party cloud storage is disabled in Teams ($($st.Checked -join ', ') off).$($st.Note)"
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "Third-party cloud storage is enabled in Teams: $($st.Enabled -join ', '). Organizational files can be moved to unmanaged storage.$($st.Note)" -CurrentValue "Enabled: $($st.Enabled -join ', ')" -Remediation $ctrl.Remediation
    }
}

# ── TMS-2.4 Teams Email Integration Disabled ─────────────────────────────────
function Test-NRGControlTeamsEmailIntegration {
    [CmdletBinding()] param()
    $cid = 'TMS-2.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $cli = Get-NRGTeamsSection -Teams (Get-NRGRawData -Key 'Teams') -Name 'ClientConfiguration'
    $emailInt = Get-NRGObjectField -Item $cli -Key 'AllowEmailIntoChannel' -Default $null
    if ($null -eq $emailInt) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AllowEmailIntoChannel (Teams client configuration) was not collected; not assessed.'
    } elseif (-not [bool]$emailInt) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Email into Teams channels is disabled.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Email can be sent directly into Teams channels. A channel email address is a way to put a message, and any attachment, in front of the channel''s members.' -CurrentValue 'AllowEmailIntoChannel = True' -Remediation $ctrl.Remediation
    }
}

# ── TMS-2.5 Cloud Recording Disabled for External ────────────────────────────
function Test-NRGControlTeamsRecordingExternal {
    [CmdletBinding()] param()
    $cid = 'TMS-2.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    # Microsoft: external participants and guests cannot start a meeting
    # recording (third-party compliance recording aside). There is no tenant
    # setting that grants it, so there is nothing to score. The field read
    # before, AllowCloudRecordingForCalls, is the 1:1 CALL recording switch
    # in the calling policy and says nothing about external participants.
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
        -Detail 'Enforced by the platform: guests and external participants cannot start a Teams meeting recording, and no tenant setting allows it (third-party compliance recording by another organization is the only exception, and organizers are notified). Nothing to score.'
}

# ── TMS-2.6 Broad Channel Meeting Invite Disabled ────────────────────────────
function Test-NRGControlTeamsBroadChannel {
    [CmdletBinding()] param()
    $cid = 'TMS-2.6'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $meet = Get-NRGTeamsSection -Teams (Get-NRGRawData -Key 'Teams') -Name 'MeetingPolicy'
    $broad = Get-NRGObjectField -Item $meet -Key 'AllowChannelMeetingScheduling' -Default $null
    if ($null -eq $broad) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AllowChannelMeetingScheduling (global meeting policy) was not collected; not assessed.'
    } elseif (-not [bool]$broad) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Channel meeting scheduling is off in the global meeting policy.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Channel meeting scheduling is on — a channel meeting invites every channel member, including guests. Review channel membership before relying on it.' -CurrentValue 'AllowChannelMeetingScheduling = True' -Remediation $ctrl.Remediation
    }
}

# ── TMS-2.7 Chat with External Users Restricted ──────────────────────────────
function Test-NRGControlTeamsExternalChat {
    [CmdletBinding()] param()
    $cid = 'TMS-2.7'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $fed  = Get-NRGTeamsSection -Teams (Get-NRGRawData -Key 'Teams') -Name 'FederationConfig'
    $mode = Get-NRGTeamsFederationMode -Federation $fed
    if (-not $mode) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Federation configuration (AllowFederatedUsers) was not collected; not assessed.'
    } elseif ($mode -in @('Disabled','AllowList')) {
        $d = if ($mode -eq 'Disabled') { 'External (federated) chat is disabled.' } else { "External chat is limited to $(@($fed.AllowedDomains).Count) allowlisted domain(s)." }
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail $d
    } elseif ($mode -eq 'BlockList') {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'Users in any external organization except the blocked domains can start chats with internal users.' -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Users in any external organization can start chats with internal users — social engineering by direct Teams message bypasses email security controls.' -Remediation $ctrl.Remediation
    }
}

# ── TMS-2.8 PSTN Dial-Out Restricted ────────────────────────────────────────
function Test-NRGControlTeamsPSTN {
    [CmdletBinding()] param()
    $cid = 'TMS-2.8'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $meet = Get-NRGTeamsSection -Teams (Get-NRGRawData -Key 'Teams') -Name 'MeetingPolicy'
    $pstn = Get-NRGObjectField -Item $meet -Key 'AllowPSTNUsersToBypassLobby' -Default $null
    if ($null -eq $pstn) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AllowPSTNUsersToBypassLobby (global meeting policy) was not collected; not assessed.'
    } elseif (-not [bool]$pstn) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'PSTN dial-in users cannot bypass the lobby — they wait for admission like other external participants.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'PSTN dial-in users bypass the meeting lobby. Anyone who dials the meeting number joins directly without admission.' -CurrentValue 'AllowPSTNUsersToBypassLobby = True' -RequiredValue 'AllowPSTNUsersToBypassLobby = False' -Remediation $ctrl.Remediation
    }
}

# ── TMS-3.1 Teams Meeting Watermarks Enabled ─────────────────────────────────
# A Teams Premium feature; license gating moves the Gap out of the score on
# tenants without it.
function Test-NRGControlTeamsWatermarks {
    [CmdletBinding()] param()
    $cid = 'TMS-3.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $meet = Get-NRGTeamsSection -Teams (Get-NRGRawData -Key 'Teams') -Name 'MeetingPolicy'
    $wm = Get-NRGObjectField -Item $meet -Key 'AllowWatermarkForScreenSharing' -Default $null
    if ($null -eq $wm) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AllowWatermarkForScreenSharing (global meeting policy) was not collected; not assessed.'
    } elseif ([bool]$wm) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Organizers can watermark shared content in meetings, showing each viewer''s email address over it.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Watermarking of shared content is off in the global meeting policy. A leaked screenshot of a sensitive meeting cannot be traced to the participant who took it.' -CurrentValue 'AllowWatermarkForScreenSharing = False' -Remediation $ctrl.Remediation
    }
}

# ── TMS-3.2 Auto-Admit Only Organization Users ────────────────────────────────
# Who bypasses the lobby (Microsoft):
#   OrganizerOnly / EveryoneInCompanyExcludingGuests — only the organization
#   EveryoneInCompany  — the organization and its guests
#   InvitedUsers       — whoever the organizer invited, external included
#   EveryoneInSameAndFederatedCompany — the organization and every
#                        federated (trusted) organization
#   Everyone           — anyone, anonymous included
function Test-NRGControlTeamsAutoAdmit {
    [CmdletBinding()] param()
    $cid = 'TMS-3.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $meet = Get-NRGTeamsSection -Teams (Get-NRGRawData -Key 'Teams') -Name 'MeetingPolicy'
    $autoAdmit = [string](Get-NRGObjectField -Item $meet -Key 'AutoAdmittedUsers' -Default '')
    $req = 'OrganizerOnly or EveryoneInCompanyExcludingGuests'
    if (-not $autoAdmit) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AutoAdmittedUsers (global meeting policy) was not collected; not assessed.'
    } elseif ($autoAdmit -in @('OrganizerOnly','EveryoneInCompanyExcludingGuests')) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Auto-admit: $autoAdmit — everyone outside the organization, guests included, waits in the lobby."
    } elseif ($autoAdmit -in @('EveryoneInCompany','InvitedUsers')) {
        $who = if ($autoAdmit -eq 'EveryoneInCompany') { 'guest accounts' } else { 'any external person the organizer invited' }
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "Auto-admit is '$autoAdmit': besides the organization, $who bypass the lobby." -CurrentValue "AutoAdmittedUsers = $autoAdmit" -RequiredValue $req -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "Auto-admit is '$autoAdmit', so participants from outside the organization are admitted without waiting in the lobby." -CurrentValue "AutoAdmittedUsers = $autoAdmit" -RequiredValue $req -Remediation $ctrl.Remediation
    }
}

# ── TMS-3.3 Meeting Chat Managed for External Users ─────────────────────────
function Test-NRGControlTeamsMeetingChat {
    [CmdletBinding()] param()
    $cid = 'TMS-3.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $meet = Get-NRGTeamsSection -Teams (Get-NRGRawData -Key 'Teams') -Name 'MeetingPolicy'
    $chat = [string](Get-NRGObjectField -Item $meet -Key 'MeetingChatEnabledType' -Default '')
    if (-not $chat) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'MeetingChatEnabledType (global meeting policy) was not collected; not assessed.'
    } elseif ($chat -eq 'Disabled' -or $chat -match 'ExceptAnonymous') {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Anonymous participants cannot use meeting chat (MeetingChatEnabledType = $chat)."
    } elseif ($chat -eq 'Enabled') {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Meeting chat is open to every participant, anonymous ones included.' -CurrentValue 'MeetingChatEnabledType = Enabled' -RequiredValue 'EnabledExceptAnonymous or Disabled' -Remediation 'Set-CsTeamsMeetingPolicy -Identity Global -MeetingChatEnabledType EnabledExceptAnonymous'
    } else {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "MeetingChatEnabledType returned an unrecognized value ('$chat'); not assessed."
    }
}

# ── TMS-3.4 Prevent Copying Meeting Chat ─────────────────────────────────────
function Test-NRGControlTeamsChatCopy {
    [CmdletBinding()] param()
    $cid = 'TMS-3.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid

    # Teams chat content is governed by Purview DLP: is any enabled DLP
    # policy targeting the Teams workload? An unread DLP list is not "no
    # DLP policies" — it scored a Gap on every run without Purview.
    $pvw = Get-NRGRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success -or (Get-NRGNestedProperty -Object $pvw -Path 'Data.SectionStatus.DLPPolicies' -Default 'Collected') -ne 'Collected') {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'Purview DLP policies were not collected — Teams chat DLP coverage was not assessed.'
        return
    }

    $dlp = @(Get-NRGObjectField -Item $pvw.Data -Key 'DLPPolicies' -Default @() | Where-Object { $null -ne $_ })
    if ($dlp.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No DLP policies exist, so meeting and channel chat content is not inspected for sensitive information before it leaves the tenant.' `
            -CurrentValue 'Zero DLP policies' -RequiredValue 'An enabled DLP policy covering the Teams workload' `
            -Remediation $ctrl.Remediation
        return
    }

    $teamsPolicies  = @($dlp | Where-Object { @(Get-NRGObjectField -Item $_ -Key 'Workloads' -Default @()) -match 'Teams' })
    $enabledTeams   = @($teamsPolicies | Where-Object { (Get-NRGObjectField -Item $_ -Key 'Enabled' -Default $false) -eq $true })

    if ($enabledTeams.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($enabledTeams.Count) enabled DLP policy(ies) cover the Teams workload, so sensitive content in chat is inspected."
    } elseif ($teamsPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "$($teamsPolicies.Count) DLP policy(ies) target Teams but none are enabled — they are in test or disabled mode, so nothing is enforced." `
            -CurrentValue "$($teamsPolicies.Count) Teams DLP policies, 0 enabled" `
            -RequiredValue 'At least one enabled DLP policy covering Teams' -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($dlp.Count) DLP policy(ies) exist but none target the Teams workload, so chat content is outside DLP inspection even though mail and files are covered." `
            -CurrentValue "0 of $($dlp.Count) DLP policies cover Teams" `
            -RequiredValue 'An enabled DLP policy covering the Teams workload' -Remediation $ctrl.Remediation
    }
}

# ── TMS-4.1 Meeting Recording Storage and Permissions Scoped ─────────────────
function Test-NRGControlTeamsMeetingRecordingScope {
    [CmdletBinding()] param()
    $cid = 'TMS-4.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $meet = Get-NRGTeamsSection -Teams (Get-NRGRawData -Key 'Teams') -Name 'MeetingPolicy'
    # NewMeetingRecordingExpirationDays: 1-99999 = auto-expiry; -1 = never.
    $expiry = Get-NRGObjectField -Item $meet -Key 'NewMeetingRecordingExpirationDays' -Default $null
    if ($null -eq $expiry) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'NewMeetingRecordingExpirationDays (global meeting policy) was not collected; not assessed.'
    } elseif ([int]$expiry -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Meeting recordings auto-expire after $expiry days — recordings are not retained indefinitely."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Meeting recordings never auto-expire (retention set to unlimited). Recorded meeting content accumulates in OneDrive/SharePoint indefinitely, expanding the data-at-rest exposure.' -CurrentValue 'NewMeetingRecordingExpirationDays = -1 (never expires)' -RequiredValue 'A finite expiration (e.g. 60-120 days)' -Remediation $ctrl.Remediation
    }
}

# ── TMS-4.2 Anonymous Users Cannot Start Meetings ────────────────────────────
function Test-NRGControlTeamsAnonymousStart {
    [CmdletBinding()] param()
    $cid = 'TMS-4.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $meet = Get-NRGTeamsSection -Teams (Get-NRGRawData -Key 'Teams') -Name 'MeetingPolicy'
    $anonStart = Get-NRGObjectField -Item $meet -Key 'AllowAnonymousUsersToStartMeeting' -Default $null
    if ($null -eq $anonStart) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AllowAnonymousUsersToStartMeeting (global meeting policy) was not collected; not assessed.'
    } elseif (-not [bool]$anonStart) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Anonymous users cannot start Teams meetings independently.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Anonymous users can start meetings. Unidentified external users can initiate calls into your organization.' -CurrentValue 'AllowAnonymousUsersToStartMeeting = $true' -RequiredValue '$false' -Remediation $ctrl.Remediation
    }
}

# ── TMS-4.3 Federated External Domain Allowlist ───────────────────────────────
function Test-NRGControlTeamsFederationAllowlist {
    [CmdletBinding()] param()
    $cid = 'TMS-4.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $fed  = Get-NRGTeamsSection -Teams (Get-NRGRawData -Key 'Teams') -Name 'FederationConfig'
    $mode = Get-NRGTeamsFederationMode -Federation $fed
    if (-not $mode) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Federation configuration (AllowFederatedUsers) was not collected; not assessed.'
    } elseif ($mode -eq 'AllowList') {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Federation is limited to $(@($fed.AllowedDomains).Count) allowlisted domain(s)."
    } elseif ($mode -eq 'Disabled') {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Teams federation with external domains is disabled.'
    } elseif ($mode -eq 'BlockList') {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "Federation uses a blocklist ($(@($fed.BlockedDomains).Count) domain(s)): every other external domain is allowed." -CurrentValue 'Blocklist mode' -RequiredValue 'Allowlist specific trusted domains only' -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Teams federation is open to all external domains. Any Teams user at any organization can contact your users.' -CurrentValue 'Open federation — all domains allowed' -RequiredValue 'Allowlist specific trusted domains only' -Remediation $ctrl.Remediation
    }
}

# ── TMS-4.4 Public events (town halls, webinars, legacy live events) ─────────
# Microsoft retired Teams live events on June 30, 2026 (events scheduled
# before then run until February 28, 2027); town halls and webinars replace
# them, and both attendee settings default to Everyone — public and anonymous.
function Test-NRGControlTeamsLiveEvents {
    [CmdletBinding()] param()
    $cid = 'TMS-4.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $tms = Get-NRGRawData -Key 'Teams'
    $ev  = Get-NRGTeamsSection -Teams $tms -Name 'EventsPolicy'
    if (-not $ev) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The Teams events policy (Get-CsTeamsEventsPolicy) was not collected; not assessed.'
        return
    }
    $open = @(); $closed = @()
    $web = [string](Get-NRGObjectField -Item $ev -Key 'AllowWebinars' -Default '')
    $webAccess = [string](Get-NRGObjectField -Item $ev -Key 'EventAccessType' -Default '')
    if ($web -eq 'Disabled') { $closed += 'webinars (off)' } elseif ($webAccess -eq 'Everyone') { $open += 'webinars (EventAccessType = Everyone)' } elseif ($webAccess) { $closed += "webinars ($webAccess)" }
    $th = [string](Get-NRGObjectField -Item $ev -Key 'AllowTownhalls' -Default '')
    $thAccess = [string](Get-NRGObjectField -Item $ev -Key 'TownhallEventAttendeeAccess' -Default '')
    if ($th -eq 'Disabled') { $closed += 'town halls (off)' } elseif ($thAccess -eq 'Everyone') { $open += 'town halls (TownhallEventAttendeeAccess = Everyone)' } elseif ($thAccess) { $closed += "town halls ($thAccess)" }
    $bc = Get-NRGTeamsSection -Teams $tms -Name 'BroadcastPolicy'
    if ($bc -and (Get-NRGObjectField -Item $bc -Key 'AllowBroadcastScheduling' -Default $false) -eq $true -and [string](Get-NRGObjectField -Item $bc -Key 'BroadcastAttendeeVisibilityMode' -Default '') -eq 'Everyone') {
        $open += 'legacy live events already scheduled (BroadcastAttendeeVisibilityMode = Everyone)'
    }
    if (($open.Count + $closed.Count) -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The events policy returned neither webinar nor town hall attendee settings; not assessed.'
    } elseif ($open.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "No Teams event type can be attended by anonymous internet users: $($closed -join '; ')."
    } elseif ($closed.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "Anonymous internet users can attend $($open -join '; '); restricted: $($closed -join '; ')." -CurrentValue ($open -join '; ') -RequiredValue 'Every event type restricted to the organization (and guests), or turned off' -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "Anonymous internet users can attend $($open -join '; '). Organizers can publish company content to a fully public, unauthenticated audience." -CurrentValue ($open -join '; ') -RequiredValue 'Every event type restricted to the organization (and guests), or turned off' -Remediation $ctrl.Remediation
    }
}
