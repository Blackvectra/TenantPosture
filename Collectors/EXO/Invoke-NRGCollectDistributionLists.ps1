#Requires -Version 7.0
#
# Invoke-NRGCollectDistributionLists.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Read every distribution list in the tenant, with the settings that decide
#          who can email it and who is on it, so the distribution-list scan can say
#          which lists are exposed. READ-ONLY: Get-* cmdlets only, in the Exchange
#          Online session; it never creates, adds, removes or changes a list, a
#          member or a setting.
#
# Sets:     EXO-DistributionLists
# Consumes: nothing (reads Exchange Online directly)
# Cmdlets:  Get-AcceptedDomain, Get-DistributionGroup, Get-DynamicDistributionGroup,
#           Get-DistributionGroupMember, Get-DynamicDistributionGroupMember, all
#           resolved through Get-NRGExoCommand so they run in the Exchange Online
#           session and not in a Security & Compliance session loaded beside it.
#
# Data populated (Data.*):
#   Lists          one record per list: identity, type, owners (ManagedBy), sender
#                  settings, moderation, join/depart restriction, address-book
#                  visibility, member read status, member count, members (display
#                  name and UPN only), outside members, nested groups
#   AcceptedDomains / TenantInitialDomain   what "outside the organization" means
#   Limits         the member cap and list cap this run used, stated in the output
#   Scope          what the scan covers and what it does not
#   Stats          counts, including throttled reads
#   SectionStatus  per section: NotRun / Collected / Failed
#
# SectionStatus (the contract every multi-query collector keeps):
#   AcceptedDomains     Collected only when at least one domain came back; without
#                       it no member can be called inside or outside
#   DistributionGroups  Get-DistributionGroup (lists and mail-enabled security groups)
#   DynamicGroups       Get-DynamicDistributionGroup
#   Members             Collected only when EVERY in-scope list's members were read
#                       to the cap or beyond; Failed otherwise, and each list says
#                       why in its own MembersStatus (Read / Truncated / Failed / NotRead)
# An empty Lists is therefore ambiguous only when a section is not Collected, and
# the evaluator consults the status before it concludes anything from an empty list.
#
# Limits that are stated, not hidden:
#   * Get-DistributionGroup and the member cmdlets return 1000 rows unless told
#     otherwise; the list read asks for Unlimited, and a member read asks for the cap
#     plus one so a list larger than the cap is reported as truncated, not as complete.
#   * Throttled reads are retried with a growing delay; after several lists in a row
#     are still throttled the member reads stop and the rest are marked NotRead.
#   * Member reads are direct members only. Nested groups are recorded, not expanded.
#   * A dynamic list's members are the calculated list Exchange stores (refreshed about
#     every 24 hours), a snapshot and not the live filter result.

# Exchange reports throttling as free text. Anything else (permission, not found) is
# not retried: retrying a refusal only delays the same answer.
$script:NRGDLThrottlePattern = '(?i)throttl|\b429\b|too many requests|server is busy|ServerBusy|try again later|temporarily unavailable'

function Wait-NRGDLBackoff {
    [CmdletBinding()]
    param([int] $Attempt = 1)
    $seconds = [Math]::Min(30, [Math]::Pow(2, $Attempt)) + ((Get-Random -Minimum 0 -Maximum 1000) / 1000.0)
    Start-Sleep -Seconds $seconds
}

# One read with bounded retry on throttling. Returns what happened instead of
# throwing, so the caller can mark one list failed and carry on with the rest.
function Invoke-NRGDLRead {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [scriptblock] $Read,
        [int] $MaxRetries = 3
    )
    $attempt = 0
    while ($true) {
        $attempt++
        try {
            $rows = @(& $Read)
            return [pscustomobject]@{ Ok = $true; Value = $rows; Error = ''; Throttled = ($attempt -gt 1); Attempts = $attempt }
        } catch {
            $msg = (($_.Exception.Message) -split "`r?`n")[0]
            $isThrottle = [bool]($msg -match $script:NRGDLThrottlePattern)
            if ($isThrottle -and $attempt -le $MaxRetries) {
                Wait-NRGDLBackoff -Attempt $attempt
                continue
            }
            return [pscustomobject]@{ Ok = $false; Value = @(); Error = $msg; Throttled = $isThrottle; Attempts = $attempt }
        }
    }
}

# Only the optional parameters this Exchange module actually has. The "with display
# names" switches turn the GUIDs Exchange returns for owners, allowed senders and
# moderators into names a reader can use; a module without them still reads the list.
function Get-NRGDLReadParameters {
    [CmdletBinding()]
    param([AllowNull()] $Command)
    $params = @{ ResultSize = 'Unlimited'; ErrorAction = 'Stop' }
    $supported = Get-NRGObjectField -Item $Command -Key 'Parameters' -Default $null
    if ($null -ne $supported -and $supported -is [System.Collections.IDictionary]) {
        foreach ($name in @(
                'IncludeManagedByWithDisplayNames',
                'IncludeAcceptMessagesOnlyFromWithDisplayNames',
                'IncludeAcceptMessagesOnlyFromDLMembersWithDisplayNames',
                'IncludeAcceptMessagesOnlyFromSendersOrMembersWithDisplayNames',
                'IncludeModeratedByWithDisplayNames')) {
            if ($supported.ContainsKey($name)) { $params[$name] = $true }
        }
    }
    return $params
}

# A list-valued property: $null when Exchange did not return it, an array (possibly
# empty) when it did. An empty owner list and an unread one are different facts.
function Get-NRGDLStoredList {
    [CmdletBinding()]
    param([AllowNull()] $Item, [Parameter(Mandatory)] [string] $Key)
    $v = Get-NRGRuleList -Item $Item -Key $Key
    if ($null -eq $v) { return $null }
    return , @(@($v) | ForEach-Object { ConvertTo-NRGDLText -Value $_ -MaxLength 320 } | Where-Object { $_ })
}

function Invoke-NRGCollectDistributionLists {
    [CmdletBinding()]
    param(
        # Members read per list. A list larger than this is reported as truncated.
        [ValidateRange(1, 100000)] [int] $MemberLimit = 2000,

        # Lists whose members are read. Settings are read for every list regardless.
        [ValidateRange(1, 100000)] [int] $MemberReadListLimit = 1000,

        # Retries per read when Exchange throttles.
        [ValidateRange(0, 10)] [int] $MaxRetries = 3,

        # Consecutive throttled lists after which member reads stop.
        [ValidateRange(1, 20)] [int] $ThrottleStopAfter = 3
    )

    $result = @{
        CollectorId = 'EXO-DistributionLists'
        CollectedAt = (Get-Date).ToString('o')
        Success     = $false
        Data        = @{
            Lists               = @()
            AcceptedDomains     = @()
            TenantInitialDomain = ''
            CommandSource       = ''
            Limits              = @{
                MemberLimit          = $MemberLimit
                MemberReadListLimit  = $MemberReadListLimit
                MaxRetries           = $MaxRetries
                ThrottleStopAfter    = $ThrottleStopAfter
            }
            Scope               = @{
                Covers    = @('Distribution lists', 'Mail-enabled security groups', 'Dynamic distribution lists')
                NotCovered = @(
                    'Microsoft 365 Groups, including Teams-connected groups (a different object with its own sender settings)',
                    'Members of nested groups (only direct members are read)',
                    'Every other area of the tenant: this scan reads distribution lists only'
                )
            }
            Stats               = @{
                DistributionGroups        = 0
                MailEnabledSecurityGroups = 0
                DynamicGroups             = 0
                ListsTotal                = 0
                MemberReadsAttempted      = 0
                MemberReadsRead           = 0
                MemberReadsTruncated      = 0
                MemberReadsFailed         = 0
                MemberReadsNotRead        = 0
                ThrottledReads            = 0
                ThrottleStopped           = $false
            }
            Errors              = @()
            SectionStatus       = @{
                AcceptedDomains    = 'NotRun'
                DistributionGroups = 'NotRun'
                DynamicGroups      = 'NotRun'
                Members            = 'NotRun'
            }
        }
    }

    $errors = [System.Collections.Generic.List[string]]::new()
    $note = {
        param([string] $Source, [string] $Message)
        $clean = ConvertTo-NRGDLText -Value $Message -MaxLength 300
        $errors.Add("${Source}: $clean")
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source $Source -Message $(if ($clean) { $clean } else { 'unknown error' })
        }
    }

    # Pin every cmdlet to the Exchange Online session. A Source other than
    # ExchangeOnline means the session could not be told apart from another one,
    # and a value read from the wrong tenant is worse than no value.
    $resolve = {
        param([string] $Name)
        $r = Get-NRGExoCommand -Name $Name -Session ExchangeOnline
        [pscustomobject]@{
            Command = Get-NRGObjectField -Item $r -Key 'Command' -Default $null
            Source  = [string](Get-NRGObjectField -Item $r -Key 'Source' -Default 'Unknown')
        }
    }
    $usable = {
        param($Resolved, [string] $Name)
        if ($null -eq $Resolved.Command) {
            return "$Name is not available in the Exchange Online session (the signed-in account may lack the role that grants it)"
        }
        if ($Resolved.Source -ne 'ExchangeOnline') {
            return "$Name could not be pinned to the Exchange Online session (source: $($Resolved.Source))"
        }
        return ''
    }

    try {
        # ── Accepted domains: what "outside the organization" means ───────────────
        $domains = [System.Collections.Generic.List[string]]::new()
        $initial = ''
        $adCmd = & $resolve 'Get-AcceptedDomain'
        $adWhy = & $usable $adCmd 'Get-AcceptedDomain'
        if ($adWhy) {
            $result.Data.SectionStatus.AcceptedDomains = 'Failed'
            & $note 'DL-AcceptedDomains' $adWhy
        } else {
            $read = Invoke-NRGDLRead -MaxRetries $MaxRetries -Read ({ & $adCmd.Command -ErrorAction Stop }.GetNewClosure())
            if ($read.Ok) {
                foreach ($row in @($read.Value)) {
                    $d = ([string](Get-NRGObjectField -Item $row -Key 'DomainName' -Default '')).Trim().ToLowerInvariant()
                    if ($d -and -not $domains.Contains($d)) { $domains.Add($d) }
                    if (-not $initial -and (ConvertTo-NRGDLBoolean (Get-NRGObjectField -Item $row -Key 'InitialDomain' -Default $null)) -eq $true) { $initial = $d }
                }
                if ($domains.Count -gt 0) {
                    $result.Data.SectionStatus.AcceptedDomains = 'Collected'
                } else {
                    $result.Data.SectionStatus.AcceptedDomains = 'Failed'
                    & $note 'DL-AcceptedDomains' 'Get-AcceptedDomain returned no domains, so no member can be classified as inside or outside the organization'
                }
            } else {
                $result.Data.SectionStatus.AcceptedDomains = 'Failed'
                & $note 'DL-AcceptedDomains' $read.Error
            }
        }
        $result.Data.AcceptedDomains = @($domains)
        $result.Data.TenantInitialDomain = $initial

        # ── The lists themselves ──────────────────────────────────────────────────
        $records = [System.Collections.Generic.List[object]]::new()
        $newRecord = {
            param($Row, [bool] $IsDynamic)
            $details = [string](Get-NRGObjectField -Item $Row -Key 'RecipientTypeDetails' -Default $(if ($IsDynamic) { 'DynamicDistributionGroup' } else { '' }))
            $guid = [string](Get-NRGObjectField -Item $Row -Key 'Guid' -Default '')
            if (-not $guid) { $guid = [string](Get-NRGObjectField -Item $Row -Key 'ExternalDirectoryObjectId' -Default '') }
            $join   = Get-NRGObjectField -Item $Row -Key 'MemberJoinRestriction' -Default $null
            $depart = Get-NRGObjectField -Item $Row -Key 'MemberDepartRestriction' -Default $null
            $rec = [ordered]@{
                Name                 = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $Row -Key 'Name' -Default '')
                DisplayName          = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $Row -Key 'DisplayName' -Default (Get-NRGObjectField -Item $Row -Key 'Name' -Default ''))
                PrimarySmtpAddress   = ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $Row -Key 'PrimarySmtpAddress' -Default '') -MaxLength 320
                Guid                 = ConvertTo-NRGDLText -Value $guid -MaxLength 64
                RecipientTypeDetails = ConvertTo-NRGDLText -Value $details -MaxLength 60
                Kind                 = Get-NRGDistributionListKind -RecipientTypeDetails $details
                IsDynamic            = $IsDynamic
                ManagedBy                                   = Get-NRGDLStoredList -Item $Row -Key 'ManagedBy'
                ManagedByWithDisplayNames                   = Get-NRGDLStoredList -Item $Row -Key 'ManagedByWithDisplayNames'
                RequireSenderAuthenticationEnabled          = ConvertTo-NRGDLBoolean (Get-NRGObjectField -Item $Row -Key 'RequireSenderAuthenticationEnabled' -Default $null)
                AcceptMessagesOnlyFrom                      = Get-NRGDLStoredList -Item $Row -Key 'AcceptMessagesOnlyFrom'
                AcceptMessagesOnlyFromWithDisplayNames      = Get-NRGDLStoredList -Item $Row -Key 'AcceptMessagesOnlyFromWithDisplayNames'
                AcceptMessagesOnlyFromDLMembers             = Get-NRGDLStoredList -Item $Row -Key 'AcceptMessagesOnlyFromDLMembers'
                AcceptMessagesOnlyFromDLMembersWithDisplayNames = Get-NRGDLStoredList -Item $Row -Key 'AcceptMessagesOnlyFromDLMembersWithDisplayNames'
                AcceptMessagesOnlyFromSendersOrMembers      = Get-NRGDLStoredList -Item $Row -Key 'AcceptMessagesOnlyFromSendersOrMembers'
                AcceptMessagesOnlyFromSendersOrMembersWithDisplayNames = Get-NRGDLStoredList -Item $Row -Key 'AcceptMessagesOnlyFromSendersOrMembersWithDisplayNames'
                ModerationEnabled                           = ConvertTo-NRGDLBoolean (Get-NRGObjectField -Item $Row -Key 'ModerationEnabled' -Default $null)
                ModeratedBy                                 = Get-NRGDLStoredList -Item $Row -Key 'ModeratedBy'
                ModeratedByWithDisplayNames                 = Get-NRGDLStoredList -Item $Row -Key 'ModeratedByWithDisplayNames'
                MemberJoinRestriction                       = $(if ($null -ne $join)   { ConvertTo-NRGDLText -Value $join   -MaxLength 40 } else { $null })
                MemberDepartRestriction                     = $(if ($null -ne $depart) { ConvertTo-NRGDLText -Value $depart -MaxLength 40 } else { $null })
                HiddenFromAddressListsEnabled               = ConvertTo-NRGDLBoolean (Get-NRGObjectField -Item $Row -Key 'HiddenFromAddressListsEnabled' -Default $null)
                RecipientFilter      = $(if ($IsDynamic) { ConvertTo-NRGDLText -Value (Get-NRGObjectField -Item $Row -Key 'RecipientFilter' -Default '') -MaxLength 1000 } else { '' })
                MembersStatus        = 'NotRead'
                MembersNote          = ''
                MemberCount          = $null
                Members              = @()
                ExternalMembers      = @()
                UnresolvedMemberCount = 0
                NestedGroups         = @()
            }
            return $rec
        }

        $dgCmd = & $resolve 'Get-DistributionGroup'
        $dgWhy = & $usable $dgCmd 'Get-DistributionGroup'
        if ($dgWhy) {
            $result.Data.SectionStatus.DistributionGroups = 'Failed'
            & $note 'DL-DistributionGroups' $dgWhy
        } else {
            $dgParams = Get-NRGDLReadParameters -Command $dgCmd.Command
            $read = Invoke-NRGDLRead -MaxRetries $MaxRetries -Read ({ & $dgCmd.Command @dgParams }.GetNewClosure())
            if ($read.Ok) {
                foreach ($row in @($read.Value)) {
                    $rec = & $newRecord $row $false
                    $records.Add($rec)
                    if ($rec['RecipientTypeDetails'] -eq 'MailUniversalSecurityGroup') { $result.Data.Stats.MailEnabledSecurityGroups++ } else { $result.Data.Stats.DistributionGroups++ }
                }
                $result.Data.SectionStatus.DistributionGroups = 'Collected'
            } else {
                $result.Data.SectionStatus.DistributionGroups = 'Failed'
                & $note 'DL-DistributionGroups' $read.Error
            }
        }

        $ddCmd = & $resolve 'Get-DynamicDistributionGroup'
        $ddWhy = & $usable $ddCmd 'Get-DynamicDistributionGroup'
        if ($ddWhy) {
            $result.Data.SectionStatus.DynamicGroups = 'Failed'
            & $note 'DL-DynamicGroups' $ddWhy
        } else {
            $ddParams = Get-NRGDLReadParameters -Command $ddCmd.Command
            $read = Invoke-NRGDLRead -MaxRetries $MaxRetries -Read ({ & $ddCmd.Command @ddParams }.GetNewClosure())
            if ($read.Ok) {
                foreach ($row in @($read.Value)) {
                    $records.Add((& $newRecord $row $true))
                    $result.Data.Stats.DynamicGroups++
                }
                $result.Data.SectionStatus.DynamicGroups = 'Collected'
            } else {
                $result.Data.SectionStatus.DynamicGroups = 'Failed'
                & $note 'DL-DynamicGroups' $read.Error
            }
        }

        $ordered = @($records | Sort-Object { $_['DisplayName'] }, { $_['PrimarySmtpAddress'] })
        $result.Data.Stats.ListsTotal = $ordered.Count

        # ── Members, one list at a time ───────────────────────────────────────────
        $listsCollected = ($result.Data.SectionStatus.DistributionGroups -eq 'Collected') -or ($result.Data.SectionStatus.DynamicGroups -eq 'Collected')
        $memberCmd = & $resolve 'Get-DistributionGroupMember'
        $memberWhy = & $usable $memberCmd 'Get-DistributionGroupMember'
        $dynMemberCmd = & $resolve 'Get-DynamicDistributionGroupMember'
        $dynMemberWhy = & $usable $dynMemberCmd 'Get-DynamicDistributionGroupMember'

        $consecutiveThrottled = 0
        $stopped = $false
        $position = 0
        foreach ($rec in $ordered) {
            $position++
            $isDynamic = [bool]$rec['IsDynamic']
            $cmdInfo = if ($isDynamic) { $dynMemberCmd } else { $memberCmd }
            $cmdWhy  = if ($isDynamic) { $dynMemberWhy } else { $memberWhy }

            if ($position -gt $MemberReadListLimit) {
                $rec['MembersStatus'] = 'NotRead'
                $rec['MembersNote'] = "Members not read: this run reads members for the first $MemberReadListLimit lists only (-MemberReadListLimit)."
                $result.Data.Stats.MemberReadsNotRead++
                continue
            }
            if ($stopped) {
                $rec['MembersStatus'] = 'NotRead'
                $rec['MembersNote'] = "Members not read: Exchange kept throttling, so member reads stopped after $ThrottleStopAfter lists in a row. Run again later."
                $result.Data.Stats.MemberReadsNotRead++
                continue
            }
            if ($cmdWhy) {
                $rec['MembersStatus'] = 'Failed'
                $rec['MembersNote'] = "Members not read: $cmdWhy."
                $result.Data.Stats.MemberReadsFailed++
                continue
            }
            # Never call a member read with a blank identity: Exchange documents that a
            # null or unknown Identity returns every object, as if none was given.
            $identity = [string]$rec['Guid']
            if (-not $identity) { $identity = [string]$rec['PrimarySmtpAddress'] }
            if (-not $identity) {
                $rec['MembersStatus'] = 'NotRead'
                $rec['MembersNote'] = 'Members not read: Exchange returned no identifier for this list.'
                $result.Data.Stats.MemberReadsNotRead++
                continue
            }

            Write-Progress -Activity 'Reading distribution list members' -Status ("{0} of {1}" -f $position, $ordered.Count) -PercentComplete ([int](100 * $position / [Math]::Max(1, $ordered.Count)))
            $result.Data.Stats.MemberReadsAttempted++
            $cmd = $cmdInfo.Command
            $take = $MemberLimit + 1
            $read = Invoke-NRGDLRead -MaxRetries $MaxRetries -Read ({ & $cmd -Identity $identity -ResultSize $take -ErrorAction Stop }.GetNewClosure())
            if ($read.Throttled) { $result.Data.Stats.ThrottledReads++ }

            if (-not $read.Ok) {
                $rec['MembersStatus'] = 'Failed'
                $rec['MembersNote'] = 'Members not read: ' + (ConvertTo-NRGDLText -Value $read.Error -MaxLength 200)
                $result.Data.Stats.MemberReadsFailed++
                & $note 'DL-Members' ("{0}: {1}" -f $rec['PrimarySmtpAddress'], $read.Error)
                if ($read.Throttled) {
                    $consecutiveThrottled++
                    if ($consecutiveThrottled -ge $ThrottleStopAfter) { $stopped = $true; $result.Data.Stats.ThrottleStopped = $true }
                } else {
                    $consecutiveThrottled = 0
                }
                continue
            }
            $consecutiveThrottled = 0

            $rows = @($read.Value)
            $truncated = ($rows.Count -gt $MemberLimit)
            if ($truncated) { $rows = @($rows | Select-Object -First $MemberLimit) }

            $members = [System.Collections.Generic.List[object]]::new()
            $external = [System.Collections.Generic.List[object]]::new()
            $nested = [System.Collections.Generic.List[object]]::new()
            $unresolved = 0
            foreach ($m in $rows) {
                $c = Get-NRGDistributionListMemberClass -Member $m -AcceptedDomains @($domains)
                if ($c.IsGroup) {
                    $nested.Add([ordered]@{ DisplayName = $c.DisplayName; PrimarySmtpAddress = $c.PrimarySmtpAddress })
                    continue
                }
                # Display name and one identifier, nothing else: no phone, office, manager or
                # directory attribute reaches the results file.
                $person = [ordered]@{ DisplayName = $c.DisplayName; UserPrincipalName = $c.UserPrincipalName }
                $members.Add($person)
                if ($c.Class -eq 'External') { $external.Add($person) }
                elseif ($c.Class -ne 'Internal') { $unresolved++ }
            }

            $rec['Members'] = @($members)
            $rec['ExternalMembers'] = @($external)
            $rec['NestedGroups'] = @($nested)
            $rec['UnresolvedMemberCount'] = $unresolved
            $rec['MemberCount'] = $members.Count
            if ($truncated) {
                $rec['MembersStatus'] = 'Truncated'
                $rec['MembersNote'] = "The first $MemberLimit members were read and the list has more; the count, the outside members and the member list cover only those $MemberLimit (-MemberLimit)."
                $result.Data.Stats.MemberReadsTruncated++
            } else {
                $rec['MembersStatus'] = 'Read'
                $rec['MembersNote'] = $(if ($isDynamic) { 'Calculated membership that Exchange stores for this list and refreshes about every 24 hours: a snapshot, not a live evaluation of the recipient filter.' } else { '' })
                $result.Data.Stats.MemberReadsRead++
            }
        }
        Write-Progress -Activity 'Reading distribution list members' -Completed

        $incomplete = $result.Data.Stats.MemberReadsFailed + $result.Data.Stats.MemberReadsNotRead
        if (-not $listsCollected) {
            $result.Data.SectionStatus.Members = 'NotRun'
        } elseif ($incomplete -gt 0) {
            $result.Data.SectionStatus.Members = 'Failed'
        } else {
            $result.Data.SectionStatus.Members = 'Collected'
        }

        $result.Data.Lists = @($ordered)
        $result.Data.CommandSource = 'ExchangeOnline'
        # Success means the inventory is usable at all: at least one list query came
        # back. A run in which neither did has nothing to evaluate.
        $result.Success = $listsCollected
    } catch {
        & $note 'DL-Collector' $_.Exception.Message
    }

    $result.Data.Errors = @($errors)
    Set-NRGRawData -Key 'EXO-DistributionLists' -Data $result

    $sections = $result.Data.SectionStatus
    $notCollected = @($sections.Keys | Where-Object { $sections[$_] -ne 'Collected' } | Sort-Object)
    $covStatus = if (-not $result.Success) { 'Failed' } elseif ($notCollected.Count -gt 0) { 'Partial' } else { 'Collected' }
    $covNote = if ($notCollected.Count -gt 0) { 'Not collected: ' + ($notCollected -join ', ') + '. See Data.Errors and each list''s MembersStatus.' } else { "$($result.Data.Stats.ListsTotal) list(s) read." }
    Register-NRGCoverage -Family 'EXO-DistributionLists' -Status $covStatus -Note $covNote

    return $result
}
