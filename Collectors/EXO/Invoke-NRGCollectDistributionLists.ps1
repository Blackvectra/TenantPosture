#Requires -Version 7.0
#
# Invoke-NRGCollectDistributionLists.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Inventory every distribution list (classic, mail-enabled security and
#          dynamic) with its members, delivery and join settings, owners, and the
#          tenant-level filtering bypasses that decide who can reach it.
#
# READ-ONLY WITHOUT EXCEPTION. Every Exchange call is a Get-* cmdlet. This
# collector LISTS members; it never creates, adds, removes or changes a user,
# group, rule or setting. NRG.DistributionLists.Tests.ps1 parses this file and
# fails on any command that is not a Get-* cmdlet or a reviewed local helper.
#
# Sets:     EXO-DistributionLists
# Consumes: EXO-MailboxConfig (accepted domains, anti-spam policies and rules),
#           EXO-ConnectionFilter (IP Allow List) -- reused when a full assessment
#           already collected them, read here when not (the -DistributionListsOnly
#           run collects nothing else).
# Cmdlets:  Get-DistributionGroup, Get-DistributionGroupMember,
#           Get-DynamicDistributionGroup, Get-DynamicDistributionGroupMember,
#           Get-Recipient (dynamic-list preview fallback), Get-AcceptedDomain,
#           Get-TransportRule, Get-HostedConnectionFilterPolicy,
#           Get-HostedContentFilterPolicy, Get-HostedContentFilterRule.
#
# Data shape (Data.*):
#   Lists[]            one row per list: Name, DisplayName, PrimarySmtpAddress, Kind,
#                      RecipientTypeDetails, Owners, OwnerCount, OwnersKnown,
#                      RequireSenderAuthenticationEnabled, AllowedSenders,
#                      AllowedSendersKnown, ModerationEnabled, ModeratedBy, ModeratedByKnown,
#                      MemberJoinRestriction, MemberDepartRestriction,
#                      HiddenFromAddressListsEnabled, MembershipBasis, MemberStatus,
#                      MemberError, MemberCount, MemberCountIsLowerBound,
#                      MembersTruncated, Members[] (DisplayName, UPN, RecipientType,
#                      Class), ExternalMemberCount, UnresolvedMemberCount,
#                      NestedGroupCount, NestedGroups
#   AcceptedDomains[]  lower-case domain names
#   BypassInputs       TransportRules[] (SCL-setting rules and their conditions),
#                      ConnectionFilter[], AntiSpamPolicies[], AntiSpamRulesRead,
#                      Source (where each came from)
#   Stats, Limits, Scope
#   SectionStatus      Lists, DynamicLists, Members, AcceptedDomains, TransportRules,
#                      ConnectionFilter, AntiSpam: NotRun / Collected / Failed
#
# EMPTY IS NOT CLEAN. Every section defaults to an empty list, and each query has
# its own try/catch so one failure does not abort the rest. An empty list is
# therefore ambiguous (queried and found nothing, or the query failed), so every
# section publishes SectionStatus and every evaluator consults it. A list whose
# member read failed carries MemberStatus 'Failed', never an empty Members that
# reads as "nobody is in it".

# Whether an error message describes Exchange throttling. Only throttling is
# retried: any other failure is real and is recorded, not repeated.
function Test-NRGDlThrottleMessage {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] [string] $Message)
    if ([string]::IsNullOrWhiteSpace($Message)) { return $false }
    return [bool]($Message -match '(?i)throttl|too many requests|\b429\b|rate.?limit|server is busy|temporarily unavailable|exceeded .{0,40}(quota|limit)')
}

# Whether an object carries a property or key at all. Exchange and the EXO module
# OMIT optional properties rather than nulling them, so "absent" and "empty" are
# different answers and only the caller knows which one matters.
function Test-NRGDlHasField {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] $Item, [Parameter(Mandatory)] [string] $Key)
    if ($null -eq $Item) { return $false }
    if ($Item -is [System.Collections.IDictionary]) { return [bool]$Item.Contains($Key) }
    return ($null -ne $Item.PSObject.Properties[$Key])
}

# A boolean read from API data. [bool]"False" is $true, so a string is parsed, and
# anything that is not clearly True or False is $null (not read), never a default.
function ConvertTo-NRGDlBool {
    [CmdletBinding()]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    $s = ([string]$Value).Trim()
    if ($s -ieq 'True') { return $true }
    if ($s -ieq 'False') { return $false }
    return $null
}

# Strings out of a multi-valued property, dropping empties and keeping order.
function ConvertTo-NRGDlStringList {
    [CmdletBinding()]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return @() }
    return @(@($Value) | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { ([string]$_).Trim() })
}

# One read-only Exchange query, retried only when Exchange throttles it. It takes the
# resolved command and its parameters rather than a scriptblock, so no closure is
# involved and the call is easy to audit: the only thing it ever invokes is the Get-*
# command the caller resolved through Get-NRGExoCommand. A persistent failure is
# rethrown for the caller to record against the section or list it belongs to.
function Invoke-NRGDlRead {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Command,
        [hashtable] $Parameters = @{},
        [ValidateRange(0, 10)] [int] $Retries = 3,
        [ValidateRange(0, 300)] [int] $BaseDelaySeconds = 2,
        [hashtable] $Stats
    )
    $attempt = 0
    while ($true) {
        try {
            return @(& $Command @Parameters -ErrorAction Stop)
        } catch {
            if ($attempt -ge $Retries -or -not (Test-NRGDlThrottleMessage -Message $_.Exception.Message)) { throw }
            $attempt++
            if ($Stats) { $Stats['ThrottleRetries'] = [int]$Stats['ThrottleRetries'] + 1 }
            $delay = $BaseDelaySeconds * [math]::Pow(2, $attempt - 1)
            if ($delay -gt 0) { Start-Sleep -Seconds ([int][math]::Min($delay, 120)) }
        }
    }
}

# One member row. Only a display name, a UPN (or the primary address for a
# recipient that has no UPN, such as a mail contact) and two derived flags leave
# this function: nothing else on the recipient object is copied, so a phone number
# or title on the raw object cannot reach the worksheet.
function ConvertTo-NRGDlMember {
    [CmdletBinding()]
    param(
        [AllowNull()] $Recipient,
        [AllowEmptyCollection()] [string[]] $AcceptedDomains,
        [bool] $DomainsKnown
    )
    $type = [string](Get-NRGObjectField -Item $Recipient -Key 'RecipientTypeDetails' -Default '')
    if (-not $type) { $type = [string](Get-NRGObjectField -Item $Recipient -Key 'RecipientType' -Default '') }
    $primary = [string](Get-NRGObjectField -Item $Recipient -Key 'PrimarySmtpAddress' -Default '')
    $upn = [string](Get-NRGObjectField -Item $Recipient -Key 'UserPrincipalName' -Default '')
    if (-not $upn) { $upn = $primary }
    $display = [string](Get-NRGObjectField -Item $Recipient -Key 'DisplayName' -Default '')
    if (-not $display) { $display = [string](Get-NRGObjectField -Item $Recipient -Key 'Name' -Default '') }

    $kind = switch -Regex ($type) {
        '^GuestMailUser$'                                                                                          { 'Guest'; break }
        '^MailContact$'                                                                                            { 'Contact'; break }
        '^MailUser$'                                                                                               { 'MailUser'; break }
        'DistributionGroup|SecurityGroup|GroupMailbox|RoomList'                                                    { 'Group'; break }
        'Mailbox$'                                                                                                 { 'Mailbox'; break }
        default                                                                                                    { 'Other' }
    }

    $class = 'Unresolved'
    if ($kind -eq 'Group')      { $class = 'Internal' }     # a tenant object; its own members are classified under its own row
    elseif ($kind -eq 'Guest')  { $class = 'External' }     # an outside identity held in the directory
    elseif ($DomainsKnown) {
        # A mail contact or mail user delivers to its ExternalEmailAddress; the primary address can be in-tenant while mail leaves.
        $addr = ''
        if ($kind -in @('Contact', 'MailUser')) { $addr = ([string](Get-NRGObjectField -Item $Recipient -Key 'ExternalEmailAddress' -Default '')) -replace '^(?i)\s*smtp:\s*', '' }
        if ([string]::IsNullOrWhiteSpace($addr)) { $addr = $primary }
        # Get-NRGRecipientClass reads a blank as 'Internal'; a blank here means the address was not returned.
        if (-not [string]::IsNullOrWhiteSpace($addr)) { $class = Get-NRGRecipientClass -Recipient $addr -AcceptedDomains $AcceptedDomains }
    }

    return [ordered]@{ DisplayName = $display; UPN = $upn; RecipientType = $type; Class = $class }
}

function Invoke-NRGCollectDistributionLists {
    [CmdletBinding()]
    param(
        # Members read per list. One more is requested so truncation is detected
        # rather than guessed; beyond this the list is reported "more than N".
        [ValidateRange(1, 50000)] [int] $MaxMembersPerList = 500,

        # Lists read in one run. A tenant above this is reported as truncated, never as complete.
        [ValidateRange(1, 100000)] [int] $MaxLists = 5000,

        # Retries per query when Exchange throttles it, with exponential backoff from the base delay.
        [ValidateRange(0, 10)] [int] $ThrottleRetries = 3,
        [ValidateRange(0, 300)] [int] $ThrottleBaseDelaySeconds = 2
    )

    $result = @{
        CollectorId = 'EXO-DistributionLists'
        CollectedAt = (Get-Date).ToString('o')
        Success     = $false
        Data        = @{
            Lists           = @()
            AcceptedDomains = @()
            BypassInputs    = @{
                TransportRules    = @()
                ConnectionFilter  = @()
                AntiSpamPolicies  = @()
                AntiSpamRulesRead = $false
                Source            = @{ AcceptedDomains = 'NotRun'; TransportRules = 'NotRun'; ConnectionFilter = 'NotRun'; AntiSpam = 'NotRun' }
            }
            Stats  = @{
                ListsRead = 0; DynamicListsRead = 0; MembersRead = 0
                ListsMembersFailed = 0; ListsMembersTruncated = 0; ThrottleRetries = 0
                TransportRulesTotal = 0; TransportRulesSettingScl = 0
            }
            Limits = @{ MaxMembersPerList = $MaxMembersPerList; MaxLists = $MaxLists; ListsSeen = 0; ListsTruncated = $false }
            # What a run of this collector does and does not cover, so a clean result is never
            # read as covering more than it read.
            Scope  = @{
                Included    = @('Distribution lists (including mail-enabled security groups)', 'Dynamic distribution lists')
                NotIncluded = @('Microsoft 365 Groups and Teams-connected lists (Get-UnifiedGroup is not called)',
                                'Outlook Safe Senders (per mailbox; one query per mailbox)',
                                'Members of nested groups (a nested group is listed, not expanded)')
            }
            # Every list above defaults to @() and each query has its own try/catch, so an empty
            # list is ambiguous; evaluators MUST consult this map before concluding anything
            # from one. 'Members' is Collected only when EVERY list's members were read.
            SectionStatus = @{
                Lists = 'NotRun'; DynamicLists = 'NotRun'; Members = 'NotRun'; AcceptedDomains = 'NotRun'
                TransportRules = 'NotRun'; ConnectionFilter = 'NotRun'; AntiSpam = 'NotRun'
            }
        }
    }
    $d = $result.Data
    $status = $d.SectionStatus
    $stats = $d.Stats

    $fail = {
        param([string] $Section, $ErrorRecord)
        $status[$Section] = 'Failed'
        $msg = [string]$ErrorRecord.Exception.Message
        if ($msg.Length -gt 1500) { $msg = $msg.Substring(0, 1500) }
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source "EXO-DistributionLists-$Section" -Message $msg
        }
    }

    try {
        # ── Accepted domains: needed to call a member external or internal ────────
        $domains = @()
        $domainsKnown = $false
        try {
            $mc = Get-NRGRawData -Key 'EXO-MailboxConfig'
            if ($mc -and (Test-NRGSectionCollected $mc 'AcceptedDomains')) {
                $domains = @(@(Get-NRGNestedProperty -Object $mc -Path 'Data.AcceptedDomains' -Default @()) |
                    ForEach-Object { ([string](Get-NRGObjectField -Item $_ -Key 'DomainName' -Default '')).ToLowerInvariant() } | Where-Object { $_ })
                $d.BypassInputs.Source.AcceptedDomains = 'Reused EXO-MailboxConfig'
            } else {
                $adCmd = (Get-NRGExoCommand -Name 'Get-AcceptedDomain' -Session ExchangeOnline).Command
                if (-not $adCmd) { throw 'Get-AcceptedDomain is not available in the Exchange Online session.' }
                $domains = @(@(Invoke-NRGDlRead -Command $adCmd -Retries $ThrottleRetries -BaseDelaySeconds $ThrottleBaseDelaySeconds -Stats $stats) |
                    ForEach-Object { ([string](Get-NRGObjectField -Item $_ -Key 'DomainName' -Default '')).ToLowerInvariant() } | Where-Object { $_ })
                $d.BypassInputs.Source.AcceptedDomains = 'Read'
            }
            # A tenant always has at least its .onmicrosoft.com domain: none means the read did not work.
            if ($domains.Count -eq 0) { throw 'No accepted domains were returned.' }
            $d.AcceptedDomains = @($domains)
            $domainsKnown = $true
            $status.AcceptedDomains = 'Collected'
        } catch { & $fail 'AcceptedDomains' $_ }

        # ── Lists ────────────────────────────────────────────────────────────────
        $rawLists = [System.Collections.Generic.List[object]]::new()   # @{ Object; Kind }
        try {
            $dgCmd = (Get-NRGExoCommand -Name 'Get-DistributionGroup' -Session ExchangeOnline).Command
            if (-not $dgCmd) { throw 'Get-DistributionGroup is not available in the Exchange Online session.' }
            foreach ($g in @(Invoke-NRGDlRead -Command $dgCmd -Parameters @{ ResultSize = 'Unlimited' } -Retries $ThrottleRetries -BaseDelaySeconds $ThrottleBaseDelaySeconds -Stats $stats)) {
                $t = [string](Get-NRGObjectField -Item $g -Key 'RecipientTypeDetails' -Default '')
                $rawLists.Add(@{ Object = $g; Kind = $(if ($t -match 'SecurityGroup') { 'MailEnabledSecurity' } elseif ($t -match 'RoomList') { 'RoomList' } else { 'Distribution' }) })
            }
            $status.Lists = 'Collected'
        } catch { & $fail 'Lists' $_ }
        try {
            $ddCmd = (Get-NRGExoCommand -Name 'Get-DynamicDistributionGroup' -Session ExchangeOnline).Command
            if (-not $ddCmd) { throw 'Get-DynamicDistributionGroup is not available in the Exchange Online session.' }
            foreach ($g in @(Invoke-NRGDlRead -Command $ddCmd -Parameters @{ ResultSize = 'Unlimited' } -Retries $ThrottleRetries -BaseDelaySeconds $ThrottleBaseDelaySeconds -Stats $stats)) {
                $rawLists.Add(@{ Object = $g; Kind = 'Dynamic' })
            }
            $status.DynamicLists = 'Collected'
        } catch { & $fail 'DynamicLists' $_ }

        $d.Limits.ListsSeen = $rawLists.Count
        if ($rawLists.Count -gt $MaxLists) { $d.Limits.ListsTruncated = $true }
        $toRead = @($rawLists | Select-Object -First $MaxLists)

        # ── Members: one bounded, retried read per list ──────────────────────────
        $memberCmd  = (Get-NRGExoCommand -Name 'Get-DistributionGroupMember' -Session ExchangeOnline).Command
        $dynMemCmd  = (Get-NRGExoCommand -Name 'Get-DynamicDistributionGroupMember' -Session ExchangeOnline).Command
        $recipCmd   = (Get-NRGExoCommand -Name 'Get-Recipient' -Session ExchangeOnline).Command
        $cap        = $MaxMembersPerList
        $rows       = [System.Collections.Generic.List[object]]::new()
        $anyMemberFailed = $false
        foreach ($entry in $toRead) {
            $g = $entry.Object; $kind = [string]$entry.Kind
            $primary = [string](Get-NRGObjectField -Item $g -Key 'PrimarySmtpAddress' -Default '')
            $name    = [string](Get-NRGObjectField -Item $g -Key 'Name' -Default '')
            $display = [string](Get-NRGObjectField -Item $g -Key 'DisplayName' -Default $name)
            $typeD   = [string](Get-NRGObjectField -Item $g -Key 'RecipientTypeDetails' -Default '')
            $identity = if ($primary) { $primary } elseif ([string](Get-NRGObjectField -Item $g -Key 'ExternalDirectoryObjectId' -Default '')) { [string](Get-NRGObjectField -Item $g -Key 'ExternalDirectoryObjectId' -Default '') } else { $name }

            $owners = @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $g -Key 'ManagedBy' -Default $null))
            $allowed = @()
            $allowedKnown = $false
            foreach ($ak in 'AcceptMessagesOnlyFromSendersOrMembers', 'AcceptMessagesOnlyFrom', 'AcceptMessagesOnlyFromDLMembers') {
                if (Test-NRGDlHasField -Item $g -Key $ak) { $allowedKnown = $true; $allowed += @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $g -Key $ak -Default $null)) }
            }
            $joinRaw   = [string](Get-NRGObjectField -Item $g -Key 'MemberJoinRestriction' -Default '')
            $departRaw = [string](Get-NRGObjectField -Item $g -Key 'MemberDepartRestriction' -Default '')

            $row = [ordered]@{
                Name                               = $name
                DisplayName                        = $display
                PrimarySmtpAddress                 = $primary
                Kind                               = $kind
                RecipientTypeDetails               = $typeD
                Owners                             = @($owners)
                OwnerCount                         = $owners.Count
                # Exchange omits a property it does not return; absent is not the same as empty, so these say which.
                OwnersKnown                        = (Test-NRGDlHasField -Item $g -Key 'ManagedBy')
                # $null means Exchange did not return the setting: not read, never defaulted to the safe value.
                RequireSenderAuthenticationEnabled = ConvertTo-NRGDlBool -Value (Get-NRGObjectField -Item $g -Key 'RequireSenderAuthenticationEnabled' -Default $null)
                AllowedSenders                     = @($allowed)
                AllowedSendersKnown                = $allowedKnown
                ModerationEnabled                  = ConvertTo-NRGDlBool -Value (Get-NRGObjectField -Item $g -Key 'ModerationEnabled' -Default $null)
                ModeratedBy                        = @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $g -Key 'ModeratedBy' -Default $null))
                ModeratedByKnown                   = (Test-NRGDlHasField -Item $g -Key 'ModeratedBy')
                MemberJoinRestriction              = $(if ($joinRaw) { $joinRaw } else { $null })
                MemberDepartRestriction            = $(if ($departRaw) { $departRaw } else { $null })
                HiddenFromAddressListsEnabled      = ConvertTo-NRGDlBool -Value (Get-NRGObjectField -Item $g -Key 'HiddenFromAddressListsEnabled' -Default $null)
                # Dynamic: 'DynamicCalculated' is the list Microsoft stores on the group (Get-DynamicDistributionGroupMember);
                # 'DynamicPreview' is a preview of the list's filter, used only when that cmdlet is unavailable.
                MembershipBasis                    = $(if ($kind -eq 'Dynamic') { 'DynamicCalculated' } else { 'Static' })
                MemberStatus                       = 'NotRun'
                MemberError                        = ''
                MemberCount                        = $null
                MemberCountIsLowerBound            = $false
                MembersTruncated                   = $false
                Members                            = @()
                ExternalMemberCount                = 0
                UnresolvedMemberCount              = 0
                NestedGroupCount                   = 0
                NestedGroups                       = @()
            }

            try {
                $raw = @()
                if ($kind -eq 'Dynamic') {
                    # Get-DynamicDistributionGroupMember returns the calculated membership Microsoft stores on the group (refreshed
                    # about every 24 hours). Microsoft says not to use the older filter-preview procedure for a modern dynamic group.
                    if ($dynMemCmd) {
                        $raw = @(Invoke-NRGDlRead -Command $dynMemCmd -Parameters @{ Identity = $identity; ResultSize = ($cap + 1) } -Retries $ThrottleRetries -BaseDelaySeconds $ThrottleBaseDelaySeconds -Stats $stats)
                    } elseif ($recipCmd) {
                        $row.MembershipBasis = 'DynamicPreview'
                        $filter = [string](Get-NRGObjectField -Item $g -Key 'RecipientFilter' -Default '')
                        if (-not $filter) { throw 'The list returned no RecipientFilter, so its members cannot be previewed.' }
                        $raw = @(Invoke-NRGDlRead -Command $recipCmd -Parameters @{ RecipientPreviewFilter = $filter; ResultSize = ($cap + 1) } -Retries $ThrottleRetries -BaseDelaySeconds $ThrottleBaseDelaySeconds -Stats $stats)
                    } else { throw 'Neither Get-DynamicDistributionGroupMember nor Get-Recipient is available in the Exchange Online session.' }
                } else {
                    if (-not $memberCmd) { throw 'Get-DistributionGroupMember is not available in the Exchange Online session.' }
                    $raw = @(Invoke-NRGDlRead -Command $memberCmd -Parameters @{ Identity = $identity; ResultSize = ($cap + 1) } -Retries $ThrottleRetries -BaseDelaySeconds $ThrottleBaseDelaySeconds -Stats $stats)
                }
                # The service may ignore -ResultSize, so the bound is enforced here too.
                $raw = @($raw | Select-Object -First ($cap + 1))
                $row.MembersTruncated = ($raw.Count -gt $cap)
                $kept = @($raw | Select-Object -First $cap)
                $members = @($kept | ForEach-Object { ConvertTo-NRGDlMember -Recipient $_ -AcceptedDomains $domains -DomainsKnown $domainsKnown })
                $row.Members               = $members
                $row.MemberCount           = $members.Count
                $row.MemberCountIsLowerBound = $row.MembersTruncated
                $row.ExternalMemberCount   = @($members | Where-Object { $_.Class -eq 'External' }).Count
                $row.UnresolvedMemberCount = @($members | Where-Object { $_.Class -eq 'Unresolved' }).Count
                $nested = @($members | Where-Object { $_.RecipientType -match 'DistributionGroup|SecurityGroup|GroupMailbox|RoomList' })
                $row.NestedGroupCount = $nested.Count
                $row.NestedGroups     = @($nested | ForEach-Object { $_.DisplayName })
                $row.MemberStatus     = 'Collected'
                $stats.MembersRead += $members.Count
                if ($row.MembersTruncated) { $stats.ListsMembersTruncated++ }
            } catch {
                $anyMemberFailed = $true
                $stats.ListsMembersFailed++
                $row.MemberStatus = 'Failed'
                $m = [string]$_.Exception.Message
                $row.MemberError = $(if ($m.Length -gt 300) { $m.Substring(0, 300) } else { $m })
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'EXO-DistributionLists-Members' -Message ("[$primary] " + $row.MemberError)
                }
            }
            if ($kind -eq 'Dynamic') { $stats.DynamicListsRead++ } else { $stats.ListsRead++ }
            $rows.Add($row)
        }
        $d.Lists = @($rows)
        # 'Members' is trustworthy only when at least one list section ran and no list's member read failed.
        if ($status.Lists -eq 'Collected' -or $status.DynamicLists -eq 'Collected') {
            $status.Members = $(if ($anyMemberFailed) { 'Failed' } else { 'Collected' })
        }

        # ── Transport rules that set SCL, with their CONDITIONS ───────────────────
        # EXO-Inventory stores SetSCL but not the conditions, and a rule's conditions are
        # what make a bypass broad or narrow, so this reads the rules itself.
        try {
            $trCmd = (Get-NRGExoCommand -Name 'Get-TransportRule' -Session ExchangeOnline).Command
            if (-not $trCmd) { throw 'Get-TransportRule is not available in the Exchange Online session.' }
            $allRules = @(Invoke-NRGDlRead -Command $trCmd -Retries $ThrottleRetries -BaseDelaySeconds $ThrottleBaseDelaySeconds -Stats $stats)
            $stats.TransportRulesTotal = $allRules.Count
            $tr = [System.Collections.Generic.List[object]]::new()
            foreach ($r in $allRules) {
                $sclRaw = Get-NRGObjectField -Item $r -Key 'SetSCL' -Default $null
                if ($null -eq $sclRaw -or [string]::IsNullOrWhiteSpace([string]$sclRaw)) { continue }   # the same filter Microsoft's own command uses
                $scl = 0
                $sclParsed = [int]::TryParse(([string]$sclRaw).Trim(), [System.Globalization.NumberStyles]::Integer, [System.Globalization.CultureInfo]::InvariantCulture, [ref]$scl)
                $predicates = @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $r -Key 'Conditions' -Default $null) |
                    ForEach-Object { ($_ -replace '^.*\.', '') -replace 'Predicate$', '' })
                $tr.Add([ordered]@{
                    Name                        = [string](Get-NRGObjectField -Item $r -Key 'Name' -Default '')
                    State                       = [string](Get-NRGObjectField -Item $r -Key 'State' -Default '')
                    Mode                        = [string](Get-NRGObjectField -Item $r -Key 'Mode' -Default '')
                    Priority                    = [string](Get-NRGObjectField -Item $r -Key 'Priority' -Default '')
                    SetSCL                      = $(if ($sclParsed) { $scl } else { $null })
                    # Conditions is always returned by Exchange; its absence means the conditions were not read,
                    # which is different from a rule that has none.
                    ConditionsKnown             = (Test-NRGDlHasField -Item $r -Key 'Conditions')
                    Predicates                  = @($predicates)
                    SenderDomainIs              = @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $r -Key 'SenderDomainIs' -Default $null))
                    SenderIpRanges              = @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $r -Key 'SenderIpRanges' -Default $null))
                    From                        = @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $r -Key 'From' -Default $null))
                    FromScope                   = [string](Get-NRGObjectField -Item $r -Key 'FromScope' -Default '')
                    SentTo                      = @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $r -Key 'SentTo' -Default $null))
                    SentToMemberOf              = @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $r -Key 'SentToMemberOf' -Default $null))
                    HeaderContainsMessageHeader = [string](Get-NRGObjectField -Item $r -Key 'HeaderContainsMessageHeader' -Default '')
                    HeaderContainsWords         = @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $r -Key 'HeaderContainsWords' -Default $null))
                    SubjectContainsWords        = @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $r -Key 'SubjectContainsWords' -Default $null))
                    SubjectOrBodyContainsWords  = @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $r -Key 'SubjectOrBodyContainsWords' -Default $null))
                })
            }
            $d.BypassInputs.TransportRules = @($tr)
            $stats.TransportRulesSettingScl = $tr.Count
            $d.BypassInputs.Source.TransportRules = 'Read'
            $status.TransportRules = 'Collected'
        } catch { & $fail 'TransportRules' $_ }

        # ── IP Allow List ─────────────────────────────────────────────────────────
        try {
            $cfRaw = Get-NRGRawData -Key 'EXO-ConnectionFilter'
            $cfRows = @()
            if ($cfRaw -and [bool](Get-NRGObjectField -Item $cfRaw -Key 'Success' -Default $false)) {
                $cfRows = @(@(Get-NRGNestedProperty -Object $cfRaw -Path 'Data.ConnectionFilter' -Default @()) | ForEach-Object {
                    [ordered]@{
                        Name        = [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '')
                        IsDefault   = [bool](Get-NRGObjectField -Item $_ -Key 'IsDefault' -Default $false)
                        IPAllowList = @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $_ -Key 'IPAllowList' -Default $null))
                    } })
                $d.BypassInputs.Source.ConnectionFilter = 'Reused EXO-ConnectionFilter'
            } else {
                $cfCmd = (Get-NRGExoCommand -Name 'Get-HostedConnectionFilterPolicy' -Session ExchangeOnline).Command
                if (-not $cfCmd) { throw 'Get-HostedConnectionFilterPolicy is not available in the Exchange Online session.' }
                $cfRows = @(@(Invoke-NRGDlRead -Command $cfCmd -Retries $ThrottleRetries -BaseDelaySeconds $ThrottleBaseDelaySeconds -Stats $stats) | ForEach-Object {
                    [ordered]@{
                        Name        = [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '')
                        IsDefault   = [bool](Get-NRGObjectField -Item $_ -Key 'IsDefault' -Default $false)
                        IPAllowList = @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $_ -Key 'IPAllowList' -Default $null))
                    } })
                $d.BypassInputs.Source.ConnectionFilter = 'Read'
            }
            $d.BypassInputs.ConnectionFilter = @($cfRows)
            $status.ConnectionFilter = 'Collected'
        } catch { & $fail 'ConnectionFilter' $_ }

        # ── Anti-spam allowed senders and domains ─────────────────────────────────
        try {
            $mc = Get-NRGRawData -Key 'EXO-MailboxConfig'
            $policies = @(); $rulesRaw = $null; $rulesRead = $false
            if ($mc -and (Test-NRGSectionCollected $mc 'AntiSpamPolicies')) {
                $policies = @(Get-NRGNestedProperty -Object $mc -Path 'Data.AntiSpamPolicies' -Default @())
                # Get-NRGRuleList, not Get-NRGObjectField: an empty collected list must stay distinct from
                # an unread one, and Get-NRGObjectField hands an empty array back as $null.
                $rr = Get-NRGRuleList -Item (Get-NRGObjectField -Item $mc -Key 'Data' -Default $null) -Key 'AntiSpamRules'
                if ($null -ne $rr) { $rulesRaw = @($rr); $rulesRead = $true }
                $d.BypassInputs.Source.AntiSpam = 'Reused EXO-MailboxConfig'
            } else {
                $hcCmd = (Get-NRGExoCommand -Name 'Get-HostedContentFilterPolicy' -Session ExchangeOnline).Command
                if (-not $hcCmd) { throw 'Get-HostedContentFilterPolicy is not available in the Exchange Online session.' }
                $policies = @(Invoke-NRGDlRead -Command $hcCmd -Retries $ThrottleRetries -BaseDelaySeconds $ThrottleBaseDelaySeconds -Stats $stats)
                # The rules say which custom policies apply to anyone. A failed rules read is recorded
                # and leaves 'in force' unknown; it does not fail the section.
                try {
                    $hrCmd = (Get-NRGExoCommand -Name 'Get-HostedContentFilterRule' -Session ExchangeOnline).Command
                    if (-not $hrCmd) { throw 'Get-HostedContentFilterRule is not available in the Exchange Online session.' }
                    $rulesRaw = @(Invoke-NRGDlRead -Command $hrCmd -Retries $ThrottleRetries -BaseDelaySeconds $ThrottleBaseDelaySeconds -Stats $stats)
                    $rulesRead = $true
                } catch {
                    if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                        Register-NRGException -Source 'EXO-DistributionLists-AntiSpamRules' -Message ([string]$_.Exception.Message)
                    }
                }
                $d.BypassInputs.Source.AntiSpam = 'Read'
            }
            $d.BypassInputs.AntiSpamRulesRead = $rulesRead
            $d.BypassInputs.AntiSpamPolicies = @($policies | ForEach-Object {
                $pn = [string](Get-NRGObjectField -Item $_ -Key 'Name' -Default '')
                $isDef = [bool](Get-NRGObjectField -Item $_ -Key 'IsDefault' -Default $false)
                # In force: the default policy always; a custom policy only when an enabled rule applies it
                # ($null when the rules were not read, so the verdict keeps the entry rather than dropping it).
                $inForce = if ($isDef) { $true } elseif (-not $rulesRead) { $null } else {
                    [bool](@(@($rulesRaw) | Where-Object {
                        [string](Get-NRGObjectField -Item $_ -Key 'HostedContentFilterPolicy' -Default '') -eq $pn -and
                        [string](Get-NRGObjectField -Item $_ -Key 'State' -Default '') -eq 'Enabled' }).Count -gt 0)
                }
                [ordered]@{
                    Name                 = $pn
                    IsDefault            = $isDef
                    AllowedSenders       = @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $_ -Key 'AllowedSenders' -Default $null))
                    AllowedSenderDomains = @(ConvertTo-NRGDlStringList -Value (Get-NRGObjectField -Item $_ -Key 'AllowedSenderDomains' -Default $null))
                    InForce              = $inForce
                }
            })
            $status.AntiSpam = 'Collected'
        } catch { & $fail 'AntiSpam' $_ }

        $result.Success = $true
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            $bad = @($status.Keys | Where-Object { $status[$_] -ne 'Collected' })
            $note = "$($stats.ListsRead) lists, $($stats.DynamicListsRead) dynamic lists, $($stats.MembersRead) members read"
            if ($bad.Count -eq 0) { Register-NRGCoverage -Family 'EXO-DistributionLists' -Status 'Collected' -Note $note }
            elseif ($status.Lists -ne 'Collected' -and $status.DynamicLists -ne 'Collected') { Register-NRGCoverage -Family 'EXO-DistributionLists' -Status 'Failed' -Note 'No distribution list could be read.' }
            else { Register-NRGCoverage -Family 'EXO-DistributionLists' -Status 'Partial' -Note ("$note; not collected: " + ($bad -join ', ')) }
        }
    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'EXO-DistributionLists' -Message ([string]$_.Exception.Message)
        }
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'EXO-DistributionLists' -Status 'Failed' -Note ([string]$_.Exception.Message)
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'EXO-DistributionLists' -Data $result
    }
    return $result
}
