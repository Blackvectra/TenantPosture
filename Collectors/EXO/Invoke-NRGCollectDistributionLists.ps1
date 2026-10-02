#Requires -Version 7.0
#
# Invoke-NRGCollectDistributionLists.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Inventory every distribution list in the tenant: its current settings
#          and who is in it. Feeds the DL-* evaluator and the worksheet.
#
# READ-ONLY. Calls only Exchange Online Get-* cmdlets, each resolved through
# Get-NRGExoCommand pinned to the Exchange Online session (never a name that could
# bind to the Security & Compliance session). It creates, adds, removes and changes
# nothing, and NRG.DistributionLists.Tests.ps1 fails if a write cmdlet name appears.
#
# Data key set:  EXO-DistributionLists
# Cmdlets read:  Get-DistributionGroup, Get-DynamicDistributionGroup,
#                Get-DistributionGroupMember, Get-DynamicDistributionGroupMember,
#                Get-AcceptedDomain
# Graph scopes:  none. This collector does not use Graph.
#
# Data populated (Data.*):
#   Lists            one record per list: Name, DisplayName, PrimarySmtpAddress, Guid,
#                    ListType (Distribution / MailEnabledSecurity / RoomList / Dynamic),
#                    Owners, RequireSenderAuthenticationEnabled, AcceptMessagesOnlyFrom*,
#                    ModerationEnabled, ModeratedBy, MemberJoinRestriction,
#                    MemberDepartRestriction, HiddenFromAddressListsEnabled, then the
#                    member read: MemberStatus, MemberCount, Members, ExternalMembers,
#                    NestedGroups.
#   AcceptedDomains  what "external" is measured against.
#   Stats, SectionStatus
#
# HOW A READ FAILS WITHOUT SAYING SO, and what this collector does about it
#   * A property Exchange OMITS is not a property that is empty. Every field is read
#     through Get-NRGObjectField with an "absent" sentinel: an omitted scalar is $null
#     (not read), an omitted list is $null (not read), and only a list that came back
#     (even empty) is an empty list. "No owner" and "owner not read" never look alike.
#   * An empty Lists array is "none found" or "the query failed". SectionStatus says
#     which: DistributionGroups / DynamicDistributionGroups / AcceptedDomains / Members,
#     each NotRun / Collected / Failed.
#   * A throttled Exchange call is retried with backoff; one that still fails marks that
#     LIST's member read Failed (MemberStatus), never "no members".
#   * A list bigger than -MemberReadLimit is read up to the limit and marked Truncated:
#     the count is "at least", and "no external member found" is not claimed for it.
#   * An address that cannot be classified against the accepted domains is counted as
#     unclassified, never as internal. With no accepted-domain read, nothing is called
#     external or internal.
#   * A member carries ONLY a UPN (or, for a contact or group, its address) and a
#     display name. Nothing else about the person is stored.
#
# NIST SP 800-53 (this tool's mapping, see Config/distribution-list-baseline.json):
#   AC-2, AC-3, AC-4, AC-6, SC-7, SI-8

# Throttle-looking error text. Matched against the exception message only; anything
# else (a permissions error, a missing object) is not retried.
$script:NRGDlThrottlePattern = '(?i)throttl|too many requests|\b429\b|budget|server\s*busy|temporarily unavailable|try again later|rate limit'
# Replaced in tests so a retry does not wait.
$script:NRGDlSleep = { param([double] $Seconds) Start-Sleep -Seconds $Seconds }
$script:NRGDlRetryCount = 0

function Invoke-NRGDlExoRead {
    # One Exchange read with throttle backoff. Returns the result as an array (empty
    # when the cmdlet returned nothing). Throws the last error when retries run out.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] $Command,
        [hashtable] $Parameters = @{},
        [int] $Retries = 3
    )
    $attempt = 0
    while ($true) {
        try {
            return , @(& $Command @Parameters -ErrorAction Stop)
        } catch {
            $msg = [string]$_.Exception.Message
            if ($attempt -ge $Retries -or $msg -notmatch $script:NRGDlThrottlePattern) { throw }
            $attempt++
            $script:NRGDlRetryCount++
            & $script:NRGDlSleep ([Math]::Min(30, [Math]::Pow(2, $attempt)))
        }
    }
}

function ConvertTo-NRGDlBool {
    # Exchange booleans arrive as [bool]; a replayed or stubbed value can be the string
    # 'False', and [bool]'False' is $true. Anything unparseable is "not read".
    [CmdletBinding()]
    param([AllowNull()] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $Value }
    if ($Value -is [string]) {
        if ($Value -ieq 'True')  { return $true }
        if ($Value -ieq 'False') { return $false }
    }
    return $null
}

function Get-NRGDlListType {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [string] $RecipientTypeDetails)
    switch -Regex ($RecipientTypeDetails) {
        '^MailUniversalDistributionGroup$' { return 'Distribution' }
        '^MailUniversalSecurityGroup$'     { return 'MailEnabledSecurity' }
        '^RoomList$'                       { return 'RoomList' }
        '^DynamicDistributionGroup$'       { return 'Dynamic' }
        default                            { return 'Other' }
    }
}

function Get-NRGDlMemberKind {
    # Whether a member is a nested group, and whether its address is outside the tenant.
    # Returns Kind = Group / Person and Class = External / Internal / Unresolved.
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Member, [AllowEmptyCollection()] [string[]] $AcceptedDomains = @())
    $details = [string](Get-NRGObjectField -Item $Member -Key 'RecipientTypeDetails' -Default '')
    $type    = [string](Get-NRGObjectField -Item $Member -Key 'RecipientType' -Default '')
    $isGroup = (($details + ' ' + $type) -match 'DistributionGroup|SecurityGroup|RoomList|GroupMailbox')
    if ($isGroup) { return [pscustomobject]@{ Kind = 'Group'; Class = 'Internal' } }

    # ExternalEmailAddress first, as Get-NRGRecipientClass does: on a mail user the primary
    # address can be in-tenant while mail leaves to the external one.
    $addr = ([string](Get-NRGObjectField -Item $Member -Key 'ExternalEmailAddress' -Default '')) -replace '^(?i)\s*smtp:\s*', ''
    if ([string]::IsNullOrWhiteSpace($addr)) { $addr = [string](Get-NRGObjectField -Item $Member -Key 'PrimarySmtpAddress' -Default '') }
    # Get-NRGRecipientClass returns 'Internal' for a blank string and treats an empty
    # accepted-domain set as "everything is external"; neither is a verdict here.
    if ([string]::IsNullOrWhiteSpace($addr) -or @($AcceptedDomains).Count -eq 0) {
        return [pscustomobject]@{ Kind = 'Person'; Class = 'Unresolved' }
    }
    return [pscustomobject]@{ Kind = 'Person'; Class = (Get-NRGRecipientClass -Recipient $addr -AcceptedDomains $AcceptedDomains) }
}

function Invoke-NRGCollectDistributionLists {
    [CmdletBinding()]
    param(
        # The most members read per list. A list over the limit is Truncated, not complete.
        [ValidateRange(1, 100000)] [int] $MemberReadLimit = 5000,
        # How many times a throttled Exchange call is retried before that read is Failed.
        [ValidateRange(0, 10)] [int] $ThrottleRetries = 3
    )

    $script:NRGDlRetryCount = 0
    $result = @{
        CollectorId = 'EXO-DistributionLists'
        CollectedAt = (Get-Date).ToString('o')
        Success     = $false
        Data        = @{
            Lists           = @()
            AcceptedDomains = @()
            TenantDomain    = ''
            Stats           = @{
                ListsRead                 = 0
                DistributionGroups        = 0
                DynamicDistributionGroups = 0
                MemberReadLimit           = $MemberReadLimit
                ListsMembersCollected     = 0
                ListsMembersTruncated     = 0
                ListsMembersFailed        = 0
                ThrottleRetries           = 0
            }
            # Every list above defaults to @(), so an empty one cannot say whether the
            # query found nothing or failed. This map can.
            SectionStatus   = @{
                DistributionGroups        = 'NotRun'
                DynamicDistributionGroups = 'NotRun'
                AcceptedDomains           = 'NotRun'
                Members                   = 'NotRun'
            }
        }
    }
    $fail = {
        param([string] $Source, [string] $Message)
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source $Source -Message $Message
        }
    }
    $sentinel = [pscustomobject]@{ Absent = $true }

    try {
        # Each cmdlet is pinned to the Exchange Online session. Get-Recipient-style names
        # also exist in Security & Compliance; an unqualified call runs the session loaded last.
        $cmd = @{}
        foreach ($n in 'Get-DistributionGroup', 'Get-DynamicDistributionGroup', 'Get-DistributionGroupMember', 'Get-DynamicDistributionGroupMember', 'Get-AcceptedDomain') {
            $cmd[$n] = (Get-NRGExoCommand -Name $n -Session ExchangeOnline).Command
        }

        # ── Accepted domains: what "external" is measured against ───────────────
        $domains = @()
        if ($cmd['Get-AcceptedDomain']) {
            try {
                $acc = Invoke-NRGDlExoRead -Command $cmd['Get-AcceptedDomain'] -Retries $ThrottleRetries
                $domains = @($acc | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'DomainName' -Default '') } |
                    Where-Object { $_ } | ForEach-Object { $_.ToLowerInvariant() })
                $def = @($acc | Where-Object { (ConvertTo-NRGDlBool (Get-NRGObjectField -Item $_ -Key 'Default' -Default $null)) -eq $true }) | Select-Object -First 1
                if ($def) { $result.Data.TenantDomain = [string](Get-NRGObjectField -Item $def -Key 'DomainName' -Default '') }
                $result.Data.AcceptedDomains = $domains
                # No accepted domain at all means no basis for "external".
                $result.Data.SectionStatus.AcceptedDomains = if ($domains.Count -gt 0) { 'Collected' } else { 'Failed' }
                if ($domains.Count -eq 0) { & $fail 'EXO-DL-AcceptedDomains' 'Get-AcceptedDomain returned no domain names; members cannot be classified as external.' }
            } catch {
                $result.Data.SectionStatus.AcceptedDomains = 'Failed'
                & $fail 'EXO-DL-AcceptedDomains' $_.Exception.Message
            }
        } else {
            $result.Data.SectionStatus.AcceptedDomains = 'Failed'
            & $fail 'EXO-DL-AcceptedDomains' 'Get-AcceptedDomain is not available in the Exchange Online session.'
        }

        # ── Enumerate the lists ─────────────────────────────────────────────────
        $groups = [System.Collections.Generic.List[object]]::new()
        $read = {
            param([string] $Name, [string] $Section, [string] $Source)
            if (-not $cmd[$Name]) {
                $result.Data.SectionStatus[$Section] = 'Failed'
                & $fail $Source "$Name is not available in the Exchange Online session."
                return
            }
            try {
                $rows = Invoke-NRGDlExoRead -Command $cmd[$Name] -Parameters @{ ResultSize = 'Unlimited' } -Retries $ThrottleRetries
                foreach ($r in $rows) { $groups.Add([pscustomobject]@{ Object = $r; Dynamic = ($Section -eq 'DynamicDistributionGroups') }) }
                $result.Data.Stats[$Section] = @($rows).Count
                $result.Data.SectionStatus[$Section] = 'Collected'
            } catch {
                $result.Data.SectionStatus[$Section] = 'Failed'
                & $fail $Source $_.Exception.Message
            }
        }
        & $read 'Get-DistributionGroup' 'DistributionGroups' 'EXO-DL-DistributionGroups'
        & $read 'Get-DynamicDistributionGroup' 'DynamicDistributionGroups' 'EXO-DL-DynamicGroups'

        # ── One record per list, then its members ───────────────────────────────
        $records = [System.Collections.Generic.List[object]]::new()
        $membersFailed = 0
        foreach ($g in $groups) {
            $o = $g.Object
            $details = [string](Get-NRGObjectField -Item $o -Key 'RecipientTypeDetails' -Default '')
            $type = if ($g.Dynamic) { 'Dynamic' } else { Get-NRGDlListType -RecipientTypeDetails $details }
            $missing = [System.Collections.Generic.List[string]]::new()

            # Scalar: $null when omitted. List: $null when omitted, an array (possibly empty) when returned.
            $scalar = { param([string] $Key) $v = Get-NRGObjectField -Item $o -Key $Key -Default $sentinel
                        if ([object]::ReferenceEquals($v, $sentinel)) { $missing.Add($Key); return $null }; return $v }
            $list = { param([string] $Key) $v = Get-NRGObjectField -Item $o -Key $Key -Default $sentinel
                      if ([object]::ReferenceEquals($v, $sentinel)) { $missing.Add($Key); return $null }
                      return , @(@($v) | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ }) }

            $name    = [string](Get-NRGObjectField -Item $o -Key 'Name' -Default '')
            $display = [string](Get-NRGObjectField -Item $o -Key 'DisplayName' -Default $name)
            $smtp    = [string](Get-NRGObjectField -Item $o -Key 'PrimarySmtpAddress' -Default '')
            $guid    = [string](Get-NRGObjectField -Item $o -Key 'Guid' -Default '')
            $rsae    = ConvertTo-NRGDlBool (& $scalar 'RequireSenderAuthenticationEnabled')
            $rec = [ordered]@{
                Name                                   = $name
                DisplayName                            = $display
                PrimarySmtpAddress                     = $smtp
                Guid                                   = $guid
                ListType                               = $type
                RecipientTypeDetails                   = $details
                IsDirSynced                            = (ConvertTo-NRGDlBool (Get-NRGObjectField -Item $o -Key 'IsDirSynced' -Default $null))
                RecipientFilter                        = $(if ($g.Dynamic) { [string](Get-NRGObjectField -Item $o -Key 'RecipientFilter' -Default '') } else { '' })
                Owners                                 = (& $list 'ManagedBy')
                RequireSenderAuthenticationEnabled     = $rsae
                AcceptMessagesOnlyFrom                 = (& $list 'AcceptMessagesOnlyFrom')
                AcceptMessagesOnlyFromDLMembers        = (& $list 'AcceptMessagesOnlyFromDLMembers')
                AcceptMessagesOnlyFromSendersOrMembers = (& $list 'AcceptMessagesOnlyFromSendersOrMembers')
                ModerationEnabled                      = (ConvertTo-NRGDlBool (& $scalar 'ModerationEnabled'))
                ModeratedBy                            = (& $list 'ModeratedBy')
                MemberJoinRestriction                  = $null
                MemberDepartRestriction                = $null
                HiddenFromAddressListsEnabled          = (ConvertTo-NRGDlBool (& $scalar 'HiddenFromAddressListsEnabled'))
                PropertiesNotReturned                  = @()
                MemberStatus                           = 'NotRun'
                MemberCount                            = $null
                MembersTruncated                       = $false
                MemberError                            = ''
                Members                                = @()
                ExternalMembers                        = @()
                NestedGroups                           = @()
                UnclassifiedMemberCount                = 0
            }
            if (-not $g.Dynamic) {
                # A dynamic list has no join or leave setting: membership is its filter.
                $j = & $scalar 'MemberJoinRestriction';   if ($null -ne $j) { $rec.MemberJoinRestriction = [string]$j }
                $d = & $scalar 'MemberDepartRestriction'; if ($null -ne $d) { $rec.MemberDepartRestriction = [string]$d }
            }
            $rec.PropertiesNotReturned = @($missing)

            # ── Members ─────────────────────────────────────────────────────────
            $idToken = if ($guid) { $guid } elseif ($smtp) { $smtp } else { $name }
            $mc = if ($g.Dynamic) { $cmd['Get-DynamicDistributionGroupMember'] } else { $cmd['Get-DistributionGroupMember'] }
            if (-not $mc -or [string]::IsNullOrWhiteSpace($idToken)) {
                $rec.MemberStatus = 'Failed'
                $rec.MemberError = if (-not $mc) { 'The member cmdlet is not available in the Exchange Online session.' } else { 'The list has no identity to read members with.' }
                $membersFailed++
                & $fail 'EXO-DL-Members' ("{0}: {1}" -f $(if ($smtp) { $smtp } else { $name }), $rec.MemberError)
            } else {
                try {
                    # One more than the limit, so "exactly at the limit" and "over it" differ.
                    $rows = Invoke-NRGDlExoRead -Command $mc -Parameters @{ Identity = $idToken; ResultSize = ($MemberReadLimit + 1) } -Retries $ThrottleRetries
                    $truncated = (@($rows).Count -gt $MemberReadLimit)
                    $keep = @(if ($truncated) { $rows | Select-Object -First $MemberReadLimit } else { $rows })
                    $members = [System.Collections.Generic.List[object]]::new()
                    $external = [System.Collections.Generic.List[object]]::new()
                    $nested = [System.Collections.Generic.List[object]]::new()
                    $unclassified = 0
                    foreach ($m in $keep) {
                        $mUpn = foreach ($k in 'UserPrincipalName', 'WindowsLiveID', 'PrimarySmtpAddress') {
                            $x = [string](Get-NRGObjectField -Item $m -Key $k -Default ''); if ($x) { $x; break } }
                        $mName = [string](Get-NRGObjectField -Item $m -Key 'DisplayName' -Default (Get-NRGObjectField -Item $m -Key 'Name' -Default ''))
                        $row = [ordered]@{ UPN = [string]$mUpn; DisplayName = $mName }
                        $members.Add($row)
                        $kind = Get-NRGDlMemberKind -Member $m -AcceptedDomains $domains
                        if ($kind.Kind -eq 'Group') { $nested.Add($row) }
                        elseif ($kind.Class -eq 'External') { $external.Add($row) }
                        elseif ($kind.Class -eq 'Unresolved') { $unclassified++ }
                    }
                    $rec.Members = @($members); $rec.ExternalMembers = @($external); $rec.NestedGroups = @($nested)
                    $rec.UnclassifiedMemberCount = $unclassified
                    $rec.MemberCount = $members.Count
                    $rec.MembersTruncated = $truncated
                    $rec.MemberStatus = if ($truncated) { 'Truncated' } else { 'Collected' }
                } catch {
                    $rec.MemberStatus = 'Failed'
                    $rec.MemberError = ([string]$_.Exception.Message) -replace '[\x00-\x1F\x7F]+', ' '
                    if ($rec.MemberError.Length -gt 300) { $rec.MemberError = $rec.MemberError.Substring(0, 300) }
                    $membersFailed++
                    & $fail 'EXO-DL-Members' ("{0}: {1}" -f $(if ($smtp) { $smtp } else { $name }), $rec.MemberError)
                }
            }
            $records.Add([pscustomobject]$rec)
        }

        $result.Data.Lists = @($records)
        $result.Data.Stats.ListsRead = $records.Count
        $result.Data.Stats.ListsMembersCollected = @($records | Where-Object { $_.MemberStatus -eq 'Collected' }).Count
        $result.Data.Stats.ListsMembersTruncated = @($records | Where-Object { $_.MemberStatus -eq 'Truncated' }).Count
        $result.Data.Stats.ListsMembersFailed    = $membersFailed
        $result.Data.Stats.ThrottleRetries       = $script:NRGDlRetryCount
        # Truncated is a declared, per-list limit; only a failed read makes the section unreliable.
        $result.Data.SectionStatus.Members = if ($membersFailed -eq 0) { 'Collected' } else { 'Failed' }
        $result.Success = $true

        $sec = $result.Data.SectionStatus
        $cov = if ($sec.DistributionGroups -ne 'Collected' -and $sec.DynamicDistributionGroups -ne 'Collected') { 'Failed' }
               elseif ($sec.DistributionGroups -eq 'Collected' -and $sec.DynamicDistributionGroups -eq 'Collected' -and $sec.AcceptedDomains -eq 'Collected' -and $sec.Members -eq 'Collected' -and $result.Data.Stats.ListsMembersTruncated -eq 0) { 'Collected' }
               else { 'Partial' }
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'EXO-DistributionLists' -Status $cov -Note ("{0} list(s) read; members read for {1}, truncated for {2}, failed for {3}; {4} throttle retries" -f $records.Count, $result.Data.Stats.ListsMembersCollected, $result.Data.Stats.ListsMembersTruncated, $membersFailed, $script:NRGDlRetryCount)
        }
    } catch {
        & $fail 'EXO-DistributionLists' $_.Exception.Message
        if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
            Register-NRGCoverage -Family 'EXO-DistributionLists' -Status 'Failed' -Note $_.Exception.Message
        }
    }

    if (Get-Command Set-NRGRawData -ErrorAction SilentlyContinue) {
        Set-NRGRawData -Key 'EXO-DistributionLists' -Data $result
    }
    return $result
}
