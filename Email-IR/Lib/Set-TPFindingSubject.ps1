#Requires -Version 7.0
<#
.SYNOPSIS
    Set-TPFindingSubject.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: Make a per-mailbox finding say WHOSE mailbox it describes and WHAT
             evidence supports it. The mailbox evaluators read one mailbox at a
             time and emit findings with no account on them; when the triage
             deep-dive loops over several users, two users' "inbox rule" findings
             were indistinguishable in the report and the JSON. This tags the
             findings a dive produced with the account and an Evidence summary
             (sources read, sources missing, whether every required source was
             read) taken from that user's own raw data, before the next user's
             data replaces it.
    Data keys consumed: IR-MailboxProfile, IR-MailboxSentItems, IR-MailboxInbox,
    IR-MailboxRecoverable, IR-MailboxRules, IR-MailboxForwarding, IR-UserConsents,
    IR-UserAuthMethods.
    Graph scopes / cmdlets: none.
#>

Set-StrictMode -Version Latest

function Get-TPDeepDiveEvidenceKeys {
    <#
    .SYNOPSIS
        The raw-data keys a per-mailbox deep-dive reads. Required keys are the
        ones a mailbox conclusion cannot stand without; the rest are reported
        when present and named when missing (several are routinely unavailable
        under delegated Graph scope).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()
    [ordered]@{
        Required = @('IR-MailboxProfile', 'IR-MailboxSentItems', 'IR-MailboxInbox', 'IR-MailboxRules')
        Optional = @('IR-MailboxRecoverable', 'IR-MailboxForwarding', 'IR-UserConsents', 'IR-UserAuthMethods')
    }
}

function Get-TPDeepDiveEvidence {
    <#
    .SYNOPSIS
        Summarizes what the current raw data holds for one mailbox: which
        sources were read, which were not, and whether every required source was.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()
    $keys = Get-TPDeepDiveEvidenceKeys
    $read = [System.Collections.Generic.List[string]]::new()
    $missing = [System.Collections.Generic.List[string]]::new()
    $partial = [System.Collections.Generic.List[string]]::new()
    # An OPTIONAL source that was read but stopped at its page cap. A missing
    # optional source is routine (delegated scope) and only named; one that was
    # read and cut short means indicators may sit in the pages not read, so it
    # makes the evidence incomplete like a required one.
    $optionalTruncated = [System.Collections.Generic.List[string]]::new()
    foreach ($k in @($keys.Required) + @($keys.Optional)) {
        $bag = Get-TPRawData -Key $k
        $ok = $bag -and [bool](Get-TPObjectField -Item $bag -Key 'Success' -Default $false)
        if ($ok) {
            $read.Add($k)
            # A source that was read but only in part: the page cap stopped it
            # (Truncated) or the collector recorded a limitation. It is read,
            # not complete, and a "nothing found" over it is not a clean result.
            if ([bool](Get-TPNestedProperty -Object $bag -Path 'Data.Truncated' -Default $false)) {
                $partial.Add("$k (stopped at its page cap; older items in the window were not read)")
                if ($k -in $keys.Optional) { $optionalTruncated.Add("$k (stopped at its page cap; more items exist than were read)") }
            }
            $lim = [string](Get-TPNestedProperty -Object $bag -Path 'Data.CollectionLimitation' -Default '')
            if ($lim) { $partial.Add("$k ($lim)") }
        } else { $missing.Add($k) }
    }
    $requiredMissing = @($keys.Required | Where-Object { $_ -in $missing })
    $requiredPartial = @($partial | Where-Object { $p = $_; @($keys.Required | Where-Object { $p.StartsWith($_ + ' ') }).Count -gt 0 })
    return [ordered]@{
        SourcesRead     = @($read)
        SourcesMissing  = @($missing)
        SourcesPartial  = @($partial)
        RequiredMissing = @($requiredMissing)
        RequiredPartial = @($requiredPartial)
        OptionalTruncated = @($optionalTruncated)
        Complete        = ($requiredMissing.Count -eq 0 -and $requiredPartial.Count -eq 0 -and $optionalTruncated.Count -eq 0)
    }
}

function Set-TPFindingSubject {
    <#
    .SYNOPSIS
        Tags the findings added since -Since with the account they describe and
        the evidence summary. A finding that already names a subject is left
        alone, so a finding can never be re-attributed to another user.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)] [ValidateRange(0, 1000000)] [int] $Since,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Subject,
        [AllowNull()] [object] $Evidence = $null
    )
    $all = @(Get-TPFindings)
    $tagged = 0
    for ($i = $Since; $i -lt $all.Count; $i++) {
        $f = $all[$i]
        if ($null -eq $f) { continue }
        if ($f.PSObject.Properties['Subject'] -and $f.Subject) { continue }
        Add-Member -InputObject $f -NotePropertyName 'Subject' -NotePropertyValue $Subject -Force
        Add-Member -InputObject $f -NotePropertyName 'Evidence' -NotePropertyValue $Evidence -Force
        $tagged++
    }
    return $tagged
}
