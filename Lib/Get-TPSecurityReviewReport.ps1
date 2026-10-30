#Requires -Version 7.0
#
# Get-TPSecurityReviewReport.ps1
# Dependencies: Get-TPObjectField, Get-TPNestedProperty, Get-TPRunScope, Test-TPDomainName, ConvertTo-TPUtcDateTime
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: The client-facing security configuration review: the Conditional
#   Access checklist and the Intune and endpoint checklist (both Maester's
#   checks) regrouped into what a client can act on, in plain language, for a
#   PDF they can keep and forward.
#
#     Recommended next steps   not met, ordered by severity, each with what to do
#     Ready to turn on         a matching policy exists in report-only mode
#     In place                 met
#     Not checked              the data was not read, or a license is needed
#
# HONESTY RULES (pinned by TP.SecurityReview.Tests.ps1):
#   - Nothing says compliant or secure. Page one says this is a point-in-time
#     review of configuration, not an audit or a compliance determination, and
#     that a check met means the setting was in place when read.
#   - Every checklist row lands in exactly one group, or is counted as not
#     applying; the counts sum to the rows read.
#   - A partial or quick run is refused: a document a client forwards must not
#     read as the whole tenant when it is not.
#   - The model carries no account name, policy name, finding detail, command
#     or report-only policy body: only each check's title, reason, severity,
#     status and the recommended change, and its Maester reference.
#
# Inputs:  -CAChecklist, -IntuneChecklist (the views or Read-TPRunRecord's
#          trimmed copies), -Metadata, -ClientName, -PreparedBy.
# Graph scopes / cmdlets used: none. No network.

function Get-TPSecurityReviewGroupNames {
    [CmdletBinding()]
    param()
    return [ordered]@{
        NextSteps   = 'Recommended next steps'
        TurnOn      = 'Ready to turn on'
        InPlace     = 'In place'
        NotChecked  = 'Not checked in this review'
    }
}

function Get-TPSecurityReviewReport {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [object] $CAChecklist,
        [AllowNull()] [object] $IntuneChecklist,
        [AllowNull()] [object] $Metadata,
        [AllowEmptyString()] [string] $ClientName = '',
        [AllowEmptyString()] [string] $PreparedBy = ''
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $scope = Get-TPRunScope -Metadata $Metadata
    if ($scope -ne 'Full') {
        $why = if ($scope -eq 'Partial') { 'a partial run (-ControlId)' } else { 'a quick scan (-Quick)' }
        return [ordered]@{ Available = $false; Refused = $true; Note = "The client security review covers the whole tenant and is not written from $why. Run a full assessment." }
    }
    $sources = [ordered]@{
        Access  = @{ View = $CAChecklist; Title = 'Sign-in protection (Conditional Access)' }
        Devices = @{ View = $IntuneChecklist; Title = 'Devices, attack surface reduction and antivirus (Intune)' }
    }
    $haveAny = $false
    foreach ($k in $sources.Keys) { if ((Get-TPObjectField -Item $sources[$k].View -Key 'Available' -Default $false) -eq $true) { $haveAny = $true } }
    if (-not $haveAny) {
        return [ordered]@{ Available = $false; Refused = $false; Note = 'The results file carries no Conditional Access or Intune checklist (a run from before they existed). Run the assessment again.' }
    }

    $names = Get-TPSecurityReviewGroupNames
    $groupOf = @{ Fail = 'NextSteps'; Staged = 'TurnOn'; Pass = 'InPlace'; NotAssessed = 'NotChecked'; NeedsLicense = 'NotChecked' }
    $sevRank = @{ High = 0; Medium = 1; Low = 2 }
    $groups = [ordered]@{}
    foreach ($k in $names.Keys) { $groups[$k] = [System.Collections.Generic.List[object]]::new() }
    $notApplicable = 0
    $topicCounts = [ordered]@{}

    foreach ($topic in $sources.Keys) {
        $view = $sources[$topic].View
        $tc = [ordered]@{ Title = $sources[$topic].Title; Read = $false }
        foreach ($k in $names.Keys) { $tc[$k] = 0 }
        if ((Get-TPObjectField -Item $view -Key 'Available' -Default $false) -eq $true) {
            $tc.Read = $true
            foreach ($r in @(Get-TPObjectField -Item $view -Key 'Rows' -Default @() | Where-Object { $null -ne $_ })) {
                $status = [string](Get-TPObjectField -Item $r -Key 'Status' -Default '')
                if ($status -eq 'NotApplicable') { $notApplicable++; continue }
                $g = $groupOf[$status]
                if (-not $g) { $g = 'NotChecked' }
                $kind = [string](Get-TPObjectField -Item $r -Key 'Kind' -Default '')
                $area = [string](Get-TPObjectField -Item $r -Key 'Area' -Default '')
                $item = [ordered]@{
                    Reference   = [string](Get-TPObjectField -Item $r -Key 'Id' -Default '')
                    Topic       = $topic
                    TopicTitle  = $sources[$topic].Title
                    Area        = $(if ($area) { $area } elseif ($kind -eq 'Presence') { 'Recommended policy' } elseif ($kind -eq 'Hygiene') { 'Policy hygiene' } elseif ($kind -eq 'Simulation') { 'Sign-in simulation' } else { '' })
                    Title       = [string](Get-TPObjectField -Item $r -Key 'Title' -Default '')
                    Why         = [string](Get-TPObjectField -Item $r -Key 'Why' -Default '')
                    Severity    = [string](Get-TPObjectField -Item $r -Key 'Severity' -Default '')
                    Group       = $g
                    Action      = ''
                }
                $item.Action = switch ($status) {
                    'Fail'         { [string](Get-TPObjectField -Item $r -Key 'Recommended' -Default '') }
                    'Staged'       { 'A matching policy already exists in report-only mode. Review what it would have done, then turn it on.' }
                    'NeedsLicense' { "Needs $([string](Get-TPObjectField -Item $r -Key 'LicenseRequirement' -Default 'an additional license')), which this tenant's subscriptions do not include." }
                    'NotAssessed'  { 'The settings this check reads could not be read in this review, so nothing is claimed either way.' }
                    default        { '' }
                }
                $groups[$g].Add($item)
                $tc[$g]++
            }
        }
        $topicCounts[$topic] = $tc
    }

    $sorted = [ordered]@{}
    foreach ($k in $groups.Keys) {
        $sorted[$k] = @($groups[$k] | Sort-Object -Stable @{ Expression = { $sevRank[[string]$_.Severity] ?? 9 } }, @{ Expression = { $_.Topic } })
    }
    $counts = [ordered]@{}
    foreach ($k in $groups.Keys) { $counts[$k] = $groups[$k].Count }
    $total = 0; foreach ($k in $counts.Keys) { $total += $counts[$k] }

    $domain = ([string](Get-TPObjectField -Item $Metadata -Key 'TenantDomain' -Default '')).ToLowerInvariant()
    if ($domain -and -not (Test-TPDomainName -Value $domain)) { $domain = '' }
    $time = ConvertTo-TPUtcDateTime (Get-TPObjectField -Item $Metadata -Key 'AssessmentTime' -Default $null)
    $client = if ($ClientName) { $ClientName } elseif ($domain) { $domain } else { 'Your organization' }
    $sd = Get-TPObjectField -Item $CAChecklist -Key 'SecurityDefaults' -Default $null
    # The promise to keep break-glass accounts excluded is made only when an
    # approved record exists; otherwise the report says they must be found.
    $eaSource = [string](Get-TPNestedProperty -Object $CAChecklist -Path 'EmergencyAccess.Source' -Default '')

    return [ordered]@{
        Available     = $true
        Refused       = $false
        Note          = ''
        ClientName    = $client
        TenantDomain  = $domain
        PreparedBy    = $PreparedBy
        AssessedAt    = $(if ($null -ne $time) { $time.ToString('MMMM d, yyyy', [cultureinfo]::InvariantCulture) } else { [string](Get-TPObjectField -Item $Metadata -Key 'AssessmentDate' -Default 'Not recorded') })
        ToolVersion   = [string](Get-TPObjectField -Item $Metadata -Key 'ToolVersion' -Default '')
        Total         = $total
        NotApplicable = $notApplicable
        Counts        = $counts
        Topics        = $topicCounts
        Groups        = $sorted
        GroupNames    = $names
        Priorities    = @($sorted.NextSteps | Where-Object { $_.Severity -eq 'High' } | Select-Object -First 8)
        Statements    = [ordered]@{
            Purpose = "This report reviews how your Microsoft 365 sign-in protection (Conditional Access) and device management (Intune compliance, app protection, attack surface reduction, Windows LAPS and Microsoft Defender Antivirus) are configured, against $total checks drawn from Microsoft's recommended policies and the open-source Maester test suite. For each it shows whether it was in place, what to do next, and what could not be checked."
            NotThis = 'It is a point-in-time review of configuration, not a security audit, a penetration test or a determination that your organization is or is not compliant with any standard. A check in place means the setting was there when it was read; it does not mean every account or device is protected.'
            Scope   = 'Covered: Conditional Access policies and their exclusions, a simulated sign-in for a sample of accounts, Intune compliance policies for Windows, iOS, Android and macOS, app protection for iOS and Android, attack surface reduction rules, Windows LAPS and Defender Antivirus policy values. Not covered: your network equipment, unmanaged devices beyond what app protection controls, third-party security products, and the rest of the Microsoft 365 assessment, which is reported separately.'
            Changes = $(if ($eaSource -eq 'ApprovedRecord') { 'Every change listed here should be tested before it is enforced. Conditional Access changes can lock people out: we stage them in report-only mode first and keep your recorded emergency access accounts excluded.' } else { 'Every change listed here should be tested before it is enforced. Conditional Access changes can lock people out: we stage them in report-only mode first. No emergency access (break-glass) accounts are on record for this review, so they must be identified and excluded before any policy is turned on.' })
            SecurityDefaults = $(if ($sd -eq $true) { 'Security Defaults is on in this tenant. It gives a basic level of sign-in protection, and while it is on Conditional Access policies cannot be turned on: moving to the recommended policies means turning it off once they are ready.' } else { '' })
        }
    }
}
