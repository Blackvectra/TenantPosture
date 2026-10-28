#Requires -Version 7.0
#
# Get-TPHipaaClientReport.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: The client-facing HIPAA Security Rule report model: the readiness
#   view (Get-TPHipaaReadiness) regrouped into what a client can act on, in
#   plain language, for a PDF they can keep and forward.
#
#     Verified in Microsoft 365     every mapped technical check passed
#     Partly verified               the standard's own checks passed; some of
#                                   its implementation specifications are not
#     Needs attention               a mapped check fell short
#     Not verified in this review   mapped checks produced no result
#     Your documentation            nothing in Microsoft 365 can show it: a
#                                   policy, a process, a risk analysis, an
#                                   agreement or training
#
# HONESTY RULES (pinned by TP.HipaaClientReport.Tests.ps1):
#   - Nothing says compliant. A group name states a technical result; page one
#     says this is not a risk analysis and not a compliance determination, and
#     that it supports the client's HIPAA program for the parts Microsoft 365
#     controls.
#   - Every one of the 63 standards and implementation specifications lands in
#     exactly one group; the counts sum to the catalog.
#   - A partial or quick run is refused: a document a client forwards must not
#     read as the whole tenant when it is not.
#   - Addressable is never "optional"; page one says what it means.
#   - Control IDs are kept (small) so the MSP can trace every line; finding
#     detail, remediation commands, account names and the tenant id are not
#     carried.
#
# Inputs:  -Findings, -Metadata, -ClientName, -PreparedBy, -ConfigPath (tests).
# Consumes: findings only (through Get-TPHipaaReadiness) and controls.json.
# Graph scopes / cmdlets used: none. No network.

function Get-TPHipaaClientGroupNames {
    [CmdletBinding()]
    param()
    return [ordered]@{
        Verified      = 'Verified in Microsoft 365'
        Partly        = 'Partly verified'
        Attention     = 'Needs attention'
        NotVerified   = 'Not verified in this review'
        Documentation = 'Your documentation'
    }
}

function Get-TPHipaaClientReport {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [AllowNull()] [object] $Metadata,
        [AllowEmptyString()] [string] $ClientName = '',
        [AllowEmptyString()] [string] $PreparedBy = '',
        [AllowEmptyString()] [string] $ConfigPath = ''
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $scope = Get-TPRunScope -Metadata $Metadata
    if ($scope -ne 'Full') {
        $why = if ($scope -eq 'Partial') { 'a partial run (-ControlId)' } else { 'a quick scan (-Quick evaluates Critical and High controls only)' }
        return [ordered]@{ Available = $false; Refused = $true; Note = "The client HIPAA report covers the whole tenant and is not written from $why. Run a full assessment." }
    }

    $ready = if ($ConfigPath) { Get-TPHipaaReadiness -Findings $Findings -ConfigPath $ConfigPath } else { Get-TPHipaaReadiness -Findings $Findings }
    if (-not [bool](Get-TPObjectField -Item $ready -Key 'Available' -Default $false)) {
        return [ordered]@{ Available = $false; Refused = $false; Note = 'The HIPAA Security Rule catalog (Config/hipaa-security-rule.json) was not found.' }
    }
    $st = Get-TPHipaaStatusNames
    $names = Get-TPHipaaClientGroupNames
    $defs = @{}
    foreach ($c in @(Get-TPControlDefinitions)) { $defs[[string]$c.ControlId] = $c }
    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Informational = 4 }

    $groupOf = @{
        $st.Satisfied   = 'Verified'
        $st.SpecsOpen   = 'Partly'
        $st.Shortfall   = 'Attention'
        $st.NotAssessed = 'NotVerified'
        $st.Attestation = 'Documentation'
    }
    $groups = [ordered]@{}
    foreach ($k in $names.Keys) { $groups[$k] = [System.Collections.Generic.List[object]]::new() }

    foreach ($r in @($ready.Items)) {
        $g = $groupOf[[string]$r.Status]
        if (-not $g) { $g = 'NotVerified' }
        # One line per check, worst instance first, without the finding detail.
        $checks = [ordered]@{}
        foreach ($e in @($r.Evidence)) {
            $cid = [string]$e.ControlId
            $state = [string]$e.State
            if (-not $checks.Contains($cid)) {
                $def = if ($defs.ContainsKey($cid)) { $defs[$cid] } else { $null }
                $checks[$cid] = [ordered]@{
                    ControlId    = $cid
                    Title        = [string]$e.Title
                    State        = $state
                    Severity     = [string](Get-TPObjectField -Item $def -Key 'Severity' -Default '')
                    BusinessRisk = [string](Get-TPObjectField -Item $def -Key 'BusinessRisk' -Default '')
                }
            } else {
                $rank = @{ Gap = 0; Partial = 1; NotRun = 2; Error = 2; NotApplicable = 3; Satisfied = 4 }
                if (($rank[$state] ?? 2) -lt ($rank[[string]$checks[$cid].State] ?? 2)) { $checks[$cid].State = $state }
            }
        }
        $checkList = @($checks.Values)
        $item = [ordered]@{
            Citation    = [string]$r.Citation
            Name        = [string]$r.Name
            Kind        = [string]$r.Kind
            Requirement = $(if ([string]$r.Kind -eq 'Standard') { 'Standard' } else { [string]$r.Requirement })
            Safeguard   = [string]$r.Safeguard
            Group       = $g
            Passed      = @($checkList | Where-Object { $_.State -eq 'Satisfied' })
            Failed      = @($checkList | Where-Object { $_.State -in @('Gap', 'Partial') } | Sort-Object @{ Expression = { $sevRank[[string]$_.Severity] ?? 9 } }, ControlId)
            NoResult    = @($checkList | Where-Object { $_.State -notin @('Satisfied', 'Gap', 'Partial') })
            Why         = ''
        }
        switch ($g) {
            'Verified'      { $item.Why = 'Every Microsoft 365 setting we check for this requirement is in place.' }
            'Partly'        {
                $tally = $r.Specifications
                $open = if ($null -ne $tally) { [int]$tally.Total - [int]$tally[$st.Satisfied] } else { 0 }
                $item.Why = "The checks for this standard passed; $open of its implementation specification(s) are not yet verified (listed separately)."
            }
            'Attention'     { $item.Why = 'At least one Microsoft 365 setting this requirement depends on is missing or only partly in place.' }
            'NotVerified'   { $item.Why = 'The settings this requirement depends on could not be read in this review (a service was not reachable, not licensed, or not included), so nothing is claimed either way.' }
            'Documentation' {
                $reason = [string]$r.TenantEvidenceReason
                $item.Why = if ($reason) { $reason } else { 'Your written policy, procedure or record.' }
            }
        }
        $groups[$g].Add($item)
    }

    # By safeguard, then in the rule's own order (the catalog's), never by the
    # citation text, which sorts (b)(3) before (a)(7).
    $sortGroup = { param($list) @($list | Sort-Object -Stable @{ Expression = { switch ($_.Safeguard) { 'Administrative' { 0 } 'Physical' { 1 } 'Technical' { 2 } default { 3 } } } }) }
    $counts = [ordered]@{}
    foreach ($k in $groups.Keys) { $counts[$k] = $groups[$k].Count }
    $bySafeguard = [System.Collections.Generic.List[object]]::new()
    foreach ($sg in @($ready.Items | ForEach-Object { [string]$_.Safeguard } | Select-Object -Unique)) {
        $row = [ordered]@{ Safeguard = $sg; Total = 0 }
        foreach ($k in $groups.Keys) { $row[$k] = @($groups[$k] | Where-Object { $_.Safeguard -eq $sg }).Count; $row.Total += $row[$k] }
        $bySafeguard.Add($row)
    }
    $attention = @($groups.Attention | ForEach-Object { $_.Failed } | Where-Object { $null -ne $_ })
    $priorities = @($attention | Group-Object ControlId | ForEach-Object { $_.Group[0] } |
        Sort-Object @{ Expression = { $sevRank[[string]$_.Severity] ?? 9 } }, ControlId | Select-Object -First 8)

    $domain = ([string](Get-TPObjectField -Item $Metadata -Key 'TenantDomain' -Default '')).ToLowerInvariant()
    if ($domain -and -not (Test-TPDomainName -Value $domain)) { $domain = '' }
    $time = ConvertTo-TPUtcDateTime (Get-TPObjectField -Item $Metadata -Key 'AssessmentTime' -Default $null)
    $client = if ($ClientName) { $ClientName } elseif ($domain) { $domain } else { 'Your organization' }

    return [ordered]@{
        Available    = $true
        Refused      = $false
        Note         = ''
        ClientName   = $client
        TenantDomain = $domain
        PreparedBy   = $PreparedBy
        AssessedAt   = $(if ($null -ne $time) { $time.ToString('MMMM d, yyyy', [cultureinfo]::InvariantCulture) } else { [string](Get-TPObjectField -Item $Metadata -Key 'AssessmentDate' -Default 'Not recorded') })
        ToolVersion  = [string](Get-TPObjectField -Item $Metadata -Key 'ToolVersion' -Default '')
        Rule         = [string]$ready.Framework
        RuleSource   = [string]$ready.Source
        RuleSnapshot = [string]$ready.SourceSnapshot
        Total        = @($ready.Items).Count
        Counts       = $counts
        BySafeguard  = $bySafeguard.ToArray()
        Groups       = [ordered]@{
            Verified      = @(& $sortGroup $groups.Verified)
            Partly        = @(& $sortGroup $groups.Partly)
            Attention     = @(& $sortGroup $groups.Attention)
            NotVerified   = @(& $sortGroup $groups.NotVerified)
            Documentation = @(& $sortGroup $groups.Documentation)
        }
        GroupNames   = $names
        Priorities   = $priorities
        Statements   = [ordered]@{
            Purpose     = "This report reviews how your Microsoft 365 environment is configured against the HIPAA Security Rule (45 CFR Part 164, Subpart C). For each of the rule's $(@($ready.Items).Count) standards and implementation specifications it shows whether the Microsoft 365 settings that support it were verified, need attention, could not be checked, or depend on your own documentation."
            NotThis     = 'It is not a HIPAA risk analysis (45 CFR 164.308(a)(1)(ii)(A)) and not a determination that your organization is or is not compliant. HIPAA compliance is an ongoing program of risk analysis, safeguards, policies, procedures and documentation. This review supports that program for the parts Microsoft 365 controls.'
            Scope       = 'Covered: Microsoft 365 tenant configuration (identity and sign-in, email, file sharing, devices managed through Intune, data protection and audit settings) as read on the date shown. Not covered: your network equipment, physical facilities, unmanaged devices, third-party applications, and your written policies and procedures.'
            Addressable = 'Required means the specification must be implemented. Addressable does not mean optional: you implement it if it is reasonable and appropriate, and otherwise document why not and what equivalent measure you use (45 CFR 164.306(d)(3)).'
            Verified    = 'Verified means every Microsoft 365 setting we check for that requirement was in place when we looked. A setting can change after the date shown, and a requirement can have parts beyond what a configuration check can see.'
        }
    }
}
