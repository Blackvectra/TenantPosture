#Requires -Version 7.0
#
# Get-TPOnboardingModel.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: The new-client onboarding report ("where you stand" plus a
#   30/60/90-day plan), built from one FULL run's findings and data the tool
#   already holds: controls.json (Title, BusinessRisk, Severity,
#   LicenseRequirement), Config/operational-impact.json (archetype and effort
#   class) and the license gate. A VIEW: it creates no finding and moves no
#   score.
#
# Rules (each pinned by TP.OnboardingReport.Tests.ps1):
#   - A first-look report covers the whole tenant: a partial (-ControlId) or
#     quick (-Quick) run is refused.
#   - Score and maturity are the values the run recorded (Metadata.Maturity).
#   - Plan buckets, per open (Gap or Partial) control at its worst finding:
#       Needs a license decision  the improvement plan's 'Buy first' track
#                                 (not confirmed licensed), plus every
#                                 control license gating already took out
#                                 of the score; each names the license that
#                                 would unlock it
#       Plan after review         no operational-impact entry: never Days
#                                 1-30, since an undocumented impact is not
#                                 evidence of no impact
#       Days 1-30                 Critical/High on the improvement plan's 'Do
#                                 now' track (a documented low-friction
#                                 archetype: Get-TPLowFrictionArchetypes)
#       Days 31-60                remaining Critical/High, and any control
#                                 whose effort is a policy change or a staged
#                                 rollout
#       Days 61-90                the rest (projects, discovery first, Medium
#                                 and Low)
#     A bucket says when work starts, never how long it takes: effort is the
#     archetype's class, never an hour or day figure.
#   - "Coming Microsoft changes" is read from Config/microsoft-changes.json
#     when that file exists, keeping only entries dated today or later; the
#     date is shown as the file gives it, never inferred. Without the file
#     the section is absent.
#
# Data consumed: findings (shape-agnostic), Metadata (Maturity, TenantDomain,
#   AssessmentTime, ToolVersion, ControlSelection, QuickScan), the license
#   profile. Data set: none. Graph scopes / cmdlets used: none.

# Coming Microsoft changes from the catalog file, dated today or later, by
# date. Returns $null when the file is absent or unreadable.
function Get-TPMicrosoftChanges {
    [CmdletBinding()]
    param(
        [AllowEmptyString()] [string] $Path = '',
        [datetime] $Now = [datetime]::UtcNow,
        [AllowNull()] [System.Collections.IDictionary] $Worst
    )
    if (-not $Path) {
        $root = if ((Get-Variable -Name TPModuleRoot -Scope Script -ErrorAction SilentlyContinue) -and $script:TPModuleRoot) { $script:TPModuleRoot } else { Split-Path -Parent $PSScriptRoot }
        $Path = Join-Path $root 'Config' 'microsoft-changes.json'
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { $raw = Get-Content -LiteralPath $Path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 16 -ErrorAction Stop } catch {
        Write-Verbose "microsoft-changes.json not read: $($_.Exception.Message)"
        return $null
    }
    $today = $Now.ToUniversalTime().Date
    $out = [System.Collections.Generic.List[object]]::new()
    $undated = 0
    foreach ($c in @(Get-TPObjectField -Item $raw -Key 'changes' -Default @())) {
        if ($null -eq $c) { continue }
        $dateText = ([string](Get-TPObjectField -Item $c -Key 'Date' -Default '')).Trim()
        # The last day the stated date covers: a day, or the end of a month.
        $until = $null; $parsed = [datetime]::MinValue
        if ($dateText -cmatch '\A\d{4}-\d{2}-\d{2}\z' -and [datetime]::TryParseExact($dateText, 'yyyy-MM-dd', [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) { $until = $parsed }
        elseif ($dateText -cmatch '\A\d{4}-\d{2}\z' -and [datetime]::TryParseExact($dateText, 'yyyy-MM', [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$parsed)) { $until = $parsed.AddMonths(1).AddDays(-1) }
        if ($null -eq $until) { $undated++; continue }
        if ($until -lt $today) { continue }
        $related = [System.Collections.Generic.List[object]]::new()
        foreach ($rid in @(Get-TPObjectField -Item $c -Key 'RelatedControls' -Default @())) {
            $id = [string]$rid
            if ($id -cnotmatch '\A[A-Z]{2,8}-\d+\.\d+\z') { continue }
            $state = if ($null -ne $Worst -and $Worst.Contains($id)) { [string](Get-TPObjectField -Item $Worst[$id] -Key 'State' -Default '') } else { '' }
            $related.Add([ordered]@{ ControlId = $id; State = $(if ($state) { $state } else { 'Not assessed in this run' }) })
        }
        $out.Add([ordered]@{
            Id            = [string](Get-TPObjectField -Item $c -Key 'Id' -Default '')
            Title         = [string](Get-TPObjectField -Item $c -Key 'Title' -Default '')
            Date          = $dateText
            DateQualifier = [string](Get-TPObjectField -Item $c -Key 'DateQualifier' -Default '')
            SortDate      = $until
            Summary       = [string](Get-TPObjectField -Item $c -Key 'Summary' -Default '')
            Impact        = [string](Get-TPObjectField -Item $c -Key 'Impact' -Default '')
            Related       = $related.ToArray()
            SourceUrl     = [string](Get-TPObjectField -Item $c -Key 'SourceUrl' -Default '')
            SourceTitle   = [string](Get-TPObjectField -Item $c -Key 'SourceTitle' -Default '')
        })
    }
    return [ordered]@{
        Version         = [string](Get-TPObjectField -Item $raw -Key 'version' -Default '')
        SourceRetrieved = [string](Get-TPObjectField -Item $raw -Key 'sourceRetrieved' -Default '')
        Changes         = @($out | Sort-Object { $_.SortDate }, { $_.Id })
        Undated         = $undated
    }
}

function Get-TPOnboardingModel {
    <#
    .SYNOPSIS
        Builds the onboarding report model from a full run's findings.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)] [object] $Metadata,
        [AllowNull()] [object] $LicenseProfile,
        [AllowEmptyString()] [string] $ChangesPath = '',
        [AllowEmptyString()] [string] $ImpactPath = '',
        [datetime] $Now = [datetime]::UtcNow
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $scope = Get-TPRunScope -Metadata $Metadata
    if ($scope -ne 'Full') {
        $why = if ($scope -eq 'Partial') { "a partial run ($(Format-TPControlSelectionNotice -Selection (Get-TPObjectField -Item $Metadata -Key 'ControlSelection' -Default $null)))" } else { 'a quick scan (-Quick evaluates Critical and High controls only)' }
        return [ordered]@{ Available = $false; Refused = $true; Note = "The onboarding report covers the whole tenant and is not written from $why Run a full assessment." }
    }

    if (-not $PSBoundParameters.ContainsKey('LicenseProfile')) {
        $LicenseProfile = try { Get-TPTenantLicenseProfile } catch { $null }
    }
    $licenseRead = [bool](Get-TPObjectField -Item $LicenseProfile -Key 'HasLicenseData' -Default $false)
    $impactCatalog = if ($ImpactPath) { Get-TPOperationalImpactCatalog -ConfigPath $ImpactPath } else { Get-TPOperationalImpactCatalog }
    $defs = @{}
    foreach ($c in @(Get-TPControlDefinitions)) { $defs[[string]$c.ControlId] = $c }
    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Informational = 4 }
    $marker = if ((Get-Variable -Name TPUpgradeMarker -Scope Script -ErrorAction SilentlyContinue) -and $script:TPUpgradeMarker) { [string]$script:TPUpgradeMarker } else { 'licensing upgrade opportunity' }

    $worst = Get-TPControlWorstFindings -Findings @($Findings | Where-Object { $null -ne $_ })
    $item = {
        param($cid, $f)
        $def = if ($defs.ContainsKey($cid)) { $defs[$cid] } else { $null }
        $title = [string](Get-TPObjectField -Item $def -Key 'Title' -Default ([string](Get-TPObjectField -Item $f -Key 'Title' -Default $cid)))
        return [ordered]@{
            ControlId    = $cid
            Title        = $title
            Severity     = [string](Get-TPObjectField -Item $def -Key 'Severity' -Default ([string](Get-TPObjectField -Item $f -Key 'Severity' -Default '')))
            State        = [string](Get-TPObjectField -Item $f -Key 'State' -Default '')
            Workload     = [string](Get-TPObjectField -Item $def -Key 'Workload' -Default '')
            BusinessRisk = [string](Get-TPObjectField -Item $def -Key 'BusinessRisk' -Default '')
            License      = [string](Get-TPObjectField -Item $def -Key 'LicenseRequirement' -Default '')
            CurrentValue = [string](Get-TPObjectField -Item $f -Key 'CurrentValue' -Default '')
            Remediation  = [string](Get-TPFindingRemediation -Finding $f -Control $def)
        }
    }

    $counts = [ordered]@{ Satisfied = 0; Partial = 0; Gap = 0; NotApplicable = 0; Error = 0 }
    $open = [System.Collections.Generic.List[object]]::new()
    $working = [System.Collections.Generic.List[object]]::new()
    $licenseList = [System.Collections.Generic.List[object]]::new()
    foreach ($cid in $worst.Keys) {
        $f = $worst[$cid]
        $state = [string](Get-TPObjectField -Item $f -Key 'State' -Default '')
        if ($counts.Contains($state)) { $counts[$state]++ }
        if ($state -eq 'Satisfied') { $working.Add((& $item $cid $f)); continue }
        if ($state -eq 'NotApplicable' -and ([string](Get-TPObjectField -Item $f -Key 'Detail' -Default '')).Contains($marker)) {
            $it = & $item $cid $f
            $it['Reason'] = 'License gating took it out of the score: the tenant does not hold the license it needs.'
            $licenseList.Add($it); continue
        }
        if ($state -in @('Gap', 'Partial')) { $open.Add((& $item $cid $f)) }
    }

    $buckets = [ordered]@{ Days1to30 = [System.Collections.Generic.List[object]]::new(); Days31to60 = [System.Collections.Generic.List[object]]::new(); Days61to90 = [System.Collections.Generic.List[object]]::new(); PlanAfterReview = [System.Collections.Generic.List[object]]::new() }
    $midEffort = @('Policy change', 'Policy change, then tuning', 'Staged rollout')
    foreach ($it in $open) {
        $f = $worst[$it.ControlId]
        $def = if ($defs.ContainsKey($it.ControlId)) { $defs[$it.ControlId] } else { $null }
        $impact = Get-TPControlOperationalImpact -ControlId $it.ControlId -Catalog $impactCatalog
        $licensed = Test-TPFindingLicensed -Finding $f -Definition $def -LicenseProfile $LicenseProfile
        $track = Get-TPRemediationTrack -Licensed $licensed -Impact $impact
        $it['Archetype'] = [string](Get-TPObjectField -Item $impact -Key 'Archetype' -Default '')
        $it['Effort'] = if ($null -ne $impact) { [string](Get-TPObjectField -Item $impact -Key 'Effort' -Default '') } else { 'Not documented' }
        $it['ImpactSummary'] = if ($null -ne $impact) { [string](Get-TPObjectField -Item $impact -Key 'Summary' -Default '') } else { 'Operational impact not documented.' }
        $highish = $it.Severity -in @('Critical', 'High')
        if ($track -eq 'Buy first') {
            $it['Reason'] = if ($licenseRead) { 'Not licensed: the tenant''s subscriptions do not include what this control needs.' } else { 'Licensing was not read in this run, so whether the tenant holds what this control needs is not confirmed.' }
            $licenseList.Add($it)
        } elseif ($null -eq $impact) {
            $buckets.PlanAfterReview.Add($it)
        } elseif ($track -eq 'Do now' -and $highish) {
            $buckets.Days1to30.Add($it)
        } elseif ($highish -or $it.Effort -in $midEffort) {
            if ($it.Effort -in @('Project', 'Discovery first')) { $it['Note'] = 'Starts in this window; a project or a discovery pass can run past it.' }
            $buckets.Days31to60.Add($it)
        } else {
            $buckets.Days61to90.Add($it)
        }
    }

    $bySev = { param($list) @($list | Sort-Object @{ Expression = { $sevRank[[string]$_.Severity] ?? 9 } }, @{ Expression = { if ($_.State -eq 'Gap') { 0 } else { 1 } } }, @{ Expression = { $_.ControlId } }) }
    $plan = [ordered]@{}
    foreach ($k in $buckets.Keys) { $plan[$k] = & $bySev $buckets[$k] }
    $risks = @(& $bySev @($open | Where-Object { $_.Severity -in @('Critical', 'High') }) | Select-Object -First 5)
    $workingSorted = & $bySev $working

    $openBySev = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0 }
    foreach ($it in $open) { if ($openBySev.Contains($it.Severity)) { $openBySev[$it.Severity]++ } }
    $workBy = [ordered]@{}
    foreach ($it in $working) { $wl = if ($it.Workload) { $it.Workload } else { 'Other' }; $workBy[$wl] = 1 + ($workBy[$wl] ?? 0) }

    $mat = Get-TPObjectField -Item $Metadata -Key 'Maturity' -Default $null
    $domain = ([string](Get-TPObjectField -Item $Metadata -Key 'TenantDomain' -Default '')).ToLowerInvariant()
    if (-not (Test-TPDomainName -Value $domain)) { $domain = '' }
    $time = ConvertTo-TPUtcDateTime (Get-TPObjectField -Item $Metadata -Key 'AssessmentTime' -Default $null)

    return [ordered]@{
        Available       = $true
        Refused         = $false
        Note            = ''
        TenantDomain    = $domain
        AssessedAt      = $(if ($null -ne $time) { $time.ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture) + ' UTC' } else { [string](Get-TPObjectField -Item $Metadata -Key 'AssessmentDate' -Default 'Not recorded') })
        ToolVersion     = [string](Get-TPObjectField -Item $Metadata -Key 'ToolVersion' -Default '')
        Score           = Get-TPObjectField -Item $mat -Key 'Score' -Default $null
        MaturityLabel   = [string](Get-TPObjectField -Item $mat -Key 'Label' -Default '')
        MaturityRecorded = ($null -ne $mat)
        Qualification   = [string](Get-TPObjectField -Item $mat -Key 'Qualification' -Default '')
        LicenseTier     = $(if ($licenseRead) { [string](Get-TPObjectField -Item $LicenseProfile -Key 'TierLabel' -Default '') } else { 'Not read in this run' })
        LicenseRead     = $licenseRead
        Counts          = $counts
        Controls        = $worst.Count
        OpenBySeverity  = $openBySev
        TopRisks        = $risks
        Working         = $workingSorted
        WorkingByWorkload = $workBy
        Plan            = $plan
        LicenseDecision = @(& $bySev $licenseList)
        Changes         = (Get-TPMicrosoftChanges -Path $ChangesPath -Now $Now -Worst $worst)
        Statement       = 'This report describes what TenantPosture observed in this tenant at the time shown. It is a starting position and a plan, not a statement that the tenant meets any framework. Controls the run could not assess are counted separately and are neither open nor passed.'
        PlanNote        = 'A window says when the work should start, not how long it takes. Effort is a class (Single setting, Policy change, Staged rollout, Discovery first, Project, ...), never a time estimate. Days 1-30 holds only Critical and High items whose change is documented as invisible to users; anything without a documented operational impact waits for review.'
    }
}
