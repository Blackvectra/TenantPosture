#Requires -Version 7.0
#
# Get-NRGBaseline.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: NRG Security Baseline — a desired-state VIEW over the assessment.
#   Config/nrg-baseline.json says which controls NRG requires of a managed
#   client and at which tier; this file resolves, for one tenant, whether each
#   required control is observed to meet it. Like Get-NRGAssessmentScope it
#   emits no findings, changes none, and moves no framework score.
#
# Data consumed: findings (Get-NRGFindings), raw data (CollectedAt, Success),
#   coverage, the tenant license profile, Config/nrg-baseline.json, and
#   Config/baseline-exceptions/<tenant-domain>.psd1.
# Data set: none (module state is read only).
#
# Four separate answers per control, never one overloaded enum:
#   ObservedState      Satisfied / Failed / NotApplicable / NotVerified
#   Constraint         None / LicenseBlocked
#   Disposition        Normal / ApprovedException
#   EffectivenessState Effective / Ineffective / Unknown
# plus DependencyState and EvidenceFreshness (Current / Stale / None).
#
# Invariants (each pinned by NRG.Baseline.Tests.ps1):
#   - a control with no finding is NotVerified, never Satisfied;
#   - a finding whose collector did not succeed this run is NotVerified, so a
#     replayed Satisfied cannot outlive the data it came from;
#   - evidence older than its freshness window is NotVerified;
#   - license-blocked is a constraint, not a failure;
#   - an approved exception keeps the observed state and only changes the
#     disposition; an exception without a review date, or past it, is not
#     approved;
#   - effectiveness is Unknown whenever the assessment cannot read it;
#   - a dependency's state is reported beside the control and never changes
#     the control's own observed state.
#
# Graph scopes / cmdlets required: none.

# ── Definition ────────────────────────────────────────────────────────────────

function Get-NRGBaselineDefinition {
    <#
    .SYNOPSIS
        Loads and validates Config/nrg-baseline.json (cached per module load).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $Path,
        [switch] $Force
    )
    Set-StrictMode -Version Latest

    if (-not $Path -and -not $Force -and (Get-Variable -Name NRGBaselineDefinition -Scope Script -ErrorAction SilentlyContinue) -and $script:NRGBaselineDefinition) {
        return $script:NRGBaselineDefinition
    }
    $moduleRoot = if ((Get-Variable -Name NRGModuleRoot -Scope Script -ErrorAction SilentlyContinue) -and $script:NRGModuleRoot) { $script:NRGModuleRoot }
                  elseif ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot }
                  else { (Get-Location).Path }
    $resolved = if ($Path) { $Path } else { Join-Path $moduleRoot 'Config' 'nrg-baseline.json' }
    if (-not (Test-Path -LiteralPath $resolved)) { throw "NRG baseline definition not found: $resolved" }
    $raw = Get-Content -LiteralPath $resolved -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20

    $version   = [string](Get-NRGObjectField -Item $raw -Key 'version' -Default '')
    $tierOrder = @(Get-NRGObjectField -Item $raw -Key 'tierOrder' -Default @('Minimum', 'Standard', 'Hardened'))
    if (-not $version) { throw "nrg-baseline.json has no version." }
    if ($tierOrder.Count -eq 0) { throw "nrg-baseline.json has no tierOrder." }

    $windows = [ordered]@{}
    $fw = Get-NRGObjectField -Item $raw -Key 'freshnessWindowsDays' -Default $null
    if ($null -ne $fw) { foreach ($p in $fw.PSObject.Properties) { $windows[[string]$p.Name] = [int]$p.Value } }
    foreach ($cls in @('Daily', 'Weekly', 'Monthly', 'PointInTime')) {
        if (-not $windows.Contains($cls)) { throw "nrg-baseline.json freshnessWindowsDays lacks '$cls'." }
    }

    $controls = [ordered]@{}
    foreach ($c in @(Get-NRGObjectField -Item $raw -Key 'controls' -Default @())) {
        $cid  = [string](Get-NRGObjectField -Item $c -Key 'ControlId' -Default '')
        $tier = [string](Get-NRGObjectField -Item $c -Key 'Tier' -Default '')
        if (-not $cid) { throw "nrg-baseline.json: a control has no ControlId." }
        if ($controls.Contains($cid)) { throw "nrg-baseline.json: $cid is listed twice." }
        if ($tier -notin $tierOrder) { throw "nrg-baseline.json: $cid has tier '$tier', not one of $($tierOrder -join ', ')." }
        $fresh = [string](Get-NRGObjectField -Item $c -Key 'FreshnessClass' -Default '')
        if (-not $windows.Contains($fresh)) { throw "nrg-baseline.json: $cid has freshness class '$fresh' with no window." }
        $controls[$cid] = [ordered]@{
            ControlId               = $cid
            Title                   = [string](Get-NRGObjectField -Item $c -Key 'Title' -Default '')
            Tier                    = $tier
            Owner                   = [string](Get-NRGObjectField -Item $c -Key 'Owner' -Default '')
            RawDataKeys             = @(Get-NRGObjectField -Item $c -Key 'RawDataKeys' -Default @() | Where-Object { $_ })
            EvidenceSource          = [string](Get-NRGObjectField -Item $c -Key 'EvidenceSource' -Default '')
            ExpectedState           = [string](Get-NRGObjectField -Item $c -Key 'ExpectedState' -Default '')
            SlaClass                = [string](Get-NRGObjectField -Item $c -Key 'SlaClass' -Default '')
            DependsOn               = @(Get-NRGObjectField -Item $c -Key 'DependsOn' -Default @() | Where-Object { $_ })
            FreshnessClass          = $fresh
            EffectivenessCheck      = [string](Get-NRGObjectField -Item $c -Key 'EffectivenessCheck' -Default '')
            EffectivenessCapability = [string](Get-NRGObjectField -Item $c -Key 'EffectivenessCapability' -Default 'NotCollected')
            EffectivenessEvidence   = (Get-NRGObjectField -Item $c -Key 'EffectivenessEvidence' -Default $null)
            Automated               = [bool](Get-NRGObjectField -Item $c -Key 'Automated' -Default $true)
            Reason                  = [string](Get-NRGObjectField -Item $c -Key 'Reason' -Default '')
        }
    }

    $def = [ordered]@{
        Version              = $version
        TierOrder            = @($tierOrder)
        FreshnessWindowsDays = $windows
        Controls             = $controls
        Path                 = $resolved
    }
    if (-not $Path) { $script:NRGBaselineDefinition = $def }
    return $def
}

function Get-NRGBaselineRequiredControls {
    <#
    .SYNOPSIS
        The controls a tenant at -TargetTier must satisfy: its tier and every
        tier below it (Minimum ⊂ Standard ⊂ Hardened). Assessment-only
        controls are not in the definition and so are never required.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $TargetTier,
        [AllowNull()] [object] $Definition
    )
    Set-StrictMode -Version Latest
    $def = if ($null -ne $Definition) { $Definition } else { Get-NRGBaselineDefinition }
    $order = @($def.TierOrder)
    $idx = [array]::IndexOf($order, $TargetTier)
    if ($idx -lt 0) { throw "Unknown baseline tier '$TargetTier'. Expected one of: $($order -join ', ')." }
    $allowed = @($order[0..$idx])
    return @($def.Controls.Values | Where-Object { $_.Tier -in $allowed })
}

# ── Exceptions ────────────────────────────────────────────────────────────────

function ConvertTo-NRGBaselineClientSlug {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyString()] [string] $TenantDomain)
    if ([string]::IsNullOrWhiteSpace($TenantDomain)) { return '' }
    $slug = ($TenantDomain.Trim().ToLowerInvariant() -replace '[^a-z0-9.-]', '')
    if ($slug -eq 'example') { return '' }
    return $slug
}

function Get-NRGBaselineExceptions {
    <#
    .SYNOPSIS
        Reads Config/baseline-exceptions/<tenant-domain>.psd1 and returns every
        entry with a verdict: Approved, or the reason it is not.
    .DESCRIPTION
        Data only (Import-PowerShellDataFile). An entry is Approved when it
        carries ControlId, Reason, CompensatingControl, Approver, ApprovedDate
        and a parseable ReviewDate that is on or after -AsOf, and any ExpiryDate
        is after -AsOf. Anything else is returned with Approved = $false and a
        stated reason, so a lapsed exception is visible rather than silently
        dropped.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $Path,
        [AllowNull()] [AllowEmptyString()] [string] $TenantDomain,
        [datetime] $AsOf = (Get-Date)
    )
    Set-StrictMode -Version Latest

    $empty = [ordered]@{ Available = $false; Path = ''; Entries = @(); Approved = @{}; Rejected = @() }
    $moduleRoot = if ((Get-Variable -Name NRGModuleRoot -Scope Script -ErrorAction SilentlyContinue) -and $script:NRGModuleRoot) { $script:NRGModuleRoot }
                  elseif ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot }
                  else { (Get-Location).Path }
    $resolved = ''
    if ($Path) {
        if ($Path -match '\.\.[\\/]') { throw 'Path traversal not allowed in -Path.' }
        $resolved = $Path
    } elseif ($TenantDomain) {
        $slug = ConvertTo-NRGBaselineClientSlug -TenantDomain $TenantDomain
        if (-not $slug) { return $empty }
        $resolved = Join-Path $moduleRoot 'Config' 'baseline-exceptions' "$slug.psd1"
    } else {
        return $empty
    }
    if (-not (Test-Path -LiteralPath $resolved)) {
        Write-Verbose "Baseline exceptions file not found at $resolved."
        return $empty
    }
    try {
        $data = Import-PowerShellDataFile -LiteralPath $resolved -ErrorAction Stop
    } catch {
        Write-Warning "Baseline exceptions file could not be parsed and is ignored: $($_.Exception.Message)"
        return $empty
    }

    $entries  = [System.Collections.Generic.List[object]]::new()
    $approved = @{}
    $rejected = [System.Collections.Generic.List[object]]::new()
    $parse = {
        param([object] $v)
        $out = [datetime]::MinValue
        if ($null -eq $v) { return $null }
        if ($v -is [datetime]) { return $v }
        if ([datetime]::TryParse([string]$v, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeLocal, [ref]$out)) { return $out }
        return $null
    }
    foreach ($e in @(Get-NRGObjectField -Item $data -Key 'Exceptions' -Default @())) {
        if ($null -eq $e) { continue }
        $cid = [string](Get-NRGObjectField -Item $e -Key 'ControlId' -Default '')
        $row = [ordered]@{
            ControlId           = $cid
            Reason              = [string](Get-NRGObjectField -Item $e -Key 'Reason' -Default '')
            CompensatingControl = [string](Get-NRGObjectField -Item $e -Key 'CompensatingControl' -Default '')
            Approver            = [string](Get-NRGObjectField -Item $e -Key 'Approver' -Default '')
            ApprovedDate        = [string](Get-NRGObjectField -Item $e -Key 'ApprovedDate' -Default '')
            ReviewDate          = [string](Get-NRGObjectField -Item $e -Key 'ReviewDate' -Default '')
            ExpiryDate          = [string](Get-NRGObjectField -Item $e -Key 'ExpiryDate' -Default '')
            Approved            = $false
            Verdict             = ''
        }
        $missing = @(foreach ($k in @('ControlId', 'Reason', 'CompensatingControl', 'Approver', 'ApprovedDate', 'ReviewDate')) { if ([string]::IsNullOrWhiteSpace([string]$row[$k])) { $k } })
        $review  = & $parse (Get-NRGObjectField -Item $e -Key 'ReviewDate' -Default $null)
        $expiry  = & $parse (Get-NRGObjectField -Item $e -Key 'ExpiryDate' -Default $null)
        if ($missing.Count -gt 0) {
            $row.Verdict = "Not approved: missing $($missing -join ', ')."
        } elseif ($null -eq $review) {
            $row.Verdict = "Not approved: ReviewDate '$($row.ReviewDate)' is not a date."
        } elseif ($review.Date -lt $AsOf.Date) {
            $row.Verdict = "Not approved: review date $($review.ToString('yyyy-MM-dd')) has passed; the exception must be re-approved."
        } elseif ($row.ExpiryDate -and $null -eq $expiry) {
            $row.Verdict = "Not approved: ExpiryDate '$($row.ExpiryDate)' is not a date."
        } elseif ($null -ne $expiry -and $expiry.Date -lt $AsOf.Date) {
            $row.Verdict = "Not approved: expired $($expiry.ToString('yyyy-MM-dd'))."
        } else {
            $row.Approved = $true
            $row.Verdict  = "Approved by $($row.Approver) on $($row.ApprovedDate); review by $($review.ToString('yyyy-MM-dd'))."
        }
        $entries.Add([pscustomobject]$row)
        if ($row.Approved -and $cid) { $approved[$cid] = [pscustomobject]$row }
        elseif ($cid) { $rejected.Add([pscustomobject]$row) }
    }
    return [ordered]@{ Available = $true; Path = $resolved; Entries = @($entries); Approved = $approved; Rejected = @($rejected) }
}

# ── Compliance view ───────────────────────────────────────────────────────────

function Get-NRGBaselineCompliance {
    <#
    .SYNOPSIS
        Resolves the NRG Security Baseline for one tenant: per required
        control, what was observed, what constrains it, whether an approved
        exception covers it, and whether it is known to be effective.
    .DESCRIPTION
        A view. Reads findings and module state; writes nothing. Every value
        is derived from evidence positively present: a missing finding, a
        collector that did not succeed, a skipped workload, an advisory
        control, or evidence older than its freshness window all resolve to
        NotVerified. Nothing here can turn an unknown into a pass.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [object[]] $Findings,
        [ValidateSet('Minimum', 'Standard', 'Hardened')] [string] $TargetTier = 'Standard',
        [AllowNull()] [object] $Definition,
        [AllowNull()] [object] $Exceptions,
        [AllowNull()] [AllowEmptyString()] [string] $TenantDomain,
        [AllowNull()] [object] $RawData,
        [AllowNull()] [hashtable] $Coverage,
        [AllowNull()] [object] $LicenseProfile,
        [datetime] $AsOf = (Get-Date),
        [switch] $QuickScan
    )
    Set-StrictMode -Version Latest

    $def = if ($null -ne $Definition) { $Definition } else { Get-NRGBaselineDefinition }
    $required = @(Get-NRGBaselineRequiredControls -TargetTier $TargetTier -Definition $def)
    $exc = if ($null -ne $Exceptions) { $Exceptions } else { Get-NRGBaselineExceptions -TenantDomain $TenantDomain -AsOf $AsOf }
    $approvedExc = if ($exc -and $exc.Approved) { $exc.Approved } else { @{} }

    $raw = if ($PSBoundParameters.ContainsKey('RawData')) { $RawData } elseif (Get-Command Get-NRGRawData -ErrorAction SilentlyContinue) { Get-NRGRawData } else { $null }
    $cov = if ($PSBoundParameters.ContainsKey('Coverage')) { $Coverage } elseif (Get-Command Get-NRGCoverage -ErrorAction SilentlyContinue) { Get-NRGCoverage } else { @{} }
    if ($null -eq $cov) { $cov = @{} }
    $rawPopulated = ($null -ne $raw) -and (@($raw.Keys).Count -gt 0)

    # The scope classifier already knows why a control has no verdict; reuse
    # its buckets rather than re-deriving them.
    $scope = $null
    try {
        $scope = Get-NRGAssessmentScope -Findings $Findings -Coverage $cov -LicenseProfile $LicenseProfile -RawData $raw -QuickScan:$QuickScan
    } catch { Write-Verbose "Scope classification unavailable for the baseline view: $($_.Exception.Message)" }
    $bucketOf = @{}
    if ($scope -and $scope.Available) {
        foreach ($b in @('LicenceBlocked', 'CollectionIncomplete', 'NoProgrammaticCheck', 'ThirdPartyAttested', 'NotApplicableToTenant', 'NotEvaluatedThisMode', 'SkippedByOperator', 'NoResult', 'Errors')) {
            foreach ($row in @(Get-NRGObjectField -Item $scope -Key $b -Default @())) {
                $rid = [string](Get-NRGObjectField -Item $row -Key 'ControlId' -Default '')
                if ($rid -and -not $bucketOf.ContainsKey($rid)) { $bucketOf[$rid] = @{ Bucket = $b; Reason = [string](Get-NRGObjectField -Item $row -Key 'Reason' -Default '') } }
            }
        }
    }

    $rank = Get-NRGStateSeverityRank
    $byControl = @{}
    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $cid = [string](Get-NRGObjectField -Item $f -Key 'ControlId' -Default '')
        if (-not $cid) { continue }
        if (-not $byControl.ContainsKey($cid)) { $byControl[$cid] = [System.Collections.Generic.List[object]]::new() }
        $byControl[$cid].Add($f)
    }
    $worst = {
        param([object[]] $list)
        $best = $null; $bestRank = -1
        foreach ($f in $list) {
            $st = [string](Get-NRGObjectField -Item $f -Key 'State' -Default '')
            $r  = if ($rank.ContainsKey($st)) { $rank[$st] } else { 0 }
            if ($r -gt $bestRank) { $best = $f; $bestRank = $r }
        }
        return $best
    }
    $parseTs = {
        param([object] $v)
        $out = [datetime]::MinValue
        if ($null -eq $v) { return $null }
        if ($v -is [datetime]) { return $v }
        if ([datetime]::TryParse([string]$v, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$out)) { return $out }
        return $null
    }
    $upgradeMarker = if ((Get-Variable -Name NRGUpgradeMarker -Scope Script -ErrorAction SilentlyContinue) -and $script:NRGUpgradeMarker) { $script:NRGUpgradeMarker } else { 'licensing upgrade opportunity' }

    $rows = [System.Collections.Generic.List[object]]::new()
    $observedById = @{}
    foreach ($ctrl in $required) {
        $cid = $ctrl.ControlId
        $r = [ordered]@{
            ControlId               = $cid
            Title                   = $ctrl.Title
            RequiredTier            = $ctrl.Tier
            Owner                   = $ctrl.Owner
            ExpectedState           = $ctrl.ExpectedState
            SlaClass                = $ctrl.SlaClass
            ObservedState           = 'NotVerified'
            ObservedFindingState    = ''
            Constraint              = 'None'
            Disposition             = 'Normal'
            EffectivenessState      = 'Unknown'
            EffectivenessCapability = $ctrl.EffectivenessCapability
            EffectivenessDetail     = ''
            DependsOn               = @($ctrl.DependsOn)
            DependencyState         = 'None'
            EvidenceSource          = $ctrl.EvidenceSource
            EvidenceTimestamp       = ''
            EvidenceFreshness       = 'None'
            FreshnessClass          = $ctrl.FreshnessClass
            # Why a NotVerified row is NotVerified, as one of a small fixed set,
            # so 27 unknowns read as an engineering list rather than a number.
            NotVerifiedCause        = ''
            Reason                  = ''
            ExceptionSummary        = ''
            BaselineStatus          = ''
        }

        if (-not $ctrl.Automated) {
            $r.Reason = 'Not assessed by the tool: this requirement is verified manually and no collector reads its evidence yet.'
            $r.NotVerifiedCause = 'Manual control'
        } else {
            # ── Evidence timestamp and collector health from the raw data ──
            $evidenceTimes = [System.Collections.Generic.List[datetime]]::new()
            $collectorProblem = ''
            foreach ($key in @($ctrl.RawDataKeys)) {
                $covEntry = if ($cov -is [System.Collections.IDictionary] -and $cov.Contains($key)) { $cov[$key] } else { $null }
                $covStatus = if ($covEntry) { [string](Get-NRGObjectField -Item $covEntry -Key 'Status' -Default '') } else { '' }
                if ($covStatus -in @('Failed', 'NotCollected', 'Skipped')) { $collectorProblem = "collector '$key' reported $covStatus"; continue }
                if ($rawPopulated) {
                    $entry = if ($raw -is [System.Collections.IDictionary] -and $raw.Contains($key)) { $raw[$key] } else { $null }
                    if ($null -eq $entry) { $collectorProblem = "collector '$key' produced no data"; continue }
                    $ok = Get-NRGObjectField -Item $entry -Key 'Success' -Default $null
                    if ($null -ne $ok -and -not [bool]$ok) { $collectorProblem = "collector '$key' did not succeed"; continue }
                    $ts = & $parseTs (Get-NRGObjectField -Item $entry -Key 'CollectedAt' -Default $null)
                    if ($null -ne $ts) { $evidenceTimes.Add($ts) }
                }
            }

            # Two statements: an if-block yielding an empty array assigns $null.
            $list = @()
            if ($byControl.ContainsKey($cid)) { $list = @($byControl[$cid]) }
            $f = if ($list.Count -gt 0) { & $worst $list } else { $null }
            $fState = if ($f) { [string](Get-NRGObjectField -Item $f -Key 'State' -Default '') } else { '' }
            $detail = if ($f) { [string](Get-NRGObjectField -Item $f -Key 'Detail' -Default '') } else { '' }
            $r.ObservedFindingState = $fState
            if ($evidenceTimes.Count -eq 0 -and $f) {
                $ts = & $parseTs (Get-NRGObjectField -Item $f -Key 'Timestamp' -Default $null)
                if ($null -ne $ts) { $evidenceTimes.Add($ts) }
            }
            $evidenceAt = if ($evidenceTimes.Count -gt 0) { ($evidenceTimes | Sort-Object | Select-Object -First 1) } else { $null }
            if ($null -ne $evidenceAt) { $r.EvidenceTimestamp = $evidenceAt.ToString('o') }

            $bucket = if ($bucketOf.ContainsKey($cid)) { $bucketOf[$cid] } else { $null }

            $collectorKey = if ($collectorProblem -match "collector '([^']+)'") { $Matches[1] } else { '' }
            if ($null -eq $f) {
                $r.ObservedState = 'NotVerified'
                $r.Reason = if ($bucket) { $bucket.Reason } else { 'No finding was produced for this control in this run.' }
                $b0 = if ($bucket) { $bucket.Bucket } else { '' }
                $r.NotVerifiedCause = if ($collectorKey) { "Collector unavailable: $collectorKey" }
                                      elseif ($b0 -eq 'SkippedByOperator') { 'Skipped by operator' }
                                      elseif ($b0 -eq 'NotEvaluatedThisMode') { 'Quick scan' }
                                      else { 'No result' }
            } elseif ($collectorProblem) {
                # A verdict cannot outlive the data it came from.
                $r.ObservedState = 'NotVerified'
                $r.Reason = "The $collectorProblem in this run, so the recorded verdict ($fState) is not evidence.$(if ($detail) { " $detail" })"
                $r.NotVerifiedCause = "Collector unavailable: $collectorKey"
            } elseif ($fState -eq 'Satisfied') {
                $r.ObservedState = 'Satisfied'; $r.Reason = $detail
            } elseif ($fState -in @('Gap', 'Partial')) {
                $r.ObservedState = 'Failed'; $r.Reason = "$fState$(if ($detail) { ": $detail" })"
            } elseif ($fState -eq 'Error') {
                $r.ObservedState = 'NotVerified'; $r.Reason = "The evaluator raised an error; the true state is unknown.$(if ($detail) { " $detail" })"
                $r.NotVerifiedCause = 'Evaluator error'
            } else {
                # NotApplicable: only the scope classifier's positive signals decide what kind.
                $b = if ($bucket) { $bucket.Bucket } else { '' }
                if ($b -eq 'LicenceBlocked' -or $detail -like "*$upgradeMarker*") {
                    $r.ObservedState = 'NotApplicable'; $r.Constraint = 'LicenseBlocked'
                    $r.Reason = if ($detail) { $detail } else { 'This tenant does not hold the license the control requires.' }
                } elseif ($b -in @('ThirdPartyAttested', 'NotApplicableToTenant')) {
                    $r.ObservedState = 'NotApplicable'
                    $r.Reason = if ($bucket.Reason) { $bucket.Reason } elseif ($detail) { $detail } else { 'Reported not applicable to this tenant.' }
                } else {
                    $r.ObservedState = 'NotVerified'
                    $r.Reason = if ($bucket -and $bucket.Reason) { $bucket.Reason } elseif ($detail) { $detail } else { 'Reported not applicable without a reason the baseline can classify.' }
                    $r.NotVerifiedCause = if ($b -eq 'SkippedByOperator') { 'Skipped by operator' }
                                          elseif ($b -eq 'NoProgrammaticCheck' -or $detail -match 'requires manual verification|manual review required') { 'Manual verification' }
                                          elseif ($detail -match 'was not read|not read\b') { 'Evidence not read' }
                                          # The collector ran and succeeded, but the evaluator still had no
                                          # evidence (a section or a second source, such as the SharePoint
                                          # shell, did not produce it): that is unread evidence, not an
                                          # unavailable collector.
                                          elseif ($b -eq 'CollectionIncomplete' -and $evidenceTimes.Count -gt 0) { 'Evidence not read' }
                                          elseif ($b -eq 'CollectionIncomplete') { "Collector unavailable: $(@($ctrl.RawDataKeys)[0])" }
                                          else { 'Unclassified' }
                }
            }

            # ── Freshness: stale evidence is not evidence ──
            if ($null -ne $evidenceAt) {
                $window = [int]$def.FreshnessWindowsDays[$ctrl.FreshnessClass]
                $age = ($AsOf - $evidenceAt).TotalDays
                if ($age -gt $window) {
                    $r.EvidenceFreshness = 'Stale'
                    if ($r.ObservedState -in @('Satisfied', 'NotApplicable')) {
                        $r.ObservedState = 'NotVerified'
                        $r.Constraint = 'None'
                        $r.NotVerifiedCause = 'Stale evidence'
                        $r.Reason = "Evidence is $([math]::Floor($age)) day(s) old; the $($ctrl.FreshnessClass) freshness class allows $window. A verdict that old is not evidence.$(if ($r.Reason) { " Last observed: $($r.Reason)" })"
                    }
                } else {
                    $r.EvidenceFreshness = 'Current'
                }
            } else {
                $r.EvidenceFreshness = 'None'
            }
        }

        # ── Disposition: an approved exception changes the disposition only ──
        if ($approvedExc.ContainsKey($cid)) {
            $e = $approvedExc[$cid]
            $r.Disposition = 'ApprovedException'
            $r.ExceptionSummary = "$($e.Reason) Compensating control: $($e.CompensatingControl) ($($e.Verdict))"
        } elseif ($exc -and $exc.Rejected) {
            $rej = @($exc.Rejected | Where-Object { $_.ControlId -eq $cid })
            if ($rej.Count -gt 0) { $r.ExceptionSummary = "Exception on file is not in force: $($rej[0].Verdict)" }
        }

        # ── Effectiveness: only what the assessment can actually read ──
        if ($ctrl.EffectivenessCapability -ne 'Collected' -or $null -eq $ctrl.EffectivenessEvidence) {
            $r.EffectivenessState = 'Unknown'
            $r.EffectivenessDetail = 'The effectiveness evidence is not collected by the assessment.'
        } else {
            $ev = $ctrl.EffectivenessEvidence
            $evType = [string](Get-NRGObjectField -Item $ev -Key 'Type' -Default '')
            if ($evType -eq 'DeviceControls') {
                $devIds = @(Get-NRGObjectField -Item $ev -Key 'Controls' -Default @())
                $devStates = @(foreach ($d in $devIds) {
                    if ($byControl.ContainsKey($d)) { [string](Get-NRGObjectField -Item (& $worst @($byControl[$d])) -Key 'State' -Default '') } else { '' }
                })
                if (@($devStates | Where-Object { $_ }).Count -eq 0) {
                    $r.EffectivenessState = 'Unknown'; $r.EffectivenessDetail = "No endpoint results ($($devIds -join ', ')) were ingested this run (-DeviceResults)."
                } elseif ($devStates -contains 'Gap' -or $devStates -contains 'Partial') {
                    $r.EffectivenessState = 'Ineffective'; $r.EffectivenessDetail = "Endpoint checks $($devIds -join ', ') report failing devices."
                } elseif (@($devStates | Where-Object { $_ -ne 'Satisfied' }).Count -eq 0) {
                    $r.EffectivenessState = 'Effective'; $r.EffectivenessDetail = "Endpoint checks $($devIds -join ', ') pass on every device that reported."
                } else {
                    $r.EffectivenessState = 'Unknown'; $r.EffectivenessDetail = "Endpoint checks $($devIds -join ', ') did not all reach a verdict."
                }
            } else {
                $r.EffectivenessState = 'Unknown'
                $r.EffectivenessDetail = "Evidence type '$evType' is not evaluated by this version; it needs a comparison with a prior run."
            }
        }

        $observedById[$cid] = $r
        $rows.Add($r)
    }

    # ── Dependencies: visible, never inferred into the dependent's state ──
    foreach ($r in $rows) {
        $deps = @($r.DependsOn)
        if ($deps.Count -eq 0) { $r.DependencyState = 'None'; continue }
        $states = @(foreach ($d in $deps) {
            if ($observedById.ContainsKey($d)) { "$d=$($observedById[$d].ObservedState)" }
            elseif ($byControl.ContainsKey($d)) { "$d=$([string](Get-NRGObjectField -Item (& $worst @($byControl[$d])) -Key 'State' -Default ''))" }
            else { "$d=NotVerified" }
        })
        $unmet = @($states | Where-Object { $_ -notlike '*=Satisfied' })
        $r.DependencyState = if ($unmet.Count -eq 0) { 'Met' } else { "Unmet: $($unmet -join ', ')" }
    }

    # ── Display status (derived; the four fields above are the record) ──
    foreach ($r in $rows) {
        $r.BaselineStatus = if ($r.Constraint -eq 'LicenseBlocked') { 'LicenseBlocked' }
                            elseif ($r.Disposition -eq 'ApprovedException') { 'ApprovedException' }
                            else { $r.ObservedState }
    }

    $count = { param([string] $status) @($rows | Where-Object { $_.BaselineStatus -eq $status }).Count }
    # NotVerified split by cause, largest first: the engineering list behind the number.
    $byCause = [ordered]@{}
    $causeGroups = @($rows | Where-Object { $_.ObservedState -eq 'NotVerified' } |
        Group-Object { if ($_.NotVerifiedCause) { $_.NotVerifiedCause } else { 'Unclassified' } } |
        Sort-Object -Property @{ Expression = 'Count'; Descending = $true }, @{ Expression = 'Name'; Descending = $false })
    foreach ($g in $causeGroups) { $byCause[[string]$g.Name] = [int]$g.Count }
    $byTier = [ordered]@{}
    foreach ($t in @($def.TierOrder)) {
        $tr = @($rows | Where-Object { $_.RequiredTier -eq $t })
        if ($tr.Count -eq 0) { continue }
        $byTier[$t] = [ordered]@{
            Required          = $tr.Count
            Satisfied         = @($tr | Where-Object { $_.BaselineStatus -eq 'Satisfied' }).Count
            Failed            = @($tr | Where-Object { $_.BaselineStatus -eq 'Failed' }).Count
            NotVerified       = @($tr | Where-Object { $_.BaselineStatus -eq 'NotVerified' }).Count
            NotApplicable     = @($tr | Where-Object { $_.BaselineStatus -eq 'NotApplicable' }).Count
            LicenseBlocked    = @($tr | Where-Object { $_.BaselineStatus -eq 'LicenseBlocked' }).Count
            ApprovedException = @($tr | Where-Object { $_.BaselineStatus -eq 'ApprovedException' }).Count
        }
    }
    $summary = [ordered]@{
        BaselineVersion        = $def.Version
        TargetTier             = $TargetTier
        RequiredControls       = $rows.Count
        Satisfied              = (& $count 'Satisfied')
        Failed                 = (& $count 'Failed')
        NotVerified            = (& $count 'NotVerified')
        NotApplicable          = (& $count 'NotApplicable')
        LicenseBlocked         = (& $count 'LicenseBlocked')
        ApprovedException      = (& $count 'ApprovedException')
        StaleEvidence          = @($rows | Where-Object { $_.EvidenceFreshness -eq 'Stale' }).Count
        NoEvidence             = @($rows | Where-Object { $_.EvidenceFreshness -eq 'None' }).Count
        NotVerifiedByCause     = $byCause
        EffectivenessEffective = @($rows | Where-Object { $_.EffectivenessState -eq 'Effective' }).Count
        EffectivenessIneffective = @($rows | Where-Object { $_.EffectivenessState -eq 'Ineffective' }).Count
        EffectivenessUnknown   = @($rows | Where-Object { $_.EffectivenessState -eq 'Unknown' }).Count
        ExceptionsNotInForce   = @(if ($exc -and $exc.Rejected) { @($exc.Rejected).Count } else { 0 })[0]
        ByTier                 = $byTier
    }
    return [ordered]@{
        Available       = $true
        BaselineVersion = $def.Version
        TargetTier      = $TargetTier
        AsOf            = $AsOf.ToString('o')
        ExceptionsPath  = $(if ($exc -and $exc.Available) { $exc.Path } else { '' })
        Summary         = $summary
        Controls        = @($rows | ForEach-Object { [pscustomobject]$_ })
    }
}

# ── Regressions ───────────────────────────────────────────────────────────────

function Get-NRGBaselineRegressions {
    <#
    .SYNOPSIS
        Compares this run's baseline compliance with a prior run's and returns
        the required controls that were acceptable then and are not now.
    .DESCRIPTION
        A regression is a required control whose baseline status was Satisfied
        or ApprovedException in the prior run and is Failed or NotVerified now,
        under a comparable context. The context is comparable only when both
        runs used the same baseline version and target tier; otherwise
        Comparable is false, the reason is stated, and only controls present
        in both runs at the same required tier are compared, so a control the
        new version added is never reported as a regression.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [object] $Current,
        [AllowNull()] [object] $Prior,
        [AllowNull()] [AllowEmptyString()] [string] $PriorRunTime,
        [datetime] $Detected = (Get-Date)
    )
    Set-StrictMode -Version Latest

    $result = [ordered]@{
        Available              = $false
        Comparable             = $false
        BaselineVersionChanged = $false
        TargetTierChanged      = $false
        PriorBaselineVersion   = ''
        PriorTargetTier        = ''
        CurrentBaselineVersion = ''
        CurrentTargetTier      = ''
        Note                   = ''
        Regressions            = @()
        Improvements           = @()
        ConfigurationRegressed = 0
        EvidenceLost           = 0
    }
    if ($null -eq $Current) { $result.Note = 'No current baseline compliance to compare.'; return $result }
    $result.CurrentBaselineVersion = [string](Get-NRGObjectField -Item $Current -Key 'BaselineVersion' -Default '')
    $result.CurrentTargetTier      = [string](Get-NRGObjectField -Item $Current -Key 'TargetTier' -Default '')
    if ($null -eq $Prior) { $result.Note = 'The prior run carries no baseline compliance (it predates the baseline, or was run without it); nothing to compare.'; return $result }
    $result.Available = $true
    $result.PriorBaselineVersion = [string](Get-NRGObjectField -Item $Prior -Key 'BaselineVersion' -Default '')
    $result.PriorTargetTier      = [string](Get-NRGObjectField -Item $Prior -Key 'TargetTier' -Default '')
    $result.BaselineVersionChanged = ($result.PriorBaselineVersion -ne $result.CurrentBaselineVersion)
    $result.TargetTierChanged      = ($result.PriorTargetTier -ne $result.CurrentTargetTier)
    $result.Comparable = -not ($result.BaselineVersionChanged -or $result.TargetTierChanged)
    if (-not $result.Comparable) {
        $result.Note = "The baseline context changed (v$($result.PriorBaselineVersion) $($result.PriorTargetTier) -> v$($result.CurrentBaselineVersion) $($result.CurrentTargetTier)). A lower result does not mean the client got worse; only controls required in both runs at the same tier are compared."
    }

    $priorById = @{}
    foreach ($p in @(Get-NRGObjectField -Item $Prior -Key 'Controls' -Default @())) {
        $priorId = [string](Get-NRGObjectField -Item $p -Key 'ControlId' -Default '')
        if ($priorId) { $priorById[$priorId] = $p }
    }
    $acceptable = @('Satisfied', 'ApprovedException')
    $bad = @('Failed', 'NotVerified')
    $regs = [System.Collections.Generic.List[object]]::new()
    $imps = [System.Collections.Generic.List[object]]::new()
    foreach ($c in @(Get-NRGObjectField -Item $Current -Key 'Controls' -Default @())) {
        $cid = [string](Get-NRGObjectField -Item $c -Key 'ControlId' -Default '')
        if (-not $cid -or -not $priorById.ContainsKey($cid)) { continue }
        $p = $priorById[$cid]
        $curTier = [string](Get-NRGObjectField -Item $c -Key 'RequiredTier' -Default '')
        $priTier = [string](Get-NRGObjectField -Item $p -Key 'RequiredTier' -Default '')
        if (-not $result.Comparable -and $curTier -ne $priTier) { continue }
        $cur = [string](Get-NRGObjectField -Item $c -Key 'BaselineStatus' -Default '')
        $pri = [string](Get-NRGObjectField -Item $p -Key 'BaselineStatus' -Default '')
        $row = [ordered]@{
            ControlId    = $cid
            Title        = [string](Get-NRGObjectField -Item $c -Key 'Title' -Default '')
            RequiredTier = $curTier
            Owner        = [string](Get-NRGObjectField -Item $c -Key 'Owner' -Default '')
            SlaClass     = [string](Get-NRGObjectField -Item $c -Key 'SlaClass' -Default '')
            Previous     = $pri
            Current      = $cur
            # Why the current state is NotVerified, when it is. Ten controls
            # going Satisfied -> NotVerified because one sign-in failed is a
            # sensor outage, not drift; the cause says which.
            CurrentCause = [string](Get-NRGObjectField -Item $c -Key 'NotVerifiedCause' -Default '')
            Kind         = $(if ($cur -eq 'Failed') { 'ConfigurationRegressed' } elseif ($cur -eq 'NotVerified') { 'EvidenceLost' } else { 'Other' })
            PriorRun     = [string]$PriorRunTime
            Detected     = $Detected.ToString('o')
            Reason       = [string](Get-NRGObjectField -Item $c -Key 'Reason' -Default '')
            Action       = "Review and restore: $([string](Get-NRGObjectField -Item $c -Key 'ExpectedState' -Default ''))"
        }
        if ($pri -in $acceptable -and $cur -in $bad) { $regs.Add([pscustomobject]$row) }
        elseif ($pri -in $bad -and $cur -eq 'Satisfied') { $imps.Add([pscustomobject]$row) }
    }
    $result.Regressions  = @($regs)
    $result.Improvements = @($imps)
    $result.ConfigurationRegressed = @($regs | Where-Object { $_.Kind -eq 'ConfigurationRegressed' }).Count
    $result.EvidenceLost           = @($regs | Where-Object { $_.Kind -eq 'EvidenceLost' }).Count
    if ($result.Comparable -and -not $result.Note) {
        $result.Note = "$($regs.Count) baseline regression(s) against the prior run (same baseline v$($result.CurrentBaselineVersion), tier $($result.CurrentTargetTier)): $($result.ConfigurationRegressed) configuration regressed, $($result.EvidenceLost) evidence lost (a collector or sign-in did not complete this run; the configuration may be unchanged)."
    }
    return $result
}
