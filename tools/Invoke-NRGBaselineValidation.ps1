#Requires -Version 7.0
#
# Invoke-NRGBaselineValidation.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Validate one live run's NRG Security Baseline results against the
#   evidence they were derived from, and write a Markdown validation report.
#   Connects to nothing. Reads a results JSON produced by
#   Invoke-NRGAssessment.ps1 (v4.14.3 + baseline), replays its findings, raw
#   data and coverage into module state exactly as -FromResults does,
#   recomputes the baseline view, and then, for EVERY required control,
#   joins the baseline row with: the finding(s) and their states, the
#   assessment-scope bucket, the license status, each collector's Success
#   and CollectedAt, the coverage entry, control links (duplicates), and the
#   exceptions file. Each row gets an automatic classification:
#
#     ImplementationBugCandidate   the baseline disagrees with its own evidence
#     CollectorCoverageGap         the evidence was never collected this run
#     LicensingApplicability       licensing decided the result
#     EditorialReview              a genuine Failed / stale / exception to judge
#     ExpectedBehavior             the row is what the design says it should be
#
#   It never changes code, config, findings or the results file, and it
#   never fixes a gap to make the report cleaner: the point is to find
#   false failures, false NotVerified results, duplicate controls, and
#   freshness or dependency rules that would mislead an operator, BEFORE
#   v1.0 is locked.
#
# Usage:
#   .\tools\Invoke-NRGBaselineValidation.ps1 -ResultsPath .\output\<tenant>-<stamp>-results.json
#   .\tools\Invoke-NRGBaselineValidation.ps1 -ResultsPath ... -TargetTier Standard -OutputPath .\output\baseline-validation.md
#
# Data consumed: results JSON (Metadata, Findings, RawData, Coverage,
#   BaselineCompliance, BaselineRegressions), Config/nrg-baseline.json,
#   Config/baseline-exceptions/<tenant-domain>.psd1.
# Data set: none in the tenant; one Markdown file on disk.
# Graph scopes / cmdlets required: none.

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateScript({
        if ($_ -match '\.\.[\\/]') { throw 'Path traversal not allowed in -ResultsPath.' }
        if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Results file not found: $_" }
        $true
    })]
    [string] $ResultsPath,

    # Defaults to the tier recorded in the results metadata, else Standard.
    [ValidateSet('', 'Minimum', 'Standard', 'Hardened')]
    [string] $TargetTier = '',

    # Defaults to <results>-baseline-validation.md beside the results file.
    [string] $OutputPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path $repoRoot 'NRG-Assessment.psm1') -Force -WarningAction SilentlyContinue

# Absolute paths from here on. The hardened file writer uses .NET, which
# resolves a relative path against the PROCESS working directory
# (C:\WINDOWS\system32 in an elevated window), not PowerShell's location; a
# relative -ResultsPath therefore wrote the report into System32 and failed.
$ResultsPath = (Resolve-Path -LiteralPath $ResultsPath).ProviderPath
if ($OutputPath) {
    $outDir = Split-Path -Parent $OutputPath
    if ($outDir -and -not [System.IO.Path]::IsPathRooted($OutputPath)) { $OutputPath = Join-Path (Get-Location).ProviderPath $OutputPath }
    elseif (-not $outDir) { $OutputPath = Join-Path (Get-Location).ProviderPath $OutputPath }
}

# ── Load and replay ───────────────────────────────────────────────────────────
$json = Get-Content -LiteralPath $ResultsPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20 -AsHashtable
$meta = if ($json.Contains('Metadata') -and $json.Metadata) { [hashtable]$json.Metadata } else { @{} }
$findings = [object[]]@($json.Findings | Where-Object { $null -ne $_ })
$runTimeText = [string](Get-NRGObjectField -Item $meta -Key 'AssessmentTime' -Default '')
$runTime = [datetime]::MinValue
if (-not [datetime]::TryParse($runTimeText, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$runTime)) {
    $runTime = (Get-Item -LiteralPath $ResultsPath).LastWriteTime
    Write-Warning "Metadata.AssessmentTime is missing or unparseable; using the file's write time ($($runTime.ToString('o'))) as the run time."
}
$tenantDomain = [string](Get-NRGObjectField -Item $meta -Key 'TenantDomain' -Default '')
if (-not $TargetTier) {
    $t = [string](Get-NRGObjectField -Item $meta -Key 'TargetTier' -Default '')
    $TargetTier = if ($t -in @('Minimum', 'Standard', 'Hardened')) { $t } else { 'Standard' }
}
if (-not $OutputPath) { $OutputPath = [System.IO.Path]::ChangeExtension($ResultsPath, $null).TrimEnd('.') + '-baseline-validation.md' }

Clear-NRGState
$coverageRestored = 0; $coverageDropped = @()
if ($json.Contains('Coverage') -and $json.Coverage) {
    foreach ($k in @($json.Coverage.Keys)) {
        $e = $json.Coverage[$k]
        $st = [string](Get-NRGObjectField -Item $e -Key 'Status' -Default '')
        $nt = [string](Get-NRGObjectField -Item $e -Key 'Note' -Default '')
        try { Register-NRGCoverage -Family ([string]$k) -Status $st -Note $nt; $coverageRestored++ } catch { $coverageDropped += "$k=$st" }
    }
}
if ($json.Contains('RawData') -and $json.RawData) {
    foreach ($k in @($json.RawData.Keys)) { try { Set-NRGRawData -Key ([string]$k) -Data $json.RawData[$k] } catch { Write-Warning "Raw data key '$k' could not be restored: $($_.Exception.Message)" } }
}
$raw = Get-NRGRawData
$cov = Get-NRGCoverage
$licProfile = try { Get-NRGTenantLicenseProfile } catch { $null }
$hasLicData = ($null -ne $licProfile) -and [bool](Get-NRGObjectField -Item $licProfile -Key 'HasLicenseData' -Default $false)
$exc = Get-NRGBaselineExceptions -TenantDomain $tenantDomain -AsOf $runTime
$scope = Get-NRGAssessmentScope -Findings $findings -Coverage $cov -LicenseProfile $licProfile -RawData $raw `
            -QuickScan:([bool](Get-NRGObjectField -Item $meta -Key 'QuickScan' -Default $false))
$bucketOf = @{}
foreach ($b in @('LicenceBlocked', 'CollectionIncomplete', 'StandardNotApproved', 'NoProgrammaticCheck', 'ThirdPartyAttested', 'NotApplicableToTenant', 'NotEvaluatedThisMode', 'SkippedByOperator', 'NoResult', 'Errors')) {
    foreach ($row in @(Get-NRGObjectField -Item $scope -Key $b -Default @())) {
        $rid = [string](Get-NRGObjectField -Item $row -Key 'ControlId' -Default '')
        if ($rid -and -not $bucketOf.ContainsKey($rid)) { $bucketOf[$rid] = $b }
    }
}

# As at the run (what the operator saw) and as at today (what a republish would show).
$asRun   = Get-NRGBaselineCompliance -Findings $findings -TargetTier $TargetTier -TenantDomain $tenantDomain -RawData $raw -Coverage $cov -LicenseProfile $licProfile -AsOf $runTime -Exceptions $exc
$asToday = Get-NRGBaselineCompliance -Findings $findings -TargetTier $TargetTier -TenantDomain $tenantDomain -RawData $raw -Coverage $cov -LicenseProfile $licProfile -AsOf (Get-Date) -Exceptions $exc
$embedded = if ($json.Contains('BaselineCompliance')) { $json.BaselineCompliance } else { $null }
$embeddedRegs = if ($json.Contains('BaselineRegressions')) { $json.BaselineRegressions } else { $null }
$links = if (Get-Command Get-NRGControlLinkMap -ErrorAction SilentlyContinue) { Get-NRGControlLinkMap } else { @{} }

$byControl = @{}
foreach ($f in $findings) {
    $cid = [string](Get-NRGObjectField -Item $f -Key 'ControlId' -Default '')
    if (-not $cid) { continue }
    if (-not $byControl.ContainsKey($cid)) { $byControl[$cid] = [System.Collections.Generic.List[object]]::new() }
    $byControl[$cid].Add($f)
}
$embeddedById = @{}
if ($embedded) { foreach ($c in @(Get-NRGObjectField -Item $embedded -Key 'Controls' -Default @())) { $embeddedById[[string](Get-NRGObjectField -Item $c -Key 'ControlId' -Default '')] = $c } }

# ── Cross-check every required control ────────────────────────────────────────
$rows = [System.Collections.Generic.List[object]]::new()
foreach ($r in $asRun.Controls) {
    $cid = [string]$r.ControlId
    $fl = @()
    if ($byControl.ContainsKey($cid)) { $fl = @($byControl[$cid]) }
    $fStates = @($fl | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'State' -Default '') })
    $fDetail = if ($fl.Count -gt 0) { [string](Get-NRGObjectField -Item $fl[0] -Key 'Detail' -Default '') } else { '' }
    $keys = @((Get-NRGBaselineDefinition).Controls[$cid].RawDataKeys)
    $collectors = @(foreach ($k in $keys) {
        $entry = if ($raw -is [System.Collections.IDictionary] -and $raw.Contains($k)) { $raw[$k] } else { $null }
        $ok = if ($null -ne $entry) { Get-NRGObjectField -Item $entry -Key 'Success' -Default $null } else { $null }
        $at = if ($null -ne $entry) { [string](Get-NRGObjectField -Item $entry -Key 'CollectedAt' -Default '') } else { '' }
        $cv = if ($cov.Contains($k)) { [string]$cov[$k].Status } else { '' }
        "$k=$(if ($null -eq $entry) { 'absent' } elseif ($null -eq $ok) { 'no Success field' } elseif ($ok) { 'ok' } else { 'FAILED' })$(if ($cv) { "/cov:$cv" })$(if ($at) { " @$at" })"
    })
    $anyCollectorFailed = @($collectors | Where-Object { $_ -match '=FAILED|=absent|cov:(Failed|Skipped|NotCollected)' }).Count -gt 0
    # A collector can succeed overall while one of its sections failed; an
    # evaluator that did not consult SectionStatus then scores an empty list
    # as clean (EXO-2.6 on the first Exchange-connected run).
    $failedSections = @(foreach ($k in $keys) {
        $entry = if ($raw -is [System.Collections.IDictionary] -and $raw.Contains($k)) { $raw[$k] } else { $null }
        $ss = if ($null -ne $entry) { Get-NRGNestedProperty -Object $entry -Path 'Data.SectionStatus' -Default $null } else { $null }
        if ($ss -is [System.Collections.IDictionary]) { foreach ($name in @($ss.Keys)) { if ([string]$ss[$name] -eq 'Failed') { "$k/$name" } } }
        elseif ($null -ne $ss) { foreach ($p in $ss.PSObject.Properties) { if ([string]$p.Value -eq 'Failed') { "$k/$($p.Name)" } } }
    })
    $licStatus = if ($cid -eq 'VM-VERIFY-01') { 'n/a' } else { try { Get-NRGControlLicenseStatus -ControlId $cid } catch { 'n/a' } }
    $bucket = if ($bucketOf.ContainsKey($cid)) { $bucketOf[$cid] } else { '' }
    $group = if ($links.ContainsKey($cid)) { [string]$links[$cid].Primary } else { '' }
    $emb = if ($embeddedById.ContainsKey($cid)) { [string](Get-NRGObjectField -Item $embeddedById[$cid] -Key 'BaselineStatus' -Default '') } else { '' }
    $todayRow = @($asToday.Controls | Where-Object { $_.ControlId -eq $cid })[0]
    $excOnFile = @($exc.Entries | Where-Object { $_.ControlId -eq $cid })

    $class = 'ExpectedBehavior'; $checks = [System.Collections.Generic.List[string]]::new()
    $st = [string]$r.ObservedState; $bs = [string]$r.BaselineStatus
    if ($emb -and $emb -ne $bs) { $class = 'ImplementationBugCandidate'; $checks.Add("embedded BaselineStatus '$emb' differs from recomputed '$bs'") }
    if ($cid -eq 'VM-VERIFY-01') {
        $checks.Add('manual requirement; NotVerified until a Defender VM collector exists')
    } elseif ($st -eq 'Satisfied') {
        if ($anyCollectorFailed) { $class = 'ImplementationBugCandidate'; $checks.Add('Satisfied while a collector did not succeed') }
        # Note only: most failed sections belong to other controls sharing the
        # collector. The operator confirms the evaluator does not read the named
        # section; a Satisfied that does is an implementation bug.
        if ($failedSections.Count -gt 0) { $checks.Add("CHECK: a section of its collector failed ($($failedSections -join ', ')) — confirm the evaluator does not score from that section") }
        if ($fStates -notcontains 'Satisfied') { $class = 'ImplementationBugCandidate'; $checks.Add("Satisfied without a Satisfied finding ($($fStates -join ','))") }
        if ($fStates -contains 'Gap' -or $fStates -contains 'Partial') { $class = 'ImplementationBugCandidate'; $checks.Add('Satisfied while an instance finding is Gap/Partial') }
    } elseif ($st -eq 'Failed') {
        if ($fStates -notcontains 'Gap' -and $fStates -notcontains 'Partial') { $class = 'ImplementationBugCandidate'; $checks.Add("Failed without a Gap/Partial finding ($($fStates -join ','))") }
        elseif ($licStatus -eq 'NotMet') { $class = 'LicensingApplicability'; $checks.Add('Failed although the license status is NotMet: license gating should have moved it') }
        elseif ($class -eq 'ExpectedBehavior') { $class = 'EditorialReview'; $checks.Add('genuinely below the proposed standard? confirm the finding, then decide tier or remediation') }
    } elseif ($bs -eq 'LicenseBlocked') {
        if ($licStatus -eq 'Met') { $class = 'ImplementationBugCandidate'; $checks.Add('LicenseBlocked while the license status is Met') }
        elseif (-not $hasLicData) { $class = 'LicensingApplicability'; $checks.Add('LicenseBlocked with no SKU data read: the marker came from the evaluator, confirm it') }
        else { $class = 'LicensingApplicability'; $checks.Add("license status $licStatus; confirm NRG cannot enforce this without the license") }
    } elseif ($st -eq 'NotVerified') {
        if ($fStates.Count -gt 0 -and ($fStates -contains 'Satisfied' -or $fStates -contains 'Gap' -or $fStates -contains 'Partial') -and -not $anyCollectorFailed -and $r.EvidenceFreshness -ne 'Stale') {
            $class = 'ImplementationBugCandidate'; $checks.Add("NotVerified although a verdict ($($fStates -join ',')) exists, its collectors succeeded and the evidence is current")
        } elseif ($r.EvidenceFreshness -eq 'Stale') {
            $class = 'EditorialReview'; $checks.Add("stale at the run time itself: the $($r.FreshnessClass) window is shorter than the gap between collection and this run; is that freshness class realistic?")
        } elseif ($bucket -eq 'StandardNotApproved') {
            $class = 'EditorialReview'; $checks.Add('an NRG standard this control is judged against is not approved or configured; approve it (Config/nrg-standards.json, asr-required-rules.json or the monitoring address) and re-run')
        } elseif ($anyCollectorFailed -or $bucket -in @('CollectionIncomplete', 'SkippedByOperator', 'NoResult', 'Errors')) {
            $class = 'CollectorCoverageGap'; $checks.Add("evidence not collected ($(if ($bucket) { $bucket } else { 'collector state' })); the control could have been assessed")
        } elseif ($bucket -eq 'NoProgrammaticCheck' -or $fDetail -match 'requires manual verification') {
            $checks.Add('manual verification by design')
        } elseif ($fStates -contains 'Error') {
            $class = 'CollectorCoverageGap'; $checks.Add('evaluator error; see Exceptions')
        } else {
            $class = 'ImplementationBugCandidate'; $checks.Add("NotVerified for a reason the validation cannot classify: $($r.Reason)")
        }
    } elseif ($st -eq 'NotApplicable') {
        if ($bucket -eq 'ThirdPartyAttested') { $class = 'LicensingApplicability'; $checks.Add('declared third-party EDR; confirm in the vendor console, not here') }
        else { $checks.Add("not applicable to this tenant: $($r.Reason)") }
    }
    if ($bs -eq 'ApprovedException') { $class = 'EditorialReview'; $checks.Add("approved exception on file; underlying state $st must stay visible in the report") }
    elseif ($excOnFile.Count -gt 0) { $checks.Add("exception on file but not in force: $($excOnFile[0].Verdict)") }
    if ($group -and $group -ne $cid) { $checks.Add("duplicate: reads the same setting as $group (control links); required twice?") }
    if ($todayRow -and $todayRow.ObservedState -ne $st) { $checks.Add("would read $($todayRow.ObservedState) on a republish today (evidence age vs $($r.FreshnessClass) window)") }
    if ($r.DependencyState -like 'Unmet*' -and $st -eq 'Satisfied') { $checks.Add("satisfied while a dependency is unmet ($($r.DependencyState)): operationally misleading?") }

    $rows.Add([pscustomobject]@{
        ControlId = $cid; Tier = $r.RequiredTier; Owner = $r.Owner
        BaselineStatus = $bs; Observed = $st; Constraint = $r.Constraint; Disposition = $r.Disposition
        Effectiveness = $r.EffectivenessState; Freshness = $r.EvidenceFreshness; Dependencies = $r.DependencyState
        FindingStates = ($fStates -join ','); ScopeBucket = $bucket; License = $licStatus
        Collectors = ($collectors -join '; '); Embedded = $emb
        Classification = $class; Checks = ($checks -join ' | '); Reason = $r.Reason
    })
}

# ── Contract inspection ───────────────────────────────────────────────────────
$contractNotes = [System.Collections.Generic.List[string]]::new()
$expectedFields = @('ControlId', 'RequiredTier', 'ObservedState', 'Constraint', 'Disposition', 'EvidenceSource', 'EvidenceTimestamp', 'EvidenceFreshness', 'EffectivenessState', 'Reason', 'BaselineStatus')
if ($null -eq $embedded) { $contractNotes.Add('BaselineCompliance is ABSENT from the results JSON (the run predates the baseline or the view failed; see Metadata.BaselineError).') }
else {
    $sample = @(Get-NRGObjectField -Item $embedded -Key 'Controls' -Default @())
    $contractNotes.Add("BaselineCompliance present: version $(Get-NRGObjectField -Item $embedded -Key 'BaselineVersion' -Default '?'), tier $(Get-NRGObjectField -Item $embedded -Key 'TargetTier' -Default '?'), $($sample.Count) control rows.")
    if ($sample.Count -gt 0) {
        $missing = @($expectedFields | Where-Object { $null -eq (Get-NRGObjectField -Item $sample[0] -Key $_ -Default $null) -and -not ($sample[0] -is [System.Collections.IDictionary] -and $sample[0].Contains($_)) })
        if ($missing.Count -gt 0) { $contractNotes.Add("Control rows lack fields: $($missing -join ', ').") } else { $contractNotes.Add('Every contract field is present on the control rows.') }
        $emptyTs = @($sample | Where-Object { -not [string](Get-NRGObjectField -Item $_ -Key 'EvidenceTimestamp' -Default '') -and [string](Get-NRGObjectField -Item $_ -Key 'ObservedState' -Default '') -ne 'NotVerified' }).Count
        if ($emptyTs -gt 0) { $contractNotes.Add("$emptyTs verified rows carry no EvidenceTimestamp (a consumer cannot age them).") }
    }
    $metaVer = [string](Get-NRGObjectField -Item $meta -Key 'BaselineVersion' -Default '')
    $metaTier = [string](Get-NRGObjectField -Item $meta -Key 'TargetTier' -Default '')
    if (-not $metaVer -or -not $metaTier) { $contractNotes.Add('Metadata lacks BaselineVersion / TargetTier.') } else { $contractNotes.Add("Metadata carries BaselineVersion $metaVer and TargetTier $metaTier.") }
}
if ($null -eq $embeddedRegs) { $contractNotes.Add('BaselineRegressions is absent (no -BaselineResults given, or the run predates the baseline).') }
else {
    $contractNotes.Add("BaselineRegressions present: Available=$(Get-NRGObjectField -Item $embeddedRegs -Key 'Available' -Default '?'), Comparable=$(Get-NRGObjectField -Item $embeddedRegs -Key 'Comparable' -Default '?'), $(@(Get-NRGObjectField -Item $embeddedRegs -Key 'Regressions' -Default @()).Count) regression(s). Note: $(Get-NRGObjectField -Item $embeddedRegs -Key 'Note' -Default '')")
}
if ($coverageDropped.Count -gt 0) { $contractNotes.Add("Coverage entries the replay could not restore: $($coverageDropped -join ', ').") }
$skippedCov = @($json.Coverage.Keys | Where-Object { [string](Get-NRGObjectField -Item $json.Coverage[$_] -Key 'Status' -Default '') -eq 'Skipped' })
if ($skippedCov.Count -gt 0) { $contractNotes.Add("Coverage marks $($skippedCov -join ', ') as Skipped. Note: Invoke-NRGAssessment.ps1 -FromResults does not restore 'Skipped' coverage (its filter predates the status), so a republish files those controls as collection-incomplete rather than operator-skipped. Implementation bug candidate in the entry point, not in the baseline.") }

# ── Report ────────────────────────────────────────────────────────────────────
$esc = { param([object] $v) ([string]$v).Replace('|', '\|').Replace("`r", ' ').Replace("`n", ' ') }
$s = $asRun.Summary
$sb = [System.Text.StringBuilder]::new()
$null = $sb.AppendLine("# NRG Security Baseline v$($s.BaselineVersion) — live validation")
$null = $sb.AppendLine()
$null = $sb.AppendLine("**Results file:** $(& $esc (Split-Path -Leaf $ResultsPath))  ")
$null = $sb.AppendLine("**Tenant:** $(& $esc $tenantDomain)  **Run time:** $($runTime.ToString('o'))  **Target tier:** $TargetTier  ")
$null = $sb.AppendLine("**Findings:** $($findings.Count)  **Raw data keys:** $(@($raw.Keys).Count)  **Coverage entries restored:** $coverageRestored  **License data read:** $hasLicData  **Exceptions file:** $(if ($exc.Available) { & $esc $exc.Path } else { 'none' })")
$null = $sb.AppendLine()
$null = $sb.AppendLine('This report changes nothing. It checks every required baseline control against the evidence it was derived from and classifies what it finds. A clean report is one where every row is ExpectedBehavior, LicensingApplicability with the license confirmed, CollectorCoverageGap with a known cause, or EditorialReview with a decision recorded.')
$null = $sb.AppendLine()
$null = $sb.AppendLine('## Summary as the operator saw it')
$null = $sb.AppendLine()
$null = $sb.AppendLine('| | Count |'); $null = $sb.AppendLine('|---|---|')
foreach ($k in @('RequiredControls', 'Satisfied', 'Failed', 'NotVerified', 'LicenseBlocked', 'ApprovedException', 'NotApplicable', 'StaleEvidence', 'NoEvidence')) { $null = $sb.AppendLine("| $k | $($s[$k]) |") }
$null = $sb.AppendLine("| Effectiveness known | $([int]$s.EffectivenessEffective + [int]$s.EffectivenessIneffective) |")
$null = $sb.AppendLine("| Effectiveness unknown | $($s.EffectivenessUnknown) |")
$null = $sb.AppendLine()
$causes = Get-NRGObjectField -Item $s -Key 'NotVerifiedByCause' -Default $null
if ($null -ne $causes -and @($causes.Keys).Count -gt 0) {
    $null = $sb.AppendLine('Not verified, by cause (the engineering list behind the number):')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('| Cause | Controls |'); $null = $sb.AppendLine('|---|---|')
    foreach ($k in @($causes.Keys)) { $null = $sb.AppendLine("| $(& $esc $k) | $($causes[$k]) |") }
    $null = $sb.AppendLine()
}
$null = $sb.AppendLine("Presentation check: configuration satisfied is $($s.Satisfied) of $($s.RequiredControls); effectiveness is known for $([int]$s.EffectivenessEffective + [int]$s.EffectivenessIneffective) of $($s.RequiredControls). Confirm in the HTML that the two are shown as separate blocks and that nothing renders the first as an effectiveness figure.")
$null = $sb.AppendLine()
$null = $sb.AppendLine('## Classification')
$null = $sb.AppendLine()
$null = $sb.AppendLine('| Classification | Controls |'); $null = $sb.AppendLine('|---|---|')
foreach ($g in ($rows | Group-Object Classification | Sort-Object Name)) { $null = $sb.AppendLine("| $($g.Name) | $($g.Count) |") }
$null = $sb.AppendLine()
$null = $sb.AppendLine('## Results contract')
$null = $sb.AppendLine()
foreach ($n in $contractNotes) { $null = $sb.AppendLine("- $(& $esc $n)") }
$null = $sb.AppendLine()
$order = @{ ImplementationBugCandidate = 0; CollectorCoverageGap = 1; LicensingApplicability = 2; EditorialReview = 3; ExpectedBehavior = 4 }
foreach ($cls in ($order.Keys | Sort-Object { $order[$_] })) {
    $set = @($rows | Where-Object { $_.Classification -eq $cls })
    if ($set.Count -eq 0) { continue }
    $null = $sb.AppendLine("## $cls ($($set.Count))")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('| Control | Tier | Baseline | Observed | Finding states | Scope bucket | License | Freshness | Effectiveness | Dependencies | Collectors | Checks | Reason |')
    $null = $sb.AppendLine('|---|---|---|---|---|---|---|---|---|---|---|---|---|')
    foreach ($x in ($set | Sort-Object Tier, ControlId)) {
        $null = $sb.AppendLine("| $($x.ControlId) | $($x.Tier) | **$($x.BaselineStatus)** | $($x.Observed) | $(& $esc $x.FindingStates) | $(& $esc $x.ScopeBucket) | $($x.License) | $($x.Freshness) | $($x.Effectiveness) | $(& $esc $x.Dependencies) | $(& $esc $x.Collectors) | $(& $esc $x.Checks) | $(& $esc $x.Reason) |")
    }
    $null = $sb.AppendLine()
}
$null = $sb.AppendLine('## Operator review of the required set')
$null = $sb.AppendLine()
$null = $sb.AppendLine('For every Minimum and Standard control below, answer one question: if a new client signed tomorrow, would NRG tell its technicians this is what to implement? Record No as a tier change in docs/NRG-SECURITY-BASELINE-CANDIDATES.md before v1.0 is locked.')
$null = $sb.AppendLine()
$null = $sb.AppendLine('| Control | Tier | Owner | Expected state | Keep tier? (Y/N) | Note |'); $null = $sb.AppendLine('|---|---|---|---|---|---|')
foreach ($r in ($asRun.Controls | Where-Object { $_.RequiredTier -in @('Minimum', 'Standard') } | Sort-Object RequiredTier, ControlId)) {
    $null = $sb.AppendLine("| $($r.ControlId) | $($r.RequiredTier) | $($r.Owner) | $(& $esc $r.ExpectedState) |  |  |")
}
$dir = Split-Path -Parent $OutputPath
if ($dir -and -not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) { Set-NRGSensitiveFileContent -Path $OutputPath -Content $sb.ToString() }
else { $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8 }

Write-Host ""
Write-Host "NRG baseline validation: $($rows.Count) required controls checked" -ForegroundColor Cyan
foreach ($g in ($rows | Group-Object Classification | Sort-Object { $order[$_.Name] })) {
    $color = switch ($g.Name) { 'ImplementationBugCandidate' { 'Red' } 'CollectorCoverageGap' { 'Yellow' } 'EditorialReview' { 'Yellow' } default { 'DarkGray' } }
    Write-Host ("  {0,-28} {1,3}" -f $g.Name, $g.Count) -ForegroundColor $color
}
Write-Host "  Report: $OutputPath" -ForegroundColor Green
