#Requires -Version 7.0
#
# Get-TPFleetModel.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: The fleet view for an MSP: every client's saved runs under the
#   output folder, one row per client, built offline from results files. A
#   VIEW like the tenant comparison: it creates no finding, moves no score,
#   reads and writes no module state, and connects to nothing
#   (TP.FleetDashboard.Tests.ps1 enforces that over the AST and tokens).
#
# Rules (each pinned by TP.FleetDashboard.Tests.ps1):
#   - Runs are listed by Get-TPWebRunList (both output layouts, never an
#     incident-response output) and opened only through Resolve-TPWebRunPath
#     and Read-TPRunRecord.
#   - Runs are grouped by tenant: the recorded TenantId first; a run without
#     one joins the client whose name or domain it carries.
#   - Only a FULL run sets a client's score, maturity label, open gap counts,
#     baseline coverage and trend. A partial (-ControlId) or quick (-Quick) run
#     is shown beside it as a re-check and never replaces those figures, so a
#     score never rises because controls dropped out of a run.
#   - Score and maturity label are the values the run RECORDED
#     (Metadata.Maturity), never recomputed; a run that recorded none says so.
#   - Change since the previous full run comes from Get-TPBaselineRegressions
#     (same tenant, same baseline version and tier, or it says the standard
#     changed); a tool-version change and controls added to or removed from
#     the catalog between the two runs are stated beside it.
#   - Age is judged by the NRG Security Baseline's own freshness classes
#     (Config/tp-baseline.json freshnessWindowsDays): Current within the
#     Weekly window, Aging within the Monthly window, Overdue beyond it. No
#     other threshold is invented.
#   - An active client in the clients file with no run at all is listed as
#     never assessed.
#   - -Anonymize labels clients "Client A", "Client B", ... and the model then
#     carries no client name, tenant domain, tenant ID, folder or file name.
#     The model never carries a TenantId or an operator in either mode.
#
# Data consumed: <OutputRoot>/**/<base>-results.json (Metadata, finding
#   states, BaselineCompliance); optionally Config/clients.json (ClientName,
#   TenantDomain, TenantId, DelegatedOrg, Active). Data set: none.
# Graph scopes / cmdlets used: none.

# A tenant id usable for grouping: a GUID, lower-case, and not the all-zero
# placeholder the sample clients file ships with.
function ConvertTo-TPFleetTenantId {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [object] $Value)
    $id = ([string]$Value).Trim().ToLowerInvariant()
    if ($id -cnotmatch '\A[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\z') { return '' }
    if ($id -ceq '00000000-0000-0000-0000-000000000000') { return '' }
    return $id
}

# "Client A" ... "Client Z", "Client AA", ...
function Get-TPFleetAnonymousLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [int] $Index)
    $n = $Index; $s = ''
    do { $s = [char](65 + ($n % 26)) + $s; $n = [math]::Floor($n / 26) - 1 } while ($n -ge 0)
    return "Client $s"
}

# The clients file as records: ClientName, TenantDomain, TenantId,
# DelegatedOrg, Active. A named file that cannot be read throws; no file
# returns an empty list.
function Read-TPFleetClients {
    [CmdletBinding()]
    param([AllowEmptyString()] [string] $ClientsFile)
    $list = [System.Collections.Generic.List[object]]::new()
    if ([string]::IsNullOrEmpty($ClientsFile)) { return , $list }
    if (-not (Test-Path -LiteralPath $ClientsFile -PathType Leaf)) { throw 'The clients file was not found.' }
    try {
        $raw = Get-Content -LiteralPath $ClientsFile -Raw -Encoding utf8 | ConvertFrom-Json -Depth 16 -ErrorAction Stop
    } catch { throw 'The clients file is not valid JSON.' }
    foreach ($c in @(Get-TPObjectField -Item $raw -Key 'clients' -Default @())) {
        if ($null -eq $c) { continue }
        $domain = ([string](Get-TPObjectField -Item $c -Key 'TenantDomain' -Default '')).ToLowerInvariant()
        if (-not (Test-TPDomainName -Value $domain)) { $domain = '' }
        $org = ([string](Get-TPObjectField -Item $c -Key 'DelegatedOrg' -Default '')).ToLowerInvariant()
        if (-not (Test-TPDomainName -Value $org)) { $org = '' }
        $name = ([string](Get-TPObjectField -Item $c -Key 'ClientName' -Default '')) -replace '[\p{C}]', ''
        $name = $name.Trim()
        if ($name.Length -gt 120) { $name = $name.Substring(0, 120) }
        if (-not $name) { $name = $domain }
        if (-not $name -and -not $org) { continue }
        $active = Get-TPObjectField -Item $c -Key 'Active' -Default $true
        $list.Add([ordered]@{
            ClientName   = $name
            TenantDomain = $domain
            DelegatedOrg = $org
            TenantId     = (ConvertTo-TPFleetTenantId (Get-TPObjectField -Item $c -Key 'TenantId' -Default ''))
            Active       = ($active -eq $true)
        })
    }
    return , $list
}

# Open (Gap or Partial) controls by severity, from a run's worst-per-control
# findings.
function Get-TPFleetOpenCounts {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Worst)
    $c = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0; Open = 0; Satisfied = 0; NoVerdict = 0 }
    foreach ($cid in $Worst.Keys) {
        $state = [string](Get-TPObjectField -Item $Worst[$cid] -Key 'State' -Default '')
        if ($state -in @('Gap', 'Partial')) {
            $c.Open++
            $sev = [string](Get-TPObjectField -Item $Worst[$cid] -Key 'Severity' -Default '')
            if ($c.Contains($sev)) { $c[$sev]++ }
        } elseif ($state -eq 'Satisfied') { $c.Satisfied++ }
        else { $c.NoVerdict++ }
    }
    return $c
}

function Get-TPFleetModel {
    <#
    .SYNOPSIS
        Builds the fleet dashboard model from every saved run under an output
        folder. Offline; connects to nothing.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $OutputRoot,
        [AllowEmptyString()] [string] $ClientsFile = '',
        [datetime] $Now = [datetime]::UtcNow,
        [switch] $Anonymize,
        [ValidateRange(2, 52)] [int] $TrendRuns = 12
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $nowUtc = $Now.ToUniversalTime()

    # ── Freshness classes, from the baseline definition ──
    $def = Get-TPBaselineDefinition
    $windows = $def.FreshnessWindowsDays
    $currentDays = [int]$windows['Weekly']
    $overdueDays = [int]$windows['Monthly']
    $freshness = [ordered]@{
        CurrentDays = $currentDays
        OverdueDays = $overdueDays
        Basis       = "Age is judged by the NRG Security Baseline's freshness classes (Config/tp-baseline.json, baseline v$($def.Version)): Current within the Weekly window ($currentDays days), Aging within the Monthly window ($overdueDays days), Overdue beyond it, when the evidence behind every Weekly- and Monthly-class baseline row has expired."
    }

    $clients = Read-TPFleetClients -ClientsFile $ClientsFile
    $controlDefs = @{}
    foreach ($c in @(Get-TPControlDefinitions)) { $controlDefs[[string]$c.ControlId] = $c }
    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Informational = 4 }

    # ── Read every run ──
    $runs = [System.Collections.Generic.List[object]]::new()
    $unreadable = 0; $skippedIr = 0
    foreach ($row in @(Get-TPWebRunList -OutputRoot $OutputRoot -ClientsFile $ClientsFile)) {
        $folder = [string](Get-TPObjectField -Item $row -Key 'folder' -Default '')
        $id     = [string](Get-TPObjectField -Item $row -Key 'id' -Default '')
        $found  = Resolve-TPWebRunPath -OutputRoot $OutputRoot -Folder $folder -Id $id -Kind Results
        if ($found.Status -ne 'Ok') { continue }
        try { $rec = Read-TPRunRecord -Path $found.Path } catch { $unreadable++; continue }
        if ($rec.IsIncidentResponse) { $skippedIr++; continue }
        $meta = $rec.Metadata
        $time = Get-TPRunRecordTime -Record $rec
        $timeSource = 'recorded'
        if ($null -eq $time) { $time = ([datetime]$rec.FileWriteTimeUtc).ToUniversalTime(); $timeSource = 'file' }
        $domain = ([string](Get-TPObjectField -Item $meta -Key 'TenantDomain' -Default '')).ToLowerInvariant()
        if (-not (Test-TPDomainName -Value $domain)) { $domain = '' }
        $runs.Add([ordered]@{
            Label       = ([string](Get-TPObjectField -Item $row -Key 'tenant' -Default '')).ToLowerInvariant()
            Domain      = $domain
            TenantId    = (ConvertTo-TPFleetTenantId (Get-TPObjectField -Item $meta -Key 'TenantId' -Default ''))
            Time        = $time
            TimeSource  = $timeSource
            Scope       = (Get-TPRunScope -Metadata $meta)
            Metadata    = $meta
            Worst       = (Get-TPControlWorstFindings -Findings @($rec.Findings))
            Baseline    = $rec.BaselineCompliance
            ToolVersion = [string](Get-TPObjectField -Item $meta -Key 'ToolVersion' -Default '')
        })
    }

    # ── Group by tenant ──
    $groups = [ordered]@{}
    $nameToKey = @{}
    foreach ($r in @($runs | Where-Object { $_.TenantId })) {
        $key = 'id:' + $r.TenantId
        if (-not $groups.Contains($key)) { $groups[$key] = [System.Collections.Generic.List[object]]::new() }
        $groups[$key].Add($r)
        foreach ($n in @($r.Label, $r.Domain)) { if ($n) { $nameToKey[$n] = $key } }
    }
    foreach ($cl in $clients) {
        if ($cl.TenantId -and $groups.Contains('id:' + $cl.TenantId)) {
            foreach ($n in @($cl.TenantDomain, $cl.DelegatedOrg)) { if ($n) { $nameToKey[$n] = 'id:' + $cl.TenantId } }
        }
    }
    foreach ($r in @($runs | Where-Object { -not $_.TenantId })) {
        $key = $null
        foreach ($n in @($r.Label, $r.Domain)) { if ($n -and $nameToKey.ContainsKey($n)) { $key = $nameToKey[$n]; break } }
        if (-not $key) { $key = 'name:' + $(if ($r.Label) { $r.Label } else { $r.Domain }) }
        if (-not $groups.Contains($key)) { $groups[$key] = [System.Collections.Generic.List[object]]::new() }
        $groups[$key].Add($r)
    }

    # ── One row per client ──
    $rows = [System.Collections.Generic.List[object]]::new()
    $matchedClients = [System.Collections.Generic.HashSet[int]]::new()
    $toolVersions = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($key in $groups.Keys) {
        $all = @($groups[$key] | Sort-Object { $_.Time })
        $names = [System.Collections.Generic.HashSet[string]]::new()
        $tid = ''
        foreach ($r in $all) { foreach ($n in @($r.Label, $r.Domain)) { if ($n) { $null = $names.Add($n) } }; if ($r.TenantId) { $tid = $r.TenantId } }

        # The client record, by tenant id first, then by domain.
        $client = $null
        for ($i = 0; $i -lt $clients.Count; $i++) {
            $cl = $clients[$i]
            if (($tid -and $cl.TenantId -eq $tid) -or ($cl.TenantDomain -and $names.Contains($cl.TenantDomain)) -or ($cl.DelegatedOrg -and $names.Contains($cl.DelegatedOrg))) {
                $client = $cl; $null = $matchedClients.Add($i); break
            }
        }
        $latestAny = $all[-1]
        $displayName = if ($client) { $client.ClientName } elseif ($latestAny.Label) { $latestAny.Label } else { $latestAny.Domain }
        $fulls = @($all | Where-Object { $_.Scope -eq 'Full' })
        $notes = [System.Collections.Generic.List[string]]::new()
        if ($client -and -not $client.Active) { $notes.Add('Marked inactive in the clients file.') }
        if (-not $client -and $clients.Count -gt 0) { $notes.Add('Not in the clients file.') }

        $entry = [ordered]@{
            Name          = $displayName
            Domain        = $(if ($client -and $client.TenantDomain) { $client.TenantDomain } else { $latestAny.Domain })
            Status        = 'NoFullRun'
            Active        = $(if ($client) { $client.Active } else { $null })
            RunCount      = $all.Count
            FullRunCount  = $fulls.Count
            LatestFull    = $null
            Trend         = @()
            Change        = $null
            Recheck       = $null
            Notes         = $notes
        }

        if ($fulls.Count -gt 0) {
            $lf = $fulls[-1]
            $null = $toolVersions.Add($lf.ToolVersion)
            $mat = Get-TPObjectField -Item $lf.Metadata -Key 'Maturity' -Default $null
            $scoreRaw = Get-TPObjectField -Item $mat -Key 'Score' -Default $null
            $score = $null
            if ($null -ne $scoreRaw -and "$scoreRaw" -match '\A\d{1,3}(\.\d+)?\z') { $score = [int][math]::Round([double]"$scoreRaw") }
            $open = Get-TPFleetOpenCounts -Worst $lf.Worst
            $age = ($nowUtc - $lf.Time).TotalDays
            $bc = $lf.Baseline
            $ev = Get-TPObjectField -Item $bc -Key 'EvidenceCoverage' -Default $null
            $past = 0; $required = 0
            foreach ($bRow in @(Get-TPObjectField -Item $bc -Key 'Controls' -Default @())) {
                if ($null -eq $bRow) { continue }
                $required++
                $cls = [string](Get-TPObjectField -Item $bRow -Key 'FreshnessClass' -Default '')
                if ($cls -and $windows.Contains($cls) -and $age -gt [int]$windows[$cls]) { $past++ }
            }
            $entry.Status = if ($age -le $currentDays) { 'Current' } elseif ($age -le $overdueDays) { 'Aging' } else { 'Overdue' }
            $entry.LatestFull = [ordered]@{
                RunTime          = $lf.Time.ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture) + ' UTC'
                RunDate          = $lf.Time.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
                TimeSource       = $lf.TimeSource
                AgeDays          = [int][math]::Floor([math]::Max($age, 0))
                Score            = $score
                MaturityLabel    = [string](Get-TPObjectField -Item $mat -Key 'Label' -Default '')
                MaturityRecorded = ($null -ne $mat)
                EvidenceComplete = [bool](Get-TPObjectField -Item $mat -Key 'EvidenceComplete' -Default $false)
                ToolVersion      = $lf.ToolVersion
                Controls         = $lf.Worst.Count
                OpenCritical     = $open.Critical
                OpenHigh         = $open.High
                OpenMedium       = $open.Medium
                OpenLow          = $open.Low
                NoVerdict        = $open.NoVerdict
                BaselineVersion  = [string](Get-TPObjectField -Item $bc -Key 'BaselineVersion' -Default '')
                TargetTier       = [string](Get-TPObjectField -Item $bc -Key 'TargetTier' -Default '')
                BaselineRecorded = ($null -ne $bc)
                EvidencePercent  = $(if ($null -ne $ev) { Get-TPObjectField -Item $ev -Key 'Percent' -Default $null } else { $null })
                EvidenceKnown    = $(if ($null -ne $ev) { Get-TPObjectField -Item $ev -Key 'Known' -Default $null } else { $null })
                EvidenceApplicable = $(if ($null -ne $ev) { Get-TPObjectField -Item $ev -Key 'Applicable' -Default $null } else { $null })
                PastWindow       = $past
                RequiredRows     = $required
                OpenControlIds   = @($lf.Worst.Keys | Where-Object { [string](Get-TPObjectField -Item $lf.Worst[$_] -Key 'State' -Default '') -in @('Gap', 'Partial') })
            }
            if ($lf.TimeSource -eq 'file') { $notes.Add('The latest full run records no assessment time; the results file''s write time is used for its age.') }
            if (-not $entry.LatestFull.MaturityRecorded) { $notes.Add('The latest full run recorded no score or maturity label.') }

            # Trend over full runs only, oldest first.
            $trend = [System.Collections.Generic.List[object]]::new()
            foreach ($r in @($fulls | Select-Object -Last $TrendRuns)) {
                $m = Get-TPObjectField -Item $r.Metadata -Key 'Maturity' -Default $null
                $s = Get-TPObjectField -Item $m -Key 'Score' -Default $null
                if ($null -ne $s -and "$s" -match '\A\d{1,3}(\.\d+)?\z') {
                    $trend.Add([ordered]@{ Date = $r.Time.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture); Score = [int][math]::Round([double]"$s"); ToolVersion = $r.ToolVersion })
                }
            }
            $entry.Trend = $trend.ToArray()

            # Change since the previous full run.
            if ($fulls.Count -ge 2) {
                $pf = $fulls[-2]
                $reg = Get-TPBaselineRegressions -Current $lf.Baseline -Prior $pf.Baseline -PriorRunTime ($pf.Time.ToString('o')) -Detected $nowUtc
                $added = @($lf.Worst.Keys | Where-Object { -not $pf.Worst.Contains($_) })
                $removed = @($pf.Worst.Keys | Where-Object { -not $lf.Worst.Contains($_) })
                $entry.Change = [ordered]@{
                    PreviousRunDate        = $pf.Time.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
                    Available              = [bool]$reg.Available
                    Comparable             = [bool]$reg.Comparable
                    Note                   = [string]$reg.Note
                    Regressed              = @(@($reg.Regressions) | Where-Object { $_.Kind -eq 'ConfigurationRegressed' } | ForEach-Object { [string]$_.ControlId })
                    EvidenceLost           = @(@($reg.Regressions) | Where-Object { $_.Kind -eq 'EvidenceLost' } | ForEach-Object { [string]$_.ControlId })
                    Resolved               = @(@($reg.Improvements) | ForEach-Object { [string]$_.ControlId })
                    PreviousToolVersion    = $pf.ToolVersion
                    ToolVersionChanged     = ($pf.ToolVersion -ne $lf.ToolVersion)
                    ControlsAdded          = $added.Count
                    ControlsRemoved        = $removed.Count
                }
                if ($entry.Change.ToolVersionChanged) {
                    $notes.Add("Compared across tool versions ($(if ($pf.ToolVersion) { $pf.ToolVersion } else { 'not recorded' }) to $(if ($lf.ToolVersion) { $lf.ToolVersion } else { 'not recorded' })): a change can come from the tool (a tightened check, a new control) as well as from the tenant.")
                }
                if ($added.Count -gt 0 -or $removed.Count -gt 0) {
                    $notes.Add("The control catalog differs between the two full runs: $($added.Count) control(s) only in the latest, $($removed.Count) only in the previous. Those are not compared.")
                }
            }
        } else {
            $notes.Add('No full run on record: only partial or quick re-checks, which describe the controls they selected and nothing else.')
        }

        # A partial or quick run newer than the latest full run: shown, never scored.
        $newestFullTime = if ($fulls.Count -gt 0) { $fulls[-1].Time } else { [datetime]::MinValue }
        $re = @($all | Where-Object { $_.Scope -ne 'Full' -and $_.Time -gt $newestFullTime })
        if ($re.Count -gt 0) {
            $last = $re[-1]
            $sel = Get-TPObjectField -Item $last.Metadata -Key 'ControlSelection' -Default $null
            $counts = Get-TPFleetOpenCounts -Worst $last.Worst
            $entry.Recheck = [ordered]@{
                Kind          = $last.Scope
                RunDate       = $last.Time.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture)
                Selected      = $(if ($last.Scope -eq 'Partial') { [int](Get-TPObjectField -Item $sel -Key 'SelectedCount' -Default 0) } else { $last.Worst.Count })
                TotalControls = [int](Get-TPObjectField -Item $sel -Key 'TotalControls' -Default 0)
                Patterns      = @(@(Get-TPObjectField -Item $sel -Key 'Include' -Default @()) | Where-Object { $_ } | ForEach-Object { [string]$_ })
                Satisfied     = $counts.Satisfied
                Open          = $counts.Open
                NoVerdict     = $counts.NoVerdict
                Count         = $re.Count
            }
        }
        $rows.Add($entry)
    }

    # ── Active clients with no run at all ──
    $never = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $clients.Count; $i++) {
        if ($matchedClients.Contains($i)) { continue }
        $cl = $clients[$i]
        if (-not $cl.Active) { continue }
        $never.Add([ordered]@{ Name = $cl.ClientName; Domain = $cl.TenantDomain; Status = 'NeverAssessed' })
    }

    # ── Order: what needs attention first ──
    $statusOrder = @{ Overdue = 0; NoFullRun = 1; Aging = 2; Current = 3 }
    $sorted = @($rows | Sort-Object @{ Expression = { $statusOrder[$_.Status] } },
        @{ Expression = { if ($_.LatestFull) { -([int]$_.LatestFull.OpenCritical * 1000 + [int]$_.LatestFull.OpenHigh) } else { 0 } } },
        @{ Expression = { [string]$_.Name } })

    # ── Fleet KPIs ──
    $withFull = @($sorted | Where-Object { $_.LatestFull })
    $openCrit = 0; $openHigh = 0
    foreach ($r in $withFull) { $openCrit += [int]$r.LatestFull.OpenCritical; $openHigh += [int]$r.LatestFull.OpenHigh }
    $gapCount = @{}
    foreach ($r in $withFull) { foreach ($cid in @($r.LatestFull.OpenControlIds)) { $gapCount[$cid] = 1 + ($gapCount[$cid] ?? 0) } }
    $top = @($gapCount.Keys | ForEach-Object {
        $d = if ($controlDefs.ContainsKey($_)) { $controlDefs[$_] } else { $null }
        [ordered]@{
            ControlId = [string]$_
            Title     = [string](Get-TPObjectField -Item $d -Key 'Title' -Default '')
            Severity  = [string](Get-TPObjectField -Item $d -Key 'Severity' -Default '')
            Clients   = [int]$gapCount[$_]
        }
    } | Sort-Object @{ Expression = { -$_.Clients } }, @{ Expression = { $sevRank[[string]$_.Severity] ?? 9 } }, @{ Expression = { $_.ControlId } } | Select-Object -First 10)

    $kpis = [ordered]@{
        Clients        = $sorted.Count + $never.Count
        WithRuns       = $sorted.Count
        InWindow       = @($withFull | Where-Object { $_.Status -in @('Current', 'Aging') }).Count
        Current        = @($withFull | Where-Object { $_.Status -eq 'Current' }).Count
        Aging          = @($withFull | Where-Object { $_.Status -eq 'Aging' }).Count
        Overdue        = @($withFull | Where-Object { $_.Status -eq 'Overdue' }).Count
        NoFullRun      = @($sorted | Where-Object { $_.Status -eq 'NoFullRun' }).Count
        NeverAssessed  = $never.Count
        OpenCritical   = $openCrit
        OpenHigh       = $openHigh
    }

    $fleetNotes = [System.Collections.Generic.List[string]]::new()
    $versions = @($toolVersions | Where-Object { $_ } | Sort-Object)
    if ($versions.Count -gt 1) { $fleetNotes.Add("The latest full runs were made by different tool versions ($($versions -join ', ')), so scores are compared across tool versions: a check tightened or added between versions moves a score without the tenant changing.") }
    if ($unreadable -gt 0) { $fleetNotes.Add("$unreadable results file(s) could not be read and are not shown.") }
    $fleetNotes.Add('Scores and maturity labels are the values each run recorded. Open counts are controls whose worst finding is a Gap or Partial in the latest full run; a control that was not assessed is neither open nor passed.')

    # ── Anonymize: no name, domain or tenant identifier leaves the model ──
    $idx = 0
    foreach ($r in @($sorted) + @($never)) {
        if ($Anonymize) { $r.Name = Get-TPFleetAnonymousLabel -Index $idx; $r.Domain = '' }
        $idx++
    }
    foreach ($r in $sorted) { $r.Notes = @($r.Notes) }

    return [ordered]@{
        Available     = ($runs.Count -gt 0)
        Note          = $(if ($runs.Count -gt 0) { '' } else { 'No assessment runs were found under the output folder.' })
        GeneratedAt   = $nowUtc
        Anonymized    = [bool]$Anonymize
        Freshness     = $freshness
        Kpis          = $kpis
        TopGaps       = $top
        Clients       = $sorted
        NeverAssessed = $never.ToArray()
        RunsRead      = $runs.Count
        Notes         = $fleetNotes.ToArray()
    }
}
