#Requires -Version 7.0
#
# Invoke-TPMcpTool.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose:  The tools of the local, read-only MCP server (Start-TPMcpServer.ps1):
#           their definitions (input and output schemas) and what each returns
#           from past assessment results files.
# Consumes: results files under the output folder, resolved only through
#           Resolve-TPWebRunPath -Kind Results and listed only through
#           Get-TPWebRunList; Config/controls.json, Config/benchmark-mappings.json,
#           Config/operational-impact.json and Config/tp-baseline.json through
#           the module's own readers.
# Graph scopes / cmdlets used: none. No network, no sign-in, no file write.
#
# Rules every tool keeps (docs/TP-MCP-SERVER.md):
#   * A run is addressed by (folder, id) exactly as list_runs returned them; no
#     argument is ever a path.
#   * NotApplicable, Error and "no finding" are never a pass; a value the
#     results file does not record is reported as not recorded, never
#     recomputed or guessed (get_scope says when it computes, and from what).
#   * RawData, the Exceptions array, TenantId, the operator's account and file
#     paths are never returned. Identities are pseudonymized unless the operator
#     started the server with -IncludeIdentities.
#   * Tenant-controlled text (policy, rule and group names, finding detail) is
#     returned only as values of JSON fields.

# A tool failure the model should see (isError content), as opposed to a
# protocol error. The message is fixed text and never echoes an argument. The
# marker lives in the exception's Data so the dispatcher can tell it from a
# fault in the server itself (whose text is never returned).
function Stop-TPMcpTool {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Message)
    $e = [System.InvalidOperationException]::new($Message)
    $e.Data['TPMcpToolError'] = $true
    throw $e
}

function Get-TPMcpNotPassNote {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return 'NotApplicable, Error and a control with no finding are not passes: each means the tool reached no verdict (not assessed, not licensed, skipped, or the check failed). Only Satisfied is a pass.'
}

# ── Definitions ──────────────────────────────────────────────────────────────

function Get-TPMcpToolDefinitions {
    [CmdletBinding()]
    [OutputType([object[]])]
    param()

    $folder = [ordered]@{ type = 'string'; description = 'The run''s folder exactly as list_runs returned it (a tenant folder name, or _flat for the output folder itself).'; maxLength = 255 }
    $id     = [ordered]@{ type = 'string'; description = 'The run''s id exactly as list_runs returned it.'; maxLength = 255 }
    $cid    = [ordered]@{ type = 'string'; description = 'A control ID such as AAD-1.1, EXO-7.2 or DEV-8.3.'; maxLength = 32 }
    $obj    = [ordered]@{ type = 'object' }
    $arr    = [ordered]@{ type = 'array' }
    $str    = [ordered]@{ type = 'string' }
    $int    = [ordered]@{ type = 'integer' }
    $bool   = [ordered]@{ type = 'boolean' }
    $ro     = [ordered]@{ readOnlyHint = $true; destructiveHint = $false; idempotentHint = $true; openWorldHint = $false }
    $states = @('Satisfied', 'Partial', 'Gap', 'NotApplicable', 'Error')

    $tool = {
        param([string] $Name, [string] $Title, [string] $Description, $Properties, [string[]] $Required, $Output, [string[]] $OutputRequired)
        [ordered]@{
            name         = $Name
            title        = $Title
            description  = $Description
            inputSchema  = [ordered]@{ type = 'object'; properties = $Properties; required = @($Required); additionalProperties = $false }
            outputSchema = [ordered]@{ type = 'object'; properties = $Output; required = @($OutputRequired) }
            annotations  = $ro
        }
    }

    return @(
        (& $tool 'list_runs' 'List assessment runs' 'Lists the TenantPosture assessment runs saved under the output folder, newest first: tenant label, folder and id (the address every other tool takes), assessment date, tool version and control count. Incident-response outputs are never listed.' `
            ([ordered]@{
                tenant = [ordered]@{ type = 'string'; description = 'Optional: only runs whose tenant label contains this text (case-insensitive).'; maxLength = 253 }
                limit  = [ordered]@{ type = 'integer'; description = 'Maximum runs to return (default 50, at most 200).'; minimum = 1; maximum = 200 }
            }) @() `
            ([ordered]@{ runs = $arr; total = $int; returned = $int; truncated = $bool; note = $str }) @('runs', 'total', 'returned', 'truncated'))

        (& $tool 'get_run_summary' 'Summarize one run' 'Summarizes one assessment run: metadata, the maturity label and score as the run recorded them, finding counts by state and severity, worst state per control, the NRG Security Baseline version, tier and its evidence and effectiveness coverage lines, and the license profile read from the run''s subscribed SKUs.' `
            ([ordered]@{ folder = $folder; id = $id }) @('folder', 'id') `
            ([ordered]@{ run = $obj; maturity = $obj; findingInstances = $obj; controls = $obj; baseline = $obj; license = $obj; notes = $arr }) @('run', 'maturity', 'findingInstances', 'controls', 'baseline', 'license', 'notes'))

        (& $tool 'list_findings' 'List findings of one run' 'Lists the findings of one run with a short detail, optionally filtered by state, severity, workload or control ID. A control can have several findings (one per DNS domain, for example).' `
            ([ordered]@{
                folder    = $folder
                id        = $id
                state     = [ordered]@{ type = 'string'; enum = $states; description = 'Optional state filter.' }
                severity  = [ordered]@{ type = 'string'; enum = @('Critical', 'High', 'Medium', 'Low', 'Informational'); description = 'Optional severity filter.' }
                workload  = [ordered]@{ type = 'string'; description = 'Optional workload filter: the control ID prefix (AAD, EXO, DEF, TMS, SPO, PVW, INT, PPL, DNS, DEV).'; maxLength = 8 }
                controlId = $cid
                limit     = [ordered]@{ type = 'integer'; description = 'Maximum findings to return (default 50, at most 200).'; minimum = 1; maximum = 200 }
            }) @('folder', 'id') `
            ([ordered]@{ findings = $arr; total = $int; returned = $int; truncated = $bool; note = $str }) @('findings', 'total', 'returned', 'truncated', 'note'))

        (& $tool 'get_finding' 'Get the findings for one control' 'Returns every finding one run recorded for one control: state, detail, current and required value, remediation, framework citations and affected objects (capped).' `
            ([ordered]@{ folder = $folder; id = $id; controlId = $cid }) @('folder', 'id', 'controlId') `
            ([ordered]@{ controlId = $str; instances = $arr; worstState = $str; note = $str }) @('controlId', 'instances', 'note'))

        (& $tool 'get_control' 'Describe one control' 'Describes one control from the tool''s catalog (no run needed): definition, license requirement, framework references, configuration benchmark mapping, operational impact of remediating it, and its NRG Security Baseline row if it has one.' `
            ([ordered]@{ controlId = $cid }) @('controlId') `
            ([ordered]@{ control = $obj; benchmarks = $obj; operationalImpact = $obj; baseline = $obj }) @('control', 'benchmarks', 'operationalImpact', 'baseline'))

        (& $tool 'compare_runs' 'Compare two runs of one tenant' 'Compares two runs of the SAME tenant (A before, B after): controls whose worst state changed, new and resolved gaps, and controls present in only one run. Refuses two different tenants; that comparison is Compare-TPTenantBaseline.ps1, run offline.' `
            ([ordered]@{ folderA = $folder; idA = $id; folderB = $folder; idB = $id }) @('folderA', 'idA', 'folderB', 'idB') `
            ([ordered]@{ runA = $obj; runB = $obj; changed = $arr; newGaps = $arr; resolvedGaps = $arr; onlyInA = $arr; onlyInB = $arr; unchangedCount = $int; notes = $arr }) @('runA', 'runB', 'changed', 'newGaps', 'resolvedGaps', 'onlyInA', 'onlyInB', 'unchangedCount', 'notes'))

        (& $tool 'get_baseline' 'Get the baseline rows of one run' 'Returns the NRG Security Baseline rows the run recorded (BaselineCompliance): per required control the tier, observed state, display status, reason code and reason. Optionally filtered by status.' `
            ([ordered]@{
                folder = $folder
                id     = $id
                status = [ordered]@{ type = 'string'; enum = @('Satisfied', 'Failed', 'NotVerified', 'NotApplicable', 'LicenseBlocked', 'ApprovedException'); description = 'Optional filter on the row''s display status (BaselineStatus).' }
                limit  = [ordered]@{ type = 'integer'; description = 'Maximum rows to return (default 100, at most 200).'; minimum = 1; maximum = 200 }
            }) @('folder', 'id') `
            ([ordered]@{ recorded = $bool; baselineVersion = $str; targetTier = $str; summary = $obj; evidenceCoverage = $obj; effectivenessCoverage = $obj; rows = $arr; total = $int; returned = $int; truncated = $bool; note = $str }) @('recorded', 'rows', 'note'))

        (& $tool 'get_scope' 'What one run did not assess' 'Lists which controls the run did not reach a verdict on and why (collection incomplete, license blocked, skipped by the operator, no automated check, no result), with the plain-language limitations. Computed from the results file the way a -FromResults republish does; the answer says so.' `
            ([ordered]@{ folder = $folder; id = $id }) @('folder', 'id') `
            ([ordered]@{ computed = $bool; basis = $str; totalControls = $int; scoredControls = $int; unscoredControls = $int; buckets = $obj; coverageIssues = $arr; limitations = $arr }) @('computed', 'basis', 'buckets', 'limitations'))

        (& $tool 'get_change_impact' 'What fixing each open item would break' 'Returns the change-impact view the run recorded: its open findings sorted into implementNow (licensed and invisible to users), needsPlanning (someone will notice), couldBreakAccounts (can lock a person, an administrator, a device or a mailbox out) and licenseDecision, and for each risky change the accounts the run''s data shows would be affected, how complete that evidence is, what the tool cannot see, and the emergency-access accounts to exclude. Optionally one list, or one control.' `
            ([ordered]@{
                folder    = $folder
                id        = $id
                list      = [ordered]@{ type = 'string'; enum = @('implementNow', 'needsPlanning', 'couldBreakAccounts', 'licenseDecision'); description = 'Optional: return only this list.' }
                controlId = $cid
            }) @('folder', 'id') `
            ([ordered]@{ recorded = $bool; summary = $obj; implementNow = $arr; needsPlanning = $arr; couldBreakAccounts = $arr; licenseDecision = $arr; emergencyAccess = $obj; scopeNotice = $str; note = $str }) @('recorded', 'note'))
    )
}

# ── Shared helpers ───────────────────────────────────────────────────────────

# The run named by (folder, id), loaded, or a tool error with a fixed message.
function Get-TPMcpRunByAddress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Ctx,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Folder,
        [Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Id
    )
    $found = Resolve-TPWebRunPath -OutputRoot $Ctx.OutputRoot -Folder $Folder -Id $Id -Kind Results
    if ($found.Status -eq 'BadRequest') { Stop-TPMcpTool -Message 'folder and id must be the values list_runs returned (letters, digits, dot, underscore and hyphen only).' }
    if ($found.Status -ne 'Ok') { Stop-TPMcpTool -Message 'No assessment run with that folder and id. Call list_runs for the runs that exist.' }
    try {
        $run = Get-TPMcpRun -Path $found.Path -Cache $Ctx.RunCache
    } catch {
        [Console]::Error.WriteLine("tenantposture-mcp: results file not read: $($_.Exception.Message)")
        Stop-TPMcpTool -Message 'That run''s results file could not be read.'
    }
    if ($run.IsIncidentResponse) { Stop-TPMcpTool -Message 'No assessment run with that folder and id. Incident-response outputs are never served.' }
    if ($null -ne $Ctx.Pseudo -and -not $run.Contains('IdentitiesLearned')) {
        foreach ($f in @($run.Findings)) {
            Import-TPMcpIdentities -State $Ctx.Pseudo -Value (Get-TPObjectField -Item $f -Key 'AffectedObjects' -Default $null)
        }
        # The accounts the change-impact view names (DisplayName, UserPrincipalName).
        if ($null -ne $run.ChangeImpact) { Import-TPMcpIdentities -State $Ctx.Pseudo -Value $run.ChangeImpact }
        $run['IdentitiesLearned'] = $true
    }
    return $run
}

function Get-TPMcpWorkload {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter()] [AllowNull()] [AllowEmptyString()] [string] $ControlId)
    if ($ControlId -cmatch '\A([A-Z]{2,6})-') { return $Matches[1] }
    return ''
}

function Test-TPMcpControlId {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter()] [AllowNull()] [AllowEmptyString()] [string] $Value)
    return ($Value -cmatch '\A[A-Z]{2,6}-\d{1,3}(\.\d{1,3}){1,3}\z')
}

# The run's identity block: no TenantId, no operator, no path.
function Get-TPMcpRunHeader {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowNull()] [object] $Metadata,
        [Parameter(Mandatory)] [string] $Folder,
        [Parameter(Mandatory)] [string] $Id
    )
    $time = Get-TPObjectField -Item $Metadata -Key 'AssessmentTime' -Default $null
    $timeText = if ($time -is [datetime]) { $time.ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture) } elseif ($time) { [string]$time } else { '' }
    return [ordered]@{
        folder              = $Folder
        id                  = $Id
        tenantDomain        = [string](Get-TPObjectField -Item $Metadata -Key 'TenantDomain' -Default '')
        assessmentTime      = $timeText
        assessmentDate      = [string](Get-TPObjectField -Item $Metadata -Key 'AssessmentDate' -Default '')
        toolVersion         = [string](Get-TPObjectField -Item $Metadata -Key 'ToolVersion' -Default '')
        quickScan           = [bool](Get-TPObjectField -Item $Metadata -Key 'QuickScan' -Default $false)
        thirdPartyEDR       = [string](Get-TPObjectField -Item $Metadata -Key 'ThirdPartyEDR' -Default '')
        thirdPartyAwareness = [string](Get-TPObjectField -Item $Metadata -Key 'ThirdPartyAwareness' -Default '')
        baselineVersion     = [string](Get-TPObjectField -Item $Metadata -Key 'BaselineVersion' -Default '')
        targetTier          = [string](Get-TPObjectField -Item $Metadata -Key 'TargetTier' -Default '')
    }
}

# Worst state per control, by the tool's one order (Get-TPStateSeverityRank).
function Get-TPMcpWorstStates {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [hashtable] $Ctx,
        [Parameter()] [AllowNull()] [AllowEmptyCollection()] [object[]] $Findings
    )
    $rank = $Ctx.StateRank
    $worst = @{}
    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $cid = [string](Get-TPObjectField -Item $f -Key 'ControlId' -Default '')
        if (-not $cid) { continue }
        $state = [string](Get-TPObjectField -Item $f -Key 'State' -Default '')
        if (-not $worst.ContainsKey($cid)) { $worst[$cid] = $f; continue }
        $old = [string](Get-TPObjectField -Item $worst[$cid] -Key 'State' -Default '')
        if (($rank[$state] ?? 0) -gt ($rank[$old] ?? 0)) { $worst[$cid] = $f }
    }
    return $worst
}

function Get-TPMcpIntArg {
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter()] [AllowNull()] [object] $Value, [int] $Default, [int] $Max)
    if ($null -eq $Value) { return $Default }
    $n = [int]$Value
    if ($n -lt 1) { return 1 }
    if ($n -gt $Max) { return $Max }
    return $n
}

# ── Tools ────────────────────────────────────────────────────────────────────

function Invoke-TPMcpListRuns {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Ctx, [Parameter(Mandatory)] [hashtable] $Arguments)

    $limit  = Get-TPMcpIntArg -Value $Arguments['limit'] -Default 50 -Max 200
    $filter = [string]($Arguments['tenant'] ?? '')
    $rows = @(Get-TPWebRunList -OutputRoot $Ctx.OutputRoot -ClientsFile $Ctx.ClientsFile -MetadataCache $Ctx.MetaCache)
    $out = [System.Collections.Generic.List[object]]::new()
    $total = 0
    foreach ($r in $rows) {
        $label = [string](Get-TPObjectField -Item $r -Key 'tenant' -Default '')
        if ($filter -and $label.IndexOf($filter, [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
        $folderSeg = [string](Get-TPObjectField -Item $r -Key 'folder' -Default '')
        $idSeg     = [string](Get-TPObjectField -Item $r -Key 'id' -Default '')
        $found = Resolve-TPWebRunPath -OutputRoot $Ctx.OutputRoot -Folder $folderSeg -Id $idSeg -Kind Results
        if ($found.Status -ne 'Ok') { continue }
        $file  = Get-Item -LiteralPath $found.Path
        $stamp = '{0}|{1}|{2}' -f $file.FullName, $file.Length, $file.LastWriteTimeUtc.Ticks
        $summary = $null
        if ($Ctx.SummaryCache.ContainsKey($stamp)) {
            $summary = $Ctx.SummaryCache[$stamp]
        } else {
            try {
                $run = Read-TPMcpRunFile -Path $found.Path
                $ids = @($run.Findings | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'ControlId' -Default '') } | Where-Object { $_ } | Sort-Object -Unique)
                $hdr = Get-TPMcpRunHeader -Metadata $run.Metadata -Folder $folderSeg -Id $idSeg
                $summary = [ordered]@{
                    Skip         = [bool]$run.IsIncidentResponse
                    Date         = $(if ($hdr.assessmentTime) { $hdr.assessmentTime } else { [string](Get-TPObjectField -Item $r -Key 'timestamp' -Default '') })
                    DateSource   = $(if ($hdr.assessmentTime) { 'Metadata.AssessmentTime' } else { 'file write time' })
                    ToolVersion  = $hdr.toolVersion
                    ControlCount = $ids.Count
                    FindingCount = @($run.Findings).Count
                    Baseline     = ($null -ne $run.BaselineCompliance)
                }
            } catch {
                [Console]::Error.WriteLine("tenantposture-mcp: a results file was not read for the listing: $($_.Exception.Message)")
                $summary = [ordered]@{ Skip = $false; Date = [string](Get-TPObjectField -Item $r -Key 'timestamp' -Default ''); DateSource = 'file write time'; ToolVersion = ''; ControlCount = $null; FindingCount = $null; Baseline = $false; Unreadable = $true }
            }
            $Ctx.SummaryCache[$stamp] = $summary
        }
        if ($summary.Skip) { continue }
        $total++
        if ($out.Count -ge $limit) { continue }
        $out.Add([ordered]@{
            tenant           = $label
            folder           = $folderSeg
            id               = $idSeg
            date             = $summary.Date
            dateSource       = $summary.DateSource
            toolVersion      = $summary.ToolVersion
            controlCount     = $summary.ControlCount
            findingCount     = $summary.FindingCount
            baselineRecorded = [bool]$summary.Baseline
            readable         = -not [bool](Get-TPObjectField -Item $summary -Key 'Unreadable' -Default $false)
        })
    }
    return [ordered]@{
        runs      = $out.ToArray()
        total     = $total
        returned  = $out.Count
        truncated = ($total -gt $out.Count)
        note      = 'The tenant label is for display: pass folder and id, exactly as given, to the other tools.'
    }
}

function Invoke-TPMcpRunSummary {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Ctx, [Parameter(Mandatory)] [hashtable] $Arguments)

    $run = Get-TPMcpRunByAddress -Ctx $Ctx -Folder $Arguments['folder'] -Id $Arguments['id']
    $meta = $run.Metadata
    $findings = @($run.Findings)

    # Maturity: as the run recorded it, never recomputed here.
    $mat = Get-TPObjectField -Item $meta -Key 'Maturity' -Default $null
    $maturity = if ($null -ne $mat) {
        $m = [ordered]@{ recorded = $true }
        foreach ($k in 'Label', 'ObservedLabel', 'Tier', 'Score', 'EvidenceComplete', 'Qualification', 'ScoredControls', 'ErrorFindings', 'UnknownStates', 'CriticalGaps', 'HighGaps', 'Satisfied', 'Partial', 'Gap', 'NotApplicable', 'Total') {
            $v = Get-TPMcpField -Item $mat -Key $k
            if ($null -ne $v) { $m[$k] = $v }
        }
        $m
    } else {
        [ordered]@{ recorded = $false; note = 'The results file records no maturity label or score.' }
    }

    $byState = [ordered]@{}; $bySeverity = [ordered]@{}
    foreach ($f in $findings) {
        $s = [string](Get-TPObjectField -Item $f -Key 'State' -Default '(none)')
        $v = [string](Get-TPObjectField -Item $f -Key 'Severity' -Default '(none)')
        $byState[$s] = 1 + ($byState[$s] ?? 0)
        $bySeverity[$v] = 1 + ($bySeverity[$v] ?? 0)
    }
    $worst = Get-TPMcpWorstStates -Ctx $Ctx -Findings $findings
    $ctlState = [ordered]@{}; $openBySeverity = [ordered]@{}
    foreach ($cid in @($worst.Keys | Sort-Object)) {
        $s = [string](Get-TPObjectField -Item $worst[$cid] -Key 'State' -Default '(none)')
        $ctlState[$s] = 1 + ($ctlState[$s] ?? 0)
        if ($s -in @('Gap', 'Partial')) {
            $v = [string](Get-TPObjectField -Item $worst[$cid] -Key 'Severity' -Default '(none)')
            $openBySeverity[$v] = 1 + ($openBySeverity[$v] ?? 0)
        }
    }

    $bc = $run.BaselineCompliance
    $baseline = if ($null -ne $bc -and [bool](Get-TPObjectField -Item $bc -Key 'Available' -Default $true)) {
        $sum = Get-TPObjectField -Item $bc -Key 'Summary' -Default $null
        $s = [ordered]@{ recorded = $true
            baselineVersion = [string](Get-TPObjectField -Item $bc -Key 'BaselineVersion' -Default '')
            targetTier      = [string](Get-TPObjectField -Item $bc -Key 'TargetTier' -Default '')
            counts          = [ordered]@{} }
        foreach ($k in 'RequiredControls', 'Satisfied', 'Failed', 'NotVerified', 'NotApplicable', 'LicenseBlocked', 'ApprovedException', 'StaleEvidence', 'NoEvidence') {
            $s.counts[$k] = Get-TPObjectField -Item $sum -Key $k -Default $null
        }
        $ev  = Get-TPMcpField -Item $bc -Key 'EvidenceCoverage'
        $eff = Get-TPMcpField -Item $bc -Key 'EffectivenessCoverage'
        $s['evidenceCoverage']      = $(if ($null -ne $ev)  { $ev }  else { [ordered]@{ recorded = $false; note = 'Not recorded in this results file.' } })
        $s['effectivenessCoverage'] = $(if ($null -ne $eff) { $eff } else { [ordered]@{ recorded = $false; note = 'Not recorded in this results file.' } })
        $s['note'] = 'Coverage lines are not scores: they say how much of the baseline the evidence reached, not how well the tenant meets it.'
        $s
    } else {
        [ordered]@{ recorded = $false; note = 'The results file records no NRG Security Baseline view (older run, or the view was not resolved).' }
    }

    $skus = @($run.SubscribedSkus)
    $license = if ($skus.Count -gt 0) {
        $lp = Get-TPTenantLicenseProfile -SubscribedSkus $skus
        $l = [ordered]@{ read = $true; source = 'The run''s subscribed SKUs (RawData AAD-Inventory).' }
        foreach ($p in $lp.PSObject.Properties) {
            if ($p.Name -eq 'TierLabel' -or ($p.Name -like 'Has*' -and $p.Value -is [bool])) { $l[$p.Name] = $p.Value }
        }
        $l
    } else {
        [ordered]@{ read = $false; note = 'Licensing was not read in this run (no subscribed SKUs in the results file). Unknown licensing is not "unlicensed".' }
    }

    return [ordered]@{
        run              = Get-TPMcpRunHeader -Metadata $meta -Folder ([string]$Arguments['folder']) -Id ([string]$Arguments['id'])
        maturity         = $maturity
        findingInstances = [ordered]@{ total = $findings.Count; byState = $byState; bySeverity = $bySeverity }
        controls         = [ordered]@{ total = $worst.Count; byWorstState = $ctlState; openBySeverity = $openBySeverity; rule = 'One row per control at its worst instance: Gap > Error > Partial > NotApplicable > Satisfied. openBySeverity counts Gap and Partial controls.' }
        baseline         = $baseline
        license          = $license
        notes            = @(
            (Get-TPMcpNotPassNote)
            'Counts describe this run''s results file only; the maturity label and score are the values the run recorded.'
        )
    }
}

function Invoke-TPMcpListFindings {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Ctx, [Parameter(Mandatory)] [hashtable] $Arguments)

    $run = Get-TPMcpRunByAddress -Ctx $Ctx -Folder $Arguments['folder'] -Id $Arguments['id']
    $limit = Get-TPMcpIntArg -Value $Arguments['limit'] -Default 50 -Max 200
    $state = [string]($Arguments['state'] ?? ''); $sev = [string]($Arguments['severity'] ?? '')
    $wl = [string]($Arguments['workload'] ?? ''); $cid = [string]($Arguments['controlId'] ?? '')
    if ($cid -and -not (Test-TPMcpControlId -Value $cid)) { Stop-TPMcpTool -Message 'controlId must look like AAD-1.1.' }

    $rows = [System.Collections.Generic.List[object]]::new()
    $total = 0
    foreach ($f in @($run.Findings)) {
        $fid = [string](Get-TPObjectField -Item $f -Key 'ControlId' -Default '')
        $fs  = [string](Get-TPObjectField -Item $f -Key 'State' -Default '')
        $fv  = [string](Get-TPObjectField -Item $f -Key 'Severity' -Default '')
        $fw  = Get-TPMcpWorkload -ControlId $fid
        if ($state -and $fs -ne $state) { continue }
        if ($sev -and $fv -ne $sev) { continue }
        if ($wl -and $fw -ne $wl.ToUpperInvariant()) { continue }
        if ($cid -and $fid -ne $cid) { continue }
        $total++
        if ($rows.Count -ge $limit) { continue }
        $rows.Add([ordered]@{
            controlId = $fid
            title     = [string](Get-TPObjectField -Item $f -Key 'Title' -Default '')
            state     = $fs
            severity  = $fv
            workload  = $fw
            instance  = [string](Get-TPObjectField -Item $f -Key 'Instance' -Default '')
            detail    = [string](Get-TPObjectField -Item $f -Key 'Detail' -Default '')
        })
    }
    return [ordered]@{
        findings  = $rows.ToArray()
        total     = $total
        returned  = $rows.Count
        truncated = ($total -gt $rows.Count)
        note      = (Get-TPMcpNotPassNote) + ' Detail is shortened here; get_finding returns it in full.'
    }
}

function Invoke-TPMcpGetFinding {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Ctx, [Parameter(Mandatory)] [hashtable] $Arguments)

    $cid = [string]$Arguments['controlId']
    if (-not (Test-TPMcpControlId -Value $cid)) { Stop-TPMcpTool -Message 'controlId must look like AAD-1.1.' }
    $run = Get-TPMcpRunByAddress -Ctx $Ctx -Folder $Arguments['folder'] -Id $Arguments['id']
    $fields = 'ControlId', 'State', 'Severity', 'Category', 'Title', 'Instance', 'Detail', 'CurrentValue', 'RequiredValue', 'Remediation', 'FrameworkIds', 'AffectedObjects', 'Coverage', 'Timestamp'
    $instances = [System.Collections.Generic.List[object]]::new()
    foreach ($f in @($run.Findings)) {
        if ([string](Get-TPObjectField -Item $f -Key 'ControlId' -Default '') -ne $cid) { continue }
        $one = [ordered]@{}
        foreach ($k in $fields) { $one[$k] = Get-TPMcpField -Item $f -Key $k }
        $instances.Add($one)
    }
    if ($instances.Count -eq 0) {
        return [ordered]@{
            controlId  = $cid
            instances  = @()
            worstState = ''
            note       = 'This run recorded no finding for this control. That is not a pass: the control was not evaluated in this run (get_scope says why when it can).'
        }
    }
    $w = Get-TPMcpWorstStates -Ctx $Ctx -Findings $instances.ToArray()
    return [ordered]@{
        controlId  = $cid
        instances  = $instances.ToArray()
        worstState = [string](Get-TPObjectField -Item $w[$cid] -Key 'State' -Default '')
        note       = (Get-TPMcpNotPassNote) + ' AffectedObjects lists are capped; the results file holds every entry.'
    }
}

function Invoke-TPMcpGetControl {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Ctx, [Parameter(Mandatory)] [hashtable] $Arguments)

    $cid = [string]$Arguments['controlId']
    if (-not (Test-TPMcpControlId -Value $cid)) { Stop-TPMcpTool -Message 'controlId must look like AAD-1.1.' }
    $def = @(Get-TPControlDefinitions) | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'ControlId' -Default '') -ceq $cid } | Select-Object -First 1
    if ($null -eq $def) { Stop-TPMcpTool -Message 'That control ID is not in this tool''s control catalog (Config/controls.json). Endpoint DEV-* checks are defined in Config/device-controls.json and are not described here.' }

    $control = [ordered]@{}
    foreach ($k in 'ControlId', 'Title', 'Description', 'BusinessRisk', 'Severity', 'Workload', 'Category', 'Automated', 'CollectorDependency', 'EvaluatorFunction', 'LicenseRequirement', 'Remediation', 'References') {
        $control[$k] = Get-TPMcpField -Item $def -Key $k
    }

    if ($null -eq $Ctx.Benchmarks) { $Ctx.Benchmarks = Get-TPBenchmarkMapping }
    $bm = $Ctx.Benchmarks
    $benchmarks = if (-not [bool](Get-TPObjectField -Item $bm -Key 'Available' -Default $false)) {
        [ordered]@{ mapped = $false; note = 'The benchmark mapping could not be read.' }
    } elseif ($bm.Controls.Contains($cid)) {
        [ordered]@{ mapped = $true; items = @($bm.Controls[$cid]) }
    } elseif ($bm.Unmapped.Contains($cid)) {
        [ordered]@{ mapped = $false; reason = [string]$bm.Unmapped[$cid].Reason; earnBy = [string]$bm.Unmapped[$cid].EarnBy }
    } else {
        [ordered]@{ mapped = $false; note = 'Not listed in the benchmark mapping.' }
    }

    $impact = Get-TPControlOperationalImpact -ControlId $cid -Catalog (Get-TPOperationalImpactCatalog)
    $operationalImpact = if ($null -ne $impact) {
        $o = [ordered]@{ documented = $true }
        foreach ($k in @($impact.Keys)) { $o[$k] = $impact[$k] }
        $o
    } else {
        [ordered]@{ documented = $false; note = 'Operational impact not documented. That is not "no impact": nobody has recorded what enabling it changes.' }
    }

    $bdef = Get-TPBaselineDefinition
    $baseline = if ($bdef.Controls.Contains($cid)) {
        $row = $bdef.Controls[$cid]
        $b = [ordered]@{ inBaseline = $true; baselineVersion = $bdef.Version }
        foreach ($k in 'Tier', 'Title', 'Owner', 'ExpectedState', 'EvidenceSource', 'SlaClass', 'FreshnessClass', 'EffectivenessCapability', 'Cis', 'CisProfile', 'CisRelation') { $b[$k] = $row[$k] }
        $b
    } else {
        [ordered]@{ inBaseline = $false; baselineVersion = $bdef.Version; note = 'Not a row of the NRG Security Baseline: the control is assessment-only and never required by a tier.' }
    }

    return [ordered]@{ control = $control; benchmarks = $benchmarks; operationalImpact = $operationalImpact; baseline = $baseline }
}

function Invoke-TPMcpCompareRuns {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Ctx, [Parameter(Mandatory)] [hashtable] $Arguments)

    $a = Get-TPMcpRunByAddress -Ctx $Ctx -Folder $Arguments['folderA'] -Id $Arguments['idA']
    $b = Get-TPMcpRunByAddress -Ctx $Ctx -Folder $Arguments['folderB'] -Id $Arguments['idB']
    # The same guard as Publish-TPDeltaReport: both runs must carry a tenant ID
    # and it must be the same one. The IDs are compared, never returned.
    $ta = [string](Get-TPObjectField -Item $a.Metadata -Key 'TenantId' -Default '')
    $tb = [string](Get-TPObjectField -Item $b.Metadata -Key 'TenantId' -Default '')
    if ([string]::IsNullOrWhiteSpace($ta) -or [string]::IsNullOrWhiteSpace($tb) -or -not $ta.Equals($tb, [System.StringComparison]::OrdinalIgnoreCase)) {
        Stop-TPMcpTool -Message 'Refusing to compare: the two runs do not carry the same tenant ID (or one carries none), so this would not be one tenant''s drift. To compare two different tenants against the NRG Security Baseline, run Compare-TPTenantBaseline.ps1 offline.'
    }

    $hA = Get-TPMcpRunHeader -Metadata $a.Metadata -Folder ([string]$Arguments['folderA']) -Id ([string]$Arguments['idA'])
    $hB = Get-TPMcpRunHeader -Metadata $b.Metadata -Folder ([string]$Arguments['folderB']) -Id ([string]$Arguments['idB'])
    $wA = Get-TPMcpWorstStates -Ctx $Ctx -Findings @($a.Findings)
    $wB = Get-TPMcpWorstStates -Ctx $Ctx -Findings @($b.Findings)
    $verdict = @{ Satisfied = 0; Partial = 1; Gap = 2 }   # the states that are verdicts, best to worst
    $open = @('Gap', 'Partial')

    $changed = [System.Collections.Generic.List[object]]::new()
    $newGaps = [System.Collections.Generic.List[object]]::new()
    $resolved = [System.Collections.Generic.List[object]]::new()
    $onlyA = [System.Collections.Generic.List[string]]::new()
    $onlyB = [System.Collections.Generic.List[string]]::new()
    $same = 0
    foreach ($cid in @(@($wA.Keys) + @($wB.Keys) | Sort-Object -Unique)) {
        if (-not $wB.ContainsKey($cid)) { $onlyA.Add($cid); continue }
        if (-not $wA.ContainsKey($cid)) { $onlyB.Add($cid); continue }
        $sa = [string](Get-TPObjectField -Item $wA[$cid] -Key 'State' -Default '')
        $sb = [string](Get-TPObjectField -Item $wB[$cid] -Key 'State' -Default '')
        if ($sa -eq $sb) { $same++; continue }
        $direction = if ($verdict.ContainsKey($sa) -and $verdict.ContainsKey($sb)) {
            if ($verdict[$sb] -gt $verdict[$sa]) { 'Regressed' } else { 'Improved' }
        } else { 'VerdictChanged' }
        $row = [ordered]@{
            controlId = $cid
            title     = [string](Get-TPObjectField -Item $wB[$cid] -Key 'Title' -Default '')
            severity  = [string](Get-TPObjectField -Item $wB[$cid] -Key 'Severity' -Default '')
            before    = $sa
            after     = $sb
            direction = $direction
        }
        $changed.Add($row)
        if ($sb -in $open -and $sa -notin $open) { $newGaps.Add($row) }
        if ($sa -in $open -and $sb -eq 'Satisfied') { $resolved.Add($row) }
    }

    $notes = [System.Collections.Generic.List[string]]::new()
    $notes.Add('States are each control''s worst instance. VerdictChanged means one side is NotApplicable or Error (no verdict): a gap that became NotApplicable or Error is not resolved, it is no longer assessed.')
    $notes.Add('newGaps: Gap or Partial in B and neither in A. resolvedGaps: Gap or Partial in A and Satisfied in B.')
    if ($hA.toolVersion -ne $hB.toolVersion) { $notes.Add('The runs were made by different tool versions, so a change can come from the tool (a tightened check, a new control) as well as from the tenant.') }
    if ($hA.baselineVersion -and $hB.baselineVersion -and $hA.baselineVersion -ne $hB.baselineVersion) { $notes.Add('The NRG Security Baseline version differs between the runs: the standard changed, which this comparison does not judge.') }
    if ($hA.assessmentTime -and $hB.assessmentTime -and ([string]$hB.assessmentTime -lt [string]$hA.assessmentTime)) { $notes.Add('Run B is older than run A; before and after follow the order given, not the dates.') }

    return [ordered]@{
        runA           = $hA
        runB           = $hB
        changed        = $changed.ToArray()
        newGaps        = $newGaps.ToArray()
        resolvedGaps   = $resolved.ToArray()
        onlyInA        = $onlyA.ToArray()
        onlyInB        = $onlyB.ToArray()
        unchangedCount = $same
        notes          = $notes.ToArray()
    }
}

function Invoke-TPMcpGetBaseline {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Ctx, [Parameter(Mandatory)] [hashtable] $Arguments)

    $run = Get-TPMcpRunByAddress -Ctx $Ctx -Folder $Arguments['folder'] -Id $Arguments['id']
    $bc = $run.BaselineCompliance
    if ($null -eq $bc -or -not [bool](Get-TPObjectField -Item $bc -Key 'Available' -Default $true)) {
        return [ordered]@{ recorded = $false; rows = @(); note = 'The results file records no NRG Security Baseline view (older run, or the view was not resolved). It is not recomputed here.' }
    }
    $limit = Get-TPMcpIntArg -Value $Arguments['limit'] -Default 100 -Max 200
    $status = [string]($Arguments['status'] ?? '')
    $rows = [System.Collections.Generic.List[object]]::new()
    $total = 0
    foreach ($r in @(Get-TPObjectField -Item $bc -Key 'Controls' -Default @())) {
        if ($null -eq $r) { continue }
        $bs = [string](Get-TPObjectField -Item $r -Key 'BaselineStatus' -Default '')
        if ($status -and $bs -ne $status) { continue }
        $total++
        if ($rows.Count -ge $limit) { continue }
        $rows.Add([ordered]@{
            controlId          = [string](Get-TPObjectField -Item $r -Key 'ControlId' -Default '')
            title              = [string](Get-TPObjectField -Item $r -Key 'Title' -Default '')
            tier               = [string](Get-TPObjectField -Item $r -Key 'RequiredTier' -Default '')
            observedState      = [string](Get-TPObjectField -Item $r -Key 'ObservedState' -Default '')
            baselineStatus     = $bs
            constraint         = [string](Get-TPObjectField -Item $r -Key 'Constraint' -Default '')
            disposition        = [string](Get-TPObjectField -Item $r -Key 'Disposition' -Default '')
            effectivenessState = [string](Get-TPObjectField -Item $r -Key 'EffectivenessState' -Default '')
            reasonCode         = [string](Get-TPObjectField -Item $r -Key 'ReasonCode' -Default '')
            reason             = [string](Get-TPObjectField -Item $r -Key 'Reason' -Default '')
        })
    }
    $sum = Get-TPObjectField -Item $bc -Key 'Summary' -Default $null
    $summary = [ordered]@{}
    foreach ($k in 'RequiredControls', 'Satisfied', 'Failed', 'NotVerified', 'NotApplicable', 'LicenseBlocked', 'ApprovedException') { $summary[$k] = Get-TPObjectField -Item $sum -Key $k -Default $null }
    $ev  = Get-TPMcpField -Item $bc -Key 'EvidenceCoverage'
    $eff = Get-TPMcpField -Item $bc -Key 'EffectivenessCoverage'
    return [ordered]@{
        recorded              = $true
        baselineVersion       = [string](Get-TPObjectField -Item $bc -Key 'BaselineVersion' -Default '')
        targetTier            = [string](Get-TPObjectField -Item $bc -Key 'TargetTier' -Default '')
        summary               = $summary
        evidenceCoverage      = $(if ($null -ne $ev)  { $ev }  else { [ordered]@{ recorded = $false } })
        effectivenessCoverage = $(if ($null -ne $eff) { $eff } else { [ordered]@{ recorded = $false } })
        rows                  = $rows.ToArray()
        total                 = $total
        returned              = $rows.Count
        truncated             = ($total -gt $rows.Count)
        note                  = 'Rows as the run recorded them. NotVerified, NotApplicable and LicenseBlocked are not passes; an ApprovedException is a disposition beside the observed state, never a change to it. Coverage lines are not scores.'
    }
}

function Invoke-TPMcpGetChangeImpact {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Ctx, [Parameter(Mandatory)] [hashtable] $Arguments)

    $run = Get-TPMcpRunByAddress -Ctx $Ctx -Folder $Arguments['folder'] -Id $Arguments['id']
    $ci = $run.ChangeImpact
    if ($null -eq $ci -or -not [bool](Get-TPObjectField -Item $ci -Key 'Available' -Default $false)) {
        return [ordered]@{ recorded = $false; note = 'The results file records no change-impact view (a run made before this tool version, or the view failed). It is not recomputed here; republish the run with Invoke-TPAssessment.ps1 -FromResults to add it.' }
    }
    $cidArg = [string]($Arguments['controlId'] ?? '')
    if ($cidArg -and -not (Test-TPMcpControlId -Value $cidArg)) { Stop-TPMcpTool -Message 'controlId must look like AAD-1.1.' }
    $names = [ordered]@{ implementNow = 'ImplementNow'; needsPlanning = 'NeedsPlanning'; couldBreakAccounts = 'CouldBreakAccounts'; licenseDecision = 'LicenseDecision' }
    $want = [string]($Arguments['list'] ?? '')
    $out = [ordered]@{ recorded = $true; summary = (Get-TPMcpField -Item $ci -Key 'Summary') }
    foreach ($k in $names.Keys) {
        if ($want -and $k -ne $want) { continue }
        # Get-TPMcpField returns the list whole; assign it before enumerating.
        $list = Get-TPMcpField -Item $ci -Key $names[$k]
        $items = @($list | Where-Object { $null -ne $_ })
        if ($cidArg) { $items = @($items | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'ControlId' -Default '') -eq $cidArg }) }
        $out[$k] = $items
    }
    $out['emergencyAccess'] = Get-TPMcpField -Item $ci -Key 'EmergencyAccess'
    $out['scopeNotice'] = [string](Get-TPObjectField -Item $ci -Key 'ScopeNotice' -Default '')
    $out['note'] = 'As the run recorded it. Accounts are named only from what the run read: a block whose status is NotRead or NotEstablished, or that is not Complete, is not a list of everyone affected, and NoneFound never means nothing can break. EmergencyAccess accounts are to be excluded from a new policy, not fixed. Changes nothing in the tenant.'
    if ($cidArg -and -not (@($names.Keys | Where-Object { $out.Contains($_) -and @($out[$_]).Count -gt 0 }).Count)) {
        $out['note'] = 'This control is not open in this run (or not in the list asked for), so it is in none of the lists. ' + $out['note']
    }
    return $out
}

function Invoke-TPMcpGetScope {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [hashtable] $Ctx, [Parameter(Mandatory)] [hashtable] $Arguments)

    $run = Get-TPMcpRunByAddress -Ctx $Ctx -Folder $Arguments['folder'] -Id $Arguments['id']
    $coverage = @{}
    if ($run.Coverage -is [System.Collections.IDictionary]) { foreach ($k in @($run.Coverage.Keys)) { $coverage[[string]$k] = $run.Coverage[$k] } }
    $skus = @($run.SubscribedSkus)
    $lp = if ($skus.Count -gt 0) { Get-TPTenantLicenseProfile -SubscribedSkus $skus } else { $null }
    $quick = [bool](Get-TPObjectField -Item $run.Metadata -Key 'QuickScan' -Default $false)
    $scope = Get-TPAssessmentScope -Findings @($run.Findings) -Coverage $coverage -RawData $run.RawDataStatus -LicenseProfile $lp -QuickScan:$quick

    $bucketNames = [ordered]@{
        CollectionIncomplete  = 'CollectionIncomplete'
        NoResult              = 'NoResult'
        Errors                = 'Errors'
        StandardNotApproved   = 'StandardNotApproved'
        SkippedByOperator     = 'SkippedByOperator'
        NotEvaluatedThisMode  = 'NotEvaluatedThisMode'
        LicenceBlocked        = 'LicenseBlocked'
        ThirdPartyAttested    = 'ThirdPartyAttested'
        NoProgrammaticCheck   = 'NoProgrammaticCheck'
        NotApplicableToTenant = 'NotApplicableToTenant'
    }
    $buckets = [ordered]@{}
    foreach ($src in $bucketNames.Keys) {
        $rows = @(Get-TPObjectField -Item $scope -Key $src -Default @() | Where-Object { $null -ne $_ } | ForEach-Object {
            [ordered]@{
                controlId = [string](Get-TPObjectField -Item $_ -Key 'ControlId' -Default '')
                title     = [string](Get-TPObjectField -Item $_ -Key 'Title' -Default '')
                severity  = [string](Get-TPObjectField -Item $_ -Key 'Severity' -Default '')
                reason    = [string](Get-TPObjectField -Item $_ -Key 'Reason' -Default '')
            }
        })
        $buckets[$bucketNames[$src]] = [ordered]@{ count = $rows.Count; controls = $rows }
    }
    $covIssues = @(Get-TPObjectField -Item $scope -Key 'CoverageIssues' -Default @() | Where-Object { $null -ne $_ } | ForEach-Object {
        [ordered]@{
            collector = [string](Get-TPObjectField -Item $_ -Key 'Family' -Default '')
            status    = [string](Get-TPObjectField -Item $_ -Key 'Status' -Default '')
            note      = [string](Get-TPObjectField -Item $_ -Key 'Note' -Default '')
        }
    })
    $runVersion = [string](Get-TPObjectField -Item $run.Metadata -Key 'ToolVersion' -Default '')
    $basis = 'Computed now from the results file (findings, collector coverage, which collectors succeeded, and the subscribed SKUs), the way a -FromResults republish computes it; the results file does not store this section. The control catalog is this tool''s (' + $Ctx.ToolVersion + ')' +
        $(if ($runVersion -and $runVersion -ne $Ctx.ToolVersion) { '; the run was made by ' + $runVersion + ', so a control added since appears under NoResult.' } else { '.' })
    if (-not $run.HasRawData) { $basis += ' The results file carries no collector status, so a collector failure can only be seen from the findings'' own detail.' }
    return [ordered]@{
        computed         = [bool](Get-TPObjectField -Item $scope -Key 'Available' -Default $false)
        basis            = $basis
        totalControls    = [int](Get-TPObjectField -Item $scope -Key 'TotalControls' -Default 0)
        scoredControls   = [int](Get-TPObjectField -Item $scope -Key 'ScoredControls' -Default 0)
        unscoredControls = [int](Get-TPObjectField -Item $scope -Key 'UnscoredControls' -Default 0)
        buckets          = $buckets
        coverageIssues   = $covIssues
        limitations      = @(Get-TPObjectField -Item $scope -Key 'Limitations' -Default @())
    }
}

# ── Dispatch ─────────────────────────────────────────────────────────────────

# Validates arguments against the tool's input schema (unknown keys, types,
# enums, bounds, required). Returns $null when valid, else a fixed message.
function Test-TPMcpArguments {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Schema,
        [Parameter(Mandatory)] [hashtable] $Arguments
    )
    $props = $Schema['properties']
    foreach ($k in @($Arguments.Keys)) {
        if (-not $props.Contains([string]$k)) { return "Unknown argument. Allowed: $(@($props.Keys) -join ', ')." }
    }
    foreach ($r in @($Schema['required'])) {
        if (-not $Arguments.ContainsKey($r) -or $null -eq $Arguments[$r] -or ([string]$Arguments[$r]) -eq '') { return "Missing required argument: $r." }
    }
    foreach ($k in @($Arguments.Keys)) {
        $p = $props[[string]$k]; $v = $Arguments[$k]
        if ($null -eq $v) { continue }
        switch ($p['type']) {
            'string' {
                if ($v -isnot [string]) { return "Argument $k must be a string." }
                if ($p.Contains('maxLength') -and $v.Length -gt $p['maxLength']) { return "Argument $k is too long." }
                if ($p.Contains('enum') -and @($p['enum']) -cnotcontains $v) { return "Argument $k must be one of: $(@($p['enum']) -join ', ')." }
            }
            'integer' {
                $isInt = ($v -is [int] -or $v -is [long]) -or ($v -is [double] -and [math]::Floor($v) -eq $v)
                if (-not $isInt) { return "Argument $k must be an integer." }
                if ($p.Contains('minimum') -and $v -lt $p['minimum']) { return "Argument $k must be at least $($p['minimum'])." }
                if ($p.Contains('maximum') -and $v -gt $p['maximum']) { return "Argument $k must be at most $($p['maximum'])." }
            }
        }
    }
    return $null
}

# Runs one tool. Returns the result object; throws through Stop-TPMcpTool for a tool
# failure the model should see.
function Invoke-TPMcpTool {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Ctx,
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)] [hashtable] $Arguments
    )
    $impl = @{
        list_runs       = 'Invoke-TPMcpListRuns'
        get_run_summary = 'Invoke-TPMcpRunSummary'
        list_findings   = 'Invoke-TPMcpListFindings'
        get_finding     = 'Invoke-TPMcpGetFinding'
        get_control     = 'Invoke-TPMcpGetControl'
        compare_runs    = 'Invoke-TPMcpCompareRuns'
        get_baseline    = 'Invoke-TPMcpGetBaseline'
        get_scope       = 'Invoke-TPMcpGetScope'
        get_change_impact = 'Invoke-TPMcpGetChangeImpact'
    }
    $def = @(Get-TPMcpToolDefinitions) | Where-Object { $_['name'] -ceq $Name } | Select-Object -First 1
    if ($null -eq $def -or -not $impl.ContainsKey($Name)) { throw [System.ArgumentException]::new('Unknown tool.') }
    $bad = Test-TPMcpArguments -Schema $def['inputSchema'] -Arguments $Arguments
    if ($bad) { Stop-TPMcpTool -Message $bad }
    $result = & $impl[$Name] -Ctx $Ctx -Arguments $Arguments

    # Every value leaves through the same filter. Catalog text (get_control) is
    # the tool's own and is not pseudonymized; run data is.
    $state = if ($Name -eq 'get_control') { $null } else { $Ctx.Pseudo }
    $maxLen = switch ($Name) { 'list_findings' { 300 } 'list_runs' { 300 } 'get_baseline' { 600 } 'get_scope' { 600 } default { 4000 } }
    $maxItems = switch ($Name) { 'get_finding' { 50 } 'get_control' { 100 } default { 250 } }
    return (Protect-TPMcpValue -Value $result -State $state -MaxLength $maxLen -MaxItems $maxItems -MaxDepth 10)
}
