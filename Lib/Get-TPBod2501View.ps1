#Requires -Version 7.0
#
# Get-TPBod2501View.ps1
# Dependencies: Get-TPObjectField, Get-TPControlDefinitions, Get-TPScubaAlignment,
#               Get-TPSSPConfigFile, Read-TPScubaResults (optional),
#               Config/bod-25-01-required.json, Config/scuba-alignment.json
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Builds the CISA BOD 25-01 required-configurations view: every
#          Microsoft 365 policy CISA lists as required under Binding Operational
#          Directive 25-01, joined to the controls that cite it
#          (References.SCuBA), the recorded relation of each control to the
#          rule (Config/scuba-alignment.json) and this run's findings, with an
#          independent ScubaGear result beside it when one is supplied.
#
#          The rules, which are the SSP's and the HIPAA view's:
#            * The required list is CISA's, encoded as data with its source
#              and retrieval date. Nothing is derived from "every SHALL".
#            * Statuses are technical, never "compliant" (Get-TPBod2501StatusNames,
#              the one copy of the strings). 'Tool-verified: met' needs every
#              citing control whose relation is Equivalent to be Satisfied;
#              any Equivalent control with a Gap or Partial is 'Tool-verified:
#              shortfall'. A policy evidenced only by Partial-relation
#              controls, or by a mix with an Equivalent control that produced
#              no verdict, is 'Partly checked', and the view names what the
#              tool does not check. Citing controls that produced no verdict
#              (no finding, NotApplicable, Error, not selected) leave it 'Not
#              assessed'. A policy no control establishes (no citation, or
#              only Manual / Unsupported relations, listed as cited, not
#              counted) is 'Manual evidence required'; a product this tool does
#              not read is 'Product not assessed by this tool'.
#            * A control's state across its instance findings: any Gap, then
#              any Partial (a known shortfall is never hidden behind an
#              instance that could not be evaluated, since an Error is no
#              verdict), then any state that is not a verdict (NotRun), then
#              NotApplicable, Satisfied only when every instance passed. The
#              same order the HIPAA view uses.
#            * An independent ScubaGear result is shown beside the tool's own
#              and a difference in direction is flagged 'Results differ -
#              review'. Neither result is preferred; ScubaGear's report is what
#              CISA expects agencies to submit.
#            * This is a VIEW: no findings, no score, no module state written.
#
# Inputs:  -Findings          assessment findings (shape-agnostic).
#          -ScubaResults      optional map of ScubaGear 'Control ID' -> 'Result'.
#          -ScubaResultsPath  optional ScubaGear results file (CSV or JSON).
#          -ConfigPath        optional override for Config/bod-25-01-required.json.
#
# Outputs: [ordered] hashtable - Policies, Products, Summary, Available.
#
# Consumes: findings + Config/bod-25-01-required.json + Config/scuba-alignment.json
#           + Config/controls.json. No Graph, no EXO, no network.
#

$script:TPBod2501Catalog = $null

# The row statuses, in one place: the publisher, the entry point and the tests
# read these rather than repeating the strings. None of them states that a
# requirement of the directive is fulfilled.
$script:TPBod2501Status = [ordered]@{
    Met                = 'Tool-verified: met'
    Shortfall          = 'Tool-verified: shortfall'
    Partly             = 'Partly checked'
    NotAssessed        = 'Not assessed'
    Manual             = 'Manual evidence required'
    ProductNotAssessed = 'Product not assessed by this tool'
}

# The flag on a policy whose tool status and independent ScubaGear result point
# in opposite directions.
$script:TPBod2501Differ = "Results differ $([char]0x2014) review"

function Get-TPBod2501StatusNames {
    [CmdletBinding()]
    param()
    return $script:TPBod2501Status
}

function Get-TPBod2501DifferLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return $script:TPBod2501Differ
}

function Get-TPBod2501Catalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $ConfigPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ($script:TPBod2501Catalog -and -not $ConfigPath) { return $script:TPBod2501Catalog }
    $data = Get-TPSSPConfigFile -FileName 'bod-25-01-required.json' -ConfigPath $ConfigPath
    if (-not $data) { return $null }
    if (-not $ConfigPath) { $script:TPBod2501Catalog = $data }
    return $data
}

function Get-TPBod2501View {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()] [AllowEmptyCollection()]
        [object[]] $Findings,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [System.Collections.IDictionary] $ScubaResults,

        [Parameter(Mandatory = $false)]
        [string] $ScubaResultsPath,

        [Parameter(Mandatory = $false)]
        [string] $ConfigPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $st = $script:TPBod2501Status

    $empty = [ordered]@{
        Policies = @(); Products = @()
        Summary = [ordered]@{ Total = 0; ByStatus = [ordered]@{}; Mapped = 0; Equivalent = 0; PartialOnly = 0; NotCounted = 0; Uncited = 0; Differ = 0 }
        Available = $false
        UnavailableReason = 'bod-25-01-required.json missing or empty'
    }

    $cat = if ($ConfigPath) { Get-TPBod2501Catalog -ConfigPath $ConfigPath } else { Get-TPBod2501Catalog }
    if (-not $cat) { return $empty }
    $policies = @(Get-TPObjectField -Item $cat -Key 'policies' -Default @())
    if ($policies.Count -eq 0) { return $empty }

    # Fail closed: without the control definitions every policy would read
    # 'Manual evidence required', a plausible view built on nothing.
    $defs = @()
    try { $defs = @(Get-TPControlDefinitions) } catch {
        $empty['UnavailableReason'] = "controls.json could not be loaded: $($_.Exception.Message)"
        return $empty
    }
    if (@($defs | Where-Object { $null -ne $_ }).Count -eq 0) {
        $empty['UnavailableReason'] = 'controls.json returned no control definitions'
        return $empty
    }
    $align = Get-TPScubaAlignment
    if (-not $align.Available) {
        $empty['UnavailableReason'] = 'scuba-alignment.json missing or unreadable: the relation of each control to its rule is unknown'
        return $empty
    }

    # ── Independent ScubaGear results ────────────────────────────────────────
    # An unreadable or foreign file costs the comparison only, never the view.
    $scubaError = ''
    if ($null -eq $ScubaResults -and $ScubaResultsPath) {
        if (-not (Test-Path -LiteralPath $ScubaResultsPath -PathType Leaf)) {
            $scubaError = 'The ScubaGear results file was not found.'
        } elseif (-not (Get-Command Read-TPScubaResults -ErrorAction SilentlyContinue)) {
            $scubaError = 'The ScubaGear results reader is not loaded.'
        } else {
            try { $ScubaResults = Read-TPScubaResults -Path $ScubaResultsPath }
            catch { $scubaError = "The ScubaGear results file could not be read: $($_.Exception.Message)" }
        }
    }
    $haveScuba = ($null -ne $ScubaResults -and $ScubaResults.Count -gt 0)

    # ── Products ─────────────────────────────────────────────────────────────
    $products = [ordered]@{}
    foreach ($p in @(Get-TPObjectField -Item $cat -Key 'products' -Default @())) {
        $k = [string](Get-TPObjectField -Item $p -Key 'Key' -Default '')
        if (-not $k) { continue }
        $products[$k] = [ordered]@{
            Key            = $k
            Name           = [string](Get-TPObjectField -Item $p -Key 'Name' -Default $k)
            AssessedByTool = ((Get-TPObjectField -Item $p -Key 'AssessedByTool' -Default $false) -eq $true)
        }
    }

    # ── Citations: rule id -> controls ───────────────────────────────────────
    $citers = @{}
    $meta = @{}
    foreach ($d in $defs) {
        $cid = [string](Get-TPObjectField -Item $d -Key 'ControlId' -Default '')
        if (-not $cid) { continue }
        $refs = Get-TPObjectField -Item $d -Key 'References' -Default $null
        $rule = [string](Get-TPObjectField -Item $refs -Key 'SCuBA' -Default '')
        if (-not $rule) { continue }
        if (-not $citers.ContainsKey($rule)) { $citers[$rule] = [System.Collections.Generic.List[string]]::new() }
        $citers[$rule].Add($cid)
        $meta[$cid] = [ordered]@{
            Title       = [string](Get-TPObjectField -Item $d -Key 'Title'       -Default '')
            Remediation = [string](Get-TPObjectField -Item $d -Key 'Remediation' -Default '')
        }
    }

    # ── Findings by control id: every instance kept ─────────────────────────
    $byId = @{}
    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $cid = [string](Get-TPObjectField -Item $f -Key 'ControlId' -Default '')
        if (-not $cid) { continue }
        if (-not $byId.ContainsKey($cid)) { $byId[$cid] = [System.Collections.Generic.List[object]]::new() }
        $byId[$cid].Add($f)
    }
    $controlState = {
        param($list)
        $states = @($list | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'State' -Default '') })
        if ($states.Count -eq 0)         { return 'NotRun' }
        if ($states -contains 'Gap')     { return 'Gap' }
        if ($states -contains 'Partial') { return 'Partial' }
        if (@($states | Where-Object { $_ -notin @('Satisfied', 'NotApplicable') }).Count -gt 0) { return 'NotRun' }
        if ($states -contains 'NotApplicable') { return 'NotApplicable' }
        return 'Satisfied'
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($p in $policies) {
        $polId = [string](Get-TPObjectField -Item $p -Key 'PolicyId' -Default '')
        if (-not $polId) { continue }
        $prodKey = [string](Get-TPObjectField -Item $p -Key 'Product' -Default '')
        $prod = if ($products.Contains($prodKey)) { $products[$prodKey] } else { [ordered]@{ Key = $prodKey; Name = $prodKey; AssessedByTool = $false } }

        $controls = [System.Collections.Generic.List[object]]::new()
        $notCounted = [System.Collections.Generic.List[object]]::new()
        $ids = @()
        if ($citers.ContainsKey($polId)) { $ids = @($citers[$polId] | Sort-Object) }
        foreach ($cid in $ids) {
            $m = $null
            if ($align.Mappings.Contains($cid)) { $m = $align.Mappings[$cid] }
            $relation = if ($m) { [string](Get-TPObjectField -Item $m -Key 'Relation' -Default '') } else { '' }
            $note     = if ($m) { [string](Get-TPObjectField -Item $m -Key 'Note' -Default '') } else { 'No relation to the rule is recorded in scuba-alignment.json.' }
            $instances = @()
            if ($byId.ContainsKey($cid)) { $instances = @($byId[$cid]) }
            $state = & $controlState $instances
            $evidence = @(foreach ($f in $instances) {
                $ist = [string](Get-TPObjectField -Item $f -Key 'State' -Default '')
                [ordered]@{
                    Instance = [string](Get-TPObjectField -Item $f -Key 'Instance' -Default '')
                    State    = $(if ($ist) { $ist } else { 'NotRun' })
                    # Kept for every state, Satisfied included: a passing
                    # finding's Detail carries its qualifications.
                    Detail   = [string](Get-TPObjectField -Item $f -Key 'Detail' -Default '')
                }
            })
            $entry = [ordered]@{
                ControlId   = $cid
                Title       = [string]$meta[$cid]['Title']
                Relation    = $(if ($relation) { $relation } else { 'Unrecorded' })
                Note        = $note
                State       = $state
                Evidence    = $evidence
                Remediation = $(if ($state -in @('Gap', 'Partial')) { [string]$meta[$cid]['Remediation'] } else { '' })
            }
            # Only Equivalent and Partial relations bear on the rule. A Manual or
            # Unsupported relation asserts nothing about it, and a citation with
            # no recorded relation is not trusted: listed, not counted.
            if ($relation -in @('Equivalent', 'Partial')) { $controls.Add($entry) } else { $notCounted.Add($entry) }
        }

        $equiv   = @($controls | Where-Object { $_['Relation'] -eq 'Equivalent' })
        $partial = @($controls | Where-Object { $_['Relation'] -eq 'Partial' })
        $verdict = { param($c) $c['State'] -in @('Satisfied', 'Gap', 'Partial') }
        $short   = { param($c) $c['State'] -in @('Gap', 'Partial') }
        $notChecked = [System.Collections.Generic.List[string]]::new()

        $status =
            if (-not $prod['AssessedByTool']) { $st.ProductNotAssessed }
            elseif ($controls.Count -eq 0) { $st.Manual }
            elseif (@($equiv | Where-Object { & $short $_ }).Count -gt 0) { $st.Shortfall }
            elseif ($equiv.Count -gt 0 -and @($equiv | Where-Object { $_['State'] -ne 'Satisfied' }).Count -eq 0) { $st.Met }
            elseif (@($controls | Where-Object { & $verdict $_ }).Count -gt 0) { $st.Partly }
            else { $st.NotAssessed }

        if ($status -eq $st.Partly) {
            foreach ($c in $equiv) {
                if (-not (& $verdict $c)) { $notChecked.Add("$($c['ControlId']) checks the same requirement but produced no verdict this run ($($c['State'])).") }
            }
            foreach ($c in $partial) {
                $notChecked.Add("$($c['ControlId']) covers part of the rule: $($c['Note'])")
            }
        }

        # Related shortfalls: a Partial-relation control reporting a Gap or
        # Partial beside an Equivalent verdict of met. The status stays the
        # Equivalent judgment; the shortfall is named, never hidden.
        $related = @()
        if ($status -eq $st.Met) {
            $related = @($partial | Where-Object { & $short $_ } | ForEach-Object { "$($_['ControlId']) ($($_['State']))" })
        }

        # ── Independent comparison ──────────────────────────────────────────
        $indep = ''
        if ($haveScuba -and $ScubaResults.Contains($polId)) { $indep = [string]$ScubaResults[$polId] }
        # Direction of the tool's own reading: 'pass' only when what it checks
        # all passed, 'fail' when a counted control reported a shortfall.
        $toolDir = ''
        if ($status -eq $st.Met) { $toolDir = 'pass' }
        elseif ($status -eq $st.Shortfall) { $toolDir = 'fail' }
        elseif ($status -eq $st.Partly) {
            if (@($controls | Where-Object { & $short $_ }).Count -gt 0) { $toolDir = 'fail' }
            elseif (@($controls | Where-Object { & $verdict $_ }).Count -gt 0) { $toolDir = 'pass' }
        }
        $differ = ($toolDir -eq 'pass' -and $indep -eq 'Fail') -or ($toolDir -eq 'fail' -and $indep -eq 'Pass')

        $rows.Add([ordered]@{
            PolicyId          = $polId
            Product           = $prodKey
            ProductName       = [string]$prod['Name']
            Criticality       = [string](Get-TPObjectField -Item $p -Key 'Criticality' -Default '')
            Statement         = [string](Get-TPObjectField -Item $p -Key 'Statement' -Default '')
            CisaDateAddedOrModified = [string](Get-TPObjectField -Item $p -Key 'CisaDateAddedOrModified' -Default '')
            CisaDueDate       = [string](Get-TPObjectField -Item $p -Key 'CisaDueDate' -Default '')
            Status            = $status
            Controls          = $controls.ToArray()
            CitedNotCounted   = $notCounted.ToArray()
            NotChecked        = @($notChecked)
            RelatedShortfalls = $related
            IndependentResult = $indep
            ResultsDiffer     = [bool]$differ
        })
    }

    $byStatus = [ordered]@{}
    foreach ($s in @($st.Values)) { $byStatus[$s] = @($rows | Where-Object { $_['Status'] -eq $s }).Count }

    $prodRows = [System.Collections.Generic.List[object]]::new()
    foreach ($k in @($rows | ForEach-Object { $_['Product'] } | Select-Object -Unique)) {
        $pr = @($rows | Where-Object { $_['Product'] -eq $k })
        $tally = [ordered]@{}
        foreach ($s in @($st.Values)) { $tally[$s] = @($pr | Where-Object { $_['Status'] -eq $s }).Count }
        $prodRows.Add([ordered]@{
            Key            = $k
            Name           = [string]$pr[0]['ProductName']
            AssessedByTool = ($products.Contains($k) -and $products[$k]['AssessedByTool'])
            Total          = $pr.Count
            ByStatus       = $tally
        })
    }

    $summary = [ordered]@{
        Total       = $rows.Count
        ByStatus    = $byStatus
        # Mapped: at least one control with an Equivalent or Partial relation.
        Mapped      = @($rows | Where-Object { @($_['Controls']).Count -gt 0 }).Count
        Equivalent  = @($rows | Where-Object { @($_['Controls'] | Where-Object { $_['Relation'] -eq 'Equivalent' }).Count -gt 0 }).Count
        PartialOnly = @($rows | Where-Object { @($_['Controls']).Count -gt 0 -and @($_['Controls'] | Where-Object { $_['Relation'] -eq 'Equivalent' }).Count -eq 0 }).Count
        NotCounted  = @($rows | Where-Object { @($_['Controls']).Count -eq 0 -and @($_['CitedNotCounted']).Count -gt 0 }).Count
        Uncited     = @($rows | Where-Object { @($_['Controls']).Count -eq 0 -and @($_['CitedNotCounted']).Count -eq 0 }).Count
        Differ      = @($rows | Where-Object { $_['ResultsDiffer'] }).Count
        ProductsNotAssessed = @($prodRows | Where-Object { -not $_['AssessedByTool'] } | ForEach-Object { $_['Name'] })
    }

    $directive = Get-TPObjectField -Item $cat -Key 'directive' -Default $null
    $scubaMeta = Get-TPObjectField -Item $cat -Key 'scubaGear' -Default $null
    [ordered]@{
        Policies          = $rows.ToArray()
        Products          = $prodRows.ToArray()
        Summary           = $summary
        Framework         = [string](Get-TPObjectField -Item $cat -Key 'framework' -Default 'CISA BOD 25-01 required configurations')
        CatalogVersion    = [string](Get-TPObjectField -Item $cat -Key 'version' -Default '')
        Source            = @(Get-TPObjectField -Item $cat -Key 'source' -Default @())
        SourceRetrieved   = [string](Get-TPObjectField -Item $cat -Key 'sourceRetrieved' -Default '')
        SourceNote        = [string](Get-TPObjectField -Item $cat -Key 'sourceNote' -Default '')
        Basis             = [string](Get-TPObjectField -Item $cat -Key 'basis' -Default '')
        NotEncoded        = [string](Get-TPObjectField -Item $cat -Key 'notEncoded' -Default '')
        DirectiveIssued   = [string](Get-TPObjectField -Item $directive -Key 'issued' -Default '')
        DirectiveUrl      = [string](Get-TPObjectField -Item $directive -Key 'url' -Default '')
        AppliesTo         = [string](Get-TPObjectField -Item $directive -Key 'appliesTo' -Default '')
        RequiredActions   = @(Get-TPObjectField -Item $directive -Key 'requiredActions' -Default @())
        ScubaGearVersion  = [string](Get-TPObjectField -Item $scubaMeta -Key 'version' -Default '')
        AlignmentChecked  = [string](Get-TPObjectField -Item $align.Source -Key 'CheckedOn' -Default '')
        IndependentSupplied = $haveScuba
        IndependentError  = $scubaError
        Available         = $true
    }
}
