#Requires -Version 7.0
#
# Get-TPRemediationProof.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: The proof-of-fix model: for the controls a re-check covered, what
#   the tool observed before the fix and after it, from two saved results
#   files of ONE tenant. A client-facing remediation certificate is built from
#   it (Publish-TPRemediationProof). A VIEW: it creates no finding, moves no
#   score, reads no module state and connects to nothing.
#
# Rules (each pinned by TP.RemediationProof.Tests.ps1):
#   - Same tenant only: both files must carry a TenantId and it must be the
#     same one, the guard Publish-TPDeltaReport applies. The id is compared,
#     never rendered.
#   - The after run must be newer than the before run, by the assessment time
#     each recorded; a time that cannot be read refuses (the order cannot be
#     established).
#   - Controls compared: the after run's selection (its SelectedControlIds on
#     a partial run, otherwise every control it has a finding for), narrowed
#     by -ControlId patterns when given, and kept only when the before run has
#     a finding for it. A control the after run selected that the before run
#     never assessed is listed, not compared.
#   - Verdicts per control, each run judged at its worst finding:
#       Resolved          before Gap/Partial, after Satisfied
#       Improved          before Gap, after Partial
#       Not resolved      the same open state before and after
#       Regressed         before Satisfied and after open, or Partial to Gap
#       Already met       Satisfied before and after
#       No earlier verdict before NotApplicable/Error, after a verdict
#       Not verifiable    after NotApplicable, Error or no finding: never
#                         "resolved", whatever the before state was
#   - Evidence: both run times (UTC), tool versions, SHA-256 of both files and
#     the exact selection patterns. Never the operator, never the TenantId,
#     never a finding's Detail.
#
# Data consumed: two records from Read-TPRunRecord -Hash. Data set: none.
# Graph scopes / cmdlets used: none.

function Get-TPRemediationProofVerdictOrder {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @('Resolved', 'Improved', 'Not resolved', 'Regressed', 'Not verifiable', 'No earlier verdict', 'Already met')
}

function Get-TPRemediationProofVerdict {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowEmptyString()] [string] $Before,
        [AllowEmptyString()] [string] $After
    )
    $verdicts = @('Satisfied', 'Partial', 'Gap')
    if ($After -notin $verdicts) { return 'Not verifiable' }
    if ($Before -notin $verdicts) { return 'No earlier verdict' }
    if ($Before -eq 'Satisfied' -and $After -eq 'Satisfied') { return 'Already met' }
    if ($After -eq 'Satisfied') { return 'Resolved' }
    if ($Before -eq 'Gap' -and $After -eq 'Partial') { return 'Improved' }
    if ($Before -eq 'Satisfied') { return 'Regressed' }
    if ($Before -eq 'Partial' -and $After -eq 'Gap') { return 'Regressed' }
    return 'Not resolved'
}

function Get-TPRemediationProof {
    <#
    .SYNOPSIS
        Builds the proof-of-fix model from two results records of one tenant.
    .DESCRIPTION
        Returns Available = $false with Refused = $true and a Note when the two
        runs are not the same tenant, the after run is not newer, or a pattern
        is not a control pattern; Available = $false with Refused = $false when
        no control is in both runs.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [object] $Before,
        [Parameter(Mandatory)] [object] $After,
        [AllowNull()] [AllowEmptyCollection()] [string[]] $ControlId = @()
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $result = [ordered]@{ Available = $false; Refused = $false; Note = '' }
    $refuse = { param($why) $result.Refused = $true; $result.Note = $why; return $result }

    foreach ($rec in @($Before, $After)) {
        if ([bool](Get-TPObjectField -Item $rec -Key 'IsIncidentResponse' -Default $false)) { return (& $refuse 'An incident-response output is not an assessment run; a proof of fix compares two assessment results files.') }
    }
    $patterns = @($ControlId | Where-Object { $_ })
    $rule = Get-TPControlIdPatternRule
    foreach ($p in $patterns) {
        if ($p -cnotmatch $rule) { return (& $refuse "'$p' is not a control pattern (letters, digits, dot, hyphen, * and ? only).") }
    }

    $mb = Get-TPObjectField -Item $Before -Key 'Metadata' -Default $null
    $ma = Get-TPObjectField -Item $After -Key 'Metadata' -Default $null
    $tb = ([string](Get-TPObjectField -Item $mb -Key 'TenantId' -Default '')).Trim()
    $ta = ([string](Get-TPObjectField -Item $ma -Key 'TenantId' -Default '')).Trim()
    if (-not $tb -or -not $ta) { return (& $refuse 'Refusing: one of the results files carries no TenantId, so it cannot be shown to be the same tenant.') }
    if (-not $tb.Equals($ta, [System.StringComparison]::OrdinalIgnoreCase)) { return (& $refuse 'Refusing: the two results files are from different tenants (their TenantIds differ). A proof of fix compares one tenant with itself.') }

    $timeB = Get-TPRunRecordTime -Record $Before
    $timeA = Get-TPRunRecordTime -Record $After
    if ($null -eq $timeB -or $null -eq $timeA) { return (& $refuse 'Refusing: a results file records no readable assessment time, so which run came first cannot be established.') }
    if ($timeA -le $timeB) { return (& $refuse "Refusing: the after run ($($timeA.ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture)) UTC) is not newer than the before run ($($timeB.ToString('yyyy-MM-dd HH:mm', [cultureinfo]::InvariantCulture)) UTC).") }

    $worstB = Get-TPControlWorstFindings -Findings @(Get-TPObjectField -Item $Before -Key 'Findings' -Default @())
    $worstA = Get-TPControlWorstFindings -Findings @(Get-TPObjectField -Item $After -Key 'Findings' -Default @())

    # The after run's selection.
    $selA = Get-TPObjectField -Item $ma -Key 'ControlSelection' -Default $null
    $scopeA = Get-TPRunScope -Metadata $ma
    # Two statements, never `$x = if (...) { @(...) }`: an if-statement unrolls a
    # one-element array into its element.
    $afterIds = @($worstA.Keys)
    if ($scopeA -eq 'Partial') {
        $afterIds = @(@(Get-TPObjectField -Item $selA -Key 'SelectedControlIds' -Default @()) | Where-Object { $_ } | ForEach-Object { [string]$_ })
    }
    if ($scopeA -eq 'Partial' -and $afterIds.Count -eq 0) { $afterIds = @($worstA.Keys) }
    if ($patterns.Count -gt 0) {
        $afterIds = @($afterIds | Where-Object { $id = $_; @($patterns | Where-Object { $id -like $_ }).Count -gt 0 })
    }
    $afterIds = @($afterIds | Where-Object { $_ -cmatch '\A[A-Z]{2,8}-\d+\.\d+\z' } | Sort-Object -Unique)

    $defs = @{}
    try { foreach ($c in @(Get-TPControlDefinitions)) { $defs[[string]$c.ControlId] = $c } } catch { Write-Verbose "controls.json unavailable: $($_.Exception.Message)" }

    $rows = [System.Collections.Generic.List[object]]::new()
    $notInBefore = [System.Collections.Generic.List[string]]::new()
    foreach ($cid in $afterIds) {
        if (-not $worstB.Contains($cid)) { $notInBefore.Add($cid); continue }
        $fb = $worstB[$cid]
        $fa = if ($worstA.Contains($cid)) { $worstA[$cid] } else { $null }
        $sb = [string](Get-TPObjectField -Item $fb -Key 'State' -Default '')
        $sa = if ($null -ne $fa) { [string](Get-TPObjectField -Item $fa -Key 'State' -Default '') } else { '' }
        $def = if ($defs.ContainsKey($cid)) { $defs[$cid] } else { $null }
        $title = [string](Get-TPObjectField -Item $def -Key 'Title' -Default '')
        if (-not $title) { $title = [string](Get-TPObjectField -Item $fa -Key 'Title' -Default ([string](Get-TPObjectField -Item $fb -Key 'Title' -Default ''))) }
        $sev = [string](Get-TPObjectField -Item $def -Key 'Severity' -Default ([string](Get-TPObjectField -Item $fb -Key 'Severity' -Default '')))
        $verdict = Get-TPRemediationProofVerdict -Before $sb -After $sa
        $rows.Add([ordered]@{
            ControlId    = $cid
            Title        = $title
            Severity     = $sev
            BeforeState  = $(if ($sb) { $sb } else { 'No state recorded' })
            BeforeValue  = [string](Get-TPObjectField -Item $fb -Key 'CurrentValue' -Default '')
            AfterState   = $(if ($null -eq $fa) { 'No finding' } elseif ($sa) { $sa } else { 'No state recorded' })
            AfterValue   = $(if ($null -ne $fa) { [string](Get-TPObjectField -Item $fa -Key 'CurrentValue' -Default '') } else { '' })
            Verdict      = $verdict
        })
    }

    if ($rows.Count -eq 0) {
        $result.Note = if ($afterIds.Count -eq 0) { 'No control in the after run matches the selection, so there is nothing to compare.' } else { 'None of the controls the after run covers was assessed in the before run, so there is nothing to compare.' }
        return $result
    }

    $order = Get-TPRemediationProofVerdictOrder
    $counts = [ordered]@{}
    foreach ($v in $order) { $counts[$v] = @($rows | Where-Object { $_.Verdict -eq $v }).Count }
    $sorted = @($rows | Sort-Object @{ Expression = { [array]::IndexOf($order, $_.Verdict) } }, @{ Expression = { $_.ControlId } })

    $domain = ([string](Get-TPObjectField -Item $ma -Key 'TenantDomain' -Default '')).ToLowerInvariant()
    if (-not (Test-TPDomainName -Value $domain)) { $domain = '' }
    $describe = {
        param($rec, $meta, $time)
        $sel = Get-TPObjectField -Item $meta -Key 'ControlSelection' -Default $null
        $scope = Get-TPRunScope -Metadata $meta
        return [ordered]@{
            RunTime      = $time.ToString('yyyy-MM-dd HH:mm:ss', [cultureinfo]::InvariantCulture) + ' UTC'
            ToolVersion  = [string](Get-TPObjectField -Item $meta -Key 'ToolVersion' -Default '')
            Sha256       = [string](Get-TPObjectField -Item $rec -Key 'Sha256' -Default '')
            FileName     = [string](Get-TPObjectField -Item $rec -Key 'FileName' -Default '')
            Scope        = $scope
            Include      = @(@(Get-TPObjectField -Item $sel -Key 'Include' -Default @()) | Where-Object { $_ } | ForEach-Object { [string]$_ })
            Exclude      = @(@(Get-TPObjectField -Item $sel -Key 'Exclude' -Default @()) | Where-Object { $_ } | ForEach-Object { [string]$_ })
        }
    }
    $beforeInfo = & $describe $Before $mb $timeB
    $afterInfo = & $describe $After $ma $timeA

    $notes = [System.Collections.Generic.List[string]]::new()
    if ($beforeInfo.ToolVersion -ne $afterInfo.ToolVersion) { $notes.Add("The two runs were made by different tool versions ($(if ($beforeInfo.ToolVersion) { $beforeInfo.ToolVersion } else { 'not recorded' }) and $(if ($afterInfo.ToolVersion) { $afterInfo.ToolVersion } else { 'not recorded' })); a check tightened between versions can change a verdict without the tenant changing.") }
    if ($notInBefore.Count -gt 0) { $notes.Add("$($notInBefore.Count) control(s) the after run covers were not assessed in the before run and are not compared: $(@($notInBefore) -join ', ').") }
    if (-not $beforeInfo.Sha256 -or -not $afterInfo.Sha256) { $notes.Add('A file hash was not computed for one of the runs.') }

    $resolved = [int]$counts['Resolved']
    $result.Available = $true
    $result['TenantDomain'] = $domain
    $result['Before'] = $beforeInfo
    $result['After'] = $afterInfo
    $result['Patterns'] = $patterns
    $result['Controls'] = $sorted
    $result['Counts'] = $counts
    $result['NotInBefore'] = $notInBefore.ToArray()
    $result['Headline'] = "$resolved of $($sorted.Count) listed control(s) resolved"
    $result['Statement'] = "This certificate covers only the $($sorted.Count) control(s) listed below, and only what TenantPosture observed in this tenant at the two run times shown. It is not an assessment of the whole tenant and not a statement that the tenant meets any framework. A control marked Not verifiable produced no verdict in the after run and is not shown as fixed."
    $result['Notes'] = $notes.ToArray()
    return $result
}
