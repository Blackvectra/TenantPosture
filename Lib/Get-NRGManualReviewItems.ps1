#Requires -Version 7.0
#
# Get-NRGManualReviewItems.ps1
# Dependencies: Get-NRGObjectField, Get-NRGControlDefinitions, Get-NRGAssessmentScope output.
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Turns the two dangerous buckets Get-NRGAssessmentScope.ps1 sorts
#          controls.json controls into — NoProgrammaticCheck (no automated
#          test exists, or the check ran and could not reach a verdict) and
#          CollectionIncomplete (the control could have been
#          assessed and was not) — into questionnaire items, the same way
#          Get-NRGSSPQuestionnaireItems.ps1 does for the NIST 800-171
#          requirements the tenant scan cannot reach.
#
#          These two buckets, not the other three Get-NRGAssessmentScope
#          computes (LicenceBlocked, NotEvaluatedThisMode, NoResult), are
#          deliberately what this asks about. LicenceBlocked is benign and
#          already priced under Upgrade Unlocks — asking about it here would
#          duplicate that section with a worse UI. NotEvaluatedThisMode is a
#          -Quick artifact that a normal run resolves on its own. NoResult is
#          a tool fault to fix, not a question to hand a client.
#
#          The question text is the control's own Description field verbatim
#          from controls.json, never an invented paraphrase — the same rule
#          Get-NRGSSPQuestionnaireItems.ps1 applies to the NIST requirement
#          Statement, for the same reason: controls.json already states what
#          each control checks for in plain language, and paraphrasing risks
#          asking something subtly different from what the control actually
#          means.
#
# Inputs:  -Scope     the [ordered] hashtable from Get-NRGAssessmentScope.
#          -Workload  optional filter to one workload (e.g. 'SPO'), so a
#                      questionnaire can go to the person who actually owns
#                      that workload instead of everyone getting every
#                      unassessed control across the tenant.
#
# Outputs: array of [ordered] hashtables, one per item needing an answer.
#          Always an array, never $null, even when nothing qualifies.
#
# Consumes: Get-NRGAssessmentScope output + Config/controls.json (via
#           Get-NRGControlDefinitions). No Graph, no EXO, no network.
#

function Get-NRGManualReviewItems {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary] $Scope,

        [Parameter(Mandatory = $false)]
        [AllowNull()] [AllowEmptyString()]
        [string] $Workload,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object] $Answers
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # List + .ToArray() throughout, never `$x = if (...) { @(...) } else { @() }`
    # — that assigns $null instead of an empty array on the branch that
    # yields one, which throws under StrictMode the first time a caller
    # reads .Count on a tenant with nothing left to ask.
    $items = [System.Collections.Generic.List[object]]::new()

    $available = $false
    if ($Scope -and $Scope.Contains('Available')) { $available = [bool]$Scope['Available'] }
    if (-not $available) { return $items.ToArray() }

    $defsById = @{}
    foreach ($c in @(Get-NRGControlDefinitions)) {
        $cid = [string](Get-NRGObjectField -Item $c -Key 'ControlId' -Default '')
        if ($cid) { $defsById[$cid] = $c }
    }

    $ansById = @{}
    if ($Answers) {
        $node = Get-NRGObjectField -Item $Answers -Key 'Controls' -Default $null
        if ($node -is [System.Collections.IDictionary]) {
            foreach ($k in $node.Keys) { $ansById[[string]$k] = $node[$k] }
        } elseif ($node) {
            foreach ($p in $node.PSObject.Properties) { $ansById[[string]$p.Name] = $p.Value }
        }
    }

    foreach ($bucket in @('NoProgrammaticCheck', 'CollectionIncomplete')) {
        foreach ($row in @(Get-NRGObjectField -Item $Scope -Key $bucket -Default @())) {
            $cid = [string](Get-NRGObjectField -Item $row -Key 'ControlId' -Default '')
            if (-not $cid) { continue }

            $wl = [string](Get-NRGObjectField -Item $row -Key 'Workload' -Default '')
            if ($Workload -and $wl -ne $Workload) { continue }

            $def = if ($defsById.ContainsKey($cid)) { $defsById[$cid] } else { $null }
            $question = if ($def) { [string](Get-NRGObjectField -Item $def -Key 'Description' -Default '') } else { '' }
            if (-not $question) { $question = [string](Get-NRGObjectField -Item $row -Key 'Title' -Default '') }
            $businessRisk = if ($def) { [string](Get-NRGObjectField -Item $def -Key 'BusinessRisk' -Default '') } else { '' }

            $ans  = if ($ansById.ContainsKey($cid)) { $ansById[$cid] } else { $null }
            $poam = if ($ans) { Get-NRGObjectField -Item $ans -Key 'Poam' -Default $null } else { $null }

            $items.Add([ordered]@{
                ControlId               = $cid
                Title                   = [string](Get-NRGObjectField -Item $row -Key 'Title' -Default '')
                Workload                = $wl
                Severity                = [string](Get-NRGObjectField -Item $row -Key 'Severity' -Default '')
                Bucket                  = $bucket
                Reason                  = [string](Get-NRGObjectField -Item $row -Key 'Reason' -Default '')
                Question                = $question
                BusinessRisk            = $businessRisk
                CurrentStatus           = if ($ans) { [string](Get-NRGObjectField -Item $ans -Key 'Status' -Default '') } else { '' }
                CurrentEvidence         = if ($ans) { [string](Get-NRGObjectField -Item $ans -Key 'Evidence' -Default '') } else { '' }
                CurrentOwner            = if ($ans) { [string](Get-NRGObjectField -Item $ans -Key 'Owner' -Default '') } else { '' }
                CurrentNaReason         = if ($ans) { [string](Get-NRGObjectField -Item $ans -Key 'NotApplicableReason' -Default '') } else { '' }
                CurrentCompensating     = if ($ans) { [string](Get-NRGObjectField -Item $ans -Key 'CompensatingControl' -Default '') } else { '' }
                CurrentRiskAcceptance   = if ($ans) { [string](Get-NRGObjectField -Item $ans -Key 'RiskAcceptance' -Default '') } else { '' }
                CurrentPoamWeakness     = if ($poam) { [string](Get-NRGObjectField -Item $poam -Key 'Weakness' -Default '') } else { '' }
                CurrentPoamRemedy       = if ($poam) { [string](Get-NRGObjectField -Item $poam -Key 'Remedy'   -Default '') } else { '' }
                CurrentPoamOwner        = if ($poam) { [string](Get-NRGObjectField -Item $poam -Key 'Owner'    -Default '') } else { '' }
                CurrentPoamDueDate      = if ($poam) { [string](Get-NRGObjectField -Item $poam -Key 'DueDate'  -Default '') } else { '' }
            })
        }
    }

    return $items.ToArray()
}
