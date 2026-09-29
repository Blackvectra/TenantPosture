#Requires -Version 7.0
<#
.SYNOPSIS
    Get-NRGBaselineReason.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: The ONE explanation contract for a baseline row. Every surface —
             the compliance view, the plan, the results JSON, the HTML and
             Markdown reports, the regression rows and any downstream consumer
             — reads the same pair: a stable machine-readable ReasonCode and a
             short human-readable Reason. Nothing else invents wording, and a
             consumer keys on the code, never on prose.
    The codes form one deterministic precedence (first match wins):
      ManualVerificationRequired  a human must verify; no collector reads it
      SkippedByOperator           the operator excluded the workload or evaluator
      ThirdPartyHandled           a declared non-Microsoft product covers it;
                                  attested, not verified
      OptionalCollectorRequired   an opt-in collector was needed and not enabled
      LicenseBlocked              the tenant demonstrably lacks the license
      LicensingUnknown            plan only: licensing not read yet
      CollectorUnavailable        a collector did not complete successfully
      EvidenceStale               evidence older than its freshness window
      EvidenceNotRead             the collector ran but the evidence was not read
      EvaluationError             the evaluator errored or produced no result
      ControlFailed               assessed and below the expected state
      Satisfied                   assessed and at the expected state
      NotApplicable               assessed and does not apply to this tenant
      Automatic                   plan only: expected assessable; the run decides
    A skipped collector therefore never reads as license-blocked, and a
    third-party declaration never reads as manual: the higher signal wins.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Set-StrictMode -Version Latest

function Get-NRGBaselineReasonCodes {
    <#
    .SYNOPSIS
        The reason-code catalog in precedence order: Code -> Precedence, Scope
        (Run / Plan / Both) and Meaning. Written into the results JSON so a
        consumer can read the vocabulary beside the rows that use it.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()
    $codes = [ordered]@{}
    $i = 0
    foreach ($e in @(
        @('ManualVerificationRequired', 'Both', 'A human must verify this; no collector reads its evidence, or the evaluator asks for manual verification.'),
        @('SkippedByOperator',          'Both', 'The operator excluded this workload or evaluator for the run (a -Skip flag or a quick scan).'),
        @('ThirdPartyHandled',          'Both', 'A declared non-Microsoft product provides this capability. Attested by the assessor, not verified by the assessment, not scored.'),
        @('OptionalCollectorRequired',  'Both', 'An opt-in collector is needed to read this evidence and was not enabled.'),
        @('LicenseBlocked',             'Both', 'The tenant demonstrably does not hold the license the control requires; it cannot be configured, so it is not scored.'),
        @('LicensingUnknown',           'Plan', 'Licensing has not been read; whether the control applies is unknown until the tenant is connected.'),
        @('CollectorUnavailable',       'Run',  'A collector this control depends on did not complete successfully, so its evidence is missing.'),
        @('EvidenceStale',              'Run',  'The evidence is older than the freshness window for its class; a verdict that old is not evidence.'),
        @('EvidenceNotRead',            'Run',  'The collector ran but the specific evidence this control needs was not read (a section failed, a value could not be resolved).'),
        @('EvaluationError',            'Run',  'The evaluator raised an error or produced no result; the true state is unknown.'),
        @('ControlFailed',              'Run',  'Assessed and below the expected state (a Gap or a Partial).'),
        @('Satisfied',                  'Run',  'Assessed and at the expected state.'),
        @('NotApplicable',              'Run',  'Assessed and does not apply to this tenant, for the stated reason.'),
        @('Automatic',                  'Plan', 'Expected to be assessed automatically; the run decides the outcome.')
    )) {
        $i++
        $codes[$e[0]] = [ordered]@{ Code = $e[0]; Precedence = $i; Scope = $e[1]; Meaning = $e[2] }
    }
    return $codes
}

function Get-NRGReasonSentence {
    <#
    .SYNOPSIS
        The first sentence of a finding detail, trimmed to one line, with the
        cross-reference boilerplate the evaluators append removed.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyString()] [string] $Text, [int] $MaxLength = 240)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $t = ($Text -replace '\s+', ' ').Trim()
    $t = $t -replace '\s*Scored together with .*$', ''
    $t = $t -replace '\s*\(see Exceptions\)', ''
    $t = $t -replace '^(Not assessed\.|Not assessed —|Not assessed:)\s*', ''
    # First sentence: a period followed by a space and a capital, or the end.
    $m = [regex]::Match($t, '^(.+?[.!?])(?:\s+[A-Z(]|$)')
    $s = if ($m.Success) { $m.Groups[1].Value } else { $t }
    if ($s.Length -gt $MaxLength) { $s = $s.Substring(0, $MaxLength - 1).TrimEnd() + '…' }
    return $s
}

function ConvertTo-NRGBaselineReasonCode {
    <#
    .SYNOPSIS
        Maps a plan Expected bucket to its ReasonCode.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $Expected)
    switch ($Expected) {
        'Manual'                    { return 'ManualVerificationRequired' }
        'SkippedByOperator'         { return 'SkippedByOperator' }
        'ThirdPartyHandled'         { return 'ThirdPartyHandled' }
        'OptionalCollectorRequired' { return 'OptionalCollectorRequired' }
        'LicenseBlockedExpected'    { return 'LicenseBlocked' }
        'LicensingUnknown'          { return 'LicensingUnknown' }
        'Automatic'                 { return 'Automatic' }
        default                     { return 'EvaluationError' }
    }
}

function Resolve-NRGBaselineReason {
    <#
    .SYNOPSIS
        Resolves a compliance row to its ReasonCode and Reason.
    .DESCRIPTION
        Reads the row's ObservedState, Constraint, NotVerifiedCause and the
        finding detail, and returns the one code that applies under the
        catalog precedence, with a short explanation derived from the same
        evidence the state came from. The long prose the view already built
        is not consulted for the code; only the classified signals are.
    .PARAMETER OptionalCollector
        The optional-collector catalog entry for this control, if any (see
        Get-NRGOptionalCollectorCatalog). With one present, an unread evidence
        that the detail attributes to that collector's switch resolves
        OptionalCollectorRequired rather than EvidenceNotRead.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [object] $Row,
        [AllowNull()] [AllowEmptyString()] [string] $Detail = '',
        [AllowNull()] [object] $OptionalCollector = $null,
        [AllowNull()] [AllowEmptyString()] [string] $ThirdPartyMarker = 'Third-party EDR declared:'
    )
    Set-StrictMode -Version Latest
    $state  = [string](Get-NRGObjectField -Item $Row -Key 'ObservedState' -Default '')
    $constr = [string](Get-NRGObjectField -Item $Row -Key 'Constraint' -Default '')
    $cause  = [string](Get-NRGObjectField -Item $Row -Key 'NotVerifiedCause' -Default '')
    $prose  = [string](Get-NRGObjectField -Item $Row -Key 'Reason' -Default '')
    $fState = [string](Get-NRGObjectField -Item $Row -Key 'ObservedFindingState' -Default '')
    $cid    = [string](Get-NRGObjectField -Item $Row -Key 'ControlId' -Default '')
    $sentence = Get-NRGReasonSentence -Text $Detail
    $out = { param([string] $code, [string] $reason) [ordered]@{ ReasonCode = $code; Reason = $reason } }

    if ($state -eq 'NotVerified') {
        if ($cause -eq 'Manual control') {
            return & $out 'ManualVerificationRequired' 'Verified manually: no collector reads this evidence yet.'
        }
        if ($cause -eq 'Manual verification') {
            return & $out 'ManualVerificationRequired' "The evaluator requires manual verification.$(if ($sentence) { " $sentence" })"
        }
        if ($cause -eq 'Skipped by operator') {
            return & $out 'SkippedByOperator' 'The workload was skipped for this run by the operator (a -Skip flag).'
        }
        if ($cause -eq 'Quick scan') {
            return & $out 'SkippedByOperator' 'The evaluator was omitted by the quick scan (-Quick).'
        }
        if ($cause -like 'Collector unavailable:*') {
            $key = ($cause -replace '^Collector unavailable:\s*', '').Trim()
            return & $out 'CollectorUnavailable' "The $key collector did not succeed in this run, so the evidence is missing$(if ($fState) { " and the recorded verdict ($fState) is not evidence" })."
        }
        if ($cause -eq 'Stale evidence') {
            $s = Get-NRGReasonSentence -Text $prose
            return & $out 'EvidenceStale' $(if ($s) { $s } else { 'The evidence is older than its freshness window.' })
        }
        if ($cause -eq 'Evidence not read') {
            if ($null -ne $OptionalCollector) {
                $sw = [string](Get-NRGObjectField -Item $OptionalCollector -Key 'Switch' -Default '')
                $nm = [string](Get-NRGObjectField -Item $OptionalCollector -Key 'Name' -Default 'optional collector')
                $swWord = $sw.TrimStart('-')
                if ($swWord -and ($Detail -match [regex]::Escape($swWord) -or $Detail -match 'Management Shell')) {
                    return & $out 'OptionalCollectorRequired' "Needs the $nm ($sw), which was not enabled for this run."
                }
            }
            return & $out 'EvidenceNotRead' $(if ($sentence) { $sentence } else { 'The evidence this control needs was not read.' })
        }
        if ($cause -eq 'Evaluator error') {
            return & $out 'EvaluationError' "The evaluator raised an error; the true state is unknown.$(if ($sentence) { " $sentence" })"
        }
        return & $out 'EvaluationError' $(if ($cause -eq 'No result') { 'No finding was produced for this control in this run.' } elseif ($sentence) { $sentence } else { 'Reported without a reason the baseline can classify.' })
    }

    if ($constr -eq 'LicenseBlocked') {
        $req = ''
        if ($cid -and (Get-Command Get-NRGControlById -ErrorAction SilentlyContinue)) {
            try { $c = Get-NRGControlById -ControlId $cid; if ($c) { $req = [string](Get-NRGObjectField -Item $c -Key 'LicenseRequirement' -Default '') } } catch { $req = '' }
        }
        return & $out 'LicenseBlocked' $(if ($req) { "Requires $req, which this tenant does not hold; not scored." } else { 'This tenant does not hold the license the control requires; not scored.' })
    }

    if ($state -eq 'NotApplicable') {
        if ($ThirdPartyMarker -and ($Detail -like "$ThirdPartyMarker*" -or $prose -like "$ThirdPartyMarker*")) {
            $src = if ($Detail) { $Detail } else { $prose }
            $product = if ($src -match 'provided by (.+?), as declared') { $Matches[1] } else { 'a declared third-party product' }
            return & $out 'ThirdPartyHandled' "Third-party EDR declared: this capability is provided by $product, as declared by the assessor; not verified by this assessment and not scored."
        }
        return & $out 'NotApplicable' $(if ($sentence) { $sentence } elseif ($prose) { Get-NRGReasonSentence -Text $prose } else { 'Reported not applicable to this tenant.' })
    }

    if ($state -eq 'Failed') {
        $lead = if ($fState -eq 'Partial') { 'Partial: ' } else { '' }
        return & $out 'ControlFailed' "$lead$(if ($sentence) { $sentence } else { 'Below the expected state.' })"
    }
    if ($state -eq 'Satisfied') {
        return & $out 'Satisfied' $(if ($sentence) { $sentence } else { 'At the expected state.' })
    }
    return & $out 'EvaluationError' $(if ($sentence) { $sentence } else { "Unrecognized observed state '$state'." })
}
