#Requires -Version 7.0
<#
.SYNOPSIS
    Get-TPBaselineReason.ps1 — TenantPosture
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
      StandardNotApproved         the evidence was read but an NRG standard it is judged against is not approved
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

function Get-TPBaselineReasonCodes {
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
        @('StandardNotApproved',        'Run',  'The evidence was read, but an NRG standard the expected state names (an approved list or monitoring address) is not approved or configured, so that part is not assessed.'),
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

function Get-TPReasonSentence {
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

function ConvertTo-TPBaselineReasonCode {
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

function Resolve-TPBaselineReason {
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
        Get-TPOptionalCollectorCatalog). With one present, an unread evidence
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
    $state  = [string](Get-TPObjectField -Item $Row -Key 'ObservedState' -Default '')
    $constr = [string](Get-TPObjectField -Item $Row -Key 'Constraint' -Default '')
    $cause  = [string](Get-TPObjectField -Item $Row -Key 'NotVerifiedCause' -Default '')
    $prose  = [string](Get-TPObjectField -Item $Row -Key 'Reason' -Default '')
    $fState = [string](Get-TPObjectField -Item $Row -Key 'ObservedFindingState' -Default '')
    $cid    = [string](Get-TPObjectField -Item $Row -Key 'ControlId' -Default '')
    # A multi-component detail reads "Verified: ... Shortfall: ... Not assessed: ...".
    # The reason must name what decides the code, not the half that passed: a Partial
    # shows its shortfall, an unread verdict shows what was not established.
    $focus = $Detail
    if ($Detail -match '(?s)^\s*Verified:') {
        if ($state -eq 'Failed' -and $Detail -match '(?s)Shortfall:\s*(.+?)(?=\s+Not assessed:|$)') { $focus = $Matches[1] }
        elseif ($state -eq 'NotVerified' -and $Detail -match '(?s)Not assessed:\s*(.+)$') { $focus = "Not established: $($Matches[1])" }
    }
    $sentence = Get-TPReasonSentence -Text $focus
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
            $s = Get-TPReasonSentence -Text $prose
            return & $out 'EvidenceStale' $(if ($s) { $s } else { 'The evidence is older than its freshness window.' })
        }
        if ($cause -eq 'Standard not approved') {
            return & $out 'StandardNotApproved' $(if ($sentence) { $sentence } else { 'An NRG standard this control is judged against is not approved or configured.' })
        }
        if ($cause -eq 'Evidence not read') {
            if ($null -ne $OptionalCollector) {
                $sw = [string](Get-TPObjectField -Item $OptionalCollector -Key 'Switch' -Default '')
                $nm = [string](Get-TPObjectField -Item $OptionalCollector -Key 'Name' -Default 'optional collector')
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
        if ($cid -and (Get-Command Get-TPControlById -ErrorAction SilentlyContinue)) {
            try { $c = Get-TPControlById -ControlId $cid; if ($c) { $req = [string](Get-TPObjectField -Item $c -Key 'LicenseRequirement' -Default '') } } catch { $req = '' }
        }
        return & $out 'LicenseBlocked' $(if ($req) { "Requires $req, which this tenant does not hold; not scored." } else { 'This tenant does not hold the license the control requires; not scored.' })
    }

    if ($state -eq 'NotApplicable') {
        if ($ThirdPartyMarker -and ($Detail -like "$ThirdPartyMarker*" -or $prose -like "$ThirdPartyMarker*")) {
            $src = if ($Detail) { $Detail } else { $prose }
            $product = if ($src -match 'provided by (.+?), as declared') { $Matches[1] } else { 'a declared third-party product' }
            return & $out 'ThirdPartyHandled' "Third-party EDR declared: this capability is provided by $product, as declared by the assessor; not verified by this assessment and not scored."
        }
        return & $out 'NotApplicable' $(if ($sentence) { $sentence } elseif ($prose) { Get-TPReasonSentence -Text $prose } else { 'Reported not applicable to this tenant.' })
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

function Get-TPBaselineCoverage {
    <#
    .SYNOPSIS
        Two coverage metrics over the compliance rows, derived from the reason
        contract and kept strictly apart from the baseline score.
    .DESCRIPTION
        Evidence coverage answers: of the applicable required controls, how many
        have current, usable evidence? Known = Satisfied + ControlFailed +
        ThirdPartyHandled (attested by the assessor, usable, not verified).
        Unknown = every code that means the evidence was not obtained
        (CollectorUnavailable, EvidenceStale, EvidenceNotRead,
        ManualVerificationRequired, SkippedByOperator,
        OptionalCollectorRequired, EvaluationError). LicenseBlocked is in the
        denominator and reported separately: the tool knows why it cannot
        verify the control, and that is not evidence the requirement is met.
        NotApplicable is outside the denominator: a control that does not
        apply does not lower coverage. Known + Unknown + LicenseBlocked =
        Applicable.

        Effectiveness coverage answers: of the required controls, how many
        have effectiveness evidence today? Known only where EffectivenessState
        is Effective or Ineffective; Unknown stays unknown however perfect the
        configuration evidence is.

        Neither number is the baseline score, and a high evidence coverage
        never implies the baseline is met: a tenant failing every control has
        100% evidence coverage.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([Parameter(Mandatory)] [AllowNull()] [AllowEmptyCollection()] [object[]] $Rows)
    Set-StrictMode -Version Latest
    $rows = @($Rows | Where-Object { $null -ne $_ })
    $code = { param($r) [string](Get-TPObjectField -Item $r -Key 'ReasonCode' -Default '') }
    $knownCodes   = @('Satisfied', 'ControlFailed', 'ThirdPartyHandled')
    $unknownCodes = @('CollectorUnavailable', 'EvidenceStale', 'StandardNotApproved', 'EvidenceNotRead', 'ManualVerificationRequired', 'SkippedByOperator', 'OptionalCollectorRequired', 'EvaluationError', 'LicensingUnknown')
    $na  = @($rows | Where-Object { (& $code $_) -eq 'NotApplicable' })
    $lb  = @($rows | Where-Object { (& $code $_) -eq 'LicenseBlocked' })
    $kn  = @($rows | Where-Object { (& $code $_) -in $knownCodes })
    $unk = @($rows | Where-Object { (& $code $_) -in $unknownCodes })
    $other = @($rows | Where-Object { (& $code $_) -notin ($knownCodes + $unknownCodes + @('NotApplicable', 'LicenseBlocked')) })
    $applicable = $rows.Count - $na.Count
    $gaps = [ordered]@{}
    foreach ($c in (Get-TPBaselineReasonCodes).Keys) {
        if ($c -notin $unknownCodes) { continue }
        $n = @($unk | Where-Object { (& $code $_) -eq $c }).Count
        if ($n -gt 0) { $gaps[$c] = $n }
    }
    $evPct = if ($applicable -gt 0) { [math]::Round(100.0 * $kn.Count / $applicable, 1) } else { 0.0 }

    $effState = { param($r) [string](Get-TPObjectField -Item $r -Key 'EffectivenessState' -Default 'Unknown') }
    $eff = @($rows | Where-Object { (& $effState $_) -eq 'Effective' })
    $ineff = @($rows | Where-Object { (& $effState $_) -eq 'Ineffective' })
    $effKnown = $eff.Count + $ineff.Count
    $collectable = @($rows | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'EffectivenessCapability' -Default '') -eq 'Collected' }).Count
    $effPct = if ($rows.Count -gt 0) { [math]::Round(100.0 * $effKnown / $rows.Count, 1) } else { 0.0 }

    return [ordered]@{
        Evidence = [ordered]@{
            Required       = $rows.Count
            Applicable     = $applicable
            Known          = $kn.Count
            Unknown        = $unk.Count + $other.Count
            LicenseBlocked = $lb.Count
            NotApplicable  = $na.Count
            Percent        = $evPct
            Gaps           = $gaps
            Rule           = 'Known = Satisfied + ControlFailed + ThirdPartyHandled (attested, not verified). Unknown = evidence not obtained. LicenseBlocked is in the denominator and shown separately. NotApplicable is outside the denominator. Not a score: a tenant failing every control has 100% evidence coverage.'
        }
        Effectiveness = [ordered]@{
            Required            = $rows.Count
            Known               = $effKnown
            Effective           = $eff.Count
            Ineffective         = $ineff.Count
            Unknown             = $rows.Count - $effKnown
            CapabilityCollected = $collectable
            Percent             = $effPct
            Rule                = 'Known only where EffectivenessState is Effective or Ineffective. Configuration evidence never counts as effectiveness evidence.'
        }
    }
}
