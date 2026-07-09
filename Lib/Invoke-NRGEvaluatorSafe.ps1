#Requires -Version 7.0
#
# Invoke-NRGEvaluatorSafe.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: the single, testable gate every entry point uses to run one evaluator
#   so that a bug in ONE evaluator can never (a) crash the whole assessment or
#   (b) silently drop a control from the report. This is the ScubaGear-grade
#   guarantee — an assessment always emits a finding for every control it owns,
#   even if the evaluator hit an unhandled property error on partial tenant data.
#
# Behaviour:
#   - Runs the evaluator.
#   - If it throws, records the exception (console + JSON) AND back-fills an
#     'Error' finding for every control that evaluator owns which does not
#     already have a finding — so the control surfaces as "could not be
#     assessed" rather than vanishing. 'Error' is deliberate, not
#     'NotApplicable': it flags a defect to fix, and the maturity scorer counts
#     it separately (never as a pass or a gap).
#
# Consumes: Get-NRGControlDefinitions, Get-NRGFindings, Add-NRGFinding,
#           Register-NRGException.

function Invoke-NRGEvaluatorSafe {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $EvaluatorFunction
    )

    if (-not (Get-Command $EvaluatorFunction -ErrorAction SilentlyContinue)) { return }

    try {
        & $EvaluatorFunction
    } catch {
        $errMsg = $_.Exception.Message.Split([char]10)[0]
        Write-Warning "Evaluator $EvaluatorFunction — $errMsg"
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            try { Register-NRGException -Source $EvaluatorFunction -Message $errMsg } catch { }
        }

        # Back-fill: no control this evaluator owns may silently vanish.
        try {
            $owned = @(Get-NRGControlDefinitions | Where-Object { $_.EvaluatorFunction -eq $EvaluatorFunction })
            if ($owned.Count -gt 0) {
                $already = [System.Collections.Generic.HashSet[string]]::new(
                    [string[]]@(@(Get-NRGFindings) | ForEach-Object { [string]$_.ControlId }),
                    [System.StringComparer]::OrdinalIgnoreCase)
                foreach ($c in $owned) {
                    if (-not $already.Contains([string]$c.ControlId)) {
                        Add-NRGFinding -ControlId $c.ControlId -State 'Error' `
                            -Category ([string]$c.Category) -Title ([string]$c.Title) `
                            -Detail "Evaluator error — control could not be assessed on this tenant's data: $errMsg"
                    }
                }
            }
        } catch {
            # The safety net must never itself throw.
        }
    }
}
