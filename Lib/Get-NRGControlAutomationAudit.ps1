#Requires -Version 7.0
#
# Get-NRGControlAutomationAudit.ps1
# Dependencies: Get-NRGControlDefinitions (control list); the evaluator functions
#               must be loaded so their ASTs can be inspected. No tenant calls.
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
#
# Purpose: Machine-verify the tool's own coverage claim. For every control it
#   parses the AST of the control's evaluator and determines whether that
#   evaluator can actually produce DIFFERENT verdicts from tenant data — i.e.
#   emit both a pass (Satisfied) and a fail (Gap/Partial). A control that can
#   only ever return one state (always Satisfied, always Partial "manual review",
#   always NotApplicable) is not genuinely automated no matter what the
#   `Automated` flag in controls.json says.
#
#   This is what powers the CI honesty-gate (Testing/NRG.CoverageHonesty.Tests.ps1):
#   no control may claim Automated=true unless it is proven to discriminate or is
#   on a documented exceptions list. No other M365 assessment tool machine-checks
#   its own coverage claims this way.
#
# Method (static, deterministic): resolve each Add-NRGFinding call's -ControlId
#   (literal, or a variable traced to its literal assignment) and collect the set
#   of -State literals emitted for that control. "Discriminates" = the outcome
#   set {Satisfied, Gap, Partial} has 2+ distinct members. Being static it cannot
#   prove a branch is reachable, but emitting both a pass and a fail literal is a
#   strong, conservative signal and never produces a FALSE "not automated".

function Get-NRGControlAutomationAudit {
    [CmdletBinding()]
    param()

    Set-StrictMode -Version Latest

    $AddFn = 'Add-NRGFinding'

    # ── AST helpers ───────────────────────────────────────────────────────────
    $literalOf = {
        param($ast)
        if ($null -eq $ast) { return $null }
        if ($ast -is [System.Management.Automation.Language.PipelineAst]) {
            if ($ast.PipelineElements.Count -eq 1) { return (& $literalOf $ast.PipelineElements[0]) }
            return $null
        }
        if ($ast -is [System.Management.Automation.Language.CommandExpressionAst])       { return (& $literalOf $ast.Expression) }
        if ($ast -is [System.Management.Automation.Language.StringConstantExpressionAst])   { return $ast.Value }
        if ($ast -is [System.Management.Automation.Language.ExpandableStringExpressionAst]) { return $ast.Value }
        return $null
    }
    $paramArg = {
        param($cmdAst, [string]$name)
        $els = $cmdAst.CommandElements
        for ($i = 0; $i -lt $els.Count - 1; $i++) {
            $e = $els[$i]
            if ($e -is [System.Management.Automation.Language.CommandParameterAst] -and $e.ParameterName -eq $name) {
                return $els[$i + 1]
            }
        }
        return $null
    }

    # Per-evaluator analysis, cached (functions serve one or many controls).
    $fnCache = @{}
    $analyze = {
        param([string]$fn)
        if ($fnCache.ContainsKey($fn)) { return $fnCache[$fn] }
        $map = @{}
        $cmd = Get-Command $fn -ErrorAction SilentlyContinue
        if (-not $cmd -or -not $cmd.ScriptBlock) { $fnCache[$fn] = $null; return $null }
        $ast = $cmd.ScriptBlock.Ast

        # varName -> literal string, so -ControlId $anyVar resolves to its control.
        $varLit = @{}
        foreach ($a in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true)) {
            if ($a.Left -is [System.Management.Automation.Language.VariableExpressionAst]) {
                $lit = & $literalOf $a.Right
                if ($lit) { $varLit[$a.Left.VariablePath.UserPath] = $lit }
            }
        }

        foreach ($call in $ast.FindAll({ param($n)
                $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq $AddFn }, $true)) {
            $cidAst = & $paramArg $call 'ControlId'
            $cid = & $literalOf $cidAst
            if (-not $cid -and $cidAst -is [System.Management.Automation.Language.VariableExpressionAst]) {
                $vn = $cidAst.VariablePath.UserPath
                if ($varLit.ContainsKey($vn)) { $cid = $varLit[$vn] }
            }
            if (-not $cid) { continue }   # unresolved dynamic ControlId (e.g. loop guard) — skip

            $state    = & $literalOf (& $paramArg $call 'State')
            $advisory = [bool]($call.Extent.Text -match 'ADVISORY ONLY|Manual review required|Manual verification|manually verif|not exposed by any supported')

            if (-not $map.ContainsKey($cid)) { $map[$cid] = @{ States = [System.Collections.Generic.HashSet[string]]::new(); Advisory = $false } }
            if ($state) { [void]$map[$cid].States.Add($state) }
            if ($advisory) { $map[$cid].Advisory = $true }
        }
        $fnCache[$fn] = $map
        return $map
    }

    $controls = @()
    try { $controls = @(Get-NRGControlDefinitions) } catch { $controls = @() }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $controls) {
        $cid = [string]$c.ControlId
        $fn  = [string]$c.EvaluatorFunction
        $automated = [bool]$c.Automated
        $fnExists = [bool](Get-Command $fn -ErrorAction SilentlyContinue)
        $map = if ($fn) { & $analyze $fn } else { $null }
        $entry = if ($map -and $map.ContainsKey($cid)) { $map[$cid] } else { $null }

        $states   = if ($entry) { @($entry.States) } else { @() }
        $advisory = if ($entry) { [bool]$entry.Advisory } else { $false }
        $outcome  = @($states | Where-Object { $_ -in @('Satisfied','Gap','Partial') } | Sort-Object -Unique)
        $discriminates = ($outcome.Count -ge 2)

        $class =
            if (-not $fnExists)      { 'MissingEvaluator' }
            elseif (-not $entry)     { 'NotWired' }
            elseif ($discriminates)  { 'Implemented' }
            elseif ($advisory)       { 'AdvisoryManual' }
            elseif ((@($states | Sort-Object -Unique) -join ',') -eq 'NotApplicable') { 'Stub' }
            elseif ($outcome.Count -eq 1) { 'SingleVerdict' }
            else                     { 'Other' }

        $rows.Add([pscustomobject][ordered]@{
            ControlId     = $cid
            Workload      = [string]$c.Workload
            Evaluator     = $fn
            Automated     = $automated
            States        = (@($states | Sort-Object) -join '|')
            Discriminates = $discriminates
            Advisory      = $advisory
            Class         = $class
        })
    }
    return @($rows)
}
