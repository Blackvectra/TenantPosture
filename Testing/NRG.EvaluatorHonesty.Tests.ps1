#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
#
# NRG.EvaluatorHonesty.Tests.ps1
#
# The anti-false-PASS guard. The single most damaging failure mode for a
# security assessment is telling a client they PASS a control that was never
# actually evaluated — a green check backed by no evidence. That happens when a
# collector fails (403 / throttle / missing license) and the evaluator reads the
# resulting null/empty data as "nothing wrong -> Satisfied" instead of guarding
# to NotApplicable.
#
# This suite runs EVERY evaluator with NO collected data present (Clear-NRGState
# wipes the raw-data store) and asserts none of them emit Satisfied or Partial.
# With zero evidence the only honest verdicts are NotApplicable or Error. A
# Satisfied/Partial here is a false result by definition, and it fails the build
# naming the exact control.
#
# Scope note: this guards the DANGEROUS direction only (claiming compliance with
# no data). A throw on missing data is the concern of NRG.EvaluatorResilience;
# here a throw that produces no finding simply cannot be a false pass.

Describe 'No evaluator reports a PASS on data that was never collected' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
    }

    # Discovery-time: one test case per control. Parsed here (not in BeforeAll)
    # because -TestCases is bound during discovery; a BeforeAll value would be
    # $null at that point and the loop would generate zero cases.
    $repoRoot  = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    $evalCases = @(
        (Get-Content -LiteralPath (Join-Path $repoRoot 'Config/controls.json') -Raw -Encoding utf8 |
            ConvertFrom-Json).controls |
            ForEach-Object { @{ ControlId = $_.ControlId; EvaluatorFunction = $_.EvaluatorFunction } }
    )

    It '<ControlId> (<EvaluatorFunction>) yields no Satisfied/Partial when its collector never ran' -TestCases $evalCases {
        Clear-NRGState   # wipe findings AND raw data -> Get-NRGRawData returns null for every key

        if (-not (Get-Command $EvaluatorFunction -ErrorAction SilentlyContinue)) {
            Set-ItResult -Skipped -Because "$EvaluatorFunction is not loaded/exported"
            return
        }

        # A throw on missing data is EvaluatorResilience's concern, not ours — a
        # throw that adds no finding cannot be a false pass, so swallow it here.
        try { & $EvaluatorFunction | Out-Null } catch { }

        $falsePasses = @(
            Get-NRGFindings | Where-Object {
                $_.ControlId -eq $ControlId -and $_.State -in @('Satisfied', 'Partial')
            }
        )
        $falsePasses.Count | Should -Be 0 `
            -Because "no data was collected for $ControlId, so a $($falsePasses.State -join '/') verdict is a green check with no evidence — the evaluator must guard to NotApplicable (or Error)"
    }
}
