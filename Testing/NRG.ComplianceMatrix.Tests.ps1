#Requires -Version 7.0
#
# NRG.ComplianceMatrix.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Publish-NRGComplianceMatrix had no test at all, and on a live -AllFiles run
# it failed every time with "XLSX publish failed: The property 'BusinessRisk'
# cannot be found" — the caller degrades that to a warning, so the workbook
# silently was not produced. Cause: DEV-* endpoint findings (always emitted,
# NotApplicable without -DeviceResults) are not in controls.json, so the
# control-definition lookup is $null, and under StrictMode a member read on
# $null throws before ?? applies.

Describe 'Publish-NRGComplianceMatrix' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-cm-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null

        $script:Meta = @{ TenantDomain = 'contoso.onmicrosoft.com'; AssessmentDate = '2026-09-24'; ToolVersion = '4.12.1' }
        $script:Findings = @(
            @{ ControlId = 'AAD-6.1'; Title = 'User App Registration Disabled'; Category = 'Identity'
               State = 'Satisfied'; Severity = 'High'; Detail = 'ok'; CurrentValue = ''; RequiredValue = ''
               FrameworkIds = @('NIST:AC-6', 'CIS:5.1.5.1') }
            # A DEV-* finding exactly as the device evaluator emits it with no
            # -DeviceResults: no controls.json definition behind it.
            @{ ControlId = 'DEV-1.1'; Title = 'Endpoint check'; Category = 'Device'
               State = 'NotApplicable'; Severity = 'Informational'; Detail = 'No device results supplied.'
               FrameworkIds = @() }
        )
    }

    AfterAll { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }

    It 'publishes when findings include a control that is not in controls.json (DEV-*)' -Skip:(-not (
        (& { foreach ($py in 'python3','python') { try { $null = & $py -c 'import openpyxl' 2>&1; if ($LASTEXITCODE -eq 0) { return $true } } catch { } } return $false })
    )) {
        $path = Join-Path $script:Tmp 'matrix.xlsx'
        { Publish-NRGComplianceMatrix -Metadata $script:Meta -Findings $script:Findings -OutputPath $path -ErrorAction Stop } |
            Should -Not -Throw
        Test-Path -LiteralPath $path | Should -BeTrue
    }

    It 'tolerates findings that omit CurrentValue / RequiredValue / FrameworkIds' -Skip:(-not (
        (& { foreach ($py in 'python3','python') { try { $null = & $py -c 'import openpyxl' 2>&1; if ($LASTEXITCODE -eq 0) { return $true } } catch { } } return $false })
    )) {
        $sparse = @(@{ ControlId = 'AAD-6.1'; Title = 't'; Category = 'Identity'; State = 'Gap'; Severity = 'High'; Detail = 'd' })
        $path = Join-Path $script:Tmp 'sparse.xlsx'
        { Publish-NRGComplianceMatrix -Metadata $script:Meta -Findings $sparse -OutputPath $path -ErrorAction Stop } |
            Should -Not -Throw
    }
}
