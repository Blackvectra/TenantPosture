#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
#
# TP.CollectorContract.Tests.ps1
#
# Guards the contract between Config/controls.json, the collectors, and the
# evaluators. Existing suites check each side in isolation — the schema
# validates the JSON shape, EvaluatorWiring proves the evaluator functions
# exist — but nothing checked that the raw-data KEY a control claims to depend
# on is a key some collector actually produces.
#
# It had drifted: 64 controls (a third of the tool) declared keys such as
# 'Teams-Config', 'SharePoint-TenantSettings', 'Purview-AuditConfig' and
# 'PowerPlatform-DLP' that no collector ever set. Nothing broke at runtime
# because the evaluators call Get-TPRawData with the real key directly, so the
# metadata rotted silently and invisibly.
#
# That matters for more than tidiness: CollectorDependency is the documented
# link between a control and its data source, and anything built on it — a new
# evaluator wired from the metadata, dependency-aware skipping, coverage
# reporting — would read a key that never exists and degrade to a permanent,
# silent NotApplicable.

# Double-quoted deliberately. The apostrophe in "collectors'" closed the
# single-quoted string, so everything after it parsed as code and the whole
# file failed to parse — which Pester reports as a container failure, not as a
# test failure, and a container failure is easy to skim past in a green run.
# This suite was therefore guarding nothing.
Describe "controls.json CollectorDependency matches the collectors' actual keys" {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }

        $script:Controls = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 |
            ConvertFrom-Json).controls)

        # Every key any collector writes, taken from the Set-TPRawData calls
        # themselves so the test cannot drift from the implementation.
        $script:RealKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($f in Get-ChildItem (Join-Path $script:RepoRoot 'Collectors') -Filter '*.ps1' -Recurse -File) {
            foreach ($m in [regex]::Matches((Get-Content -LiteralPath $f.FullName -Raw), "Set-TPRawData\s+-Key\s+'([A-Za-z0-9\-]+)'")) {
                $null = $script:RealKeys.Add($m.Groups[1].Value)
            }
        }

        # Every key any evaluator reads.
        $script:ReadKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($f in Get-ChildItem (Join-Path $script:RepoRoot 'Evaluators') -Filter '*.ps1' -File) {
            foreach ($m in [regex]::Matches((Get-Content -LiteralPath $f.FullName -Raw), "Get-TPRawData\s+-Key\s+'([A-Za-z0-9\-]+)'")) {
                $null = $script:ReadKeys.Add($m.Groups[1].Value)
            }
        }
    }

    It 'the collectors expose a sane number of raw-data keys' {
        $script:RealKeys.Count | Should -BeGreaterThan 10 `
            -Because 'if the Set-TPRawData scan found almost nothing the checks below would pass vacuously'
    }

    It 'every CollectorDependency names a key some collector actually sets' {
        $bad = @()
        foreach ($c in $script:Controls) {
            if ([string]::IsNullOrWhiteSpace($c.CollectorDependency)) { continue }
            foreach ($key in ($c.CollectorDependency -split ',')) {
                $k = $key.Trim()
                if ($k -and -not $script:RealKeys.Contains($k)) {
                    $bad += ('{0} -> {1}' -f $c.ControlId, $k)
                }
            }
        }
        $bad -join "`n" | Should -BeNullOrEmpty `
            -Because 'a control pointing at a raw-data key no collector produces is false metadata; anything built on that link resolves to data that never arrives'
    }

    It 'every key an evaluator reads is a key some collector sets' {
        $orphans = @($script:ReadKeys | Where-Object { -not $script:RealKeys.Contains($_) } | Sort-Object)
        $orphans -join ', ' | Should -BeNullOrEmpty `
            -Because 'an evaluator reading a key no collector writes always gets $null, so its control silently never evaluates'
    }
}
