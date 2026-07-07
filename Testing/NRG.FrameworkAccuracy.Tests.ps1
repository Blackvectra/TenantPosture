#Requires -Version 7.0
#
# NRG.FrameworkAccuracy.Tests.ps1
#
# Dependencies: None (reads Config/controls.json + Config/framework-baselines/)
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
# Purpose: Validate every framework crosswalk ID in controls.json against an
#          authoritative, bug-worked-out reference. Today: SCuBA IDs vs the
#          bundled CISA ScubaGear v1.8.0 baseline. Catches typos, nonexistent
#          IDs, and version drift (e.g. MS.AAD.3.3v1 -> v2) in CI instead of at
#          client-report time.
#
# Consumes: Config/controls.json, Config/framework-baselines/scuba-ids-v1.8.0.txt
# Sets:     nothing.

Describe 'Framework crosswalk accuracy' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $controlsPath = Join-Path $script:RepoRoot 'Config' 'controls.json'
        $script:Controls = (Get-Content -LiteralPath $controlsPath -Raw | ConvertFrom-Json)
        if ($script:Controls.PSObject.Properties['controls']) { $script:Controls = $script:Controls.controls }

        $scubaPath = Join-Path $script:RepoRoot 'Config' 'framework-baselines' 'scuba-ids-v1.8.0.txt'
        $script:AuthScuba = @(Get-Content -LiteralPath $scubaPath |
            Where-Object { $_ -and -not $_.StartsWith('#') } |
            ForEach-Object { $_.Trim() })
    }

    Context 'SCuBA references vs authoritative ScubaGear v1.8.0 baseline' {
        It 'Bundled authoritative baseline is non-empty' {
            $script:AuthScuba.Count | Should -BeGreaterThan 100
        }

        It 'Every References.SCuBA value exists in the authoritative baseline' {
            $authSet = [System.Collections.Generic.HashSet[string]]::new(
                [string[]]$script:AuthScuba, [System.StringComparer]::Ordinal)
            $bad = [System.Collections.Generic.List[string]]::new()
            foreach ($c in $script:Controls) {
                $ref = $c.References
                if ($null -eq $ref) { continue }
                $scuba = $ref.SCuBA
                if (-not $scuba) { continue }
                foreach ($id in @($scuba)) {
                    if (-not $authSet.Contains([string]$id)) {
                        $bad.Add("$($c.ControlId) -> $id")
                    }
                }
            }
            $bad -join "`n" | Should -BeNullOrEmpty -Because 'every SCuBA ID must be a real ScubaGear v1.8.0 policy (regenerate the baseline file on version upgrade)'
        }

        It 'Every prose SCuBA citation matches the control''s SCuBA reference' {
            $rx = [regex]'MS\.[A-Z]+\.\d+\.\d+v\d+'
            $stale = [System.Collections.Generic.List[string]]::new()
            foreach ($c in $script:Controls) {
                $scuba = if ($c.References) { [string]$c.References.SCuBA } else { '' }
                foreach ($fld in 'Remediation','Description','BusinessRisk') {
                    $txt = [string]$c.$fld
                    foreach ($m in $rx.Matches($txt)) {
                        if ($m.Value -ne $scuba) { $stale.Add("$($c.ControlId).$fld cites $($m.Value) but SCuBA=$scuba") }
                    }
                }
            }
            $stale -join "`n" | Should -BeNullOrEmpty -Because 'prose citations must not drift from the formal SCuBA mapping'
        }
    }

    Context 'NIST 800-53r5 references are well-formed control identifiers' {
        # NIST control IDs are stable across the catalog, so the realistic error
        # is a typo or a bad family prefix, not version drift. Validate the
        # FAMILY-N or FAMILY-N(M) shape with a real 800-53r5 family prefix.
        It 'Every References.NIST token matches FAMILY-N[(M)] with a valid r5 family' {
            $validFamilies = 'AC','AT','AU','CA','CM','CP','IA','IR','MA','MP','PE','PL','PM','PS','PT','RA','SA','SC','SI','SR'
            $rx = [regex]'^([A-Z]{2})-\d+(\(\d+\))?$'
            $bad = [System.Collections.Generic.List[string]]::new()
            foreach ($c in $script:Controls) {
                if ($null -eq $c.References) { continue }
                $nist = [string]$c.References.NIST
                if (-not $nist) { continue }
                foreach ($tok in ($nist -split '[;,]')) {
                    $t = $tok.Trim()
                    if (-not $t) { continue }
                    $m = $rx.Match($t)
                    if (-not $m.Success -or $m.Groups[1].Value -notin $validFamilies) {
                        $bad.Add("$($c.ControlId) -> '$t'")
                    }
                }
            }
            $bad -join "`n" | Should -BeNullOrEmpty -Because 'every NIST token must be a well-formed 800-53r5 control ID'
        }
    }

    Context 'MITRE ATT&CK references are well-formed Enterprise technique IDs' {
        # Framework is declared "MITRE ATT&CK Enterprise". IDs must be T#### or
        # T####.### (sub-technique). Guards typos and stray non-technique tokens.
        # (The Mobile-vs-Enterprise scope error that removed T1533 is not
        # format-detectable — re-run the authoritative attack.mitre.org check on
        # ATT&CK version bumps.)
        It 'Every References.MITRE token matches T#### or T####.###' {
            $rx = [regex]'^T\d{4}(\.\d{3})?$'
            $bad = [System.Collections.Generic.List[string]]::new()
            foreach ($c in $script:Controls) {
                if ($null -eq $c.References) { continue }
                $mitre = $c.References.MITRE
                if (-not $mitre) { continue }
                foreach ($id in @($mitre)) {
                    if (-not $rx.IsMatch([string]$id)) { $bad.Add("$($c.ControlId) -> '$id'") }
                }
            }
            $bad -join "`n" | Should -BeNullOrEmpty -Because 'every MITRE token must be a well-formed ATT&CK technique ID'
        }
    }
}
