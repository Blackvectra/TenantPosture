#Requires -Version 7.0
#
# TP.FrameworkAccuracy.Tests.ps1
#
# Dependencies: None (reads Config/controls.json + Config/framework-baselines/)
# TenantPosture
# Author: Matthew Levorson
# Purpose: Validate every framework crosswalk ID in controls.json against an
#          authoritative, bug-worked-out reference. Today: SCuBA IDs vs the
#          bundled CISA ScubaGear 2.0.0 baseline. Catches typos, nonexistent
#          IDs, and version drift (e.g. MS.AAD.3.3v1 -> v2) in CI instead of at
#          client-report time.
#
# Consumes: Config/controls.json, Config/framework-baselines/scuba-ids-v2.0.0.txt
# Sets:     nothing.

Describe 'Framework crosswalk accuracy' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $controlsPath = Join-Path $script:RepoRoot 'Config' 'controls.json'
        $script:Controls = (Get-Content -LiteralPath $controlsPath -Raw | ConvertFrom-Json)
        if ($script:Controls.PSObject.Properties['controls']) { $script:Controls = $script:Controls.controls }

        $scubaPath = Join-Path $script:RepoRoot 'Config' 'framework-baselines' 'scuba-ids-v2.0.0.txt'
        $script:AuthScuba = @(Get-Content -LiteralPath $scubaPath |
            Where-Object { $_ -and -not $_.StartsWith('#') } |
            ForEach-Object { $_.Trim() })

        $cisPath = Join-Path $script:RepoRoot 'Config' 'framework-baselines' 'cis-controls-v8.1-safeguards.txt'
        $script:AuthCis = @(Get-Content -LiteralPath $cisPath |
            Where-Object { $_ -match '^\d' } |
            ForEach-Object { ($_ -split '\s+', 2)[0] })
    }

    Context 'SCuBA references vs authoritative ScubaGear 2.0.0 baseline' {
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
            $bad -join "`n" | Should -BeNullOrEmpty -Because 'every SCuBA ID must be a real ScubaGear 2.0.0 policy (regenerate the baseline file on version upgrade)'
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

    Context 'CIS Controls v8.1 references vs authoritative safeguard list' {
        It 'Bundled CIS v8.1 safeguard list has all 153 safeguards' {
            $script:AuthCis.Count | Should -Be 153
        }

        It 'Every References.CISControls safeguard exists in the authoritative v8.1 list' {
            $authSet = [System.Collections.Generic.HashSet[string]]::new(
                [string[]]$script:AuthCis, [System.StringComparer]::Ordinal)
            $bad = [System.Collections.Generic.List[string]]::new()
            foreach ($c in $script:Controls) {
                if ($null -eq $c.References) { continue }
                $cis = $c.References.CISControls
                if ($null -eq $cis) { continue }
                foreach ($sg in @($cis)) {
                    if (-not $authSet.Contains([string]$sg)) { $bad.Add("$($c.ControlId) -> $sg") }
                }
            }
            $bad -join "`n" | Should -BeNullOrEmpty -Because 'every CIS Controls v8.1 safeguard must exist in the authoritative list'
        }

        It 'Every control carries a CISControls field (array, possibly empty)' {
            $missing = @($script:Controls | Where-Object {
                $null -eq $_.References -or $null -eq $_.References.PSObject.Properties['CISControls']
            } | ForEach-Object { $_.ControlId })
            $missing -join ', ' | Should -BeNullOrEmpty
        }
    }

    Context 'CMMC 2.0 references — domain + level correctness' {
        # CMMC 2.0 L2 practices map 1:1 to NIST SP 800-171 R2 requirements (3.X.Y).
        # The domain prefix is fixed by the 3.X family; the level (L1/L2) is fixed
        # by the 17-practice FAR 52.204-21 Level 1 subset. Both are authoritative
        # and typo-detectable.
        It 'Every CMMC id has the right domain for its 800-171 family and the right level' {
            $fam2dom = @{ '3.1'='AC';'3.2'='AT';'3.3'='AU';'3.4'='CM';'3.5'='IA';'3.6'='IR';
                          '3.7'='MA';'3.8'='MP';'3.9'='PS';'3.10'='PE';'3.11'='RA';'3.12'='CA';
                          '3.13'='SC';'3.14'='SI' }
            $L1 = @('3.1.1','3.1.2','3.1.20','3.1.22','3.5.1','3.5.2','3.8.3','3.10.1',
                    '3.10.3','3.10.4','3.10.5','3.13.1','3.13.5','3.14.1','3.14.2','3.14.4','3.14.5')
            $rx = [regex]'^([A-Z]{2})\.L([12])-(3\.\d+)\.(\d+)$'
            $bad = [System.Collections.Generic.List[string]]::new()
            foreach ($c in $script:Controls) {
                if ($null -eq $c.References) { continue }
                $cmmc = [string]$c.References.CMMC
                if (-not $cmmc) { continue }
                foreach ($tok in ($cmmc -split '[;,]')) {
                    $t = $tok.Trim(); if (-not $t) { continue }
                    $m = $rx.Match($t)
                    if (-not $m.Success) { $bad.Add("$($c.ControlId) -> '$t' (malformed)"); continue }
                    $dom = $m.Groups[1].Value; $lvl = $m.Groups[2].Value
                    $fam = $m.Groups[3].Value; $nist = "$fam.$($m.Groups[4].Value)"
                    $wantDom = $fam2dom[$fam]
                    $wantLvl = if ($L1 -contains $nist) { '1' } else { '2' }
                    if ($dom -ne $wantDom -or $lvl -ne $wantLvl) {
                        $bad.Add("$($c.ControlId) -> $t (expected $wantDom.L$wantLvl-$nist)")
                    }
                }
            }
            $bad -join "`n" | Should -BeNullOrEmpty -Because 'CMMC domain must match the 800-171 family and level must match the FAR-17 L1 subset'
        }
    }

    Context 'ISO/IEC 27001:2022 references — valid Annex A control numbers' {
        It 'Every ISO27001 id is a real Annex A 2022 control (A.5.1-37, A.6.1-8, A.7.1-14, A.8.1-34)' {
            $isoMax = @{ '5'=37; '6'=8; '7'=14; '8'=34 }
            $rx = [regex]'^A\.(\d+)\.(\d+)$'
            $bad = [System.Collections.Generic.List[string]]::new()
            foreach ($c in $script:Controls) {
                if ($null -eq $c.References) { continue }
                $iso = [string]$c.References.ISO27001
                if (-not $iso) { continue }
                foreach ($tok in ($iso -split '[;,]')) {
                    $t = $tok.Trim(); if (-not $t) { continue }
                    $m = $rx.Match($t)
                    if (-not $m.Success) { $bad.Add("$($c.ControlId) -> '$t' (malformed)"); continue }
                    $clause = $m.Groups[1].Value; $num = [int]$m.Groups[2].Value
                    if (-not $isoMax.ContainsKey($clause) -or $num -lt 1 -or $num -gt $isoMax[$clause]) {
                        $bad.Add("$($c.ControlId) -> $t (out of Annex A range)")
                    }
                }
            }
            $bad -join "`n" | Should -BeNullOrEmpty -Because 'every ISO 27001:2022 Annex A control number must exist'
        }
    }
}
