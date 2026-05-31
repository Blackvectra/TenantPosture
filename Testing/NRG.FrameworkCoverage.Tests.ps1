#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
<#
.SYNOPSIS
    Framework citation coverage invariants for Config/controls.json.

.DESCRIPTION
    The MSP business case for this tool is "I can sell HIPAA / SOC 2 / PCI DSS /
    ISO 27001 assessments and every gap has a citation." That breaks the moment
    a new control lands without all framework refs populated. These tests guard
    that contract on every PR:

      - Every control must carry a non-empty citation for CIS, CMMC, NIST,
        MITRE, HIPAA, SOC2, PCIDSS, ISO27001.
      - HIPAA citations must begin with "§164." (Security Rule / Privacy Rule /
        Breach Notification — every applicable subpart starts with that).
      - SOC 2 citations must match a real TSC code (CC1-CC9, A1, C1, P1-P8).
      - PCI DSS citations must reference a Req number (Req 1-12) or a dotted
        sub-requirement.
      - ISO 27001 citations must reference an Annex A clause (A.5-A.8).
#>

Describe 'controls.json — framework citation coverage' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:JsonPath = Join-Path $script:RepoRoot 'Config\controls.json'
        $script:Data     = Get-Content -LiteralPath $script:JsonPath -Raw -Encoding utf8 | ConvertFrom-Json
        $script:Controls = @($script:Data.controls)
    }

    It 'controls.json exists and parses' {
        $script:Controls.Count | Should -BeGreaterOrEqual 150 -Because 'sanity bound — we should have ≥150 controls today'
    }

    Context 'Every control has every required framework citation' {

        $requiredFrameworks = @('CIS','CMMC','NIST','MITRE','HIPAA','SOC2','PCIDSS','ISO27001')

        foreach ($fw in $requiredFrameworks) {
            It "100% of controls have a non-empty $fw citation" {
                $offenders = @($script:Controls | Where-Object {
                    $val = $null
                    if ($_.PSObject.Properties['References'] -and $_.References) {
                        $prop = $_.References.PSObject.Properties[$fw]
                        if ($prop) { $val = $prop.Value }
                    }
                    # MITRE may be a string OR an array; empty array also fails
                    if ($val -is [array]) { return $val.Count -eq 0 }
                    [string]::IsNullOrWhiteSpace([string]$val)
                } | ForEach-Object { $_.ControlId })

                $offenders | Should -BeNullOrEmpty -Because "$fw must be cited for every control — this gate exists because the MSP product depends on it"
            }
        }
    }

    Context 'Citations match each framework''s reference shape' {

        It 'Every HIPAA citation begins with §164.' {
            $bad = @($script:Controls | Where-Object {
                $h = [string]$_.References.HIPAA
                $h -and -not $h.StartsWith([char]0xA7 + '164.')
            } | ForEach-Object { "$($_.ControlId): $($_.References.HIPAA)" })
            $bad | Should -BeNullOrEmpty -Because 'HIPAA citations are Security/Privacy/Breach Rule references — all §164.xxx'
        }

        It 'Every SOC 2 citation matches a Trust Services Criteria code' {
            # Allowed prefixes: CC1-CC9, A1-A3 (availability), C1-C2 (confidentiality),
            # PI1-PI2 (processing integrity), P1-P8 (privacy)
            $pattern = '^(CC[1-9](\.\d+)?|A[1-3](\.\d+)?|C[1-2](\.\d+)?|PI[1-2](\.\d+)?|P[1-8](\.\d+)?)(,\s*(CC[1-9](\.\d+)?|A[1-3](\.\d+)?|C[1-2](\.\d+)?|PI[1-2](\.\d+)?|P[1-8](\.\d+)?))*$'
            $bad = @($script:Controls | Where-Object {
                $v = [string]$_.References.SOC2
                $v -and ($v -notmatch $pattern)
            } | ForEach-Object { "$($_.ControlId): $($_.References.SOC2)" })
            $bad | Should -BeNullOrEmpty -Because 'SOC 2 cites must be TSC codes (CC, A, C, PI, P)'
        }

        It 'Every PCI DSS citation references "Req N" or a dotted sub-requirement' {
            $pattern = '^Req\s*\d+(\.\d+)*(,\s*Req\s*\d+(\.\d+)*)*$'
            $bad = @($script:Controls | Where-Object {
                $v = [string]$_.References.PCIDSS
                $v -and ($v -notmatch $pattern)
            } | ForEach-Object { "$($_.ControlId): $($_.References.PCIDSS)" })
            $bad | Should -BeNullOrEmpty -Because 'PCI DSS cites must be Req N or Req N.N.N'
        }

        It 'Every ISO 27001 citation references an Annex A clause' {
            $pattern = '^A\.[5-8](\.\d+)?(,\s*A\.[5-8](\.\d+)?)*$'
            $bad = @($script:Controls | Where-Object {
                $v = [string]$_.References.ISO27001
                $v -and ($v -notmatch $pattern)
            } | ForEach-Object { "$($_.ControlId): $($_.References.ISO27001)" })
            $bad | Should -BeNullOrEmpty -Because 'ISO 27001:2022 Annex A is organized as A.5 (org), A.6 (people), A.7 (physical), A.8 (technological)'
        }
    }

    Context 'No regression on the specific HIPAA mappings audit-fixed in this release' {
        # These are the 10 confirmed HIPAA mapping errors the audit caught.
        # If a future PR reverts any of them, this test fires.

        $fixed = @{
            'EXO-1.1'  = '§164.312(b)'
            'EXO-1.2' = '§164.312(e)(1)'
            'EXO-5.1' = '§164.312(b)'
            'EXO-7.3' = '§164.312(b)'
            'AAD-7.2' = '§164.312(a)(2)(ii)'
            'INT-4.3' = '§164.308(a)(1)(ii)(B)'
            'PVW-1.1' = '§164.312(b)'
            'PVW-2.4' = '§164.308(a)(6)'
            'PVW-4.2' = '§164.316(b)(2)(i)'
            'PVW-4.3' = '§164.502(b)'
        }
        foreach ($entry in $fixed.GetEnumerator()) {
            $id  = $entry.Key
            $expected = $entry.Value
            It "$id HIPAA citation still references $expected" {
                $c = $script:Controls | Where-Object ControlId -eq $id
                $c | Should -Not -BeNullOrEmpty
                [string]$c.References.HIPAA | Should -Match ([regex]::Escape($expected))
            }
        }
    }
}
