#Requires -Version 7.0
#
# TP.NISTPhysical.Tests.ps1
#
# Guards Config/nist-physical.json and Lib/Get-TPNISTPhysicalPosture.ps1 — the
# physical, media, maintenance and endpoint-device 800-53 section.
#
# The section exists because a Microsoft 365 tenant scan cannot see a locked
# server room, a certificate of destruction, or a returned badge, and omitting
# those controls silently is the dangerous option: a reader looking at a clean
# NIST family table would reasonably infer the physical families were assessed
# and passed. Listing them makes the boundary explicit.
#
# That only holds while two properties hold, and both are enforced here.
#
#   1. An 'Attested' item NEVER reports a compliance state. It was not
#      assessed. If the status derivation ever let evidence leak into an
#      Attested row, the section would start making exactly the claim it was
#      built to avoid — and it would look more authoritative for doing so,
#      because it sits under a NIST heading.
#
#   2. Every EvidenceControls entry names a control that really exists. This
#      config is hand-maintained against controls.json; a renamed or retired
#      control ID would silently produce a "Not assessed" row for a control the
#      tool does in fact check, understating real coverage to the customer.

Describe 'NIST physical / media / device section' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }

        . (Join-Path $script:RepoRoot 'Lib' 'Get-TPObjectField.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Get-TPNISTPhysicalPosture.ps1')

        $script:ConfigPath = Join-Path $script:RepoRoot 'Config/nist-physical.json'
        $script:Config     = Get-Content -LiteralPath $script:ConfigPath -Raw -Encoding utf8 | ConvertFrom-Json

        $script:ControlIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($c in (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 |
                        ConvertFrom-Json).controls) {
            $null = $script:ControlIds.Add($c.ControlId)
        }

        # Flatten every item once so the per-item assertions below stay readable.
        $script:Items = @()
        foreach ($g in $script:Config.groups) {
            foreach ($i in $g.Items) {
                $script:Items += [pscustomobject]@{ Group = $g.Id; Item = $i }
            }
        }
    }

    Context 'Config shape' {

        It 'declares at least one group with items' {
            @($script:Config.groups).Count | Should -BeGreaterThan 0
            @($script:Items).Count         | Should -BeGreaterThan 0
        }

        It 'gives every item a NIST control ID, title and scope' {
            $bad = @()
            foreach ($row in $script:Items) {
                $i = $row.Item
                if (-not $i.PSObject.Properties['NistControl'] -or [string]::IsNullOrWhiteSpace($i.NistControl)) { $bad += "$($row.Group): missing NistControl" ; continue }
                if (-not $i.PSObject.Properties['NistTitle']   -or [string]::IsNullOrWhiteSpace($i.NistTitle))   { $bad += "$($i.NistControl): missing NistTitle" }
                if (-not $i.PSObject.Properties['Scope']       -or [string]::IsNullOrWhiteSpace($i.Scope))       { $bad += "$($i.NistControl): missing Scope" }
            }
            $bad -join '; ' | Should -BeNullOrEmpty
        }

        It 'uses only the three defined scopes' {
            $bad = @($script:Items | Where-Object { $_.Item.Scope -notin @('Tenant','Hybrid','Attested') } |
                     ForEach-Object { "$($_.Item.NistControl) => $($_.Item.Scope)" })
            $bad -join '; ' | Should -BeNullOrEmpty
        }

        It 'uses well-formed 800-53 control identifiers' {
            $bad = @($script:Items | Where-Object { $_.Item.NistControl -notmatch '^[A-Z]{2}-\d{1,3}(\(\d{1,3}\))?$' } |
                     ForEach-Object { $_.Item.NistControl })
            $bad -join '; ' | Should -BeNullOrEmpty
        }

        It 'names no duplicate 800-53 control across the whole config' {
            $dupes = @($script:Items | Group-Object { $_.Item.NistControl } | Where-Object { $_.Count -gt 1 } |
                       ForEach-Object { $_.Name })
            $dupes -join ', ' | Should -BeNullOrEmpty -Because 'a control listed twice would render twice with two different verdicts'
        }

        It 'gives every item at least two implementation options' {
            # The section was asked for as OPTIONS, not as a list of failures.
            # A single option is a directive; a client with an existing
            # third-party stack needs to see the alternatives.
            $bad = @($script:Items | Where-Object {
                -not $_.Item.PSObject.Properties['Options'] -or @($_.Item.Options).Count -lt 2
            } | ForEach-Object { $_.Item.NistControl })
            $bad -join ', ' | Should -BeNullOrEmpty
        }

        It 'gives every item the device aspect it covers' {
            $bad = @($script:Items | Where-Object {
                -not $_.Item.PSObject.Properties['DeviceAspect'] -or [string]::IsNullOrWhiteSpace($_.Item.DeviceAspect)
            } | ForEach-Object { $_.Item.NistControl })
            $bad -join ', ' | Should -BeNullOrEmpty
        }
    }

    Context 'Scope contracts' {

        It 'every EvidenceControls entry names a control that exists in controls.json' {
            # The drift guard. A stale ID here silently understates coverage.
            $bad = @()
            foreach ($row in $script:Items) {
                if (-not $row.Item.PSObject.Properties['EvidenceControls']) { continue }
                foreach ($cid in @($row.Item.EvidenceControls)) {
                    if (-not $script:ControlIds.Contains([string]$cid)) {
                        $bad += "$($row.Item.NistControl) => $cid"
                    }
                }
            }
            $bad -join '; ' | Should -BeNullOrEmpty
        }

        It 'every Tenant-scoped item cites at least one evidence control' {
            # Claiming a control is "evidenced by this assessment" with nothing
            # behind it is the false-coverage failure mode in miniature.
            $bad = @($script:Items | Where-Object {
                $_.Item.Scope -eq 'Tenant' -and
                (-not $_.Item.PSObject.Properties['EvidenceControls'] -or @($_.Item.EvidenceControls).Count -eq 0)
            } | ForEach-Object { $_.Item.NistControl })
            $bad -join ', ' | Should -BeNullOrEmpty
        }

        It 'every Hybrid item cites evidence controls AND names the off-tenant evidence' {
            $bad = @($script:Items | Where-Object {
                $_.Item.Scope -eq 'Hybrid' -and (
                    -not $_.Item.PSObject.Properties['EvidenceControls'] -or
                    @($_.Item.EvidenceControls).Count -eq 0 -or
                    -not $_.Item.PSObject.Properties['OffTenantEvidence'] -or
                    [string]::IsNullOrWhiteSpace($_.Item.OffTenantEvidence)
                )
            } | ForEach-Object { $_.Item.NistControl })
            $bad -join ', ' | Should -BeNullOrEmpty -Because 'Hybrid means partly evidenced — both halves must be stated'
        }

        It 'every Attested item names the off-tenant evidence and cites no tenant evidence' {
            # An Attested row whose only content is "we cannot see this" is
            # worse than useless — it tells the assessor a control exists
            # without telling them what to go and collect.
            $bad = @()
            foreach ($row in $script:Items) {
                $i = $row.Item
                if ($i.Scope -ne 'Attested') { continue }
                if (-not $i.PSObject.Properties['OffTenantEvidence'] -or [string]::IsNullOrWhiteSpace($i.OffTenantEvidence)) {
                    $bad += "$($i.NistControl): no OffTenantEvidence"
                }
                if ($i.PSObject.Properties['EvidenceControls'] -and @($i.EvidenceControls).Count -gt 0) {
                    $bad += "$($i.NistControl): Attested but cites tenant evidence — it should be Hybrid"
                }
            }
            $bad -join '; ' | Should -BeNullOrEmpty
        }

        It 'covers the physical families the M365 assessment genuinely cannot reach' {
            # PE / MP / MA are the families a tenant scan is blind to. If they
            # ever vanish from this config the report silently reverts to
            # implying the NIST family table is the whole picture.
            $fams = @($script:Items | ForEach-Object { ($_.Item.NistControl -split '-')[0] } | Sort-Object -Unique)
            foreach ($f in 'PE','MP','MA','PS') {
                $fams | Should -Contain $f -Because "the $f family is not observable from Microsoft 365 and must be represented"
            }
        }
    }

    Context 'Posture join' {

        It 'returns Available = $false rather than throwing when the config is missing' {
            $missing = Join-Path ([IO.Path]::GetTempPath()) ("tp-nope-" + [Guid]::NewGuid().ToString('N') + '.json')
            $res = Get-TPNISTPhysicalPosture -Findings @() -ConfigPath $missing
            $res.Available | Should -BeFalse
            @($res.Groups).Count | Should -Be 0
        }

        It 'returns a populated posture for an empty findings set, without throwing' {
            $res = Get-TPNISTPhysicalPosture -Findings @() -ConfigPath $script:ConfigPath
            $res.Available | Should -BeTrue
            @($res.Groups).Count | Should -BeGreaterThan 0
        }

        It 'reports Not assessed for a Tenant item whose evidence controls produced no finding' {
            $res = Get-TPNISTPhysicalPosture -Findings @() -ConfigPath $script:ConfigPath
            $items = @($res.Groups | ForEach-Object { $_.Items })
            $tenant = @($items | Where-Object { $_.Scope -eq 'Tenant' })
            $tenant.Count | Should -BeGreaterThan 0
            foreach ($t in $tenant) {
                $t.Status | Should -Be 'Not assessed' `
                    -Because "$($t.NistControl) had no findings at all — absence of data is not a verdict"
            }
        }

        It 'never assigns a compliance status to an Attested item' {
            # The load-bearing assertion of this whole suite. Feed it a findings
            # set that satisfies EVERY control in the tool and confirm the
            # Attested rows still refuse to claim anything.
            $all = @($script:ControlIds | ForEach-Object {
                @{ ControlId = $_; State = 'Satisfied'; Title = 'synthetic' }
            })
            $res = Get-TPNISTPhysicalPosture -Findings $all -ConfigPath $script:ConfigPath
            $attested = @($res.Groups | ForEach-Object { $_.Items } | Where-Object { $_.Scope -eq 'Attested' })
            $attested.Count | Should -BeGreaterThan 0
            foreach ($a in $attested) {
                $a.Status | Should -Be 'Attestation required' `
                    -Because "$($a.NistControl) is not observable from Microsoft 365 and must never read as compliant"
            }
        }

        It 'reports Met only when every cited control is Satisfied' {
            $all = @($script:ControlIds | ForEach-Object {
                @{ ControlId = $_; State = 'Satisfied'; Title = 'synthetic' }
            })
            $res = Get-TPNISTPhysicalPosture -Findings $all -ConfigPath $script:ConfigPath
            $tenant = @($res.Groups | ForEach-Object { $_.Items } | Where-Object { $_.Scope -eq 'Tenant' })
            foreach ($t in $tenant) { $t.Status | Should -Be 'Met' }
        }

        It 'reports Gap when every cited control is a Gap' {
            $all = @($script:ControlIds | ForEach-Object {
                @{ ControlId = $_; State = 'Gap'; Title = 'synthetic' }
            })
            $res = Get-TPNISTPhysicalPosture -Findings $all -ConfigPath $script:ConfigPath
            $tenant = @($res.Groups | ForEach-Object { $_.Items } | Where-Object { $_.Scope -eq 'Tenant' })
            foreach ($t in $tenant) { $t.Status | Should -Be 'Gap' }
        }

        It 'reports Partial for a mix of Satisfied and Gap' {
            # SC-28 cites three controls; satisfy one and fail another.
            $findings = @(
                @{ ControlId = 'INT-1.3'; State = 'Satisfied'; Title = 'BitLocker' },
                @{ ControlId = 'INT-2.4'; State = 'Gap';       Title = 'FileVault' },
                @{ ControlId = 'INT-1.4'; State = 'Satisfied'; Title = 'MAM' }
            )
            $res = Get-TPNISTPhysicalPosture -Findings $findings -ConfigPath $script:ConfigPath
            $sc28 = @($res.Groups | ForEach-Object { $_.Items } | Where-Object { $_.NistControl -eq 'SC-28' })
            $sc28.Status    | Should -Be 'Partial'
            $sc28.Satisfied | Should -Be 2
            $sc28.Gap       | Should -Be 1
        }

        It 'does not treat NotApplicable as evidence of compliance' {
            # An evaluator that could not assess a control has said nothing. It
            # must not push a physical item to Met.
            $findings = @(
                @{ ControlId = 'INT-1.3'; State = 'NotApplicable'; Title = 'BitLocker' },
                @{ ControlId = 'INT-2.4'; State = 'NotApplicable'; Title = 'FileVault' },
                @{ ControlId = 'INT-1.4'; State = 'NotApplicable'; Title = 'MAM' }
            )
            $res  = Get-TPNISTPhysicalPosture -Findings $findings -ConfigPath $script:ConfigPath
            $sc28 = @($res.Groups | ForEach-Object { $_.Items } | Where-Object { $_.NistControl -eq 'SC-28' })
            $sc28.Status | Should -Be 'Not assessed'
            $sc28.NA     | Should -Be 3
        }

        It 'distinguishes a control that did not run from one that returned NotApplicable' {
            # A skipped workload and an evaluator verdict of "not applicable to
            # this tenant" are different facts and must not be conflated.
            $res  = Get-TPNISTPhysicalPosture -Findings @() -ConfigPath $script:ConfigPath
            $sc28 = @($res.Groups | ForEach-Object { $_.Items } | Where-Object { $_.NistControl -eq 'SC-28' })
            $sc28.NotRun | Should -Be 3
            $sc28.NA     | Should -Be 0
        }

        It 'counts scopes consistently with the config' {
            $res = Get-TPNISTPhysicalPosture -Findings @() -ConfigPath $script:ConfigPath
            $expectTenant   = @($script:Items | Where-Object { $_.Item.Scope -eq 'Tenant'   }).Count
            $expectHybrid   = @($script:Items | Where-Object { $_.Item.Scope -eq 'Hybrid'   }).Count
            $expectAttested = @($script:Items | Where-Object { $_.Item.Scope -eq 'Attested' }).Count

            $res.TenantItems      | Should -Be $expectTenant
            $res.HybridItems      | Should -Be $expectHybrid
            $res.AttestedItems    | Should -Be $expectAttested
            $res.AttestationCount | Should -Be ($expectHybrid + $expectAttested)
        }

        It 'README and CLAUDE.md state the live item and scope counts' {
            # Same rationale as the DocAccuracy suite: these are derived numbers
            # that rot the moment an item is added to nist-physical.json, and a
            # README claiming 14 attested controls while the config holds 12 is
            # a claim about assessment scope, not a typo.
            $readme = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'README.md') -Raw -Encoding utf8
            $claude = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'CLAUDE.md') -Raw -Encoding utf8
            $blob   = "$readme`n$claude"

            $total    = @($script:Items).Count
            $tenant   = @($script:Items | Where-Object { $_.Item.Scope -eq 'Tenant'   }).Count
            $hybrid   = @($script:Items | Where-Object { $_.Item.Scope -eq 'Hybrid'   }).Count
            $attested = @($script:Items | Where-Object { $_.Item.Scope -eq 'Attested' }).Count

            foreach ($m in [regex]::Matches($blob, '(\d+)\s+800-53 controls spanning')) {
                [int]$m.Groups[1].Value | Should -Be $total
            }
            foreach ($m in [regex]::Matches($blob, '(\d+)\s+800-53 controls covering endpoint posture')) {
                [int]$m.Groups[1].Value | Should -Be $total
            }
            foreach ($m in [regex]::Matches($blob, '`Tenant`\s*\((\d+),')) {
                [int]$m.Groups[1].Value | Should -Be $tenant
            }
            foreach ($m in [regex]::Matches($blob, '`Hybrid`\s*\((\d+),')) {
                [int]$m.Groups[1].Value | Should -Be $hybrid
            }
            foreach ($m in [regex]::Matches($blob, '`Attested`\s*\((\d+),')) {
                [int]$m.Groups[1].Value | Should -Be $attested
            }

            # The README renders the same three numbers as a table; pin those
            # cells too, or the prose and the table can disagree with each other
            # while both pass.
            $expectByScope = @{ Tenant = $tenant; Hybrid = $hybrid; Attested = $attested }
            foreach ($scope in $expectByScope.Keys) {
                foreach ($m in [regex]::Matches($readme, ('\|\s*\*\*{0}\*\*\s*\|[^|]*\|\s*(\d+)\s*\|' -f $scope))) {
                    [int]$m.Groups[1].Value | Should -Be $expectByScope[$scope] `
                        -Because "the README scope table must state $($expectByScope[$scope]) $scope items"
                }
            }
        }

        It 'skips $null findings without throwing' {
            $res = Get-TPNISTPhysicalPosture -Findings @($null, @{ControlId='INT-1.3';State='Satisfied'}) -ConfigPath $script:ConfigPath
            $res.Available | Should -BeTrue
        }
    }
}
