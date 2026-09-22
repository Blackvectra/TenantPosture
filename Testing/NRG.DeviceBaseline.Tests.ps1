#Requires -Version 7.0
#
# NRG.DeviceBaseline.Tests.ps1
#
# Guards Config/device-baseline.json and Publishers/Publish-NRGDeviceBaseline.ps1
# — the managed device BUILD STANDARD.
#
# This document gets printed and worked down by a technician, and handed to a
# client as "this is our standard". Three things have to hold for that to be
# safe:
#
#   1. It touches nothing. Same rule as the device guide — no Graph, no EXO, no
#      endpoint. A build standard that needs an authenticated session is not
#      usable at the bench.
#
#   2. Every cross-reference resolves. A VerifiedBy naming a control that no
#      longer exists tells the reader the assessment covers something it does
#      not, and a NIST citation with no catalog entry renders as a bare code an
#      auditor cannot follow. Both rot silently as the tool changes around them.
#
#   3. Every item is actionable. A requirement with no "how" is a wish, and one
#      with no "why" gets skipped the first time it is inconvenient — which is
#      exactly when it matters.

Describe 'Managed device baseline (build standard)' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }

        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        $script:CfgPath = Join-Path $script:RepoRoot 'Config/device-baseline.json'
        $script:Cfg     = Get-Content -LiteralPath $script:CfgPath -Raw -Encoding utf8 | ConvertFrom-Json
        $script:Stages  = @($script:Cfg.stages)
        $script:Items   = @(foreach ($s in $script:Stages) { foreach ($i in $s.Items) { $i } })

        $script:ControlIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        foreach ($c in (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 |
                        ConvertFrom-Json).controls) { $null = $script:ControlIds.Add($c.ControlId) }

        $script:Catalog = (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/nist-800-53-catalog.json') -Raw -Encoding utf8 |
            ConvertFrom-Json).controls

        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-base-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force -Path $script:Tmp | Out-Null
        $script:MdPath   = Join-Path $script:Tmp 'baseline.md'
        $script:HtmlPath = Join-Path $script:Tmp 'baseline.html'

        $script:Error = $null
        try {
            Publish-NRGDeviceBaseline -OutputPath $script:MdPath -ClientName 'Example Client' -ErrorAction Stop
        } catch { $script:Error = $_ }

        $script:Md   = if (Test-Path -LiteralPath $script:MdPath)   { Get-Content -LiteralPath $script:MdPath   -Raw } else { '' }
        $script:Html = if (Test-Path -LiteralPath $script:HtmlPath) { Get-Content -LiteralPath $script:HtmlPath -Raw } else { '' }
    }

    AfterAll {
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) {
            Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
        Clear-NRGState
    }

    Context 'Config integrity' {

        It 'has stages, each with items' {
            $script:Stages.Count | Should -BeGreaterThan 0
            foreach ($s in $script:Stages) {
                @($s.Items).Count | Should -BeGreaterThan 0 -Because "stage $($s.Id) must contain requirements"
            }
        }

        It 'gives every item a unique, well-formed ID' {
            $ids = @($script:Items | ForEach-Object { $_.Id })
            foreach ($id in $ids) { $id | Should -Match '^DB-\d+\.\d+$' }
            ($ids | Group-Object | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name }) -join ', ' |
                Should -BeNullOrEmpty -Because 'a duplicate ID makes the checklist ambiguous'
        }

        It 'gives every item a requirement, a why, and a how' {
            # A requirement with no "how" is a wish. One with no "why" gets
            # skipped the first time it is inconvenient.
            $bad = @()
            foreach ($i in $script:Items) {
                foreach ($f in 'Requirement', 'Why', 'How') {
                    if (-not $i.PSObject.Properties[$f] -or [string]::IsNullOrWhiteSpace([string]$i.$f)) {
                        $bad += "$($i.Id): missing $f"
                    }
                }
            }
            $bad -join '; ' | Should -BeNullOrEmpty
        }

        It 'declares Mandatory as a real boolean on every item' {
            foreach ($i in $script:Items) {
                $i.PSObject.Properties['Mandatory'] | Should -Not -BeNullOrEmpty -Because "$($i.Id) must declare Mandatory"
                $i.Mandatory | Should -BeOfType [bool]
            }
        }

        It 'names at least one platform per item, from the known set' {
            $known = @('Windows', 'macOS', 'iOS', 'Android')
            foreach ($i in $script:Items) {
                @($i.AppliesTo).Count | Should -BeGreaterThan 0 -Because "$($i.Id) must say what it applies to"
                foreach ($p in @($i.AppliesTo)) {
                    $p | Should -BeIn $known -Because "$($i.Id) names an unknown platform"
                }
            }
        }

        It 'every VerifiedBy names a control that exists in controls.json' {
            # The drift guard. A stale ID tells the reader the assessment covers
            # something it does not.
            $bad = @()
            foreach ($i in $script:Items) {
                foreach ($v in @($i.VerifiedBy)) {
                    if (-not $script:ControlIds.Contains([string]$v)) { $bad += "$($i.Id) => $v" }
                }
            }
            $bad -join '; ' | Should -BeNullOrEmpty
        }

        It 'every NIST citation resolves to a catalog title' {
            # Otherwise the row renders as a bare code the reader cannot follow
            # back to their own 800-53 documentation.
            $bad = @()
            foreach ($i in $script:Items) {
                @($i.Nist).Count | Should -BeGreaterThan 0 -Because "$($i.Id) must cite at least one 800-53 control"
                foreach ($n in @($i.Nist)) {
                    if (-not $script:Catalog.PSObject.Properties[$n]) { $bad += "$($i.Id) => $n" }
                    (Get-NRGNISTControlTitle -ControlId $n) | Should -Not -BeNullOrEmpty
                }
            }
            $bad -join '; ' | Should -BeNullOrEmpty
        }

        It 'covers the whole device lifecycle, not just the build' {
            # A standard that stops at hand-over is the one that leaves data on
            # a laptop nobody collected. Offboarding is the stage most often
            # skipped and the one that matters after the relationship ends.
            $ids = @($script:Stages | ForEach-Object { $_.Id })
            foreach ($stage in 'procure', 'provision', 'harden', 'inservice', 'offboard') {
                $ids | Should -Contain $stage
            }
        }

        It 'marks the non-negotiable controls mandatory' {
            # Encryption, EDR, patching, MDM enrollment and the CA enforcement
            # that gives them teeth. If any of these become optional the
            # standard has quietly stopped being one.
            foreach ($id in 'DB-2.1', 'DB-2.3', 'DB-2.5', 'DB-3.2', 'DB-4.1', 'DB-4.3') {
                $item = @($script:Items | Where-Object { $_.Id -eq $id })
                $item.Count      | Should -Be 1 -Because "$id must exist"
                $item[0].Mandatory | Should -BeTrue -Because "$id is not optional in a managed estate"
            }
        }
    }

    Context 'Rendered standard' {

        It 'publishes without throwing' {
            $script:Error | Should -BeNullOrEmpty
            $script:Md.Length   | Should -BeGreaterThan 6000
            $script:Html.Length | Should -BeGreaterThan 6000
        }

        It 'the publisher makes no tenant, device, or network call' {
            $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Publishers/Publish-NRGDeviceBaseline.ps1') -Raw
            foreach ($forbidden in 'Invoke-NRGGraphRequest', 'graph\.microsoft', 'Invoke-RestMethod',
                                   'Invoke-WebRequest', 'Connect-MgGraph', 'Connect-ExchangeOnline',
                                   'Get-Mailbox', 'Resolve-NRGDns', 'Get-NRGRawData') {
                $src | Should -Not -Match $forbidden -Because "the build standard must not $forbidden"
            }
        }

        It 'leads with a checklist a technician can work down' {
            $script:Md | Should -BeLike '*## Build checklist*'
            # One unchecked box per requirement.
            ([regex]::Matches($script:Md, '(?m)^- \[ \] ')).Count | Should -Be $script:Items.Count
            # And the checklist comes before the detail, not after.
            $script:Md.IndexOf('## Build checklist') | Should -BeLessThan $script:Md.IndexOf('## The standard in detail')
        }

        It 'renders every requirement with its why, how and citations' {
            foreach ($i in $script:Items) {
                $script:Md | Should -BeLike "*$($i.Id) — $($i.Requirement)*"
                $script:Md | Should -BeLike "*$($i.Why)*"
                $script:Md | Should -BeLike "*$($i.How)*"
            }
        }

        It 'renders 800-53 titles beside the identifiers' {
            $script:Md | Should -BeLike '*SC-28 Protection of Information at Rest*'
            $script:Md | Should -BeLike '*SI-2 Flaw Remediation*'
        }

        It 'says plainly when an item cannot be checked from the tenant' {
            # Half the standard is build-time work no scan can confirm. Leaving
            # that implicit invites the reader to assume the assessment covers
            # everything listed.
            $unverifiable = @($script:Items | Where-Object { @($_.VerifiedBy).Count -eq 0 })
            $unverifiable.Count | Should -BeGreaterThan 0
            $script:Md | Should -BeLike '*Not checkable from the tenant*'
        }

        It 'renders code spans rather than eating the backticks' {
            # A backtick in a PowerShell double-quoted string is the escape
            # character; `$(...) escapes the interpolation outright. Both
            # happened here before this test existed.
            $bt = [char]0x60
            $script:Md.Contains($bt + 'DB-1.1' + $bt) | Should -BeTrue
            $script:Md.Contains($bt + 'M' + $bt)      | Should -BeTrue
            $script:Md | Should -Not -Match '\$\(EscMd'
        }

        It 'titles the standard for the named client' {
            $script:Md   | Should -BeLike '*Managed Device Baseline — Example Client*'
            $script:Html | Should -BeLike '*Managed Device Baseline*'
        }

        It 'produces self-contained, printable HTML' {
            $script:Html | Should -Match '<!DOCTYPE html>'
            $script:Html | Should -Match '</html>'
            $script:Html | Should -Match '@media print'
            $script:Html | Should -Not -Match 'src="http'
            $script:Html | Should -Not -Match 'href="http'
        }

        It 'escapes hostile config content rather than emitting live markup' {
            $evil = Join-Path $script:Tmp 'evil.json'
            @{
                version = '1.0'; title = 'T'
                stages = @(@{
                    Id = 's1'; Title = 'S'; Description = 'd'
                    Items = @(@{
                        Id = 'DB-9.9'; Requirement = '<script>nrgbaseprobe</script>'
                        Mandatory = $true; AppliesTo = @('Windows')
                        Why = 'w'; How = 'h'; Nist = @('SC-28'); VerifiedBy = @()
                    })
                })
            } | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $evil -Encoding utf8

            $p = Join-Path $script:Tmp 'evil.md'
            Publish-NRGDeviceBaseline -OutputPath $p -ConfigPath $evil
            $h = Get-Content -LiteralPath ([System.IO.Path]::ChangeExtension($p, '.html')) -Raw
            $h | Should -Not -Match '<script>nrgbaseprobe'
            $h | Should -Match 'nrgbaseprobe'
        }

        It 'leaks no object-stringification artifacts' {
            foreach ($leak in 'System\.Collections\.Hashtable', 'System\.Object\[\]', 'System\.Collections\.Generic') {
                $script:Md   | Should -Not -Match $leak
                $script:Html | Should -Not -Match $leak
            }
        }
    }

    Context 'Degradation' {

        It 'rejects a path-traversal output path' {
            { Publish-NRGDeviceBaseline -OutputPath '../../evil.md' } | Should -Throw
        }

        It 'throws a clear error when the config is missing' {
            $missing = Join-Path $script:Tmp ('nope-' + [Guid]::NewGuid().ToString('N') + '.json')
            { Publish-NRGDeviceBaseline -OutputPath (Join-Path $script:Tmp 'x.md') -ConfigPath $missing } |
                Should -Throw '*device baseline not generated*'
        }

        It 'throws a clear error on malformed JSON rather than writing a broken standard' {
            $bad = Join-Path $script:Tmp 'bad.json'
            '{ not json' | Out-File -LiteralPath $bad -Encoding utf8
            { Publish-NRGDeviceBaseline -OutputPath (Join-Path $script:Tmp 'y.md') -ConfigPath $bad } |
                Should -Throw '*device baseline not generated*'
        }
    }
}
