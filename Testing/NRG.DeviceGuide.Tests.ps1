#Requires -Version 7.0
#
# NRG.DeviceGuide.Tests.ps1
#
# Guards Publishers/Publish-NRGDeviceGuide.ps1 and New-NRGDeviceGuide.ps1 — the
# NIST 800-53 device and endpoint GUIDE.
#
# The guide is reference material, and the two properties that make it that
# rather than a report are both easy to break by accident:
#
#   1. It touches nothing. No Graph, no Exchange Online, no device, no network
#      of any kind. That is what lets it be generated before a tenant is
#      connected, during a sales conversation, or on a site with nothing open.
#      A single Invoke-NRGGraphRequest slipped into the publisher would turn it
#      into something that needs an authenticated session, and the failure would
#      only surface in front of a client.
#
#   2. It works with NO findings. The whole document must render from config
#      alone. Findings are optional annotation, and supplying them may change
#      what the guide reports as already done — never what it RECOMMENDS.
#
# The suite also pins the content contract that makes the guide useful at all:
# every control carries the device aspect it covers and two or more ways to
# satisfy it, because a single option is a directive and a client with an
# existing third-party stack needs alternatives.

Describe 'NIST device and endpoint guide' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }

        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        $script:Config = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/nist-physical.json') -Raw -Encoding utf8 |
            ConvertFrom-Json
        $script:Items = @(foreach ($g in $script:Config.groups) { foreach ($i in $g.Items) { $i } })

        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-guide-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force -Path $script:Tmp | Out-Null

        # The load-bearing case: no findings at all.
        $script:MdPath   = Join-Path $script:Tmp 'guide.md'
        $script:HtmlPath = Join-Path $script:Tmp 'guide.html'
        $script:Error    = $null
        try {
            Publish-NRGDeviceGuide -OutputPath $script:MdPath -ClientName 'Example Client' -ErrorAction Stop
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

    Context 'It is a guide, not an assessment' {

        It 'renders with NO findings supplied' {
            # If this ever requires findings it has stopped being a guide.
            $script:Error | Should -BeNullOrEmpty
            $script:Md.Length   | Should -BeGreaterThan 8000
            $script:Html.Length | Should -BeGreaterThan 8000
        }

        It 'the publisher makes no tenant, device, or network call' {
            # Static guard. The guide's whole premise is that it connects to
            # nothing, and that premise is invisible at runtime until it breaks
            # in front of a client.
            $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Publishers/Publish-NRGDeviceGuide.ps1') -Raw
            foreach ($forbidden in 'Invoke-NRGGraphRequest', 'graph\.microsoft', 'Invoke-RestMethod',
                                   'Invoke-WebRequest', 'Connect-MgGraph', 'Connect-ExchangeOnline',
                                   'Get-Mailbox', 'Resolve-NRGDns', 'Get-NRGRawData') {
                $src | Should -Not -Match $forbidden -Because "the device guide must not $forbidden"
            }
        }

        It 'the entry point makes no tenant, device, or network call' {
            $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'New-NRGDeviceGuide.ps1') -Raw
            foreach ($forbidden in 'Invoke-NRGGraphRequest', 'graph\.microsoft', 'Invoke-RestMethod',
                                   'Invoke-WebRequest', 'Connect-MgGraph', 'Connect-ExchangeOnline',
                                   'Connect-NRGServices') {
                $src | Should -Not -Match $forbidden -Because "New-NRGDeviceGuide.ps1 must not $forbidden"
            }
        }

        It 'says on its face that it is reference material' {
            $script:Md   | Should -BeLike '*reference guide, not an assessment*'
            $script:Md   | Should -BeLike '*Nothing here was measured against your environment*'
            $script:Html | Should -BeLike '*not an assessment*'
            $script:Html | Should -BeLike '*Nothing in this document was collected from a device*'
        }
    }

    Context 'Content contract' {

        It 'renders every control from the config' {
            foreach ($it in $script:Items) {
                $script:Md | Should -BeLike "*$($it.NistControl) — $($it.NistTitle)*" `
                    -Because "$($it.NistControl) must appear in the guide"
            }
        }

        It 'renders every implementation option' {
            # 98 options across 31 controls. A dropped option is guidance the
            # client silently never sees.
            $total = 0
            foreach ($it in $script:Items) { $total += @($it.Options).Count }
            $rendered = ([regex]::Matches($script:Md, '(?m)^- ')).Count
            $rendered | Should -BeGreaterOrEqual $total `
                -Because "all $total implementation options must render"
        }

        It 'gives every control at least two options' {
            # A single option is a directive. A client already standardised on a
            # third-party stack needs alternatives, or the guide reads as a
            # sales document for one vendor.
            $thin = @($script:Items | Where-Object { @($_.Options).Count -lt 2 } | ForEach-Object { $_.NistControl })
            $thin -join ', ' | Should -BeNullOrEmpty
        }

        It 'states the scope of every control' {
            foreach ($scope in 'Tenant', 'Hybrid', 'Attested') {
                $script:Md | Should -BeLike "*Scope:** $scope*"
            }
        }

        It 'explains that an Attested control is not a lesser control' {
            # Without this an operator reasonably deprioritises everything the
            # tenant cannot see, which is most of the physical families.
            $script:Md   | Should -BeLike '*not a lesser control*'
            $script:Html | Should -BeLike '*not a lesser control*'
        }

        It 'carries the evidence-to-keep note on every attested control' {
            $attested = @($script:Items | Where-Object { $_.Scope -eq 'Attested' })
            $attested.Count | Should -BeGreaterThan 0
            foreach ($it in $attested) {
                $script:Md | Should -BeLike "*$($it.OffTenantEvidence)*" `
                    -Because "$($it.NistControl) must tell the assessor what to collect"
            }
        }

        It 'includes a quick-reference table covering every control' {
            $script:Md | Should -BeLike '*## Quick reference*'
            $rows = ([regex]::Matches($script:Md, '(?m)^\| \d+ \| \*\*[A-Z]{2}-')).Count
            $rows | Should -Be @($script:Items).Count
        }

        It 'titles the document for the named client' {
            $script:Md   | Should -BeLike '*Device and Endpoint Guide for Example Client*'
            $script:Html | Should -BeLike '*Device and Endpoint Guide for Example Client*'
        }
    }

    Context 'HTML deliverable' {

        It 'is a well-formed, self-contained document' {
            $script:Html | Should -Match '<!DOCTYPE html>'
            $script:Html | Should -Match '</html>'
        }

        It 'references no external asset' {
            # It gets emailed, opened offline, and printed on a site with no
            # network. A CDN font or remote stylesheet breaks all three.
            $script:Html | Should -Not -Match 'src="http'
            $script:Html | Should -Not -Match 'href="http'
            $script:Html | Should -Not -Match '@import'
        }

        It 'carries print styling so it can be handed over on paper' {
            $script:Html | Should -Match '@media print'
        }

        It 'escapes hostile config content rather than emitting live markup' {
            $evil = Join-Path $script:Tmp 'evil.json'
            @{
                version = '1.0'
                groups  = @(@{
                    Id = 'g1'; Title = 'G'; Description = 'd'
                    Items = @(@{
                        NistControl = 'AC-1'
                        NistTitle   = '<script>nrgguideprobe</script>'
                        Scope       = 'Attested'
                        DeviceAspect = 'aspect'
                        OffTenantEvidence = 'evidence'
                        Options     = @('one', 'two')
                    })
                })
            } | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $evil -Encoding utf8

            $p = Join-Path $script:Tmp 'evil.md'
            Publish-NRGDeviceGuide -OutputPath $p -ConfigPath $evil
            $h = Get-Content -LiteralPath ([System.IO.Path]::ChangeExtension($p, '.html')) -Raw

            $h | Should -Not -Match '<script>nrgguideprobe'
            $h | Should -Match 'nrgguideprobe'   # present, but escaped
        }

        It 'leaks no object-stringification artifacts' {
            foreach ($leak in 'System\.Collections\.Hashtable', 'System\.Object\[\]', 'System\.Collections\.Generic') {
                $script:Md   | Should -Not -Match $leak
                $script:Html | Should -Not -Match $leak
            }
        }
    }

    Context 'Optional findings annotation' {

        BeforeAll {
            # SC-28 is evidenced by INT-1.3 / INT-2.4 / INT-1.4.
            $script:Annotated = Join-Path $script:Tmp 'annotated.md'
            Publish-NRGDeviceGuide -OutputPath $script:Annotated -Findings @(
                @{ ControlId = 'INT-1.3'; State = 'Gap';       Title = 'BitLocker' },
                @{ ControlId = 'INT-2.4'; State = 'Satisfied'; Title = 'FileVault' }
            )
            $script:AnnMd = Get-Content -LiteralPath $script:Annotated -Raw
        }

        It 'reports assessment results when findings are supplied' {
            $script:AnnMd | Should -BeLike '*Assessment result*'
            $script:AnnMd | Should -BeLike '*INT-1.3 — Gap*'
        }

        It 'reports no assessment results when findings are not supplied' {
            $script:Md | Should -Not -BeLike '*Assessment result*'
        }

        It 'recommends exactly the same options either way' {
            # Findings may change what the guide says is DONE. They must never
            # change what it says to DO — otherwise two clients with the same
            # obligations get different advice because one was scanned first.
            $optsOf = {
                param($text)
                @([regex]::Matches($text, '(?m)^- (.+)$') | ForEach-Object { $_.Groups[1].Value }) -join "`n"
            }
            (& $optsOf $script:AnnMd) | Should -Be (& $optsOf $script:Md)
        }

        It 'never claims compliance for an attested control, even with findings' {
            # The rule the whole physical section exists to enforce, restated
            # here because the guide is the copy a client actually reads.
            $all = @(
                @{ ControlId = 'INT-1.3'; State = 'Satisfied' }, @{ ControlId = 'INT-2.4'; State = 'Satisfied' },
                @{ ControlId = 'INT-1.4'; State = 'Satisfied' }, @{ ControlId = 'AAD-12.3'; State = 'Satisfied' }
            )
            $p = Join-Path $script:Tmp 'allsat.md'
            Publish-NRGDeviceGuide -OutputPath $p -Findings $all
            $txt = Get-Content -LiteralPath $p -Raw

            foreach ($it in @($script:Items | Where-Object { $_.Scope -eq 'Attested' })) {
                $section = ($txt -split "### $([regex]::Escape($it.NistControl)) — ")[1]
                if ($section) {
                    $section = ($section -split '(?m)^### ')[0]
                    $section | Should -Not -Match 'Assessment result' `
                        -Because "$($it.NistControl) is attested and must carry no verdict"
                }
            }
        }
    }

    Context 'Degradation' {

        It 'rejects a path-traversal output path' {
            { Publish-NRGDeviceGuide -OutputPath '../../evil.md' } | Should -Throw
        }

        It 'throws a clear error when the config is missing rather than writing an empty guide' {
            $missing = Join-Path $script:Tmp ('nope-' + [Guid]::NewGuid().ToString('N') + '.json')
            { Publish-NRGDeviceGuide -OutputPath (Join-Path $script:Tmp 'x.md') -ConfigPath $missing } |
                Should -Throw '*device guide not generated*'
        }
    }
}
