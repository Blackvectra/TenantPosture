#Requires -Version 7.0
#
# NRG.PublisherMetadata.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Two bug classes found by generating the matrices and reading the output,
# rather than by running the suite — which passed throughout.
#
# 1. `$Metadata.Operator ?? ''` aborts the publisher when the key is absent.
#    Under StrictMode a missing key THROWS before `??` can supply the default.
#    Metadata is assembled ad hoc: the live path in Invoke-NRGAssessment.ps1
#    sets Operator and TenantId, but the -FromResults replay path builds a
#    fallback carrying only TenantDomain / AssessmentDate / ToolVersion. The
#    caller wraps each publisher in a try/catch that degrades to a warning, so
#    the XLSX compliance matrix was simply NOT PRODUCED on a replay, with one
#    warning line in console output and no other signal.
#
# 2. The Summary surfaces omitted the Error count. Errors are scored as
#    failures and sit in the denominator, so a reader adding
#    met + partial + gaps + N/A came up short of the finding count with no way
#    to tell whether the missing rows were passes or failures. The per-family
#    and per-control rollups already carried an Error column; the headline
#    summaries — the part anyone actually reads — did not, because `Error`
#    was never put into the Python payload's Overall block.

Describe 'Publisher metadata robustness' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        # EXACTLY the fallback hashtable Invoke-NRGAssessment.ps1 builds when
        # -FromResults is given a results file with no Metadata block.
        $script:ReplayMetadata = @{
            TenantDomain   = 'example.com'
            AssessmentDate = 'September 15, 2026'
            ToolVersion    = '4.12.1'
        }
    }

    Context 'the -FromResults metadata shape does not abort a publisher' {

        It 'no publisher reads a Metadata key with dot-access followed by ??' {
            # Static guard, so a newly added `$Metadata.Something ?? 'x'` fails
            # here rather than silently suppressing a deliverable on replay.
            # Behavioural coverage alone would only catch the keys we thought
            # to omit today.
            $offenders = [System.Collections.Generic.List[string]]::new()
            foreach ($f in Get-ChildItem (Join-Path $script:RepoRoot 'Publishers') -Filter '*.ps1' -Recurse) {
                $lines = Get-Content -LiteralPath $f.FullName
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    $line = $lines[$i]
                    # Skip comment lines — the fix commentary quotes the very
                    # pattern it warns against, and a grep that cannot tell
                    # code from prose fails on its own documentation.
                    if ($line -match '^\s*#') { continue }
                    if ($line -match '\$Metadata\.[A-Za-z_][A-Za-z0-9_]*\s*\?\?') {
                        $offenders.Add("$($f.Name):$($i + 1): $($line.Trim())")
                    }
                }
            }
            $offenders -join "`n" | Should -BeNullOrEmpty -Because @'
under StrictMode a missing hashtable key throws before ?? can apply, so this
pattern aborts the publisher whenever the key is absent — which it is on the
-FromResults replay path. Use Get-NRGObjectField -Item $Metadata -Key <k> -Default <d>.
'@
        }

        It 'Metadata keys absent on the replay path really do throw on dot-access' {
            # Pins the premise itself. If a future PowerShell made this benign
            # the guard above would be cargo-cult, and this test says so.
            #
            # StrictMode is SCOPE-based, and Pester does not run It blocks under
            # it. Asserting here without setting it produced a passing read and
            # a failing test — the opposite of the production behaviour. The
            # module sets StrictMode itself, which is why the publishers throw.
            { & { Set-StrictMode -Version Latest; $null = $script:ReplayMetadata.Operator ?? '' } } | Should -Throw
            { & { Set-StrictMode -Version Latest; $null = $script:ReplayMetadata.TenantId ?? '' } } | Should -Throw
            # And a key that IS present must not throw, so the guard is testing
            # absence rather than StrictMode refusing everything.
            { & { Set-StrictMode -Version Latest; $null = $script:ReplayMetadata.TenantDomain ?? '' } } | Should -Not -Throw
        }

        It 'Get-NRGObjectField returns the default for those same keys' {
            Get-NRGObjectField -Item $script:ReplayMetadata -Key 'Operator' -Default 'admin' | Should -Be 'admin'
            Get-NRGObjectField -Item $script:ReplayMetadata -Key 'TenantId' -Default ''      | Should -Be ''
            Get-NRGObjectField -Item $script:ReplayMetadata -Key 'TenantDomain' -Default 'x' | Should -Be 'example.com'
        }
    }

    Context 'summary surfaces account for every finding state' {

        BeforeAll {
            Clear-NRGState
            # A spread that puts a non-zero count in EVERY state. A fixture with
            # no Error findings passes against the omission being tested.
            $states = @('Satisfied','Gap','Partial','Error','NotApplicable')
            $i = 0
            foreach ($c in @(Get-NRGControlDefinitions)) {
                Add-NRGFinding -ControlId $c.ControlId -State $states[$i % 5] -Category $c.Category `
                    -Title $c.Title -Severity $c.Severity -Detail 'fixture' `
                    -FrameworkIds (Get-NRGFrameworkCitations -ControlId $c.ControlId)
                $i++
            }
            $script:Findings = @(Get-NRGFindings)
            $script:Overall  = Get-NRGCoverageScore -Findings $script:Findings -FrameworkId 'NIST' -ErrorHandling 'Gap'
        }

        AfterAll { Clear-NRGState }

        It 'the fixture actually exercises the Error state' {
            $script:Overall.Error | Should -BeGreaterThan 0 -Because 'a fixture with no errors cannot detect an omitted Error row'
        }

        It 'the five states sum to the finding count' {
            ($script:Overall.Satisfied + $script:Overall.Partial + $script:Overall.Gap +
             $script:Overall.Error + $script:Overall.NA) | Should -Be $script:Findings.Count
        }

        It 'the NIST matrix Markdown summary names the Error count' {
            $out = Join-Path ([System.IO.Path]::GetTempPath()) ("nistmx-" + [guid]::NewGuid().ToString('N'))
            try {
                Publish-NRGNISTMatrix -Metadata $script:ReplayMetadata -Findings $script:Findings -OutputPath $out
                $md = Get-Content -LiteralPath $out -Raw
                $md | Should -Match '(?i)\|\s*Errors?[^|]*\|\s*\d+\s*\|' -Because @'
errors are scored as failures and sit in the denominator. Without the row a
reader adds met + partial + gaps + not-assessable, comes up short of the
finding count, and cannot tell whether the missing rows passed or failed.
'@
                # And the number must be the real one, not a hardcoded zero.
                $md | Should -Match ("\|\s*Errors[^|]*\|\s*" + [regex]::Escape([string]$script:Overall.Error) + "\s*\|")
            } finally {
                foreach ($p in @($out, "$out.html", "$out.xlsx")) {
                    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
                }
            }
        }

        It 'the NIST matrix publishes on the replay metadata shape at all' {
            # The regression: this threw, the caller swallowed it as a warning,
            # and the deliverable silently did not exist.
            $out = Join-Path ([System.IO.Path]::GetTempPath()) ("nistmx2-" + [guid]::NewGuid().ToString('N'))
            try {
                { Publish-NRGNISTMatrix -Metadata $script:ReplayMetadata -Findings $script:Findings -OutputPath $out } |
                    Should -Not -Throw
                Test-Path -LiteralPath $out | Should -BeTrue
            } finally {
                foreach ($p in @($out, "$out.html", "$out.xlsx")) {
                    if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
                }
            }
        }

        It 'the remediation script publishes on the replay metadata shape' {
            $out = Join-Path ([System.IO.Path]::GetTempPath()) ("rem-" + [guid]::NewGuid().ToString('N') + ".ps1")
            try {
                { Publish-NRGRemediationScript -Metadata $script:ReplayMetadata -Findings $script:Findings -OutputPath $out } |
                    Should -Not -Throw
            } finally {
                if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Force -ErrorAction SilentlyContinue }
            }
        }
    }
}
