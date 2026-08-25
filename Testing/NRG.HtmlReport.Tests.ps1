#Requires -Version 7.0
#
# NRG.HtmlReport.Tests.ps1
#
# End-to-end smoke test for Publishers/Publish-NRGAssessmentHTML.ps1 — the
# paid client deliverable. The report generator is ~1000 lines of string
# interpolation and, until now, nothing rendered it: schema validation checks
# the JSON, PSScriptAnalyzer checks style, EvaluatorWiring checks the function
# graph — but a broken here-string or an unescaped tenant value would sail
# through every one of those and land in front of a client. This suite builds a
# report from synthetic findings spanning every State/Severity/workload and
# asserts the output is well-formed, complete, leak-free, and injection-safe.
#
# Findings are constructed through the REAL Add-NRGFinding so the finding shape
# can never drift from what evaluators actually emit at runtime.

Describe 'Publish-NRGAssessmentHTML end-to-end render' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        Clear-NRGState

        $states     = @('Satisfied', 'Gap', 'Partial', 'NotApplicable', 'Error')
        $severities = @('Critical', 'High', 'Medium', 'Low', 'Informational')
        $workloads  = @('AAD', 'EXO', 'DEF', 'TMS', 'PVW', 'SPO', 'INT', 'PPL', 'DNS')

        # Real citations are emitted by Get-NRGFrameworkCitations as
        # "Framework:value" pairs. Keep the synthetic set in that shape — the
        # NIST family rollup parses the NIST: prefix off this exact string, so
        # a fixture using a different separator would silently exercise none of
        # that code path.
        $script:NistRefs = @('AC-2, IA-2', 'AU-6', 'SC-8(1)', 'SI-4', 'CM-6, AC-3')

        $script:TitleMarker = 'ZZUNIQUEFINDINGTITLE'
        $script:GapCount    = 0
        $n = 0
        foreach ($wl in $workloads) {
            foreach ($st in $states) {
                $n++
                $sev = $severities[$n % $severities.Count]
                if ($st -eq 'Gap') { $script:GapCount++ }
                Add-NRGFinding -ControlId ("{0}-{1}.{2}" -f $wl, $n, ($n % 9)) `
                    -State $st -Severity $sev -Category 'Identity' `
                    -Title ("{0} {1} {2}" -f $script:TitleMarker, $wl, $st) `
                    -Detail ("Synthetic detail for {0} {1}" -f $wl, $st) `
                    -CurrentValue 'current-x' -RequiredValue 'required-y' `
                    -Remediation 'Do the thing.' `
                    -FrameworkIds @('CIS:1.1', 'SCuBA:MS.AAD.1.1v1',
                                    ("NIST:{0}" -f $script:NistRefs[$n % $script:NistRefs.Count]))
            }
        }

        # Injection probe: a hostile finding value must be HTML-escaped by
        # ConvertTo-NRGHtmlSafe, never emitted as live markup.
        $script:XssMarker = 'nrgxssprobe'
        Add-NRGFinding -ControlId 'AAD-9.9' -State 'Gap' -Severity 'High' -Category 'Identity' `
            -Title ("<script>{0}</script>" -f $script:XssMarker) `
            -Detail ("<img src=x onerror={0}>" -f $script:XssMarker) `
            -Remediation 'Escape me.'
        $script:GapCount++

        $script:findings    = Get-NRGFindings
        $script:metadata    = @{
            TenantDomain   = 'contoso.onmicrosoft.com'
            TenantId       = '00000000-0000-0000-0000-000000000000'
            Operator       = 'assessor@nrgtechservices.com'
            AssessmentDate = 'July 30, 2026'
            AssessmentTime = '2026-07-30T00:00:00.0000000+00:00'
            ToolVersion    = '4.12.1'
            QuickScan      = $false
        }
        $script:connections = @{ Graph = $true; EXO = $true; IPPSSession = $true; Teams = $true; SharePoint = $true }

        $script:tmp     = Join-Path ([IO.Path]::GetTempPath()) ("nrg-html-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force -Path $script:tmp | Out-Null
        $script:outPath = Join-Path $script:tmp 'report.html'

        $script:renderError = $null
        try {
            Publish-NRGAssessmentHTML -Metadata $script:metadata -Findings $script:findings `
                -Connections $script:connections -OutputPath $script:outPath -ClientName 'Contoso Ltd' -ErrorAction Stop
        } catch {
            $script:renderError = $_
        }

        $script:html = if (Test-Path -LiteralPath $script:outPath) {
            Get-Content -LiteralPath $script:outPath -Raw
        } else { '' }
    }

    AfterAll {
        if ($script:tmp -and (Test-Path -LiteralPath $script:tmp)) {
            Remove-Item -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
        Clear-NRGState
    }

    It 'renders without throwing' {
        $script:renderError | Should -BeNullOrEmpty `
            -Because 'the generator must never throw on a valid finding set — a throw here is a broken deliverable'
    }

    It 'writes a non-trivial HTML file' {
        Test-Path -LiteralPath $script:outPath | Should -BeTrue
        $script:html.Length | Should -BeGreaterThan 5000
    }

    It 'is a well-formed HTML document' {
        $script:html | Should -Match '<!DOCTYPE html>'
        $script:html | Should -Match '</html>'
    }

    It 'contains the core report sections' {
        foreach ($anchor in 'id="exec"', 'id="findings"', 'id="fw-section"', 'id="nist-families"', 'id="nist-physical"') {
            $script:html | Should -BeLike "*$anchor*" -Because "section marker $anchor must render"
        }
    }

    It 'renders the NIST 800-53 family rollup with its cited families' {
        # The fixture cites AC, IA, AU, SC, SI and CM. Each must appear as a
        # family row with its full 800-53 name — a rollup that rendered the
        # section shell but no rows would still satisfy the anchor check above.
        foreach ($fam in 'Access Control', 'Identification and Authentication',
                         'Audit and Accountability', 'System and Communications Protection',
                         'System and Information Integrity', 'Configuration Management') {
            $script:html | Should -BeLike "*$fam*" -Because "NIST family '$fam' is cited by the fixture and must roll up"
        }
        # The control enhancement must survive parsing intact, not be truncated
        # to its base control.
        $script:html | Should -BeLike '*SC-8(1)*'
    }

    It 'states that NIST family rows do not sum to the assessment total' {
        # A cross-family control is counted in every family it cites. Without
        # this caveat on the page, a reader adding the Assessed column and
        # getting more than the control count would reasonably conclude the
        # numbers are wrong.
        $script:html | Should -BeLike '*do not sum to the assessment total*'
    }

    It 'renders the physical/device section without claiming compliance for attested controls' {
        # The section is rendered from Config/nist-physical.json, so it appears
        # regardless of what the synthetic findings contain. What must hold in
        # the OUTPUT is that the not-observable controls carry the attestation
        # label and the page says the section is unscored — the two sentences
        # that stop a reader inferring a physical pass from a clean NIST table.
        $script:html | Should -BeLike '*Attestation required*'
        $script:html | Should -BeLike '*Nothing in this section is scored*'
        # A representative control from each family the tenant cannot see.
        foreach ($c in 'MP-6', 'PE-3', 'MA-5') {
            $script:html | Should -BeLike "*$c*" -Because "$c is not observable from M365 and must still be listed"
        }
        # And the section must actually offer options, not just verdicts.
        $script:html | Should -BeLike '*Implementation options*'
    }

    It 'renders findings from every workload (report is not empty)' {
        $count = ([regex]::Matches($script:html, [regex]::Escape($script:TitleMarker))).Count
        # At minimum every Gap finding (one per workload) must reach the report.
        $count | Should -BeGreaterOrEqual 9 `
            -Because 'a report that dropped its findings would render near-empty and still pass the structural checks'
    }

    It 'HTML-escapes hostile finding content (no live markup injection)' {
        # No LIVE markup may survive: the raw tags (with a literal '<') must be
        # turned into &lt;...&gt; entities by ConvertTo-NRGHtmlSafe. We assert on
        # the raw TAG, not on the "onerror=" attribute substring — that inert
        # text legitimately survives *inside* the escaped entity and its presence
        # is not a vulnerability.
        $script:html | Should -Not -Match ('<script>{0}' -f [regex]::Escape($script:XssMarker))
        $script:html | Should -Not -Match ('<img[^>]*onerror={0}' -f [regex]::Escape($script:XssMarker))
        # ...but the payload text must still be present (escaped), proving it
        # rendered through the escaper rather than being silently dropped.
        $script:html | Should -Match ([regex]::Escape($script:XssMarker))
    }

    It 'leaks no object-stringification artifacts' {
        # These strings only appear when a hashtable/array is accidentally
        # interpolated instead of formatted — never in intentional report HTML.
        $script:html | Should -Not -Match 'System\.Collections\.Hashtable'
        $script:html | Should -Not -Match 'System\.Object\[\]'
        $script:html | Should -Not -Match 'System\.Collections\.Generic'
    }
}
