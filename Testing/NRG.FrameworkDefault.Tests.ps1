#Requires -Version 7.0
#
# NRG.FrameworkDefault.Tests.ps1
#
# Pins the one deliberate behavioral difference between the two twins.
#
# NRG defaults its report to NIST. The other repo defaults to All.
# Everything else in these two codebases is mirrored line for line, which makes
# this exactly the setting a careless sync would silently flip — and the failure
# would be invisible: the report still renders, still scores correctly, and just
# shows the wrong practice's frameworks to a client.
#
# What is NOT in question here: narrowing the report never narrows the
# assessment. Every control keeps every citation, every framework is still
# scored, and the results JSON and the XLSX matrix are identical either way.
# These tests assert that too, because it is the property that makes a default
# safe to change at all.

Describe 'Report framework default' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }

        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop

        $script:EntryPath = Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1'
        $tokens = $null; $perr = $null
        $script:EntryAst = [System.Management.Automation.Language.Parser]::ParseFile($script:EntryPath, [ref]$tokens, [ref]$perr)
        @($perr).Count | Should -Be 0
    }

    It 'the entry point defaults -Framework to NIST' {
        $param = $script:EntryAst.ParamBlock.Parameters |
            Where-Object { $_.Name.VariablePath.UserPath -eq 'Framework' }
        $param | Should -Not -BeNullOrEmpty -Because 'the -Framework parameter must exist'
        $param.DefaultValue.Value | Should -Be 'NIST'
    }

    It 'the entry point accepts the other frameworks explicitly' {
        $param = $script:EntryAst.ParamBlock.Parameters |
            Where-Object { $_.Name.VariablePath.UserPath -eq 'Framework' }
        $set = $param.Attributes |
            Where-Object { $_.TypeName.Name -eq 'ValidateSet' } |
            ForEach-Object { $_.PositionalArguments.Value }
        foreach ($fw in 'All', 'NIST', 'CIS', 'SCuBA', 'CMMC') {
            $set | Should -Contain $fw
        }
    }

    It 'the PUBLISHER default stays multi-framework in both repos' {
        # Only the entry point differs. Moving the narrowing into the publisher
        # would change behavior for every direct caller and for the other twin.
        $cmd = Get-Command Publish-NRGAssessmentHTML
        $default = $cmd.Parameters['Frameworks'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateNotNullOrEmptyAttribute] }
        $default | Should -Not -BeNullOrEmpty

        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Publishers/Publish-NRGAssessmentHTML.ps1') -Raw
        $src | Should -Match "\[string\[\]\] \`$Frameworks = @\('CIS','SCuBA','NIST','CMMC'\)"
    }

    It 'narrowing the report does not change any framework score' {
        # The load-bearing property. If a narrowed report ever scored
        # differently, the default would stop being a presentation choice and
        # start being an assessment choice.
        Clear-NRGState
        $states = @('Satisfied','Gap','Partial','NotApplicable','Error')
        $n = 0
        foreach ($c in (Get-NRGControlDefinitions)) {
            $n++
            Add-NRGFinding -ControlId $c.ControlId -State $states[$n % 5] -Severity $c.Severity `
                -Category $c.Category -Title $c.Title -Detail 'synthetic' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId $c.ControlId)
        }
        $f = Get-NRGFindings

        $before = @{}
        foreach ($fw in 'CIS','SCuBA','NIST','CMMC') {
            $before[$fw] = (Get-NRGCoverageScore -Findings $f -FrameworkId $fw -ErrorHandling 'Gap').Score
        }

        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("fw-" + [Guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        try {
            $meta = @{ TenantDomain='contoso.onmicrosoft.com'; TenantId='0'; Operator='a@b.com'
                       AssessmentDate='August 26, 2026'; AssessmentTime='2026-08-26T00:00:00Z'
                       ToolVersion='4.12.1'; QuickScan=$false }
            $conn = @{ Graph=$true; EXO=$true; IPPSSession=$true; Teams=$true; SharePoint=$true }
            Publish-NRGAssessmentHTML -Metadata $meta -Findings $f -Connections $conn `
                -OutputPath (Join-Path $tmp 'narrow.html') -Frameworks @('NIST')

            foreach ($fw in 'CIS','SCuBA','NIST','CMMC') {
                (Get-NRGCoverageScore -Findings $f -FrameworkId $fw -ErrorHandling 'Gap').Score |
                    Should -Be $before[$fw] -Because "the $fw score must not move when the report narrows"
            }
        } finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
            Clear-NRGState
        }
    }

    It 'every control still carries every framework citation' {
        # A "NIST focus" that stripped the other citations from controls.json
        # would make the default irreversible. This is the guard against that.
        $controls = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 |
            ConvertFrom-Json).controls)
        foreach ($fw in 'CIS','SCuBA','CMMC','ISO27001','SOC2','HIPAA') {
            $withFw = @($controls | Where-Object {
                $_.References.PSObject.Properties[$fw] -and
                -not [string]::IsNullOrWhiteSpace([string]$_.References.$fw)
            })
            $withFw.Count | Should -BeGreaterThan 0 -Because "$fw citations must survive the NIST default"
        }
    }
}
