#Requires -Version 7.0
#
# TP.FrameworkDefault.Tests.ps1
#
# Pins the one deliberate behavioral difference between the two twins.
#
# The NRG profile defaults its report to NIST; the NLS profile and the neutral
# default say All. The entry point itself carries no default: the active
# profile decides. A careless edit could silently flip this, and the failure
# would be invisible: the report still renders, still scores correctly, and
# just shows the wrong practice's frameworks to a client.
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

        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

        $script:EntryPath = Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1'
        $tokens = $null; $perr = $null
        $script:EntryAst = [System.Management.Automation.Language.Parser]::ParseFile($script:EntryPath, [ref]$tokens, [ref]$perr)
        @($perr).Count | Should -Be 0
    }

    It 'the entry point has no -Framework default of its own; the profile decides' {
        $param = $script:EntryAst.ParamBlock.Parameters |
            Where-Object { $_.Name.VariablePath.UserPath -eq 'Framework' }
        $param | Should -Not -BeNullOrEmpty -Because 'the -Framework parameter must exist'
        $param.DefaultValue | Should -BeNullOrEmpty
        $src = Get-Content -LiteralPath $script:EntryPath -Raw
        $src | Should -Match "Get-TPObjectField -Item \`$TPBrand -Key 'DefaultFramework' -Default 'All'"
    }

    It 'the NRG profile defaults to NIST, the NLS profile and the neutral default to All' {
        $cfg = Join-Path $script:RepoRoot 'Config'
        (Import-PowerShellDataFile (Join-Path $cfg 'profiles' 'nrg.psd1')).DefaultFramework | Should -Be 'NIST'
        (Import-PowerShellDataFile (Join-Path $cfg 'profiles' 'nls.psd1')).DefaultFramework | Should -Be 'All'
        (Import-PowerShellDataFile (Join-Path $cfg 'branding.psd1')).DefaultFramework      | Should -Be 'All'
    }

    It 'the module loads the profile TP_PROFILE names, and refuses a path' {
        $m = Get-Module TenantPosture
        (& $m { $script:TPBrand['ProfileName'] }) | Should -Be 'branding'
        $saved = $env:TP_PROFILE
        try {
            $env:TP_PROFILE = 'nrg'
            Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
            $TPBrand['ProfileName'] | Should -Be 'nrg'
            $TPBrand['CompanyName'] | Should -Be 'NRG Technology Services'
            @((Get-TPStandards).DmarcReportingAddresses) | Should -Be @('dmarc@nrgtechservices.com')
            $env:TP_PROFILE = '../branding'
            Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop -WarningAction SilentlyContinue 3>$null
            $TPBrand['ProfileName'] | Should -Be 'branding'
        } finally {
            $env:TP_PROFILE = $saved
            Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        }
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
        $cmd = Get-Command Publish-TPAssessmentHTML
        $default = $cmd.Parameters['Frameworks'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidateNotNullOrEmptyAttribute] }
        $default | Should -Not -BeNullOrEmpty

        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Publishers/Publish-TPAssessmentHTML.ps1') -Raw
        $src | Should -Match "\[string\[\]\] \`$Frameworks = @\('CIS','SCuBA','NIST','CMMC'\)"
    }

    It 'narrowing the report does not change any framework score' {
        # The load-bearing property. If a narrowed report ever scored
        # differently, the default would stop being a presentation choice and
        # start being an assessment choice.
        Clear-TPState
        $states = @('Satisfied','Gap','Partial','NotApplicable','Error')
        $n = 0
        foreach ($c in (Get-TPControlDefinitions)) {
            $n++
            Add-TPFinding -ControlId $c.ControlId -State $states[$n % 5] -Severity $c.Severity `
                -Category $c.Category -Title $c.Title -Detail 'synthetic' `
                -FrameworkIds (Get-TPFrameworkCitations -ControlId $c.ControlId)
        }
        $f = Get-TPFindings

        $before = @{}
        foreach ($fw in 'CIS','SCuBA','NIST','CMMC') {
            $before[$fw] = (Get-TPCoverageScore -Findings $f -FrameworkId $fw -ErrorHandling 'Gap').Score
        }

        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("fw-" + [Guid]::NewGuid().ToString('N').Substring(0,8))
        New-Item -ItemType Directory -Force -Path $tmp | Out-Null
        try {
            $meta = @{ TenantDomain='contoso.onmicrosoft.com'; TenantId='0'; Operator='a@b.com'
                       AssessmentDate='August 26, 2026'; AssessmentTime='2026-08-26T00:00:00Z'
                       ToolVersion='4.12.1'; QuickScan=$false }
            $conn = @{ Graph=$true; EXO=$true; IPPSSession=$true; Teams=$true; SharePoint=$true }
            Publish-TPAssessmentHTML -Metadata $meta -Findings $f -Connections $conn `
                -OutputPath (Join-Path $tmp 'narrow.html') -Frameworks @('NIST')

            foreach ($fw in 'CIS','SCuBA','NIST','CMMC') {
                (Get-TPCoverageScore -Findings $f -FrameworkId $fw -ErrorHandling 'Gap').Score |
                    Should -Be $before[$fw] -Because "the $fw score must not move when the report narrows"
            }
        } finally {
            Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
            Clear-TPState
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
