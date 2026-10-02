#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.OutputParity.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: A verdict and its evidence limitation must read the same in every
             deliverable. Findings come from the REAL evaluators (a Partial with a
             named shortfall, and a not-assessed verdict whose Detail says what was
             verified and what was not), are published to the results JSON shape, the
             HTML report, the Markdown summary and the XLSX workbook, and each output
             must carry the verdict and the limitation sentence. A format that dropped
             the limitation would read cleaner than the run it reprints.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Verdict and evidence limitation survive every output format' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        Clear-NRGState
        # Pins the 'no approved list' scenario: the shipped lists are approved, so the file is replaced for this test.
        Mock -ModuleName NRG-Assessment Get-NRGStandards { [ordered]@{ DmarcReportingAddresses = @(); CommonAttachmentFileTypes = @(); PriorityUsers = @(); RequiredConditionalAccessTemplates = @() } }
        $raw = { param([string] $Id, $Data) @{ CollectorId = $Id; CollectedAt = (Get-Date).ToString('o'); Success = $true; Data = $Data } }
        # DEF-2.3: filter on, no approved blocked-type list -> not assessed, filter half verified.
        Set-NRGRawData -Key 'Defender-Policies' -Data (& $raw 'Defender-Policies' @{
            MalwareFilter = @{ Available = $true; Rules = @(); FileFilterEnabledCount = 1; Policies = @(@{ Name = 'Default'; IsDefault = $true; EnableFileFilter = $true; FileTypes = @('exe'); ZapEnabled = $false }) } })
        # DEF-2.2: spam/phish ZAP on, malware ZAP off -> Partial with a named shortfall.
        Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (& $raw 'EXO-MailboxConfig' @{ SectionStatus = @{ AntiSpamPolicies = 'Collected' }; AntiSpamRules = @()
            AntiSpamPolicies = @(@{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $true; PhishZapEnabled = $true }) })
        Test-NRGControlDefenderCommonAttachments
        Test-NRGControlDefenderZAP
        $script:Findings = @(Get-NRGFindings | Where-Object { $_.ControlId -in @('DEF-2.2', 'DEF-2.3') })
        $script:P22 = $script:Findings | Where-Object ControlId -eq 'DEF-2.2'
        $script:P23 = $script:Findings | Where-Object ControlId -eq 'DEF-2.3'

        $script:tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-parity-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force -Path $script:tmp | Out-Null
        $meta = @{ TenantId = '00000000-0000-0000-0000-000000000000'; TenantDomain = 'contoso.example'; TenantName = 'Contoso'; AssessmentTime = (Get-Date).ToString('o'); AssessmentDate = (Get-Date).ToString('yyyy-MM-dd'); Operator = 'Test Operator'; ToolVersion = $NRGAssessmentVersion; QuickScan = $false }
        $conn = @{ Graph = $true; EXO = $true; IPPSSession = $true; Teams = $false; SharePoint = $false }
        $py0 = (Get-Command python3, python -ErrorAction SilentlyContinue | Select-Object -First 1).Source
        $script:HaveOpenpyxl = $false
        if ($py0) { & $py0 -c 'import openpyxl' 2>$null; $script:HaveOpenpyxl = ($LASTEXITCODE -eq 0) }
        $script:Html = ''; $script:Md = ''; $script:Json = ''; $script:Xlsx = ''
        $script:Json = ($script:Findings | ConvertTo-Json -Depth 8)
        try { Publish-NRGAssessmentHTML -Metadata $meta -Findings $script:Findings -Connections $conn -OutputPath (Join-Path $script:tmp 'r.html') -ClientName 'Contoso' -ErrorAction Stop
              $script:Html = Get-Content -LiteralPath (Join-Path $script:tmp 'r.html') -Raw } catch { $script:HtmlErr = $_ }
        try { Publish-NRGAssessmentSummary -Metadata $meta -Findings $script:Findings -Connections $conn -OutputPath (Join-Path $script:tmp 'r.md') -ErrorAction Stop
              $md = Get-ChildItem -Path $script:tmp -Filter '*.md' | Select-Object -First 1
              if ($md) { $script:Md = Get-Content -LiteralPath $md.FullName -Raw } } catch { $script:MdErr = $_ }
        try { Publish-NRGComplianceMatrix -Metadata $meta -Findings $script:Findings -OutputPath (Join-Path $script:tmp 'r.xlsx') -ErrorAction Stop
              $x = Get-ChildItem -Path $script:tmp -Filter '*.xlsx' | Select-Object -First 1
              if ($x) {
                  $py = (Get-Command python3, python -ErrorAction SilentlyContinue | Select-Object -First 1).Source
                  $script:Xlsx = (& $py -c "import openpyxl,sys; wb=openpyxl.load_workbook(sys.argv[1]); print('\n'.join(str(c.value) for ws in wb for row in ws.iter_rows() for c in row if c.value is not None))" $x.FullName) -join "`n"
              } } catch { $script:XlsxErr = $_ }
    }
    AfterAll { if ($script:tmp) { Remove-Item -LiteralPath $script:tmp -Recurse -Force -ErrorAction SilentlyContinue }; Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    It 'the evaluators produced the two verdicts under test' {
        $script:P22.State | Should -Be 'Partial'
        $script:P23.State | Should -Be 'NotApplicable'
        $script:P22.Detail | Should -Match 'Malware ZAP is off'
        $script:P23.Detail | Should -Match 'Not assessed: whether the filter blocks the NRG'
    }
    It 'the JSON shape carries verdict, detail and the limitation' {
        $script:Json | Should -Match 'Malware ZAP is off'
        $script:Json | Should -Match 'Not assessed: whether the filter blocks the NRG'
    }
    It 'the HTML report renders and carries the shortfall and the not-assessed limitation' {
        $script:HtmlErr | Should -BeNullOrEmpty
        $script:Html | Should -Match 'Malware ZAP is off'
        $script:Html | Should -Match 'whether the filter blocks the NRG blocked-file-type list'
    }
    It 'the Markdown summary renders and carries the shortfall and the not-assessed limitation' {
        $script:MdErr | Should -BeNullOrEmpty
        $script:Md | Should -Match 'Malware ZAP is off'
        $script:Md | Should -Match 'whether the filter blocks the NRG'
    }
    It 'the XLSX workbook carries the shortfall and the not-assessed limitation' {
        if (-not $script:HaveOpenpyxl) { Set-ItResult -Skipped -Because 'python with openpyxl is not available, so the workbook is not produced'; return }
        $script:XlsxErr | Should -BeNullOrEmpty
        $script:Xlsx | Should -Match 'Malware ZAP is off'
        $script:Xlsx | Should -Match 'whether the filter blocks the NRG'
    }
    It 'no output presents the not-assessed control as passing' {
        foreach ($o in @($script:Html, $script:Md)) { $o | Should -Not -Match 'DEF-2\.3[^\n]{0,200}Satisfied' }
    }
}
