#Requires -Version 7.0
#
# TP.SecurityReview.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Guards the client-facing security configuration review
# (Lib/Get-TPSecurityReviewReport.ps1, Publishers/Publish-TPSecurityReviewReport.ps1,
# New-TPSecurityReview.ps1, Read-TPRunRecord -IncludeChecklists):
#   - every checklist row lands in exactly one group or is counted as not
#     applying, and the counts sum; next steps carry the recommended change,
#     High first
#   - a partial or quick run, and a results file without the checklists, are
#     refused
#   - no account name, policy name, detail or report-only policy body reaches
#     the model, the HTML or the PDF
#   - page one says what the review is not before any number; nothing says
#     compliant or secure; the page loads nothing and escapes everything
#   - the standalone script writes the HTML from a results file and refuses a
#     partial run (exit 4)
# Data keys consumed: synthetic checklists only. Graph scopes / cmdlets: none.

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('tp-sr-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    $null = New-Item -ItemType Directory -Path $script:Tmp -Force
    $script:Meta = @{ TenantDomain = 'contoso.onmicrosoft.com'; AssessmentTime = '2026-10-28T09:00:00Z'; ToolVersion = '9.9.9' }

    $script:CaRow = { param($Id, $Kind, $Status, $Sev = 'High') @{ Id = $Id; Kind = $Kind; Title = "Check $Id"; Why = "Why $Id"; Severity = $Sev; Status = $Status; Recommended = "Do $Id"; LicenseRequirement = 'Entra ID P2'; Detail = 'Met by: Secret Policy Name'; Items = @(@{ Kind = 'User'; Id = 'x'; DisplayName = 'victim@contoso.com' }) } }
    $script:Ca = @{ Available = $true; SecurityDefaults = $false; Rows = @(
        (& $script:CaRow 'MT.1007' 'Presence' 'Fail' 'High'),
        (& $script:CaRow 'MT.1009' 'Presence' 'Staged' 'High'),
        (& $script:CaRow 'MT.1005' 'Hygiene' 'Pass' 'High'),
        (& $script:CaRow 'MT.1012' 'Presence' 'NeedsLicense' 'High'),
        (& $script:CaRow 'MT.1033' 'Simulation' 'NotAssessed' 'High'),
        (& $script:CaRow 'MT.1224' 'Hygiene' 'NotApplicable' 'Medium'),
        (& $script:CaRow 'MT.1015' 'Presence' 'Fail' 'Medium'));
        Fixes = @(@{ Key = 'mfa-all-users'; Policy = @{ displayName = 'Report-only body'; conditions = @{ users = @{ excludeUsers = @('99999999-9999-9999-9999-999999999999') } } } }) }
    $script:IcRow = { param($Id, $Area, $Status, $Sev = 'Medium') @{ Id = $Id; Area = $Area; Title = "Check $Id"; Why = "Why $Id"; Severity = $Sev; Status = $Status; Recommended = "Set $Id"; Detail = 'Policy Hidden Name'; Items = @(@{ Name = 'Hidden Policy'; Note = 'x' }) } }
    $script:Ic = @{ Available = $true; Rows = @(
        (& $script:IcRow 'MT.1054' 'Tenant' 'Fail' 'High'),
        (& $script:IcRow 'MT.1228' 'iOS' 'Pass'),
        (& $script:IcRow 'MT.1232' 'Android' 'NotApplicable'),
        (& $script:IcRow 'MT.1178' 'ASR' 'Fail' 'High')) }
}

AfterAll {
    if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'The client security review model' {
    BeforeAll { $script:Model = Get-TPSecurityReviewReport -CAChecklist $script:Ca -IntuneChecklist $script:Ic -Metadata $script:Meta -ClientName 'Contoso Ltd' }

    It 'puts every row in exactly one group, counts what does not apply, and the counts sum' {
        $script:Model.Available | Should -BeTrue
        $script:Model.Counts.NextSteps | Should -Be 4
        $script:Model.Counts.TurnOn | Should -Be 1
        $script:Model.Counts.InPlace | Should -Be 2
        $script:Model.Counts.NotChecked | Should -Be 2
        $script:Model.NotApplicable | Should -Be 2
        $script:Model.Total | Should -Be 9
        ($script:Model.Total + $script:Model.NotApplicable) | Should -Be (@($script:Ca.Rows).Count + @($script:Ic.Rows).Count)
    }
    It 'orders next steps High first and carries the recommended change' {
        $next = @($script:Model.Groups.NextSteps)
        @($next | Select-Object -First 3 | ForEach-Object { $_.Severity }) | Should -Be @('High', 'High', 'High')
        ($next | Where-Object Reference -eq 'MT.1007').Action | Should -Be 'Do MT.1007'
        ($next | Where-Object Reference -eq 'MT.1054').Action | Should -Be 'Set MT.1054'
        @($script:Model.Priorities).Count | Should -Be 3
    }
    It 'says why an unchecked row was not checked and names the license a row needs' {
        ($script:Model.Groups.NotChecked | Where-Object Reference -eq 'MT.1012').Action | Should -Match 'Entra ID P2'
        ($script:Model.Groups.TurnOn | Where-Object Reference -eq 'MT.1009').Action | Should -Match 'report-only'
    }
    It 'carries no account name, policy name, detail or report-only policy body' {
        $json = $script:Model | ConvertTo-Json -Depth 20
        $json | Should -Not -Match 'victim@contoso\.com|Secret Policy Name|Hidden Policy|Policy Hidden Name|Report-only body|99999999-9999'
    }
    It 'refuses a partial or quick run, and a file without the checklists' {
        $partial = Get-TPSecurityReviewReport -CAChecklist $script:Ca -IntuneChecklist $script:Ic -Metadata @{ TenantDomain = 'contoso.com'; ControlSelection = @{ Partial = $true } }
        $partial.Available | Should -BeFalse; $partial.Refused | Should -BeTrue
        $quick = Get-TPSecurityReviewReport -CAChecklist $script:Ca -IntuneChecklist $script:Ic -Metadata @{ TenantDomain = 'contoso.com'; QuickScan = $true }
        $quick.Refused | Should -BeTrue
        $none = Get-TPSecurityReviewReport -CAChecklist $null -IntuneChecklist $null -Metadata $script:Meta
        $none.Available | Should -BeFalse; $none.Note | Should -Match 'no Conditional Access or Intune checklist'
    }
    It 'reports an area that was not reviewed instead of dropping it' {
        $m = Get-TPSecurityReviewReport -CAChecklist $script:Ca -IntuneChecklist $null -Metadata $script:Meta
        $m.Available | Should -BeTrue
        $m.Topics.Devices.Read | Should -BeFalse
    }
}

Describe 'The client security review page' {
    BeforeAll {
        $script:Hostile = @{ Available = $true; Rows = @(@{ Id = 'MT.1007'; Kind = 'Presence'; Title = '<img src=x onerror=alert(1)>'; Why = '<script>alert(1)</script>'; Severity = 'High'; Status = 'Fail'; Recommended = 'x' }) }
        $model = Get-TPSecurityReviewReport -CAChecklist $script:Ca -IntuneChecklist $script:Ic -Metadata $script:Meta -ClientName 'Contoso Ltd'
        $script:Files = Publish-TPSecurityReviewReport -Model $model -OutputPath (Join-Path $script:Tmp 'contoso-security-review.html') -GeneratedAt ([datetime]'2026-10-28T10:00:00Z')
        $script:Html = Get-Content -LiteralPath $script:Files.Html -Raw
    }
    It 'says what it is not on page one, before the numbers' {
        $notThis = $script:Html.IndexOf('What this is not')
        $notThis | Should -BeGreaterThan 0
        $notThis | Should -BeLessThan $script:Html.IndexOf('class="tp-kpis"')
        $script:Html | Should -Match 'not a security audit'
    }
    It 'never calls the tenant compliant or secure and loads nothing' {
        $script:Html | Should -Not -Match '(?i)\bis compliant\b|\bfully compliant\b|\byou are compliant\b|\bis secure\b|\bfully secure\b'
        $script:Html | Should -Not -Match '<script|<link |src="http|@import'
        $script:Html | Should -Not -Match 'victim@contoso\.com|Secret Policy Name|Hidden Policy'
    }
    It 'escapes a hostile check title' {
        $m = Get-TPSecurityReviewReport -CAChecklist $script:Hostile -IntuneChecklist $null -Metadata $script:Meta
        $f = Publish-TPSecurityReviewReport -Model $m -OutputPath (Join-Path $script:Tmp 'evil-security-review.html')
        $h = Get-Content -LiteralPath $f.Html -Raw
        $h | Should -Not -Match '<img src=x|<script>alert'
    }
}

Describe 'PDF and the standalone script' {
    BeforeDiscovery {
        $browser = $env:TP_PDF_BROWSER
        $script:CanPrint = [bool]($browser -and (Test-Path -LiteralPath $browser))
    }
    It 'prints a PDF when a headless browser is present' -Skip:(-not $script:CanPrint) {
        $model = Get-TPSecurityReviewReport -CAChecklist $script:Ca -IntuneChecklist $script:Ic -Metadata $script:Meta -ClientName 'Contoso Ltd'
        $files = Publish-TPSecurityReviewReport -Model $model -OutputPath (Join-Path $script:Tmp 'pdf-security-review.html') -Pdf
        $files.Pdf | Should -Not -BeNullOrEmpty
        $bytes = [System.IO.File]::ReadAllBytes($files.Pdf)
        [System.Text.Encoding]::ASCII.GetString($bytes, 0, 5) | Should -Be '%PDF-'
    }
    It 'Read-TPRunRecord -IncludeChecklists keeps the row facts and drops detail, items and policy bodies' {
        $path = Join-Path $script:Tmp 'contoso-20261028-090000-results.json'
        @{ Metadata = $script:Meta; Findings = @(); CAChecklist = $script:Ca; IntuneChecklist = $script:Ic } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding UTF8
        $rec = Read-TPRunRecord -Path $path -IncludeChecklists
        @($rec.CAChecklist.Rows).Count | Should -Be @($script:Ca.Rows).Count
        ($rec | ConvertTo-Json -Depth 20) | Should -Not -Match 'victim@contoso\.com|Secret Policy Name|Hidden Policy|Report-only body'
        (Read-TPRunRecord -Path $path).CAChecklist | Should -BeNullOrEmpty
    }
    It 'the standalone script writes the review from a results file and refuses a partial run' {
        $path = Join-Path $script:Tmp 'contoso-20261028-090000-results.json'
        $out = Join-Path $script:Tmp 'standalone'
        $null = New-Item -ItemType Directory -Path $out -Force
        & pwsh -NoProfile -File (Join-Path $script:RepoRoot 'New-TPSecurityReview.ps1') -ResultsPath $path -OutputPath $out -ClientName 'Contoso Ltd' -NoPdf *> $null
        $LASTEXITCODE | Should -Be 0
        @(Get-ChildItem -LiteralPath $out -Filter '*-security-review-*.html').Count | Should -Be 1
        $partial = Join-Path $script:Tmp 'contoso-20261028-090001-results.json'
        @{ Metadata = @{ TenantDomain = 'contoso.com'; AssessmentTime = '2026-10-28T09:00:00Z'; ControlSelection = @{ Partial = $true } }; Findings = @(); CAChecklist = $script:Ca } | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $partial -Encoding UTF8
        & pwsh -NoProfile -File (Join-Path $script:RepoRoot 'New-TPSecurityReview.ps1') -ResultsPath $partial -OutputPath $out -NoPdf *> $null
        $LASTEXITCODE | Should -Be 4
    }
}

Describe 'Entry point wiring' {
    It 'publishes the review with -SecurityReview, prints it with -Pdf, and shadows no parameter' {
        $text = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
        $text | Should -Match '\[switch\] \$SecurityReview'
        $text | Should -Match 'Publish-TPSecurityReviewReport -Model \$reviewModel .*-Pdf:\$Pdf'
        $text | Should -Not -Match '(?m)^\s*\$securityReview\s*='
    }
}
