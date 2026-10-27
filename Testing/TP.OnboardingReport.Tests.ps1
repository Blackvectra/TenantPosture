#Requires -Version 7.0
#
# TP.OnboardingReport.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Guards the new-client onboarding report: Lib/Get-TPOnboardingModel.ps1,
# Publishers/Publish-TPOnboardingReport.ps1 and Invoke-TPAssessment.ps1
# -OnboardingReport:
#   - the 30/60/90 bucket rules, with Days 1-30 reusing the improvement plan's
#     own "Do now" decision, and an undocumented impact never in Days 1-30
#   - license-blocked items in their own list with the license that unlocks them
#   - a partial or quick run is refused (and the entry point stops before sign-in)
#   - the coming-changes section appears only when its catalog file exists,
#     lists only entries dated today or later and shows dates as given
#   - no "compliant", no time-based effort figure, no pricing
# Data keys consumed: none live. Graph scopes / cmdlets: none (stubs only).

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    $script:Mod = Get-Module TenantPosture
    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('tp-onb-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    $null = [IO.Directory]::CreateDirectory($script:Tmp)
    $script:Now = [datetime]::new(2030, 6, 15, 12, 0, 0, [DateTimeKind]::Utc)
    $script:Lic = Get-TPTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'SPB'; ServicePlans = @('AAD_PREMIUM', 'INTUNE_A', 'ATP_ENTERPRISE', 'EXCHANGE_S_ARCHIVE_ADDON') })
    $marker = & $script:Mod { $script:TPUpgradeMarker }

    # Real controls, chosen by their own severity and licensing, so the model's
    # reads of controls.json are exercised rather than bypassed.
    $controls = @(Get-TPControlDefinitions)
    $licensed = { param($c) [bool](Test-TPLicenseRequirementMet -LicenseRequirement ([string]$c.LicenseRequirement) -LicenseProfile $script:Lic -ControlId $c.ControlId) }
    $pick = {
        param([string] $Sev, [bool] $Lic, [string[]] $Not)
        @($controls | Where-Object { $_.Severity -eq $Sev -and $_.ControlId -notin $Not -and ((& $licensed $_) -eq $Lic) -and ($Lic -or [string]$_.LicenseRequirement) } | Select-Object -First 1)[0].ControlId
    }
    $used = [System.Collections.Generic.List[string]]::new()
    $take = { param($s, $l) $id = & $pick $s $l @($used); $used.Add($id); $id }
    $script:Id = [ordered]@{
        A = & $take 'Critical' $true; A2 = & $take 'High' $true; B = & $take 'High' $true; C = & $take 'High' $true
        D = & $take 'Medium' $true; E = & $take 'Medium' $true; F = & $take 'Low' $true; G = & $take 'High' $false
        H = & $take 'Medium' $true; S = & $take 'High' $true; N = & $take 'Low' $true
    }
    foreach ($k in $script:Id.Keys) { $script:Id[$k] | Should -Not -BeNullOrEmpty -Because "a control for case $k" }

    # An impact catalog this suite controls: real archetypes, chosen mappings.
    $real = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/operational-impact.json') -Raw | ConvertFrom-Json -AsHashtable
    $map = [ordered]@{}
    $map[$script:Id.A] = 'none-visible'; $map[$script:Id.A2] = 'admin-review-workload'
    $map[$script:Id.C] = 'device-gate'; $map[$script:Id.D] = 'mail-flow-latency'
    $map[$script:Id.E] = 'none-visible'; $map[$script:Id.F] = 'auth-hardware'; $map[$script:Id.G] = 'none-visible'
    # B is deliberately absent: no documented impact.
    $script:Impact = Join-Path $script:Tmp 'impact.json'
    [ordered]@{ version = 'test'; archetypes = $real.archetypes; controls = $map; overrides = @{} } | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $script:Impact -Encoding utf8

    $mk = { param($id, $state, $detail = 'fixture detail') [pscustomobject]@{ ControlId = $id; State = $state; Severity = 'High'; Title = "t $id"; Detail = $detail; CurrentValue = "cv $id"; Remediation = '' } }
    $script:Findings = @(
        (& $mk $script:Id.A 'Gap'); (& $mk $script:Id.A2 'Partial'); (& $mk $script:Id.B 'Gap'); (& $mk $script:Id.C 'Gap')
        (& $mk $script:Id.D 'Gap'); (& $mk $script:Id.E 'Gap'); (& $mk $script:Id.F 'Partial'); (& $mk $script:Id.G 'Gap')
        (& $mk $script:Id.H 'NotApplicable' "Not scored: this control requires X — $marker, not counted against the score.")
        (& $mk $script:Id.S 'Satisfied'); (& $mk $script:Id.N 'NotApplicable' 'Not licensed? no: does not apply.')
    )
    $script:Meta = @{ TenantDomain = 'contoso.example'; TenantId = 'aaaaaaaa-1111-4111-8111-000000000001'; AssessmentTime = $script:Now.AddHours(-1).ToString('o'); ToolVersion = '4.14.3'
        Maturity = @{ Score = 47; Label = 'Developing'; Qualification = '' }; Operator = 'operator@msp.example' }
    $script:Build = {
        param([object] $Meta = $script:Meta, [object] $LicenseProfile = $script:Lic, [string] $Changes = (Join-Path $script:Tmp 'no-such-changes.json'))
        Get-TPOnboardingModel -Findings $script:Findings -Metadata $Meta -LicenseProfile $LicenseProfile -ImpactPath $script:Impact -ChangesPath $Changes -Now $script:Now
    }
    $script:M = & $script:Build
    $script:Ids = { param($list) @($list | ForEach-Object { $_.ControlId }) }
}

AfterAll {
    if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue
}

Describe 'Onboarding: the 30/60/90 buckets' {
    It 'Days 1-30 holds Critical and High items on the improvement plan''s Do now track only' {
        @(& $script:Ids $script:M.Plan.Days1to30) | Should -Be @($script:Id.A, $script:Id.A2)
        foreach ($it in $script:M.Plan.Days1to30) { $it.Archetype | Should -BeIn (& $script:Mod { Get-TPLowFrictionArchetypes }) }
    }
    It 'an item with no documented impact is planned after review, never in Days 1-30' {
        @(& $script:Ids $script:M.Plan.PlanAfterReview) | Should -Be @($script:Id.B)
        @(& $script:Ids $script:M.Plan.Days1to30) | Should -Not -Contain $script:Id.B
        @($script:M.Plan.PlanAfterReview)[0].Effort | Should -Be 'Not documented'
    }
    It 'Days 31-60 holds the remaining High items and policy changes; a project there says it can run past the window' {
        @(& $script:Ids $script:M.Plan.Days31to60) | Should -Be @($script:Id.C, $script:Id.D)
        $c = @($script:M.Plan.Days31to60 | Where-Object { $_.ControlId -eq $script:Id.C })[0]
        $c.Effort | Should -Be 'Project'
        $c.Note | Should -Match 'can run past it'
    }
    It 'Days 61-90 holds the rest: low-friction Medium items and Low projects' {
        @(& $script:Ids $script:M.Plan.Days61to90) | Should -Be @($script:Id.E, $script:Id.F)
    }
    It 'the Do now decision is the improvement plan''s own, not a second copy' {
        $plan = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Get-TPNISTImprovementPlan.ps1') -Raw
        $onb = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Get-TPOnboardingModel.ps1') -Raw
        $onb | Should -Match 'Get-TPRemediationTrack'
        $onb | Should -Not -Match "'none-visible'"
        ([regex]::Matches($plan, "'none-visible'")).Count | Should -Be 1 -Because 'the set is defined once, in Get-TPLowFrictionArchetypes'
        $plan | Should -Match 'Get-TPRemediationTrack -Licensed'
    }
}

Describe 'Onboarding: license decisions' {
    It 'lists an unlicensed item and a license-gated one, each with the license that unlocks it' {
        $lic = @($script:M.LicenseDecision)
        @(& $script:Ids $lic | Sort-Object) | Should -Be @(@($script:Id.G, $script:Id.H) | Sort-Object)
        foreach ($it in $lic) { $it.License | Should -Not -BeNullOrEmpty }
        @($lic | Where-Object { $_.ControlId -eq $script:Id.G })[0].Reason | Should -Match '^Not licensed'
        @($lic | Where-Object { $_.ControlId -eq $script:Id.H })[0].Reason | Should -Match 'License gating'
    }
    It 'with licensing not read, says so rather than calling it unlicensed' {
        $m = & $script:Build -LicenseProfile $null
        $m.LicenseTier | Should -Be 'Not read in this run'
        @($m.LicenseDecision | Where-Object { $_.ControlId -eq $script:Id.G })[0].Reason | Should -Match 'not read'
    }
    It 'a satisfied control is working and a plain not-applicable one is neither open nor passed' {
        @(& $script:Ids $script:M.Working) | Should -Be @($script:Id.S)
        $all = @(& $script:Ids @($script:M.Plan.Values | ForEach-Object { $_ })) + @(& $script:Ids $script:M.LicenseDecision)
        $all | Should -Not -Contain $script:Id.N
        $script:M.Counts.NotApplicable | Should -Be 2
    }
    It 'top risks are open Critical and High items with their business risk from controls.json' {
        $r = @($script:M.TopRisks)
        $r[0].ControlId | Should -Be $script:Id.A
        $r[0].BusinessRisk | Should -Be ([string](Get-TPControlById -ControlId $script:Id.A).BusinessRisk)
        @($r).Count | Should -BeLessOrEqual 5
    }
}

Describe 'Onboarding: refusals' {
    It 'refuses a partial run' {
        $meta = $script:Meta.Clone(); $meta['ControlSelection'] = @{ Partial = $true; SelectedCount = 1; TotalControls = 253; Include = @('AAD-1.2'); SelectedControlIds = @('AAD-1.2') }
        $m = & $script:Build -Meta $meta
        $m.Available | Should -BeFalse
        $m.Refused | Should -BeTrue
        $m.Note | Should -Match 'partial run'
        { Publish-TPOnboardingReport -Model $m -OutputPath (Join-Path $script:Tmp 'x.html') } | Should -Throw '*not generated*'
    }
    It 'refuses a quick scan' {
        $meta = $script:Meta.Clone(); $meta['QuickScan'] = $true
        (& $script:Build -Meta $meta).Note | Should -Match 'quick scan'
    }
}

Describe 'Onboarding: coming Microsoft changes' {
    BeforeAll {
        $script:Changes = Join-Path $script:Tmp 'microsoft-changes.json'
        [ordered]@{ version = '1'; sourceRetrieved = '2030-06-01'; changes = @(
            [ordered]@{ Id = 'later'; Title = 'Later change'; Date = '2031-01-15'; DateQualifier = 'Starting'; Summary = 's1'; Impact = 'i1'; RelatedControls = @($script:Id.A, 'ZZZ-9.9'); SourceUrl = 'https://learn.microsoft.com/x'; SourceTitle = 'Learn' }
            [ordered]@{ Id = 'month'; Title = 'This year change'; Date = '2030-12'; DateQualifier = 'By'; Summary = 's2'; Impact = ''; RelatedControls = @(); SourceUrl = 'javascript:alert(1)'; SourceTitle = 'Bad' }
            [ordered]@{ Id = 'past'; Title = 'Past change'; Date = '2020-01-01'; DateQualifier = ''; Summary = 'old'; Impact = ''; RelatedControls = @(); SourceUrl = ''; SourceTitle = '' }
            [ordered]@{ Id = 'undated'; Title = 'Undated change'; Date = 'TBD'; DateQualifier = ''; Summary = 'x'; Impact = ''; RelatedControls = @(); SourceUrl = ''; SourceTitle = '' }
        ) } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:Changes -Encoding utf8
        $script:MC = & $script:Build -Changes $script:Changes
        $script:FilesC = Publish-TPOnboardingReport -Model $script:MC -OutputPath (Join-Path $script:Tmp 'with-changes.html') -GeneratedAt $script:Now
    }
    It 'lists only entries dated today or later, by date, with the date as the file gives it' {
        @($script:MC.Changes.Changes | ForEach-Object { $_.Id }) | Should -Be @('month', 'later')
        @($script:MC.Changes.Changes)[0].Date | Should -Be '2030-12'
        $script:MC.Changes.Undated | Should -Be 1
    }
    It 'shows each related control''s state in this tenant' {
        $rel = @(@($script:MC.Changes.Changes)[1].Related)
        @($rel | Where-Object { $_.ControlId -eq $script:Id.A })[0].State | Should -Be 'Gap'
        @($rel | Where-Object { $_.ControlId -eq 'ZZZ-9.9' })[0].State | Should -Be 'Not assessed in this run'
    }
    It 'renders the section, with https sources only' {
        $html = Get-Content -LiteralPath $script:FilesC.Html -Raw
        $html | Should -Match 'id="microsoft-changes"'
        $html | Should -Match 'By 2030-12'
        $html | Should -Match 'href="https://learn\.microsoft\.com/x" rel="noopener noreferrer"'
        $html | Should -Not -Match 'javascript:'
        $html | Should -Not -Match 'Past change|Undated change'
    }
    It 'without the catalog file the section is absent, silently' {
        $script:M.Changes | Should -BeNullOrEmpty
        $f = Publish-TPOnboardingReport -Model $script:M -OutputPath (Join-Path $script:Tmp 'no-changes.html') -GeneratedAt $script:Now
        (Get-Content -LiteralPath $f.Html -Raw) | Should -Not -Match 'microsoft-changes|Coming Microsoft changes'
        (Get-Content -LiteralPath $f.Markdown -Raw) | Should -Not -Match 'Coming Microsoft changes'
    }
    It 'reads Config/microsoft-changes.json by default, and only when it exists' {
        $m = Get-TPOnboardingModel -Findings $script:Findings -Metadata $script:Meta -LicenseProfile $script:Lic -ImpactPath $script:Impact -Now $script:Now
        if (Test-Path -LiteralPath (Join-Path $script:RepoRoot 'Config/microsoft-changes.json')) { $m.Changes | Should -Not -BeNullOrEmpty }
        else { $m.Changes | Should -BeNullOrEmpty }
    }
}

Describe 'Onboarding: what the report says' {
    BeforeAll {
        # Data text (titles, business risk, remediation, impact summaries) is
        # replaced with a placeholder so these checks judge the report's own words.
        $neutral = & $script:Build -Changes $script:Changes
        $scrub = { param($it) foreach ($k in 'Title', 'BusinessRisk', 'Remediation', 'CurrentValue', 'ImpactSummary', 'License', 'Reason') { if ($it.Contains($k)) { $it[$k] = 'DATA' } } }
        foreach ($list in @($neutral.Plan.Values) + @(, $neutral.LicenseDecision) + @(, $neutral.Working) + @(, $neutral.TopRisks)) { foreach ($it in @($list)) { & $scrub $it } }
        foreach ($c in @($neutral.Changes.Changes)) { $c.Title = 'DATA'; $c.Summary = 'DATA'; $c.Impact = 'DATA' }
        $f = Publish-TPOnboardingReport -Model $neutral -OutputPath (Join-Path $script:Tmp 'neutral.html') -GeneratedAt $script:Now `
            -Brand @{ CompanyName = 'Contoso Managed IT'; PrimaryColor = '#2563eb'; HourlyRate = 98765; AssessmentFee = 43210 }
        $script:Text = (Get-Content -LiteralPath $f.Html -Raw) + "`n" + (Get-Content -LiteralPath $f.Markdown -Raw)
        $script:Real = Publish-TPOnboardingReport -Model $script:M -OutputPath (Join-Path $script:Tmp 'real.html') -GeneratedAt $script:Now
    }
    It 'never says compliant' {
        $script:Text | Should -Not -Match '(?i)\bcompliant\b'
    }
    It 'gives no time-based effort figure: the only day numbers are the window labels' {
        $hits = @([regex]::Matches($script:Text, '(?i)\b\d+\s*(h|hrs?|hours?|days?|weeks?)\b') | ForEach-Object { $_.Value })
        $hits | Should -BeNullOrEmpty
        $script:Text | Should -Match 'Days 1-30'
        $script:Text | Should -Match 'Days 31-60'
        $script:Text | Should -Match 'Days 61-90'
        $script:Text | Should -Match 'never a time estimate'
    }
    It 'makes no cost promise' {
        $script:Text | Should -Not -Match '98765|43210|\$\s?\d'
    }
    It 'names the score and maturity as recorded, the license tier, and the scope statement' {
        $script:Text | Should -Match 'Score \(recorded\)'
        $script:Text | Should -Match 'Developing'
        $script:Text | Should -Match 'Microsoft 365 Business Premium'
        $script:Text | Should -Match 'neither open nor passed'
    }
    It 'is self-contained and never carries the operator or a finding''s detail' {
        $html = Get-Content -LiteralPath $script:Real.Html -Raw
        $html | Should -Not -Match '(?i)<script|<link'
        $html | Should -Not -Match 'operator@msp\.example|fixture detail|aaaaaaaa-1111'
        $html | Should -Match '@media print'
    }
    It 'escapes hostile text' {
        $m = & $script:Build
        @($m.Plan.Days1to30)[0].Remediation = '<script>alert(1)</script>[x](javascript:y)'
        $f = Publish-TPOnboardingReport -Model $m -OutputPath (Join-Path $script:Tmp 'hostile.html')
        (Get-Content -LiteralPath $f.Html -Raw) | Should -Not -Match '<script>alert'
        (Get-Content -LiteralPath $f.Markdown -Raw) | Should -Not -Match '(?<!\\)\[x(?<!\\)\]\('
    }
}

Describe 'Onboarding: the entry point' {
    It 'declares -OnboardingReport, implied by -AllFiles' {
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
        (Get-Command (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1')).Parameters.ContainsKey('OnboardingReport') | Should -BeTrue
        $src | Should -Match '\(\$OnboardingReport -or \$AllFiles\)'
        $src | Should -Match "On = \[bool\]\`$OnboardingReport;"
    }
    It 'refuses -OnboardingReport with -ControlId before anything signs in (exit 4)' {
        $mods = Join-Path $script:Tmp 'mods'
        $exoVersion = [string](& $script:Mod { Get-TPExoModuleFloor }).Min
        $stub = {
            param([string] $Name, [string] $Version, [string] $Guid, [string] $Body)
            $d = Join-Path $mods $Name $Version
            $null = [IO.Directory]::CreateDirectory($d)
            Set-Content -LiteralPath (Join-Path $d "$Name.psd1") -Encoding utf8 -Value "@{ RootModule = '$Name.psm1'; ModuleVersion = '$Version'; GUID = '$Guid'; FunctionsToExport = '*'; CmdletsToExport = @(); AliasesToExport = @() }"
            Set-Content -LiteralPath (Join-Path $d "$Name.psm1") -Encoding utf8 -Value $Body
        }
        & $stub 'Microsoft.Graph.Authentication' '2.40.0' 'b0b0b0b0-1111-4222-8333-444444444444' 'function Connect-MgGraph { [CmdletBinding()] param($Scopes, $ContextScope, [switch] $NoWelcome, $TenantId, $Environment) throw "sign-in attempted" }; function Get-MgContext { $null }; function Disconnect-MgGraph { }; function Invoke-MgGraphRequest { @{ value = @() } }'
        & $stub 'ExchangeOnlineManagement' $exoVersion 'c0c0c0c0-1111-4222-8333-555555555555' 'function Connect-ExchangeOnline { throw "sign-in attempted" }; function Disconnect-ExchangeOnline { }; function Get-ConnectionInformation { @() }'
        & $stub 'MicrosoftTeams' '5.9.0' 'd0d0d0d0-1111-4222-8333-666666666666' 'function Connect-MicrosoftTeams { throw "sign-in attempted" }'
        $old = $env:PSModulePath
        try {
            $env:PSModulePath = $mods + [System.IO.Path]::PathSeparator + $env:PSModulePath
            $out = Join-Path $script:Tmp 'entry'
            $cmd = "& '$(Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1')' -NonInteractive -ControlId AAD-1.2 -OnboardingReport -OutputPath '$out'; exit `$LASTEXITCODE"
            $text = (& (Get-Process -Id $PID).Path -NoProfile -NonInteractive -Command $cmd *>&1 | Out-String) -replace "\e\[[0-9;]*m", ''
            $code = $LASTEXITCODE
        } finally { $env:PSModulePath = $old }
        $code | Should -Be 4 -Because $text
        $text | Should -Match 'OnboardingReport is a first look at the whole tenant'
        $text | Should -Not -Match 'Connecting to M365|sign-in attempted'
    }
}
