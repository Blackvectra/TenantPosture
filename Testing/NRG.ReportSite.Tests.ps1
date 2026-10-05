#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.ReportSite.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: The multi-page report site (landing page, one page per workload, action-plan CSV) is
             a VIEW over existing findings. These tests pin that it preserves every finding, verdict
             and limitation; keeps requirement, observed configuration, NRG verdict and independent
             comparison apart; keeps requirement strength (SHALL / SHOULD) apart from risk severity
             and the Automated / Manual / Declaration badge apart from the verdict; keeps collection
             failures, licensing limits, manual checks, operator declarations and unapproved NRG
             standards distinct; escapes hostile tenant text; and changes no finding.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Report site preserves every finding, verdict and limitation' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        Clear-NRGState
        $script:Hostile = '<script>alert(1)</script>"&'
        $add = { param($id, $state, $detail, $extra = @{}) Add-NRGFinding -ControlId $id -State $state -Category 'Identity' -Title "Title $id" -Severity 'High' -Detail $detail -CurrentValue "observed-$id" -RequiredValue "required-$id" -Remediation "fix-$id" -FrameworkIds 'NIST:AC-2' @extra }
        & $add 'AAD-1.1' 'Satisfied' 'Verified: blocked by policy X.'
        & $add 'DNS-1.3' 'Satisfied' 'contoso.com DMARC p=quarantine (100%).' @{ Instance = 'contoso.com' }
        & $add 'DNS-1.3' 'Partial'   'other.org DMARC p=quarantine but pct=50.' @{ Instance = 'other.org' }
        & $add 'AAD-1.2' 'Gap'       "Shortfall: $($script:Hostile) excluded." @{ AffectedObjects = @([ordered]@{ UserPrincipalName = 'a@x.example'; Reason = 'none' }, 'plain-string-object') }
        & $add 'AAD-11.3' 'NotApplicable' 'The risky service principal data was not collected; not assessed.'
        & $add 'PPL-2.2' 'NotApplicable' 'This control requires manual verification.'
        & $add 'DEF-2.3' 'NotApplicable' 'Verified: filter on. Not assessed: whether it blocks the list, because none is approved (Config/nrg-standards.json).'
        & $add 'INT-1.5' 'NotApplicable' 'Third-party EDR declared: provided by Cortex XDR, as declared by the assessor; not verified.'
        & $add 'PVW-4.1' 'NotApplicable' 'Needs E5. Not scored as a gap — surfaced as a licensing upgrade opportunity.'
        & $add 'TMS-1.4' 'NotApplicable' 'Sharing is off, so this does not apply.'
        & $add 'EXO-7.2' 'Gap' '=cmd|calc injection text'
        $script:Findings = @(Get-NRGFindings)
        $script:Before = ($script:Findings | ConvertTo-Json -Depth 8)

        $script:Out = Join-Path ([IO.Path]::GetTempPath()) ("nrg-site-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        $scuba = Join-Path $script:Out 'in.csv'
        New-Item -ItemType Directory -Force -Path $script:Out | Out-Null
        Set-Content -LiteralPath $scuba -Value "Control ID,Requirement,Result,Criticality`nMS.EXO.4.2v1,DMARC,Fail,Shall`nMS.AAD.1.1v1,Legacy,Pass,Shall" -Encoding utf8
        $meta = @{ TenantId = '00000000-0000-0000-0000-000000000000'; TenantDomain = 'contoso.example'; AssessmentTime = '2026-09-30T10:49:00-05:00'; AssessmentDate = '2026-09-30'; ToolVersion = '4.14.3'; Operator = 'Test' }
        $script:Site = Join-Path $script:Out 'site'
        $script:Result = Publish-NRGReportSite -Metadata $meta -Findings $script:Findings -OutputPath $script:Site -ScubaResultsPath $scuba
        $script:Page = @{}
        foreach ($f in Get-ChildItem -LiteralPath $script:Site -Filter '*.html') { $script:Page[$f.BaseName] = Get-Content -LiteralPath $f.FullName -Raw }
        $script:Enc = { param($t) [System.Net.WebUtility]::HtmlEncode([string]$t) }
    }
    AfterAll { if ($script:Out) { Remove-Item -LiteralPath $script:Out -Recurse -Force -ErrorAction SilentlyContinue }; Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    It 'writes a landing page, one page per workload and an action plan' {
        $script:Page.Keys | Should -Contain 'index'
        foreach ($w in 'AAD', 'DNS', 'PPL', 'DEF', 'INT', 'PVW', 'TMS', 'EXO') { $script:Page.Keys | Should -Contain $w }
        Test-Path (Join-Path $script:Site 'ActionPlan.csv') | Should -BeTrue
    }
    It 'every finding, with its title, detail, observed and required values, is on its workload page' {
        foreach ($f in $script:Findings) {
            $pg = $script:Page[($f.ControlId -split '-')[0]]
            foreach ($field in 'ControlId', 'Title', 'Detail', 'CurrentValue', 'RequiredValue') {
                $pg | Should -Match ([regex]::Escape((& $script:Enc $f.$field))) -Because "$($f.ControlId) $field must be in the report"
            }
        }
    }
    It 'every per-domain instance is its own row' {
        $script:Page['DNS'] | Should -Match 'contoso\.com'; $script:Page['DNS'] | Should -Match 'other\.org'
    }
    It 'the verdict counts on the pages equal the finding states' {
        $pills = @([regex]::Matches(($script:Page.GetEnumerator() | Where-Object { $_.Key -ne 'index' } | ForEach-Object { $_.Value }) -join '', "<span class='pill \w+'>([^<]+)</span>") | ForEach-Object { $_.Groups[1].Value })
        @($pills | Where-Object { $_ -eq 'Satisfied' }).Count | Should -Be @($script:Findings | Where-Object State -eq 'Satisfied').Count
        @($pills | Where-Object { $_ -eq 'Partial' }).Count   | Should -Be 1
        @($pills | Where-Object { $_ -eq 'Gap' }).Count       | Should -Be 2
        $pills.Count | Should -Be $script:Findings.Count
    }
    It 'collection failures, manual checks, declarations, licensing limits and unapproved standards are distinct' {
        (Get-NRGFindingLimitKind -Finding ($script:Findings | Where-Object ControlId -eq 'AAD-11.3')) | Should -Be 'Collection'
        (Get-NRGFindingLimitKind -Finding ($script:Findings | Where-Object ControlId -eq 'PPL-2.2'))  | Should -Be 'Manual'
        (Get-NRGFindingLimitKind -Finding ($script:Findings | Where-Object ControlId -eq 'DEF-2.3'))  | Should -Be 'StandardNotApproved'
        (Get-NRGFindingLimitKind -Finding ($script:Findings | Where-Object ControlId -eq 'INT-1.5'))  | Should -Be 'Declaration'
        (Get-NRGFindingLimitKind -Finding ($script:Findings | Where-Object ControlId -eq 'PVW-4.1'))  | Should -Be 'Licensing'
        (Get-NRGFindingLimitKind -Finding ($script:Findings | Where-Object ControlId -eq 'TMS-1.4'))  | Should -Be 'NotApplicable'
        $script:Page['index'] | Should -Match '<b>1</b> Collection failures'
        $script:Page['index'] | Should -Match '<b>1</b> Manual checks'
        $script:Page['index'] | Should -Match '<b>1</b> Operator declarations'
        $script:Page['index'] | Should -Match '<b>1</b> Licensing limits'
        $script:Page['index'] | Should -Match '<b>1</b> NRG standards not approved'
    }
    It 'the Automated / Manual / Declaration badge is separate from the verdict' {
        $script:Page['PPL'] | Should -Match "badge m'>Manual"
        $script:Page['PPL'] | Should -Match "pill unk'>Not assessed"
        $script:Page['INT'] | Should -Match "badge d'>Declaration"
        $script:Page['INT'] | Should -Match 'Declared, not verified'
        $script:Page['AAD'] | Should -Match "badge'>Automated"
    }
    It 'requirement strength (SHALL) is shown apart from risk severity and only where a rule is mapped' {
        $script:Page['DNS'] | Should -Match "class='strength'>SHALL"
        $script:Page['DNS'] | Should -Match '>High<'
        $script:Page['TMS'] | Should -Match 'Sharing is off'
    }
    It 'requirement, observed configuration, NRG verdict and independent comparison are four separate things' {
        $script:Page['DNS'] | Should -Match 'Required: required-DNS-1\.3'
        $script:Page['DNS'] | Should -Match 'observed-DNS-1\.3'
        $script:Page['DNS'] | Should -Match 'MS\.EXO\.4\.2v1'
        $script:Page['DNS'] | Should -Match 'Independent scan: <b>Fail</b>'
    }
    It 'a difference from the independent scan is flagged as something to investigate, not as an error or a score' {
        $script:Page['index'] | Should -Match 'Independent comparison'
        $script:Page['index'] | Should -Match 'not a score to match'
        $script:Page['index'] | Should -Match 'DNS-1\.3'
    }
    It 'tenant identity, run time, tool version and baseline versions are on the landing page' {
        $script:Page['index'] | Should -Match 'contoso\.example'; $script:Page['index'] | Should -Match '00000000-0000-0000-0000-000000000000'
        $script:Page['index'] | Should -Match 'NRG-Assessment 4\.14\.3'; $script:Page['index'] | Should -Match 'ScubaGear 2\.0\.0'
    }
    It 'evidence, exclusions and affected objects are expandable and include every object' {
        $script:Page['AAD'] | Should -Match '<details><summary>Evidence</summary>'
        $script:Page['AAD'] | Should -Match 'Affected objects \(2\)'
        $script:Page['AAD'] | Should -Match 'a@x\.example'; $script:Page['AAD'] | Should -Match 'plain-string-object'
    }
    It 'hostile tenant text is escaped and the pages carry no script or external asset' {
        foreach ($pg in $script:Page.Values) { $pg | Should -Not -Match '<script' ; $pg | Should -Not -Match 'https?://(?!www\.w3)' -Because 'self-contained: no external assets' }
        $script:Page['AAD'] | Should -Match ([regex]::Escape('&lt;script&gt;alert(1)&lt;/script&gt;'))
    }
    It 'the action plan lists what needs action with owner, target date, status and evidence columns, and neutralizes formulas' {
        $rows = @(Import-Csv -LiteralPath (Join-Path $script:Site 'ActionPlan.csv'))
        foreach ($c in 'Owner', 'Target date', 'Resolution status', 'Evidence of resolution', 'Risk severity', 'Observed', 'Remediation') { $rows[0].PSObject.Properties.Name | Should -Contain $c }
        @($rows | Where-Object 'Control ID' -eq 'AAD-1.2').Count | Should -Be 1
        @($rows | Where-Object 'Control ID' -eq 'AAD-1.1').Count | Should -Be 0 -Because 'a satisfied control needs no action'
        @($rows | Where-Object 'Control ID' -eq 'DEF-2.3')[0].'Action type' | Should -Be 'Approve the NRG standard'
        @($rows | Where-Object 'Control ID' -eq 'PPL-2.2')[0].'Action type' | Should -Be 'Verify manually'
        @($rows | Where-Object 'Control ID' -eq 'AAD-11.3')[0].'Action type' | Should -Be 'Re-collect and verify'
        @($rows | Where-Object 'Control ID' -in @('INT-1.5', 'PVW-4.1', 'TMS-1.4')).Count | Should -Be 0 -Because 'declared, unlicensed and not-applicable items are not actions'
        (@($rows | Where-Object 'Control ID' -eq 'EXO-7.2')[0].'Why (verified / shortfall / not assessed)') | Should -Match "^'="
        $rows | ForEach-Object { $_.'Resolution status' | Should -Be 'Open'; $_.Owner | Should -BeNullOrEmpty }
    }
    It 'generating the site changes no finding' {
        ($script:Findings | ConvertTo-Json -Depth 8) | Should -Be $script:Before
        ((Get-NRGFindings) | ConvertTo-Json -Depth 8) | Should -Be $script:Before
    }
    It 'branding colors are restricted to #rrggbb before they reach CSS' {
        $script:Page['index'] | Should -Match '--p:#[0-9a-fA-F]{6};--s:#[0-9a-fA-F]{6}'
    }
    It 'findings tables keep identifier, verdict, risk, check and evidence columns from collapsing (first work-computer screenshot: "Con trol", "Infor mati onal")' {
        $pg = $script:Page['EXO']
        $pg | Should -Match "<table class='ft'>"
        # A cell may not break anywhere: that lets a column shrink to one character.
        $pg | Should -Not -Match 'td\{[^}]*overflow-wrap:anywhere'
        $pg | Should -Match 'table\.ft th:nth-child\(1\)[^{]*\{white-space:nowrap\}'
    }
    It 'a passing control whose evaluator left CurrentValue empty shows its Detail sentence as the observation, not a blank cell' {
        $f = @{ ControlId = 'EXO-1.1'; State = 'Satisfied'; Severity = 'Informational'; Category = 'Audit'; Title = 'Mailbox Audit Logging Enabled'
                Detail = 'Mailbox auditing is on for the organization and no mailbox bypasses it.'; CurrentValue = ''; RequiredValue = ''; FrameworkIds = ''; Remediation = '' }
        $dir = Join-Path $script:Out 'obs'
        $null = Publish-NRGReportSite -Metadata @{ TenantDomain = 'contoso.example'; ToolVersion = '4.14.3' } -Findings @($f) -OutputPath $dir
        $html = Get-Content -LiteralPath (Join-Path $dir 'EXO.html') -Raw
        $html | Should -Match '<td>Mailbox auditing is on for the organization'
    }
    It 'a rule for a different requirement is labeled as context and is never listed as a disagreement' {
        $dir = Join-Path $script:Out 'unsupported'
        $csv = Join-Path $script:Out 'unsupported.csv'
        Set-Content -LiteralPath $csv -Value "Control ID,Requirement,Result,Criticality`
MS.AAD.5.2v1,User consent restricted,Pass,Shall" -Encoding utf8
        $f = @{ ControlId = 'AAD-12.4'; State = 'Gap'; Severity = 'High'; Category = 'Apps'; Title = 'OAuth Apps with Tenant-Wide Consent'
                Detail = '57 applications hold tenant-wide consent.'; CurrentValue = '57'; RequiredValue = '0'; FrameworkIds = ''; Remediation = '' }
        $null = Publish-NRGReportSite -Metadata @{ TenantDomain = 'contoso.example'; ToolVersion = '4.14.3' } -Findings @($f) -OutputPath $dir -ScubaResultsPath $csv
        $aad = Get-Content -LiteralPath (Join-Path $dir 'AAD.html') -Raw
        $idx = Get-Content -LiteralPath (Join-Path $dir 'index.html') -Raw
        $aad | Should -Match 'Different requirement \(context only, not compared\)'
        $aad | Should -Not -Match "<div class='diff'>"
        $idx | Should -Not -Match '<li><b>AAD-12\.4</b>'
    }
    It 'accepts the ScubaGear JSON results file as well as the CSV, with the same verdicts' {
        $dir = Join-Path $script:Out 'scuba-json'
        $json = Join-Path $script:Out 'ScubaResults_x.json'
        $doc = [ordered]@{ MetaData = @{ ToolVersion = '2.0.0' }; Results = [ordered]@{
            EXO = @([ordered]@{ GroupName = 'Forwarding'; Controls = @([ordered]@{ 'Control ID' = 'MS.EXO.1.1v2'; Result = 'Fail'; Requirement = 'x' }) })
            SecuritySuite = @([ordered]@{ GroupName = 'DLP'; Controls = @([ordered]@{ 'Control ID' = 'MS.SECURITYSUITE.3.2v1'; Result = 'Warning' }) }) } }
        $doc | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $json -Encoding utf8
        $map = & (Get-Module NRG-Assessment) { param($p) Read-NRGScubaResults -Path $p } $json
        $map['MS.EXO.1.1v2'] | Should -Be 'Fail'
        $map['MS.SECURITYSUITE.3.2v1'] | Should -Be 'Warning'
        $f = @{ ControlId = 'EXO-6.1'; State = 'Satisfied'; Severity = 'High'; Category = 'Mail'; Title = 'Forwarding'
                Detail = 'No forwarding.'; CurrentValue = ''; RequiredValue = ''; FrameworkIds = ''; Remediation = '' }
        $r = Publish-NRGReportSite -Metadata @{ TenantDomain = 'contoso.example'; ToolVersion = '4.14.3' } -Findings @($f) -OutputPath $dir -ScubaResultsPath $json
        Test-Path (Join-Path $dir 'index.html') | Should -BeTrue
    }
    It 'a file that is not a ScubaGear result costs the comparison, never the site' {
        $dir = Join-Path $script:Out 'scuba-foreign'
        $bad = Join-Path $script:Out 'foreign.json'
        Set-Content -LiteralPath $bad -Value '{"hello": "world"}' -Encoding utf8
        $f = @{ ControlId = 'EXO-6.1'; State = 'Satisfied'; Severity = 'High'; Category = 'Mail'; Title = 'Forwarding'
                Detail = 'No forwarding.'; CurrentValue = ''; RequiredValue = ''; FrameworkIds = ''; Remediation = '' }
        $null = Publish-NRGReportSite -Metadata @{ TenantDomain = 'contoso.example'; ToolVersion = '4.14.3' } -Findings @($f) -OutputPath $dir -ScubaResultsPath $bad -WarningVariable w -WarningAction SilentlyContinue
        Test-Path (Join-Path $dir 'index.html') | Should -BeTrue
        ($w -join ' ') | Should -Match 'ScubaGear results not used'
    }
    It 'a CSV without the Control ID and Result columns is reported, not a crash' {
        $dir = Join-Path $script:Out 'scuba-badcsv'
        $bad = Join-Path $script:Out 'bad.csv'
        Set-Content -LiteralPath $bad -Value "Name,Value`
foo,bar" -Encoding utf8
        $f = @{ ControlId = 'EXO-6.1'; State = 'Satisfied'; Severity = 'High'; Category = 'Mail'; Title = 'Forwarding'
                Detail = 'No forwarding.'; CurrentValue = ''; RequiredValue = ''; FrameworkIds = ''; Remediation = '' }
        { Publish-NRGReportSite -Metadata @{ TenantDomain = 'contoso.example'; ToolVersion = '4.14.3' } -Findings @($f) -OutputPath $dir -ScubaResultsPath $bad -WarningAction SilentlyContinue } | Should -Not -Throw
        Test-Path (Join-Path $dir 'index.html') | Should -BeTrue
    }
    It 'a relative OutputPath is created under the current PowerShell location, not the process start folder' {
        $base = Join-Path $script:Out 'relbase'
        $null = New-Item -ItemType Directory -Path $base -Force
        $f = @{ ControlId = 'EXO-6.1'; State = 'Satisfied'; Severity = 'High'; Category = 'Mail'; Title = 'Forwarding'
                Detail = 'No forwarding.'; CurrentValue = ''; RequiredValue = ''; FrameworkIds = ''; Remediation = '' }
        Push-Location -LiteralPath $base
        try {
            $null = Publish-NRGReportSite -Metadata @{ TenantDomain = 'contoso.example'; ToolVersion = '4.14.3' } -Findings @($f) -OutputPath '.\out\site'
        } finally { Pop-Location }
        Test-Path (Join-Path $base 'out\site\index.html') | Should -BeTrue
        Test-Path (Join-Path $base 'out\site\EXO.html') | Should -BeTrue
    }
}

# Found by the security review of #106 (2026-10-04). The report site carries finding Detail,
# observed values and affected objects (mailboxes, forwarding targets, app names), so its files get
# the same owner-only protection as the results JSON, applied before the content is written, on
# both callers: the entry point and the standalone rebuild, which used to republish an owner-only
# results file into files every local user could read. And a results file is input: a control ID
# from it must not name a file outside the site folder or break out of a link on the landing page.
Describe 'Report site files are owner-only and a results file cannot steer file names' {
    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-siteacl-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        $null = New-Item -ItemType Directory -Path $script:Tmp -Force
        $script:OwnerOnly = {
            param([string] $Path)
            if ($IsWindows) {
                $acl = Get-Acl -LiteralPath $Path
                $broad = @($acl.Access | Where-Object { [string]$_.IdentityReference -match '(^|\\)(Everyone|Users|Authenticated Users)$' })
                return ($acl.AreAccessRulesProtected -and $broad.Count -eq 0)
            }
            # Group and other bits (rwx rwx) clear.
            return (([int][System.IO.File]::GetUnixFileMode($Path)) -band 0x3F) -eq 0
        }
        $script:Gap = @{ ControlId = 'EXO-7.2'; State = 'Gap'; Severity = 'High'; Category = 'Mail'; Title = 'External forwarding rules'
                         Detail = 'Shortfall: 1 inbox rule forwards outside the organization.'; CurrentValue = '1 rule'; RequiredValue = 'none'
                         FrameworkIds = ''; Remediation = 'Remove the rule.'
                         AffectedObjects = @([ordered]@{ Mailbox = 'ceo@contoso.example'; RuleName = 'r'; ForwardTo = 'drop@evil.example' }) }
        $script:Meta = @{ TenantDomain = 'contoso.example'; TenantId = '00000000-0000-0000-0000-000000000000'; ToolVersion = '4.14.3' }
    }
    AfterAll { if ($script:Tmp) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue } }

    It 'every file the publisher writes is owner-only when it returns, before any caller-side step' {
        $site = Join-Path $script:Tmp 'site-direct'
        $r = Publish-NRGReportSite -Metadata $script:Meta -Findings @($script:Gap) -OutputPath $site
        @($r.Files).Count | Should -BeGreaterThan 2
        foreach ($f in @($r.Files)) { (& $script:OwnerOnly $f) | Should -BeTrue -Because "$(Split-Path -Leaf $f) carries tenant findings" }
        # The action plan keeps the byte-order mark Excel needs.
        $bytes = [System.IO.File]::ReadAllBytes((Join-Path $site 'ActionPlan.csv'))
        @($bytes[0..2]) | Should -Be @(239, 187, 191)
    }
    It 'the standalone rebuild (New-NRGReportSite.ps1) writes owner-only files from an owner-only results file' {
        $res = Join-Path $script:Tmp 'contoso-results.json'
        Set-NRGSensitiveFileContent -Path $res -Content (@{ Metadata = $script:Meta; Findings = @($script:Gap) } | ConvertTo-Json -Depth 10)
        $site = Join-Path $script:Tmp 'site-standalone'
        $null = & pwsh -NoProfile -File (Join-Path $script:Root 'New-NRGReportSite.ps1') -ResultsPath $res -OutputPath $site 2>&1
        $LASTEXITCODE | Should -Be 0
        $files = @(Get-ChildItem -LiteralPath $site -File)
        $files.Count | Should -BeGreaterThan 2
        foreach ($f in $files) { (& $script:OwnerOnly $f.FullName) | Should -BeTrue -Because "$($f.Name) carries tenant findings" }
    }
    It 'the publisher writes only through the hardened writer' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root 'Publishers/Publish-NRGReportSite.ps1'), [ref]$null, [ref]$null)
        $plain = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -in @('Set-Content', 'Out-File', 'Add-Content') }, $true))
        $dotnet = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and [string]$n.Member -match '^Write(All|Lines|Text|Bytes)' }, $true))
        ($plain.Count + $dotnet.Count) | Should -Be 0
    }
    It 'a control ID from a results file cannot name a file outside the site folder or break out of a link' {
        # Two levels deep, so a '../../' escape lands inside the temp folder this test searches.
        $site = Join-Path $script:Tmp 'a' 'b' 'site-hostile'
        $mk ={ param($id) @{ ControlId = $id; State = 'Gap'; Severity = 'High'; Category = 'X'; Title = 't'; Detail = 'd'; CurrentValue = ''; RequiredValue = ''; FrameworkIds = ''; Remediation = '' } }
        $hostile = @(
            (& $mk "x'onmouseover='alert(1)-1.1"),
            (& $mk '..\..\escape-1.1'),
            (& $mk '../../escape-1.2'),
            (& $mk 'EXO-6.1')
        )
        { $null = Publish-NRGReportSite -Metadata $script:Meta -Findings $hostile -OutputPath $site } | Should -Not -Throw
        # Nothing written beside or above the site folder.
        @(Get-ChildItem -LiteralPath $script:Tmp -Filter '*escape*' -Recurse -ErrorAction SilentlyContinue).Count | Should -Be 0
        foreach ($f in @(Get-ChildItem -LiteralPath $site -Recurse -File)) {
            $f.DirectoryName | Should -Be ((Resolve-Path -LiteralPath $site).Path)
            $f.Name | Should -Match '^([A-Za-z]{1,12}\.html|ActionPlan\.csv)$'
        }
        (Get-Content -LiteralPath (Join-Path $site 'index.html') -Raw) | Should -Not -Match "onmouseover='alert"
        # The finding itself is still reported, under an unrecognized workload.
        (Get-ChildItem -LiteralPath $site -Filter '*.html' | ForEach-Object { Get-Content -LiteralPath $_.FullName -Raw }) -join "`n" | Should -Match 'onmouseover=&#39;alert'
    }
}
