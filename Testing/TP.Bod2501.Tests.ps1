#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
#
# TP.Bod2501.Tests.ps1
# TenantPosture
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
#
# Guards the CISA BOD 25-01 required-configurations view:
# Config/bod-25-01-required.json (CISA's Required Configurations list, Microsoft
# 365 rows), Lib/Get-TPBod2501View.ps1 and Publishers/Publish-TPBod2501View.ps1.
#
# The rules are the SSP's and the HIPAA view's: the required list is CISA's and
# carries its source; a policy no check establishes never reads as met, even
# with every control in the tool satisfied; a citing control with no verdict
# counts in neither direction; a disagreement with ScubaGear is flagged, never
# resolved; and nothing says "compliant".
#
# Data keys consumed: none. Graph scopes / cmdlets: none.

Describe 'CISA BOD 25-01 required-configurations view' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module TenantPosture
        $script:CatPath = Join-Path $script:Root 'Config' 'bod-25-01-required.json'
        $script:Cat = Get-Content -LiteralPath $script:CatPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 20
        $script:Policies = @($script:Cat.policies)
        $script:ScubaIds = @(Get-Content -LiteralPath (Join-Path $script:Root 'Config' 'framework-baselines' 'scuba-ids-v2.0.0.txt') |
            Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object { ($_ -split '\s')[0].Trim() })
        $script:Align = Get-Content -LiteralPath (Join-Path $script:Root 'Config' 'scuba-alignment.json') -Raw | ConvertFrom-Json -Depth 20
        $script:Controls = @(Get-TPControlDefinitions)
        $script:St = & $script:Mod { Get-TPBod2501StatusNames }
        $script:Differ = & $script:Mod { Get-TPBod2501DifferLabel }

        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('tp-bod-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        $null = New-Item -ItemType Directory -Force -Path $script:Tmp

        function script:F([string] $Cid, [string] $State, [string] $Detail = '', [string] $Instance = '') {
            @{ ControlId = $Cid; State = $State; Detail = $Detail; Title = "$Cid title"; Instance = $Instance }
        }
        # Every control in the tool satisfied, except the overrides given.
        function script:AllPassExcept([hashtable] $Override = @{}) {
            @($script:Controls | ForEach-Object {
                $s = if ($Override.ContainsKey($_.ControlId)) { $Override[$_.ControlId] } else { 'Satisfied' }
                F $_.ControlId $s 'checked'
            })
        }
        function script:View([object[]] $Findings, $Scuba = $null, [string] $ScubaPath = '', [string] $Config = '') {
            $a = @{ Findings = $Findings }
            if ($null -ne $Scuba) { $a.ScubaResults = $Scuba }
            if ($ScubaPath) { $a.ScubaResultsPath = $ScubaPath }
            if ($Config) { $a.ConfigPath = $Config }
            Get-TPBod2501View @a
        }
        function script:Row($View, [string] $PolicyId) { @($View['Policies'] | Where-Object { $_['PolicyId'] -eq $PolicyId })[0] }
        $script:AllPass = AllPassExcept
    }

    AfterAll {
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    Context 'Catalog: CISA''s Required Configurations list, as retrieved' {

        It 'holds the 56 Microsoft 365 policies, each once' {
            $script:Policies.Count | Should -Be 56
            @($script:Policies.PolicyId | Select-Object -Unique).Count | Should -Be 56
        }

        It 'every policy id is a current ScubaGear v2.0.0 policy id' {
            foreach ($p in $script:Policies) { $script:ScubaIds | Should -Contain $p.PolicyId -Because "$($p.PolicyId) is not in scuba-ids-v2.0.0.txt" }
        }

        It 'every policy is a SHALL with its statement, CISA dates and a known product' {
            $keys = @($script:Cat.products.Key)
            foreach ($p in $script:Policies) {
                $p.Criticality | Should -Be 'SHALL'
                $p.Statement   | Should -Match 'SHALL' -Because $p.PolicyId
                $p.CisaDateAddedOrModified | Should -Match '^(January|February|March|April|May|June|July|August|September|October|November|December) \d{4}$'
                $p.CisaDueDate | Should -Not -BeNullOrEmpty
                $keys | Should -Contain $p.Product
                $p.PolicyId | Should -Match ('^MS\.' + [regex]::Escape($p.Product.ToUpperInvariant()) + '\.')
            }
        }

        It 'records CISA as its source, the retrieval date, the basis and the ScubaGear version it was checked against' {
            @($script:Cat.source).Count | Should -BeGreaterThan 0
            foreach ($u in @($script:Cat.source)) { $u | Should -Match '^https://www\.cisa\.gov/' }
            $script:Cat.directive.url | Should -Match '^https://www\.cisa\.gov/'
            $script:Cat.sourceRetrieved | Should -Match '^\d{4}-\d{2}-\d{2}$'
            $script:Cat.basis | Should -Match 'Required Configurations page'
            $script:Cat.scubaGear.version | Should -Be $script:Align.Source.ToolVersion
            $script:Cat.notEncoded | Should -Match 'Google Workspace'
        }

        It 'uses US spelling and never says compliant' {
            $raw = Get-Content -LiteralPath $script:CatPath -Raw
            $raw | Should -Not -Match '(?i)licence|organisation|behaviour|catalogue'
            $raw | Should -Not -Match '(?i)\bcompliant\b'
        }
    }

    Context 'Statuses' {

        It 'with every control in the tool satisfied, the policies no check establishes still claim nothing' {
            $v = View $script:AllPass
            $v.Available | Should -BeTrue
            $v.Summary.Total | Should -Be 56
            foreach ($r in @($v.Policies | Where-Object { @($_['Controls']).Count -eq 0 })) {
                $r['Status'] | Should -Be $script:St.Manual -Because $r['PolicyId']
            }
            # Cited only by controls whose relation establishes nothing: still manual, listed as not counted.
            $r31 = Row $v 'MS.AAD.3.1v1'
            $r31['Status'] | Should -Be $script:St.Manual
            @($r31['CitedNotCounted'].ControlId) | Should -Contain 'AAD-9.2'
            (Row $v 'MS.AAD.7.7v1')['Status'] | Should -Be $script:St.Manual
            (Row $v 'MS.AAD.6.1v1')['Status'] | Should -Be $script:St.Manual
            $v.Summary.ByStatus[$script:St.Met] | Should -Be $v.Summary.Equivalent
            $v.Summary.ByStatus[$script:St.Partly] | Should -Be $v.Summary.PartialOnly
            $v.Summary.ByStatus[$script:St.Manual] | Should -Be ($v.Summary.Uncited + $v.Summary.NotCounted)
        }

        It 'an Equivalent check that passed is tool-verified met' {
            (Row (View $script:AllPass) 'MS.AAD.1.1v1')['Status'] | Should -Be $script:St.Met
        }

        It 'an Equivalent check with a Gap or Partial is a tool-verified shortfall' {
            (Row (View (AllPassExcept @{ 'AAD-1.1' = 'Gap' })) 'MS.AAD.1.1v1')['Status'] | Should -Be $script:St.Shortfall
            (Row (View (AllPassExcept @{ 'AAD-1.2' = 'Partial' })) 'MS.AAD.3.2v2')['Status'] | Should -Be $script:St.Shortfall
        }

        It 'a known shortfall on one instance is not hidden by an Error on another' {
            $f = @(F 'AAD-1.1' 'Error' 'boom' 'one'; F 'AAD-1.1' 'Gap' 'open' 'two')
            (Row (View $f) 'MS.AAD.1.1v1')['Status'] | Should -Be $script:St.Shortfall
        }

        It 'only Partial-relation checks is partly checked, and names what the tool does not check' {
            $r = Row (View $script:AllPass) 'MS.AAD.2.1v1'
            $r['Status'] | Should -Be $script:St.Partly
            ($r['NotChecked'] -join ' ') | Should -Match 'AAD-1\.5 covers part of the rule'
        }

        It 'an Equivalent check with no verdict beside a passing one is partly checked, never met' {
            $r = Row (View (AllPassExcept @{ 'TMS-4.3' = 'NotApplicable' })) 'MS.TEAMS.2.1v2'
            $r['Status'] | Should -Be $script:St.Partly
            ($r['NotChecked'] -join ' ') | Should -Match 'TMS-4\.3 checks the same requirement but produced no verdict'
        }

        It 'citing checks that produced no verdict, an Error, or no finding at all leave the policy not assessed' {
            (Row (View (AllPassExcept @{ 'AAD-1.5' = 'Error' })) 'MS.AAD.2.1v1')['Status'] | Should -Be $script:St.NotAssessed
            (Row (View (AllPassExcept @{ 'AAD-1.5' = 'NotApplicable' })) 'MS.AAD.2.1v1')['Status'] | Should -Be $script:St.NotAssessed
            $none = View @()
            $none.Summary.ByStatus[$script:St.NotAssessed] | Should -Be $none.Summary.Mapped
            $none.Summary.ByStatus[$script:St.Met] | Should -Be 0
        }

        It 'a met policy still names a related check that reports a shortfall' {
            $r = Row (View (AllPassExcept @{ 'EXO-7.4' = 'Gap' })) 'MS.EXO.5.1v1'
            $r['Status'] | Should -Be $script:St.Met
            @($r['RelatedShortfalls']) | Should -Contain 'EXO-7.4 (Gap)'
        }

        It 'a product this tool does not read is product not assessed, whatever the findings say' {
            $cfg = Join-Path $script:Tmp 'bod-powerbi.json'
            @{
                framework = 'test'; source = @('https://www.cisa.gov/x'); sourceRetrieved = '2026-10-27'
                products = @(@{ Key = 'powerbi'; Name = 'Power BI'; AssessedByTool = $false }, @{ Key = 'aad'; Name = 'Entra ID'; AssessedByTool = $true })
                policies = @(
                    @{ PolicyId = 'MS.POWERBI.1.1v1'; Product = 'powerbi'; Criticality = 'SHALL'; Statement = 'x SHALL y.' },
                    @{ PolicyId = 'MS.AAD.1.1v1'; Product = 'aad'; Criticality = 'SHALL'; Statement = 'Legacy authentication SHALL be blocked.' }
                )
            } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $cfg -Encoding utf8
            $v = View $script:AllPass -Config $cfg
            (Row $v 'MS.POWERBI.1.1v1')['Status'] | Should -Be $script:St.ProductNotAssessed
            (Row $v 'MS.AAD.1.1v1')['Status'] | Should -Be $script:St.Met
            @($v.Summary.ProductsNotAssessed) | Should -Contain 'Power BI'
        }

        It 'no status states that a requirement is fulfilled' {
            foreach ($s in @($script:St.Values)) { $s | Should -Not -Match '(?i)complian|fulfil|satisf' }
        }

        It 'is a view: it changes no finding' {
            $f = @(F 'AAD-1.1' 'Gap' 'detail kept')
            $before = $f | ConvertTo-Json -Depth 5
            $null = View $f
            ($f | ConvertTo-Json -Depth 5) | Should -Be $before
        }

        It 'fails closed when the catalog is missing' {
            $v = View $script:AllPass -Config (Join-Path $script:Tmp 'absent.json')
            $v.Available | Should -BeFalse
        }
    }

    Context 'ScubaGear side by side' {

        It 'flags a policy where the tool and ScubaGear point in opposite directions, in either direction' {
            $v = View $script:AllPass -Scuba @{ 'MS.AAD.1.1v1' = 'Fail'; 'MS.AAD.5.1v1' = 'Pass' }
            (Row $v 'MS.AAD.1.1v1')['ResultsDiffer'] | Should -BeTrue
            (Row $v 'MS.AAD.1.1v1')['IndependentResult'] | Should -Be 'Fail'
            (Row $v 'MS.AAD.5.1v1')['ResultsDiffer'] | Should -BeFalse
            $v.Summary.Differ | Should -Be 1
            # The tool's status is not changed by the independent result.
            (Row $v 'MS.AAD.1.1v1')['Status'] | Should -Be $script:St.Met
            $g = View (AllPassExcept @{ 'AAD-1.2' = 'Gap' }) -Scuba @{ 'MS.AAD.3.2v2' = 'Pass' }
            (Row $g 'MS.AAD.3.2v2')['ResultsDiffer'] | Should -BeTrue
        }

        It 'does not flag a policy the tool did not judge' {
            $v = View @() -Scuba @{ 'MS.AAD.6.1v1' = 'Fail'; 'MS.AAD.1.1v1' = 'Fail' }
            (Row $v 'MS.AAD.6.1v1')['ResultsDiffer'] | Should -BeFalse
            (Row $v 'MS.AAD.1.1v1')['ResultsDiffer'] | Should -BeFalse
            (Row $v 'MS.AAD.6.1v1')['IndependentResult'] | Should -Be 'Fail'
        }

        It 'reads a ScubaGear results CSV, and an unreadable one costs the comparison only' {
            $csv = Join-Path $script:Tmp 'ScubaResults.csv'
            "Control ID,Result`nMS.AAD.1.1v1,Fail`nMS.EXO.5.1v1,Pass" | Set-Content -LiteralPath $csv -Encoding utf8
            $v = View $script:AllPass -ScubaPath $csv
            $v.IndependentSupplied | Should -BeTrue
            (Row $v 'MS.AAD.1.1v1')['ResultsDiffer'] | Should -BeTrue
            $bad = Join-Path $script:Tmp 'not-scuba.csv'
            "a,b`n1,2" | Set-Content -LiteralPath $bad -Encoding utf8
            $w = View $script:AllPass -ScubaPath $bad
            $w.Available | Should -BeTrue
            $w.IndependentSupplied | Should -BeFalse
            $w.IndependentError | Should -Not -BeNullOrEmpty
        }
    }

    Context 'Published Markdown and HTML' {

        BeforeAll {
            $hostile = '<script>alert(1)</script> [click](https://evil.example/x) ![i](https://evil.example/i.png) `code` | pipe'
            $f = AllPassExcept @{ 'AAD-1.1' = 'Gap' }
            $f += F 'AAD-1.1' 'Gap' $hostile 'second'
            $v = View $f -Scuba @{ 'MS.EXO.5.1v1' = 'Fail' }
            $script:Md = Join-Path $script:Tmp 'bod.md'
            Publish-TPBod2501View -View $v -OutputPath $script:Md -Metadata @{ TenantDomain = 'contoso<b>.example'; AssessmentDate = '2026-10-27' }
            $script:MdText = Get-Content -LiteralPath $script:Md -Raw
            $script:HtmlText = Get-Content -LiteralPath ([IO.Path]::ChangeExtension($script:Md, '.html')) -Raw
        }

        It 'says on page one: technical readiness view, not an attestation; FCEB; ScubaGear is what CISA expects; counts per status' {
            foreach ($t in @($script:MdText, $script:HtmlText)) {
                $t | Should -Match 'technical readiness view, not an attestation'
                $t | Should -Match 'federal civilian executive branch'
                $t | Should -Match 'ScubaGear is CISA'
                $t | Should -Match 'what CISA expects'
                foreach ($s in @($script:St.Values)) { $t | Should -Match ([regex]::Escape((ConvertTo-TPHtmlSafe $s))) }
            }
            $script:MdText | Should -Match 'Policies: 56\.'
        }

        It 'lists every required policy' {
            foreach ($p in $script:Policies) { $script:HtmlText | Should -Match ([regex]::Escape($p.PolicyId)) }
        }

        It 'flags the ScubaGear disagreement for review' {
            $script:HtmlText | Should -Match ([regex]::Escape($script:Differ))
            $script:MdText | Should -Match ([regex]::Escape($script:Differ))
        }

        It 'never calls the tenant compliant' {
            $script:MdText   | Should -Not -Match '(?i)\bcompliant\b|\bcompliance\b'
            $script:HtmlText | Should -Not -Match '(?i)\bcompliant\b|\bcompliance\b'
        }

        It 'escapes tenant text in the HTML and runs no script' {
            $script:HtmlText | Should -Not -Match '<script'
            $script:HtmlText | Should -Match '&lt;script&gt;'
            $script:HtmlText | Should -Not -Match '<b>\.example'
            $script:HtmlText | Should -Match "default-src 'none'"
        }

        It 'escapes Markdown link, image, code and table syntax from tenant text' {
            $script:MdText | Should -Not -Match '<script>'
            $script:MdText | Should -Not -Match '(?<!\\)\[click\]\('
            $script:MdText | Should -Not -Match '(?<!\\)!\[i\]'
            $script:MdText | Should -Match '\\\|'
        }
    }

    Context 'Entry point' {

        It 'has a -BOD2501 switch that -AllFiles implies, and passes -ScubaResultsPath to the view' {
            $src = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-TPAssessment.ps1') -Raw
            $src | Should -Match '\[switch\] \$BOD2501'
            $src | Should -Match ([regex]::Escape('if (($BOD2501 -or $AllFiles)'))
            $src | Should -Match ([regex]::Escape('$bodArgs.ScubaResultsPath = $ScubaResultsPath'))
        }

        It 'writes the view from a saved results file with -FromResults' {
            $mods = Join-Path $script:Tmp 'mods'
            $exoVersion = [string](& $script:Mod { Get-TPExoModuleFloor }).Min
            foreach ($m in @(
                    @{ N = 'Microsoft.Graph.Authentication'; V = '2.40.0'; G = 'b0b0b0b0-1111-4222-8333-444444444444' },
                    @{ N = 'ExchangeOnlineManagement'; V = $exoVersion; G = 'c0c0c0c0-1111-4222-8333-555555555555' },
                    @{ N = 'MicrosoftTeams'; V = '5.9.0'; G = 'd0d0d0d0-1111-4222-8333-666666666666' })) {
                $dir = Join-Path $mods $m.N $m.V
                $null = New-Item -ItemType Directory -Path $dir -Force
                Set-Content -LiteralPath (Join-Path $dir "$($m.N).psd1") -Encoding utf8 -Value "@{ RootModule = '$($m.N).psm1'; ModuleVersion = '$($m.V)'; GUID = '$($m.G)'; FunctionsToExport = '*'; CmdletsToExport = @(); AliasesToExport = @() }"
                Set-Content -LiteralPath (Join-Path $dir "$($m.N).psm1") -Encoding utf8 -Value '# stand-in: -FromResults signs in to nothing'
            }
            $results = Join-Path $script:Tmp 'saved-results.json'
            [ordered]@{
                Metadata = [ordered]@{ TenantDomain = 'contoso.onmicrosoft.com'; AssessmentDate = '2026-10-27'; ToolVersion = '4.14.3' }
                Findings = @(
                    [ordered]@{ ControlId = 'AAD-1.1'; State = 'Satisfied'; Severity = 'High'; Category = 'Identity'; Title = 'Legacy Authentication Blocked'; Detail = 'blocked'; FrameworkIds = '' },
                    [ordered]@{ ControlId = 'AAD-1.2'; State = 'Gap'; Severity = 'High'; Category = 'Identity'; Title = 'MFA Required for All Users'; Detail = 'not enforced'; FrameworkIds = '' }
                )
            } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $results -Encoding utf8
            $out = Join-Path $script:Tmp 'republish'
            $old = $env:PSModulePath
            try {
                $env:PSModulePath = $mods + [IO.Path]::PathSeparator + $env:PSModulePath
                $cmd = "& '$(Join-Path $script:Root 'Invoke-TPAssessment.ps1')' -FromResults '$results' -NonInteractive -BOD2501 -SkipReportSite -OutputPath '$out'; exit `$LASTEXITCODE"
                $text = (& pwsh -NoProfile -NonInteractive -Command $cmd *>&1 | Out-String)
            } finally { $env:PSModulePath = $old }
            $text | Should -Not -Match 'BOD 25-01 view publish failed' -Because $text
            $md = @(Get-ChildItem -LiteralPath $out -Filter '*-bod-25-01.md' -ErrorAction SilentlyContinue)
            $md.Count | Should -Be 1 -Because $text
            @(Get-ChildItem -LiteralPath $out -Filter '*-bod-25-01.html' -ErrorAction SilentlyContinue).Count | Should -Be 1
            $body = Get-Content -LiteralPath $md[0].FullName -Raw
            $body | Should -Match 'MS\.AAD\.1\.1v1'
            $body | Should -Match ([regex]::Escape("1 $($script:St.Met)"))
            $body | Should -Match ([regex]::Escape("1 $($script:St.Shortfall)"))
        }
    }
}
