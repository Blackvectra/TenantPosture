#Requires -Version 7.0
#
# TP.FleetDashboard.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Guards New-TPFleetDashboard.ps1, Lib/Get-TPFleetModel.ps1 and
# Publishers/Publish-TPFleetDashboard.ps1: the offline fleet view across every
# client's saved runs. Fixtures are results files written the way the entry
# point writes them, in both output layouts, read back by the real code:
#   - runs of one tenant in a tenant folder and in the flat layout are one client
#   - a partial (-ControlId) or quick run never replaces the full-run score
#   - the score is the one the run recorded, never recomputed
#   - an active client with no run is "never assessed"; an inactive one is not listed
#   - Current / Aging / Overdue come from the baseline's own freshness classes
#   - change since the previous full run comes from Get-TPBaselineRegressions,
#     with the tool-version and catalog differences stated
#   - an incident-response output is never read
#   - -Anonymize leaves no client name, domain or tenant id in any file or name
#   - nothing connects anywhere (static, over the AST and tokens, and mocked)
# Data keys consumed: none live. Graph scopes / cmdlets: none.

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    $script:Mod = Get-Module TenantPosture
    . (Join-Path $script:RepoRoot 'Testing' 'TP.MspFixtures.ps1')

    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('tp-fleet-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    $script:Root = Join-Path $script:Tmp 'output'
    $null = [IO.Directory]::CreateDirectory($script:Root)
    $script:Now = [datetime]::new(2030, 6, 15, 12, 0, 0, [DateTimeKind]::Utc)
    $now = $script:Now
    $ids = @{
        contoso   = 'aaaaaaaa-1111-4111-8111-000000000001'; fabrikam = 'bbbbbbbb-2222-4222-8222-000000000002'
        northwind = 'cccccccc-3333-4333-8333-000000000003'; tailspin = 'eeeeeeee-5555-4555-8555-000000000005'
        wingtip   = 'ffffffff-6666-4666-8666-000000000006'
    }
    $script:Ids = $ids
    $f1 = @(@('AAD-1.1', 'Gap', 'High'), @('AAD-1.2', 'Satisfied', 'Critical'), @('EXO-1.6', 'Partial', 'High'), @('DNS-1.1', 'Gap', 'Medium'))
    $f2 = @(@('AAD-1.1', 'Satisfied', 'High'), @('AAD-1.2', 'Gap', 'Critical'), @('EXO-1.6', 'Partial', 'High'), @('DNS-1.1', 'Gap', 'Medium'), @('SPO-1.1', 'Gap', 'High'))
    $b1 = @(@('AAD-1.1', 'Failed'), @('AAD-1.2', 'Satisfied'), @('EXO-1.6', 'Failed'))
    $b2 = @(@('AAD-1.1', 'Satisfied'), @('AAD-1.2', 'Failed'), @('EXO-1.6', 'Failed', 'Minimum', 'Monthly'))
    $w = { param($o, $rel) Write-TPMspFixture -Object $o -Path (Join-Path $script:Root $rel) | Out-Null }

    & $w (New-TPMspFixtureResults -TenantId $ids.contoso -Time $now.AddDays(-70) -Findings $f1 -Score 52 -Label 'Developing' -BaselineRows $b1 -ToolVersion '4.14.2') 'contoso.example/contoso-20300406-120000-results.json'
    & $w (New-TPMspFixtureResults -TenantId $ids.contoso -Time $now.AddDays(-40) -Findings $f1 -Score 58 -Label 'Developing' -BaselineRows $b1 -ToolVersion '4.14.2') 'contoso.example/contoso-20300506-120000-results.json'
    # Recorded score 66 although these findings would compute differently: the recorded value is shown.
    & $w (New-TPMspFixtureResults -TenantId $ids.contoso -Time $now.AddDays(-3) -Findings $f2 -Score 66 -Label 'Defined (provisional: evidence incomplete)' -BaselineRows $b2) 'contoso.example/contoso-20300612-120000-results.json'
    & $w (New-TPMspFixtureResults -TenantId $ids.contoso -Time $now.AddDays(-1) -Findings @(, @('AAD-1.2', 'Satisfied', 'Critical')) -Score 100 -Label 'Optimizing (provisional: partial run, 1 of 253 controls)' -SelectedControlIds @('AAD-1.2') -Include @('AAD-1.2') -BaselineRows $b2) 'contoso.example/contoso-20300614-120000-results.json'
    & $w ([ordered]@{ Metadata = @{ TenantDomain = 'contoso.example'; TenantId = $ids.contoso }; DeepDives = @(@{ User = 'victim@contoso.example' }); Findings = @() }) 'contoso.example/victim-email-results.json'

    # Fabrikam: one run in a tenant folder, the newer in the flat layout (initial domain).
    & $w (New-TPMspFixtureResults -Domain 'fabrikam.example' -TenantId $ids.fabrikam -Time $now.AddDays(-60) -Findings $f1 -Score 40 -Label 'Developing' -BaselineRows $b1) 'fabrikam.example/fabrikam-a-results.json'
    & $w (New-TPMspFixtureResults -Domain 'fabrikam.onmicrosoft.com' -TenantId $ids.fabrikam -Time $now.AddDays(-50) -Findings @(@('AAD-1.1', 'Gap', 'High'), @('AAD-1.2', 'Gap', 'Critical')) -Score 31 -Label 'Initial' -BaselineRows $b1 -EvidencePercent 61) 'fabrikam-20300426-120000-results.json'

    # Northwind: aging, with a newer quick scan.
    & $w (New-TPMspFixtureResults -Domain 'northwind.example' -TenantId $ids.northwind -Time $now.AddDays(-20) -Findings @(@('AAD-1.1', 'Satisfied', 'High'), @('DNS-1.1', 'Gap', 'Medium')) -Score 88 -Label 'Managed' -BaselineRows $b2 -EvidencePercent 92) 'northwind.example/northwind-a-results.json'
    & $w (New-TPMspFixtureResults -Domain 'northwind.example' -TenantId $ids.northwind -Time $now.AddDays(-5) -Findings @(, @('AAD-1.1', 'Satisfied', 'High')) -Score 100 -Label 'Optimizing' -Quick -BaselineRows $b2) 'northwind.example/northwind-b-results.json'

    # Tailspin: only a partial run, and not in the clients file.
    & $w (New-TPMspFixtureResults -Domain 'tailspin.example' -TenantId $ids.tailspin -Time $now.AddDays(-2) -Findings @(, @('EXO-1.6', 'Gap', 'High')) -SelectedControlIds @('EXO-1.6') -Include @('EXO-1.6') -BaselineRows $b2) 'tailspin.example/tailspin-a-results.json'

    # Wingtip: a full run with no TenantId and no maturity recorded.
    & $w (New-TPMspFixtureResults -Domain 'wingtip.example' -TenantId '' -Time $now.AddDays(-2) -Findings @(, @('AAD-1.1', 'Gap', 'High')) -NoMaturity -NoBaseline) 'wingtip.example/wingtip-a-results.json'

    $script:Clients = Join-Path $script:Tmp 'clients.json'
    @{ clients = @(
        @{ ClientName = 'Contoso Ltd'; TenantDomain = 'contoso.example'; TenantId = $ids.contoso; DelegatedOrg = 'contoso.onmicrosoft.com'; Active = $true }
        @{ ClientName = 'Fabrikam Inc'; TenantDomain = 'fabrikam.example'; TenantId = $ids.fabrikam; DelegatedOrg = 'fabrikam.onmicrosoft.com'; Active = $true }
        @{ ClientName = '=HYPERLINK("x")<b>Northwind</b>'; TenantDomain = 'northwind.example'; TenantId = $ids.northwind; DelegatedOrg = 'northwind.onmicrosoft.com'; Active = $true }
        @{ ClientName = 'Wingtip Toys'; TenantDomain = 'wingtip.example'; TenantId = $ids.wingtip; DelegatedOrg = 'wingtip.onmicrosoft.com'; Active = $true }
        @{ ClientName = 'Adatum Corp'; TenantDomain = 'adatum.example'; TenantId = 'dddddddd-4444-4444-8444-000000000004'; DelegatedOrg = 'adatum.onmicrosoft.com'; Active = $true }
        @{ ClientName = 'Litware Inactive'; TenantDomain = 'litware.example'; TenantId = '00000000-0000-0000-0000-000000000000'; DelegatedOrg = 'litware.onmicrosoft.com'; Active = $false }
    ) } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:Clients -Encoding utf8

    $script:Model = Get-TPFleetModel -OutputRoot $script:Root -ClientsFile $script:Clients -Now $script:Now
    $script:Row = { param([string] $Name) @($script:Model.Clients | Where-Object { $_.Name -like "*$Name*" })[0] }
    $script:Out = Join-Path $script:Tmp 'fleet'
    $script:Files = Publish-TPFleetDashboard -Model $script:Model -OutputPath $script:Out -GeneratedAt $script:Now
    $script:AnonModel = Get-TPFleetModel -OutputRoot $script:Root -ClientsFile $script:Clients -Now $script:Now -Anonymize
    $script:AnonOut = Join-Path $script:Tmp 'fleet-anon'
    $script:AnonFiles = Publish-TPFleetDashboard -Model $script:AnonModel -OutputPath $script:AnonOut -GeneratedAt $script:Now
    $script:Read = { param($files) ($files.Values | ForEach-Object { Get-Content -LiteralPath $_ -Raw }) -join "`n" }

    $script:CodeOf = {
        param([string] $Path)
        $tokens = $null; $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
        [pscustomobject]@{
            Errors   = @($errs).Count
            Code     = (@($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' ')
            Commands = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        }
    }
}

AfterAll {
    if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue
}

Describe 'Fleet model: runs and clients' {
    It 'groups a tenant''s runs from both layouts into one client, by tenant id' {
        $fab = & $script:Row 'Fabrikam'
        $fab.RunCount | Should -Be 2
        $fab.FullRunCount | Should -Be 2
        $fab.LatestFull.Score | Should -Be 31 -Because 'the newer (flat-layout) run is the latest'
        @($script:Model.Clients | Where-Object { $_.Name -match 'fabrikam' }).Count | Should -Be 1
    }
    It 'never reads an incident-response output' {
        (& $script:Row 'Contoso').RunCount | Should -Be 4
        $script:Model.RunsRead | Should -Be 10
    }
    It 'shows the score the run recorded, never a recomputed one' {
        $c = & $script:Row 'Contoso'
        $c.LatestFull.Score | Should -Be 66
        $c.LatestFull.MaturityLabel | Should -Be 'Defined (provisional: evidence incomplete)'
    }
    It 'a partial re-check never replaces the full-run score, and is shown beside it' {
        $c = & $script:Row 'Contoso'
        $c.LatestFull.Score | Should -Be 66 -Because 'the newer partial run recorded 100 for one control'
        $c.Recheck.Kind | Should -Be 'Partial'
        $c.Recheck.Selected | Should -Be 1
        $c.Recheck.Satisfied | Should -Be 1
        @($c.Recheck.Patterns) | Should -Be @('AAD-1.2')
        @($c.Trend | ForEach-Object { $_.Score }) | Should -Be @(52, 58, 66) -Because 'the trend is over full runs only'
    }
    It 'a quick scan is a re-check too, never the score' {
        $n = & $script:Row 'Northwind'
        $n.LatestFull.Score | Should -Be 88
        $n.Recheck.Kind | Should -Be 'Quick'
    }
    It 'a client with only partial runs has no score at all' {
        $t = & $script:Row 'tailspin'
        $t.Status | Should -Be 'NoFullRun'
        $t.LatestFull | Should -BeNullOrEmpty
        $t.Recheck.Kind | Should -Be 'Partial'
        ($t.Notes -join ' ') | Should -Match 'Not in the clients file'
    }
    It 'a run with no TenantId joins its client by domain, and an unrecorded score says so' {
        $wt = & $script:Row 'Wingtip'
        $wt.LatestFull.Score | Should -BeNullOrEmpty
        $wt.LatestFull.MaturityRecorded | Should -BeFalse
        ($wt.Notes -join ' ') | Should -Match 'recorded no score'
    }
    It 'an active client with no run is never assessed; an inactive one is not listed' {
        @($script:Model.NeverAssessed | ForEach-Object { $_.Name }) | Should -Be @('Adatum Corp')
        ($script:Model.Clients.Name + $script:Model.NeverAssessed.Name) | Should -Not -Contain 'Litware Inactive'
    }
}

Describe 'Fleet model: freshness from the baseline''s own classes' {
    It 'Current within the Weekly window, Aging within the Monthly window, Overdue beyond it' {
        $json = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/tp-baseline.json') -Raw | ConvertFrom-Json
        $script:Model.Freshness.CurrentDays | Should -Be $json.freshnessWindowsDays.Weekly
        $script:Model.Freshness.OverdueDays | Should -Be $json.freshnessWindowsDays.Monthly
        $script:Model.Freshness.Basis | Should -Match 'Weekly window'
        (& $script:Row 'Contoso').Status | Should -Be 'Current'
        (& $script:Row 'Northwind').Status | Should -Be 'Aging'
        (& $script:Row 'Fabrikam').Status | Should -Be 'Overdue'
    }
    It 'counts the required rows whose evidence is past its own window' {
        $n = & $script:Row 'Northwind'
        $n.LatestFull.RequiredRows | Should -Be 3
        $n.LatestFull.PastWindow | Should -Be 2 -Because 'two Weekly rows are past 8 days at 20 days; the Monthly row is not'
    }
    It 'fleet KPIs add up' {
        $k = $script:Model.Kpis
        $k.Clients | Should -Be 6
        $k.NeverAssessed | Should -Be 1
        $k.Overdue | Should -Be 1
        $k.InWindow | Should -Be 3
        $k.NoFullRun | Should -Be 1
        $k.OpenCritical | Should -Be 2
    }
    It 'lists the most common open gaps by number of clients' {
        $top = @($script:Model.TopGaps)
        $top[0].ControlId | Should -Be 'AAD-1.1' -Because 'open in Fabrikam and Wingtip'
        $top[0].Clients | Should -Be 2
        $top.Count | Should -BeLessOrEqual 10
    }
}

Describe 'Fleet model: change since the previous full run' {
    It 'reads regressions and resolutions from Get-TPBaselineRegressions' {
        $ch = (& $script:Row 'Contoso').Change
        $ch.Available | Should -BeTrue
        @($ch.Regressed) | Should -Be @('AAD-1.2')
        @($ch.Resolved) | Should -Be @('AAD-1.1')
        $ch.PreviousRunDate | Should -Be '2030-05-06'
    }
    It 'says when the runs were made by different tool versions and when the catalog differs' {
        $c = & $script:Row 'Contoso'
        $c.Change.ToolVersionChanged | Should -BeTrue
        ($c.Notes -join ' ') | Should -Match 'Compared across tool versions \(4\.14\.2 to 4\.14\.3\)'
        $c.Change.ControlsAdded | Should -Be 1
        ($c.Notes -join ' ') | Should -Match 'control catalog differs'
    }
    It 'uses the regression function rather than its own comparison' {
        (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Get-TPFleetModel.ps1') -Raw) | Should -Match 'Get-TPBaselineRegressions -Current'
    }
}

Describe 'Fleet dashboard: outputs' {
    It 'writes HTML, Markdown and CSV named fleet-dashboard-<time>' {
        foreach ($p in $script:Files.Values) { Test-Path -LiteralPath $p | Should -BeTrue; (Split-Path -Leaf $p) | Should -Match '^fleet-dashboard-20300615-120000\.(html|md|csv)$' }
    }
    It 'the HTML is self-contained and uses the shared theme' {
        $html = Get-Content -LiteralPath $script:Files.Html -Raw
        $html | Should -Match "default-src 'none'"
        $html | Should -Not -Match '(?i)<script|<link|(https?:)?//[a-z0-9]'
        $html | Should -Match 'tp-masthead'
        $html | Should -Match 'Partial re-check'
    }
    It 'escapes a hostile client name in every format and neutralizes it in the CSV' {
        $html = Get-Content -LiteralPath $script:Files.Html -Raw
        $html | Should -Not -Match '<b>Northwind'
        $html | Should -Match '&lt;b&gt;Northwind'
        (Get-Content -LiteralPath $script:Files.Markdown -Raw) | Should -Not -Match '<b>Northwind'
        $rows = Import-Csv -LiteralPath $script:Files.Csv
        @($rows).Count | Should -Be 6
        @($rows | Where-Object { $_.Client -like '*Northwind*' })[0].Client | Should -Match "^'="
    }
    It 'never prints a tenant id, the operator, a finding detail or raw data' {
        $all = & $script:Read $script:Files
        foreach ($id in $script:Ids.Values) { $all | Should -Not -Match ([regex]::Escape($id)) }
        $all | Should -Not -Match 'operator@msp\.example|alice@|rawdata-marker|exception-marker|victim@'
    }
    It 'never says compliant' {
        (& $script:Read $script:Files) | Should -Not -Match '(?i)\bcompliant\b|\bcompliance\b'
    }
}

Describe 'Fleet dashboard: -Anonymize' {
    It 'labels clients Client A, B, ... and leaves no name, domain or tenant id anywhere' {
        @($script:AnonModel.Clients | ForEach-Object { $_.Name }) | Should -Be @('Client A', 'Client B', 'Client C', 'Client D', 'Client E')
        $script:AnonModel.NeverAssessed[0].Name | Should -Be 'Client F'
        $all = (& $script:Read $script:AnonFiles) + ($script:AnonFiles.Values -join ' ') + ($script:AnonModel | ConvertTo-Json -Depth 12)
        foreach ($n in 'contoso', 'fabrikam', 'northwind', 'tailspin', 'wingtip', 'adatum', 'litware', 'Hyperlink') {
            $all.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) | Should -Be -1 -Because "anonymized output must not carry '$n'"
        }
        foreach ($id in $script:Ids.Values) { $all | Should -Not -Match ([regex]::Escape($id)) }
        (Split-Path -Leaf $script:AnonFiles.Html) | Should -Match '-anonymized\.html$'
    }
}

Describe 'Fleet dashboard: it connects to nothing' {
    It 'makes no network, tenant or sign-in call when it runs' {
        Mock -ModuleName 'TenantPosture' Invoke-RestMethod -MockWith { throw 'network' }
        Mock -ModuleName 'TenantPosture' Invoke-WebRequest -MockWith { throw 'network' }
        Mock -ModuleName 'TenantPosture' Invoke-TPGraphRequest -MockWith { throw 'graph' }
        Mock -ModuleName 'TenantPosture' Resolve-TPDns -MockWith { throw 'dns' }
        Mock -ModuleName 'TenantPosture' Connect-TPServices -MockWith { throw 'sign-in' }
        $m = Get-TPFleetModel -OutputRoot $script:Root -ClientsFile $script:Clients -Now $script:Now
        $null = Publish-TPFleetDashboard -Model $m -OutputPath (Join-Path $script:Tmp 'nonet') -GeneratedAt $script:Now
        foreach ($cmd in 'Invoke-RestMethod', 'Invoke-WebRequest', 'Invoke-TPGraphRequest', 'Resolve-TPDns', 'Connect-TPServices') {
            Should -Invoke -ModuleName 'TenantPosture' -CommandName $cmd -Times 0 -Exactly
        }
    }
    It '<File> makes no tenant, network or module-state call' -ForEach @(
        @{ File = 'Lib/Get-TPFleetModel.ps1' }
        @{ File = 'Lib/Read-TPRunRecord.ps1' }
        @{ File = 'Publishers/Publish-TPFleetDashboard.ps1' }
        @{ File = 'New-TPFleetDashboard.ps1' }
    ) {
        $src = & $script:CodeOf (Join-Path $script:RepoRoot $File)
        $src.Errors | Should -Be 0
        $forbidden = '^Connect-', '^Disconnect-', '^Invoke-(RestMethod|WebRequest|TPGraphRequest|TPGraphAllPages|Expression|Command)$',
            '^Resolve-(TPDns|DnsName|TPTenantId)$', '^Test-(Connection|NetConnection)$', '^Start-(Process|Job|ThreadJob)$',
            '^Get-Mg', '^Send-MailMessage$', '^(Get|Set)-TP(RawData|Findings|Coverage)$', '^Add-TPFinding$',
            '^Register-TP(Coverage|Exception)$', '^Clear-TPState$'
        foreach ($cmd in $src.Commands) { foreach ($f in $forbidden) { $cmd | Should -Not -Match $f -Because "$File must not call $cmd" } }
        foreach ($t in 'System\.Net\.Http', 'HttpClient', 'WebClient', 'System\.Net\.Sockets', 'graph\.microsoft', 'login\.microsoftonline', 'https?://') {
            $src.Code | Should -Not -Match $t -Because "$File must not reference $t"
        }
    }
    It 'the public functions are exported from both lists' {
        foreach ($fn in 'Get-TPFleetModel', 'Publish-TPFleetDashboard', 'Read-TPRunRecord', 'Get-TPReportTheme') {
            (Get-Command $fn -Module 'TenantPosture' -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
            @((Import-PowerShellDataFile (Join-Path $script:RepoRoot 'TenantPosture.psd1')).FunctionsToExport) | Should -Contain $fn
        }
    }
}

Describe 'Fleet dashboard: the entry point' {
    BeforeAll {
        $script:Script = Join-Path $script:RepoRoot 'New-TPFleetDashboard.ps1'
        $script:Run = {
            param([string[]] $Arguments)
            $text = & (Get-Process -Id $PID).Path -NoProfile -File $script:Script @Arguments *>&1 | Out-String
            [pscustomobject]@{ Code = $LASTEXITCODE; Text = $text }
        }
        $script:EntryRoot = Join-Path $script:Tmp 'entry-output'
        $t = [datetime]::UtcNow
        Write-TPMspFixture -Object (New-TPMspFixtureResults -Domain 'contoso.example' -Time $t.AddDays(-2) -Findings @(@('AAD-1.1', 'Gap', 'High'), @('AAD-1.2', 'Satisfied', 'Critical')) -BaselineRows @(, @('AAD-1.1', 'Failed'))) -Path (Join-Path $script:EntryRoot 'contoso.example/contoso-a-results.json') | Out-Null
    }
    It 'writes three files and exits 0, saying it connected to nothing' {
        $out = Join-Path $script:Tmp 'entry-out'
        $r = & $script:Run @('-OutputRoot', $script:EntryRoot, '-ClientsFile', $script:Clients, '-OutPath', $out)
        $r.Code | Should -Be 0 -Because $r.Text
        @(Get-ChildItem -LiteralPath $out).Count | Should -Be 3
        $r.Text | Should -Match 'This script connected to nothing'
        $r.Text | Should -Match 'never assessed'
    }
    It 'exits 2 and writes nothing when there are no runs' {
        $empty = Join-Path $script:Tmp 'empty-output'; $null = [IO.Directory]::CreateDirectory($empty)
        $out = Join-Path $script:Tmp 'entry-empty-out'
        $r = & $script:Run @('-OutputRoot', $empty, '-OutPath', $out)
        $r.Code | Should -Be 2
        Test-Path -LiteralPath $out | Should -BeFalse
    }
    It 'exits 4 when a named clients file is missing' {
        $r = & $script:Run @('-OutputRoot', $script:EntryRoot, '-ClientsFile', (Join-Path $script:Tmp 'nope.json'), '-OutPath', (Join-Path $script:Tmp 'x'))
        $r.Code | Should -Be 4
    }
    It 'with -Anonymize the console and the files carry no client name' {
        $out = Join-Path $script:Tmp 'entry-anon'
        $r = & $script:Run @('-OutputRoot', $script:EntryRoot, '-ClientsFile', $script:Clients, '-OutPath', $out, '-Anonymize')
        $r.Code | Should -Be 0
        $all = $r.Text + ((Get-ChildItem -LiteralPath $out | ForEach-Object { $_.Name + (Get-Content -LiteralPath $_.FullName -Raw) }) -join "`n")
        foreach ($n in 'contoso', 'adatum') { $all.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) | Should -Be -1 }
    }
    It 'declares nothing that signs in' {
        $params = (Get-Command $script:Script).Parameters
        foreach ($p in 'OutputRoot', 'ClientsFile', 'OutPath', 'Anonymize') { $params.ContainsKey($p) | Should -BeTrue }
        @($params.Keys | Where-Object { $_ -match 'Tenant(Domain|Id)$|Credential|Certificate|AppId|UserPrincipalName' }) | Should -BeNullOrEmpty
    }
}
