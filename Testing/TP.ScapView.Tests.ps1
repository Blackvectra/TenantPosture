#Requires -Version 7.0
#
# TP.ScapView.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Guards the SCAP results view (Lib/Get-TPScapView.ps1,
# Publishers/Publish-TPScapView.ps1, New-TPScapView.ps1, -ScapResults):
#   - XCCDF 1.2 (DISA SCC shape), XCCDF 1.1 and OpenSCAP ARF all read alike
#   - a rule fails when any current host fails it, is met only when every
#     host that checked it passed, and error / unknown / notchecked are never
#     a pass
#   - the newest result per host wins and the older one is listed as superseded
#   - a result older than -MaxAgeDays is not current and not counted
#   - a DTD (XXE), malformed XML or a non-XCCDF file is skipped with the reason
#   - no IP address or user name from the target facts reaches the model
#   - page one says imported, not verified, hosts in the files only, not a
#     compliance determination; every string is escaped; nothing loads
#   - the standalone script connects to nothing and writes the view
# Data: writes only under a temporary folder. Network: none.

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('tp-scap-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    $script:In = Join-Path $script:Tmp 'in'
    $null = New-Item -ItemType Directory -Force -Path $script:In
    $script:Now = [datetime]'2026-10-30T12:00:00Z'
    $script:Bench = 'xccdf_mil.disa.stig_benchmark_Windows_11_STIG'
    $script:Hostile = '<img src=x onerror=alert(1)> [click](https://evil.example) `code`'

    $rule = {
        param([string] $Id, [string] $Sev, [string] $Vid, [string] $Title)
        "<cdf:Rule id=""$Id"" severity=""$Sev""><cdf:title>$([System.Security.SecurityElement]::Escape($Title))</cdf:title><cdf:ident system=""http://cyber.mil/legacy"">$Vid</cdf:ident></cdf:Rule>"
    }
    $rules = (& $rule 'R1' 'high' 'V-1001' $script:Hostile) + (& $rule 'R2' 'medium' 'V-1002' 'Audit logon events') + (& $rule 'R3' 'low' 'V-1003' 'Review the legal notice (manual)') + (& $rule 'R4' 'medium' 'V-1004' 'Not for this platform')
    $rr = { param([string] $Id, [string] $Res, [string] $Sev = 'medium') "<cdf:rule-result idref=""$Id"" severity=""$Sev"" time=""2026-10-25T10:00:00Z""><cdf:result>$Res</cdf:result></cdf:rule-result>" }
    $scc = {
        param([string] $HostName, [string] $End, [string] $Results, [string] $Ns = 'http://checklists.nist.gov/xccdf/1.2')
@"
<?xml version="1.0" encoding="UTF-8"?>
<cdf:Benchmark xmlns:cdf="$Ns" id="$($script:Bench)">
  <cdf:title>Microsoft Windows 11 Security Technical Implementation Guide</cdf:title>
  <cdf:version>2</cdf:version>
  <cdf:Group id="G1">$rules</cdf:Group>
  <cdf:TestResult id="TR-$HostName" start-time="$End" end-time="$End">
    <cdf:benchmark href="#" id="$($script:Bench)"/>
    <cdf:profile idref="MAC-1_Classified"/>
    <cdf:target>$HostName</cdf:target>
    <cdf:target-address>10.0.0.55</cdf:target-address>
    <cdf:target-facts>
      <cdf:fact name="urn:scap:fact:asset:identifier:fqdn" type="string">$($HostName.ToLowerInvariant()).contoso.local</cdf:fact>
      <cdf:fact name="urn:scap:fact:asset:identifier:interface_name" type="string">CONTOSO\jdoe-secret</cdf:fact>
      <cdf:fact name="urn:scap:fact:asset:identifier:mac" type="string">00:11:22:33:44:55</cdf:fact>
    </cdf:target-facts>
    $Results
    <cdf:score system="urn:xccdf:scoring:default" maximum="100">71.4</cdf:score>
  </cdf:TestResult>
</cdf:Benchmark>
"@
    }
    $put = { param([string] $Name, [string] $Text) Set-Content -LiteralPath (Join-Path $script:In $Name) -Value $Text -Encoding utf8 }

    # WS01 (current): R1 pass, R2 fail, R3 manual, R4 n/a; an older WS01 file passes R2 and is superseded.
    & $put 'WS01_XCCDF-Results.xml' (& $scc 'WS01' '2026-10-25T10:00:00Z' ((& $rr 'R1' 'pass' 'high') + (& $rr 'R2' 'fail') + (& $rr 'R3' 'notchecked' 'low') + (& $rr 'R4' 'notapplicable')))
    & $put 'WS01_XCCDF-Results_old.xml' (& $scc 'WS01' '2026-10-02T10:00:00Z' ((& $rr 'R1' 'pass' 'high') + (& $rr 'R2' 'pass')))
    # WS02, XCCDF 1.1: R1 fail, R2 pass, R3 manual, R4 n/a, R5 error, R6 a value XCCDF does not define.
    & $put 'ws02.xml' (& $scc 'WS02' '2026-10-26T10:00:00Z' ((& $rr 'R1' 'fail' 'high') + (& $rr 'R2' 'pass') + (& $rr 'R3' 'notchecked' 'low') + (& $rr 'R4' 'notapplicable') + (& $rr 'R5' 'error') + (& $rr 'R6' 'compliant-ish')) 'http://checklists.nist.gov/xccdf/1.1')
    # WS03 inside an OpenSCAP ARF collection: R1 pass, R2 pass.
    & $put 'ws03-arf.xml' @"
<?xml version="1.0" encoding="UTF-8"?>
<arf:asset-report-collection xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1">
  <arf:report-requests><arf:report-request id="collection1"><arf:content>
    $((& $scc 'WS03' '2026-10-27T10:00:00Z' ((& $rr 'R1' 'pass' 'high') + (& $rr 'R2' 'pass'))) -replace '<\?xml[^>]*\?>', '')
  </arf:content></arf:report-request></arf:report-requests>
</arf:asset-report-collection>
"@
    # WS04: a fail from July, older than 30 days.
    & $put 'ws04.xml' (& $scc 'WS04' '2026-07-01T10:00:00Z' (& $rr 'R1' 'fail' 'high'))
    # Hostile and broken files.
    & $put 'xxe.xml' @"
<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"><TestResult><target>&xxe;</target></TestResult></Benchmark>
"@
    & $put 'broken.xml' '<Benchmark><TestResult><target>X</target>'
    & $put 'notxccdf.xml' '<?xml version="1.0"?><root><item>hello</item></root>'

    $script:View = Get-TPScapView -Path $script:In -Now $script:Now
    $script:B = @($script:View.Benchmarks)[0]
    $script:R = @{}; foreach ($r in @($script:B.Rules)) { $script:R[$r.Reference] = $r }
}

AfterAll {
    if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Reading SCAP results' {
    It 'reads XCCDF 1.2, XCCDF 1.1 and ARF into one benchmark with the title, version and profile' {
        $script:View.Available | Should -BeTrue
        @($script:View.Benchmarks).Count | Should -Be 1
        $script:B.BenchmarkId | Should -Be $script:Bench
        $script:B.Title | Should -Be 'Microsoft Windows 11 Security Technical Implementation Guide'
        $script:B.Version | Should -Be '2'
        @($script:B.Profiles) | Should -Contain 'MAC-1_Classified'
        $script:B.HostsTotal | Should -Be 4
        $script:B.HostsCurrent | Should -Be 3
    }
    It 'refuses a DTD (XXE), malformed XML and a file with no TestResult, each with the reason, and still reads the rest' {
        $sk = @{}; foreach ($s in @($script:View.FilesSkipped)) { $sk[$s.File] = $s.Reason }
        $sk['xxe.xml'] | Should -Match 'DTD'
        $sk['broken.xml'] | Should -Match 'well-formed'
        $sk['notxccdf.xml'] | Should -Match 'No XCCDF TestResult'
        ($script:View | ConvertTo-Json -Depth 20) | Should -Not -Match 'root:x:0'
    }
    It 'refuses a file over the size limit without reading it' {
        $big = Join-Path $script:Tmp 'big.xml'
        Set-Content -LiteralPath $big -Value ('<a>' + ('x' * 5000) + '</a>')
        $r = & (Get-Module TenantPosture) { param($p) Read-TPScapResultFile -Path $p -MaxFileBytes 2048 } $big
        $r.Ok | Should -BeFalse
        $r.Reason | Should -Match 'limit'
    }
    It 'keeps no IP address, MAC address or user name from the target facts' {
        $json = $script:View | ConvertTo-Json -Depth 20
        $json | Should -Not -Match '10\.0\.0\.55'
        $json | Should -Not -Match 'jdoe-secret'
        $json | Should -Not -Match '00:11:22:33:44:55'
        ($script:B.Hosts | Where-Object Host -eq 'WS01').Fqdn | Should -Be 'ws01.contoso.local'
    }
}

Describe 'Judging each rule across hosts' {
    It 'fails a rule any current host fails, and names the failing hosts' {
        $script:R['V-1001'].Status | Should -Be 'Failing'
        @($script:R['V-1001'].FailingHosts) | Should -Be @('WS02')
        $script:R['V-1001'].Category | Should -Be 'CAT I'
        $script:R['V-1002'].Status | Should -Be 'Failing'
        @($script:R['V-1002'].FailingHosts) | Should -Be @('WS01')
    }
    It 'uses the newest result per host and lists the older file as superseded' {
        $ws01 = $script:B.Hosts | Where-Object Host -eq 'WS01'
        $ws01.File | Should -Be 'WS01_XCCDF-Results.xml'
        @($ws01.Superseded) | Should -Be @('WS01_XCCDF-Results_old.xml')
        $script:R['V-1002'].Pass | Should -Be 2 -Because 'WS02 and WS03 pass; the superseded WS01 pass is not counted'
    }
    It 'lists a result older than the age limit as not current and leaves it out of the counts' {
        $ws04 = $script:B.Hosts | Where-Object Host -eq 'WS04'
        $ws04.Current | Should -BeFalse
        $script:R['V-1001'].Fail | Should -Be 1 -Because 'the July fail on WS04 is not current'
    }
    It 'never counts notchecked, error, unknown or an undefined value as a pass' {
        $script:R['V-1003'].Status | Should -Be 'Manual'
        $script:R['R5'].Status | Should -Be 'NotEstablished'
        $script:R['R6'].Status | Should -Be 'NotEstablished'
        $script:R['V-1004'].Status | Should -Be 'NotApplicable'
        $script:B.Counts.Met | Should -Be 0
    }
    It 'calls a rule met only when every host that checked it passed' {
        $dir = Join-Path $script:Tmp 'allpass'
        $null = New-Item -ItemType Directory -Force -Path $dir
        Copy-Item -LiteralPath (Join-Path $script:In 'ws03-arf.xml') -Destination $dir
        $v = Get-TPScapView -Path $dir -Now $script:Now
        $met = @(@($v.Benchmarks)[0].Rules | Where-Object { $_.Status -eq 'Met' })
        @($met | ForEach-Object Reference) | Should -Be @('V-1001', 'V-1002')
        $met[0].StatusLabel | Should -Be 'Met on every host that checked it'
    }
    It 'says why nothing was produced when no file is readable' {
        $dir = Join-Path $script:Tmp 'empty'
        $null = New-Item -ItemType Directory -Force -Path $dir
        Copy-Item -LiteralPath (Join-Path $script:In 'xxe.xml') -Destination $dir
        $v = Get-TPScapView -Path $dir -Now $script:Now
        $v.Available | Should -BeFalse
        $v.Note | Should -Match 'No readable XCCDF results'
        (Get-TPScapView -Path (Join-Path $script:Tmp 'nope') -Now $script:Now).Available | Should -BeFalse
    }
}

Describe 'The SCAP results page' {
    BeforeAll {
        $script:Files = Publish-TPScapView -Model $script:View -OutputPath (Join-Path $script:Tmp 'out' 'contoso-scap.html') -GeneratedAt $script:Now
        $script:Html = Get-Content -LiteralPath $script:Files.Html -Raw
        $script:Md = Get-Content -LiteralPath $script:Files.Markdown -Raw
    }
    It 'says imported, not verified, hosts in the files only, and not a compliance determination, before any number' {
        $first = $script:Html.IndexOf('did not verify')
        $first | Should -BeGreaterThan 0
        $first | Should -BeLessThan $script:Html.IndexOf('class="tp-kpis"')
        $script:Html | Should -Match 'not the whole fleet'
        $script:Html | Should -Match 'not a compliance determination'
        $script:Md | Should -Match 'did not verify'
    }
    It 'escapes a hostile rule title in HTML and Markdown and loads nothing' {
        $script:Html | Should -Not -Match '<img src=x'
        $script:Html | Should -Not -Match '<script|<link |src="http|@import'
        $script:Md | Should -Not -Match '(?<!\\)\]\((?=https)'
        $script:Md | Should -Not -Match '(?<!\\)<img'
    }
    It 'names the failing hosts and lists the skipped files' {
        $script:Html | Should -Match 'WS02'
        $script:Html | Should -Match 'xxe\.xml'
        $script:Html | Should -Match 'Not current'
    }
    It 'never calls anything compliant' {
        foreach ($t in $script:Html, $script:Md) { $t | Should -Not -Match '(?i)\bis compliant\b|\bfully compliant\b|\bare compliant\b' }
    }
}

Describe 'The standalone script and the entry point' {
    It 'New-TPScapView.ps1 writes the view and connects to nothing' {
        $text = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'New-TPScapView.ps1') -Raw
        foreach ($f in 'Invoke-RestMethod', 'Invoke-WebRequest', 'Invoke-TPGraphRequest', 'Connect-', 'graph\.microsoft', 'Start-Process') { $text | Should -Not -Match $f }
        foreach ($f in 'Invoke-RestMethod', 'Invoke-WebRequest', 'Connect-', 'Start-Process', 'XmlUrlResolver', 'DtdProcessing\]::Parse') {
            (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib' 'Get-TPScapView.ps1') -Raw) | Should -Not -Match $f
        }
        $out = Join-Path $script:Tmp 'standalone'
        $pwsh = (Get-Process -Id $PID).Path
        & $pwsh -NoProfile -NonInteractive -File (Join-Path $script:RepoRoot 'New-TPScapView.ps1') -Path $script:In -OutputPath $out *> $null
        $LASTEXITCODE | Should -Be 0
        @(Get-ChildItem -LiteralPath $out -Filter 'scap-view-*.html').Count | Should -Be 1
        @(Get-ChildItem -LiteralPath $out -Filter 'scap-view-*.md').Count | Should -Be 1
    }
    It 'the entry point takes -ScapResults, keeps the view in the results JSON and writes the files' {
        $entry = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
        $entry | Should -Match '\[string\] \$ScapResults'
        $entry | Should -Match 'ScapView\s+=\s+\$scapView'
        $entry | Should -Match 'Publish-TPScapView -Model \$scapView'
        $entry | Should -Not -Match '(?m)^\s*\$scapResults\s*=' -Because 'variable names ignore case: $scapResults is the -ScapResults parameter'
    }
}
