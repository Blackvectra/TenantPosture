#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
#
# TP.Fuzz.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Mutation fuzzing of every parser that reads untrusted input (a
#   results JSON from another workstation, an MCP client's JSON-RPC line, a
#   SCAP or ScubaGear file, an endpoint result file, a DoH TXT answer, a web
#   request's path segments) and of the escapers that write tenant text into a
#   deliverable. Each parser has a contract the fuzzer checks on every case:
#   it answers or refuses with its own fixed sentence, never echoes the input
#   in an error, never crashes on a property the input left out, and never
#   hangs; each escaper's output can form no markup.
#
# Deterministic: tools/TPFuzz.ps1 seeds System.Random with TP_FUZZ_SEED
# (default 20261030) and runs TP_FUZZ_ITERATIONS cases per target (default
# 120). A failure prints the seed, the iteration and the input as base64, so
# it reproduces exactly. Raise TP_FUZZ_ITERATIONS for a longer local run.
# Data consumed: none. Graph scopes / cmdlets used: none; no network.

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop 3>$null
    . (Join-Path $script:RepoRoot 'tools' 'TPFuzz.ps1')
    foreach ($lib in 'Test-TPDomainName', 'Resolve-TPWebRunPath', 'Get-TPWebRunIndex') { . (Join-Path $script:RepoRoot 'Lib' "$lib.ps1") }
    foreach ($f in 'Protect-TPMcpOutput', 'Read-TPMcpRun', 'Invoke-TPMcpTool', 'Format-TPMcpMarkdown', 'Invoke-TPMcpProtocol') { . (Join-Path $script:RepoRoot 'Mcp' "$f.ps1") }

    $script:Settings = Get-TPFuzzSettings
    $script:Marker = 'FUZZMARKER-9d1e'
    $script:Dir = Join-Path $TestDrive 'fuzz'
    $null = New-Item -ItemType Directory -Force -Path $script:Dir

    # A case is checked inside a scriptblock; any failure is collected with
    # its repro line, so one run reports every broken case, not just the first.
    $script:Run = {
        param([string] $Name, [string[]] $Seeds, [scriptblock] $Check)
        $rand = [System.Random]::new($script:Settings.Seed + [Math]::Abs($Name.GetHashCode() % 100000))
        $bad = [System.Collections.Generic.List[string]]::new()
        for ($i = 0; $i -lt $script:Settings.Iterations; $i++) {
            $seed = $Seeds[$i % $Seeds.Count]
            $case = Get-TPFuzzCase -Seed $seed -Random $rand -Others $Seeds
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            try { & $Check $case $i }
            catch { $bad.Add("$($_.Exception.Message) -- $(Format-TPFuzzRepro -Seed $script:Settings.Seed -Iteration $i -Case $case)") }
            if ($sw.Elapsed.TotalSeconds -gt 10) { $bad.Add("took $([int]$sw.Elapsed.TotalSeconds) s -- $(Format-TPFuzzRepro -Seed $script:Settings.Seed -Iteration $i -Case $case)") }
            if ($bad.Count -ge 5) { break }
        }
        return , $bad
    }
    $script:Put = {
        param([string] $Name, [string] $Text)
        $p = Join-Path $script:Dir $Name
        [System.IO.File]::WriteAllText($p, $Text, [System.Text.UTF8Encoding]::new($false))
        return $p
    }
    # A refusal is a fixed sentence: never the input, and never a StrictMode
    # or null-reference crash on a field the input left out.
    $script:AssertRefusal = {
        param($ErrorRecord)
        $m = [string]$ErrorRecord.Exception.Message
        if ($m -match [regex]::Escape($script:Marker)) { throw "the error echoed the input: $m" }
        if ($ErrorRecord.Exception -is [System.NullReferenceException] -or $m -match 'cannot be found on this object|You cannot call a method on a null-valued expression|Index was outside the bounds|has not been set') {
            throw "crashed instead of refusing: $m"
        }
    }

    $finding = [ordered]@{ ControlId = 'AAD-1.1'; State = 'Satisfied'; Category = 'Identity'; Title = "Legacy auth $script:Marker"; Severity = 'High'; Detail = "Detail $script:Marker"; CurrentValue = 'x'; RequiredValue = 'y'; Remediation = 'r'; AffectedObjects = @(@{ UserPrincipalName = 'a@contoso.example' }); FrameworkIds = @('NIST:IA-2'); Timestamp = '2026-10-16T10:00:00Z' }
    $second = [ordered]@{}; foreach ($k in $finding.Keys) { $second[$k] = $finding[$k] }
    $second.ControlId = 'EXO-1.1'; $second.State = 'Gap'
    $script:ResultsSeed = ([ordered]@{
        Metadata           = [ordered]@{ TenantDomain = 'contoso.example'; TenantId = '11111111-2222-3333-4444-555555555555'; AssessmentTime = '2026-10-16T10:00:00Z'; ToolVersion = '4.14.3'; Operator = "op $script:Marker"; Maturity = [ordered]@{ Score = 72.5; Label = 'Managed' } }
        Findings           = @($finding, $second)
        Coverage           = [ordered]@{ 'AAD-Users' = [ordered]@{ Status = 'Collected' } }
        RawData            = [ordered]@{ 'AAD-Users' = [ordered]@{ Success = $true; Data = [ordered]@{ Users = @(@{ UserPrincipalName = "raw $script:Marker" }) } } }
        BaselineCompliance = [ordered]@{ BaselineVersion = '2.0'; TargetTier = 'Standard'; Rows = @([ordered]@{ ControlId = 'AAD-1.1'; ObservedState = 'Satisfied'; ReasonCode = 'Satisfied' }) }
        Exceptions         = @(@{ Message = "exc $script:Marker" })
    } | ConvertTo-Json -Depth 12 -Compress)
}

Describe 'Fuzzing: readers of untrusted files' {

    It 'Read-TPRunRecord answers or refuses with a fixed sentence on every mutated results file' {
        $bad = & $script:Run 'runrecord' @($script:ResultsSeed) {
            param([string] $Case, [int] $I)
            $p = & $script:Put "run-$I.json" $Case
            try {
                $r = Read-TPRunRecord -Path $p -Hash
                if ($r -isnot [System.Collections.IDictionary]) { throw 'did not return a record' }
            } catch { & $script:AssertRefusal $_ }
        }
        $bad | Should -BeNullOrEmpty
    }

    It 'Read-TPMcpRunFile answers or refuses with a fixed sentence, and never returns RawData or Exceptions' {
        $bad = & $script:Run 'mcprun' @($script:ResultsSeed) {
            param([string] $Case, [int] $I)
            $p = & $script:Put "mcp-$I.json" $Case
            try {
                $r = Read-TPMcpRunFile -Path $p
                if ($r -isnot [System.Collections.IDictionary]) { throw 'did not return a run' }
                if ($r.Contains('RawData') -or $r.Contains('Exceptions')) { throw 'materialized RawData or Exceptions' }
            } catch { & $script:AssertRefusal $_ }
        }
        $bad | Should -BeNullOrEmpty
    }

    It 'Read-TPScapResultFile never throws and never reads a DTD, on every mutated XCCDF file' {
        $xccdf = @"
<?xml version="1.0" encoding="UTF-8"?>
<cdf:Benchmark xmlns:cdf="http://checklists.nist.gov/xccdf/1.2" id="xccdf_mil.disa.stig_benchmark_Windows_11">
  <cdf:title>Windows 11 STIG $script:Marker</cdf:title><cdf:version>2</cdf:version>
  <cdf:Group id="G1"><cdf:Rule id="R1" severity="high"><cdf:title>Rule one</cdf:title><cdf:ident system="http://cyber.mil/legacy">V-1001</cdf:ident></cdf:Rule></cdf:Group>
  <cdf:TestResult id="TR-PC1" start-time="2026-10-25T10:00:00Z" end-time="2026-10-25T10:00:00Z">
    <cdf:benchmark href="#" id="xccdf_mil.disa.stig_benchmark_Windows_11"/><cdf:target>PC1</cdf:target>
    <cdf:rule-result idref="R1" severity="high" time="2026-10-25T10:00:00Z"><cdf:result>fail</cdf:result></cdf:rule-result>
    <cdf:score system="urn:xccdf:scoring:default" maximum="100">71.4</cdf:score>
  </cdf:TestResult>
</cdf:Benchmark>
"@
        $bad = & $script:Run 'scap' @($xccdf) {
            param([string] $Case, [int] $I)
            $p = & $script:Put "scap-$I.xml" $Case
            $r = & (Get-Module TenantPosture) { param($File) Read-TPScapResultFile -Path $File } $p
            if ($r -isnot [System.Collections.IDictionary] -or $r.Ok -isnot [bool]) { throw 'did not return a result' }
            if (-not $r.Ok -and [string]$r.Reason -match [regex]::Escape($script:Marker)) { throw "the reason echoed the input: $($r.Reason)" }
            if ($r.Ok -and $Case -match '<!DOCTYPE') { throw 'read a file with a DTD' }
        }
        $bad | Should -BeNullOrEmpty
    }

    It 'Read-TPScubaResults reads a map or refuses, on every mutated ScubaGear JSON and CSV file' {
        $json = '{"Results":{"EXO":[{"Controls":[{"Control ID":"MS.EXO.1.1v2","Result":"Pass"},{"Control ID":"MS.EXO.2.2v3","Result":"Fail"}]}]}}'
        $csv = "Control ID,Requirement,Result,Criticality,Details`r`nMS.EXO.1.1v2,Auto forwarding,Pass,Shall,x`r`nMS.AAD.3.1v1,MFA,Fail,Shall,y"
        $bad = & $script:Run 'scuba' @($json, $csv) {
            param([string] $Case, [int] $I)
            $ext = if ($Case.TrimStart().StartsWith('{')) { 'json' } else { 'csv' }
            $p = & $script:Put "ScubaResults-$I.$ext" $Case
            try {
                $r = Read-TPScubaResults -Path $p
                if ($r -isnot [System.Collections.IDictionary]) { throw 'did not return a map' }
            } catch { & $script:AssertRefusal $_ }
        }
        $bad | Should -BeNullOrEmpty
    }

    It 'the endpoint result collector never fails the run on a mutated result file' {
        $dev = ([ordered]@{ Schema = 'tp-device-compliance/1.0'; CollectedAt = (Get-Date).ToUniversalTime().ToString('o'); Elevated = $true
            Device = [ordered]@{ Hostname = 'PC-1'; Serial = 'S-1'; OSCaption = 'Windows 11 Pro'; OSBuild = '22631'; JoinType = 'EntraJoined' }
            Checks = @([ordered]@{ Id = 'DEV-1.1'; Result = 'Pass'; Observed = "BitLocker $script:Marker"; Detail = 'x' }) } | ConvertTo-Json -Depth 5 -Compress)
        $bad = & $script:Run 'device' @($dev) {
            param([string] $Case, [int] $I)
            $d = Join-Path $script:Dir "dev-$I"
            $null = New-Item -ItemType Directory -Force -Path $d
            [System.IO.File]::WriteAllText((Join-Path $d 'PC-1.json'), $Case, [System.Text.UTF8Encoding]::new($false))
            Clear-TPState
            $null = Invoke-TPCollectDeviceCompliance -ResultsPath $d
            $raw = Get-TPRawData -Key 'Device-Compliance'
            if ($null -eq $raw) { throw 'stored no result' }
        }
        $bad | Should -BeNullOrEmpty
    }
}

Describe 'Fuzzing: the MCP server and the web path guard' {

    It 'Invoke-TPMcpMessage never throws and answers each line with one JSON-RPC 2.0 message or nothing' {
        $ctx = @{ OutputRoot = $script:Dir; ClientsFile = (Join-Path $script:Dir 'none.json'); IncludeIdentities = $false; Pseudo = (New-TPMcpPseudonymMap)
            RunCache = @{}; SummaryCache = @{}; MetaCache = [hashtable]::Synchronized(@{}); Benchmarks = $null
            StateRank = @{ Gap = 5; Error = 4; Partial = 3; NotApplicable = 2; Satisfied = 1 }; ToolVersion = 'test'; ProtocolVersion = (Get-TPMcpSupportedVersions)[0]; Initialized = $true }
        $seeds = @(
            '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"x","version":"1"}}}'
            '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
            '{"jsonrpc":"2.0","id":"a","method":"tools/call","params":{"name":"tenantposture_list_runs","arguments":{"limit":5,"offset":0}}}'
            '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"tenantposture_get_control","arguments":{"controlId":"AAD-1.1","response_format":"markdown"}}}'
            '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"tenantposture_list_findings","arguments":{"folder":"_flat","id":"run-1","state":"Gap"}}}'
            '{"jsonrpc":"2.0","method":"notifications/initialized"}'
        )
        $bad = & $script:Run 'mcp' $seeds {
            param([string] $Case, [int] $I)
            $out = Invoke-TPMcpMessage -Ctx $ctx -Line $Case
            if ($null -eq $out) { return }
            if ($out -match '[\r\n]') { throw 'the answer spans more than one line' }
            $m = ConvertFrom-Json -InputObject $out -AsHashtable -ErrorAction Stop
            if ($m['jsonrpc'] -ne '2.0') { throw 'the answer is not JSON-RPC 2.0' }
            if (-not ($m.ContainsKey('result') -xor $m.ContainsKey('error'))) { throw 'the answer has neither or both of result and error' }
        }
        $bad | Should -BeNullOrEmpty
    }

    It 'Resolve-TPWebRunPath never throws, and every path it allows stays inside the output folder' {
        $root = Join-Path $script:Dir 'webroot'
        $null = New-Item -ItemType Directory -Force -Path $root
        $rootFull = [System.IO.Path]::GetFullPath($root).TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
        $bad = & $script:Run 'webpath' @('contoso.example|contoso-20261016-100000|Report|', '_flat|contoso-20261016-100000|SitePage|index.html', 'contoso.example|contoso-20261016-100000|Results|') {
            param([string] $Case, [int] $I)
            $parts = $Case -split '\|', 4
            while ($parts.Count -lt 4) { $parts += '' }
            $kind = if ($parts[2] -in 'Report', 'SitePage', 'Results') { $parts[2] } else { 'Report' }
            $r = Resolve-TPWebRunPath -OutputRoot $root -Folder $parts[0] -Id $parts[1] -Kind $kind -Page $parts[3]
            if ($r.Status -notin 'Ok', 'BadRequest', 'NotFound') { throw "unknown status $($r.Status)" }
            if ($r.Status -eq 'Ok' -and -not ([System.IO.Path]::GetFullPath([string]$r.Path)).StartsWith($rootFull, [StringComparison]::Ordinal)) { throw "allowed a path outside the root: $($r.Path)" }
        }
        $bad | Should -BeNullOrEmpty
    }

    It 'ConvertFrom-TPDnsTxtData never throws and returns a string or null, in linear time' {
        $bad = & $script:Run 'txt' @('"v=spf1 include:spf.protection.outlook.com -all"', '"v=DMARC1; p=reject; " "rua=mailto:d@contoso.example"', '"a\"b\\c"') {
            param([string] $Case, [int] $I)
            $r = ConvertFrom-TPDnsTxtData -Data $Case
            if ($null -ne $r -and $r -isnot [string]) { throw 'returned something other than a string' }
        }
        $bad | Should -BeNullOrEmpty
    }
}

Describe 'Fuzzing: the escapers that write tenant text into a deliverable' {

    BeforeAll {
        $script:TextSeeds = @('Contoso <b>Finance</b> & "Ops"', '[click](https://evil.example) `code` | pipe', "Line one`r`nline two # heading", "O'Brien's mailbox", 'plain text')
    }

    It 'ConvertTo-TPHtmlSafe output can open no tag and close no attribute' {
        $bad = & $script:Run 'html' $script:TextSeeds {
            param([string] $Case, [int] $I)
            $r = ConvertTo-TPHtmlSafe $Case
            if ($r -match '[<>"'']') { throw 'left a markup character unescaped' }
            # A lone surrogate is replaced with U+FFFD by the encoder, which is safe;
            # every other input must read back exactly.
            if ($Case -notmatch '[\uD800-\uDFFF]' -and [System.Net.WebUtility]::HtmlDecode($r) -cne $Case) { throw 'does not decode back to the input' }
        }
        $bad | Should -BeNullOrEmpty
    }

    It 'ConvertTo-TPMarkdownSafe output holds no line break and no unescaped Markdown character' {
        $bad = & $script:Run 'md' $script:TextSeeds {
            param([string] $Case, [int] $I)
            $r = ConvertTo-TPMarkdownSafe -Value $Case
            if ($r -match '[\r\n]') { throw 'left a line break' }
            # Every special character must be preceded by an odd run of backslashes.
            # Parentheses are left alone by design: with the brackets escaped no
            # link can form, and ids such as AC-2(3) read as written.
            foreach ($m in [regex]::Matches($r, '(\\*)([|`\[\]*_#>!<~])')) {
                if ($m.Groups[1].Length % 2 -eq 0) { throw "left '$($m.Groups[2].Value)' unescaped" }
            }
        }
        $bad | Should -BeNullOrEmpty
    }

    It 'ConvertTo-TPPsLiteral returns null or one string literal that parses back to the input' {
        $bad = & $script:Run 'psliteral' ($script:TextSeeds + @("'; Remove-Item C:\ -Recurse; '", '$(Get-Process)')) {
            param([string] $Case, [int] $I)
            $r = ConvertTo-TPPsLiteral -Value $Case
            if ($null -eq $r) { return }
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseInput("`$x = $r", [ref]$tokens, [ref]$errors)
            if (@($errors).Count) { throw "the literal does not parse: $($errors[0].Message)" }
            $rhs = $ast.EndBlock.Statements[0].Right.Expression
            if ($rhs -isnot [System.Management.Automation.Language.StringConstantExpressionAst]) { throw 'the literal is not one constant string' }
            if ($rhs.Value -cne $Case) { throw 'the literal does not read back as the input' }
            if (@($ast.EndBlock.Statements).Count -ne 1) { throw 'the literal ends the statement' }
        }
        $bad | Should -BeNullOrEmpty
    }
}

AfterAll { Clear-TPState; Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }
