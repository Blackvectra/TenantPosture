#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0' }
#
# TP.OsstmmAlignment.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Pins the OSSTMM 3 alignment of the tool's own security testing:
#   docs/security/osstmm-modules.json names every module A.1 to D.17 once
#   with a valid status, evidence for what it covers and a reason for what it
#   does not; every evidence file it names exists; every reviewed ZAP rule has
#   a limitation type; the summary generator says it is not an ISECOM STAR,
#   computes no rav, counts porosity from the server's own registrations and
#   types an unreviewed alert as an Anomaly; the doc's counts match the file;
#   and the manual itself is not in the repository.
# Data consumed: none. Graph scopes / cmdlets used: none.

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    $script:Data = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'docs/security/osstmm-modules.json') -Raw | ConvertFrom-Json -Depth 16
    $script:Doc = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'docs/security/OSSTMM-ALIGNMENT.md') -Raw
    $script:Gen = Join-Path $script:RepoRoot 'tools/New-TPSecurityTestSummary.ps1'
    $script:Modules = [ordered]@{
        'A.1' = 'Posture Review'; 'A.2' = 'Logistics'; 'A.3' = 'Active Detection Verification'
        'B.4' = 'Visibility Audit'; 'B.5' = 'Access Verification'; 'B.6' = 'Trust Verification'; 'B.7' = 'Control Verification'
        'C.8' = 'Process Verification'; 'C.9' = 'Configuration Verification'; 'C.10' = 'Property Validation'; 'C.11' = 'Segregation Review'
        'C.12' = 'Exposure Verification'; 'C.13' = 'Competitive Intelligence Scouting'
        'D.14' = 'Quarantine Verification'; 'D.15' = 'Privileges Audit'; 'D.16' = 'Survivability Validation'; 'D.17' = 'Alert and Log Review'
    }
    $script:Summarize = {
        param([string] $Report)
        $out = Join-Path $TestDrive ('s-' + [guid]::NewGuid().ToString('N') + '.md')
        $argv = @('-NoProfile', '-File', $script:Gen, '-OutputPath', $out, '-RunLabel', 'test')
        if ($Report) { $argv += @('-ZapReport', $Report) }
        $null = & pwsh @argv
        if ($LASTEXITCODE -ne 0) { throw "generator exited $LASTEXITCODE" }
        Get-Content -LiteralPath $out -Raw
    }
}

Describe 'OSSTMM 3 alignment of the tool''s own testing' {

    It 'names every module A.1 to D.17 exactly once, in order, with its OSSTMM name' {
        @($script:Data.modules.Id) | Should -Be @($script:Modules.Keys)
        foreach ($m in @($script:Data.modules)) { $m.Name | Should -Be $script:Modules[$m.Id] }
    }

    It 'gives each module a valid status, evidence for what it covers and a reason for what it does not' {
        foreach ($m in @($script:Data.modules)) {
            $m.Status | Should -BeIn 'Complete', 'Partial', 'NotTested', 'NotApplicable'
            if ($m.Status -in 'Complete', 'Partial') { @($m.Evidence).Count | Should -BeGreaterThan 0 -Because "$($m.Id) claims coverage" }
            if ($m.Status -ne 'Complete') { $m.Gap.Length | Should -BeGreaterThan 40 -Because "$($m.Id) must say what is not covered and why" }
            else { $m.Gap | Should -BeNullOrEmpty -Because "a Complete module with a gap is Partial ($($m.Id))" }
        }
    }

    It 'every repository file the evidence names exists' {
        $paths = foreach ($m in @($script:Data.modules)) {
            foreach ($e in @($m.Evidence)) { [regex]::Matches($e, '(?<![\w/.-])((?:Lib|Testing|tools|docs|Mcp|\.zap|\.github)/[\w./-]+\.(?:ps1|json|md|tsv|yml|yaml))') | ForEach-Object { $_.Groups[1].Value } }
        }
        @($paths).Count | Should -BeGreaterThan 10
        foreach ($p in @($paths | Sort-Object -Unique)) { Test-Path -LiteralPath (Join-Path $script:RepoRoot $p) | Should -BeTrue -Because "$p is cited as evidence" }
    }

    It 'states every channel, with Data Networks the only one that applies' {
        $ch = $script:Data.scope.channels
        @($ch.PSObject.Properties.Name) | Should -Be @('DataNetworks', 'Human', 'Physical', 'Wireless', 'Telecommunications')
        $ch.DataNetworks | Should -Match '^Applies'
        foreach ($n in 'Human', 'Physical', 'Wireless', 'Telecommunications') { $ch.$n | Should -Match '^Not applicable: .{20,}' }
    }

    It 'the doc''s module counts match the file' {
        $by = @($script:Data.modules) | Group-Object Status -AsHashTable -AsString
        $script:Doc | Should -Match ("\*\*Complete:\*\* {0} modules" -f $by['Complete'].Count)
        $script:Doc | Should -Match ("\*\*Partial:\*\* {0} modules" -f $by['Partial'].Count)
        $script:Doc | Should -Match ("\*\*Not tested:\*\* {0} modules" -f $by['NotTested'].Count)
        $script:Doc | Should -Match ("\*\*Not applicable:\*\* {0} modules" -f $by['NotApplicable'].Count)
        foreach ($m in @($script:Data.modules | Where-Object Status -in 'NotTested', 'NotApplicable')) { $script:Doc | Should -Match ([regex]::Escape("$($m.Id) $($m.Name)")) }
    }

    It 'every ZAP rule reviewed in .zap/rules.tsv has an OSSTMM limitation type with a reason, and no type for a rule not reviewed' {
        $read = { param($f) @(Get-Content -LiteralPath (Join-Path $script:RepoRoot $f) | Where-Object { $_ -and $_ -notmatch '^\s*#' }) }
        $reviewed = @(& $read '.zap/rules.tsv' | ForEach-Object { ($_ -split "`t")[0] } | Sort-Object)
        $typed = @(& $read '.zap/osstmm-limitations.tsv')
        @($typed | ForEach-Object { ($_ -split "`t")[0] } | Sort-Object) | Should -Be $reviewed
        foreach ($line in $typed) {
            $cols = $line -split "`t"
            $cols.Count | Should -Be 3
            $cols[1] | Should -BeIn 'Vulnerability', 'Weakness', 'Concern', 'Exposure', 'Anomaly', 'None'
            $cols[2].Length | Should -BeGreaterThan 30
        }
    }

    It 'the summary says it is not an ISECOM STAR and computes no rav, before anything else' {
        $text = & $script:Summarize ''
        $head = ($text -split "`n" | Select-Object -First 8) -join "`n"
        $head | Should -Match 'This is not an ISECOM STAR'
        $head | Should -Match 'No rav is calculated'
        $text | Should -Match 'Not measured in this run: no active scan report was given\.'
        $text | Should -Not -Match '(?i)\bcompliant\b|certified by|\bpassed\b'
    }

    It 'counts porosity from the server''s own registrations, not by hand' {
        $tokens = $null; $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:RepoRoot 'Lib/Start-TPWebServer.ps1'), [ref]$tokens, [ref]$errors)
        $routes = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-PodeRoute' }, $true))
        $named = $routes.Count - 1   # the wildcard route answers what no other route serves
        $text = & $script:Summarize ''
        $text | Should -Match "\| Visibility \| 1 \|"
        $text | Should -Match "\| Access \| $named \|"
        $text | Should -Match '\| `/api/scan` \| Post \|'
    }

    It 'types each alert by its reviewed rule and an unreviewed rule as an Anomaly, on every site in the report' {
        $report = Join-Path $TestDrive 'zap.json'
        @{ site = @(
            @{ '@name' = ('http' + '://127.0.0.1:8765'); alerts = @(@{ pluginid = '10055'; name = 'CSP'; riskdesc = 'Medium (High)' }, @{ pluginid = '40018'; name = 'SQL Injection'; riskdesc = 'High (Medium)' }) }
            @{ '@name' = 'https://127.0.0.1:8765'; alerts = @(@{ pluginid = '10027'; name = 'Comments'; riskdesc = 'Informational (Low)' }) }
        ) } | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $report
        $text = & $script:Summarize $report
        $text | Should -Match '\| Concern \| 1 \|'
        $text | Should -Match '\| Exposure \| 1 \|'
        $text | Should -Match '\| Anomaly \| 1 \|'
        $text | Should -Match '\| 40018 \| SQL Injection \| High \| Anomaly \|'
        $text | Should -Match '3 alert\(s\) across 2 site\(s\)'
    }

    It 'the dast workflow writes the summary after the active scan, even when the gate fails' {
        $dast = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.github/workflows/dast.yml') -Raw
        $dast | Should -Match "if: always\(\) && hashFiles\('zap-active/zap-active-report\.json'\) != ''\s+shell: pwsh\s+run: \|\s+\./tools/New-TPSecurityTestSummary\.ps1 -ZapReport zap-active/zap-active-report\.json"
    }

    It 'the repository holds neither the manual nor its STAR template' {
        $files = @(Get-ChildItem -LiteralPath $script:RepoRoot -Recurse -File -Force -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' })
        @($files | Where-Object { $_.Name -match '(?i)osstmm.*\.pdf|playbook.*\.pdf|star.*template' }) | Should -BeNullOrEmpty
        # Phrases from the manual's own STAR form; their presence would mean it was copied in.
        $script:Doc | Should -Not -Match 'I am responsible for the information within this report'
    }
}
