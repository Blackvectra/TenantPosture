#Requires -Version 7.0
#
# TP.WorkflowSecurity.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# The GitHub Actions workflows are the supply chain of this tool: the release
# job publishes the archive and signs its provenance. zizmor
# (.github/workflows/zizmor.yml) audits them on every pull request; these
# tests pin the parts of that arrangement a later edit could quietly weaken:
# the gate's strictness, the hash-locked install, a suppression with no
# reason, an action pinned by tag, a checkout that leaves its token on disk,
# a workflow with no concurrency group or with workflow-wide write access.

BeforeDiscovery {
    # -ForEach data must exist at discovery; BeforeAll runs too late and
    # would leave every per-workflow case undiscovered, so nothing would run.
    $repoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    $workflowCases = @(Get-ChildItem -LiteralPath (Join-Path $repoRoot '.github/workflows') -File |
        Where-Object { $_.Extension -in '.yml', '.yaml' } |
        ForEach-Object { @{ Name = $_.Name; FullName = $_.FullName } })
}

Describe 'Workflow security' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:WorkflowDir = Join-Path $script:RepoRoot '.github/workflows'
        $script:Workflows = @(Get-ChildItem -LiteralPath $script:WorkflowDir -File | Where-Object { $_.Extension -in '.yml', '.yaml' })
        $script:Zizmor = Get-Content -LiteralPath (Join-Path $script:WorkflowDir 'zizmor.yml') -Raw
        $script:Requirements = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.github/zizmor-requirements.txt') -Raw
        $script:Dependabot = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.github/dependabot.yml') -Raw
    }

    It 'finds the workflows' {
        $script:Workflows.Count | Should -BeGreaterThan 5
        $script:Workflows.Name | Should -Contain 'zizmor.yml'
    }

    It 'discovered one case per workflow for each per-workflow test' -TestCases @(@{ Expected = $workflowCases.Count }) {
        $Expected | Should -Be $script:Workflows.Count
    }

    Context 'zizmor gate' {

        It 'audits at the strictest persona, every severity and confidence, and fails on any finding' {
            $script:Zizmor | Should -Match '--persona=auditor --format=plain'
            $script:Zizmor | Should -Match '--persona=auditor --format=sarif'
            $script:Zizmor | Should -Not -Match '--min-severity|--min-confidence|--no-exit-codes|--offline|--persona=(regular|pedantic)'
            $script:Zizmor | Should -Match 'exit 1'
        }

        It 'runs the online audits with the job token' {
            $script:Zizmor | Should -Match 'GH_TOKEN: \$\{\{ github\.token \}\}'
        }

        It 'installs zizmor by exact version and SHA-256, wheel only, with no dependencies' {
            $script:Zizmor | Should -Match '--require-hashes --only-binary=:all: -r \.github/zizmor-requirements\.txt'
            $script:Zizmor | Should -Match '--no-deps'
            $script:Requirements | Should -Match '(?m)^zizmor==\d+\.\d+\.\d+ \\\s*\r?\n\s+--hash=sha256:[0-9a-f]{64}\s*$'
        }

        It 'is kept current by Dependabot with a cooldown' {
            $script:Dependabot | Should -Match 'package-ecosystem: "pip"\s+directory: "/\.github"'
            ([regex]::Matches($script:Dependabot, 'package-ecosystem:')).Count | Should -Be ([regex]::Matches($script:Dependabot, 'default-days: [7-9]|default-days: [1-9]\d')).Count
        }

        It 'installs every Python tool in CI from a hash-locked requirements file' {
            foreach ($wf in $script:Workflows) {
                # Join shell line continuations so a wrapped command is one line.
                $text = (Get-Content -LiteralPath $wf.FullName -Raw) -replace '\\\r?\n\s*', ' '
                foreach ($m in [regex]::Matches($text, 'pip"?\s+install\b[^\r\n]*')) {
                    $m.Value | Should -Match '--require-hashes' -Because "$($wf.Name): '$($m.Value.Trim())' must install by hash"
                    $m.Value | Should -Match '--only-binary=:all:'
                }
            }
            $yl = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.github/yamllint-requirements.txt') -Raw
            foreach ($pkg in 'yamllint', 'pathspec', 'pyyaml') {
                $yl | Should -Match "(?m)^$pkg==\d+(\.\d+)+ \\\s*\r?\n\s+--hash=sha256:[0-9a-f]{64}"
            }
        }

        It 'runs on pull requests, on main and on a schedule' {
            $script:Zizmor | Should -Match '(?m)^  pull_request:'
            $script:Zizmor | Should -Match '(?m)^  push:'
            $script:Zizmor | Should -Match '(?m)^  schedule:'
        }
    }

    Context 'Code Scanning and the OSS Scanner image' {

        It 'uploads the PSScriptAnalyzer SARIF on every run, so an alert closes once fixed' {
            # Uploads stopped whenever there were no Errors, so the warnings a
            # 2026-05-28 run uploaded under this category could never close.
            $ci = Get-Content -LiteralPath (Join-Path $script:WorkflowDir 'ci.yml') -Raw
            $ci | Should -Not -Match 'skipping SARIF upload'
            $ci | Should -Match "Out-File -LiteralPath ./psscriptanalyzer\.sarif"
            $ci | Should -Match 'category: psscriptanalyzer\b'
        }

        It 'pins the image by digest and installs every package by hash' {
            # Every Dockerfile in the tree, the scanner pins under .github/scanners
            # included: a tag alone can be re-pointed at other content after review.
            # -Force: .github and .oss-scanner are hidden folders on Linux and would be skipped.
            $dockerfiles = @(Get-ChildItem -LiteralPath $script:RepoRoot -Recurse -File -Force -Filter Dockerfile |
                Where-Object { $_.FullName -notmatch '[\\/](\.git|node_modules|output)[\\/]' })
            $dockerfiles.Count | Should -BeGreaterOrEqual 3
            foreach ($df in $dockerfiles) {
                foreach ($m in [regex]::Matches((Get-Content -LiteralPath $df.FullName -Raw), '(?m)^FROM\s+(?<ref>\S+)')) {
                    $m.Groups['ref'].Value | Should -Match '@sha256:[0-9a-f]{64}$' -Because $df.FullName
                }
            }
            $docker = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.oss-scanner/Dockerfile') -Raw
            $docker | Should -Not -Match '\b(Install-Module|Install-PSResource)\b'
            $joined = $docker -replace '\\\r?\n\s*', ' '
            foreach ($m in [regex]::Matches($joined, 'pip3?\s+install\b[^\r\n]*')) {
                $m.Value | Should -Match '--require-hashes'
                $m.Value | Should -Match '--only-binary=:all:'
            }
            $req = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.oss-scanner/requirements.txt') -Raw
            foreach ($pkg in 'openpyxl', 'et-xmlfile', 'yamllint', 'pathspec', 'pyyaml') {
                $req | Should -Match "(?m)^$pkg==\d+(\.\d+)+ \\\s*\r?\n\s+--hash=sha256:[0-9a-f]{64}"
            }
        }
    }

    Context 'every workflow' {

        It '<Name>: suppresses a zizmor finding only with a stated reason' -ForEach $workflowCases {
            $text = Get-Content -LiteralPath $FullName -Raw
            foreach ($m in [regex]::Matches($text, '#\s*zizmor:\s*ignore\[[^\]]*\](?<rest>[^\r\n]*)')) {
                $m.Groups['rest'].Value.Trim().Length | Should -BeGreaterThan 10 -Because "'$($m.Value)' needs a reason after the audit name"
            }
        }

        It '<Name>: pins every action to a full commit SHA' -ForEach $workflowCases {
            $text = Get-Content -LiteralPath $FullName -Raw
            foreach ($m in [regex]::Matches($text, '(?m)^\s*(?:-\s*)?uses:\s*(?<ref>\S+)')) {
                $ref = $m.Groups['ref'].Value
                if ($ref.StartsWith('./')) { continue }
                $ref | Should -Match '@[0-9a-f]{40}$' -Because 'a tag or branch can be moved to other code after review'
            }
        }

        It '<Name>: names the exact release each pinned SHA is, not a moving major tag' -ForEach $workflowCases {
            # zizmor's online ref-version-mismatch audit caught "# v6" beside the
            # SHA of checkout v7.0.1; a major tag moves, so the comment must be
            # the full version the SHA was released as.
            $text = Get-Content -LiteralPath $FullName -Raw
            foreach ($m in [regex]::Matches($text, '(?m)^\s*(?:-\s*)?uses:\s*\S+@[0-9a-f]{40}(?<rest>[^\r\n]*)')) {
                $m.Groups['rest'].Value | Should -Match '\A\s+#\s+v\d+\.\d+\.\d+\s*\z' -Because "'$($m.Value.Trim())' needs '# vX.Y.Z'"
            }
        }

        It '<Name>: never leaves the checkout token on disk' -ForEach $workflowCases {
            $lines = Get-Content -LiteralPath $FullName
            for ($i = 0; $i -lt $lines.Count; $i++) {
                if ($lines[$i] -notmatch 'uses:\s*actions/checkout@') { continue }
                $window = ($lines[($i + 1)..([Math]::Min($i + 6, $lines.Count - 1))]) -join "`n"
                $window | Should -Match 'persist-credentials:\s*false' -Because "the checkout at line $($i + 1) must not persist the token"
            }
        }

        It '<Name>: declares a concurrency group' -ForEach $workflowCases {
            (Get-Content -LiteralPath $FullName -Raw) | Should -Match '(?m)^concurrency:'
        }

        It '<Name>: grants no write access at the workflow level' -ForEach $workflowCases {
            $text = Get-Content -LiteralPath $FullName -Raw
            $text | Should -Not -Match '(?m)^permissions:\s*(read-all|write-all)\s*$'
            $top = [regex]::Match($text, '(?ms)^permissions:\s*\r?\n(?<body>(?:^[ \t]+\S[^\r\n]*\r?\n)+)')
            if ($top.Success) { $top.Groups['body'].Value | Should -Not -Match ':\s*write\b' }
        }
    }
}
