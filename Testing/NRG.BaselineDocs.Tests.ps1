#Requires -Version 7.0
#Requires -Modules @{ ModuleName='Pester'; ModuleVersion='5.5.0' }
#
# NRG.BaselineDocs.Tests.ps1
#
# Keeps baselines/*.md in agreement with Config/controls.json.
#
# The hand-written baselines drifted onto an earlier control-numbering scheme
# and nobody noticed: of 32 documented controls only 3 still pointed at the
# control they described. AAD-1.4 was documented as "Global Administrator
# Count" while the shipped AAD-1.4 is "Sign-in Risk CA Policy"; EXO-1.1 was
# documented as SPF while the shipped EXO-1.1 is "Mailbox Audit Logging
# Enabled". A baseline document that names a different control than the tool
# scores is worse than no document — a client reading it is told they were
# assessed against something they were not.
#
# The documents are now generated from controls.json. This suite fails the
# build whenever they disagree, so a control added, renamed, or re-severitied
# without regenerating cannot ship.

Describe 'baselines/*.md agree with Config/controls.json' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }

        $script:Controls = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 |
            ConvertFrom-Json).controls)

        $script:ById = @{}
        foreach ($c in $script:Controls) { $script:ById[$c.ControlId] = $c }

        # Workload -> baseline file. Every workload in controls.json must have one.
        $script:WorkloadFile = @{
            AAD = 'aad.md';        EXO = 'exo.md';           DEF = 'defender.md'
            TMS = 'teams.md';      PVW = 'purview.md';       SPO = 'sharepoint.md'
            INT = 'intune.md';     PPL = 'powerplatform.md'; DNS = 'dns.md'
        }

        # Parse every "### <ID> — <Title>" heading out of the baseline docs,
        # along with the Severity line that follows it.
        $script:Documented = @()
        foreach ($kv in $script:WorkloadFile.GetEnumerator()) {
            $path = Join-Path $script:RepoRoot (Join-Path 'baselines' $kv.Value)
            if (-not (Test-Path -LiteralPath $path)) { continue }
            $text = Get-Content -LiteralPath $path -Raw -Encoding utf8
            foreach ($m in [regex]::Matches($text, '(?m)^### ([A-Z]{3}-\d+\.\d+) — (.+)$')) {
                $after = $text.Substring($m.Index, [Math]::Min(400, $text.Length - $m.Index))
                $sev = [regex]::Match($after, '\*\*Severity:\*\*\s*(\w+)')
                $script:Documented += [pscustomobject]@{
                    File      = $kv.Value
                    Workload  = $kv.Key
                    ControlId = $m.Groups[1].Value
                    Title     = $m.Groups[2].Value.Trim()
                    Severity  = if ($sev.Success) { $sev.Groups[1].Value } else { '' }
                }
            }
        }
    }

    It 'a baseline document exists for every workload in controls.json' {
        $missing = @()
        foreach ($wl in @($script:Controls.Workload | Sort-Object -Unique)) {
            if (-not $script:WorkloadFile.ContainsKey($wl)) { $missing += "$wl (no file mapped)"; continue }
            $p = Join-Path $script:RepoRoot (Join-Path 'baselines' $script:WorkloadFile[$wl])
            if (-not (Test-Path -LiteralPath $p)) { $missing += "$wl -> $($script:WorkloadFile[$wl])" }
        }
        $missing -join ', ' | Should -BeNullOrEmpty `
            -Because 'a workload with no baseline document is a block of controls the documentation silently omits'
    }

    It 'the parser found the headings (guards against a vacuous pass)' {
        $script:Documented.Count | Should -BeGreaterThan 150 `
            -Because 'if the heading format changed, every assertion below would pass by matching nothing'
    }

    It 'every documented control ID exists in controls.json' {
        $bad = @($script:Documented |
            Where-Object { -not $script:ById.ContainsKey($_.ControlId) } |
            ForEach-Object { '{0}: {1}' -f $_.File, $_.ControlId })
        $bad -join "`n" | Should -BeNullOrEmpty `
            -Because 'a documented control the tool does not ship describes an assessment the client never received'
    }

    It 'every documented title matches the shipped control title' {
        $bad = @()
        foreach ($d in $script:Documented) {
            $c = $script:ById[$d.ControlId]
            if ($null -ne $c -and $c.Title -ne $d.Title) {
                $bad += ('{0}: {1} documented as "{2}" but ships as "{3}"' -f $d.File, $d.ControlId, $d.Title, $c.Title)
            }
        }
        $bad -join "`n" | Should -BeNullOrEmpty `
            -Because 'this is the exact drift that put 29 of 32 baseline sections on the wrong control'
    }

    It 'every documented severity matches the shipped control severity' {
        $bad = @()
        foreach ($d in $script:Documented) {
            $c = $script:ById[$d.ControlId]
            if ($null -ne $c -and $d.Severity -and $c.Severity -ne $d.Severity) {
                $bad += ('{0}: {1} documented {2}, ships {3}' -f $d.File, $d.ControlId, $d.Severity, $c.Severity)
            }
        }
        $bad -join "`n" | Should -BeNullOrEmpty `
            -Because 'a baseline that under-rates a control tells the client a Critical gap is merely High'
    }

    It 'every control in controls.json is documented exactly once' {
        $docIds = @($script:Documented.ControlId)
        $dupes = @($docIds | Group-Object | Where-Object Count -gt 1 | ForEach-Object { $_.Name })
        $dupes -join ', ' | Should -BeNullOrEmpty -Because 'a control documented twice can be updated in one place only'

        $undocumented = @($script:Controls.ControlId | Where-Object { $_ -notin $docIds })
        $undocumented -join ', ' | Should -BeNullOrEmpty `
            -Because 'the baselines are advertised as the control reference, so an omitted control is an undocumented assessment'
    }

    It 'each control is documented in the file for its own workload' {
        $bad = @()
        foreach ($d in $script:Documented) {
            $c = $script:ById[$d.ControlId]
            if ($null -ne $c -and $c.Workload -ne $d.Workload) {
                $bad += ('{0}: {1} is a {2} control' -f $d.File, $d.ControlId, $c.Workload)
            }
        }
        $bad -join "`n" | Should -BeNullOrEmpty
    }

    It 'no baseline cites a superseded CIS benchmark edition' {
        $bad = @()
        foreach ($f in Get-ChildItem (Join-Path $script:RepoRoot 'baselines') -Filter '*.md' -File) {
            $t = Get-Content -LiteralPath $f.FullName -Raw -Encoding utf8
            if ($t -match 'CIS (Microsoft 365 )?Foundations Benchmark v[1-5]\b') {
                $bad += $f.Name
            }
        }
        $bad -join ', ' | Should -BeNullOrEmpty `
            -Because 'the tool scores against CIS M365 Foundations v6.0.1; citing v3 misstates the standard the client was measured against'
    }
}
