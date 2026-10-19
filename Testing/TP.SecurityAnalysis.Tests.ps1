#Requires -Version 7.0
#
# TP.SecurityAnalysis.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# PSScriptAnalyzer's security rules (Invoke-Expression, plain-text passwords,
# unencrypted authentication, broken hashes) are Warning severity, and the
# PSScriptAnalyzer job fails on Error only, so they were reported and never
# stopped a merge. tools/Invoke-TPSecurityAnalysis.ps1 runs them on their own
# and fails on any finding, an in-source suppression included.
#
# CI also installed its modules by version range with no hash check, so a
# republished or substituted gallery package would have run with the job's
# token. tools/Install-TPPinnedModule.ps1 installs each by exact version and
# SHA-256. These tests drive both scripts' functions and pin the CI wiring.

Describe 'PowerShell security analysis and pinned CI modules' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'tools/Install-TPPinnedModule.ps1') -DefinitionsOnly
        . (Join-Path $script:RepoRoot 'tools/Invoke-TPSecurityAnalysis.ps1') -DefinitionsOnly
        $script:Pins = Import-PowerShellDataFile -LiteralPath (Join-Path $script:RepoRoot 'tools/pinned-modules.psd1')
        $script:Settings = Import-PowerShellDataFile -LiteralPath (Join-Path $script:RepoRoot 'PSScriptAnalyzerSecurity.psd1')
        $script:Ci = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.github/workflows/ci.yml') -Raw
        $script:Workflows = @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot '.github/workflows') -File -Filter '*.yml')

        # A package shaped like a gallery .nupkg: the module files plus the
        # NuGet metadata, optionally with one hostile entry name.
        function New-TestPackage {
            param([string] $Path, [string] $ModuleName, [string] $ExtraEntry)
            $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create)
            $zip = [System.IO.Compression.ZipArchive]::new($fs, [System.IO.Compression.ZipArchiveMode]::Create)
            try {
                foreach ($name in @("$ModuleName.psd1", "$ModuleName.psm1", 'lib/inner.txt', '[Content_Types].xml', '_rels/.rels', 'package/services/x.psmdcp', "$ModuleName.nuspec") + @($ExtraEntry | Where-Object { $_ })) {
                    $w = [System.IO.StreamWriter]::new($zip.CreateEntry($name).Open())
                    $w.Write("content of $name"); $w.Dispose()
                }
            } finally { $zip.Dispose(); $fs.Dispose() }
        }
    }

    Context 'Pin file' {

        It 'pins PSScriptAnalyzer, InjectionHunter, Pester and Pode' {
            foreach ($n in 'PSScriptAnalyzer', 'InjectionHunter', 'Pester', 'Pode') { $script:Pins.Keys | Should -Contain $n }
        }

        It 'pins every module to an exact version and a full SHA-256' {
            foreach ($n in $script:Pins.Keys) {
                $pin = Get-TPModulePin -Name $n -PinFile (Join-Path $script:RepoRoot 'tools/pinned-modules.psd1')
                $pin.Version | Should -Match '\A\d+\.\d+\.\d+\z'
                $pin.Sha256 | Should -Match '\A[0-9a-f]{64}\z'
            }
        }

        It 'refuses a version range, a short hash and an unknown module' {
            $f = Join-Path $TestDrive 'pins.psd1'
            Set-Content -LiteralPath $f -Value "@{ A = @{ Version = '[1.0.0,2.0.0]'; Sha256 = '$('a' * 64)' }; B = @{ Version = '1.0.0'; Sha256 = 'abc' } }"
            { Get-TPModulePin -Name A -PinFile $f } | Should -Throw '*exact x.y.z*'
            { Get-TPModulePin -Name B -PinFile $f } | Should -Throw '*SHA-256*'
            { Get-TPModulePin -Name C -PinFile $f } | Should -Throw '*No pin*'
        }
    }

    Context 'Installer' {

        It 'installs a package whose hash matches, without the NuGet metadata' {
            $pkg = Join-Path $TestDrive 'good.nupkg'
            New-TestPackage -Path $pkg -ModuleName 'Demo'
            $pin = [pscustomobject]@{ Name = 'Demo'; Version = '1.2.3'; Sha256 = (Get-FileHash -LiteralPath $pkg -Algorithm SHA256).Hash.ToLowerInvariant() }
            $dest = Join-Path $TestDrive 'mods-good'
            $target = Install-TPModulePackage -Pin $pin -Destination $dest -PackagePath $pkg
            $target | Should -Be (Join-Path (Join-Path $dest 'Demo') '1.2.3')
            Test-Path -LiteralPath (Join-Path $target 'Demo.psd1') | Should -BeTrue
            Test-Path -LiteralPath (Join-Path $target 'lib/inner.txt') | Should -BeTrue
            foreach ($meta in '[Content_Types].xml', '_rels', 'package', 'Demo.nuspec') {
                Test-Path -LiteralPath (Join-Path $target $meta) | Should -BeFalse
            }
        }

        It 'refuses a package whose hash differs and installs nothing' {
            $pkg = Join-Path $TestDrive 'tampered.nupkg'
            New-TestPackage -Path $pkg -ModuleName 'Demo'
            $pin = [pscustomobject]@{ Name = 'Demo'; Version = '1.2.3'; Sha256 = ('0' * 64) }
            $dest = Join-Path $TestDrive 'mods-bad'
            { Install-TPModulePackage -Pin $pin -Destination $dest -PackagePath $pkg } | Should -Throw '*does not match*refused*'
            Test-Path -LiteralPath (Join-Path $dest 'Demo') | Should -BeFalse
        }

        It 'refuses a package entry that would land outside the module folder' {
            $pkg = Join-Path $TestDrive 'slip.nupkg'
            New-TestPackage -Path $pkg -ModuleName 'Demo' -ExtraEntry '../../escaped.txt'
            $pin = [pscustomobject]@{ Name = 'Demo'; Version = '1.2.3'; Sha256 = (Get-FileHash -LiteralPath $pkg -Algorithm SHA256).Hash }
            $dest = Join-Path $TestDrive 'mods-slip'
            { Install-TPModulePackage -Pin $pin -Destination $dest -PackagePath $pkg } | Should -Throw '*outside*refused*'
            Test-Path -LiteralPath (Join-Path $TestDrive 'escaped.txt') | Should -BeFalse
            Test-Path -LiteralPath (Join-Path $dest 'escaped.txt') | Should -BeFalse
        }

        It 'downloads from the gallery over HTTPS only' {
            $text = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'tools/Install-TPPinnedModule.ps1') -Raw
            [regex]::Matches($text, 'https?://[^\s''"]+').Value | ForEach-Object { $_ | Should -Match '\Ahttps://www\.powershellgallery\.com/' }
        }
    }

    Context 'Security rules' {

        It 'runs every PSScriptAnalyzer security rule at every severity' {
            foreach ($rule in 'PSAvoidUsingInvokeExpression', 'PSAvoidUsingPlainTextForPassword', 'PSAvoidUsingConvertToSecureStringWithPlainText',
                              'PSUsePSCredentialType', 'PSAvoidUsingUsernameAndPasswordParams', 'PSAvoidUsingAllowUnencryptedAuthentication',
                              'PSAvoidUsingBrokenHashAlgorithms', 'PSAvoidUsingComputerNameHardcoded') {
                $script:Settings.IncludeRules | Should -Contain $rule
            }
            foreach ($sev in 'Error', 'Warning', 'Information') { $script:Settings.Severity | Should -Contain $sev }
            $script:Settings.Keys | Should -Not -Contain 'ExcludeRules'
        }

        It 'counts in-source suppressions as findings' {
            (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'tools/Invoke-TPSecurityAnalysis.ps1') -Raw) | Should -Match 'Invoke-ScriptAnalyzer [^\r\n]*-IncludeSuppressed'
        }

        It 'reports every finding as a problem and a clean run as none' {
            $root = $TestDrive
            $findings = @(
                [pscustomobject]@{ ScriptPath = (Join-Path $root 'a/x.ps1'); Line = 3; Column = 1; RuleName = 'PSAvoidUsingInvokeExpression'; Severity = 'Warning'; Message = 'iex' },
                [pscustomobject]@{ ScriptPath = (Join-Path $root 'y.ps1'); Line = 0; Column = 0; RuleName = 'PSUsePSCredentialType'; Severity = 'Information'; Message = 'cred' }
            )
            $problems = @(Get-TPSecurityAnalysisProblem -Findings $findings -RepoRoot $root)
            $problems.Count | Should -Be 2
            $problems[0] | Should -Match '\Aa/x\.ps1:3 PSAvoidUsingInvokeExpression \(Warning\)'
            @(Get-TPSecurityAnalysisProblem -Findings @() -RepoRoot $root).Count | Should -Be 0
            @(Get-TPSecurityAnalysisProblem -Findings $null -RepoRoot $root).Count | Should -Be 0
        }

        It 'writes SARIF 2.1.0 with every finding as an error and positions of at least 1' {
            $root = $TestDrive
            $findings = @([pscustomobject]@{ ScriptPath = (Join-Path $root 'y.ps1'); Line = 0; Column = 0; RuleName = 'PSUsePSCredentialType'; Severity = 'Information'; Message = 'cred' })
            $sarif = ConvertTo-TPAnalyzerSarif -Findings $findings -RepoRoot $root -ToolName 'PSScriptAnalyzer (security rules)' -ToolVersion '1.25.0'
            $json = $sarif | ConvertTo-Json -Depth 12 | ConvertFrom-Json
            $json.version | Should -Be '2.1.0'
            @($json.runs[0].results).Count | Should -Be 1
            $json.runs[0].results[0].level | Should -Be 'error'
            $json.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri | Should -Be 'y.ps1'
            $json.runs[0].results[0].locations[0].physicalLocation.region.startLine | Should -Be 1
            $empty = ConvertTo-TPAnalyzerSarif -Findings @() -RepoRoot $root -ToolName 't' -ToolVersion '1'
            @($empty.runs[0].results).Count | Should -Be 0
        }

        It 'finds a planted Invoke-Expression and plain-text password (when the pinned analyzer is installed)' {
            $have = Get-Module -ListAvailable PSScriptAnalyzer | Where-Object { [string]$_.Version -eq $script:Pins.PSScriptAnalyzer.Version }
            if (-not $have) { Set-ItResult -Skipped -Because "PSScriptAnalyzer $($script:Pins.PSScriptAnalyzer.Version) is not installed here; CI runs the real analyzer in its own job" ; return }
            Import-Module PSScriptAnalyzer -RequiredVersion $script:Pins.PSScriptAnalyzer.Version -Force
            $dir = Join-Path $TestDrive 'plant'
            $null = New-Item -ItemType Directory -Path $dir
            Set-Content -LiteralPath (Join-Path $dir 'p.ps1') -Value 'function Get-X { param([string]$Password) Invoke-Expression $Password }'
            $r = @(Invoke-ScriptAnalyzer -Path $dir -Recurse -Settings (Join-Path $script:RepoRoot 'PSScriptAnalyzerSecurity.psd1') -IncludeSuppressed)
            $r.RuleName | Should -Contain 'PSAvoidUsingInvokeExpression'
            $r.RuleName | Should -Contain 'PSAvoidUsingPlainTextForPassword'
        }
    }

    Context 'InjectionHunter baseline' {

        BeforeAll {
            # A finding as PSScriptAnalyzer reports it: the rule name, the file
            # and the extent of the flagged expression in that file.
            function New-TestFinding {
                param([string] $Path, [string] $Rule, [scriptblock] $Pick)
                $tokens = $null; $errors = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
                $node = $ast.Find($Pick, $true)
                [pscustomobject]@{ RuleName = $Rule; ScriptPath = $Path; Extent = $node.Extent; Line = $node.Extent.StartLineNumber; Column = 1; Severity = 'Warning'; Message = 'm' }
            }
            $script:IsReplace = { param($a) $a -is [System.Management.Automation.Language.BinaryExpressionAst] -and $a.Operator -eq 'Ireplace' }
            $script:Baseline = (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'tools/injection-baseline.json') -Raw | ConvertFrom-Json).entries
        }

        It 'lets a replace through only when every replacement is the empty string' {
            $f = Join-Path $TestDrive 'esc.ps1'
            Set-Content -LiteralPath $f -Value '$a -replace ''x'', '''''
            Test-TPRemovalOnlyReplace -Finding (New-TestFinding $f 'InjectionRisk.UnsafeEscaping' $script:IsReplace) | Should -BeTrue
            Set-Content -LiteralPath $f -Value '$a -replace "''", "''''"'
            Test-TPRemovalOnlyReplace -Finding (New-TestFinding $f 'InjectionRisk.UnsafeEscaping' $script:IsReplace) | Should -BeFalse
            Set-Content -LiteralPath $f -Value '$a -replace "''", "''''" -replace ''y'', '''''
            Test-TPRemovalOnlyReplace -Finding (New-TestFinding $f 'InjectionRisk.UnsafeEscaping' $script:IsReplace) | Should -BeFalse -Because 'one escaping replace in the chain is enough'
            Set-Content -LiteralPath $f -Value '$a -replace ''x'', $b'
            Test-TPRemovalOnlyReplace -Finding (New-TestFinding $f 'InjectionRisk.UnsafeEscaping' $script:IsReplace) | Should -BeFalse -Because 'a replacement that is not a constant is not proven empty'
            Set-Content -LiteralPath $f -Value '$a -replace ''x'', ''''' 
            Test-TPRemovalOnlyReplace -Finding (New-TestFinding $f 'InjectionRisk.StaticPropertyInjection' $script:IsReplace) | Should -BeFalse -Because 'only the escaping rule has this exemption'
        }

        It 'passes a reviewed finding, fails a new one, and counts copies' {
            $f = Join-Path $TestDrive 'dyn.ps1'
            Set-Content -LiteralPath $f -Value "`$o.`$p`n`$o.`$p"
            $pick = { param($a) $a -is [System.Management.Automation.Language.MemberExpressionAst] }
            $one = New-TestFinding $f 'InjectionRisk.StaticPropertyInjection' $pick
            $entry = [pscustomobject]@{ Path = 'dyn.ps1'; Rule = 'InjectionRisk.StaticPropertyInjection'; Text = '$o.$p'; Count = 1; Reason = 'Reviewed: the name comes from a literal list.' }
            $r = Compare-TPInjectionBaseline -Findings @($one) -Baseline @($entry) -RepoRoot $TestDrive
            $r.Reviewed | Should -Be 1; @($r.New).Count | Should -Be 0; @($r.Stale).Count | Should -Be 0
            $r = Compare-TPInjectionBaseline -Findings @($one, $one) -Baseline @($entry) -RepoRoot $TestDrive
            @($r.New).Count | Should -Be 1 -Because 'a second copy of a reviewed line is new code'
            $r = Compare-TPInjectionBaseline -Findings @($one) -Baseline @() -RepoRoot $TestDrive
            @($r.New).Count | Should -Be 1
        }

        It 'fails a baseline entry nothing matches any more' {
            $entry = [pscustomobject]@{ Path = 'gone.ps1'; Rule = 'InjectionRisk.Create'; Text = '[scriptblock]::Create($b)'; Count = 1; Reason = 'Reviewed: the text is a literal in the test.' }
            $r = Compare-TPInjectionBaseline -Findings @() -Baseline @($entry) -RepoRoot $TestDrive
            @($r.Stale).Count | Should -Be 1
        }

        It 'refuses an entry with no reason, a short reason, a missing field or a rule from another tool' {
            @(Test-TPInjectionBaselineEntry -Baseline @([pscustomobject]@{ Path = 'a'; Rule = 'InjectionRisk.Create'; Text = 't'; Count = 1; Reason = 'ok' })).Count | Should -BeGreaterThan 0
            @(Test-TPInjectionBaselineEntry -Baseline @([pscustomobject]@{ Path = 'a'; Rule = 'InjectionRisk.Create'; Text = 't'; Count = 1 })).Count | Should -BeGreaterThan 0
            @(Test-TPInjectionBaselineEntry -Baseline @([pscustomobject]@{ Path = 'a'; Rule = 'PSAvoidUsingInvokeExpression'; Text = 't'; Count = 1; Reason = 'A reason that is long enough to read.' })).Count | Should -BeGreaterThan 0
            @(Test-TPInjectionBaselineEntry -Baseline @([pscustomobject]@{ Path = 'a'; Rule = 'InjectionRisk.Create'; Text = 't'; Count = 0; Reason = 'A reason that is long enough to read.' })).Count | Should -BeGreaterThan 0
        }

        It 'the shipped baseline is well formed and names files that exist' {
            @($script:Baseline).Count | Should -BeGreaterThan 0
            @(Test-TPInjectionBaselineEntry -Baseline $script:Baseline) | Should -BeNullOrEmpty
            foreach ($e in $script:Baseline) { Test-Path -LiteralPath (Join-Path $script:RepoRoot $e.Path) | Should -BeTrue -Because $e.Path }
        }

        It 'never accepts a security-rule finding or an Invoke-Expression through the baseline' {
            foreach ($e in $script:Baseline) {
                $e.Rule | Should -Not -Be 'InjectionRisk.InvokeExpression'
                $e.Rule | Should -Not -Be 'InjectionRisk.CommandInjection'
            }
        }

        It 'flags a planted ScriptBlock.Create of a variable as new (when the pinned modules are installed)' {
            $ihPin = $script:Pins.InjectionHunter.Version
            $ih = Get-Module -ListAvailable InjectionHunter | Where-Object { [string]$_.Version -eq $ihPin } | Select-Object -First 1
            $pssa = Get-Module -ListAvailable PSScriptAnalyzer | Where-Object { [string]$_.Version -eq $script:Pins.PSScriptAnalyzer.Version }
            if (-not $ih -or -not $pssa) { Set-ItResult -Skipped -Because 'the pinned PSScriptAnalyzer and InjectionHunter are not installed here; CI runs them in their own job'; return }
            Import-Module PSScriptAnalyzer -RequiredVersion $script:Pins.PSScriptAnalyzer.Version -Force
            $dir = Join-Path $TestDrive 'ihplant'
            $null = New-Item -ItemType Directory -Path $dir
            Set-Content -LiteralPath (Join-Path $dir 'p.ps1') -Value 'function Invoke-X { param([string] $UserText) & ([scriptblock]::Create($UserText)) }'
            $found = @(Invoke-ScriptAnalyzer -Path $dir -Recurse -CustomRulePath (Join-Path $ih.ModuleBase 'InjectionHunter.psm1') -IncludeRule 'Measure-*' | Where-Object { $_.RuleName -like 'InjectionRisk.*' })
            $r = Compare-TPInjectionBaseline -Findings $found -Baseline $script:Baseline -RepoRoot $dir
            @($r.New).RuleName | Should -Contain 'InjectionRisk.Create'
        }
    }

    Context 'Pinned-module freshness and the OSS Scanner image' {

        BeforeAll {
            . (Join-Path $script:RepoRoot 'tools/Test-TPPinnedModuleFreshness.ps1') -DefinitionsOnly
            $script:Now = [datetime]::new(2026, 10, 19, 0, 0, 0, [DateTimeKind]::Utc)
            function New-Release { param([string] $V, [int] $DaysAgo) [pscustomobject]@{ Version = [version]$V; Published = $script:Now.AddDays(-$DaysAgo) } }
            # A feed entry as Invoke-RestMethod returns it from the gallery's v2 OData feed.
            function New-Entry { param([string] $Title, [string] $V, [string] $Pre = 'false', [string] $Pub = '2026-08-11T18:25:36.24')
                [xml]$x = "<entry xmlns:d='d' xmlns:m='m'><title>$Title</title><m:properties><d:Version>$V</d:Version><d:IsPrerelease>$Pre</d:IsPrerelease><d:Published>$Pub</d:Published></m:properties></entry>"
                [pscustomobject]@{ title = $Title; properties = [pscustomobject]@{ Version = $V; IsPrerelease = $Pre; Published = $Pub } }
            }
            $script:Image = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.github/workflows/oss-scanner-image.yml') -Raw
            $script:Docker = Get-Content -LiteralPath (Join-Path $script:RepoRoot '.oss-scanner/Dockerfile') -Raw
        }

        It 'reads only the module''s own stable releases from the feed' {
            $entries = @((New-Entry 'Pode' '2.14.1'), (New-Entry 'Pode.Kestrel' '9.9.9'), (New-Entry 'Pode' '3.0.0' 'true'), (New-Entry 'Pode' 'not-a-version'), (New-Entry 'Pode' '2.13.0' 'false' 'garbage'))
            $r = @(Get-TPGalleryReleases -Name 'Pode' -Entries $entries)
            $r.Count | Should -Be 1
            [string]$r[0].Version | Should -Be '2.14.1'
        }

        It 'fails on a newer release of the pinned major that is past the cooldown' {
            $v = Get-TPPinFreshness -Name 'Pester' -Pinned '5.8.0' -Releases @((New-Release '5.9.1' 60), (New-Release '6.2.0' 40)) -Now $script:Now -CooldownDays 7
            $v.Status | Should -Be 'Newer'
            $v.LatestSameMajor | Should -Be '5.9.1'
            $v.LatestOverall | Should -Be '6.2.0'
        }

        It 'reports a new major version without failing, and ignores a release still in its cooldown' {
            (Get-TPPinFreshness -Name 'Pester' -Pinned '5.9.1' -Releases @((New-Release '5.9.1' 60), (New-Release '6.2.0' 40)) -Now $script:Now -CooldownDays 7).Status | Should -Be 'NewMajor'
            (Get-TPPinFreshness -Name 'X' -Pinned '1.0.0' -Releases @((New-Release '1.0.0' 90), (New-Release '1.0.1' 2)) -Now $script:Now -CooldownDays 7).Status | Should -Be 'Current'
        }

        It 'says Unknown, never Current, when no release was read' {
            (Get-TPPinFreshness -Name 'X' -Pinned '1.0.0' -Releases @() -Now $script:Now -CooldownDays 7).Status | Should -Be 'Unknown'
            (Get-TPPinFreshness -Name 'X' -Pinned '1.0.0' -Releases $null -Now $script:Now -CooldownDays 7).Status | Should -Be 'Unknown'
        }

        It 'runs the freshness check weekly and on demand only, never on a pull request' {
            $script:Image | Should -Match '(?m)^  pinned-module-freshness:'
            $script:Image | Should -Match "if: github\.event_name == 'schedule' \|\| github\.event_name == 'workflow_dispatch'"
            $script:Image | Should -Match 'Test-TPPinnedModuleFreshness\.ps1'
        }

        It 'runs the image''s tests through the gate and fails the build job on its exit code' {
            $script:Docker | Should -Match 'tools/Invoke-TPTestGate\.ps1 -ResultPath /oss-test/pester-results\.xml'
            $script:Docker | Should -Match 'echo \$\? > /oss-test/exit-code'
            $script:Docker | Should -Not -Match 'Invoke-Pester|FailedCount' -Because 'the gate, never a FailedCount check, judges the suite'
            $script:Image | Should -Match 'docker cp oss-test:/oss-test'
            $script:Image | Should -Match 'if \[ "\$\{code\}" != "0" \]; then'
        }

        It 'takes the base image''s security updates when it builds' {
            $script:Docker | Should -Match 'apt-get upgrade -y'
        }
    }

    Context 'CI wiring' {

        It 'has a security-analysis job that installs the pinned analyzer and runs the gate' {
            $script:Ci | Should -Match '(?m)^  security-analysis:'
            $script:Ci | Should -Match 'Install-TPPinnedModule\.ps1 -Name PSScriptAnalyzer, InjectionHunter'
            $script:Ci | Should -Match 'Invoke-TPSecurityAnalysis\.ps1 -SarifPath'
            $script:Ci | Should -Match 'category: psscriptanalyzer-security'
        }

        It 'installs Pester and Pode through the pinned installer and imports the pinned version' {
            $script:Ci | Should -Match 'Install-TPPinnedModule\.ps1 -Name Pester -Destination'
            $script:Ci | Should -Match 'Install-TPPinnedModule\.ps1 -Name Pester, Pode -Destination'
            ([regex]::Matches($script:Ci, 'Import-Module Pester -RequiredVersion \(Import-PowerShellDataFile \./tools/pinned-modules\.psd1\)\.Pester\.Version')).Count | Should -Be 2
            $script:Ci | Should -Match 'Import-Module PSScriptAnalyzer -RequiredVersion \(Import-PowerShellDataFile \./tools/pinned-modules\.psd1\)\.PSScriptAnalyzer\.Version'
        }

        It 'no workflow installs a PowerShell module by range or without a hash' {
            foreach ($wf in $script:Workflows) {
                $text = Get-Content -LiteralPath $wf.FullName -Raw
                $text | Should -Not -Match '\b(Install-Module|Install-PSResource|Save-Module|Save-PSResource|Update-Module)\b' -Because "$($wf.Name) must install modules through tools/Install-TPPinnedModule.ps1"
            }
        }
    }
}
