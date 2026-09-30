#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.IREntryPoints.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Runs the two REAL incident-response entry points
             (Invoke-NRGEmailAssessment.ps1, Invoke-NRGSignInTriage.ps1) in fresh
             child processes against stand-in Microsoft Graph modules, and
             asserts what a reader is told: the verdict, the JSON health block,
             the HTML and Markdown wording, that reports are generated, and the
             exit code. The earlier suite called evaluators in-process and never
             launched these scripts, which is how an unsupported parameter stopped
             both of them after collection and stayed green.
             The invariant: a failed, truncated or unrun required check must
             never produce a green "no indicators" conclusion.
    Service boundary: a stub Microsoft.Graph.Authentication module whose
    Invoke-MgGraphRequest answers from a per-test scenario file. Nothing
    touches a network or a tenant.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Incident-response entry points, run for real against a stubbed Graph boundary' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent (Split-Path -Parent $PSScriptRoot) } else { (Get-Location).Path }
        $script:Tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-ir-entry-" + [guid]::NewGuid().ToString('N'))
        $script:Mods = Join-Path $script:Tmp 'mods'
        New-Item -ItemType Directory -Path $script:Mods -Force | Out-Null

        # Stand-ins for the two modules the manifest requires. Versions sit inside
        # the manifest's allowed range.
        $graphDir = Join-Path $script:Mods 'Microsoft.Graph.Authentication' '2.40.0'
        New-Item -ItemType Directory -Path $graphDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $graphDir 'Microsoft.Graph.Authentication.psd1') -Encoding utf8 -Value "@{ RootModule = 'Microsoft.Graph.Authentication.psm1'; ModuleVersion = '2.40.0'; GUID = 'b0b0b0b0-1111-4222-8333-444444444444'; FunctionsToExport = '*'; CmdletsToExport = @(); AliasesToExport = @() }"
        Set-Content -LiteralPath (Join-Path $graphDir 'Microsoft.Graph.Authentication.psm1') -Encoding utf8 -Value @'
function Connect-MgGraph { [CmdletBinding()] param($Scopes, $ContextScope, [switch] $NoWelcome, $TenantId) }
function Disconnect-MgGraph { [CmdletBinding()] param() }
function Get-MgContext { [pscustomobject]@{ Account = $env:NRG_TEST_ACCOUNT; TenantId = '00000000-0000-0000-0000-00000000abcd'; Scopes = @() } }
function Invoke-MgGraphRequest {
    [CmdletBinding()] param($Uri, $Method, $OutputType, $Headers)
    $sc = Get-Content -LiteralPath $env:NRG_TEST_SCENARIO -Raw | ConvertFrom-Json -AsHashtable -Depth 30
    foreach ($r in @($sc.routes)) {
        if ($Uri -match $r.match) {
            if ($r.ContainsKey('throw')) { throw [string]$r.throw }
            return $r.body
        }
    }
    return @{ value = @() }
}
'@
        $exoDir = Join-Path $script:Mods 'ExchangeOnlineManagement' '3.10.1'
        New-Item -ItemType Directory -Path $exoDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $exoDir 'ExchangeOnlineManagement.psd1') -Encoding utf8 -Value "@{ RootModule = 'ExchangeOnlineManagement.psm1'; ModuleVersion = '3.10.1'; GUID = 'c0c0c0c0-1111-4222-8333-555555555555'; FunctionsToExport = @(); CmdletsToExport = @(); AliasesToExport = @() }"
        Set-Content -LiteralPath (Join-Path $exoDir 'ExchangeOnlineManagement.psm1') -Encoding utf8 -Value '# stand-in'

        # A benign mailbox answer for each route the collectors read. $Routes are
        # tried first, so a scenario overrides by prepending its own.
        $script:Benign = {
            param([string] $Upn = 'alice@corp.example', [bool] $ViaUsers = $false)
            $enc = [uri]::EscapeDataString($Upn)
            $prefix = if ($ViaUsers) { "users/$enc" } else { 'me' }
            @(
                @{ match = [regex]::Escape("/v1.0/${prefix}?") + '.*displayName'; body = @{ id = 'u1'; displayName = $Upn; mail = $Upn; userPrincipalName = $Upn } }
                @{ match = 'authentication/methods'; body = @{ value = @(@{ '@odata.type' = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'; id = 'm1'; displayName = 'Phone' }) } }
            )
        }
        $script:Run = {
            param([string] $Script, [string] $ArgText, $Routes, [string] $Account = 'admin@corp.example', [string] $RepoRoot = $script:Root)
            $case = Join-Path $script:Tmp ([guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $case -Force | Out-Null
            $scenario = Join-Path $case 'scenario.json'
            (@{ routes = @($Routes) } | ConvertTo-Json -Depth 30) | Set-Content -LiteralPath $scenario -Encoding utf8
            $out = Join-Path $case 'out'
            $old = @{ P = $env:PSModulePath; S = $env:NRG_TEST_SCENARIO; A = $env:NRG_TEST_ACCOUNT }
            try {
                $env:PSModulePath = $script:Mods + [System.IO.Path]::PathSeparator + $env:PSModulePath
                $env:NRG_TEST_SCENARIO = $scenario
                $env:NRG_TEST_ACCOUNT = $Account
                $cmd = "& '$(Join-Path $RepoRoot $Script)' $ArgText -OutputPath '$out'; exit `$LASTEXITCODE"
                $text = & pwsh -NoProfile -NonInteractive -Command $cmd 2>&1 | Out-String
                $code = $LASTEXITCODE
            } finally { $env:PSModulePath = $old.P; $env:NRG_TEST_SCENARIO = $old.S; $env:NRG_TEST_ACCOUNT = $old.A }
            $file = { param($pat) @(Get-ChildItem -LiteralPath $out -Filter $pat -ErrorAction SilentlyContinue | Select-Object -First 1)[0] }
            $json = & $file '*results.json'; if (-not $json) { $json = & $file '*triage.json' }
            $html = & $file '*.html'; $md = & $file '*.md'
            [ordered]@{
                ExitCode = $code; Console = $text
                Json = $(if ($json) { Get-Content -LiteralPath $json.FullName -Raw | ConvertFrom-Json -Depth 30 } else { $null })
                Html = $(if ($html) { Get-Content -LiteralPath $html.FullName -Raw } else { '' })
                Md   = $(if ($md)   { Get-Content -LiteralPath $md.FullName -Raw }   else { '' })
            }
        }
        $script:Email = {
            param($Routes, [string] $RepoRoot = $script:Root) & $script:Run 'Invoke-NRGEmailAssessment.ps1' "-UserPrincipalName 'alice@corp.example' -NonInteractive" $Routes 'alice@corp.example' $RepoRoot
        }
        # A copy of the tool whose inbox-rule evaluator throws: black-box fault
        # injection for "a required evaluator failed", with no test hook in the
        # shipped code.
        $script:Faulty = Join-Path $script:Tmp 'faulty-copy'
        New-Item -ItemType Directory -Path $script:Faulty -Force | Out-Null
        foreach ($item in Get-ChildItem -LiteralPath $script:Root -Force | Where-Object { $_.Name -notin @('.git', 'Testing', 'docs', 'output', 'sample-report', 'sample-headers', 'baselines') }) {
            Copy-Item -LiteralPath $item.FullName -Destination $script:Faulty -Recurse -Force
        }
        $ev = Join-Path $script:Faulty 'Email-IR' 'Evaluators' 'Test-NRGEmailControls.ps1'
        $src = Get-Content -LiteralPath $ev -Raw
        $needle = "function Test-NRGEmailControlInboxRules {`n    [CmdletBinding()] param()"
        if (-not $src.Contains($needle)) { throw 'fault-injection anchor not found' }
        Set-Content -LiteralPath $ev -Encoding utf8 -Value ($src.Replace($needle, $needle + "`n    throw 'injected evaluator fault'"))
    }
    AfterAll { if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue } }

    Context 'Invoke-NRGEmailAssessment.ps1' {

        It 'complete, benign evidence: reports are written, health is complete, the verdict is the green one scoped to the evidence read' {
            $r = & $script:Email (& $script:Benign)
            $r.Json | Should -Not -BeNullOrEmpty -Because $r.Console
            $r.Json.Metadata.CollectionComplete | Should -BeTrue -Because ($r.Json.Metadata.CollectionGaps -join '; ')
            $r.Html | Should -Match 'NO STRONG INDICATORS IN THE EVIDENCE READ'
            $r.Md   | Should -Match 'NO STRONG INDICATORS IN THE EVIDENCE READ'
            @($r.Json.Exceptions).Count | Should -Be 0 -Because ((@($r.Json.Exceptions) | ForEach-Object { "$($_.Source): $($_.Message)" }) -join '; ')
            $r.ExitCode | Should -Be 0 -Because $r.Console
        }

        It 'a required read that failed: NOT CLEARED, never green, exit 3, and the gap is named in JSON, HTML and Markdown' {
            $routes = @(@{ match = 'SentItems/messages'; throw = 'Graph 403 Forbidden' }) + @(& $script:Benign)
            $r = & $script:Email $routes
            $r.Json.Metadata.CollectionComplete | Should -BeFalse
            ($r.Json.Metadata.CollectionGaps -join ' ') | Should -Match 'IR-MailboxSentItems'
            foreach ($t in $r.Html, $r.Md) {
                $t | Should -Match 'NOT CLEARED'
                $t | Should -Not -Match 'NO STRONG INDICATORS'
            }
            $r.ExitCode | Should -Be 3
        }

        It 'a read that stopped at its page cap: NOT CLEARED, with the page cap named' {
            $routes = @(@{ match = 'SentItems/messages'; body = @{ value = @(); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/me/mailFolders/SentItems/messages?next=1' } }) + @(& $script:Benign)
            $r = & $script:Email $routes
            $r.Json.Metadata.CollectionComplete | Should -BeFalse
            ($r.Json.Metadata.CollectionGaps -join ' ') | Should -Match 'page cap'
            $r.Html | Should -Match 'NOT CLEARED'
            $r.Html | Should -Not -Match 'NO STRONG INDICATORS'
            $r.ExitCode | Should -Be 3
        }

        It 'a required evaluator that throws is recorded as an assessment-health gap and cannot produce a green conclusion' {
            $r = & $script:Email (& $script:Benign) $script:Faulty
            @($r.Json.Metadata.EvaluatorFailures).Count | Should -BeGreaterThan 0 -Because $r.Console
            ($r.Json.Metadata.EvaluatorFailures -join ' ') | Should -Match 'Test-NRGEmailControlInboxRules did not finish: injected evaluator fault'
            $r.Json.Metadata.CollectionComplete | Should -BeFalse
            $r.Html | Should -Match 'NOT CLEARED'
            $r.Html | Should -Not -Match 'NO STRONG INDICATORS'
            $r.Md   | Should -Match 'did not finish'
            $r.ExitCode | Should -Be 3
        }

        It 'a rule that only forwards (Graph omits the actions it does not set) is evaluated, not crashed on' {
            $routes = @(@{ match = 'messageRules'; body = @{ value = @(@{ id = 'r1'; displayName = 'fwd'; isEnabled = $true
                actions = @{ forwardTo = @(@{ emailAddress = @{ address = 'someone@gmail.example' } }) }; conditions = @{ subjectContains = @('invoice') } }) } }) + @(& $script:Benign)
            $r = & $script:Email $routes
            @($r.Json.Metadata.EvaluatorFailures).Count | Should -Be 0 -Because ($r.Json.Metadata.EvaluatorFailures -join '; ')
            @($r.Json.Findings | Where-Object { $_.ControlId -eq 'EMAIL-1.1' })[0].State | Should -Be 'Gap'
        }

        It 'a hidden-name rule that forwards out is "critical indicators", never "likely compromised", with complete evidence' {
            $routes = @(@{ match = 'messageRules'; body = @{ value = @(@{ id = 'r1'; displayName = '.'; isEnabled = $true
                actions = @{ forwardTo = @(@{ emailAddress = @{ address = 'attacker@evil.example' } }); delete = $true }; conditions = @{} }) } }) + @(& $script:Benign)
            $r = & $script:Email $routes
            $r.Html | Should -Match 'CRITICAL INDICATORS'
            $r.Html | Should -Not -MatchExactly 'LIKELY COMPROMISED'
            $r.Md   | Should -Match 'Heuristic indicators, not a confirmed compromise'
            @($r.Json.Findings | Where-Object { $_.ControlId -eq 'EMAIL-1.1' })[0].State | Should -Be 'Gap'
        }
    }

    Context 'Invoke-NRGSignInTriage.ps1' {
        BeforeAll {
            $script:Triage = {
                param($Routes) & $script:Run 'Invoke-NRGSignInTriage.ps1' "-NonInteractive -EnableThreatIntel:`$false -DeepDive 5 -MaxSignInEvents 100" $Routes
            }
            # Six wrong-password failures then a success from the same address, per user.
            $script:Cluster = {
                param([string] $Upn, [string] $Ip)
                $now = (Get-Date).ToUniversalTime()
                $ev = @(); $n = 6
                for ($i = 0; $i -lt $n; $i++) {
                    $ev += @{ id = "f$i-$Upn"; userPrincipalName = $Upn; createdDateTime = $now.AddMinutes(-($n - $i + 1)).ToString('o'); ipAddress = $Ip; status = @{ errorCode = 50126 } }
                }
                $ev += @{ id = "s-$Upn"; userPrincipalName = $Upn; createdDateTime = $now.ToString('o'); ipAddress = $Ip; status = @{ errorCode = 0 } }
                $ev
            }
        }

        It 'sign-in reads that failed: NOT CLEARED, never green, exit 3' {
            $routes = @(@{ match = 'auditLogs/signIns'; throw = 'Graph 403 Forbidden' })
            $r = & $script:Triage $routes
            $r.Json | Should -Not -BeNullOrEmpty -Because $r.Console
            $r.Json.Metadata.CollectionComplete | Should -BeFalse
            foreach ($t in $r.Html, $r.Md) {
                $t | Should -Match 'NOT CLEARED'
                $t | Should -Not -Match 'NO STRONG INDICATORS'
            }
            $r.ExitCode | Should -Be 3
        }

        It 'a recent read that stopped at its cap: NOT CLEARED with the cap named' {
            $routes = @(@{ match = 'auditLogs/signIns'; body = @{ value = @(); '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?next=1' } })
            $r = & $script:Triage $routes
            $r.Json.Metadata.CollectionComplete | Should -BeFalse
            ($r.Json.Metadata.CollectionGaps -join ' ') | Should -Match 'stopped at'
            $r.Html | Should -Not -Match 'NO STRONG INDICATORS'
        }

        It 'complete, benign reads: green verdict scoped to the events read, exit 0 with no exceptions' {
            $r = & $script:Triage @()
            $r.Json.Metadata.CollectionComplete | Should -BeTrue -Because ($r.Json.Metadata.CollectionGaps -join '; ')
            $r.Html | Should -Match 'NO STRONG INDICATORS IN THE EVENTS READ'
        }

        It 'two flagged users: each dive is recorded with its own evidence, findings carry their own subject, and the report names both' {
            $events = @(& $script:Cluster 'alice@corp.example' '203.0.113.5') + @(& $script:Cluster 'bob@corp.example' '198.51.100.7')
            $routes = @(@{ match = 'auditLogs/signIns.*anonymizedIPAddress'; body = @{ value = @() } }
                        @{ match = 'auditLogs/signIns'; body = @{ value = $events } }) +
                      @(& $script:Benign 'alice@corp.example' $true) + @(& $script:Benign 'bob@corp.example' $true)
            # alice has a hidden-name forwarding rule; bob's mailbox is clean.
            $aliceRule = @{ match = 'users/alice%40corp\.example/mailFolders/Inbox/messageRules'; body = @{ value = @(@{ id = 'r1'; displayName = '.'; isEnabled = $true
                actions = @{ forwardTo = @(@{ emailAddress = @{ address = 'attacker@evil.example' } }) }; conditions = @{} }) } }
            $r = & $script:Triage (@($aliceRule) + $routes)
            $r.Json | Should -Not -BeNullOrEmpty -Because $r.Console
            @($r.Json.DeepDives).Count | Should -Be 2
            $upns = @($r.Json.DeepDives | ForEach-Object { $_.UserPrincipalName })
            $upns | Should -Contain 'alice@corp.example'
            $upns | Should -Contain 'bob@corp.example'
            $aliceRuleFinding = @($r.Json.Findings | Where-Object { $_.ControlId -eq 'EMAIL-1.1' -and $_.Subject -eq 'alice@corp.example' })
            $aliceRuleFinding.Count | Should -Be 1
            $aliceRuleFinding[0].State | Should -Be 'Gap'
            $bobRuleFinding = @($r.Json.Findings | Where-Object { $_.ControlId -eq 'EMAIL-1.1' -and $_.Subject -eq 'bob@corp.example' })
            $bobRuleFinding.Count | Should -Be 1
            $bobRuleFinding[0].State | Should -Be 'Satisfied' -Because "alice's rule must not be attributed to bob"
            $r.Html | Should -Match 'alice@corp.example'
            $r.Html | Should -Match 'bob@corp.example'
            $r.Html | Should -Match 'CRITICAL INDICATORS'
            $r.Html | Should -Not -MatchExactly 'CONFIRMED COMPROMISE|LIKELY COMPROMISED'
            $r.ExitCode | Should -Be 10 -Because 'a Critical finding crosses the threshold'
        }

        It 'a required per-user evaluator that throws makes that dive Incomplete and the run NOT CLEARED' {
            $events = @(& $script:Cluster 'alice@corp.example' '203.0.113.5')
            $routes = @(@{ match = 'auditLogs/signIns.*anonymizedIPAddress'; body = @{ value = @() } }, @{ match = 'auditLogs/signIns'; body = @{ value = $events } }) + @(& $script:Benign 'alice@corp.example' $true)
            $r = & $script:Run 'Invoke-NRGSignInTriage.ps1' "-NonInteractive -EnableThreatIntel:`$false -DeepDive 5 -MaxSignInEvents 100" $routes 'admin@corp.example' $script:Faulty
            $dive = @($r.Json.DeepDives | Where-Object { $_.UserPrincipalName -eq 'alice@corp.example' })[0]
            $dive.Status | Should -Be 'Incomplete' -Because $r.Console
            ($dive.Failures -join ' ') | Should -Match 'Test-NRGEmailControlInboxRules'
            $r.Json.Metadata.CollectionComplete | Should -BeFalse
            ($r.Json.Metadata.CollectionGaps -join ' ') | Should -Match 'alice@corp.example'
        }
    }
}
