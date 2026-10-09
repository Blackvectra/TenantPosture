#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    TP.IREntryPoints.Tests.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: Runs the two REAL incident-response entry points
             (Invoke-TPEmailAssessment.ps1, Invoke-TPSignInTriage.ps1) in fresh
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
        $script:Tmp  = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-ir-entry-" + [guid]::NewGuid().ToString('N'))
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
function Get-MgContext { [pscustomobject]@{ Account = $env:TP_TEST_ACCOUNT; TenantId = '00000000-0000-0000-0000-00000000abcd'; Scopes = @() } }
function Invoke-MgGraphRequest {
    [CmdletBinding()] param($Uri, $Method, $OutputType, $Headers)
    $sc = Get-Content -LiteralPath $env:TP_TEST_SCENARIO -Raw | ConvertFrom-Json -AsHashtable -Depth 30
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
            $old = @{ P = $env:PSModulePath; S = $env:TP_TEST_SCENARIO; A = $env:TP_TEST_ACCOUNT }
            try {
                $env:PSModulePath = $script:Mods + [System.IO.Path]::PathSeparator + $env:PSModulePath
                $env:TP_TEST_SCENARIO = $scenario
                $env:TP_TEST_ACCOUNT = $Account
                $cmd = "& '$(Join-Path $RepoRoot $Script)' $ArgText -OutputPath '$out'; exit `$LASTEXITCODE"
                $text = & pwsh -NoProfile -NonInteractive -Command $cmd 2>&1 | Out-String
                $code = $LASTEXITCODE
            } finally { $env:PSModulePath = $old.P; $env:TP_TEST_SCENARIO = $old.S; $env:TP_TEST_ACCOUNT = $old.A }
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
            param($Routes, [string] $RepoRoot = $script:Root, [string] $Extra = '') & $script:Run 'Invoke-TPEmailAssessment.ps1' "-UserPrincipalName 'alice@corp.example' -NonInteractive $Extra" $Routes 'alice@corp.example' $RepoRoot
        }
        # A copy of the tool whose inbox-rule evaluator throws: black-box fault
        # injection for "a required evaluator failed", with no test hook in the
        # shipped code.
        $script:Faulty = Join-Path $script:Tmp 'faulty-copy'
        New-Item -ItemType Directory -Path $script:Faulty -Force | Out-Null
        foreach ($item in Get-ChildItem -LiteralPath $script:Root -Force | Where-Object { $_.Name -notin @('.git', 'Testing', 'docs', 'output', 'sample-report', 'sample-headers', 'baselines') }) {
            Copy-Item -LiteralPath $item.FullName -Destination $script:Faulty -Recurse -Force
        }
        $ev = Join-Path $script:Faulty 'Email-IR' 'Evaluators' 'Test-TPEmailControls.ps1'
        $src = Get-Content -LiteralPath $ev -Raw
        $needle = "function Test-TPEmailControlInboxRules {`n    [CmdletBinding()] param()"
        if (-not $src.Contains($needle)) { throw 'fault-injection anchor not found' }
        Set-Content -LiteralPath $ev -Encoding utf8 -Value ($src.Replace($needle, $needle + "`n    throw 'injected evaluator fault'"))
        # A second copy where EVERY incident-response detector throws (later definitions
        # in the same file replace the real ones), so a run ends with zero findings.
        $script:FaultyAll = Join-Path $script:Tmp 'faulty-all-copy'
        Copy-Item -LiteralPath $script:Faulty -Destination $script:FaultyAll -Recurse -Force
        foreach ($rel in @(@('Email-IR', 'Evaluators', 'Test-TPEmailControls.ps1'), @('Email-IR', 'Evaluators', 'Test-TPSignInControls.ps1'))) {
            $f = Join-Path $script:FaultyAll @rel
            $text = Get-Content -LiteralPath $f -Raw
            $names = [regex]::Matches($text, '(?m)^function (Test-NRG(?:EmailControl|SignInControl)\w+)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
            $over = ($names | ForEach-Object { "`nfunction $_ { [CmdletBinding()] param([Parameter(ValueFromRemainingArguments)] `$Rest) throw 'injected evaluator fault' }" }) -join ''
            Set-Content -LiteralPath $f -Encoding utf8 -Value ($text + "`n" + $over)
        }
    }
    AfterAll { if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue } }

    Context 'Invoke-TPEmailAssessment.ps1' {

        It 'complete, benign evidence: reports are written, health is complete, the verdict is the green one scoped to the evidence read' {
            $r = & $script:Email (& $script:Benign)
            $r.Json | Should -Not -BeNullOrEmpty -Because $r.Console
            $r.Json.Metadata.CollectionComplete | Should -BeTrue -Because ($r.Json.Metadata.CollectionGaps -join '; ')
            $r.Html | Should -Match 'NO STRONG INDICATORS IN THE EVIDENCE READ'
            $r.Md   | Should -Match 'NO STRONG INDICATORS IN THE EVIDENCE READ'
            @($r.Json.Exceptions).Count | Should -Be 0 -Because ((@($r.Json.Exceptions) | ForEach-Object { "$($_.Source): $($_.Message)" }) -join '; ')
            $r.ExitCode | Should -Be 0 -Because $r.Console
        }

        It 'a mailbox that Graph answers NotFound for is reported as not read on the console, never as collected, with the likely cause stated as unconfirmed' {
            $routes = @(
                @{ match = 'SentItems/messages'; throw = 'Response status code does not indicate success: NotFound (Not Found).' }
                @{ match = 'mailFolders/inbox/messages'; throw = 'Response status code does not indicate success: NotFound (Not Found).' }
                @{ match = 'messageRules'; throw = 'Response status code does not indicate success: NotFound (Not Found).' }
            ) + @(& $script:Benign)
            $r = & $script:Email $routes
            $r.Console | Should -Not -Match 'Mailbox data collected'
            $r.Console | Should -Match 'Mailbox data NOT read'
            $r.Console | Should -Match 'no Exchange Online mailbox.*not confirmed'
            $r.Json.Metadata.CollectionComplete | Should -BeFalse
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
            ($r.Json.Metadata.EvaluatorFailures -join ' ') | Should -Match 'Test-TPEmailControlInboxRules did not finish: injected evaluator fault'
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

        It 'Critical indicators with incomplete evidence: the Critical stays, the incompleteness is stated beside it, and exit code 3 outranks nothing unless -FailOnCriticalIoC' {
            $rule = @{ match = 'messageRules'; body = @{ value = @(@{ id = 'r1'; displayName = '.'; isEnabled = $true
                actions = @{ forwardTo = @(@{ emailAddress = @{ address = 'attacker@evil.example' } }); delete = $true }; conditions = @{} }) } }
            $routes = @(@{ match = 'SentItems/messages'; throw = 'Graph 403 Forbidden' }, $rule) + @(& $script:Benign)
            $r = & $script:Email $routes
            $r.Html | Should -Match 'CRITICAL INDICATORS'
            foreach ($t in $r.Html, $r.Md) { $t | Should -Match 'also incomplete'; $t | Should -Match 'IR-MailboxSentItems' }
            $r.Json.Metadata.CollectionComplete | Should -BeFalse
            $r.ExitCode | Should -Be 3
            $r2 = & $script:Email $routes $script:Root '-FailOnCriticalIoC'
            $r2.ExitCode | Should -Be 10 -Because 'a Critical crosses the threshold when the operator asked for it; the report still says incomplete'
            $r2.Html | Should -Match 'also incomplete'
        }

        It 'zero findings because every required detector failed is NOT CLEARED and exit 3, never "no findings" exit 2' {
            $r = & $script:Email (& $script:Benign) $script:FaultyAll
            @($r.Json.Findings).Count | Should -Be 0 -Because $r.Console
            @($r.Json.Metadata.EvaluatorFailures).Count | Should -BeGreaterThan 3
            $r.Json.Metadata.CollectionComplete | Should -BeFalse
            $r.Html | Should -Match 'NOT CLEARED'
            $r.Html | Should -Not -Match 'NO STRONG INDICATORS'
            $r.ExitCode | Should -Be 3
        }

        It 'the consent-grant read stopped at one page: EMAIL-4.1 is not cleared, never Satisfied, and the run is NOT CLEARED with exit 3' {
            $routes = @(@{ match = 'oauth2PermissionGrants'; body = @{ value = @(@{ id = 'g1'; clientId = 'sp1'; consentType = 'Principal'; scope = 'User.Read openid profile' })
                '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/me/oauth2PermissionGrants?$skiptoken=x' } }
                @{ match = 'servicePrincipals/sp1'; body = @{ displayName = 'Teams'; appId = 'a1'; publisherName = 'Microsoft' } }) + @(& $script:Benign)
            $r = & $script:Email $routes
            $r.Json | Should -Not -BeNullOrEmpty -Because $r.Console
            $f = @($r.Json.Findings | Where-Object { $_.ControlId -eq 'EMAIL-4.1' })[0]
            $f.State  | Should -Be 'NotApplicable'
            $f.Detail | Should -Match '^Not cleared'
            $r.Json.Metadata.CollectionComplete | Should -BeFalse
            ($r.Json.Metadata.CollectionGaps -join ' ') | Should -Match 'IR-UserConsents'
            $r.Html | Should -Match 'NOT CLEARED'
            $r.Html | Should -Not -Match 'NO STRONG INDICATORS'
            $r.ExitCode | Should -Be 3
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

    Context 'Invoke-TPSignInTriage.ps1' {
        BeforeAll {
            $script:Triage = {
                param($Routes) & $script:Run 'Invoke-TPSignInTriage.ps1' "-NonInteractive -EnableThreatIntel:`$false -DeepDive 5 -MaxSignInEvents 100" $Routes
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

        It 'every sign-in read failing (429, risky users included): NOT CLEARED, exit 3, and no SIGNIN control is Satisfied' {
            $r = & $script:Triage @(@{ match = '.'; throw = 'Response status code does not indicate success: TooManyRequests (Too Many Requests).' })
            $r.Json | Should -Not -BeNullOrEmpty -Because $r.Console
            $r.Json.Metadata.CollectionComplete | Should -BeFalse
            $sat = @($r.Json.Findings | Where-Object { $_.ControlId -like 'SIGNIN-*' -and $_.State -eq 'Satisfied' } | ForEach-Object { $_.ControlId })
            $sat | Should -BeNullOrEmpty -Because "nothing was read, so nothing can be cleared (Satisfied: $($sat -join ', '))"
            foreach ($t in $r.Html, $r.Md) { $t | Should -Match 'NOT CLEARED'; $t | Should -Not -Match 'NO STRONG INDICATORS' }
            $r.ExitCode | Should -Be 3
        }

        It 'the recent read truncated at its cap: NOT CLEARED, and no check that rests on it concludes "nothing found"' {
            $now = (Get-Date).ToUniversalTime()
            $atHome = @(1..3 | ForEach-Object { @{ id = "e$_"; userPrincipalName = 'a@corp.example'; createdDateTime = $now.AddHours(-$_).ToString('o'); ipAddress = '198.51.100.1'
                status = @{ errorCode = 0 }; location = @{ city = 'Fargo'; state = 'North Dakota'; countryOrRegion = 'US' }; riskEventTypes_v2 = @() } })
            $routes = @(
                @{ match = 'auditLogs/signIns.*anonymizedIPAddress'; body = @{ value = @() } }
                @{ match = 'auditLogs/signIns'; body = @{ value = $atHome; '@odata.nextLink' = 'https://graph.microsoft.com/v1.0/auditLogs/signIns?next=1' } }
            )
            $r = & $script:Triage $routes
            $r.Json | Should -Not -BeNullOrEmpty -Because $r.Console
            $r.Json.Metadata.CollectionComplete | Should -BeFalse
            foreach ($cid in 'SIGNIN-1.1', 'SIGNIN-1.3', 'SIGNIN-1.6', 'SIGNIN-2.1') {
                $f = @($r.Json.Findings | Where-Object { $_.ControlId -eq $cid })
                $f.Count | Should -Be 1 -Because "$cid should report"
                $f[0].State | Should -Not -Be 'Satisfied' -Because "$cid rests on the truncated recent read: $($f[0].Detail)"
            }
            $r.Html | Should -Match 'NOT CLEARED'
            $r.Html | Should -Not -Match 'NO STRONG INDICATORS'
            $r.ExitCode | Should -Be 3
        }

        It 'complete, benign reads: green verdict scoped to the events read, exit 0 with no exceptions' {
            $r = & $script:Triage @()
            $r.Json.Metadata.CollectionComplete | Should -BeTrue -Because ($r.Json.Metadata.CollectionGaps -join '; ')
            $r.Html | Should -Match 'NO STRONG INDICATORS IN THE EVENTS READ'
        }

        It 'Graph rejecting the sign-in property list (BadRequest) does not lose the section: the window is read without it, the rejection is logged, and the fallback is recorded' {
            $routes = @(
                @{ match = 'auditLogs/signIns.*select='; throw = 'Response status code does not indicate success: BadRequest (Bad Request).' }
                @{ match = 'auditLogs/signIns.*anonymizedIPAddress'; body = @{ value = @() } }
                @{ match = 'auditLogs/signIns'; body = @{ value = @() } }
            )
            $r = & $script:Triage $routes
            $r.Json | Should -Not -BeNullOrEmpty -Because $r.Console
            $r.Json.Metadata.CollectionComplete | Should -BeTrue -Because ($r.Json.Metadata.CollectionGaps -join '; ')
            $recent = $r.Json.RawData.'IR-SignIn-Recent'
            $recent.Data.SelectFallback | Should -BeTrue
            (@($r.Json.Exceptions) | ForEach-Object { $_.Message }) -join ' ' | Should -Match 'rejected the sign-in property list'
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
            $r = & $script:Run 'Invoke-TPSignInTriage.ps1' "-NonInteractive -EnableThreatIntel:`$false -DeepDive 5 -MaxSignInEvents 100" $routes 'admin@corp.example' $script:Faulty
            $dive = @($r.Json.DeepDives | Where-Object { $_.UserPrincipalName -eq 'alice@corp.example' })[0]
            $dive.Status | Should -Be 'Incomplete' -Because $r.Console
            ($dive.Failures -join ' ') | Should -Match 'Test-TPEmailControlInboxRules'
            $r.Json.Metadata.CollectionComplete | Should -BeFalse
            ($r.Json.Metadata.CollectionGaps -join ' ') | Should -Match 'alice@corp.example'
            # The console decision matches the recorded one: a dive whose detector failed is not "complete".
            $r.Console | Should -Match 'Deep-dive incomplete \(.*Test-TPEmailControlInboxRules.*\): alice@corp.example'
            $r.Console | Should -Not -Match 'Deep-dive complete: alice@corp.example'
            # Critical indicators plus incomplete evidence: both stay visible; the Critical sets exit 10.
            $r.Html | Should -Match 'CRITICAL INDICATORS'
            $r.Html | Should -Match 'also incomplete'
            $r.Md   | Should -Match 'also incomplete'
            $r.ExitCode | Should -Be 10
        }

        It 'zero findings because every detector failed is NOT CLEARED and exit 3, never "no findings" exit 2' {
            $r = & $script:Run 'Invoke-TPSignInTriage.ps1' "-NonInteractive -EnableThreatIntel:`$false -DeepDive 5 -MaxSignInEvents 100" @() 'admin@corp.example' $script:FaultyAll
            @($r.Json.Findings).Count | Should -Be 0 -Because $r.Console
            @($r.Json.Metadata.EvaluatorFailures).Count | Should -BeGreaterThan 3
            $r.Json.Metadata.CollectionComplete | Should -BeFalse
            $r.Html | Should -Match 'NOT CLEARED'
            $r.Html | Should -Not -Match 'NO STRONG INDICATORS'
            $r.ExitCode | Should -Be 3
        }
    }
    Context 'Invoke-TPBatchSignInTriage.ps1 rolls each client''s result into the batch honestly' {
        BeforeAll {
            # The real batch runner beside a stand-in triage script that exits with
            # the code chosen per tenant: the runner invokes the triage by path.
            $script:BatchDir = Join-Path $script:Tmp 'batch'
            New-Item -ItemType Directory -Path $script:BatchDir -Force | Out-Null
            Copy-Item -LiteralPath (Join-Path $script:Root 'Invoke-TPBatchSignInTriage.ps1') -Destination $script:BatchDir
            Set-Content -LiteralPath (Join-Path $script:BatchDir 'Invoke-TPSignInTriage.ps1') -Encoding utf8 -Value @'
param($TenantId, $OutputPath, $WindowDays, $DeepDive, $DeepDiveMinScore, $EnableThreatIntel, [switch] $NonInteractive, [switch] $SkipMailDive)
$null = [System.IO.Directory]::CreateDirectory($OutputPath)   # as the real triage does first
$codes = $env:TP_TEST_EXITS | ConvertFrom-Json -AsHashtable
exit ([int]$codes[$TenantId])
'@
            $script:Batch = {
                param([int[]] $Codes)
                $case = Join-Path $script:Tmp ([guid]::NewGuid().ToString('N'))
                New-Item -ItemType Directory -Path $case -Force | Out-Null
                $clients = @(); $map = @{}
                for ($i = 0; $i -lt $Codes.Count; $i++) {
                    $tid = '00000000-0000-0000-0000-{0:D12}' -f ($i + 1)
                    $clients += [ordered]@{ ClientName = "Client$i"; TenantDomain = "client$i.example"; TenantId = $tid; Active = $true }
                    $map[$tid] = $Codes[$i]
                }
                $cfg = Join-Path $case 'clients.json'
                (@{ clients = $clients } | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $cfg -Encoding utf8
                $out = Join-Path $case 'out'
                $old = @{ P = $env:PSModulePath; E = $env:TP_TEST_EXITS }
                try {
                    $env:PSModulePath = $script:Mods + [System.IO.Path]::PathSeparator + $env:PSModulePath
                    $env:TP_TEST_EXITS = ($map | ConvertTo-Json -Compress)
                    $cmd = "& '$(Join-Path $script:BatchDir 'Invoke-TPBatchSignInTriage.ps1')' -ClientsFile '$cfg' -OutputRoot '$out'; exit `$LASTEXITCODE"
                    $text = & pwsh -NoProfile -NonInteractive -Command $cmd 2>&1 | Out-String
                    $code = $LASTEXITCODE
                } finally { $env:PSModulePath = $old.P; $env:TP_TEST_EXITS = $old.E }
                $sum = @(Get-ChildItem -LiteralPath $out -Filter 'triage-summary-*.md' -ErrorAction SilentlyContinue)[0]
                [ordered]@{ ExitCode = $code; Console = $text; Summary = $(if ($sum) { Get-Content -LiteralPath $sum.FullName -Raw } else { '' }) }
            }
        }

        It 'a client whose triage was not cleared (child exit 3) is reported as not cleared, ranks above complete clients, and the batch exits 3' {
            $r = & $script:Batch @(0, 3)
            $r.Summary | Should -Match '\| Client1 \| client1\.example \| \*\*NOT CLEARED\*\*'
            $r.Summary | Should -Not -Match 'ExitCode-3'
            $r.Summary.IndexOf('Client1') | Should -BeLessThan $r.Summary.IndexOf('Client0') -Because 'a client that was not cleared is on the call list before a completed one'
            $r.Summary | Should -Match '(?s)## Not cleared or not assessed.*Client1'
            $r.ExitCode | Should -Be 3 -Because $r.Console
        }

        It 'an authentication failure (child exit 1) or a fatal error (child exit 4) makes the batch fail, and is named' {
            $r = & $script:Batch @(0, 1)
            $r.Summary | Should -Match 'AUTH FAILED'
            $r.ExitCode | Should -Be 1 -Because $r.Console
            $r = & $script:Batch @(0, 4, 1, 3)
            $r.Summary | Should -Match 'ERROR'
            $r.ExitCode | Should -Be 4 -Because 'the most severe failure wins'
        }

        It 'a Critical client still sets exit 10 and sorts first; every client completing with no Critical exits 0' {
            $r = & $script:Batch @(3, 10, 4)
            $r.ExitCode | Should -Be 10
            $r.Summary.IndexOf('Client1') | Should -BeLessThan $r.Summary.IndexOf('Client2')
            (& $script:Batch @(0, 2)).ExitCode | Should -Be 0
        }
    }
}
