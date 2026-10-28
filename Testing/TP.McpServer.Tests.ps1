#Requires -Version 7.0
#
# TP.McpServer.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Guards Start-TPMcpServer.ps1 and Mcp/: the local, read-only Model Context
# Protocol server over saved assessment results.
#
# The protocol is tested over a REAL child process (pwsh running the entry
# script against a temporary output folder), because the failure that matters
# most for a stdio server is something other than a protocol message reaching
# standard output, and only the real process shows that. The fixtures carry the
# shape Invoke-TPAssessment.ps1 writes (Metadata, Findings, RawData, Exceptions,
# Coverage, BaselineCompliance), with identities in AffectedObjects and in the
# Detail prose, a raw inventory and an Exceptions array the server must never
# return, an older results file without the newer fields, and the incident-
# response outputs it must never serve.
#
# Data: writes only under a temporary folder. Network: none.

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    $script:Entry    = Join-Path $script:RepoRoot 'Start-TPMcpServer.ps1'
    $script:McpFiles = @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'Mcp') -Filter '*.ps1' -File | ForEach-Object { $_.FullName })
    $script:Pwsh     = (Get-Process -Id $PID).Path

    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('tp-mcp-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    $script:Out = Join-Path $script:Tmp 'output'
    $null = New-Item -ItemType Directory -Force -Path $script:Out

    # Identities the server must never return by default.
    $script:Upn        = 'jane.doe@contoso.example'
    $script:Display    = 'Jane Q Doe'
    # Named only by the change-impact view, never in a finding: proves the server
    # learns the identities that view names before it answers.
    $script:CiName     = 'Kim Changeimpact Person'
    $script:CiUpn      = 'kim.changeimpact@contoso.example'
    $script:Operator   = 'operator.person@msp.example'
    $script:TenantId   = '11111111-2222-3333-4444-555555555555'
    $script:RawMarker  = 'RAWDATA-ONLY-MARKER-7f3a'
    $script:RawUpn     = 'raw.only.person@contoso.example'
    $script:ExcMarker  = 'EXCEPTION-TEXT-MARKER-91c2'
    $script:Rlo        = [string][char]0x202E

    $write = {
        param([string] $Path, $Object)
        $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Path)
        Set-Content -LiteralPath $Path -Value ($Object | ConvertTo-Json -Depth 20) -Encoding utf8
    }
    $finding = {
        param([string] $Id, [string] $State, [string] $Severity = 'High', [string] $Detail = 'Detail.', [string] $Instance = '', $Affected = @(), [string] $Title = 'A control')
        [ordered]@{
            ControlId = $Id; State = $State; Category = 'Test'; Title = $Title; Severity = $Severity
            Detail = $Detail; CurrentValue = ''; RequiredValue = ''; Remediation = 'Fix it.'
            AffectedObjects = @($Affected); Instance = $Instance; FrameworkIds = @('NIST:IA-2')
            Timestamp = '2026-10-16T10:00:00.0000000+00:00'
        }
    }
    $baselineRow = {
        param([string] $Id, [string] $Observed, [string] $Status, [string] $Code)
        [ordered]@{
            ControlId = $Id; Title = "Row $Id"; RequiredTier = 'Minimum'; Owner = 'MSP'; ExpectedState = 'x'; SlaClass = 'Standard'
            ObservedState = $Observed; ObservedFindingState = ''; Constraint = 'None'; Disposition = 'Normal'
            EffectivenessState = 'Unknown'; EffectivenessCapability = 'NotCollected'; EffectivenessDetail = ''
            DependsOn = @(); DependencyState = 'None'; EvidenceSource = 'x'; EvidenceTimestamp = ''; EvidenceFreshness = 'Current'
            FreshnessClass = 'Weekly'; NotVerifiedCause = ''; ReasonCode = $Code; Reason = "Reason for $Id."; Detail = "Excluded $($script:Upn)."
            ExceptionSummary = ''; BaselineStatus = $Status
        }
    }

    # ── A current flat run (a command-line run) ──
    $script:FlatId = 'CONTOSO-20261016-100000'
    $flatFindings = @(
        (& $finding 'AAD-1.2' 'Partial' 'Critical' "MFA policy excludes $($script:Display) ($($script:Upn)).$($script:Rlo)" '' @(
            [ordered]@{ Principal = 'user:aaaaaaaa-0000-0000-0000-000000000001'; Exclusion = 'SharedByEveryQualifyingPolicy'; DisplayName = $script:Display; UserPrincipalName = $script:Upn }))
        (& $finding 'AAD-1.1' 'Satisfied' 'Critical' 'Legacy authentication is blocked.')
        (& $finding 'DNS-1.1' 'Gap' 'High' 'No SPF record.' 'contoso.example')
        (& $finding 'DNS-1.1' 'Satisfied' 'High' 'SPF present.' 'fabrikam.example')
        (& $finding 'EXO-1.1' 'NotApplicable' 'High' 'EXO-MailboxConfig was not collected; not assessed.')
        (& $finding 'DEF-1.1' 'Gap' 'Medium' 'Preset policies off.')
        (& $finding 'SPO-1.1' 'Error' 'Low' 'The check threw.')
    )
    & $write (Join-Path $script:Out "$($script:FlatId)-results.json") ([ordered]@{
        Metadata = [ordered]@{
            TenantDomain = 'contoso.onmicrosoft.com'; TenantId = $script:TenantId; Operator = $script:Operator
            AssessmentDate = 'October 16, 2026'; AssessmentTime = '2026-10-16T10:00:00.0000000+00:00'; ToolVersion = '4.14.3'
            QuickScan = $false; ThirdPartyEDR = ''; ThirdPartyAwareness = ''; BaselineVersion = '2.0'; TargetTier = 'Minimum'
            Maturity = [ordered]@{ Tier = 3; Label = 'Defined (provisional: evidence incomplete)'; ObservedLabel = 'Defined'; Score = 61; EvidenceComplete = $false; Qualification = '1 of 7 finding(s) produced no verdict.' }
            Brand = [ordered]@{ LogoUrl = 'https://cdn.example.com/logo.png' }
        }
        Findings = $flatFindings
        RawData = [ordered]@{
            'AAD-Inventory'     = [ordered]@{ CollectorId = 'AAD-Inventory'; Success = $true; Data = [ordered]@{ SubscribedSkus = @([ordered]@{ SkuPartNumber = 'SPB'; ServicePlans = @('AAD_PREMIUM', 'INTUNE_A') }) } }
            'AAD-Users'         = [ordered]@{ CollectorId = 'AAD-Users'; Success = $true; Data = [ordered]@{ Users = @([ordered]@{ userPrincipalName = $script:RawUpn; note = $script:RawMarker }) } }
            'EXO-MailboxConfig' = [ordered]@{ CollectorId = 'EXO-MailboxConfig'; Success = $false; Data = [ordered]@{} }
        }
        Exceptions = @([ordered]@{ Source = 'EXO'; Message = $script:ExcMarker })
        Coverage = [ordered]@{ 'EXO-MailboxConfig' = [ordered]@{ Status = 'Failed'; Note = 'Exchange did not connect.' } }
        Connections = [ordered]@{ TenantId = $script:TenantId; Account = $script:Operator }
        BaselineCompliance = [ordered]@{
            Available = $true; BaselineVersion = '2.0'; TargetTier = 'Minimum'; AsOf = '2026-10-16T10:00:00Z'; ExceptionsPath = '/secret/path/exceptions.psd1'
            Summary = [ordered]@{ RequiredControls = 3; Satisfied = 1; Failed = 1; NotVerified = 1; NotApplicable = 0; LicenseBlocked = 0; ApprovedException = 0 }
            EvidenceCoverage = [ordered]@{ Required = 3; Applicable = 3; Known = 2; Unknown = 1; LicenseBlocked = 0; NotApplicable = 0; Percent = 66.7; Gaps = [ordered]@{ CollectorUnavailable = 1 }; Rule = 'Not a score.' }
            EffectivenessCoverage = [ordered]@{ Required = 3; Known = 0; Effective = 0; Ineffective = 0; Percent = 0; CapabilityCollected = 0; Rule = 'Not a score.' }
            Controls = @(
                (& $baselineRow 'AAD-1.1' 'Satisfied' 'Satisfied' 'Satisfied')
                (& $baselineRow 'AAD-1.2' 'Failed' 'Failed' 'ControlFailed')
                (& $baselineRow 'EXO-1.1' 'NotVerified' 'NotVerified' 'CollectorUnavailable')
            )
        }
        ChangeImpact = [ordered]@{
            Available = $true; Note = ''; RunScope = 'Full'; ScopeNotice = ''
            Summary = [ordered]@{ ImplementNow = 1; NeedsPlanning = 0; CouldBreakAccounts = 1; LicenseDecision = 0; AccountsNamed = 1 }
            ImplementNow = @([ordered]@{ ControlId = 'DEF-1.1'; Title = 'Preset policies'; Severity = 'Medium'; State = 'Gap' })
            NeedsPlanning = @()
            CouldBreakAccounts = @([ordered]@{ ControlId = 'AAD-1.2'; Title = 'MFA for all users'; Severity = 'Critical'; State = 'Partial'
                Why = 'Requiring MFA blocks accounts that cannot complete it.'
                Evidence = @([ordered]@{ Type = 'MfaUnregistered'; Label = 'No MFA method registered'; Role = 'WouldBreak'; Status = 'Named'; Complete = $true; Count = 1; NotShown = 0; Note = ''
                    Accounts = @([ordered]@{ DisplayName = $script:CiName; UserPrincipalName = $script:CiUpn; ObjectId = 'bbbbbbbb-0000-0000-0000-000000000002'; Detail = 'No MFA method registered.' }) }) })
            LicenseDecision = @()
            EmergencyAccess = [ordered]@{ Type = 'EmergencyAccess'; Label = 'Emergency-access accounts to exclude'; Role = 'MustExclude'; Status = 'NotRead'; Complete = $false; Count = 0; Accounts = @(); NotShown = 0; Note = 'None on record.' }
        }
    })

    # ── A later run of the same tenant, GUI layout ──
    $script:Folder = 'contoso.example'
    $script:LaterId = 'CONTOSO-20261023-100000'
    & $write (Join-Path $script:Out $script:Folder "$($script:LaterId)-results.json") ([ordered]@{
        Metadata = [ordered]@{ TenantDomain = 'contoso.onmicrosoft.com'; TenantId = $script:TenantId.ToUpperInvariant(); AssessmentTime = '2026-10-23T10:00:00.0000000+00:00'; ToolVersion = '4.14.3' }
        Findings = @(
            (& $finding 'AAD-1.2' 'Satisfied' 'Critical')
            (& $finding 'AAD-1.1' 'Gap' 'Critical')
            (& $finding 'DNS-1.1' 'NotApplicable' 'High' 'Lookup failed.' 'contoso.example')
            (& $finding 'EXO-1.1' 'Gap' 'High')
            (& $finding 'DEF-1.1' 'Partial' 'Medium')
            (& $finding 'INT-1.1' 'Gap' 'High')
        )
        RawData = [ordered]@{}; Exceptions = @(); Coverage = [ordered]@{}
    })

    # ── Another tenant, and a run with no tenant ID ──
    & $write (Join-Path $script:Out 'fabrikam.example' 'FABRIKAM-20261020-100000-results.json') ([ordered]@{
        Metadata = [ordered]@{ TenantDomain = 'fabrikam.onmicrosoft.com'; TenantId = '99999999-2222-3333-4444-555555555555'; ToolVersion = '4.14.3' }
        Findings = @((& $finding 'AAD-1.1' 'Gap')); RawData = @{}; Exceptions = @()
    })
    # An older results file: minimal metadata, no TenantId, no Coverage, no
    # BaselineCompliance, no Maturity, findings without the newer fields.
    $script:OldId = 'OLDTENANT-20250101-090000'
    & $write (Join-Path $script:Out $script:Folder "$($script:OldId)-results.json") ([ordered]@{
        Metadata = [ordered]@{ TenantDomain = 'contoso.onmicrosoft.com'; AssessmentDate = 'January 01, 2025' }
        Findings = @(
            [ordered]@{ ControlId = 'AAD-1.1'; State = 'Gap'; Title = 'Legacy auth'; Severity = 'Critical'; Detail = 'old' }
            [ordered]@{ ControlId = 'EXO-1.1'; State = 'Satisfied' }
        )
    })

    # ── What must never be served ──
    & $write (Join-Path $script:Out 'jane.doe_contoso.example' '20261016-100000-email-results.json') ([ordered]@{ Metadata = [ordered]@{ TenantId = $script:TenantId }; Findings = @((& $finding 'EMAIL-1.1' 'Gap')); RawData = @{} })
    & $write (Join-Path $script:Out 'IR-Triage' '20261016-100000-signin-triage.json') ([ordered]@{ Metadata = @{}; Findings = @(); DeepDives = @() })
    & $write (Join-Path $script:Out 'IR-Triage' 'TRIAGE-20261016-100000-results.json') ([ordered]@{ Metadata = @{}; Findings = @() })
    & $write (Join-Path $script:Out 'sneaky.example' 'SNEAKY-20261016-100000-results.json') ([ordered]@{ Metadata = @{ TenantDomain = 'sneaky.example' }; Findings = @((& $finding 'SIGNIN-1.1' 'Gap')); DeepDives = @(@{ User = $script:Upn }) })
    $script:FlatFolderId = 'HIDDEN-20261016-100000'
    & $write (Join-Path $script:Out '_flat' "$($script:FlatFolderId)-results.json") ([ordered]@{ Metadata = @{ TenantDomain = 'hidden.example' }; Findings = @() })

    # ── Driving the real server ──
    $script:Request = {
        param([int] $Id, [string] $Method, $Params)
        $m = [ordered]@{ jsonrpc = '2.0'; id = $Id; method = $Method }
        if ($null -ne $Params) { $m['params'] = $Params }
        $m | ConvertTo-Json -Depth 20 -Compress
    }
    $script:Init = {
        param([string] $Version = '2025-11-25')
        @(
            (& $script:Request 0 'initialize' ([ordered]@{ protocolVersion = $Version; capabilities = @{}; clientInfo = @{ name = 'pester'; version = '1' } }))
            '{"jsonrpc":"2.0","method":"notifications/initialized"}'
        )
    }
    # Runs the server once over the given lines; returns the raw stdout lines
    # and the parsed responses keyed by id.
    $script:Serve = {
        param([string[]] $Lines, [string[]] $ExtraArgs = @())
        $errFile = Join-Path $script:Tmp ('err-' + [Guid]::NewGuid().ToString('N') + '.txt')
        $raw = @($Lines | & $script:Pwsh -NoProfile -NonInteractive -File $script:Entry -OutputRoot $script:Out @ExtraArgs 2>$errFile)
        $byId = @{}
        $parsed = [System.Collections.Generic.List[object]]::new()
        foreach ($l in $raw) {
            $o = $l | ConvertFrom-Json -AsHashtable -Depth 64
            $parsed.Add($o)
            if ($null -ne $o['id']) { $byId[[int]$o['id']] = $o }
        }
        [pscustomobject]@{ Raw = $raw; Parsed = $parsed.ToArray(); ById = $byId; Err = (Get-Content -LiteralPath $errFile -Raw -ErrorAction SilentlyContinue) }
    }
    $script:Call = {
        param([int] $Id, [string] $Tool, [hashtable] $Arguments = @{})
        & $script:Request $Id 'tools/call' ([ordered]@{ name = $Tool; arguments = $Arguments })
    }
    # The tool's answer from a response: structuredContent when sent, else the text.
    $script:Answer = {
        param($Response)
        $r = $Response['result']
        if ($r.Contains('structuredContent')) { return $r['structuredContent'] }
        return ($r['content'][0]['text'] | ConvertFrom-Json -AsHashtable -Depth 64)
    }

    # One server run that calls every tool with valid arguments (default privacy).
    $f = $script:Folder
    $script:AllCalls = @(& $script:Init) + @(
        (& $script:Request 1 'ping' $null)
        (& $script:Request 2 'tools/list' $null)
        (& $script:Call 10 'list_runs')
        (& $script:Call 11 'get_run_summary' @{ folder = '_flat'; id = $script:FlatId })
        (& $script:Call 12 'list_findings' @{ folder = '_flat'; id = $script:FlatId })
        (& $script:Call 13 'get_finding' @{ folder = '_flat'; id = $script:FlatId; controlId = 'AAD-1.2' })
        (& $script:Call 14 'get_control' @{ controlId = 'AAD-1.1' })
        (& $script:Call 15 'compare_runs' @{ folderA = '_flat'; idA = $script:FlatId; folderB = $f; idB = $script:LaterId })
        (& $script:Call 16 'get_baseline' @{ folder = '_flat'; id = $script:FlatId })
        (& $script:Call 17 'get_scope' @{ folder = '_flat'; id = $script:FlatId })
        (& $script:Call 18 'get_finding' @{ folder = '_flat'; id = $script:FlatId; controlId = 'DNS-1.1' })
        (& $script:Call 19 'get_finding' @{ folder = '_flat'; id = $script:FlatId; controlId = 'PVW-1.1' })
        (& $script:Call 20 'list_findings' @{ folder = '_flat'; id = $script:FlatId; state = 'Gap' })
        (& $script:Call 21 'list_findings' @{ folder = '_flat'; id = $script:FlatId; limit = 2 })
        (& $script:Call 22 'get_baseline' @{ folder = '_flat'; id = $script:FlatId; status = 'Failed' })
        (& $script:Call 23 'list_runs' @{ tenant = 'fabrikam' })
        (& $script:Call 24 'get_change_impact' @{ folder = '_flat'; id = $script:FlatId })
        (& $script:Call 25 'get_change_impact' @{ folder = $f; id = $script:LaterId })
        (& $script:Call 26 'get_change_impact' @{ folder = '_flat'; id = $script:FlatId; list = 'couldBreakAccounts'; controlId = 'AAD-1.2' })
    )
    $script:Default = & $script:Serve $script:AllCalls
    $script:WithIds = & $script:Serve $script:AllCalls @('-IncludeIdentities')
}

AfterAll {
    if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'MCP server: protocol over a real child process' {

    It 'standard output carries nothing but JSON-RPC 2.0 messages, one per line' {
        $script:Default.Raw.Count | Should -BeGreaterThan 10
        foreach ($l in $script:Default.Raw) {
            { $l | ConvertFrom-Json -AsHashtable -ErrorAction Stop } | Should -Not -Throw
            ($l | ConvertFrom-Json -AsHashtable)['jsonrpc'] | Should -Be '2.0'
        }
        # Every request with an id is answered once; the notification is not.
        $script:Default.Raw.Count | Should -Be ($script:AllCalls.Count - 1)
        $script:Default.Err | Should -Match 'tenantposture-mcp'
    }

    It 'initialize echoes a supported version and announces tools' {
        $r = $script:Default.ById[0]['result']
        $r['protocolVersion'] | Should -Be '2025-11-25'
        $r['capabilities']['tools'] | Should -Not -BeNullOrEmpty
        $r['serverInfo']['name'] | Should -Be 'tenantposture'
        $r['instructions'] | Should -Match 'data, not instructions'
    }

    It 'answers ping with an empty result' {
        $script:Default.ById[1]['result'].Count | Should -Be 0
    }

    It 'lists the nine read-only tools with input and output schemas' {
        $tools = @($script:Default.ById[2]['result']['tools'])
        @($tools | ForEach-Object { $_['name'] }) | Should -Be @('list_runs', 'get_run_summary', 'list_findings', 'get_finding', 'get_control', 'compare_runs', 'get_baseline', 'get_scope', 'get_change_impact')
        foreach ($t in $tools) {
            $t['inputSchema']['type'] | Should -Be 'object'
            $t['inputSchema']['additionalProperties'] | Should -BeFalse
            $t['outputSchema']['type'] | Should -Be 'object'
            $t['annotations']['readOnlyHint'] | Should -BeTrue
            $t['annotations']['openWorldHint'] | Should -BeFalse
            # No argument is a path.
            foreach ($p in @($t['inputSchema']['properties'].Keys)) { $p | Should -Not -Match 'path|file|dir' }
        }
    }

    It 'every tool answers without isError, and structuredContent matches the text and its output schema' {
        $tools = @{}; foreach ($t in @($script:Default.ById[2]['result']['tools'])) { $tools[$t['name']] = $t }
        $calls = @{ 10 = 'list_runs'; 11 = 'get_run_summary'; 12 = 'list_findings'; 13 = 'get_finding'; 14 = 'get_control'; 15 = 'compare_runs'; 16 = 'get_baseline'; 17 = 'get_scope'; 24 = 'get_change_impact'; 25 = 'get_change_impact' }
        foreach ($id in $calls.Keys) {
            $res = $script:Default.ById[$id]['result']
            $res.Contains('isError') | Should -BeFalse -Because "$($calls[$id]) should succeed: $($res['content'][0]['text'])"
            $res['content'][0]['type'] | Should -Be 'text'
            $fromText = $res['content'][0]['text'] | ConvertFrom-Json -AsHashtable -Depth 64
            ($fromText | ConvertTo-Json -Depth 64 -Compress) | Should -Be ($res['structuredContent'] | ConvertTo-Json -Depth 64 -Compress)
            $schema = $tools[$calls[$id]]['outputSchema']
            foreach ($req in @($schema['required'])) { $res['structuredContent'].Contains($req) | Should -BeTrue -Because "$($calls[$id]) must return $req" }
            foreach ($k in @($schema['properties'].Keys)) {
                if (-not $res['structuredContent'].Contains($k) -or $null -eq $res['structuredContent'][$k]) { continue }
                $v = $res['structuredContent'][$k]
                switch ($schema['properties'][$k]['type']) {
                    'array'   { , $v | Should -BeOfType [object[]] -Because "$($calls[$id]).$k" }
                    'object'  { $v | Should -BeOfType [System.Collections.IDictionary] -Because "$($calls[$id]).$k" }
                    'string'  { $v | Should -BeOfType [string] -Because "$($calls[$id]).$k" }
                    'integer' { ($v -is [int] -or $v -is [long]) | Should -BeTrue -Because "$($calls[$id]).$k" }
                    'boolean' { $v | Should -BeOfType [bool] -Because "$($calls[$id]).$k" }
                }
            }
        }
    }

    It 'returns the protocol errors: parse error, invalid request, unknown method, bad params, unknown tool' {
        $lines = @(& $script:Init) + @(
            '{this is not json'
            '[1,2]'
            (& $script:Request 31 'no/such/method' $null)
            '{"jsonrpc":"2.0","id":32,"method":"tools/call","params":"a string"}'
            (& $script:Call 33 'no_such_tool')
            '{"jsonrpc":"2.0","id":34,"method":"tools/call","params":{"name":"list_runs","arguments":[1]}}'
            '{"jsonrpc":"1.0","id":35,"method":"ping"}'
            ''
        )
        $s = & $script:Serve $lines
        $parse = @($s.Parsed | Where-Object { $null -eq $_['id'] })
        @($parse | Where-Object { $_['error']['code'] -eq -32700 }).Count | Should -Be 1
        @($parse | Where-Object { $_['error']['code'] -eq -32600 }).Count | Should -Be 1
        $s.ById[31]['error']['code'] | Should -Be -32601
        $s.ById[32]['error']['code'] | Should -Be -32602
        $s.ById[33]['error']['code'] | Should -Be -32602
        $s.ById[34]['error']['code'] | Should -Be -32602
        $s.ById[35]['error']['code'] | Should -Be -32600
        # The server keeps serving after every one of them.
        $s.ById[0]['result']['protocolVersion'] | Should -Be '2025-11-25'
    }

    It 'echoes 2025-06-18; answers an unknown version with its latest; sends no structured output to a 2024-11-05 client' {
        $a = & $script:Serve @((& $script:Init '2025-06-18'))
        $a.ById[0]['result']['protocolVersion'] | Should -Be '2025-06-18'
        $b = & $script:Serve @((& $script:Init '1999-01-01'))
        $b.ById[0]['result']['protocolVersion'] | Should -Be '2025-11-25'
        $c = & $script:Serve (@((& $script:Init '2024-11-05')) + @((& $script:Request 2 'tools/list' $null), (& $script:Call 3 'list_runs')))
        $c.ById[0]['result']['protocolVersion'] | Should -Be '2024-11-05'
        foreach ($t in @($c.ById[2]['result']['tools'])) { $t.Contains('outputSchema') | Should -BeFalse }
        $c.ById[3]['result'].Contains('structuredContent') | Should -BeFalse
        $c.ById[3]['result']['content'][0]['text'] | Should -Match '"runs"'
    }

    It 'a tool failure is isError content, not a protocol error, and names no path' {
        $s = & $script:Serve (@(& $script:Init) + @(
            (& $script:Call 40 'get_run_summary' @{ folder = '_flat'; id = 'NOSUCH-20200101-000000' })
            (& $script:Call 41 'list_findings' @{ folder = '_flat' })
            (& $script:Call 42 'list_findings' @{ folder = '_flat'; id = $script:FlatId; limit = 0 })
            (& $script:Call 43 'list_findings' @{ folder = '_flat'; id = $script:FlatId; state = 'Compliant' })
            (& $script:Call 44 'get_finding' @{ folder = '_flat'; id = $script:FlatId; controlId = 'not an id' })
        ))
        foreach ($i in 40..44) {
            $s.ById[$i]['result']['isError'] | Should -BeTrue
            $s.ById[$i]['result'].Contains('structuredContent') | Should -BeFalse
            $s.ById[$i]['result']['content'][0]['text'] | Should -Not -Match ([regex]::Escape($script:Tmp))
        }
        $s.ById[40]['result']['content'][0]['text'] | Should -Match 'list_runs'
        $s.ById[41]['result']['content'][0]['text'] | Should -Match 'Missing required argument: id'
    }
}

Describe 'MCP server: the tools' {

    It 'list_runs lists both layouts, newest first, with date, version and control count' {
        $a = & $script:Answer $script:Default.ById[10]
        $ids = @($a['runs'] | ForEach-Object { $_['id'] })
        $ids | Should -Contain $script:FlatId
        $ids | Should -Contain $script:LaterId
        $ids | Should -Contain $script:OldId
        $flat = @($a['runs'] | Where-Object { $_['id'] -eq $script:FlatId })[0]
        $flat['folder'] | Should -Be '_flat'
        $flat['controlCount'] | Should -Be 6
        $flat['findingCount'] | Should -Be 7
        $flat['toolVersion'] | Should -Be '4.14.3'
        $flat['dateSource'] | Should -Be 'Metadata.AssessmentTime'
        $flat['baselineRecorded'] | Should -BeTrue
        $a['total'] | Should -Be $a['returned']
    }

    It 'list_runs filters by tenant label' {
        $a = & $script:Answer $script:Default.ById[23]
        @($a['runs']).Count | Should -Be 1
        $a['runs'][0]['folder'] | Should -Be 'fabrikam.example'
    }

    It 'get_run_summary reports what the run recorded and says what it did not' {
        $a = & $script:Answer $script:Default.ById[11]
        $a['maturity']['recorded'] | Should -BeTrue
        $a['maturity']['Label'] | Should -Match 'provisional'
        $a['findingInstances']['total'] | Should -Be 7
        $a['findingInstances']['byState']['Gap'] | Should -Be 2
        # DNS-1.1 has a Gap instance beside a Satisfied one: its worst state is Gap.
        $a['controls']['byWorstState']['Gap'] | Should -Be 2
        $a['controls']['byWorstState']['Error'] | Should -Be 1
        $a['baseline']['recorded'] | Should -BeTrue
        $a['baseline']['evidenceCoverage']['Known'] | Should -Be 2
        $a['baseline']['effectivenessCoverage']['Required'] | Should -Be 3
        $a['license']['read'] | Should -BeTrue
        $a['license']['TierLabel'] | Should -Match 'Business Premium'
        ($a['notes'] -join ' ') | Should -Match 'not passes'
        $a['run'].Contains('TenantId') | Should -BeFalse
        $a['run'].Contains('tenantId') | Should -BeFalse
    }

    It 'list_findings filters and says when it truncated' {
        $gaps = & $script:Answer $script:Default.ById[20]
        @($gaps['findings'] | ForEach-Object { $_['state'] } | Sort-Object -Unique) | Should -Be @('Gap')
        $gaps['total'] | Should -Be 2
        $two = & $script:Answer $script:Default.ById[21]
        $two['returned'] | Should -Be 2
        $two['total'] | Should -Be 7
        $two['truncated'] | Should -BeTrue
    }

    It 'get_finding returns every instance, and a missing control is never a pass' {
        $dns = & $script:Answer $script:Default.ById[18]
        @($dns['instances']).Count | Should -Be 2
        $dns['worstState'] | Should -Be 'Gap'
        @($dns['instances'][0]['FrameworkIds']).Count | Should -Be 1
        $none = & $script:Answer $script:Default.ById[19]
        @($none['instances']).Count | Should -Be 0
        $none['note'] | Should -Match 'not a pass'
    }

    It 'get_control joins the catalog, the benchmark map, the operational impact and the baseline row' {
        $a = & $script:Answer $script:Default.ById[14]
        $a['control']['ControlId'] | Should -Be 'AAD-1.1'
        $a['control']['LicenseRequirement'] | Should -Not -BeNullOrEmpty
        $a['benchmarks'].Contains('mapped') | Should -BeTrue
        $a['operationalImpact']['documented'] | Should -BeTrue
        $a['baseline'].Contains('inBaseline') | Should -BeTrue
    }

    It 'get_control renders a control with no operational-impact entry as not documented, never as no impact' {
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop 3>$null
        foreach ($lib in 'Test-TPDomainName', 'Resolve-TPWebRunPath', 'Get-TPWebRunIndex') { . (Join-Path $script:RepoRoot 'Lib' "$lib.ps1") }
        foreach ($file in $script:McpFiles) { . $file }
        function Get-TPControlOperationalImpact { param($ControlId, $Catalog) return $null }
        $ctx = @{ OutputRoot = $script:Out; Pseudo = $null; Benchmarks = $null; StateRank = @{ Gap = 5; Error = 4; Partial = 3; NotApplicable = 2; Satisfied = 1 }; ToolVersion = 'test' }
        $a = Invoke-TPMcpTool -Ctx $ctx -Name 'get_control' -Arguments @{ controlId = 'AAD-1.1' }
        $a['operationalImpact']['documented'] | Should -BeFalse
        $a['operationalImpact']['note'] | Should -Match 'Operational impact not documented'
        $a['operationalImpact']['note'] | Should -Match 'not "no impact"'
        Remove-Module TenantPosture -Force -ErrorAction SilentlyContinue
    }

    It 'compare_runs reports drift for one tenant and never calls a lost verdict resolved' {
        $a = & $script:Answer $script:Default.ById[15]
        $byId = @{}; foreach ($c in @($a['changed'])) { $byId[$c['controlId']] = $c }
        $byId['AAD-1.2']['direction'] | Should -Be 'Improved'
        $byId['AAD-1.1']['direction'] | Should -Be 'Regressed'
        $byId['DNS-1.1']['direction'] | Should -Be 'VerdictChanged'
        $byId['EXO-1.1']['direction'] | Should -Be 'VerdictChanged'
        @($a['resolvedGaps'] | ForEach-Object { $_['controlId'] }) | Should -Be @('AAD-1.2')
        @($a['newGaps'] | ForEach-Object { $_['controlId'] }) | Should -Contain 'AAD-1.1'
        @($a['newGaps'] | ForEach-Object { $_['controlId'] }) | Should -Contain 'EXO-1.1'
        @($a['resolvedGaps'] | ForEach-Object { $_['controlId'] }) | Should -Not -Contain 'DNS-1.1'
        @($a['onlyInB']) | Should -Contain 'INT-1.1'
        @($a['onlyInA']) | Should -Contain 'SPO-1.1'
    }

    It 'compare_runs refuses two tenants, and a run with no tenant ID, and points to Compare-TPTenantBaseline.ps1' {
        $s = & $script:Serve (@(& $script:Init) + @(
            (& $script:Call 50 'compare_runs' @{ folderA = '_flat'; idA = $script:FlatId; folderB = 'fabrikam.example'; idB = 'FABRIKAM-20261020-100000' })
            (& $script:Call 51 'compare_runs' @{ folderA = $script:Folder; idA = $script:OldId; folderB = '_flat'; idB = $script:FlatId })
        ))
        foreach ($i in 50, 51) {
            $s.ById[$i]['result']['isError'] | Should -BeTrue
            $s.ById[$i]['result']['content'][0]['text'] | Should -Match 'Compare-TPTenantBaseline\.ps1'
            $s.ById[$i]['result']['content'][0]['text'] | Should -Not -Match '9999|1111'
        }
    }

    It 'get_baseline returns the recorded rows and filters by status' {
        $a = & $script:Answer $script:Default.ById[16]
        $a['recorded'] | Should -BeTrue
        @($a['rows']).Count | Should -Be 3
        $a['rows'][0].Keys | Should -Contain 'reasonCode'
        $a['evidenceCoverage']['Rule'] | Should -Match 'Not a score'
        $failed = & $script:Answer $script:Default.ById[22]
        @($failed['rows'] | ForEach-Object { $_['controlId'] }) | Should -Be @('AAD-1.2')
    }

    It 'get_scope says it is computed, and files the failed collector''s control as collection incomplete' {
        $a = & $script:Answer $script:Default.ById[17]
        $a['computed'] | Should -BeTrue
        $a['basis'] | Should -Match 'Computed now from the results file'
        @($a['buckets']['CollectionIncomplete']['controls'] | ForEach-Object { $_['controlId'] }) | Should -Contain 'EXO-1.1'
        $a['buckets'].Contains('LicenseBlocked') | Should -BeTrue
        $a['buckets'].Contains('LicenceBlocked') | Should -BeFalse
        @($a['coverageIssues'] | ForEach-Object { $_['collector'] }) | Should -Contain 'EXO-MailboxConfig'
        @($a['limitations']).Count | Should -BeGreaterThan 0
    }

    It 'no text the server writes itself says "compliant" (catalog titles such as "Non-Compliant Device" are data)' {
        foreach ($file in @($script:McpFiles) + @($script:Entry)) {
            $tokens = $null; $errs = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errs)
            foreach ($t in @($tokens | Where-Object { $_.Kind -in @('StringLiteral', 'StringExpandable', 'HereStringLiteral', 'HereStringExpandable') })) {
                $t.Text | Should -Not -Match '(?i)\bcompliant\b' -Because "$file must not claim compliance"
            }
        }
    }
}

Describe 'MCP server: privacy' {

    It 'by default no UPN, display name, operator, tenant ID, raw data, exception text or path is returned' {
        $all = ($script:Default.Raw -join "`n")
        foreach ($secret in $script:Upn, $script:Display, $script:CiName, $script:CiUpn, $script:Operator, $script:TenantId, $script:RawMarker, $script:RawUpn, $script:ExcMarker, $script:Tmp, '/secret/path') {
            $all | Should -Not -Match ([regex]::Escape($secret)) -Because "$secret must not leave the server"
        }
        $all | Should -Match 'user-\d+'
    }

    It 'pseudonyms are stable: the same person is the same user-<n> in AffectedObjects and in the Detail prose' {
        $a = & $script:Answer $script:Default.ById[13]
        $obj = $a['instances'][0]['AffectedObjects'][0]
        $obj['DisplayName'] | Should -Match '\Auser-\d+\z'
        $obj['UserPrincipalName'] | Should -Match '\Auser-\d+\z'
        $a['instances'][0]['Detail'] | Should -Match ([regex]::Escape($obj['DisplayName']) + '\b')
        $a['instances'][0]['Detail'] | Should -Match ([regex]::Escape($obj['UserPrincipalName']) + '\b')
        # The structured exclusion id is kept: it is what the approval record keys on.
        $obj['Principal'] | Should -Be 'user:aaaaaaaa-0000-0000-0000-000000000001'
    }

    It 'strips invisible format characters from returned text' {
        $a = & $script:Answer $script:Default.ById[13]
        $a['instances'][0]['Detail'] | Should -Not -Match '\p{Cf}'
    }

    It '-IncludeIdentities returns identities as recorded, and still never the tenant ID, raw data, exceptions or paths' {
        $all = ($script:WithIds.Raw -join "`n")
        $all | Should -Match ([regex]::Escape($script:Upn))
        $all | Should -Match ([regex]::Escape($script:Display))
        $all | Should -Match ([regex]::Escape($script:CiName))
        foreach ($secret in $script:Operator, $script:TenantId, $script:RawMarker, $script:RawUpn, $script:ExcMarker, $script:Tmp, '/secret/path') {
            $all | Should -Not -Match ([regex]::Escape($secret))
        }
    }

    It 'the redaction rule catches the Exchange "x@y" [SMTP:x@y] form and learns names only from identity keys' {
        . (Join-Path $script:RepoRoot 'Mcp' 'Protect-TPMcpOutput.ps1')
        $st = New-TPMcpPseudonymMap
        Import-TPMcpIdentities -State $st -Value @(@{ Name = 'Block legacy auth'; DisplayName = 'Ann Lee'; Recipients = @('Bo Chen') })
        $t = Protect-TPMcpText -Text 'Rule "Block legacy auth" forwards to "ann@x.example" [SMTP:ann@x.example]; Ann Lee and bo chen.' -State $st
        $t | Should -Match 'Block legacy auth'
        $t | Should -Not -Match 'ann@|Ann Lee|bo chen'
        ([regex]::Matches($t, 'user-\d+')).Count | Should -Be 4
        Protect-TPMcpText -Text ('x' * 50) -State $st -MaxLength 10 | Should -Match 'truncated: 40 more characters'
    }
}

Describe 'MCP server: paths and what is never served' {

    BeforeAll {
        $script:Refused = & $script:Serve (@(& $script:Init) + @(
            (& $script:Call 60 'get_run_summary' @{ folder = '..'; id = $script:FlatId })
            (& $script:Call 61 'get_run_summary' @{ folder = '_flat'; id = '../output/x' })
            (& $script:Call 62 'get_run_summary' @{ folder = '/etc'; id = 'passwd' })
            (& $script:Call 63 'get_run_summary' @{ folder = 'C:\Windows'; id = 'x' })
            (& $script:Call 64 'get_run_summary' @{ folder = 'jane.doe_contoso.example'; id = '20261016-100000-email' })
            (& $script:Call 65 'get_run_summary' @{ folder = 'IR-Triage'; id = 'TRIAGE-20261016-100000' })
            (& $script:Call 66 'get_run_summary' @{ folder = 'sneaky.example'; id = 'SNEAKY-20261016-100000' })
            (& $script:Call 67 'get_run_summary' @{ folder = '_flat'; id = $script:FlatFolderId })
            (& $script:Call 68 'get_run_summary' @{ folder = 'contoso.example'; id = "$($script:LaterId)`n" })
        ))
    }

    It 'refuses traversal, absolute paths, IR outputs, and a real folder named _flat' {
        foreach ($i in 60..68) {
            $res = $script:Refused.ById[$i]['result']
            $res['isError'] | Should -BeTrue -Because "call $i must be refused"
            $res['content'][0]['text'] | Should -Not -Match ([regex]::Escape($script:Tmp))
        }
    }

    It 'list_runs never lists incident-response outputs or the reserved _flat folder' {
        $a = & $script:Answer $script:Default.ById[10]
        $folders = @($a['runs'] | ForEach-Object { $_['folder'] })
        $folders | Should -Not -Contain 'IR-Triage'
        $folders | Should -Not -Contain 'jane.doe_contoso.example'
        $folders | Should -Not -Contain 'sneaky.example'
        @($a['runs'] | ForEach-Object { $_['id'] }) | Should -Not -Contain $script:FlatFolderId
    }

    It 'Resolve-TPWebRunPath -Kind Results is the guard: segments, IR names and the boundary' {
        . (Join-Path $script:RepoRoot 'Lib' 'Get-TPObjectField.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Resolve-TPWebRunPath.ps1')
        (Resolve-TPWebRunPath -OutputRoot $script:Out -Folder '_flat' -Id $script:FlatId -Kind Results).Status | Should -Be 'Ok'
        (Resolve-TPWebRunPath -OutputRoot $script:Out -Folder $script:Folder -Id $script:LaterId -Kind Results).Status | Should -Be 'Ok'
        (Resolve-TPWebRunPath -OutputRoot $script:Out -Folder '..' -Id 'x' -Kind Results).Status | Should -Be 'BadRequest'
        (Resolve-TPWebRunPath -OutputRoot $script:Out -Folder 'a/b' -Id 'x' -Kind Results).Status | Should -Be 'BadRequest'
        (Resolve-TPWebRunPath -OutputRoot $script:Out -Folder 'ir-triage' -Id 'TRIAGE-20261016-100000' -Kind Results).Status | Should -Be 'NotFound'
        (Resolve-TPWebRunPath -OutputRoot $script:Out -Folder 'jane.doe_contoso.example' -Id '20261016-100000-email' -Kind Results).Status | Should -Be 'NotFound'
        (Resolve-TPWebRunPath -OutputRoot $script:Out -Folder '_flat' -Id 'x-signin-triage' -Kind Results).Status | Should -Be 'NotFound'
        (Resolve-TPWebRunPath -OutputRoot $script:Out -Folder '_flat' -Id $script:FlatFolderId -Kind Results).Status | Should -Be 'NotFound'
    }
}

Describe 'MCP server: an older results file under StrictMode' {

    It 'every run tool answers for a file without the newer fields, and says what is not recorded' {
        $f = $script:Folder; $id = $script:OldId
        $s = & $script:Serve (@(& $script:Init) + @(
            (& $script:Call 70 'get_run_summary' @{ folder = $f; id = $id })
            (& $script:Call 71 'list_findings' @{ folder = $f; id = $id })
            (& $script:Call 72 'get_finding' @{ folder = $f; id = $id; controlId = 'EXO-1.1' })
            (& $script:Call 73 'get_baseline' @{ folder = $f; id = $id })
            (& $script:Call 74 'get_scope' @{ folder = $f; id = $id })
        ))
        foreach ($i in 70..74) { $s.ById[$i]['result'].Contains('isError') | Should -BeFalse -Because ($s.ById[$i]['result']['content'][0]['text']) }
        $sum = & $script:Answer $s.ById[70]
        $sum['maturity']['recorded'] | Should -BeFalse
        $sum['baseline']['recorded'] | Should -BeFalse
        $sum['license']['read'] | Should -BeFalse
        $sum['license']['note'] | Should -Match 'not "unlicensed"'
        (& $script:Answer $s.ById[73])['recorded'] | Should -BeFalse
        (& $script:Answer $s.ById[74])['basis'] | Should -Match 'carries no collector status'
        $s.Err | Should -Not -Match 'failed inside'
    }
}

Describe 'MCP server: read-only and off the module' {

    It '<File> makes no network, sign-in, tenant, write or process call' -ForEach @(
        @{ File = 'Start-TPMcpServer.ps1' }
        @{ File = 'Mcp/Protect-TPMcpOutput.ps1' }
        @{ File = 'Mcp/Read-TPMcpRun.ps1' }
        @{ File = 'Mcp/Invoke-TPMcpTool.ps1' }
        @{ File = 'Mcp/Invoke-TPMcpProtocol.ps1' }
    ) {
        $tokens = $null; $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:RepoRoot $File), [ref]$tokens, [ref]$errs)
        @($errs).Count | Should -Be 0
        $code = (@($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' ')
        $commands = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        $forbidden = '^Connect-', '^Disconnect-', '^Invoke-(RestMethod|WebRequest|TPGraphRequest|TPGraphAllPages|Expression|Command|TPPython)$',
            '^Resolve-(TPDns|DnsName|TPTenantId)$', '^Test-(Connection|NetConnection)$', '^Start-(Process|Job|ThreadJob|TPWebServer)$',
            '^Get-Mg', '^Get-(Mailbox|CsTenant|OrganizationConfig|Recipient)', '^Send-MailMessage$',
            '^(Set|Add|Clear)-Content$', '^Out-File$', '^New-Item$', '^Remove-Item$', '^Move-Item$', '^Copy-Item$', '^Rename-Item$',
            '^Set-TPSensitiveFile', '^Export-', '^Set-Acl$', '^Set-TPRawData$', '^Add-TPFinding$', '^Register-TP', '^Clear-TPState$',
            '^Publish-', '^New-TP(Profile|BaselineException)$', '^(Set|Remove)-TPBaselineException$'
        foreach ($cmd in $commands) {
            foreach ($f in $forbidden) { $cmd | Should -Not -Match $f -Because "$File must not call $cmd" }
        }
        foreach ($t in 'System\.Net\.', 'HttpClient', 'WebClient', 'Sockets', 'graph\.microsoft', 'login\.microsoftonline', 'outlook\.office', 'https?://',
                'Diagnostics\.Process', 'File\]::(Write|Create|Delete|Move|Copy|AppendAll|Replace)', 'FileMode\]::(Create|Append|OpenOrCreate|Truncate)', 'FileAccess\]::(Write|ReadWrite)', 'EncodedCommand') {
            $code | Should -Not -Match $t -Because "$File must not reference $t"
        }
    }

    It 'the module loader does not load Mcp/, so the export list does not change' {
        $psm1 = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Raw
        $tokens = $null; $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($psm1, [ref]$tokens, [ref]$errs)
        $load = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left.Extent.Text -eq '$loadOrder' }, $true) | Select-Object -First 1
        $load | Should -Not -BeNullOrEmpty
        $load.Right.Extent.Text | Should -Not -Match 'Mcp'
        $psm1 | Should -Not -Match "'[A-Za-z]+-TPMcp"
        (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'TenantPosture.psd1') -Raw) | Should -Not -Match 'TPMcp'
    }

    It 'the server answers only through the run index and the path guard, never a path argument' {
        $tool = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Mcp' 'Invoke-TPMcpTool.ps1') -Raw
        $tool | Should -Match 'Resolve-TPWebRunPath -OutputRoot \$Ctx\.OutputRoot -Folder \$Folder -Id \$Id -Kind Results'
        $tool | Should -Match 'Get-TPWebRunList -OutputRoot'
        # Read-TPMcpRunFile is only ever handed what the guard resolved.
        $calls = [regex]::Matches($tool, 'Read-TPMcpRunFile -Path (\S+)') | ForEach-Object { $_.Groups[1].Value }
        @($calls | Sort-Object -Unique) | Should -Be @('$found.Path')
        $calls2 = [regex]::Matches($tool, 'Get-TPMcpRun -Path (\S+)') | ForEach-Object { $_.Groups[1].Value }
        @($calls2 | Sort-Object -Unique) | Should -Be @('$found.Path')
    }
}

Describe 'MCP server: get_change_impact' {
    It 'returns the recorded lists, names accounts by pseudonym, and says what a list is not' {
        $a = & $script:Answer $script:Default.ById[24]
        $a['recorded'] | Should -BeTrue
        @($a['implementNow']).Count | Should -Be 1
        $acct = $a['couldBreakAccounts'][0]['Evidence'][0]['Accounts'][0]
        $acct['DisplayName'] | Should -Match '\Auser-\d+\z'
        $acct['UserPrincipalName'] | Should -Match '\Auser-\d+\z'
        $a['note'] | Should -Match 'never means nothing can break'
        $a['note'] | Should -Not -Match '(?i)\bcompliant\b'
    }
    It 'a run that recorded no view says so and recomputes nothing' {
        $a = & $script:Answer $script:Default.ById[25]
        $a['recorded'] | Should -BeFalse
        $a['note'] | Should -Match 'not recomputed'
    }
    It 'narrows to one list and one control' {
        $a = & $script:Answer $script:Default.ById[26]
        $a.Contains('implementNow') | Should -BeFalse
        @($a['couldBreakAccounts']).Count | Should -Be 1
        $a['couldBreakAccounts'][0]['ControlId'] | Should -Be 'AAD-1.2'
    }
}
