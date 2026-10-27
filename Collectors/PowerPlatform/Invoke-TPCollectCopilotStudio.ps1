#Requires -Version 7.0
#
# Invoke-TPCollectCopilotStudio.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Read Copilot Studio agents (Dataverse `bot` and `botcomponent`
# tables) in every Dataverse-backed Power Platform environment and keep only
# DERIVED facts per agent for the PPL-4.x controls.
#
# READ-ONLY. Every Dataverse request is a GET (Invoke-TPDataverseApi refuses
# any other method). No tenant configuration is ever modified.
#
# Sets raw data key: 'CopilotStudio'
# Consumes:          'PowerPlatform' (the environment list, when that
#                    collector ran and stored each environment's Dataverse
#                    instance URL); otherwise the list is read here.
# Network:           login.microsoftonline.com (token), api.bap.microsoft.com
#                    (environment list, only when not reused), and each
#                    environment's own Dataverse host (*.crm*.dynamics.com,
#                    *.crm.dynamics.cn, *.crm.microsoftdynamics.us,
#                    *.crm.appsplatform.us) over /api/data/v9.2/.
# Graph scopes:      none (no new Graph scope). The signed-in account needs a
#                    Dataverse security role in each environment that can read
#                    the Agent (bot), Agent component (botcomponent) and User
#                    (systemuser) tables, for example System Administrator;
#                    an environment that refuses the read is reported, never
#                    read as "no agents".
#
# HOW IT SIGNS IN — IN PROCESS, NO CHILD PROCESS (same rule as the Power
# Platform collector): Get-TPPowerPlatformToken with -Audience set to the
# environment's Dataverse URL, the same public client, the same authority
# pinned to the Graph tenant, token in memory only. After the first sign-in
# the in-memory MSAL cache answers silently for the other environments.
#
# WHAT IS STORED (privacy and secrets). Per agent: id, name, environment,
# owner's Entra object id, created/modified/published dates, authentication
# mode and trigger, access control setting, generative orchestration on/off,
# whether custom instructions are present (yes/no), the scheme and port of
# each HTTP request node (never the host or path), email-sending tools whose
# recipient/subject/body are not fixed values (tool name and field names),
# connector tools without an end-user connection mode (connector name), MCP
# tool endpoints (host only), and hard-coded-credential MATCHES as the pattern
# type plus the component id. Topic YAML, instruction text, the bot
# configuration and any matched secret value are read in memory, judged, and
# never stored in raw data or findings.
#
# FIELD MEANINGS (Microsoft Learn, Dataverse table reference: bot,
# botcomponent, systemuser):
#   bot.accesscontrolpolicy   0 Any, 1 Agent readers, 2 Group membership,
#                             3 Any (multi-tenant)  ("Defines which users may
#                             interact with the agent")
#   bot.authenticationmode    0 Unspecified, 1 None, 2 Integrated, 3 Custom
#                             Entra ID, 4 Generic OAuth2
#   bot.authenticationtrigger 0 As Needed, 1 Always
#   bot.statecode             0 Active, 1 Inactive; publishedon = last publish
#   bot.ismanaged             part of a managed solution
#   botcomponent.componenttype 9 Topic (V2), 15 Custom GPT
#   botcomponent.data         "content of the Bot Component in OBI format"
#   systemuser.azureactivedirectoryobjectid / isdisabled / applicationid
# Supported only by Maester v3.0.0's usage (MIT; read, not copied), not by a
# Learn field description: a tool is a topic component whose YAML is
# `kind: TaskDialog`; generative orchestration is
# configuration.settings.GenerativeActionsEnabled; an end-user-credential
# connector tool carries `connectionProperties: mode: Invoker`. Instructions
# are read from the Custom GPT component's `instructions:` key (the agent
# definition the Copilot Studio VS Code extension exposes) and from the
# configuration keys Maester reads. These are named in the findings as
# unconfirmed against a live tenant.
#

$script:TPDataverseApiPath = '/api/data/v9.2/'
$script:TPCopilotStudioLimits = [ordered]@{
    MaxEnvironments   = 50
    AgentPageSize     = 250
    MaxAgentPages     = 4
    ComponentPageSize = 50
    MaxComponentPages = 100
    OwnerBatchSize    = 15
}

# ── Host and URL rules ───────────────────────────────────────────────────────

function Test-TPDataverseHost {
    <#
    .SYNOPSIS
        True only for a Dataverse environment host of the commercial, GCC
        (crm9), GCC High, DoD or China clouds, with or without the `api.`
        label (Microsoft Learn: Dynamics 365 US Government URLs; Discover user
        organizations). Anchored, case-sensitive over the lower-cased name.
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] [AllowEmptyString()] [string] $HostName)
    if ([string]::IsNullOrWhiteSpace($HostName)) { return $false }
    $h = $HostName.ToLowerInvariant()
    return ($h -cmatch '\A[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:api\.)?(?:crm[0-9]{0,2}\.dynamics\.com|crm\.dynamics\.cn|crm\.microsoftdynamics\.us|crm\.appsplatform\.us)\z')
}

function ConvertTo-TPDataverseInstance {
    <#
    .SYNOPSIS
        Turns an environment's Dataverse URL into @{ Host; BaseUrl }, or $null
        when it is not an https URL on a Dataverse host with the default port,
        no user information, no query and no fragment.
    #>
    [CmdletBinding()]
    param([AllowNull()] [AllowEmptyString()] [string] $Url)
    if ([string]::IsNullOrWhiteSpace($Url)) { return $null }
    $u = $null
    if (-not [uri]::TryCreate($Url.Trim(), [System.UriKind]::Absolute, [ref]$u)) { return $null }
    if ($u.Scheme -cne 'https' -or -not $u.IsDefaultPort -or $u.UserInfo -or $u.Query -or $u.Fragment) { return $null }
    if (-not (Test-TPDataverseHost -HostName $u.Host)) { return $null }
    $h = ([string]$u.Host).ToLowerInvariant()
    return [ordered]@{ Host = $h; BaseUrl = "https://$h" }
}

function Test-TPDataverseRequestUri {
    <#
    .SYNOPSIS
        The rule every Dataverse request and every next-page link must meet:
        https, a Dataverse host, the default port, no user information, the
        Web API path. With -ExpectedHost the host must be that one (a next
        page never leaves the environment it started in). Returns the lower-
        cased host, or throws.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Uri, [string] $ExpectedHost)
    $u = $null
    if (-not [uri]::TryCreate($Uri, [System.UriKind]::Absolute, [ref]$u)) { throw 'refused: not an absolute URL' }
    if ($u.Scheme -cne 'https') { throw 'refused: only https is allowed' }
    if ($u.UserInfo) { throw 'refused: user information in the URL' }
    if (-not $u.IsDefaultPort) { throw 'refused: only the default https port is allowed' }
    if (-not (Test-TPDataverseHost -HostName $u.Host)) { throw "refused: '$($u.Host)' is not a Dataverse environment host" }
    if (-not ([string]$u.AbsolutePath).StartsWith($script:TPDataverseApiPath, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'refused: not the Dataverse Web API path' }
    $h = ([string]$u.Host).ToLowerInvariant()
    if ($ExpectedHost -and -not [string]::Equals($h, $ExpectedHost, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "refused: a link to '$h' leaves the environment host '$ExpectedHost'"
    }
    return $h
}

function Test-TPPowerPlatformAudience {
    <#
    .SYNOPSIS
        The audiences Get-TPPowerPlatformToken may request: the Power Platform
        admin API, or one Dataverse environment's base URL (https://<host>).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] [AllowEmptyString()] [string] $Audience)
    if ($Audience -ceq 'https://service.powerapps.com/') { return $true }
    $inst = ConvertTo-TPDataverseInstance -Url $Audience
    return ($null -ne $inst -and $Audience -ceq $inst.BaseUrl)
}

# ── One Dataverse Web API read ───────────────────────────────────────────────

function Invoke-TPDataverseApi {
    <#
    .SYNOPSIS
        One GET against a Dataverse environment's Web API. -Paged follows
        @odata.nextLink up to -MaxPages and returns @{ Rows; Truncated }; a
        next link that leaves the starting host is refused with a throw (a
        partial list must never read as complete). Redirects are not followed.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [Parameter(Mandatory)] [string] $Token,
        [ValidateSet('GET')] [string] $Method = 'GET',
        [switch] $Paged,
        [ValidateRange(1, 500)] [int] $MaxPages = 50,
        [ValidateRange(1, 5000)] [int] $PageSize = 100
    )
    $startHost = Test-TPDataverseRequestUri -Uri $Uri
    $headers = @{
        Authorization      = "Bearer $Token"
        Accept             = 'application/json'
        'OData-MaxVersion' = '4.0'
        'OData-Version'    = '4.0'
        Prefer             = "odata.maxpagesize=$PageSize"
    }
    if (-not $Paged) {
        return Invoke-RestMethod -Method Get -Uri $Uri -Headers $headers -MaximumRedirection 0 -TimeoutSec 120 -ErrorAction Stop
    }
    $rows  = [System.Collections.Generic.List[object]]::new()
    $next  = $Uri
    $pages = 0
    while ($next -and $pages -lt $MaxPages) {
        $null = Test-TPDataverseRequestUri -Uri $next -ExpectedHost $startHost
        $resp = Invoke-RestMethod -Method Get -Uri $next -Headers $headers -MaximumRedirection 0 -TimeoutSec 120 -ErrorAction Stop
        $vals = Get-TPObjectField -Item $resp -Key 'value' -Default $null
        if ($null -eq $vals -and -not (Test-TPFieldPresent -Item $resp -Key 'value')) { throw 'the response carried no value collection' }
        foreach ($r in @($vals)) { if ($null -ne $r) { $rows.Add($r) } }
        # Get-TPObjectField, never a dotted reader: '@odata.nextLink' is one key.
        $next = [string](Get-TPObjectField -Item $resp -Key '@odata.nextLink' -Default '')
        $pages++
        if ($next) { $null = Test-TPDataverseRequestUri -Uri $next -ExpectedHost $startHost }
    }
    return [pscustomobject]@{ Rows = $rows.ToArray(); Truncated = [bool]$next; Pages = $pages }
}

function Get-TPDataverseFailureReason {
    <#
    .SYNOPSIS
        One sentence for a failed Dataverse read: an access refusal names the
        role the operator needs; anything else keeps the error's first line.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowNull()] [object] $ErrorRecord, [string] $What = 'the read')
    $status = $null
    $ex = Get-TPObjectField -Item $ErrorRecord -Key 'Exception' -Default $null
    $resp = Get-TPObjectField -Item $ex -Key 'Response' -Default $null
    if ($resp) {
        $sc = Get-TPObjectField -Item $resp -Key 'StatusCode' -Default $null
        if ($null -ne $sc) { try { $status = [int]$sc } catch { $status = $null } }
    }
    $msg = [string](Get-TPObjectField -Item $ex -Key 'Message' -Default "$ErrorRecord")
    $msg = ($msg -split "`n")[0].Trim()
    if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) + '...' }
    if ($null -eq $status -and $msg -match '\b(401|403)\b') { $status = [int]$Matches[1] }
    if ($status -in 401, 403) {
        return "$What was refused (HTTP $status): the signed-in account has no Dataverse security role in this environment that can read the Agent (bot), Agent component (botcomponent) and User (systemuser) tables. Assign one (for example System Administrator) and re-run. Detail: $msg"
    }
    if ($null -ne $status) { return "$What failed (HTTP $status): $msg" }
    return "$What failed: $msg"
}

# ── Reading an agent definition (in memory only) ─────────────────────────────

function Get-TPCopilotStudioCredentialPatterns {
    <#
    .SYNOPSIS
        Heuristic patterns for a credential written into an agent's topic or
        tool definition. A match names its pattern type only; the matched
        text is never kept. A Power Fx reference (=Topic.x, Env.x) is not a
        literal and is not matched.
    #>
    [CmdletBinding()]
    param()
    $notRef = '(?!=|(?:Topic|System|Global|Env|User|Bot)\.)'
    @(
        [ordered]@{ Type = 'API key assignment';        Pattern = "(?i)\b(?:x-api-key|api[_-]?key|apikey|subscription-key|ocp-apim-subscription-key)[`"']?\s*[:=]\s*[`"']?$notRef[A-Za-z0-9\-_.]{16,}" }
        [ordered]@{ Type = 'Bearer token';              Pattern = '(?i)\bbearer\s+[A-Za-z0-9\-_.~+/]{20,}=*' }
        [ordered]@{ Type = 'Basic authorization value'; Pattern = '(?i)\bbasic\s+[A-Za-z0-9+/]{16,}={0,2}' }
        [ordered]@{ Type = 'Connection string secret';  Pattern = '(?i)\b(?:AccountKey|SharedAccessKey|SharedAccessSignature|Password|Pwd)\s*=\s*[^;"''\s]{6,}' }
        [ordered]@{ Type = 'Password or secret value';  Pattern = "(?i)\b(?:password|passwd|client_?secret|secret)[`"']?\s*[:=]\s*[`"']?$notRef[^\s`"'&,]{8,}" }
        [ordered]@{ Type = 'AWS access key id';         Pattern = '\b(?:AKIA|ASIA)[A-Z0-9]{16}\b' }
        [ordered]@{ Type = 'Private key block';         Pattern = '-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----' }
        [ordered]@{ Type = 'JSON web token';            Pattern = '\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' }
    )
}

function Get-TPYamlItemBlocks {
    <#
    .SYNOPSIS
        The text of every YAML list item `- kind: <Kind>` whose kind matches
        -KindPattern: the item line plus every following line indented deeper
        than its dash (or blank). A line-level reader, not a YAML parser.
    #>
    [CmdletBinding()]
    param([AllowNull()] [AllowEmptyString()] [string] $Text, [Parameter(Mandatory)] [string] $KindPattern)
    $blocks = [System.Collections.Generic.List[string]]::new()
    if ([string]::IsNullOrEmpty($Text)) { return $blocks.ToArray() }
    $lines = $Text -split "`r?`n"
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $m = [regex]::Match($lines[$i], "^(?<ind>\s*)-\s+kind:\s*(?<k>$KindPattern)\s*$")
        if (-not $m.Success) { continue }
        $ind = $m.Groups['ind'].Value.Length
        $sb = [System.Text.StringBuilder]::new()
        $null = $sb.AppendLine($lines[$i])
        for ($j = $i + 1; $j -lt $lines.Count; $j++) {
            $l = $lines[$j]
            if ($l.Trim().Length -eq 0) { $null = $sb.AppendLine($l); continue }
            $li = $l.Length - $l.TrimStart().Length
            if ($li -le $ind) { break }
            $null = $sb.AppendLine($l)
        }
        $blocks.Add($sb.ToString())
    }
    return $blocks.ToArray()
}

function Get-TPYamlScalar {
    <#
    .SYNOPSIS
        The first `key: value` scalar in a block (quotes removed), or $null.
    #>
    [CmdletBinding()]
    param([AllowNull()] [AllowEmptyString()] [string] $Text, [Parameter(Mandatory)] [string] $Key)
    if ([string]::IsNullOrEmpty($Text)) { return $null }
    $m = [regex]::Match($Text, "(?m)^\s*(?:-\s+)?$([regex]::Escape($Key)):[ \t]*(?<v>[^\r\n]*)$")
    if (-not $m.Success) { return $null }
    $v = $m.Groups['v'].Value.Trim()
    if ($v.Length -ge 2 -and (($v[0] -eq '"' -and $v[-1] -eq '"') -or ($v[0] -eq "'" -and $v[-1] -eq "'"))) { $v = $v.Substring(1, $v.Length - 2) }
    return $v
}

function Get-TPCopilotStudioComponentFacts {
    <#
    .SYNOPSIS
        Derives the PPL-4.x facts from one agent component's definition text.
        Pure: the text goes in, only derived facts come out, and nothing of
        the text itself (hosts aside, for MCP tools) is returned.
    #>
    [CmdletBinding()]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $Text,
        [int] $ComponentType,
        [string] $ComponentId,
        [string] $ComponentName
    )
    $facts = [ordered]@{
        ComponentId        = $ComponentId
        IsTool             = $false
        HttpNodes          = @()
        EmailTool          = $null
        ConnectorTool      = $null
        McpTool            = $null
        CredentialPatterns = @()
        HasInstructions    = $null
    }
    if ([string]::IsNullOrEmpty($Text)) { return $facts }

    # Credentials: every component, every state. Type names only.
    $hits = [System.Collections.Generic.List[string]]::new()
    foreach ($p in Get-TPCopilotStudioCredentialPatterns) {
        $rx = [regex]::new($p.Pattern, [System.Text.RegularExpressions.RegexOptions]::None, [TimeSpan]::FromSeconds(2))
        try { if ($rx.IsMatch($Text)) { $hits.Add($p.Type) } } catch [System.Text.RegularExpressions.RegexMatchTimeoutException] { $hits.Add("$($p.Type) (match timed out; review)") }
    }
    $facts.CredentialPatterns = @($hits | Select-Object -Unique)

    if ($ComponentType -eq 15) {
        # Custom GPT component: the agent's instructions. Present when the
        # key holds text, inline or as a block scalar on the lines below.
        $m = [regex]::Match($Text, '(?m)^(?<ind>[ \t]*)instructions:[ \t]*(?<v>[^\r\n]*)$')
        if ($m.Success) {
            $v = $m.Groups['v'].Value.Trim()
            if ($v -match '^[|>][+-]?\d*$') {
                $ind = $m.Groups['ind'].Value.Length
                $rest = $Text.Substring($m.Index + $m.Length) -split "`r?`n"
                $body = @($rest | Where-Object { $_.Trim().Length -gt 0 } | Select-Object -First 1)
                $facts.HasInstructions = ($body.Count -gt 0 -and ($body[0].Length - $body[0].TrimStart().Length) -gt $ind)
            } else {
                $facts.HasInstructions = ($v.Trim('"', "'").Trim().Length -gt 0)
            }
        } else {
            $facts.HasInstructions = $false
        }
        return $facts
    }

    # HTTP request nodes in topics: scheme and port of the URL only.
    $nodes = [System.Collections.Generic.List[object]]::new()
    foreach ($b in Get-TPYamlItemBlocks -Text $Text -KindPattern 'HttpRequestAction') {
        $nodeId = [string](Get-TPYamlScalar -Text $b -Key 'id')
        $url    = [string](Get-TPYamlScalar -Text $b -Key 'url')
        $scheme = 'Unknown'; $port = $null
        $um = [regex]::Match($url, '(?i)\b(?<s>https?)://(?<h>[^\s"''/?#\\]+)')
        if ($um.Success) {
            $scheme = $um.Groups['s'].Value.ToLowerInvariant()
            $hp = $um.Groups['h'].Value
            $pm = [regex]::Match($hp, ':(?<p>\d{1,5})$')
            if ($pm.Success) { $port = [int]$pm.Groups['p'].Value }
        }
        $risky = ($scheme -eq 'http') -or ($null -ne $port -and $port -ne 443)
        $nodes.Add([ordered]@{
            ComponentId  = $ComponentId
            NodeId       = $nodeId
            Scheme       = $scheme
            Port         = $port
            Risky        = $risky
            Undetermined = ($scheme -eq 'Unknown')
        })
    }
    $facts.HttpNodes = $nodes.ToArray()

    if ($Text -notmatch '(?m)^\s*kind:\s*TaskDialog\s*$') { return $facts }
    $facts.IsTool = $true

    $operation = [string](Get-TPYamlScalar -Text $Text -Key 'operationId')
    $connRef   = [string](Get-TPYamlScalar -Text $Text -Key 'connectionReference')
    $connector = ''
    $cm = [regex]::Match("$connRef $Text", '(?i)\bshared_[a-z0-9]+')
    if ($cm.Success) { $connector = ([string]$cm.Value).ToLowerInvariant() }

    # Connector authentication (Maester's reading: an end-user tool carries
    # connectionProperties: mode: Invoker).
    if ($connRef) {
        $mode = $null
        $pm = [regex]::Match($Text, '(?m)^(?<ind>[ \t]*)connectionProperties:[ \t]*$')
        if ($pm.Success) {
            $after = $Text.Substring($pm.Index + $pm.Length)
            $mm = [regex]::Match($after, '(?m)^[ \t]+mode:[ \t]*(?<m>[A-Za-z]+)')
            if ($mm.Success) { $mode = $mm.Groups['m'].Value }
        }
        $facts.ConnectorTool = [ordered]@{
            ComponentId = $ComponentId
            ToolName    = $ComponentName
            Connector   = $connector
            AuthMode    = $(if ($mode -eq 'Invoker') { 'EndUser' } elseif ($mode) { "Other:$mode" } else { 'NotRecorded' })
        }
    }

    # Email-sending tools: which of recipient, subject and body are not fixed.
    $emailConnectors = @('shared_office365', 'shared_outlook', 'shared_sendmail', 'shared_gmail', 'shared_smtp')
    if ($connector -in $emailConnectors -and $operation -match '(?i)^(send|forward|reply)') {
        $inputs = @{}
        foreach ($ib in Get-TPYamlItemBlocks -Text $Text -KindPattern '(?:Automatic|Manual)TaskInput') {
            $kind  = if ($ib -match 'kind:\s*ManualTaskInput') { 'Manual' } else { 'Automatic' }
            $prop  = [string](Get-TPYamlScalar -Text $ib -Key 'propertyName')
            $value = Get-TPYamlScalar -Text $ib -Key 'value'
            $leaf  = (($prop -split '[/.]') | Select-Object -Last 1)
            if ($leaf) { $inputs[$leaf.ToLowerInvariant()] = [ordered]@{ Kind = $kind; Literal = ($kind -eq 'Manual' -and $null -ne $value -and -not ([string]$value).StartsWith('=')) } }
        }
        $controlled = [System.Collections.Generic.List[string]]::new()
        foreach ($f in 'To', 'Subject', 'Body') {
            $i = $inputs[$f.ToLowerInvariant()]
            # Learn: an input not given a custom value is "Dynamically fill with AI".
            if ($null -eq $i -or -not $i.Literal) { $controlled.Add($f) }
        }
        foreach ($f in 'Cc', 'Bcc') {
            $i = $inputs[$f.ToLowerInvariant()]
            if ($null -ne $i -and -not $i.Literal) { $controlled.Add($f) }
        }
        $facts.EmailTool = [ordered]@{
            ComponentId        = $ComponentId
            ToolName           = $ComponentName
            Connector          = $connector
            Operation          = $operation
            AIControlled       = ($controlled.Count -gt 0)
            AIControlledFields = $controlled.ToArray()
        }
    }

    # MCP tools: the endpoint host only.
    if ($Text -match '(?i)\bkind:\s*[A-Za-z]*(?:ModelContextProtocol|Mcp)[A-Za-z]*\b|x-ms-agentic-protocol|mcp-streamable') {
        $mcpHost = ''
        $hm = [regex]::Match($Text, '(?i)\bhttps?://(?<h>[A-Za-z0-9.-]+)')
        if ($hm.Success) { $mcpHost = $hm.Groups['h'].Value.ToLowerInvariant() } elseif ($connector) { $mcpHost = "connector $connector" } else { $mcpHost = 'not recorded in the tool definition' }
        $facts.McpTool = [ordered]@{ ComponentId = $ComponentId; ToolName = $ComponentName; Host = $mcpHost }
    }
    return $facts
}

function Get-TPCopilotStudioOrchestration {
    <#
    .SYNOPSIS
        Reads bot.configuration (JSON) for generative orchestration and the
        instruction keys Maester reads. Returns @{ Generative; Instructions }
        with $null for "not read". The text is never kept.
    #>
    [CmdletBinding()]
    param([AllowNull()] [AllowEmptyString()] [string] $Configuration)
    $out = [ordered]@{ Generative = $null; Instructions = $null }
    if ([string]::IsNullOrWhiteSpace($Configuration)) { return $out }
    try { $cfg = $Configuration | ConvertFrom-Json -Depth 20 -ErrorAction Stop } catch { return $out }
    $g = Get-TPNestedProperty -Object $cfg -Path 'settings.GenerativeActionsEnabled' -Default $null
    if ($g -is [bool]) { $out.Generative = $g }
    elseif ("$g" -in 'true', 'false') { $out.Generative = ("$g" -eq 'true') }
    foreach ($k in 'Instructions', 'CustomInstructions', 'SystemPrompt', 'SystemMessage') {
        $v = Get-TPObjectField -Item $cfg -Key $k -Default $null
        if ($null -ne $v -and -not [string]::IsNullOrWhiteSpace([string]$v)) { $out.Instructions = $true; break }
    }
    return $out
}

function Get-TPCopilotStudioOptionLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [object] $Value, [Parameter(Mandatory)] [hashtable] $Map)
    if ($null -eq $Value -or "$Value" -eq '') { return 'Not returned' }
    $n = 0
    if ([int]::TryParse("$Value", [System.Globalization.NumberStyles]::None, [cultureinfo]::InvariantCulture, [ref]$n) -and $Map.ContainsKey($n)) { return $Map[$n] }
    return "Unknown ($Value)"
}

function ConvertTo-TPCopilotStudioDate {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [object] $Value)
    $d = ConvertTo-TPUtcDateTime $Value
    if ($d) { return $d.ToString('o') }
    return ''
}

# ── Collector ────────────────────────────────────────────────────────────────

function Invoke-TPCollectCopilotStudio {
    [CmdletBinding()] param()
    $lim = $script:TPCopilotStudioLimits
    $result = [ordered]@{
        CollectorId = 'CopilotStudio'
        CollectedAt = (Get-Date).ToString('o')
        Success     = $false
        Errors      = @()
        Data        = [ordered]@{
            Source                = 'none'      # 'dataverse' once any environment was read
            EnvironmentListSource = 'none'      # 'PowerPlatform' (reused) | 'bap-api' | 'none'
            Environments          = @()
            Agents                = @()
            Limits                = [ordered]@{}
            # 'Environments' is the environment list; every other key is one
            # environment id. Collected / Failed / NotRun / Truncated.
            SectionStatus         = [ordered]@{ Environments = 'NotRun' }
            SectionErrors         = [ordered]@{}
        }
    }
    foreach ($k in $lim.Keys) { $result.Data.Limits[$k] = $lim[$k] }
    $note = {
        param([string] $Source, [string] $Msg)
        $result.Errors += $Msg
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) { Register-TPException -Source $Source -Message $Msg }
    }

    # ── Tenant and sign-in context ───────────────────────────────────────────
    $tenantId = $null; $account = $null; $appOnly = $false
    try {
        $ctx = Get-MgContext -ErrorAction Stop
        if ($ctx) {
            $tenantId = [string](Get-TPObjectField -Item $ctx -Key 'TenantId' -Default '')
            $account  = [string](Get-TPObjectField -Item $ctx -Key 'Account' -Default '')
            $appOnly  = ([string](Get-TPObjectField -Item $ctx -Key 'AuthType' -Default '')) -eq 'AppOnly'
        }
    } catch { $tenantId = $null }

    $envRows = $null
    if (-not $tenantId) {
        $why = 'Copilot Studio agents not collected: no Graph tenant context to pin the Dataverse sign-in to.'
        $result.Data.SectionStatus.Environments = 'Failed'; $result.Data.SectionErrors['Environments'] = $why
        & $note 'CopilotStudio-Collector' $why
    } elseif ($appOnly) {
        $why = 'Copilot Studio agents not collected: app-only (certificate) runs do not sign in to Power Platform or Dataverse. Run interactively to assess the PPL-4 controls.'
        $result.Data.SectionStatus.Environments = 'Failed'; $result.Data.SectionErrors['Environments'] = $why
        & $note 'CopilotStudio-Collector' $why
    } else {
        # Reuse the Power Platform collector's list when it read the list and
        # stored each environment's Dataverse URL (a results file from before
        # that field cannot say which environments hold Dataverse).
        $pp = Get-TPRawData -Key 'PowerPlatform'
        $ppRows = @(@(Get-TPNestedProperty -Object $pp -Path 'Data.Environments' -Default @()) | Where-Object { $null -ne $_ })
        $ppOk = $pp -and (Get-TPObjectField -Item $pp -Key 'Success' -Default $false) -and
                ([string](Get-TPNestedProperty -Object $pp -Path 'Data.SectionStatus.Environments' -Default '') -eq 'Collected') -and
                (@($ppRows | Where-Object { -not (Test-TPFieldPresent -Item $_ -Key 'InstanceUrl') }).Count -eq 0)
        if ($ppOk) {
            $envRows = @($ppRows | ForEach-Object {
                [ordered]@{
                    Id          = [string](Get-TPObjectField -Item $_ -Key 'Id' -Default '')
                    DisplayName = [string](Get-TPObjectField -Item $_ -Key 'DisplayName' -Default '')
                    InstanceUrl = [string](Get-TPObjectField -Item $_ -Key 'InstanceUrl' -Default '')
                }
            })
            $result.Data.EnvironmentListSource = 'PowerPlatform'
            $result.Data.SectionStatus.Environments = 'Collected'
        } else {
            try {
                $bapToken = Get-TPPowerPlatformToken -TenantId $tenantId -LoginHint $account
                $rows = @(Invoke-TPPowerPlatformApi -Token $bapToken -Paged `
                    -Uri 'https://api.bap.microsoft.com/providers/Microsoft.BusinessAppPlatform/scopes/admin/environments?api-version=2020-10-01')
                $envRows = @($rows | Where-Object { $_ } | ForEach-Object {
                    $iu = [string](Get-TPNestedProperty -Object $_ -Path 'properties.linkedEnvironmentMetadata.instanceUrl' -Default '')
                    if (-not $iu) { $iu = [string](Get-TPNestedProperty -Object $_ -Path 'properties.linkedEnvironmentMetadata.instanceApiUrl' -Default '') }
                    [ordered]@{
                        Id          = [string](Get-TPObjectField -Item $_ -Key 'name' -Default '')
                        DisplayName = [string](Get-TPNestedProperty -Object $_ -Path 'properties.displayName' -Default '')
                        InstanceUrl = $iu
                    }
                })
                $result.Data.EnvironmentListSource = 'bap-api'
                $result.Data.SectionStatus.Environments = 'Collected'
            } catch {
                $why = "Copilot Studio agents not collected: the Power Platform environment list could not be read ($((($_.Exception.Message) -split "`n")[0].Trim())). The account needs the Power Platform Administrator (or Global Administrator) role."
                $result.Data.SectionStatus.Environments = 'Failed'; $result.Data.SectionErrors['Environments'] = $why
                & $note 'CopilotStudio-Collector' $why
            }
        }
    }

    $envRecords = [System.Collections.Generic.List[object]]::new()
    $agents     = [System.Collections.Generic.List[object]]::new()
    if ($null -ne $envRows) {
        $result.Success = $true
        $dvCount = 0
        $signInFailures = 0
        foreach ($e in $envRows) {
            $rec = [ordered]@{
                Id               = $e.Id
                DisplayName      = $e.DisplayName
                Host             = ''
                HasDataverse     = $false
                AgentsStatus     = 'NotRun'
                ComponentsStatus = 'NotRun'
                OwnersStatus     = 'NotRun'
                Reason           = ''
                AgentCount       = 0
                ManagedAgentCount = 0
            }
            $envRecords.Add($rec)
            if (-not $e.Id) { continue }

            if ([string]::IsNullOrWhiteSpace($e.InstanceUrl)) {
                # Copilot Studio agents are rows in the Dataverse bot table:
                # an environment with no Dataverse database holds none.
                $rec.AgentsStatus = 'Collected'; $rec.ComponentsStatus = 'Collected'; $rec.OwnersStatus = 'Collected'
                $rec.Reason = 'No Dataverse database: the environment cannot hold Copilot Studio agents.'
                $result.Data.SectionStatus[$e.Id] = 'Collected'
                continue
            }
            $rec.HasDataverse = $true
            $inst = ConvertTo-TPDataverseInstance -Url $e.InstanceUrl
            if (-not $inst) {
                $why = 'The environment''s Dataverse URL is not a recognized Dataverse host, so it was not contacted.'
                $rec.AgentsStatus = 'Failed'; $rec.ComponentsStatus = 'Failed'; $rec.OwnersStatus = 'Failed'; $rec.Reason = $why
                $result.Data.SectionStatus[$e.Id] = 'Failed'; $result.Data.SectionErrors[$e.Id] = $why
                & $note "CopilotStudio-$($e.Id)" "$($e.DisplayName): $why"
                continue
            }
            $rec.Host = $inst.Host
            $dvCount++
            if ($dvCount -gt $lim.MaxEnvironments) {
                $why = "Not read: the cap of $($lim.MaxEnvironments) Dataverse environments per run was reached."
                $rec.Reason = $why
                $result.Data.SectionStatus[$e.Id] = 'NotRun'; $result.Data.SectionErrors[$e.Id] = $why
                continue
            }

            $base = "$($inst.BaseUrl)$($script:TPDataverseApiPath)"
            $token = $null
            if ($signInFailures -ge 2) {
                $why = 'Not read: the Dataverse sign-in failed for two environments in a row, so no further sign-in was attempted in this run.'
                $rec.AgentsStatus = 'Failed'; $rec.ComponentsStatus = 'Failed'; $rec.OwnersStatus = 'Failed'; $rec.Reason = $why
                $result.Data.SectionStatus[$e.Id] = 'Failed'; $result.Data.SectionErrors[$e.Id] = $why
                continue
            }
            try {
                $token = Get-TPPowerPlatformToken -TenantId $tenantId -LoginHint $account -Audience $inst.BaseUrl
                $signInFailures = 0
            } catch {
                $signInFailures++
                $why = "Sign-in to the environment's Dataverse API failed: $((($_.Exception.Message) -split "`n")[0].Trim())"
                $rec.AgentsStatus = 'Failed'; $rec.ComponentsStatus = 'Failed'; $rec.OwnersStatus = 'Failed'; $rec.Reason = $why
                $result.Data.SectionStatus[$e.Id] = 'Failed'; $result.Data.SectionErrors[$e.Id] = $why
                & $note "CopilotStudio-$($e.Id)" "$($e.DisplayName): $why"
                continue
            }
            $result.Data.Source = 'dataverse'

            # Agents
            $bots = @()
            try {
                $sel = 'botid,name,schemaname,accesscontrolpolicy,authenticationmode,authenticationtrigger,statecode,publishedon,modifiedon,createdon,ismanaged,configuration,_owninguser_value,_owningteam_value'
                $r = Invoke-TPDataverseApi -Token $token -Paged -PageSize $lim.AgentPageSize -MaxPages $lim.MaxAgentPages -Uri "${base}bots?`$select=$sel"
                $bots = @($r.Rows)
                $rec.AgentsStatus = if ($r.Truncated) { 'Truncated' } else { 'Collected' }
                if ($r.Truncated) { $rec.Reason = "More than $($lim.AgentPageSize * $lim.MaxAgentPages) agents: only the first $($bots.Count) were read." }
            } catch {
                $why = Get-TPDataverseFailureReason -ErrorRecord $_ -What 'Reading the agents (bot table)'
                $rec.AgentsStatus = 'Failed'; $rec.ComponentsStatus = 'NotRun'; $rec.OwnersStatus = 'NotRun'; $rec.Reason = $why
                $result.Data.SectionStatus[$e.Id] = 'Failed'; $result.Data.SectionErrors[$e.Id] = $why
                & $note "CopilotStudio-$($e.Id)" "$($e.DisplayName): $why"
                continue
            }
            $botIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($b in $bots) { $null = $botIds.Add([string](Get-TPObjectField -Item $b -Key 'botid' -Default '')) }

            # Components (topics, tools, Custom GPT): judged here, never kept.
            $compByBot = @{}
            if ($bots.Count -eq 0) {
                $rec.ComponentsStatus = 'Collected'
            } else {
                try {
                    $r = Invoke-TPDataverseApi -Token $token -Paged -PageSize $lim.ComponentPageSize -MaxPages $lim.MaxComponentPages `
                        -Uri "${base}botcomponents?`$select=botcomponentid,name,componenttype,statecode,data,content,_parentbotid_value&`$filter=componenttype eq 9 or componenttype eq 15"
                    foreach ($c in @($r.Rows)) {
                        $parentId = [string](Get-TPObjectField -Item $c -Key '_parentbotid_value' -Default '')
                        if (-not $parentId -or -not $botIds.Contains($parentId)) { continue }
                        $ctype = 0; $null = [int]::TryParse([string](Get-TPObjectField -Item $c -Key 'componenttype' -Default ''), [ref]$ctype)
                        $cid   = [string](Get-TPObjectField -Item $c -Key 'botcomponentid' -Default '')
                        $text  = ([string](Get-TPObjectField -Item $c -Key 'data' -Default '')) + "`n" + ([string](Get-TPObjectField -Item $c -Key 'content' -Default ''))
                        $f = Get-TPCopilotStudioComponentFacts -Text $text -ComponentType $ctype -ComponentId $cid -ComponentName ([string](Get-TPObjectField -Item $c -Key 'name' -Default ''))
                        $f['Active'] = ([string](Get-TPObjectField -Item $c -Key 'statecode' -Default '0')) -eq '0'
                        $f['ComponentType'] = $ctype
                        if (-not $compByBot.ContainsKey($parentId)) { $compByBot[$parentId] = [System.Collections.Generic.List[object]]::new() }
                        $compByBot[$parentId].Add($f)
                        $text = $null
                    }
                    $rec.ComponentsStatus = if ($r.Truncated) { 'Truncated' } else { 'Collected' }
                    if ($r.Truncated) {
                        $why = "More than $($lim.ComponentPageSize * $lim.MaxComponentPages) agent components: the topic and tool definitions were read in part."
                        $rec.Reason = (@($rec.Reason, $why) | Where-Object { $_ }) -join ' '
                    }
                } catch {
                    $why = Get-TPDataverseFailureReason -ErrorRecord $_ -What 'Reading the agent components (botcomponent table)'
                    $rec.ComponentsStatus = 'Failed'
                    $rec.Reason = (@($rec.Reason, $why) | Where-Object { $_ }) -join ' '
                    & $note "CopilotStudio-$($e.Id)" "$($e.DisplayName): $why"
                }
            }

            # Owners: Dataverse user -> Entra object id.
            $ownerMap = @{}
            $ownerIds = @($bots | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key '_owninguser_value' -Default '') } | Where-Object { $_ -match '^[0-9a-fA-F-]{36}$' } | Sort-Object -Unique)
            if ($ownerIds.Count -eq 0) {
                $rec.OwnersStatus = 'Collected'
            } else {
                try {
                    for ($i = 0; $i -lt $ownerIds.Count; $i += $lim.OwnerBatchSize) {
                        $batch = @($ownerIds[$i..([Math]::Min($i + $lim.OwnerBatchSize, $ownerIds.Count) - 1)])
                        $filter = ($batch | ForEach-Object { "systemuserid eq $_" }) -join ' or '
                        $r = Invoke-TPDataverseApi -Token $token -Paged -PageSize 100 -MaxPages 5 `
                            -Uri "${base}systemusers?`$select=systemuserid,azureactivedirectoryobjectid,isdisabled,applicationid&`$filter=$filter"
                        foreach ($u in @($r.Rows)) {
                            $ownerMap[([string](Get-TPObjectField -Item $u -Key 'systemuserid' -Default '')).ToLowerInvariant()] = [ordered]@{
                                EntraObjectId     = [string](Get-TPObjectField -Item $u -Key 'azureactivedirectoryobjectid' -Default '')
                                DataverseDisabled = Get-TPObjectField -Item $u -Key 'isdisabled' -Default $null
                                IsApplication     = -not [string]::IsNullOrWhiteSpace([string](Get-TPObjectField -Item $u -Key 'applicationid' -Default ''))
                            }
                        }
                    }
                    $rec.OwnersStatus = 'Collected'
                } catch {
                    $why = Get-TPDataverseFailureReason -ErrorRecord $_ -What 'Reading the agent owners (systemuser table)'
                    $rec.OwnersStatus = 'Failed'
                    $rec.Reason = (@($rec.Reason, $why) | Where-Object { $_ }) -join ' '
                    & $note "CopilotStudio-$($e.Id)" "$($e.DisplayName): $why"
                }
            }

            $accessMap  = @{ 0 = 'Any'; 1 = 'Agent readers'; 2 = 'Group membership'; 3 = 'Any (multi-tenant)' }
            $authMap    = @{ 0 = 'Unspecified'; 1 = 'None'; 2 = 'Integrated'; 3 = 'Custom Entra ID'; 4 = 'Generic OAuth2' }
            $triggerMap = @{ 0 = 'As Needed'; 1 = 'Always' }
            foreach ($b in $bots) {
                $id = [string](Get-TPObjectField -Item $b -Key 'botid' -Default '')
                $orch = Get-TPCopilotStudioOrchestration -Configuration ([string](Get-TPObjectField -Item $b -Key 'configuration' -Default ''))
                # Two statements: an if-statement that yields an empty array assigns $null.
                $comps = @()
                if ($compByBot.ContainsKey($id)) { $comps = @($compByBot[$id]) }
                $active = @($comps | Where-Object { $_.Active })
                $gpt = @($comps | Where-Object { $_.ComponentType -eq 15 })
                $instr = $null
                if ($rec.ComponentsStatus -eq 'Collected') {
                    $instr = (@($gpt | Where-Object { $_.HasInstructions -eq $true }).Count -gt 0) -or ($orch.Instructions -eq $true)
                } elseif ($orch.Instructions -eq $true -or @($gpt | Where-Object { $_.HasInstructions -eq $true }).Count -gt 0) {
                    $instr = $true
                }
                $owningUser = [string](Get-TPObjectField -Item $b -Key '_owninguser_value' -Default '')
                $owningTeam = [string](Get-TPObjectField -Item $b -Key '_owningteam_value' -Default '')
                $owner = [ordered]@{ Kind = 'Unknown'; EntraObjectId = ''; DataverseDisabled = $null }
                if ($owningUser) {
                    $o = $ownerMap[$owningUser.ToLowerInvariant()]
                    if ($o) {
                        $owner.Kind = if ($o.IsApplication) { 'Application' } else { 'User' }
                        $owner.EntraObjectId = $o.EntraObjectId
                        $owner.DataverseDisabled = $o.DataverseDisabled
                    } elseif ($rec.OwnersStatus -eq 'Collected') {
                        $owner.Kind = 'UserNotFoundInDataverse'
                    }
                } elseif ($owningTeam) {
                    $owner.Kind = 'Team'
                }
                $managed = [bool](Get-TPObjectField -Item $b -Key 'ismanaged' -Default $false)
                if ($managed) { $rec.ManagedAgentCount++ }
                $pub = Get-TPObjectField -Item $b -Key 'publishedon' -Default $null
                $agents.Add([ordered]@{
                    Id                         = $id
                    Name                       = [string](Get-TPObjectField -Item $b -Key 'name' -Default '')
                    EnvironmentId              = $e.Id
                    EnvironmentName            = $e.DisplayName
                    IsManaged                  = $managed
                    State                      = $(if (([string](Get-TPObjectField -Item $b -Key 'statecode' -Default '')) -eq '1') { 'Inactive' } else { 'Active' })
                    Published                  = ($null -ne $pub -and "$pub" -ne '')
                    PublishedOn                = ConvertTo-TPCopilotStudioDate $pub
                    ModifiedOn                 = ConvertTo-TPCopilotStudioDate (Get-TPObjectField -Item $b -Key 'modifiedon' -Default $null)
                    CreatedOn                  = ConvertTo-TPCopilotStudioDate (Get-TPObjectField -Item $b -Key 'createdon' -Default $null)
                    AccessControlPolicy        = Get-TPCopilotStudioOptionLabel -Value (Get-TPObjectField -Item $b -Key 'accesscontrolpolicy' -Default $null) -Map $accessMap
                    AuthenticationMode         = Get-TPCopilotStudioOptionLabel -Value (Get-TPObjectField -Item $b -Key 'authenticationmode' -Default $null) -Map $authMap
                    AuthenticationTrigger      = Get-TPCopilotStudioOptionLabel -Value (Get-TPObjectField -Item $b -Key 'authenticationtrigger' -Default $null) -Map $triggerMap
                    GenerativeOrchestration    = $orch.Generative
                    CustomInstructionsPresent  = $instr
                    ComponentCount             = $comps.Count
                    HttpNodes                  = @($active | ForEach-Object { $_.HttpNodes } | Where-Object { $_ })
                    EmailTools                 = @($active | ForEach-Object { $_.EmailTool } | Where-Object { $_ })
                    ConnectorTools             = @($active | ForEach-Object { $_.ConnectorTool } | Where-Object { $_ })
                    McpTools                   = @($active | ForEach-Object { $_.McpTool } | Where-Object { $_ })
                    CredentialMatches          = @($comps | ForEach-Object { $comp = $_; @($comp.CredentialPatterns) | ForEach-Object { [ordered]@{ ComponentId = $comp['ComponentId']; PatternType = $_ } } })
                    Owner                      = $owner
                })
            }
            $rec.AgentCount = $bots.Count

            $worst = 'Collected'
            foreach ($s in @($rec.AgentsStatus, $rec.ComponentsStatus, $rec.OwnersStatus)) {
                if ($s -eq 'Failed') { $worst = 'Failed' }
                elseif ($s -eq 'Truncated' -and $worst -ne 'Failed') { $worst = 'Truncated' }
                elseif ($s -eq 'NotRun' -and $worst -eq 'Collected') { $worst = 'NotRun' }
            }
            $result.Data.SectionStatus[$e.Id] = $worst
            if ($worst -ne 'Collected' -and $rec.Reason) { $result.Data.SectionErrors[$e.Id] = $rec.Reason }
        }
    }
    $result.Data.Environments = $envRecords.ToArray()
    $result.Data.Agents       = $agents.ToArray()

    if (Get-Command Set-TPRawData -ErrorAction SilentlyContinue) {
        Set-TPRawData -Key 'CopilotStudio' -Data $result
    }
    if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
        $dv = @($envRecords | Where-Object { $_.HasDataverse })
        $bad = @($dv | Where-Object { $_.AgentsStatus -ne 'Collected' -or $_.ComponentsStatus -ne 'Collected' -or $_.OwnersStatus -ne 'Collected' })
        $covNote = "Environments=$($envRecords.Count) Dataverse=$($dv.Count) Agents=$($agents.Count)"
        if (-not $result.Success) {
            Register-TPCoverage -Family 'CopilotStudio' -Status 'Failed' -Note ($result.Errors -join '; ')
        } elseif ($dv.Count -gt 0 -and $bad.Count -eq $dv.Count) {
            Register-TPCoverage -Family 'CopilotStudio' -Status 'Failed' -Note "$covNote; no Dataverse environment was read in full (see Exceptions)"
        } elseif ($bad.Count -gt 0) {
            Register-TPCoverage -Family 'CopilotStudio' -Status 'Partial' -Note "$covNote; $($bad.Count) environment(s) read in part or not at all (see Exceptions)"
        } else {
            Register-TPCoverage -Family 'CopilotStudio' -Status 'Collected' -Note $covNote
        }
    }
    return $result
}
