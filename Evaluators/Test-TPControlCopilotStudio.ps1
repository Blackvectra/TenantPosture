#Requires -Version 7.0
#
# Test-TPControlCopilotStudio.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Evaluate Copilot Studio agent security (PPL-4.1 to PPL-4.10) from
# the derived facts the Copilot Studio collector stores.
#
# Reads:   Get-TPRawData -Key 'CopilotStudio' (every control)
#          Get-TPRawData -Key 'AAD-Users'     (PPL-4.9, owner accounts)
#          Config/tp-standards.json CopilotStudioDormantDays (PPL-4.10)
# Cmdlets / scopes: none (raw data only).
#
# Verdict rules, the same for every control here:
#   - no Copilot Studio data (collector did not run or the environment list
#     was not read): not assessed, with the reason the collector recorded;
#   - an offending agent found anywhere: Gap, naming up to five (every one in
#     AffectedObjects), and saying which environments were not read;
#   - otherwise, any Dataverse environment not read in full, or any agent
#     whose fact could not be established: not assessed, naming them;
#   - otherwise Satisfied, stating how many agents and environments were read.
# Agents from managed solutions are set aside from every verdict and counted
# in the Detail (Maester does the same for built-in agents): they are
# installed by a solution publisher and their definition is not edited in the
# environment.

function Get-TPCopilotStudioView {
    <#
    .SYNOPSIS
        The Copilot Studio raw data reduced to what every PPL-4 evaluator
        needs: whether it is usable, the Dataverse environments, the agents
        judged (managed solutions set aside) and the count set aside.
    #>
    [CmdletBinding()]
    param()
    $raw = Get-TPRawData -Key 'CopilotStudio'
    $view = [ordered]@{
        Raw = $raw; Available = $false; NotCollectedDetail = ''
        Environments = @(); Dataverse = @(); Agents = @(); Managed = 0; ManagedNames = @()
    }
    $ok = $raw -and (Get-TPObjectField -Item $raw -Key 'Success' -Default $false) -and
          ([string](Get-TPNestedProperty -Object $raw -Path 'Data.SectionStatus.Environments' -Default '') -eq 'Collected')
    if (-not $ok) {
        $view.NotCollectedDetail = Get-TPSectionNotCollectedDetail -Raw $raw -Section 'Environments' -CollectorSource 'CopilotStudio-Collector'
        # The helper's sentence stays the prefix: the scope classifier and the
        # baseline reason contract key on it.
        $view.NotCollectedDetail += ' (The Power Platform environment list the Copilot Studio agents are read from.)'
        if (-not $raw) { $view.NotCollectedDetail += ' The Copilot Studio collector did not run (it runs with the Power Platform collector; -SkipPowerPlatform skips both).' }
        return $view
    }
    $view.Available    = $true
    $view.Environments = @(@(Get-TPNestedProperty -Object $raw -Path 'Data.Environments' -Default @()) | Where-Object { $null -ne $_ })
    $view.Dataverse    = @($view.Environments | Where-Object { (Get-TPObjectField -Item $_ -Key 'HasDataverse' -Default $false) -eq $true })
    $all = @(@(Get-TPNestedProperty -Object $raw -Path 'Data.Agents' -Default @()) | Where-Object { $null -ne $_ })
    $managed = @($all | Where-Object { (Get-TPObjectField -Item $_ -Key 'IsManaged' -Default $false) -eq $true })
    $view.Managed = $managed.Count
    $view.Agents  = @($all | Where-Object { (Get-TPObjectField -Item $_ -Key 'IsManaged' -Default $false) -ne $true })
    return $view
}

function Get-TPCopilotStudioUnread {
    <#
    .SYNOPSIS
        Dataverse environments whose reads named in -Need (Agents, Components,
        Owners) did not complete, each with the reason the collector recorded.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $View, [Parameter(Mandatory)] [string[]] $Need)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($e in $View.Dataverse) {
        $bad = @(foreach ($n in $Need) {
            $s = [string](Get-TPObjectField -Item $e -Key "${n}Status" -Default 'NotRun')
            if ($s -ne 'Collected') { "$n $s" }
        })
        if ($bad.Count -eq 0) { continue }
        $name = [string](Get-TPObjectField -Item $e -Key 'DisplayName' -Default '')
        if (-not $name) { $name = [string](Get-TPObjectField -Item $e -Key 'Id' -Default '?') }
        $why = [string](Get-TPObjectField -Item $e -Key 'Reason' -Default '')
        $out.Add([ordered]@{
            Environment   = $name
            EnvironmentId = [string](Get-TPObjectField -Item $e -Key 'Id' -Default '')
            Status        = ($bad -join ', ')
            Reason        = $why
        })
    }
    return $out.ToArray()
}

function Format-TPCopilotStudioList {
    [CmdletBinding()]
    [OutputType([string])]
    param([string[]] $Items, [int] $Max = 5)
    $items = @($Items | Where-Object { $_ })
    if ($items.Count -le $Max) { return ($items -join '; ') }
    return ((@($items | Select-Object -First $Max)) -join '; ') + "; and $($items.Count - $Max) more"
}

function Add-TPCopilotStudioVerdict {
    <#
    .SYNOPSIS
        Emits the one finding for a PPL-4 control under the verdict rules in
        the file header. -Offenders and -Undetermined are lists of
        @{ Agent; Issue; Extra } built by the caller from the stored facts.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ControlId,
        [Parameter(Mandatory)] $Control,
        [AllowNull()] [string[]] $FrameworkIds,
        [Parameter(Mandatory)] $View,
        [Parameter(Mandatory)] [string[]] $Need,
        [AllowNull()] [object[]] $Offenders,
        [AllowNull()] [object[]] $Undetermined,
        [Parameter(Mandatory)] [string] $PassSentence,
        [Parameter(Mandatory)] [string] $GapSentence,
        [Parameter(Mandatory)] [string] $RequiredValue,
        [string] $Caveat = ''
    )
    $cit = @($FrameworkIds)
    $title = [string]$Control.Title
    $unread = @(Get-TPCopilotStudioUnread -View $View -Need $Need)
    $off = @($Offenders | Where-Object { $_ })
    $und = @($Undetermined | Where-Object { $_ })
    $agentLabel = { param($a) "$([string](Get-TPObjectField -Item $a -Key 'Name' -Default '?')) ($([string](Get-TPObjectField -Item $a -Key 'EnvironmentName' -Default '?')))" }
    $managedNote = if ($View.Managed -gt 0) { " $($View.Managed) agent(s) from managed solutions were set aside from this verdict." } else { '' }
    $caveatText = if ($Caveat) { " $Caveat" } else { '' }
    $unreadText = if ($unread.Count -gt 0) {
        "Copilot Studio agents were not collected in full in $($unread.Count) of $($View.Dataverse.Count) Dataverse environment(s): " +
            (Format-TPCopilotStudioList -Items @($unread | ForEach-Object { "$($_.Environment) ($($_.Status)$(if ($_.Reason) { ": $($_.Reason)" }))" }) -Max 5) + '.'
    } else { '' }

    if ($off.Count -gt 0) {
        $names = Format-TPCopilotStudioList -Items @($off | ForEach-Object { "$(& $agentLabel $_.Agent): $($_.Issue)" }) -Max 5
        $detail = "$GapSentence $($off.Count) agent(s): $names."
        if ($unreadText) { $detail += " $unreadText This Gap stands on the agents that were read; the others were not assessed." }
        $detail += $managedNote + $caveatText
        $affected = @($off | ForEach-Object {
            $o = [ordered]@{
                Agent         = [string](Get-TPObjectField -Item $_.Agent -Key 'Name' -Default '')
                AgentId       = [string](Get-TPObjectField -Item $_.Agent -Key 'Id' -Default '')
                Environment   = [string](Get-TPObjectField -Item $_.Agent -Key 'EnvironmentName' -Default '')
                EnvironmentId = [string](Get-TPObjectField -Item $_.Agent -Key 'EnvironmentId' -Default '')
                Issue         = [string]$_.Issue
            }
            if ($_.Contains('Extra') -and $_.Extra) { foreach ($k in $_.Extra.Keys) { $o[$k] = $_.Extra[$k] } }
            $o
        })
        Add-TPFinding -ControlId $ControlId -State 'Gap' -Category 'Power Platform' -Title $title -Severity $Control.Severity -FrameworkIds $cit `
            -Detail $detail -CurrentValue "$($off.Count) agent(s) fall short" -RequiredValue $RequiredValue -Remediation $Control.Remediation -AffectedObjects $affected
        return
    }
    if ($unread.Count -gt 0 -or $und.Count -gt 0) {
        $parts = [System.Collections.Generic.List[string]]::new()
        if ($unreadText) { $parts.Add($unreadText) }
        if ($und.Count -gt 0) {
            $parts.Add("For $($und.Count) agent(s) the fact this control judges could not be established: " + (Format-TPCopilotStudioList -Items @($und | ForEach-Object { "$(& $agentLabel $_.Agent): $($_.Issue)" }) -Max 5) + '.')
        }
        $affected = @($und | ForEach-Object {
            [ordered]@{
                Agent       = [string](Get-TPObjectField -Item $_.Agent -Key 'Name' -Default '')
                AgentId     = [string](Get-TPObjectField -Item $_.Agent -Key 'Id' -Default '')
                Environment = [string](Get-TPObjectField -Item $_.Agent -Key 'EnvironmentName' -Default '')
                Issue       = "Not established: $($_.Issue)"
            }
        })
        Add-TPFinding -ControlId $ControlId -State 'NotApplicable' -Category 'Power Platform' -Title $title -FrameworkIds $cit `
            -Detail ("Not assessed. " + ($parts -join ' ') + " No offending agent was found among those read.$managedNote$caveatText") `
            -RequiredValue $RequiredValue -AffectedObjects $affected
        return
    }
    $n = $View.Agents.Count
    $envCount = $View.Dataverse.Count
    Add-TPFinding -ControlId $ControlId -State 'Satisfied' -Category 'Power Platform' -Title $title -Severity 'Informational' -FrameworkIds $cit `
        -Detail "$PassSentence Read in full: $n agent(s) in $envCount Dataverse environment(s) of $($View.Environments.Count) environment(s).$managedNote$caveatText" `
        -CurrentValue "$n agent(s) read in $envCount Dataverse environment(s); none falls short" -RequiredValue $RequiredValue
}

function Get-TPCopilotStudioControl {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ControlId)
    $c = Get-TPControlById -ControlId $ControlId
    if (-not $c) { return $null }
    return [ordered]@{ Control = $c; Cit = @(Get-TPFrameworkCitations -ControlId $ControlId) }
}

function Add-TPCopilotStudioNotCollected {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ControlId, [Parameter(Mandatory)] $Ctl, [Parameter(Mandatory)] $View)
    Add-TPFinding -ControlId $ControlId -State 'NotApplicable' -Category 'Power Platform' -Title $Ctl.Control.Title -FrameworkIds $Ctl.Cit `
        -Detail $View.NotCollectedDetail
}

# ── PPL-4.1  Agents not shared with everyone or any tenant ──────────────────
function Test-TPControlCopilotStudioSharing {
    [CmdletBinding()] param()
    $cid = 'PPL-4.1'
    $ctl = Get-TPCopilotStudioControl -ControlId $cid; if (-not $ctl) { return }
    $view = Get-TPCopilotStudioView
    if (-not $view.Available) { Add-TPCopilotStudioNotCollected -ControlId $cid -Ctl $ctl -View $view; return }
    $off = [System.Collections.Generic.List[object]]::new(); $und = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $view.Agents) {
        $acp = [string](Get-TPObjectField -Item $a -Key 'AccessControlPolicy' -Default 'Not returned')
        if ($acp -in 'Any', 'Any (multi-tenant)') { $off.Add(@{ Agent = $a; Issue = "access control '$acp'"; Extra = [ordered]@{ AccessControlPolicy = $acp } }) }
        elseif ($acp -notin 'Agent readers', 'Group membership') { $und.Add(@{ Agent = $a; Issue = "access control $acp" }) }
    }
    Add-TPCopilotStudioVerdict -ControlId $cid -Control $ctl.Control -FrameworkIds $ctl.Cit -View $view -Need 'Agents' -Offenders $off -Undetermined $und `
        -PassSentence 'Every Copilot Studio agent limits who can chat with it to the users it is shared with (Agent readers) or to named security groups (Group membership).' `
        -GapSentence 'Copilot Studio agents whose access control lets anyone (Any) or any tenant (Any (multi-tenant)) chat with them:' `
        -RequiredValue 'Access control Agent readers or Group membership on every agent'
}

# ── PPL-4.2  Agents require authentication, with sign-in required ───────────
function Test-TPControlCopilotStudioAuthentication {
    [CmdletBinding()] param()
    $cid = 'PPL-4.2'
    $ctl = Get-TPCopilotStudioControl -ControlId $cid; if (-not $ctl) { return }
    $view = Get-TPCopilotStudioView
    if (-not $view.Available) { Add-TPCopilotStudioNotCollected -ControlId $cid -Ctl $ctl -View $view; return }
    $off = [System.Collections.Generic.List[object]]::new(); $und = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $view.Agents) {
        $mode = [string](Get-TPObjectField -Item $a -Key 'AuthenticationMode' -Default 'Not returned')
        $trig = [string](Get-TPObjectField -Item $a -Key 'AuthenticationTrigger' -Default 'Not returned')
        switch ($mode) {
            'None' { $off.Add(@{ Agent = $a; Issue = 'no authentication (anyone with the link can chat)'; Extra = [ordered]@{ AuthenticationMode = $mode } }) }
            'Integrated' { }   # Authenticate with Microsoft: users are always signed in (Learn).
            { $_ -in 'Custom Entra ID', 'Generic OAuth2' } {
                if ($trig -eq 'As Needed') { $off.Add(@{ Agent = $a; Issue = "manual authentication ($mode) without 'Require users to sign in'"; Extra = [ordered]@{ AuthenticationMode = $mode; AuthenticationTrigger = $trig } }) }
                elseif ($trig -ne 'Always') { $und.Add(@{ Agent = $a; Issue = "sign-in requirement $trig" }) }
            }
            default { $und.Add(@{ Agent = $a; Issue = "authentication mode $mode" }) }
        }
    }
    Add-TPCopilotStudioVerdict -ControlId $cid -Control $ctl.Control -FrameworkIds $ctl.Cit -View $view -Need 'Agents' -Offenders $off -Undetermined $und `
        -PassSentence "Every Copilot Studio agent authenticates its users: Authenticate with Microsoft, or manual authentication with 'Require users to sign in' on." `
        -GapSentence 'Copilot Studio agents that can be used without signing in:' `
        -RequiredValue "Authenticate with Microsoft, or manual authentication with 'Require users to sign in' (authentication trigger Always)"
}

# ── PPL-4.3  No HTTP request nodes over plain HTTP or a non-443 port ────────
function Test-TPControlCopilotStudioHttpNodes {
    [CmdletBinding()] param()
    $cid = 'PPL-4.3'
    $ctl = Get-TPCopilotStudioControl -ControlId $cid; if (-not $ctl) { return }
    $view = Get-TPCopilotStudioView
    if (-not $view.Available) { Add-TPCopilotStudioNotCollected -ControlId $cid -Ctl $ctl -View $view; return }
    $off = [System.Collections.Generic.List[object]]::new(); $und = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $view.Agents) {
        $nodes = @(@(Get-TPObjectField -Item $a -Key 'HttpNodes' -Default @()) | Where-Object { $_ })
        $risky = @($nodes | Where-Object { (Get-TPObjectField -Item $_ -Key 'Risky' -Default $false) -eq $true })
        $open  = @($nodes | Where-Object { (Get-TPObjectField -Item $_ -Key 'Undetermined' -Default $false) -eq $true })
        if ($risky.Count -gt 0) {
            $desc = @($risky | ForEach-Object {
                $p = Get-TPObjectField -Item $_ -Key 'Port' -Default $null
                "$([string](Get-TPObjectField -Item $_ -Key 'Scheme' -Default '?'))$(if ($null -ne $p) { " port $p" }) in component $([string](Get-TPObjectField -Item $_ -Key 'ComponentId' -Default '?'))"
            })
            $off.Add(@{ Agent = $a; Issue = "$($risky.Count) HTTP request node(s): $(Format-TPCopilotStudioList -Items $desc -Max 3)"; Extra = [ordered]@{ Nodes = ($desc -join '; ') } })
        } elseif ($open.Count -gt 0) {
            $und.Add(@{ Agent = $a; Issue = "$($open.Count) HTTP request node(s) whose URL is built at run time, so the scheme and port cannot be read" })
        }
    }
    Add-TPCopilotStudioVerdict -ControlId $cid -Control $ctl.Control -FrameworkIds $ctl.Cit -View $view -Need 'Agents', 'Components' -Offenders $off -Undetermined $und `
        -PassSentence 'No active Copilot Studio topic sends an HTTP request over plain HTTP or to a port other than 443.' `
        -GapSentence 'Copilot Studio agents with HTTP request nodes over plain HTTP or to a non-standard port (scheme and port only; the address is not recorded):' `
        -RequiredValue 'Every HTTP request node uses https on port 443' `
        -Caveat 'The URL is read from each HTTP request node in the topic definition; a URL assembled entirely from variables cannot be read.'
}

# ── PPL-4.4  No email tools with AI-controlled recipient, subject or body ───
function Test-TPControlCopilotStudioEmailTools {
    [CmdletBinding()] param()
    $cid = 'PPL-4.4'
    $ctl = Get-TPCopilotStudioControl -ControlId $cid; if (-not $ctl) { return }
    $view = Get-TPCopilotStudioView
    if (-not $view.Available) { Add-TPCopilotStudioNotCollected -ControlId $cid -Ctl $ctl -View $view; return }
    $off = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $view.Agents) {
        $tools = @(@(Get-TPObjectField -Item $a -Key 'EmailTools' -Default @()) | Where-Object { $_ -and (Get-TPObjectField -Item $_ -Key 'AIControlled' -Default $false) -eq $true })
        if ($tools.Count -eq 0) { continue }
        $desc = @($tools | ForEach-Object { "$([string](Get-TPObjectField -Item $_ -Key 'ToolName' -Default '?')) ($(@(Get-TPObjectField -Item $_ -Key 'AIControlledFields' -Default @()) -join ', ') not fixed)" })
        $off.Add(@{ Agent = $a; Issue = "email tool(s) $(Format-TPCopilotStudioList -Items $desc -Max 3)"; Extra = [ordered]@{ EmailTools = ($desc -join '; ') } })
    }
    Add-TPCopilotStudioVerdict -ControlId $cid -Control $ctl.Control -FrameworkIds $ctl.Cit -View $view -Need 'Agents', 'Components' -Offenders $off -Undetermined @() `
        -PassSentence 'No active Copilot Studio tool sends email with a recipient, subject or body left for the AI (or the conversation) to fill.' `
        -GapSentence 'Copilot Studio agents with an email-sending tool whose recipient, subject or body is not a fixed value (Microsoft documents that an input without a custom value is filled dynamically with AI):' `
        -RequiredValue 'Email-sending tools removed, or To, Subject and Body set as fixed custom values' `
        -Caveat 'Email tools are the Office 365 Outlook, Outlook.com, Mail, Gmail and SMTP connectors'' send, forward and reply operations; a value set by a Power Fx formula counts as not fixed.'
}

# ── PPL-4.5  Connector tools use end-user, not maker, credentials ───────────
function Test-TPControlCopilotStudioMakerAuth {
    [CmdletBinding()] param()
    $cid = 'PPL-4.5'
    $ctl = Get-TPCopilotStudioControl -ControlId $cid; if (-not $ctl) { return }
    $view = Get-TPCopilotStudioView
    if (-not $view.Available) { Add-TPCopilotStudioNotCollected -ControlId $cid -Ctl $ctl -View $view; return }
    $off = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $view.Agents) {
        $tools = @(@(Get-TPObjectField -Item $a -Key 'ConnectorTools' -Default @()) | Where-Object { $_ -and [string](Get-TPObjectField -Item $_ -Key 'AuthMode' -Default '') -ne 'EndUser' })
        if ($tools.Count -eq 0) { continue }
        $desc = @($tools | ForEach-Object {
            $conn = [string](Get-TPObjectField -Item $_ -Key 'Connector' -Default '')
            "$([string](Get-TPObjectField -Item $_ -Key 'ToolName' -Default '?'))$(if ($conn) { " ($conn)" })"
        })
        $off.Add(@{ Agent = $a; Issue = "connector tool(s) without end-user credentials: $(Format-TPCopilotStudioList -Items $desc -Max 3)"; Extra = [ordered]@{ Tools = ($desc -join '; ') } })
    }
    Add-TPCopilotStudioVerdict -ControlId $cid -Control $ctl.Control -FrameworkIds $ctl.Cit -View $view -Need 'Agents', 'Components' -Offenders $off -Undetermined @() `
        -PassSentence 'Every active Copilot Studio connector tool runs with the end user''s own credentials.' `
        -GapSentence 'Copilot Studio agents with connector tools that do not use end-user credentials (they act with the maker''s stored connection for everyone who chats):' `
        -RequiredValue "Credentials to use: End user credentials on every connector tool (or the environment's 'Control maker credential options' set to end-user only)" `
        -Caveat 'A tool is read as using end-user credentials when its definition records the end-user (Invoker) connection mode; that reading follows Maester''s usage and is not yet confirmed against a live tenant.'
}

# ── PPL-4.6  No hard-coded credentials in topics (heuristic) ────────────────
function Test-TPControlCopilotStudioCredentials {
    [CmdletBinding()] param()
    $cid = 'PPL-4.6'
    $ctl = Get-TPCopilotStudioControl -ControlId $cid; if (-not $ctl) { return }
    $view = Get-TPCopilotStudioView
    if (-not $view.Available) { Add-TPCopilotStudioNotCollected -ControlId $cid -Ctl $ctl -View $view; return }
    $off = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $view.Agents) {
        $hits = @(@(Get-TPObjectField -Item $a -Key 'CredentialMatches' -Default @()) | Where-Object { $_ })
        if ($hits.Count -eq 0) { continue }
        $desc = @($hits | ForEach-Object { "$([string](Get-TPObjectField -Item $_ -Key 'PatternType' -Default '?')) in component $([string](Get-TPObjectField -Item $_ -Key 'ComponentId' -Default '?'))" } | Select-Object -Unique)
        $off.Add(@{ Agent = $a; Issue = Format-TPCopilotStudioList -Items $desc -Max 3; Extra = [ordered]@{ Matches = ($desc -join '; ') } })
    }
    Add-TPCopilotStudioVerdict -ControlId $cid -Control $ctl.Control -FrameworkIds $ctl.Cit -View $view -Need 'Agents', 'Components' -Offenders $off -Undetermined @() `
        -PassSentence 'No Copilot Studio topic or tool definition matched a credential pattern.' `
        -GapSentence 'Copilot Studio agents whose topic or tool definitions match a hard-coded credential pattern (pattern type and component id only; the matched value is never read into the report):' `
        -RequiredValue 'No credential written into a topic or tool; secrets kept in a connection, environment variable backed by Azure Key Vault, or the authentication settings' `
        -Caveat 'This is a heuristic pattern match (API keys, bearer and basic values, connection-string secrets, password or secret assignments, AWS key ids, private key blocks, JSON web tokens): confirm each match in the named component, and a credential in a shape these patterns do not cover is not found.'
}

# ── PPL-4.7  MCP tool integrations listed for review (advisory) ─────────────
function Test-TPControlCopilotStudioMcpTools {
    [CmdletBinding()] param()
    $cid = 'PPL-4.7'
    $ctl = Get-TPCopilotStudioControl -ControlId $cid; if (-not $ctl) { return }
    $view = Get-TPCopilotStudioView
    if (-not $view.Available) { Add-TPCopilotStudioNotCollected -ControlId $cid -Ctl $ctl -View $view; return }
    $found = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $view.Agents) {
        foreach ($t in @(@(Get-TPObjectField -Item $a -Key 'McpTools' -Default @()) | Where-Object { $_ })) {
            $found.Add([ordered]@{
                Agent       = [string](Get-TPObjectField -Item $a -Key 'Name' -Default '')
                AgentId     = [string](Get-TPObjectField -Item $a -Key 'Id' -Default '')
                Environment = [string](Get-TPObjectField -Item $a -Key 'EnvironmentName' -Default '')
                Tool        = [string](Get-TPObjectField -Item $t -Key 'ToolName' -Default '')
                ComponentId = [string](Get-TPObjectField -Item $t -Key 'ComponentId' -Default '')
                Host        = [string](Get-TPObjectField -Item $t -Key 'Host' -Default '')
            })
        }
    }
    $unread = @(Get-TPCopilotStudioUnread -View $view -Need 'Agents', 'Components')
    if ($found.Count -gt 0) {
        # Whether an MCP server was reviewed is not recorded anywhere the tool
        # can read, so this is never a pass and never a Gap.
        $hosts = @($found | ForEach-Object { $_.Host } | Where-Object { $_ } | Sort-Object -Unique)
        $list = Format-TPCopilotStudioList -Items @($found | ForEach-Object { "$($_.Agent) ($($_.Environment)): $($_.Tool) -> $($_.Host)" }) -Max 5
        $more = if ($unread.Count -gt 0) { " Agents in $($unread.Count) Dataverse environment(s) were not collected in full, so the list may be incomplete." } else { '' }
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category 'Power Platform' -Title "$($ctl.Control.Title) (Manual review required)" -FrameworkIds $ctl.Cit `
            -Detail "This control requires manual verification: $($found.Count) Model Context Protocol (MCP) tool(s) found on Copilot Studio agents, reaching $($hosts.Count) endpoint(s) ($(Format-TPCopilotStudioList -Items $hosts -Max 5)). $list. Confirm each MCP server is approved, owned and reviewed; the tool cannot read whether a review happened.$more" `
            -CurrentValue "$($found.Count) MCP tool(s); endpoints: $(Format-TPCopilotStudioList -Items $hosts -Max 5)" -AffectedObjects $found.ToArray()
        return
    }
    # No MCP tool found. Only a complete read can say there is none to review;
    # this control never reports a Gap, because a listed integration is a
    # review item, not a failure.
    if ($unread.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category 'Power Platform' -Title $ctl.Control.Title -FrameworkIds $ctl.Cit `
            -Detail ("Not assessed. Copilot Studio agents were not collected in full in $($unread.Count) of $($view.Dataverse.Count) Dataverse environment(s): " +
                (Format-TPCopilotStudioList -Items @($unread | ForEach-Object { "$($_.Environment) ($($_.Status)$(if ($_.Reason) { ": $($_.Reason)" }))" }) -Max 5) +
                '. No Model Context Protocol (MCP) tool was found among the agents that were read.')
        return
    }
    $managedNote = if ($view.Managed -gt 0) { " $($view.Managed) agent(s) from managed solutions were set aside." } else { '' }
    Add-TPFinding -ControlId $cid -State 'Satisfied' -Category 'Power Platform' -Title $ctl.Control.Title -Severity 'Informational' -FrameworkIds $ctl.Cit `
        -Detail "No active Copilot Studio tool connects to a Model Context Protocol (MCP) server, so there is no MCP integration to review. Read in full: $($view.Agents.Count) agent(s) in $($view.Dataverse.Count) Dataverse environment(s).$managedNote An MCP tool is recognized by the MCP markers in its tool definition." `
        -CurrentValue "No MCP tool on $($view.Agents.Count) agent(s)" -RequiredValue 'Every MCP tool integration reviewed and approved'
}

# ── PPL-4.8  Generative-orchestration agents have custom instructions ───────
function Test-TPControlCopilotStudioInstructions {
    [CmdletBinding()] param()
    $cid = 'PPL-4.8'
    $ctl = Get-TPCopilotStudioControl -ControlId $cid; if (-not $ctl) { return }
    $view = Get-TPCopilotStudioView
    if (-not $view.Available) { Add-TPCopilotStudioNotCollected -ControlId $cid -Ctl $ctl -View $view; return }
    $off = [System.Collections.Generic.List[object]]::new(); $und = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $view.Agents) {
        $gen = Get-TPObjectField -Item $a -Key 'GenerativeOrchestration' -Default $null
        if ($gen -eq $false) { continue }
        $ins = Get-TPObjectField -Item $a -Key 'CustomInstructionsPresent' -Default $null
        if ($null -eq $gen) {
            if ($ins -ne $true) { $und.Add(@{ Agent = $a; Issue = 'generative orchestration setting not read' }) }
            continue
        }
        if ($ins -eq $false) { $off.Add(@{ Agent = $a; Issue = 'generative orchestration on, no custom instructions' }) }
        elseif ($ins -ne $true) { $und.Add(@{ Agent = $a; Issue = 'custom instructions not read' }) }
    }
    Add-TPCopilotStudioVerdict -ControlId $cid -Control $ctl.Control -FrameworkIds $ctl.Cit -View $view -Need 'Agents', 'Components' -Offenders $off -Undetermined $und `
        -PassSentence 'Every Copilot Studio agent that uses generative orchestration carries custom instructions.' `
        -GapSentence 'Copilot Studio agents that use generative orchestration with no custom instructions (only whether instructions exist is read; their text is not):' `
        -RequiredValue 'Custom instructions on every agent that uses generative orchestration' `
        -Caveat 'Generative orchestration is read from the agent configuration and instructions from the agent''s instructions component, following Maester''s usage; neither field is described on Microsoft Learn, and the reading is not yet confirmed against a live tenant.'
}

# ── PPL-4.9  Agents not orphaned ────────────────────────────────────────────
function Test-TPControlCopilotStudioOwnership {
    [CmdletBinding()] param()
    $cid = 'PPL-4.9'
    $ctl = Get-TPCopilotStudioControl -ControlId $cid; if (-not $ctl) { return }
    $view = Get-TPCopilotStudioView
    if (-not $view.Available) { Add-TPCopilotStudioNotCollected -ControlId $cid -Ctl $ctl -View $view; return }

    $users = Get-TPRawData -Key 'AAD-Users'
    $usersStatus = Get-TPNestedProperty -Object $users -Path 'Data.SectionStatus.Users' -Default $null
    # An older results file has no Users status: the list it carries is read as complete.
    $usersRead = $users -and (Get-TPObjectField -Item $users -Key 'Success' -Default $false) -and ($null -eq $usersStatus -or [string]$usersStatus -eq 'Collected')
    $byId = @{}
    if ($usersRead) {
        foreach ($u in @(Get-TPNestedProperty -Object $users -Path 'Data.Users' -Default @())) {
            $id = [string](Get-TPObjectField -Item $u -Key 'Id' -Default '')
            if ($id) { $byId[$id.ToLowerInvariant()] = Get-TPObjectField -Item $u -Key 'AccountEnabled' -Default $null }
        }
    }
    $off = [System.Collections.Generic.List[object]]::new(); $und = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $view.Agents) {
        $owner = Get-TPObjectField -Item $a -Key 'Owner' -Default $null
        $kind  = [string](Get-TPObjectField -Item $owner -Key 'Kind' -Default 'Unknown')
        $oid   = ([string](Get-TPObjectField -Item $owner -Key 'EntraObjectId' -Default '')).ToLowerInvariant()
        switch ($kind) {
            'User' {
                if (-not $oid) { $und.Add(@{ Agent = $a; Issue = 'the owner has no Entra object id in Dataverse' }); break }
                if (-not $usersRead) { $und.Add(@{ Agent = $a; Issue = 'the Entra ID member list (AAD-Users) was not read in full' }); break }
                if (-not $byId.ContainsKey($oid)) {
                    $off.Add(@{ Agent = $a; Issue = 'owner not found among the member accounts read from Entra ID (deleted, or not a member account)'; Extra = [ordered]@{ OwnerObjectId = $oid } })
                } elseif ($byId[$oid] -eq $false) {
                    $off.Add(@{ Agent = $a; Issue = 'owner account disabled in Entra ID'; Extra = [ordered]@{ OwnerObjectId = $oid } })
                } elseif ($byId[$oid] -ne $true) {
                    $und.Add(@{ Agent = $a; Issue = 'the owner account''s enabled state was not read' })
                }
            }
            'UserNotFoundInDataverse' { $off.Add(@{ Agent = $a; Issue = 'the owning user no longer exists in the environment''s user table' }) }
            'Team'        { $und.Add(@{ Agent = $a; Issue = 'owned by a Dataverse team; team membership is not read' }) }
            'Application' { $und.Add(@{ Agent = $a; Issue = 'owned by an application user, not a person' }) }
            default       { $und.Add(@{ Agent = $a; Issue = 'the owner was not read' }) }
        }
    }
    Add-TPCopilotStudioVerdict -ControlId $cid -Control $ctl.Control -FrameworkIds $ctl.Cit -View $view -Need 'Agents', 'Owners' -Offenders $off -Undetermined $und `
        -PassSentence 'Every Copilot Studio agent is owned by an enabled member account in Entra ID.' `
        -GapSentence 'Copilot Studio agents whose owner is disabled or no longer present (owner identified by Entra object id):' `
        -RequiredValue 'Every agent owned by an enabled, accountable user'
}

# ── PPL-4.10  Dormant published agents (threshold must be approved) ─────────
function Test-TPControlCopilotStudioDormant {
    [CmdletBinding()] param()
    $cid = 'PPL-4.10'
    $ctl = Get-TPCopilotStudioControl -ControlId $cid; if (-not $ctl) { return }
    $view = Get-TPCopilotStudioView
    if (-not $view.Available) { Add-TPCopilotStudioNotCollected -ControlId $cid -Ctl $ctl -View $view; return }

    $vals = @((Get-TPStandards).CopilotStudioDormantDays)
    $days = 0
    $approved = $vals.Count -eq 1 -and [int]::TryParse([string]$vals[0], [System.Globalization.NumberStyles]::None, [cultureinfo]::InvariantCulture, [ref]$days) -and $days -ge 1 -and $days -le 3650
    $published = @($view.Agents | Where-Object { (Get-TPObjectField -Item $_ -Key 'Published' -Default $false) -eq $true -and [string](Get-TPObjectField -Item $_ -Key 'State' -Default '') -eq 'Active' })
    if (-not $approved) {
        $ctx = Format-TPCopilotStudioList -Items @($published | ForEach-Object {
            $m = ConvertTo-TPUtcDateTime (Get-TPObjectField -Item $_ -Key 'ModifiedOn' -Default $null)
            "$([string](Get-TPObjectField -Item $_ -Key 'Name' -Default '?')) ($([string](Get-TPObjectField -Item $_ -Key 'EnvironmentName' -Default '?'))): last modified $(if ($m) { $m.ToString('yyyy-MM-dd') } else { 'not returned' })"
        }) -Max 10
        $bad = if ($vals.Count -gt 0) { " (the value on file, '$($vals -join ', ')', is not one whole number of days from 1 to 3650)" } else { '' }
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category 'Power Platform' -Title $ctl.Control.Title -FrameworkIds $ctl.Cit `
            -Detail "Verified: $($published.Count) published, active agent(s) read. Not assessed: whether any is dormant, because no dormancy threshold is approved (CopilotStudioDormantDays in Config/tp-standards.json)$bad. Context, last modified: $(if ($ctx) { $ctx } else { 'no published agent' })." `
            -RequiredValue 'An approved CopilotStudioDormantDays threshold'
        return
    }
    $cutoff = [datetime]::UtcNow.AddDays(-$days)
    $off = [System.Collections.Generic.List[object]]::new(); $und = [System.Collections.Generic.List[object]]::new()
    foreach ($a in $published) {
        $m = ConvertTo-TPUtcDateTime (Get-TPObjectField -Item $a -Key 'ModifiedOn' -Default $null)
        if (-not $m) { $und.Add(@{ Agent = $a; Issue = 'last-modified date not returned' }); continue }
        if ($m -lt $cutoff) { $off.Add(@{ Agent = $a; Issue = "published and not modified since $($m.ToString('yyyy-MM-dd'))"; Extra = [ordered]@{ ModifiedOn = $m.ToString('o') } }) }
    }
    $view.Agents = $published
    Add-TPCopilotStudioVerdict -ControlId $cid -Control $ctl.Control -FrameworkIds $ctl.Cit -View $view -Need 'Agents' -Offenders $off -Undetermined $und `
        -PassSentence "Every published, active Copilot Studio agent was modified within the approved $days days." `
        -GapSentence "Published Copilot Studio agents not modified in more than the approved $days days:" `
        -RequiredValue "Published agents modified (reviewed) within $days days, or unpublished" `
        -Caveat 'Dormancy is judged on the agent record''s last-modified date, not on how often it is used (conversation activity is not read).'
}
