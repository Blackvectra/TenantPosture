#Requires -Version 7.0
<#
.SYNOPSIS
    Resolve-TPControlSelection.ps1 — TenantPosture
    NRG Technology Services | NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Control selection for a partial run (Invoke-TPAssessment.ps1
             -ControlId / -ExcludeControlId): which controls.json controls were
             chosen, which evaluators run them, which raw-data keys those
             evaluators read (derived from the code, not guessed), which
             collectors produce those keys, and which services must be
             connected. A pure planning helper plus the small module state the
             publishers read, so a partial run is named as partial on every
             surface and never reads as a whole-tenant result.
    Rules:
      - Patterns are wildcards (-like, case-insensitive) over ControlId; each
        must match the strict character rule and match at least one control.
      - The raw-data keys an evaluator needs are its controls'
        CollectorDependency PLUS every Get-TPRawData key its function, and the
        Lib/Evaluators/Collectors functions it calls, read (AST, transitive).
        A key read through a variable, or the whole raw-data map, is resolved
        to the known key names written as literals in that function; when
        none is written there the read is undetermined and the run falls back
        to EVERY collector. Never under-collect: an evaluator that runs
        without its data reports "not assessed", which is honest but not what
        the operator asked for.
      - A collector's own reads of other collectors' data (EXO inventory reads
        AAD-Users, the Copilot collector reads Purview, DNS reads the accepted
        domains) are prerequisites, derived the same way.
      - AAD-Inventory is always collected: license gating and the license
        profile read it.
    Data keys consumed: none live (reads Config/controls.json,
    Config/tp-baseline.json and the module's own source files).
    Graph scopes / cmdlets: none — connects to nothing.
#>

Set-StrictMode -Version Latest

$script:TPControlSelection = $null
$script:TPRawDataReadIndex = $null

function Get-TPControlIdPatternRule {
    <#
    .SYNOPSIS
        The one rule a -ControlId / -ExcludeControlId pattern must meet: letters,
        digits, '.', '-', '*' and '?' only, 1 to 40 characters, matched
        case-sensitively over the whole string. Invoke-TPAssessment.ps1 and the
        batch runner carry a copy in a parameter attribute (it binds before the
        module loads); TP.ControlSelection.Tests.ps1 pins the copies equal.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return '\A[A-Za-z0-9.*?-]{1,40}\z'
}

function Get-TPCollectorCatalog {
    <#
    .SYNOPSIS
        Every assessment collector, the raw-data keys it sets and the service
        it needs, in the order the entry point runs them. TP.ControlSelection.Tests.ps1
        reads every Set-TPRawData call under Collectors/ and fails if this
        table and the code disagree.
    .NOTES
        Service: Graph, Exchange, Purview, Teams, PowerPlatform (the Power
        Platform admin API, signed in with the same account), Public (DNS:
        public resolvers; the domain list comes from Exchange or Graph).
    #>
    [CmdletBinding()]
    param()
    @(
        [ordered]@{ Function = 'Invoke-TPCollectAADAuthPolicies';        Keys = @('AAD-AuthPolicies');        Service = 'Graph' }
        [ordered]@{ Function = 'Invoke-TPCollectAADCAPolicies';          Keys = @('AAD-CAPolicies');          Service = 'Graph' }
        [ordered]@{ Function = 'Invoke-TPCollectAADUsers';               Keys = @('AAD-Users');               Service = 'Graph' }
        [ordered]@{ Function = 'Invoke-TPCollectAADRoles';               Keys = @('AAD-DirectoryRoles');      Service = 'Graph' }
        [ordered]@{ Function = 'Invoke-TPCollectAADPIM';                 Keys = @('AAD-PIMSchedules');        Service = 'Graph' }
        [ordered]@{ Function = 'Invoke-TPCollectAADIdentityGovernance';  Keys = @('AAD-IdentityGovernance');  Service = 'Graph' }
        [ordered]@{ Function = 'Invoke-TPCollectAADInventory';           Keys = @('AAD-Inventory');           Service = 'Graph' }
        [ordered]@{ Function = 'Invoke-TPCollectAADAppPermissions';      Keys = @('AAD-AppPermissions');      Service = 'Graph' }
        [ordered]@{ Function = 'Invoke-TPCollectAADDirectorySettings';   Keys = @('AAD-DirectorySettings');   Service = 'Graph' }
        [ordered]@{ Function = 'Invoke-TPCollectAADSignInEvidence';      Keys = @('AAD-SignInEvidence');      Service = 'Graph' }
        [ordered]@{ Function = 'Invoke-TPCollectSharePoint';             Keys = @('SharePoint');              Service = 'Graph' }
        [ordered]@{ Function = 'Invoke-TPCollectIntuneEndpointSecurity'; Keys = @('Intune-EndpointSecurity'); Service = 'Graph' }
        [ordered]@{ Function = 'Invoke-TPCollectIntuneDeviceCompliance'; Keys = @('Intune-DeviceCompliance'); Service = 'Graph' }
        [ordered]@{ Function = 'Invoke-TPCollectIntuneAppProtection';    Keys = @('Intune-AppProtection');    Service = 'Graph' }
        [ordered]@{ Function = 'Invoke-TPCollectPowerPlatform';          Keys = @('PowerPlatform');           Service = 'PowerPlatform' }
        [ordered]@{ Function = 'Invoke-TPCollectEXOMailboxConfig';       Keys = @('EXO-MailboxConfig');       Service = 'Exchange' }
        [ordered]@{ Function = 'Invoke-TPCollectEXOConnectionFilter';    Keys = @('EXO-ConnectionFilter');    Service = 'Exchange' }
        [ordered]@{ Function = 'Invoke-TPCollectEXOInventory';           Keys = @('EXO-Inventory');           Service = 'Exchange' }
        [ordered]@{ Function = 'Invoke-TPCollectDefender';               Keys = @('Defender-Policies');       Service = 'Exchange' }
        [ordered]@{ Function = 'Invoke-TPCollectDNSEmailRecords';        Keys = @('DNS-EmailRecords');        Service = 'Public' }
        [ordered]@{ Function = 'Invoke-TPCollectTeams';                  Keys = @('Teams');                   Service = 'Teams' }
        [ordered]@{ Function = 'Invoke-TPCollectPurview';                Keys = @('Purview');                 Service = 'Purview' }
        [ordered]@{ Function = 'Invoke-TPCollectM365Copilot';            Keys = @('M365Copilot');             Service = 'Graph' }
    )
}

function Get-TPRunProvidedRawDataKeys {
    <#
    .SYNOPSIS
        Raw-data keys the run itself records (not a collector): the Graph
        consent read at sign-in and the configured monitoring addresses. An
        evaluator reading one needs no collector for it.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @('Graph-Consent', 'Config-MonitoringAddresses')
}

function Get-TPRawDataReadIndex {
    <#
    .SYNOPSIS
        Parses every function under Lib/, Collectors/ and Evaluators/ once and
        records, per function name, the raw-data keys it reads directly, the
        module functions it calls, and whether a read could not be resolved
        to a key name. Cached for the session.
    #>
    [CmdletBinding()]
    param([switch] $Force, [AllowNull()] [AllowEmptyString()] [string] $Root)
    if (-not $Force -and -not $Root -and $null -ne $script:TPRawDataReadIndex) { return $script:TPRawDataReadIndex }
    $moduleRoot = if ($Root) { $Root } else { Split-Path -Parent $PSScriptRoot }

    $known = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($c in Get-TPCollectorCatalog) { foreach ($k in $c.Keys) { $null = $known.Add($k) } }
    foreach ($k in Get-TPRunProvidedRawDataKeys) { $null = $known.Add($k) }

    $defs = @{}
    foreach ($dir in @('Lib', 'Collectors', 'Evaluators')) {
        $path = Join-Path $moduleRoot $dir
        if (-not (Test-Path -LiteralPath $path)) { continue }
        foreach ($file in Get-ChildItem -LiteralPath $path -Recurse -Filter '*.ps1' -File) {
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
            foreach ($fd in $ast.FindAll({ param($a) $a -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
                # 'function script:X' is called as X.
                $name = ($fd.Name -replace '^(?i:script|global|local|private):', '')
                if (-not $defs.ContainsKey($name)) { $defs[$name] = [System.Collections.Generic.List[object]]::new() }
                $defs[$name].Add($fd)
            }
        }
    }

    $index = @{}
    foreach ($name in $defs.Keys) {
        $keys  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $calls = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $unresolved = [System.Collections.Generic.List[string]]::new()
        foreach ($fd in $defs[$name]) {
            $literalKeys = $null
            foreach ($cmd in $fd.Body.FindAll({ param($a) $a -is [System.Management.Automation.Language.CommandAst] }, $true)) {
                $cn = $cmd.GetCommandName()
                if (-not $cn) { continue }
                if ($cn -ne 'Get-TPRawData') {
                    if ($defs.ContainsKey($cn) -and $cn -ne $name) { $null = $calls.Add($cn) }
                    continue
                }
                # Find the -Key argument (named, abbreviated, or the first positional).
                $els = $cmd.CommandElements
                $arg = $null; $hasKey = $false
                for ($i = 1; $i -lt $els.Count; $i++) {
                    $e = $els[$i]
                    if ($e -is [System.Management.Automation.Language.CommandParameterAst]) {
                        if ('Key'.StartsWith($e.ParameterName, [System.StringComparison]::OrdinalIgnoreCase)) {
                            $hasKey = $true
                            $arg = if ($e.Argument) { $e.Argument } elseif ($i + 1 -lt $els.Count) { $els[$i + 1] } else { $null }
                            break
                        }
                        # A switch or a named parameter with its value: skip the value too.
                        if (-not $e.Argument -and $i + 1 -lt $els.Count -and $els[$i + 1] -isnot [System.Management.Automation.Language.CommandParameterAst] -and $e.ParameterName -notmatch '^(?i:Verbose|Debug)$') { $i++ }
                        continue
                    }
                    $hasKey = $true; $arg = $e; break
                }
                if ($hasKey -and $arg -is [System.Management.Automation.Language.StringConstantExpressionAst]) {
                    $null = $keys.Add($arg.Value)
                    continue
                }
                # A key in a variable, or the whole raw-data map: the keys this
                # function names as literals are the ones it can reach.
                if ($null -eq $literalKeys) {
                    $literalKeys = @($fd.Body.FindAll({ param($a) $a -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true) |
                        ForEach-Object { $_.Value } | Where-Object { $known.Contains([string]$_) } | Select-Object -Unique)
                }
                if (@($literalKeys).Count -gt 0) {
                    foreach ($k in $literalKeys) { $null = $keys.Add([string]$k) }
                } else {
                    $unresolved.Add($(if ($hasKey) { "a raw-data key read through '$($arg.Extent.Text)'" } else { 'the whole raw-data map' }))
                }
            }
        }
        $index[$name] = [ordered]@{ Keys = $keys; Calls = $calls; Unresolved = @($unresolved) }
    }
    if (-not $Root) { $script:TPRawDataReadIndex = $index }
    return $index
}

function Get-TPFunctionRawDataKeys {
    <#
    .SYNOPSIS
        The raw-data keys a function reads, itself and through every Lib,
        Collectors or Evaluators function it calls (transitively), and the
        reads that could not be resolved to a key name.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $Name, [AllowNull()] [hashtable] $Index)
    $idx = if ($null -ne $Index) { $Index } else { Get-TPRawDataReadIndex }
    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $queue = [System.Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($Name)
    $keys = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $unresolved = [System.Collections.Generic.List[string]]::new()
    $found = $idx.ContainsKey($Name)
    while ($queue.Count -gt 0) {
        $fn = $queue.Dequeue()
        if (-not $seen.Add($fn)) { continue }
        if (-not $idx.ContainsKey($fn)) { continue }
        $entry = $idx[$fn]
        foreach ($k in $entry.Keys) { $null = $keys.Add($k) }
        foreach ($u in @($entry.Unresolved)) { $unresolved.Add("$fn reads $u") }
        foreach ($c in $entry.Calls) { $queue.Enqueue($c) }
    }
    if (-not $found) { $unresolved.Add("the function $Name was not found in the module source") }
    return [ordered]@{ Function = $Name; Keys = @($keys); Unresolved = @($unresolved) }
}

function Resolve-TPControlSelection {
    <#
    .SYNOPSIS
        Resolves -ControlId / -ExcludeControlId patterns to the controls,
        evaluators, raw-data keys, collectors and services a partial run needs.
    .DESCRIPTION
        Pure: reads the control catalog and the module's own source, connects
        to nothing and changes no state. Valid is $false (with Errors naming
        each problem) when a pattern breaks the character rule, a pattern
        matches no control, or nothing is left after the exclusions; the
        entry point treats that as fatal before any sign-in.
    .PARAMETER Include
        Wildcard patterns over ControlId. Empty means every control (only
        -Exclude narrows).
    .PARAMETER Controls
        The control catalog. Defaults to Get-TPControlDefinitions.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [AllowEmptyCollection()] [string[]] $Include = @(),
        [AllowNull()] [AllowEmptyCollection()] [string[]] $Exclude = @(),
        [AllowNull()] [object[]] $Controls,
        [AllowNull()] [object] $BaselineDefinition,
        [switch] $IncludeSharePointShell,
        [switch] $SkipKeyDerivation,
        # The source read index (Get-TPRawDataReadIndex); tests pass one built
        # from a fixture folder. Defaults to the module's own source.
        [AllowNull()] [hashtable] $ReadIndex
    )
    Set-StrictMode -Version Latest

    $inc = @($Include | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { ([string]$_).Trim() })
    $exc = @($Exclude | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { ([string]$_).Trim() })
    $catalog = if ($null -ne $Controls) { @($Controls) } else { @(Get-TPControlDefinitions) }

    $result = [ordered]@{
        Valid              = $false
        Partial            = $false
        Include            = @($inc)
        Exclude            = @($exc)
        Errors             = @()
        TotalControls      = 0
        SelectedCount      = 0
        SelectedControlIds = @()
        Workloads          = [ordered]@{}
        EvaluatorFunctions = @()
        RawDataKeys        = @()
        Collectors         = @()
        Services           = [ordered]@{ Graph = $true; Exchange = $false; Purview = $false; Teams = $false; SharePointShell = $false; PowerPlatform = $false; DNS = $false }
        Undetermined       = @()
        Fallback           = $false
    }
    $errors = [System.Collections.Generic.List[string]]::new()
    $rule = Get-TPControlIdPatternRule
    foreach ($p in @($inc + $exc)) {
        if ($p -cnotmatch $rule) { $errors.Add("'$p' is not a control pattern (letters, digits, '.', '-', '*' and '?' only, 1 to 40 characters).") }
    }

    $ids = @($catalog | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'ControlId' -Default '') } | Where-Object { $_ })
    $result.TotalControls = $ids.Count
    if ($errors.Count -gt 0) { $result.Errors = @($errors); return $result }

    foreach ($p in $inc) {
        if (@($ids | Where-Object { $_ -like $p }).Count -eq 0) { $errors.Add("-ControlId '$p' matches no control in Config/controls.json.") }
    }
    foreach ($p in $exc) {
        if (@($ids | Where-Object { $_ -like $p }).Count -eq 0) { $errors.Add("-ExcludeControlId '$p' matches no control in Config/controls.json.") }
    }
    $selected = [System.Collections.Generic.List[object]]::new()
    foreach ($c in $catalog) {
        $cid = [string](Get-TPObjectField -Item $c -Key 'ControlId' -Default '')
        if (-not $cid) { continue }
        $in = ($inc.Count -eq 0) -or (@($inc | Where-Object { $cid -like $_ }).Count -gt 0)
        if (-not $in) { continue }
        if (@($exc | Where-Object { $cid -like $_ }).Count -gt 0) { continue }
        $selected.Add($c)
    }
    if ($errors.Count -eq 0 -and $selected.Count -eq 0) { $errors.Add('No control is left after the exclusions; nothing would be assessed.') }
    if ($errors.Count -gt 0) { $result.Errors = @($errors); return $result }

    $result.SelectedControlIds = @($selected | ForEach-Object { [string]$_.ControlId })
    $result.SelectedCount = $selected.Count
    $result.Partial = ($selected.Count -lt $ids.Count)
    foreach ($c in $selected) {
        $wl = [string](Get-TPObjectField -Item $c -Key 'Workload' -Default 'Other')
        if (-not $result.Workloads.Contains($wl)) { $result.Workloads[$wl] = 0 }
        $result.Workloads[$wl]++
    }
    $evaluators = @($selected | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'EvaluatorFunction' -Default '') } | Where-Object { $_ } | Select-Object -Unique)
    $result.EvaluatorFunctions = $evaluators
    $result.Valid = $true
    if ($SkipKeyDerivation) { return $result }

    # ── Raw-data keys: declared, read by the evaluators, and read by the baseline row ──
    $cat = @(Get-TPCollectorCatalog)
    $keyToCollector = @{}
    foreach ($cc in $cat) { foreach ($k in $cc.Keys) { $keyToCollector[$k] = $cc } }
    $runKeys = @(Get-TPRunProvidedRawDataKeys)
    $need = [System.Collections.Generic.SortedSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $undetermined = [System.Collections.Generic.List[object]]::new()
    $null = $need.Add('AAD-Inventory')
    foreach ($c in $selected) {
        foreach ($k in @(([string](Get-TPObjectField -Item $c -Key 'CollectorDependency' -Default '')) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) { $null = $need.Add($k) }
    }
    $index = if ($null -ne $ReadIndex) { $ReadIndex } else { Get-TPRawDataReadIndex }
    foreach ($fn in $evaluators) {
        $r = Get-TPFunctionRawDataKeys -Name $fn -Index $index
        foreach ($k in $r.Keys) { $null = $need.Add($k) }
        if (@($r.Unresolved).Count -gt 0) { $undetermined.Add([ordered]@{ Function = $fn; Reason = (@($r.Unresolved) -join '; ') }) }
    }
    $def = $BaselineDefinition
    if ($null -eq $def -and (Get-Command Get-TPBaselineDefinition -ErrorAction SilentlyContinue)) {
        try { $def = Get-TPBaselineDefinition } catch { $def = $null }
    }
    if ($null -ne $def) {
        $selSet = [System.Collections.Generic.HashSet[string]]::new([string[]]$result.SelectedControlIds, [System.StringComparer]::OrdinalIgnoreCase)
        $defRows = Get-TPObjectField -Item $def -Key 'Controls' -Default @()
        if ($defRows -is [System.Collections.IDictionary]) { $defRows = @($defRows.Values) }
        foreach ($row in @($defRows)) {
            $rid = [string](Get-TPObjectField -Item $row -Key 'ControlId' -Default '')
            if (-not $selSet.Contains($rid)) { continue }
            foreach ($k in @(Get-TPObjectField -Item $row -Key 'RawDataKeys' -Default @())) { if ($k) { $null = $need.Add([string]$k) } }
            $ev = Get-TPObjectField -Item $row -Key 'EffectivenessEvidence' -Default $null
            if ($null -ne $ev -and [string](Get-TPObjectField -Item $ev -Key 'Type' -Default '') -eq 'SignInLog') {
                $null = $need.Add('AAD-SignInEvidence'); $null = $need.Add('AAD-DirectoryRoles')
            }
        }
    }

    # ── Collector prerequisites, to a fixed point ──
    $changed = $true
    $visitedCollectors = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    while ($changed) {
        $changed = $false
        foreach ($k in @($need)) {
            if (-not $keyToCollector.ContainsKey($k)) { continue }
            $cfn = $keyToCollector[$k].Function
            if (-not $visitedCollectors.Add($cfn)) { continue }
            $cr = Get-TPFunctionRawDataKeys -Name $cfn -Index $index
            foreach ($ck in $cr.Keys) { if ($need.Add($ck)) { $changed = $true } }
        }
    }

    $unknownKeys = @($need | Where-Object { -not $keyToCollector.ContainsKey($_) -and $_ -notin $runKeys })
    foreach ($uk in $unknownKeys) { $undetermined.Add([ordered]@{ Function = '(raw-data key)'; Reason = "no collector is known to set '$uk'" }) }

    if ($undetermined.Count -gt 0) {
        # Never under-collect: run every collector.
        $result.Fallback = $true
        foreach ($cc in $cat) { foreach ($k in $cc.Keys) { $null = $need.Add($k) } }
    }
    $result.Undetermined = @($undetermined | ForEach-Object { [pscustomobject]$_ })
    $result.RawDataKeys = @($need | Where-Object { $keyToCollector.ContainsKey($_) })
    $result.Collectors = @($cat | Where-Object { $cc = $_; @($cc.Keys | Where-Object { $need.Contains($_) }).Count -gt 0 } | ForEach-Object { $_.Function })
    foreach ($cc in $cat) {
        if (@($cc.Keys | Where-Object { $need.Contains($_) }).Count -eq 0) { continue }
        switch ($cc.Service) {
            'Exchange'      { $result.Services.Exchange = $true }
            'Purview'       { $result.Services.Purview = $true }
            'Teams'         { $result.Services.Teams = $true }
            'PowerPlatform' { $result.Services.PowerPlatform = $true }
            'Public'        { $result.Services.DNS = $true }
        }
    }
    $result.Services.SharePointShell = [bool]($IncludeSharePointShell -and $need.Contains('SharePoint'))
    return $result
}

function ConvertTo-TPControlSelectionRecord {
    <#
    .SYNOPSIS
        The selection as it is recorded in the results JSON metadata
        (Metadata.ControlSelection) and held in module state for the
        publishers. Data only.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([Parameter(Mandatory)] [object] $Selection, [AllowNull()] [AllowEmptyCollection()] [string[]] $DroppedFindings = @())
    $svc = Get-TPObjectField -Item $Selection -Key 'Services' -Default $null
    $svcNames = @()
    if ($svc -is [System.Collections.IDictionary]) { $svcNames = @($svc.Keys | Where-Object { [bool]$svc[$_] }) }
    return [ordered]@{
        Include            = @(Get-TPObjectField -Item $Selection -Key 'Include' -Default @())
        Exclude            = @(Get-TPObjectField -Item $Selection -Key 'Exclude' -Default @())
        SelectedCount      = [int](Get-TPObjectField -Item $Selection -Key 'SelectedCount' -Default 0)
        TotalControls      = [int](Get-TPObjectField -Item $Selection -Key 'TotalControls' -Default 0)
        Partial            = [bool](Get-TPObjectField -Item $Selection -Key 'Partial' -Default $true)
        SelectedControlIds = @(Get-TPObjectField -Item $Selection -Key 'SelectedControlIds' -Default @())
        EvaluatorFunctions = @(Get-TPObjectField -Item $Selection -Key 'EvaluatorFunctions' -Default @())
        RawDataKeys        = @(Get-TPObjectField -Item $Selection -Key 'RawDataKeys' -Default @())
        Services           = @($svcNames)
        Fallback           = [bool](Get-TPObjectField -Item $Selection -Key 'Fallback' -Default $false)
        DroppedFindings    = @($DroppedFindings | Where-Object { $_ } | Sort-Object -Unique)
    }
}

function Set-TPControlSelection {
    <#
    .SYNOPSIS
        Records the run's control selection in module state (or clears it with
        $null), so the scope section, the baseline view and the publishers can
        name the controls that were not selected.
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    param([AllowNull()] [object] $Selection)
    if ($null -eq $Selection) { $script:TPControlSelection = $null; return }
    $ids = @(Get-TPObjectField -Item $Selection -Key 'SelectedControlIds' -Default @() | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $script:TPControlSelection = [ordered]@{
        Record = $Selection
        Ids    = [System.Collections.Generic.HashSet[string]]::new([string[]]$ids, [System.StringComparer]::OrdinalIgnoreCase)
    }
}

function Get-TPControlSelection {
    <#
    .SYNOPSIS
        The run's control selection record from module state, or $null for a
        run that assessed every control.
    #>
    [CmdletBinding()]
    param()
    if ($null -eq $script:TPControlSelection) { return $null }
    return $script:TPControlSelection.Record
}

function Get-TPSelectedControlIds {
    <#
    .SYNOPSIS
        The ControlIds selected for this run, or $null when every control was
        assessed. Read from -Metadata (Metadata.ControlSelection, so a
        republished partial run stays partial) when it carries one, else from
        module state.
    #>
    [CmdletBinding()]
    param([AllowNull()] [object] $Metadata)
    $rec = $null
    if ($null -ne $Metadata) { $rec = Get-TPObjectField -Item $Metadata -Key 'ControlSelection' -Default $null }
    if ($null -eq $rec) { $rec = Get-TPControlSelection }
    if ($null -eq $rec) { return $null }
    if (-not [bool](Get-TPObjectField -Item $rec -Key 'Partial' -Default $true)) { return $null }
    $ids = @(Get-TPObjectField -Item $rec -Key 'SelectedControlIds' -Default @() | Where-Object { $_ } | ForEach-Object { [string]$_ })
    # An empty list is a record that says nothing; never read it as "nothing was selected".
    if ($ids.Count -eq 0) { return $null }
    return ,$ids
}

function Format-TPControlSelectionNotice {
    <#
    .SYNOPSIS
        The one sentence every surface prints for a partial run (console, HTML
        report, Markdown summary, report site), or '' for a full run.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [object] $Selection)
    if ($null -eq $Selection) { return '' }
    if (-not [bool](Get-TPObjectField -Item $Selection -Key 'Partial' -Default $true)) { return '' }
    $n = [int](Get-TPObjectField -Item $Selection -Key 'SelectedCount' -Default 0)
    $t = [int](Get-TPObjectField -Item $Selection -Key 'TotalControls' -Default 0)
    $inc = @(Get-TPObjectField -Item $Selection -Key 'Include' -Default @() | Where-Object { $_ })
    $exc = @(Get-TPObjectField -Item $Selection -Key 'Exclude' -Default @() | Where-Object { $_ })
    $how = @()
    if ($inc.Count -gt 0) { $how += "-ControlId $($inc -join ', ')" }
    if ($exc.Count -gt 0) { $how += "-ExcludeControlId $($exc -join ', ')" }
    $rest = [math]::Max(0, $t - $n)
    return "Partial run: $n of $t controls selected ($($how -join '; ')). The other $rest control(s) were not assessed in this run and nothing in this report describes them; the score, the maturity tier and every framework figure cover the selected controls only."
}

function Select-TPSelectedFindings {
    <#
    .SYNOPSIS
        Removes from module state every finding whose ControlId is not in the
        selection and returns the ControlIds removed. An evaluator that owns
        several controls emits all of them; the ones the operator did not
        select are dropped (and recorded in the selection record), never scored.
    #>
    [CmdletBinding(SupportsShouldProcess = $false)]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $SelectedControlIds)
    $keep = [System.Collections.Generic.HashSet[string]]::new([string[]]@($SelectedControlIds), [System.StringComparer]::OrdinalIgnoreCase)
    $dropped = [System.Collections.Generic.List[string]]::new()
    for ($i = $script:TPFindings.Count - 1; $i -ge 0; $i--) {
        $cid = [string](Get-TPObjectField -Item $script:TPFindings[$i] -Key 'ControlId' -Default '')
        if (-not $keep.Contains($cid)) {
            $dropped.Add($cid)
            $script:TPFindings.RemoveAt($i)
        }
    }
    return @($dropped | Sort-Object -Unique)
}
