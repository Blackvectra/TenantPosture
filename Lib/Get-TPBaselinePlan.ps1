#Requires -Version 7.0
<#
.SYNOPSIS
    Get-TPBaselinePlan.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: Predict, BEFORE a run, how every required NRG Security Baseline
             control is expected to resolve — automatically assessable, manual,
             handled by a declared third-party product, dependent on an
             optional collector, skipped by the operator, expected to be
             license-blocked, or licensing unknown until the tenant is
             connected — and which collectors the run needs. After the run,
             Compare-TPBaselinePlan puts the prediction beside what happened.
    A VIEW, like the compliance view it precedes: it creates no finding, changes
    none, and moves no score. Predictive, never certain: anything that cannot be
    known until connection time is reported as unknown, not guessed.
    Data keys consumed: none live. Optional: a license profile built from a
    prior run's AAD-Inventory SubscribedSkus (Get-TPTenantLicenseProfile).
    Config consumed: Config/tp-baseline.json, Config/optional-collectors.json,
    Config/controls.json (LicenseRequirement), Config/baseline-exceptions/.
    Graph scopes / cmdlets: none — connects to nothing.
#>

Set-StrictMode -Version Latest

function Get-TPOptionalCollectorCatalog {
    <#
    .SYNOPSIS
        Reads Config/optional-collectors.json: the collectors an operator must
        enable, and the controls that need each one (with the condition).
    #>
    [CmdletBinding()]
    param([switch] $Force)
    if (-not $Force -and (Get-Variable -Name TPOptionalCollectorCatalog -Scope Script -ErrorAction SilentlyContinue) -and $script:TPOptionalCollectorCatalog) {
        return $script:TPOptionalCollectorCatalog
    }
    $path = Join-Path (Split-Path -Parent $PSScriptRoot) 'Config' 'optional-collectors.json'
    $out = [ordered]@{}
    if (-not (Test-Path -LiteralPath $path)) { $script:TPOptionalCollectorCatalog = $out; return $out }
    $raw = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json -Depth 10
    $collectors = Get-TPObjectField -Item $raw -Key 'collectors' -Default $null
    if ($null -ne $collectors) {
        foreach ($p in $collectors.PSObject.Properties) {
            $entry = $p.Value
            $controls = [ordered]@{}
            $cmap = Get-TPObjectField -Item $entry -Key 'Controls' -Default $null
            if ($null -ne $cmap) {
                foreach ($cp in $cmap.PSObject.Properties) { $controls[[string]$cp.Name] = [string]$cp.Value }
            }
            $out[[string]$p.Name] = [ordered]@{
                Id         = [string]$p.Name
                Name       = [string](Get-TPObjectField -Item $entry -Key 'Name' -Default $p.Name)
                Switch     = [string](Get-TPObjectField -Item $entry -Key 'Switch' -Default '')
                RawDataKey = [string](Get-TPObjectField -Item $entry -Key 'RawDataKey' -Default '')
                Note       = [string](Get-TPObjectField -Item $entry -Key 'Note' -Default '')
                Controls   = $controls
            }
        }
    }
    $script:TPOptionalCollectorCatalog = $out
    return $out
}

function Get-TPWorkloadSkipMap {
    <#
    .SYNOPSIS
        The -Skip* switches and the raw-data keys each one removes. The same
        table the entry point records as coverage 'Skipped'; a test pins the two
        equal so a new workload cannot be skipped in one place and not the other.
    #>
    [CmdletBinding()]
    param()
    @(
        [ordered]@{ Flag = 'SkipPurview';       Keys = @('Purview') }
        [ordered]@{ Flag = 'SkipTeams';         Keys = @('Teams') }
        [ordered]@{ Flag = 'SkipSharePoint';    Keys = @('SharePoint') }
        [ordered]@{ Flag = 'SkipIntune';        Keys = @('Intune-EndpointSecurity', 'Intune-DeviceCompliance', 'Intune-AppProtection') }
        [ordered]@{ Flag = 'SkipPowerPlatform'; Keys = @('PowerPlatform') }
        [ordered]@{ Flag = 'SkipDNS';           Keys = @('DNS-EmailRecords') }
    )
}

function Get-TPClientCollectorFlags {
    <#
    .SYNOPSIS
        The opt-in collector flags a clients.json record declares, keyed by the
        optional-collector catalog id (today: SharePointShell). Operator-declared
        expectations, never truth: a flag turns the collector on for the run
        and the plan; if the collector then fails, the run reports the failure.
        Unknown keys are warned about and ignored.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] [object] $ClientRecord)
    $out = [ordered]@{}
    $catalog = Get-TPOptionalCollectorCatalog
    foreach ($id in $catalog.Keys) { $out[$id] = $false }
    if ($null -eq $ClientRecord) { return $out }
    $block = Get-TPObjectField -Item $ClientRecord -Key 'Collectors' -Default $null
    if ($null -eq $block) { return $out }
    $names = if ($block -is [System.Collections.IDictionary]) { @($block.Keys) } else { @($block.PSObject.Properties | ForEach-Object { $_.Name }) }
    foreach ($n in $names) {
        $v = Get-TPObjectField -Item $block -Key $n -Default $false
        if ($catalog.Contains([string]$n)) { $out[[string]$n] = [bool]$v }
        else { Write-Warning "clients.json Collectors.$n is not an optional collector this version knows (known: $($catalog.Keys -join ', ')); ignored." }
    }
    return $out
}

function Get-TPCollectorService {
    <#
    .SYNOPSIS
        The connection a raw-data key is collected through, by the entry point's
        own grouping (Graph, Exchange Online, Purview, Teams, DNS, Power Platform).
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyString()] [string] $RawDataKey)
    switch -Regex ($RawDataKey) {
        '^(AAD-|Intune-|SharePoint$|M365Copilot$|Graph-Consent$)' { return 'Graph' }
        '^(EXO-|Defender-Policies$)'                             { return 'Exchange Online' }
        '^Purview$'                                              { return 'Purview (Security & Compliance)' }
        '^Teams$'                                                { return 'Teams' }
        '^DNS-'                                                  { return 'DNS (public resolvers; domain list from Graph or Exchange)' }
        '^PowerPlatform$'                                        { return 'Power Platform (BAP API, same account)' }
        '^DeviceControls$'                                       { return 'Endpoint results (-DeviceResults)' }
        default                                                  { return "Unknown ($RawDataKey)" }
    }
}

function Get-TPBaselinePlan {
    <#
    .SYNOPSIS
        Predicts how each required baseline control will resolve before a run.
    .DESCRIPTION
        Every required control at -TargetTier lands in exactly one Expected
        bucket, decided in this order, strongest signal first:

          Manual                    the baseline marks it Automated = false
          SkippedByOperator         one of its collectors is in -SkipCollectors
          ThirdPartyHandled         -ThirdPartyEDR is declared and the control is
                                    a Defender endpoint check (reported
                                    NotApplicable, attested, not verified — unless
                                    the Defender check passes on its own)
          OptionalCollectorRequired needs a collector from optional-collectors.json
                                    that is not enabled
          LicenseBlockedExpected    the license profile positively shows the
                                    requirement unmet
          LicensingUnknown          the requirement is not 'Included' and no
                                    license profile was supplied: unknown until
                                    the tenant is connected — never guessed
          Automatic                 assessable from the collectors it names

        ExpectedNotVerified counts Manual + SkippedByOperator +
        OptionalCollectorRequired: the rows the compliance view will report
        NotVerified if nothing changes. An approved exception is reported as a
        disposition and changes no expected state, exactly as in the view.
    .PARAMETER LicenseProfile
        Output of Get-TPTenantLicenseProfile. Pass one built from a prior
        run's SubscribedSkus (or live SKUs) to turn LicensingUnknown rows into
        Automatic or LicenseBlockedExpected. A profile without SKU data
        (HasLicenseData = $false) is treated as not read.
    .PARAMETER SkipCollectors
        Raw-data keys the run will skip (see Get-TPWorkloadSkipMap).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [AllowEmptyString()] [string] $TenantDomain = '',
        [ValidateSet('Minimum', 'Standard', 'Hardened')] [string] $TargetTier = 'Standard',
        [AllowNull()] [AllowEmptyString()] [string] $ThirdPartyEDR = '',
        [switch] $IncludeSharePointShell,
        [AllowNull()] [AllowEmptyCollection()] [string[]] $SkipCollectors = @(),
        [AllowNull()] [object] $LicenseProfile = $null,
        [AllowNull()] [AllowEmptyString()] [string] $LicenseSource = '',
        [AllowNull()] [object] $Definition = $null,
        [AllowNull()] [object] $Exceptions = $null,
        [datetime] $AsOf = (Get-Date)
    )
    Set-StrictMode -Version Latest

    $def = if ($null -ne $Definition) { $Definition } else { Get-TPBaselineDefinition }
    $required = @(Get-TPBaselineRequiredControls -TargetTier $TargetTier -Definition $def)
    $catalog = Get-TPOptionalCollectorCatalog
    $edrIds = if (Get-Command Get-TPDefenderEndpointCheckIds -ErrorAction SilentlyContinue) { @(Get-TPDefenderEndpointCheckIds) } else { @() }
    $skip = [System.Collections.Generic.HashSet[string]]::new([string[]]@($SkipCollectors | Where-Object { $_ }), [System.StringComparer]::OrdinalIgnoreCase)
    $hasLic = ($null -ne $LicenseProfile) -and [bool](Get-TPObjectField -Item $LicenseProfile -Key 'HasLicenseData' -Default $false)
    $licSrc = if ($hasLic) { if ($LicenseSource) { $LicenseSource } else { 'license profile supplied' } } else { 'not read' }

    $exc = if ($null -ne $Exceptions) { $Exceptions } elseif ($TenantDomain) { Get-TPBaselineExceptions -TenantDomain $TenantDomain -AsOf $AsOf } else { $null }
    $approved = if ($exc -and (Get-TPObjectField -Item $exc -Key 'Approved' -Default $null)) { $exc.Approved } else { @{} }

    # Optional collectors: which required controls each one gates, and whether
    # the operator enabled it. Only the SharePoint shell exists today; the
    # catalog decides, not this code.
    $optionalOf = @{}
    $enabledOptional = @{}
    foreach ($oc in $catalog.Values) {
        $enabled = switch ($oc.Id) { 'SharePointShell' { [bool]$IncludeSharePointShell } default { $false } }
        $enabledOptional[$oc.Id] = $enabled
        foreach ($cid in $oc.Controls.Keys) { if (-not $optionalOf.ContainsKey($cid)) { $optionalOf[$cid] = @{ Collector = $oc; Condition = [string]$oc.Controls[$cid]; Enabled = $enabled } } }
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    $serviceKeys = [ordered]@{}
    $serviceControls = @{}
    foreach ($c in $required) {
        $cid   = [string]$c.ControlId
        $keys  = @($c.RawDataKeys | Where-Object { $_ })
        $auto  = [bool](Get-TPObjectField -Item $c -Key 'Automated' -Default $true)
        $services = @($keys | ForEach-Object { Get-TPCollectorService -RawDataKey $_ } | Select-Object -Unique)
        foreach ($k in $keys) {
            $svc = Get-TPCollectorService -RawDataKey $k
            if (-not $serviceKeys.Contains($svc)) { $serviceKeys[$svc] = [System.Collections.Generic.List[string]]::new(); $serviceControls[$svc] = [System.Collections.Generic.HashSet[string]]::new() }
            if (-not $serviceKeys[$svc].Contains($k)) { $serviceKeys[$svc].Add($k) }
            $null = $serviceControls[$svc].Add($cid)
        }

        $req = ''
        if (Get-Command Get-TPControlById -ErrorAction SilentlyContinue) {
            try { $ctl = Get-TPControlById -ControlId $cid; if ($ctl) { $req = [string](Get-TPObjectField -Item $ctl -Key 'LicenseRequirement' -Default '') } } catch { $req = '' }
        }
        $licStatus = ''
        $expected = ''; $reason = ''
        $skippedKeys = @($keys | Where-Object { $skip.Contains($_) })
        $opt = if ($optionalOf.ContainsKey($cid)) { $optionalOf[$cid] } else { $null }

        if (-not $auto) {
            $expected = 'Manual'
            $reason = "Manual control ($([string](Get-TPObjectField -Item $c -Key 'EvidenceSource' -Default 'no collector'))): resolves NotVerified until a collector exists."
        } elseif ($skippedKeys.Count -gt 0) {
            $expected = 'SkippedByOperator'
            $reason = "Collector $($skippedKeys -join ', ') is skipped for this run: NotVerified, skipped by operator."
        } elseif ($ThirdPartyEDR -and $cid -in $edrIds) {
            $expected = 'ThirdPartyHandled'
            $reason = "Third-party EDR declared ($ThirdPartyEDR): reported NotApplicable, attested and not verified, unless the Defender check passes on its own."
        } elseif ($null -ne $opt -and -not $opt.Enabled) {
            $expected = 'OptionalCollectorRequired'
            $reason = "Needs the $($opt.Collector.Name) ($($opt.Collector.Switch)), not enabled$(if ($opt.Condition) { ": $($opt.Condition)" }). NotVerified until it is."
        } else {
            if ([string]::IsNullOrEmpty($req) -or $req -match '^Included') { $licStatus = 'Met' }
            elseif ($hasLic) { $licStatus = if (Test-TPLicenseRequirementMet -LicenseRequirement $req -LicenseProfile $LicenseProfile -ControlId $cid) { 'Met' } else { 'NotMet' } }
            else { $licStatus = 'Unknown' }
            if ($licStatus -eq 'NotMet') {
                $expected = 'LicenseBlockedExpected'
                $reason = "Requires $req; not held per $licSrc. Reported NotApplicable (license blocked) and not scored."
            } elseif ($licStatus -eq 'Unknown') {
                $expected = 'LicensingUnknown'
                $reason = "Requires $req. Expected status: Unknown until tenant connection (licensing not read)."
            } else {
                $expected = 'Automatic'
                $reason = "Assessable from $($services -join ', ')$(if ($null -ne $opt) { "; $($opt.Collector.Name) enabled" })."
            }
        }

        $rows.Add([ordered]@{
            ControlId           = $cid
            Title               = [string](Get-TPObjectField -Item $c -Key 'Title' -Default '')
            Tier                = [string]$c.Tier
            Owner               = [string](Get-TPObjectField -Item $c -Key 'Owner' -Default '')
            Expected            = $expected
            ExpectedNotVerified = ($expected -in @('Manual', 'SkippedByOperator', 'OptionalCollectorRequired'))
            ReasonCode          = (ConvertTo-TPBaselineReasonCode -Expected $expected)
            Reason              = $reason
            Collectors          = @($services)
            RawDataKeys         = @($keys)
            OptionalCollector   = $(if ($null -ne $opt) { [string]$opt.Collector.Name } else { '' })
            LicenseRequirement  = $req
            LicenseStatus       = $licStatus
            Disposition         = $(if ($approved -is [System.Collections.IDictionary] -and $approved.Contains($cid)) { 'ApprovedException (observed state kept)' } else { 'Normal' })
        })
    }

    $count = { param([string] $e) @($rows | Where-Object { $_.Expected -eq $e }).Count }
    $summary = [ordered]@{
        BaselineVersion           = [string]$def.Version
        TargetTier                = $TargetTier
        RequiredControls          = $rows.Count
        Automatic                 = & $count 'Automatic'
        Manual                    = & $count 'Manual'
        ThirdPartyHandled         = & $count 'ThirdPartyHandled'
        OptionalCollectorRequired = & $count 'OptionalCollectorRequired'
        SkippedByOperator         = & $count 'SkippedByOperator'
        LicenseBlockedExpected    = & $count 'LicenseBlockedExpected'
        LicensingUnknown          = & $count 'LicensingUnknown'
        ExpectedNotVerified       = @($rows | Where-Object { $_.ExpectedNotVerified }).Count
        ApprovedExceptions        = @($rows | Where-Object { $_.Disposition -like 'ApprovedException*' }).Count
        LicenseSource             = $licSrc
    }

    $collectors = [System.Collections.Generic.List[object]]::new()
    foreach ($svc in $serviceKeys.Keys) {
        $keysHere = @($serviceKeys[$svc])
        $allSkipped = @($keysHere | Where-Object { -not $skip.Contains($_) }).Count -eq 0
        $someSkipped = @($keysHere | Where-Object { $skip.Contains($_) }).Count -gt 0
        $collectors.Add([ordered]@{
            Service     = $svc
            RawDataKeys = $keysHere
            Controls    = $serviceControls[$svc].Count
            Status      = $(if ($allSkipped) { 'Skipped by operator' } elseif ($someSkipped) { 'Required (part skipped by operator)' } else { 'Required' })
        })
    }
    $optional = [System.Collections.Generic.List[object]]::new()
    foreach ($oc in $catalog.Values) {
        $needed = @($rows | Where-Object { $_.OptionalCollector -eq $oc.Name }).Count
        $enabled = [bool]$enabledOptional[$oc.Id]
        $optional.Add([ordered]@{
            Service  = $oc.Name
            Switch   = $oc.Switch
            Controls = $needed
            Enabled  = $enabled
            Status   = $(if ($enabled) { "Enabled ($($oc.Switch))" } elseif ($needed -gt 0) { "Optional; required for $needed control(s), not enabled ($($oc.Switch))" } else { 'Optional; no required control needs it' })
        })
    }

    return [ordered]@{
        Available              = $true
        BaselineVersion        = [string]$def.Version
        TargetTier             = $TargetTier
        TenantDomain           = [string]$TenantDomain
        ThirdPartyEDR          = [string]$ThirdPartyEDR
        IncludeSharePointShell = [bool]$IncludeSharePointShell
        SkipCollectors         = @($SkipCollectors | Where-Object { $_ })
        LicenseSource          = $licSrc
        AsOf                   = $AsOf.ToString('o')
        Summary                = $summary
        ReasonCodes            = @((Get-TPBaselineReasonCodes).Values | ForEach-Object { [pscustomobject]$_ })
        RequiredCollectors     = @($collectors)
        OptionalCollectors     = @($optional)
        Controls               = @($rows)
        Note                   = 'Predictive. Expected states are what the compliance view will report if the run collects what it normally collects; a collector that fails on the day moves its controls to NotVerified. Licensing unknown until connection is unknown, not assumed held. Nothing here is a verdict.'
    }
}

function Compare-TPBaselinePlan {
    <#
    .SYNOPSIS
        Puts the pre-run plan beside the compliance view of the run that
        followed: which NotVerified rows were expected, which were not (a
        collector or a read that failed on the day), and which expected
        unknowns were assessed after all.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [object] $Plan,
        [Parameter(Mandatory)] [AllowNull()] [object] $Compliance
    )
    Set-StrictMode -Version Latest
    $empty = [ordered]@{ Available = $false; Note = 'No plan or no compliance view to compare.' }
    if ($null -eq $Plan -or $null -eq $Compliance) { return $empty }
    if (-not [bool](Get-TPObjectField -Item $Plan -Key 'Available' -Default $false)) { return $empty }
    if (-not [bool](Get-TPObjectField -Item $Compliance -Key 'Available' -Default $false)) { return $empty }

    $planRows = @(Get-TPObjectField -Item $Plan -Key 'Controls' -Default @())
    $compRows = @(Get-TPObjectField -Item $Compliance -Key 'Controls' -Default @())
    $expectedNv = @{}
    $expectedOf = @{}
    foreach ($r in $planRows) {
        $cid = [string](Get-TPObjectField -Item $r -Key 'ControlId' -Default '')
        if (-not $cid) { continue }
        $expectedOf[$cid] = [string](Get-TPObjectField -Item $r -Key 'Expected' -Default '')
        if ([bool](Get-TPObjectField -Item $r -Key 'ExpectedNotVerified' -Default $false)) { $expectedNv[$cid] = $expectedOf[$cid] }
    }
    $observedNv = @{}
    $observedReason = @{}
    $observedLb = 0
    $notInPlan = [System.Collections.Generic.List[string]]::new()
    foreach ($r in $compRows) {
        $cid = [string](Get-TPObjectField -Item $r -Key 'ControlId' -Default '')
        if (-not $cid) { continue }
        # A control the view required but the plan did not know is a
        # different baseline (version or tier); it is named, never compared.
        if (-not $expectedOf.ContainsKey($cid)) { $notInPlan.Add($cid); continue }
        if ([string](Get-TPObjectField -Item $r -Key 'ObservedState' -Default '') -eq 'NotVerified') {
            $observedNv[$cid] = [string](Get-TPObjectField -Item $r -Key 'NotVerifiedCause' -Default '')
            $observedReason[$cid] = @{ Code = [string](Get-TPObjectField -Item $r -Key 'ReasonCode' -Default ''); Reason = [string](Get-TPObjectField -Item $r -Key 'Reason' -Default '') }
        }
        if ([string](Get-TPObjectField -Item $r -Key 'Constraint' -Default '') -eq 'LicenseBlocked') { $observedLb++ }
    }
    $unexpected = @(foreach ($cid in @($observedNv.Keys | Sort-Object)) {
        if (-not $expectedNv.ContainsKey($cid)) {
            [ordered]@{ ControlId = $cid; Cause = $observedNv[$cid]; ReasonCode = $observedReason[$cid].Code; Reason = $observedReason[$cid].Reason; Expected = $(if ($expectedOf.ContainsKey($cid)) { $expectedOf[$cid] } else { '' }) }
        }
    })
    $verifiedAnyway = @(foreach ($cid in @($expectedNv.Keys | Sort-Object)) {
        if (-not $observedNv.ContainsKey($cid)) {
            $row = @($compRows | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'ControlId' -Default '') -eq $cid })
            [ordered]@{ ControlId = $cid; Expected = $expectedNv[$cid]; Observed = $(if ($row.Count -gt 0) { [string](Get-TPObjectField -Item $row[0] -Key 'ObservedState' -Default '') } else { 'no row' }) }
        }
    })
    $ps = Get-TPObjectField -Item $Plan -Key 'Summary' -Default $null
    $expectedLb = [int](Get-TPObjectField -Item $ps -Key 'LicenseBlockedExpected' -Default 0)
    $unknownLic = [int](Get-TPObjectField -Item $ps -Key 'LicensingUnknown' -Default 0)
    $note = if ($unexpected.Count -eq 0 -and $verifiedAnyway.Count -eq 0) {
        "The run resolved as planned: $($expectedNv.Count) not verified, all expected."
    } else {
        "Expected $($expectedNv.Count) not verified, observed $($observedNv.Count). $($unexpected.Count) not expected (a collector or a read did not complete on the day), $($verifiedAnyway.Count) expected but verified."
    }
    if ($notInPlan.Count -gt 0) { $note += " $($notInPlan.Count) required control(s) were not in the plan (a different baseline version or tier): $($notInPlan -join ', ')." }
    return [ordered]@{
        Available                = $true
        ExpectedNotVerified      = $expectedNv.Count
        ObservedNotVerified      = $observedNv.Count
        UnexpectedNotVerified    = @($unexpected)
        ExpectedButVerified      = @($verifiedAnyway)
        ExpectedLicenseBlocked   = $expectedLb
        ObservedLicenseBlocked   = $observedLb
        LicensingUnknownBeforeRun = $unknownLic
        NotInPlan                = @($notInPlan)
        Note                     = $note
    }
}

function Format-TPBaselinePlanSummary {
    <#
    .SYNOPSIS
        The compact operator summary of a plan, one string per line.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([Parameter(Mandatory)] [AllowNull()] [object] $Plan)
    Set-StrictMode -Version Latest
    if ($null -eq $Plan -or -not [bool](Get-TPObjectField -Item $Plan -Key 'Available' -Default $false)) { return @('Baseline plan unavailable.') }
    $s = Get-TPObjectField -Item $Plan -Key 'Summary' -Default $null
    $client = [string](Get-TPObjectField -Item $Plan -Key 'TenantDomain' -Default '')
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("NRG Security Baseline v$([string](Get-TPObjectField -Item $Plan -Key 'BaselineVersion' -Default ''))")
    $lines.Add("Client: $(if ($client) { $client } else { 'not specified' })")
    $lines.Add("Tier: $([string](Get-TPObjectField -Item $Plan -Key 'TargetTier' -Default ''))")
    $edr = [string](Get-TPObjectField -Item $Plan -Key 'ThirdPartyEDR' -Default '')
    if ($edr) { $lines.Add("Third-party EDR declared: $edr") }
    $lines.Add('')
    $lines.Add("$([int](Get-TPObjectField -Item $s -Key 'RequiredControls' -Default 0)) required controls")
    $lines.Add('')
    $lines.Add('Expected coverage')
    $fmt = { param([string] $k, [string] $label) $n = [int](Get-TPObjectField -Item $s -Key $k -Default 0); '  {0,3} {1}' -f $n, $label }
    $lines.Add((& $fmt 'Automatic' 'automatic'))
    $lines.Add((& $fmt 'ThirdPartyHandled' 'third-party handled (attested, not verified)'))
    $lines.Add((& $fmt 'Manual' 'manual'))
    $lines.Add((& $fmt 'OptionalCollectorRequired' 'optional collector required'))
    $lines.Add((& $fmt 'SkippedByOperator' 'skipped by operator'))
    $lines.Add((& $fmt 'LicenseBlockedExpected' 'license blocked (expected)'))
    $lines.Add((& $fmt 'LicensingUnknown' 'licensing unknown until connection'))
    $lines.Add('')
    $lines.Add('Required collectors')
    foreach ($c in @(Get-TPObjectField -Item $Plan -Key 'RequiredCollectors' -Default @())) {
        $lines.Add(('  {0,-52} {1} ({2} control(s))' -f [string]$c.Service, [string]$c.Status, [int]$c.Controls))
    }
    foreach ($c in @(Get-TPObjectField -Item $Plan -Key 'OptionalCollectors' -Default @())) {
        $lines.Add(('  {0,-52} {1}' -f [string]$c.Service, [string]$c.Status))
    }
    $lines.Add('')
    $lines.Add("Potential NotVerified before run: $([int](Get-TPObjectField -Item $s -Key 'ExpectedNotVerified' -Default 0))")
    $lines.Add("Licensing: $([string](Get-TPObjectField -Item $s -Key 'LicenseSource' -Default 'not read'))")
    $exc = [int](Get-TPObjectField -Item $s -Key 'ApprovedExceptions' -Default 0)
    if ($exc -gt 0) { $lines.Add("Approved exceptions in force: $exc (observed state is still reported)") }
    return $lines.ToArray()
}
