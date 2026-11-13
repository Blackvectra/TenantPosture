#Requires -Version 7.0
#
# Get-TPAiUseReview.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: The client-facing "AI use readiness review" model, built offline
#   from one saved full-run results file. A VIEW over existing results, like
#   the HIPAA client report: it creates no finding, changes none, has no score,
#   re-derives no verdict, and connects to nothing.
#
#   Five parts, each from evidence the assessment already holds:
#     1 Observed AI-related configuration   Copilot entitlement and seat counts
#                                           (D1's licensing state, never re-read
#                                           from the compatibility fields), the
#                                           Copilot Studio inventory counts, and
#                                           the PPL-3.3 share as an observation
#     2 Safeguards in place                 catalog controls recorded Satisfied
#     3 Items needing attention             catalog controls recorded Gap/Partial
#     4 Organizational decisions and gaps   five review areas, every one "not
#                                           recorded in this assessment", plus
#                                           what could not be verified and why
#     5 Prioritized next steps              four groups by what each step needs
#
# HONESTY RULES (pinned by TP.AiUseReview.Tests.ps1):
#   - A partial (-ControlId) or quick (-Quick) run, or an incident-response
#     file, is refused with a reason; an eligible full run with failed or
#     truncated reads is rendered, with every gap visible.
#   - A count is one of: collected zero, complete count, a lower bound from a
#     partial read ("at least N", from deduplicated evidence), or not read.
#     Missing inventory never becomes zero.
#   - Licensing state comes from Get-TPCopilotLicensingState (D1); SKU
#     recognition, assignment state and the PPL-3.3 ratio are not re-derived,
#     and the collector's older compatibility count fields are not read here.
#   - PPL-3.3 is an observation, never a safeguard. A recognized SKU with no
#     seat assigned does not establish that AI is unused.
#   - Every catalog control lands in exactly one group; a control with no
#     finding is named as such; a duplicate catalog id or an id not in
#     controls.json is a catalog error, never dropped.
#   - Technical evidence, third-party declarations and unrecorded
#     organizational evidence stay distinguishable; a Satisfied finding whose
#     collector coverage reads Failed or Skipped is shown as a conflict.
#   - The model carries control ids, titles from controls.json, states,
#     counts, statuses and catalog text: never a finding's Detail, an account,
#     an object id, an agent or application name, or a tenant identifier.
#     ClientName is a supplied display label only.
#
# Inputs:  -Findings (ControlId/State/Severity used), -Metadata, -Facts
#          (Read-TPAiUseFacts), -ScopeBuckets (Get-TPAiUseReviewScope),
#          -LicenseProfile, -ClientName, -PreparedBy, -Hipaa, -ConfigPath.
# Data consumed: Config/ai-use-review.json, controls.json,
#          operational-impact.json, one -results.json (through the readers).
# Graph scopes / cmdlets used: none. No network. No write.

function Get-TPAiUseReviewGroupNames {
    [CmdletBinding()]
    param()
    return [ordered]@{
        Observed    = 'Observed only'
        Verified    = 'Safeguards in place'
        Attention   = 'Items needing attention'
        Attested    = 'Declared by a third party, not verified here'
        NotVerified = 'Not verified in this review'
    }
}

function Get-TPAiUseReviewRelationships {
    [CmdletBinding()]
    param()
    return @('AiSpecific', 'DirectAccess', 'SupportingGovernance', 'General')
}

# The fixed set of roles a next step may suggest. A suggestion, never an
# appointment: the review cannot know who has accepted a responsibility.
function Get-TPAiUseReviewRoles {
    [CmdletBinding()]
    param()
    return @('Business owner', 'Security/IT administrator', 'Data owner', 'Privacy/legal adviser')
}

# A whole number or $null: absence and anything that is not a count stay
# $null, never 0 (the same rule as D1's ConvertTo-TPCopilotCount).
function ConvertTo-TPAiUseCount {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)
    if ($null -eq $Value) { return $null }
    $n = $null
    if ($Value -is [int] -or $Value -is [long]) { $n = [long]$Value }
    elseif ($Value -is [double] -or $Value -is [decimal]) {
        if ([math]::Floor([double]$Value) -eq [double]$Value) { $n = [long]$Value }
    }
    elseif ($Value -is [string] -and $Value -cmatch '\A[0-9]{1,9}\z') { $n = [long]$Value }
    # A count is a whole number from 0 to int.MaxValue; anything else is not read.
    if ($null -eq $n -or $n -lt 0 -or $n -gt [int]::MaxValue) { return $null }
    return [int]$n
}

# One rendered count. Status: Complete (the whole population was read),
# LowerBound (a partial read found at least N), NotEstablished (a partial read
# found none, which is not zero), NotRead (no value).
function New-TPAiUseCount {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $Kind,
        [Parameter(Mandatory)] [string] $Label,
        [AllowNull()] [object] $Value,
        [AllowEmptyString()] [string] $Completeness = 'NotRead',
        [AllowEmptyString()] [string] $Note = ''
    )
    $v = ConvertTo-TPAiUseCount $Value
    $comp = if ($Completeness -cin @('Complete', 'Incomplete')) { $Completeness } else { 'NotRead' }
    if ($null -eq $v) { $comp = 'NotRead' }
    $status = switch ($comp) {
        'Complete'   { 'Complete' }
        'Incomplete' { if ($v -gt 0) { 'LowerBound' } else { 'NotEstablished' } }
        default      { 'NotRead' }
    }
    $display = switch ($status) {
        'Complete'       { [string]::Format([cultureinfo]::InvariantCulture, '{0}', $v) }
        'LowerBound'     { [string]::Format([cultureinfo]::InvariantCulture, 'at least {0}', $v) }
        'NotEstablished' { 'Not established (the read did not complete)' }
        default          { 'Not read' }
    }
    return [ordered]@{
        Kind         = $Kind
        Label        = $Label
        Value        = $(if ($status -in @('Complete', 'LowerBound')) { $v } else { $null })
        Completeness = $comp
        Status       = $status
        Display      = $display
        Note         = $Note
    }
}

# ── Catalog ──────────────────────────────────────────────────────────────────

function Get-TPAiUseReviewCatalog {
    <#
    .SYNOPSIS
        Loads and validates Config/ai-use-review.json. A duplicate control id,
        an id not in controls.json, an unknown relationship or a reference that
        is not an https Microsoft URL is an error, never dropped.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowEmptyString()] [string] $ConfigPath = '')
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $root = if ((Get-Variable -Name TPModuleRoot -Scope Script -ErrorAction SilentlyContinue) -and $script:TPModuleRoot) { $script:TPModuleRoot } else { Split-Path -Parent $PSScriptRoot }
    $path = if ($ConfigPath) { $ConfigPath } else { Join-Path $root 'Config' 'ai-use-review.json' }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'The AI use review catalog (Config/ai-use-review.json) was not found.' }
    $raw = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 32 -ErrorAction Stop
    if ($raw -isnot [System.Collections.IDictionary]) { throw 'The AI use review catalog is not a JSON object.' }

    $version = [string](Get-TPObjectField -Item $raw -Key 'version' -Default '')
    if (-not $version) { throw 'The AI use review catalog has no version.' }
    $relationships = Get-TPAiUseReviewRelationships
    $known = @{}
    foreach ($c in @(Get-TPControlDefinitions)) { $known[[string](Get-TPObjectField -Item $c -Key 'ControlId' -Default '')] = $c }

    $checkRef = {
        param([object] $ref, [string] $where)
        if ($null -eq $ref) { return $null }
        $url = [string](Get-TPObjectField -Item $ref -Key 'Url' -Default '')
        $uri = $null
        $ok = [System.Uri]::TryCreate($url, [System.UriKind]::Absolute, [ref]$uri) -and $uri.Scheme -eq 'https' -and
              ($uri.Host -eq 'microsoft.com' -or $uri.Host.EndsWith('.microsoft.com', [System.StringComparison]::OrdinalIgnoreCase))
        if (-not $ok) { throw "The AI use review catalog reference for $where is not an https Microsoft URL." }
        $retrieved = [string](Get-TPObjectField -Item $ref -Key 'Retrieved' -Default '')
        if ($retrieved -cnotmatch '\A\d{4}-\d{2}-\d{2}\z') { throw "The AI use review catalog reference for $where has no retrieval date (yyyy-MM-dd)." }
        return [ordered]@{ Title = [string](Get-TPObjectField -Item $ref -Key 'Title' -Default ''); Url = $url; Retrieved = $retrieved }
    }

    $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $controls = [System.Collections.Generic.List[object]]::new()
    foreach ($row in @(Get-TPObjectField -Item $raw -Key 'controls' -Default @())) {
        $cid = [string](Get-TPObjectField -Item $row -Key 'ControlId' -Default '')
        if ($cid -cnotmatch '\A[A-Z]{2,8}-\d+\.\d+\z') { throw "The AI use review catalog has a control id that is not a control id: '$cid'." }
        if (-not $seen.Add($cid)) { throw "The AI use review catalog lists $cid twice." }
        if (-not $known.ContainsKey($cid)) { throw "The AI use review catalog names $cid, which is not in controls.json." }
        $rel = [string](Get-TPObjectField -Item $row -Key 'Relationship' -Default '')
        if ($rel -cnotin $relationships) { throw "The AI use review catalog gives $cid an unknown relationship '$rel'." }
        $controls.Add([ordered]@{
            ControlId    = $cid
            Relationship = $rel
            Scope        = [string](Get-TPObjectField -Item $row -Key 'Scope' -Default '')
            Explanation  = [string](Get-TPObjectField -Item $row -Key 'Explanation' -Default '')
            Reference    = (& $checkRef (Get-TPObjectField -Item $row -Key 'Reference' -Default $null) $cid)
        })
    }
    $observations = [System.Collections.Generic.List[object]]::new()
    foreach ($row in @(Get-TPObjectField -Item $raw -Key 'observations' -Default @())) {
        $cid = [string](Get-TPObjectField -Item $row -Key 'ControlId' -Default '')
        if ($cid -cnotmatch '\A[A-Z]{2,8}-\d+\.\d+\z') { throw "The AI use review catalog has an observation id that is not a control id: '$cid'." }
        if (-not $seen.Add($cid)) { throw "The AI use review catalog lists $cid twice." }
        if (-not $known.ContainsKey($cid)) { throw "The AI use review catalog names $cid, which is not in controls.json." }
        $observations.Add([ordered]@{ ControlId = $cid; Why = [string](Get-TPObjectField -Item $row -Key 'Why' -Default '') })
    }
    $roles = Get-TPAiUseReviewRoles
    $organizational = [System.Collections.Generic.List[object]]::new()
    foreach ($row in @(Get-TPObjectField -Item $raw -Key 'organizational' -Default @())) {
        $suggested = @(@(Get-TPObjectField -Item $row -Key 'SuggestedRoles' -Default @()) | ForEach-Object { [string]$_ })
        foreach ($r in $suggested) { if ($r -cnotin $roles) { throw "The AI use review catalog suggests a role outside the fixed set: '$r'." } }
        $organizational.Add([ordered]@{
            Id             = [string](Get-TPObjectField -Item $row -Key 'Id' -Default '')
            Area           = [string](Get-TPObjectField -Item $row -Key 'Area' -Default '')
            Question       = [string](Get-TPObjectField -Item $row -Key 'Question' -Default '')
            EvidenceType   = [string](Get-TPObjectField -Item $row -Key 'EvidenceType' -Default '')
            SuggestedRoles = $suggested
            GeneralWording = [string](Get-TPObjectField -Item $row -Key 'GeneralWording' -Default '')
            HipaaWording   = [string](Get-TPObjectField -Item $row -Key 'HipaaWording' -Default '')
        })
    }
    if ($organizational.Count -eq 0) { throw 'The AI use review catalog has no organizational review areas.' }
    $facts = [System.Collections.Generic.List[object]]::new()
    foreach ($row in @(Get-TPObjectField -Item $raw -Key 'vendorFacts' -Default @())) {
        $id = [string](Get-TPObjectField -Item $row -Key 'Id' -Default '')
        $facts.Add([ordered]@{
            Id        = $id
            Statement = [string](Get-TPObjectField -Item $row -Key 'Statement' -Default '')
            Source    = (& $checkRef (Get-TPObjectField -Item $row -Key 'Source' -Default $null) "vendor fact '$id'")
        })
    }
    $retrieved = [string](Get-TPObjectField -Item $raw -Key 'vendorFactsRetrieved' -Default '')
    if ($retrieved -cnotmatch '\A\d{4}-\d{2}-\d{2}\z') { throw 'The AI use review catalog has no vendorFactsRetrieved date (yyyy-MM-dd).' }

    # Readiness gate: the reasons, the items this assessment never checks and the
    # sources. WHICH controls block is the practice's standard (tp-standards.json),
    # not part of this catalog.
    $rd = Get-TPObjectField -Item $raw -Key 'readiness' -Default $null
    $reasons = [ordered]@{}
    $rr = Get-TPObjectField -Item $rd -Key 'blockerReasons' -Default $null
    if ($rr -is [System.Collections.IDictionary]) {
        foreach ($k in @($rr.Keys)) {
            if (-not $known.ContainsKey([string]$k)) { throw "The AI use review catalog gives a blocker reason for $k, which is not in controls.json." }
            $reasons[[string]$k] = [string]$rr[$k]
        }
    }
    $notChecked = [System.Collections.Generic.List[object]]::new()
    foreach ($row in @(Get-TPObjectField -Item $rd -Key 'notChecked' -Default @())) {
        $id = [string](Get-TPObjectField -Item $row -Key 'Id' -Default '')
        $notChecked.Add([ordered]@{
            Id = $id; Title = [string](Get-TPObjectField -Item $row -Key 'Title' -Default ''); Why = [string](Get-TPObjectField -Item $row -Key 'Why' -Default '')
            Reference = (& $checkRef (Get-TPObjectField -Item $row -Key 'Reference' -Default $null) "not-checked item '$id'")
        })
    }
    $userNotChecked = @(foreach ($row in @(Get-TPObjectField -Item $rd -Key 'userNotChecked' -Default @())) {
        [ordered]@{ Id = [string](Get-TPObjectField -Item $row -Key 'Id' -Default ''); Title = [string](Get-TPObjectField -Item $row -Key 'Title' -Default ''); Why = [string](Get-TPObjectField -Item $row -Key 'Why' -Default '') }
    })
    $rdSources = @(foreach ($row in @(Get-TPObjectField -Item $rd -Key 'sources' -Default @())) { & $checkRef $row 'a readiness source' })

    return [ordered]@{
        Readiness            = [ordered]@{
            Basis          = [string](Get-TPObjectField -Item $rd -Key 'basis' -Default '')
            BlockerReasons = $reasons
            NotChecked     = $notChecked.ToArray()
            UserNotChecked = $userNotChecked
            Sources        = $rdSources
        }
        Version              = $version
        VendorFactsRetrieved = $retrieved
        Relationships        = (Get-TPObjectField -Item $raw -Key 'relationships' -Default @{})
        Controls             = $controls.ToArray()
        Observations         = $observations.ToArray()
        Organizational       = $organizational.ToArray()
        VendorFacts          = $facts.ToArray()
        ControlsJsonTotal    = $known.Count
    }
}

# ── Facts reader ─────────────────────────────────────────────────────────────

function Read-TPAiUseFacts {
    <#
    .SYNOPSIS
        Reads the allowlisted aggregate facts the AI use review needs from a
        saved results file: the M365Copilot licensing measurements and read
        statuses, the Copilot Studio inventory counts and statuses, the
        subscribed SKUs (part numbers and service plan names), each collector's
        coverage status and success flag. Nothing else is materialized.
    .DESCRIPTION
        A JsonDocument is parsed once and only the named elements are turned
        into objects; the file is bounded by Get-TPRunRecordMaxBytes. Agent
        names, environment names and ids, error text, accounts and the tenant
        id are never read. Throws a fixed sentence (never the content) when
        the file is too large, is not JSON or is not a results object.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([Parameter(Mandatory)] [string] $Path)
    Set-StrictMode -Version Latest

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item -isnot [System.IO.FileInfo]) { throw 'The results path is not a file.' }
    if ($item.Length -gt (Get-TPRunRecordMaxBytes)) { throw 'The results file is larger than this tool reads.' }

    $facts = [ordered]@{
        Available          = $false
        IsIncidentResponse = $false
        Copilot            = $null
        CopilotStudio      = $null
        SubscribedSkus     = $null
        Coverage           = [ordered]@{}
        RawDataSuccess     = [ordered]@{}
    }
    $kinds = [System.Text.Json.JsonValueKind]
    $prop = {
        param([System.Text.Json.JsonElement] $el, [string] $name)
        if ($el.ValueKind -ne $kinds::Object) { return $null }
        $out = [System.Text.Json.JsonElement]::new()
        if ($el.TryGetProperty($name, [ref]$out)) { return $out }
        return $null
    }
    $scalar = {
        param([object] $el)
        if ($null -eq $el) { return $null }
        switch ($el.ValueKind) {
            ($kinds::String) { return $el.GetString() }
            ($kinds::Number) { $d = 0.0; if ($el.TryGetDouble([ref]$d)) { return $d }; return $null }
            ($kinds::True)   { return $true }
            ($kinds::False)  { return $false }
            default          { return $null }
        }
    }
    $count = { param([object] $el) ConvertTo-TPAiUseCount (& $scalar $el) }
    $text  = { param([object] $el) $v = & $scalar $el; if ($v -is [string]) { $v } else { '' } }

    $options = [System.Text.Json.JsonDocumentOptions]::new()
    $options.MaxDepth = 256
    $stream = [System.IO.File]::Open($item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        try { $doc = [System.Text.Json.JsonDocument]::Parse($stream, $options) } catch { throw 'The results file is not valid JSON.' }
        try {
            $root = $doc.RootElement
            if ($root.ValueKind -ne $kinds::Object) { throw 'The file is not an assessment results file.' }
            if ($null -ne (& $prop $root 'DeepDives')) { $facts.IsIncidentResponse = $true; return $facts }
            $findings = & $prop $root 'Findings'
            if ($null -ne $findings -and $findings.ValueKind -eq $kinds::Array) {
                foreach ($f in $findings.EnumerateArray()) {
                    $cid = & $text (& $prop $f 'ControlId')
                    if ($cid -match '\A(EMAIL|SIGNIN)-') { $facts.IsIncidentResponse = $true; return $facts }
                }
            }
            $facts.Available = $true

            $coverage = & $prop $root 'Coverage'
            if ($null -ne $coverage -and $coverage.ValueKind -eq $kinds::Object) {
                foreach ($p in $coverage.EnumerateObject()) {
                    $st = & $text (& $prop $p.Value 'Status')
                    if ($st -cin @('Collected', 'Partial', 'NotCollected', 'Failed', 'Skipped')) { $facts.Coverage[[string]$p.Name] = $st }
                }
            }
            $rawData = & $prop $root 'RawData'
            if ($null -ne $rawData -and $rawData.ValueKind -eq $kinds::Object) {
                foreach ($p in $rawData.EnumerateObject()) {
                    $s = & $scalar (& $prop $p.Value 'Success')
                    $facts.RawDataSuccess[[string]$p.Name] = ($s -is [bool] -and $s)
                }

                # Subscribed SKUs: part number and service plan names only.
                $inv = & $prop $rawData 'AAD-Inventory'
                $skus = $null
                if ($null -ne $inv) { $skus = & $prop (& $prop $inv 'Data') 'SubscribedSkus' }
                if ($null -ne $skus -and $skus.ValueKind -eq $kinds::Array) {
                    $rows = [System.Collections.Generic.List[object]]::new()
                    foreach ($s in $skus.EnumerateArray()) {
                        $plans = [System.Collections.Generic.List[string]]::new()
                        $sp = & $prop $s 'ServicePlans'
                        if ($null -ne $sp -and $sp.ValueKind -eq $kinds::Array) {
                            foreach ($x in $sp.EnumerateArray()) { $n = & $text $x; if ($n) { $plans.Add($n) } }
                        }
                        $rows.Add([ordered]@{
                            SkuPartNumber = (& $text (& $prop $s 'SkuPartNumber'))
                            ServicePlans  = $plans.ToArray()
                            ConsumedUnits = (& $count (& $prop $s 'ConsumedUnits'))
                            PrepaidUnits  = (& $count (& $prop $s 'PrepaidUnits'))
                        })
                    }
                    $facts.SubscribedSkus = $rows.ToArray()
                }

                # M365Copilot: the envelope Get-TPCopilotLicensingState reads, allowlisted.
                $cp = & $prop $rawData 'M365Copilot'
                if ($null -ne $cp) {
                    $d = & $prop $cp 'Data'
                    $success = & $scalar (& $prop $cp 'Success')
                    $env = [ordered]@{ Success = ($success -is [bool] -and $success); Data = [ordered]@{} }
                    $ss = & $prop $d 'SectionStatus'
                    if ($null -ne $ss -and $ss.ValueKind -eq $kinds::Object) {
                        $env.Data['SectionStatus'] = [ordered]@{}
                        foreach ($k in 'Licensing', 'Users') {
                            $v = & $text (& $prop $ss $k)
                            if ($v -cin @('Collected', 'Failed', 'Truncated', 'NotRun')) { $env.Data.SectionStatus[$k] = $v }
                        }
                    }
                    $lm = & $prop $d 'LicensingMeasurements'
                    if ($null -ne $lm -and $lm.ValueKind -eq $kinds::Object) {
                        $env.Data['LicensingMeasurements'] = [ordered]@{}
                        foreach ($k in 'RecognizedSkuCount', 'PurchasedSeats', 'SkuConsumedUnits', 'EnabledMembers', 'AssignedUsers', 'AssignedEnabledMembers') {
                            $m = & $prop $lm $k
                            if ($null -eq $m) { continue }
                            $comp = & $text (& $prop $m 'Completeness')
                            $env.Data.LicensingMeasurements[$k] = [ordered]@{
                                Value        = (& $count (& $prop $m 'Value'))
                                Completeness = $(if ($comp -cin @('Complete', 'Incomplete', 'NotRead')) { $comp } else { 'NotRead' })
                            }
                        }
                    }
                    $ue = & $prop $d 'UserEnumeration'
                    if ($null -ne $ue -and $ue.ValueKind -eq $kinds::Object) {
                        $stop = & $text (& $prop $ue 'StopReason')
                        $env.Data['UserEnumeration'] = [ordered]@{
                            StopReason            = $(if ($stop -cin @('Complete', 'PageCap', 'RepeatedNextLink', 'Failed', 'NotRun')) { $stop } else { 'Unknown' })
                            PagesRead             = (& $count (& $prop $ue 'PagesRead'))
                            DistinctAccounts      = (& $count (& $prop $ue 'DistinctAccounts'))
                            DuplicateRows         = (& $count (& $prop $ue 'DuplicateRows'))
                            RowsWithoutId         = (& $count (& $prop $ue 'RowsWithoutId'))
                            AccountEnabledUnknown = (& $count (& $prop $ue 'AccountEnabledUnknown'))
                        }
                    }
                    # The older compatibility counts are not read (the view's contract);
                    # an older file therefore reads as unknown unless its SKU rows carry
                    # consumed seats. A row's id is reduced to whether it was present.
                    $ls = & $prop $d 'LicensedSkus'
                    if ($null -ne $ls -and $ls.ValueKind -eq $kinds::Array) {
                        $rows = [System.Collections.Generic.List[object]]::new()
                        foreach ($r in $ls.EnumerateArray()) {
                            if ($r.ValueKind -ne $kinds::Object) { $rows.Add('row'); continue }
                            $hasId = -not [string]::IsNullOrWhiteSpace((& $text (& $prop $r 'SkuId')))
                            $rows.Add([ordered]@{
                                SkuId         = $(if ($hasId) { 'present' } else { '' })
                                SkuPartNumber = (& $text (& $prop $r 'SkuPartNumber'))
                                PrepaidUnits  = (& $count (& $prop $r 'PrepaidUnits'))
                                ConsumedUnits = (& $count (& $prop $r 'ConsumedUnits'))
                            })
                        }
                        $env.Data['LicensedSkus'] = $rows.ToArray()
                    }
                    $facts.Copilot = $env
                }

                # Copilot Studio: statuses and counts per environment, never names or ids.
                $cs = & $prop $rawData 'CopilotStudio'
                if ($null -ne $cs) {
                    $d = & $prop $cs 'Data'
                    $success = & $scalar (& $prop $cs 'Success')
                    $listStatus = & $text (& $prop (& $prop $d 'SectionStatus') 'Environments')
                    if ($listStatus -cnotin @('Collected', 'Failed', 'NotRun')) { $listStatus = 'NotRecorded' }
                    $envs = [System.Collections.Generic.List[object]]::new()
                    $list = & $prop $d 'Environments'
                    if ($null -ne $list -and $list.ValueKind -eq $kinds::Array) {
                        foreach ($e in $list.EnumerateArray()) {
                            $hasDv = & $scalar (& $prop $e 'HasDataverse')
                            $ast = & $text (& $prop $e 'AgentsStatus')
                            $envs.Add([ordered]@{
                                HasDataverse      = ($hasDv -is [bool] -and $hasDv)
                                AgentsStatus      = $(if ($ast -cin @('Collected', 'Truncated', 'Failed', 'NotRun')) { $ast } else { 'Unknown' })
                                AgentCount        = (& $count (& $prop $e 'AgentCount'))
                                ManagedAgentCount = (& $count (& $prop $e 'ManagedAgentCount'))
                            })
                        }
                    }
                    $facts.CopilotStudio = [ordered]@{
                        Success         = ($success -is [bool] -and $success)
                        ListStatus      = $listStatus
                        Environments    = $envs.ToArray()
                        MaxEnvironments = (& $count (& $prop (& $prop $d 'Limits') 'MaxEnvironments'))
                    }
                }
            }
        } finally { $doc.Dispose() }
    } finally { $stream.Dispose() }
    return $facts
}

# ── Offline scope (the thin composition of the public functions) ────────────

function Get-TPAiUseReviewScope {
    <#
    .SYNOPSIS
        The scope classification of a saved results file, as -FromResults
        would compute it: every finding (replayed through Select-TPReplayedFinding),
        the recorded coverage and the raw inventory, through Get-TPAssessmentScope.
        Returns bucket names per control id only; nothing from the file is kept.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([Parameter(Mandatory)] [string] $Path)
    Set-StrictMode -Version Latest

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item -isnot [System.IO.FileInfo]) { throw 'The results path is not a file.' }
    if ($item.Length -gt (Get-TPRunRecordMaxBytes)) { throw 'The results file is larger than this tool reads.' }
    $full = Get-Content -LiteralPath $item.FullName -Raw -Encoding utf8 | ConvertFrom-Json -AsHashtable -Depth 64 -ErrorAction Stop
    if ($full -isnot [System.Collections.IDictionary]) { throw 'The file is not an assessment results file.' }

    $dropped = @()
    $findings = @(Select-TPReplayedFinding -Findings @(Get-TPObjectField -Item $full -Key 'Findings' -Default @()) -Dropped ([ref]$dropped))
    $valid = @((Get-Command Register-TPCoverage).Parameters['Status'].Attributes |
        Where-Object { $_ -is [System.Management.Automation.ValidateSetAttribute] } | ForEach-Object { $_.ValidValues })
    $coverage = @{}
    $block = Get-TPObjectField -Item $full -Key 'Coverage' -Default $null
    if ($block -is [System.Collections.IDictionary]) {
        foreach ($k in @($block.Keys)) {
            $st = [string](Get-TPObjectField -Item $block[$k] -Key 'Status' -Default '')
            if ($st -notin $valid) { continue }
            $coverage[[string]$k] = [ordered]@{ Status = $st; Note = [string](Get-TPObjectField -Item $block[$k] -Key 'Note' -Default '') }
        }
    }
    $rawData = Get-TPObjectField -Item $full -Key 'RawData' -Default $null
    $meta = Get-TPObjectField -Item $full -Key 'Metadata' -Default $null
    $quick = [bool](Get-TPObjectField -Item $meta -Key 'QuickScan' -Default $false)
    $scope = Get-TPAssessmentScope -Findings $findings -Coverage $coverage -RawData $rawData -QuickScan:$quick

    $buckets = [ordered]@{}
    foreach ($name in @('LicenceBlocked', 'CollectionIncomplete', 'NoProgrammaticCheck', 'ThirdPartyAttested', 'StandardNotApproved', 'NotApplicableToTenant', 'NotEvaluatedThisMode', 'NotSelected', 'SkippedByOperator', 'NoResult')) {
        foreach ($row in @(Get-TPObjectField -Item $scope -Key $name -Default @())) {
            $cid = [string](Get-TPObjectField -Item $row -Key 'ControlId' -Default '')
            if ($cid -and -not $buckets.Contains($cid)) { $buckets[$cid] = $name }
        }
    }
    return [ordered]@{
        Buckets         = $buckets
        DroppedFindings = @($dropped).Count
        RunScope        = (Get-TPRunScope -Metadata $meta)
    }
}

# ── Model ────────────────────────────────────────────────────────────────────

function Get-TPAiUseReview {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [AllowNull()] [object] $Metadata,
        [AllowNull()] [object] $Facts,
        [AllowNull()] [object] $ScopeBuckets,
        [AllowNull()] [object] $LicenseProfile,
        [AllowEmptyString()] [string] $ClientName = '',
        [AllowEmptyString()] [string] $PreparedBy = '',
        [switch] $Hipaa,
        [AllowEmptyString()] [string] $ConfigPath = '',
        # The controls whose shortfall blocks a Copilot deployment. Defaults to the
        # approved standard (tp-standards.json, CopilotReadinessBlockers); an empty
        # list means no gate is approved and no verdict is printed.
        [AllowNull()] [AllowEmptyCollection()] [string[]] $BlockerControlIds,
        # Per-account facts from Read-TPAiUseUserFacts, for accounts the operator named.
        [AllowNull()] [AllowEmptyCollection()] [object[]] $UserFacts
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $runScope = Get-TPRunScope -Metadata $Metadata
    if ($runScope -ne 'Full') {
        $why = if ($runScope -eq 'Partial') { 'a partial run (-ControlId)' } else { 'a quick scan (-Quick evaluates Critical and High controls only)' }
        return [ordered]@{ Available = $false; Refused = $true; Note = "The AI use readiness review covers the whole tenant and is not written from $why. Run a full assessment." }
    }
    if ($null -ne $Facts -and [bool](Get-TPObjectField -Item $Facts -Key 'IsIncidentResponse' -Default $false)) {
        return [ordered]@{ Available = $false; Refused = $true; Note = 'That file is an incident-response output, not an assessment. Nothing was written.' }
    }

    $catalog = Get-TPAiUseReviewCatalog -ConfigPath $ConfigPath
    $names = Get-TPAiUseReviewGroupNames
    $defs = @{}
    foreach ($c in @(Get-TPControlDefinitions)) { $defs[[string](Get-TPObjectField -Item $c -Key 'ControlId' -Default '')] = $c }
    $sevRank = @{ Critical = 0; High = 1; Medium = 2; Low = 3; Informational = 4 }
    $impactCatalog = try { Get-TPOperationalImpactCatalog } catch { $null }

    # Licensing: the recorded SKUs, read through the same profile the live run uses.
    $skus = @(Get-TPObjectField -Item $Facts -Key 'SubscribedSkus' -Default @())
    if (-not $PSBoundParameters.ContainsKey('LicenseProfile') -or $null -eq $LicenseProfile) {
        $LicenseProfile = if ($skus.Count -gt 0) { Get-TPTenantLicenseProfile -SubscribedSkus $skus } else { $null }
    }
    $licenseRead = [bool](Get-TPObjectField -Item $LicenseProfile -Key 'HasLicenseData' -Default $false)
    $entitlement = { param([string] $req, [string] $label)
        $status = if (-not $licenseRead) { 'NotRead' } elseif ([bool](Test-TPLicenseRequirementMet -LicenseRequirement $req -LicenseProfile $LicenseProfile)) { 'Detected' } else { 'NotDetected' }
        [ordered]@{ Requirement = $req; Label = $label; Status = $status; Display = $(switch ($status) { 'Detected' { 'Detected in the subscribed SKUs' } 'NotDetected' { 'Not detected in the subscribed SKUs' } default { 'Licensing was not read in this assessment' } }) }
    }

    # Findings: the replay rule, then one worst-state finding per control.
    $dropped = @()
    $kept = @(Select-TPReplayedFinding -Findings $Findings -Dropped ([ref]$dropped))
    # One worst-state finding per control id (Get-TPStateSeverityRank), with no
    # link grouping: Get-TPScoringFindings folds linked controls into one entry
    # under the group's primary id for the score, which would leave a catalog
    # control such as DEF-4.2 reading as "no finding" here.
    $worst = Get-TPControlWorstFindings -Findings $kept
    $byControl = @{}
    foreach ($k in @($worst.Keys)) { $byControl[[string]$k] = $worst[$k] }
    $coverage = Get-TPObjectField -Item $Facts -Key 'Coverage' -Default $null
    $rawOk = Get-TPObjectField -Item $Facts -Key 'RawDataSuccess' -Default $null
    $buckets = if ($null -ne $ScopeBuckets) { $ScopeBuckets } else { @{} }
    $bucketOf = { param([string] $cid) [string](Get-TPObjectField -Item $buckets -Key $cid -Default '') }

    $groups = [ordered]@{}
    foreach ($k in $names.Keys) { $groups[$k] = [System.Collections.Generic.List[object]]::new() }
    $notVerifiedText = @{
        NoFinding             = 'No finding for this control is recorded in the results file.'
        NotSelected           = 'The control was not selected for this run.'
        NotEvaluatedThisMode  = 'The control was not evaluated in this run mode.'
        CheckErrored          = 'The check errored; it produced no verdict.'
        EvidenceConflict      = 'The finding is recorded as satisfied, but the collector that supplies its evidence did not complete (coverage Failed, Skipped or NotCollected, or its collector recorded a failure). The two records disagree, so nothing is claimed either way.'
        LicenseNotHeld        = 'The tenant does not hold the license this setting needs, so it was not scored.'
        NotCollected          = 'The data this control needs was not collected in this run.'
        ManualReview          = 'This item has no automated check; it is reviewed manually.'
        SkippedByOperator     = 'The operator skipped this workload for the run.'
        NotApplicableToTenant = 'The check ran and does not apply to this tenant (the reason is in the assessment report).'
        StandardNotApproved   = 'The standard this check judges against is not yet approved, so nothing was judged.'
        NotAssessed           = 'The check produced no verdict in this run.'
    }
    $place = {
        param([object] $entry, [bool] $addToGroup = $true)
        $cid = [string]$entry.ControlId
        $def = $defs[$cid]
        $f = $byControl[$cid]
        $state = if ($null -ne $f) { [string](Get-TPObjectField -Item $f -Key 'State' -Default '') } else { '' }
        $dep = [string](Get-TPObjectField -Item $def -Key 'CollectorDependency' -Default '')
        # A control can depend on several collectors ('A,B'): each is looked up on its own, and
        # the worst status stands. A collector whose RawData records Success = false counts as
        # Failed even when its coverage line says otherwise.
        $rank = @{ Failed = 4; Skipped = 3; NotCollected = 2; Partial = 1; Collected = 0 }
        $cov = ''
        foreach ($d in @($dep -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })) {
            $c = [string](Get-TPObjectField -Item $coverage -Key $d -Default '')
            $ok = Get-TPObjectField -Item $rawOk -Key $d -Default $null
            if ($ok -is [bool] -and -not $ok) { $c = 'Failed' }
            if ($c -and (-not $cov -or $rank[$c] -gt $rank[$cov])) { $cov = $c }
        }
        $bucket = & $bucketOf $cid
        $group = 'NotVerified'; $reason = 'NotAssessed'
        switch ($state) {
            ''          { $reason = switch ($bucket) { 'NotSelected' { 'NotSelected' } 'NotEvaluatedThisMode' { 'NotEvaluatedThisMode' } default { 'NoFinding' } } }
            'Satisfied' { if ($cov -cin @('Failed', 'Skipped', 'NotCollected')) { $reason = 'EvidenceConflict' } else { $group = 'Verified'; $reason = 'Satisfied' } }
            'Gap'       { $group = 'Attention'; $reason = 'Shortfall' }
            'Partial'   { $group = 'Attention'; $reason = 'Shortfall' }
            'Error'     { $reason = 'CheckErrored' }
            default     {
                $reason = switch ($bucket) {
                    'ThirdPartyAttested'    { $group = 'Attested'; 'ThirdPartyDeclared' }
                    'LicenceBlocked'        { 'LicenseNotHeld' }
                    'CollectionIncomplete'  { 'NotCollected' }
                    'NoProgrammaticCheck'   { 'ManualReview' }
                    'SkippedByOperator'     { 'SkippedByOperator' }
                    'NotApplicableToTenant' { 'NotApplicableToTenant' }
                    'StandardNotApproved'   { 'StandardNotApproved' }
                    default                 { 'NotAssessed' }
                }
            }
        }
        $licensed = $null
        if ($group -eq 'Attention' -and $licenseRead) { $licensed = [bool](Test-TPFindingLicensed -Finding $f -Definition $def -LicenseProfile $LicenseProfile) }
        $impact = if ($impactCatalog) { Get-TPControlOperationalImpact -ControlId $cid -Catalog $impactCatalog } else { $null }
        $item = [ordered]@{
            ControlId     = $cid
            Title         = [string](Get-TPObjectField -Item $def -Key 'Title' -Default $cid)
            Severity      = [string](Get-TPObjectField -Item $def -Key 'Severity' -Default '')
            Relationship  = [string]$entry.Relationship
            Scope         = [string]$entry.Scope
            Explanation   = [string]$entry.Explanation
            Reference     = $entry.Reference
            State         = $(if ($state) { $state } else { 'NoFinding' })
            Group         = $group
            Reason        = $reason
            ReasonText    = $(switch ($reason) {
                'Satisfied'          { 'The Microsoft 365 setting this control checks was in place when the assessment ran.' }
                'Shortfall'          { if ($state -eq 'Partial') { 'The setting is only partly in place.' } else { 'The setting is missing or not enforced.' } }
                'ThirdPartyDeclared' { 'The assessor declared a third-party product covers this; the declaration was not verified by this assessment.' }
                default              { [string]$notVerifiedText[$reason] }
            })
            CoverageStatus = $cov
            ScopeBucket   = $bucket
            Licensed      = $licensed
            LicenseRequirement = [string](Get-TPObjectField -Item $def -Key 'LicenseRequirement' -Default '')
            Impact        = $(if ($null -ne $impact) { [ordered]@{ Archetype = [string]$impact.Archetype; Effort = [string]$impact.Effort; Summary = [string]$impact.Summary; Reversible = [string]$impact.Reversible } } else { $null })
        }
        if ($addToGroup) { $groups[$group].Add($item) }
        return $item
    }
    foreach ($entry in @($catalog.Controls)) { $null = & $place $entry $true }

    # ── Copilot deployment gate ──────────────────────────────────────────────
    # A technical gate over the approved blocker controls, each judged by the same
    # placement as the catalog. Asymmetric on purpose: one shortfall is "not
    # ready"; "no blockers" needs every blocker to have passed (or not apply), and
    # still never says safe, because what this assessment does not read is listed.
    $gateState = 'Approved'
    if (-not $PSBoundParameters.ContainsKey('BlockerControlIds') -or $null -eq $BlockerControlIds) {
        $stdAll = Get-TPStandards
        $BlockerControlIds = @($stdAll.CopilotReadinessBlockers)
        $gateState = [string](Get-TPObjectField -Item $stdAll -Key 'CopilotReadinessBlockersState' -Default 'NotConfigured')
    }
    $gate = [ordered]@{ Blockers = [System.Collections.Generic.List[object]]::new(); Passed = [System.Collections.Generic.List[object]]::new(); NotVerified = [System.Collections.Generic.List[object]]::new(); DoesNotApply = [System.Collections.Generic.List[object]]::new(); Invalid = [System.Collections.Generic.List[string]]::new() }
    $seenBlocker = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($bid in @($BlockerControlIds | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
        $bid = ([string]$bid).Trim()
        if (-not $seenBlocker.Add($bid)) { continue }
        if ($bid -cnotmatch '\A[A-Z]{2,8}-\d+\.\d+\z' -or -not $defs.ContainsKey($bid)) { $gate.Invalid.Add(($bid -replace '[^\x20-\x7E]', '?')); continue }
        $it = & $place ([ordered]@{ ControlId = $bid; Relationship = 'General'; Scope = ''; Explanation = ''; Reference = $null }) $false
        $row = [ordered]@{
            ControlId  = $bid
            Title      = [string]$it.Title
            Severity   = [string]$it.Severity
            State      = [string]$it.State
            Reason     = [string]$it.Reason
            ReasonText = [string]$it.ReasonText
            Why        = [string](Get-TPObjectField -Item $catalog.Readiness.BlockerReasons -Key $bid -Default '')
            Impact     = $it.Impact
            LicenseRequirement = [string]$it.LicenseRequirement
        }
        switch ([string]$it.Group) {
            'Attention' { $gate.Blockers.Add($row) }
            'Verified'  { $gate.Passed.Add($row) }
            default     { if ([string]$it.Reason -eq 'NotApplicableToTenant') { $gate.DoesNotApply.Add($row) } else { $gate.NotVerified.Add($row) } }
        }
    }
    $gateTotal = $gate.Blockers.Count + $gate.Passed.Count + $gate.NotVerified.Count + $gate.DoesNotApply.Count
    $outcome = if ($gateTotal -eq 0 -and $gate.Invalid.Count -eq 0) { 'NotConfigured' }
               elseif ($gate.Blockers.Count -gt 0) { 'BlockersFound' }
               elseif ($gate.NotVerified.Count -gt 0 -or $gate.Invalid.Count -gt 0 -or $gate.Passed.Count -eq 0) { 'NotDetermined' }
               else { 'NoBlockersInCheckedControls' }
    $gateLabel = switch ($outcome) {
        'BlockersFound'               { 'Not ready: blockers found' }
        'NoBlockersInCheckedControls' { 'No blockers found in the controls checked' }
        'NotDetermined'               { 'Cannot be determined from this assessment' }
        default                       { 'No deployment gate is approved' }
    }
    $gateSummary = switch ($outcome) {
        'BlockersFound'               { [string]::Format([cultureinfo]::InvariantCulture, '{0} of the {1} blocker control(s) were recorded as a gap or only partly in place. Resolve them before assigning Microsoft Copilot licenses.', $gate.Blockers.Count, $gateTotal) }
        'NoBlockersInCheckedControls' { [string]::Format([cultureinfo]::InvariantCulture, 'Every blocker control that applies to this tenant was recorded in place ({0} of {1}; {2} do not apply). This covers only the controls checked: the items listed as not checked, the organizational decisions and anything changed since the assessment date are outside it.', $gate.Passed.Count, $gateTotal, $gate.DoesNotApply.Count) }
        'NotDetermined'               { [string]::Format([cultureinfo]::InvariantCulture, 'No blocker control was recorded as a shortfall, but {0} of the {1} produced no verdict, so the gate is neither passed nor failed. A missing verdict is never counted as a pass.', ($gate.NotVerified.Count + $gate.Invalid.Count), ($gateTotal + $gate.Invalid.Count)) }
        default                       { switch ($gateState) {
            'Proposed'   { 'A list of blocker controls is proposed but has no recorded approval (Config/tp-standards.json, CopilotReadinessBlockers: ApprovedBy and ApprovedDate), so this review prints no deployment verdict.' }
            'Unreadable' { 'The standards file (Config/tp-standards.json) is missing or could not be read, so no blocker list was loaded and this review prints no deployment verdict.' }
            default      { 'No list of blocker controls is approved (Config/tp-standards.json, CopilotReadinessBlockers), so this review prints no deployment verdict.' }
        } }
    }
    $readiness = [ordered]@{
        Outcome      = $outcome
        GateState    = $gateState
        Label        = $gateLabel
        Summary      = $gateSummary
        Statement    = 'This is a technical gate over the Microsoft 365 settings listed here. It makes no safety determination about deploying Microsoft Copilot, and it does not replace the organizational decisions in section 4.'
        Basis        = [string]$catalog.Readiness.Basis
        Total        = $gateTotal
        Blockers     = @($gate.Blockers | Sort-Object @{ Expression = { $sevRank[[string]$_.Severity] ?? 9 } }, ControlId)
        Passed       = @($gate.Passed | Sort-Object ControlId)
        NotVerified  = @($gate.NotVerified | Sort-Object ControlId)
        DoesNotApply = @($gate.DoesNotApply | Sort-Object ControlId)
        InvalidIds   = @($gate.Invalid)
        NotChecked   = @($catalog.Readiness.NotChecked)
        Sources      = @($catalog.Readiness.Sources)
    }
    $users = @(foreach ($uf in @($UserFacts | Where-Object { $null -ne $_ })) { Get-TPAiUseUserReadiness -UserFacts $uf -NotChecked @($catalog.Readiness.UserNotChecked) })

    # Observations: PPL-3.3 and any other catalog observation, never a safeguard.
    $copilotRaw = Get-TPObjectField -Item $Facts -Key 'Copilot' -Default $null
    $lic = Get-TPCopilotLicensingState -Raw $copilotRaw
    foreach ($obs in @($catalog.Observations)) {
        $cid = [string]$obs.ControlId
        $def = $defs[$cid]
        $f = $byControl[$cid]
        $state = if ($null -ne $f) { [string](Get-TPObjectField -Item $f -Key 'State' -Default '') } else { 'NoFinding' }
        $ratio = Get-TPObjectField -Item $lic -Key 'Ratio' -Default $null
        $share = if ([bool](Get-TPObjectField -Item $ratio -Key 'Available' -Default $false)) {
            [string]::Format([cultureinfo]::InvariantCulture, '{0} of {1} enabled member accounts hold a Copilot seat', [int]$ratio.Numerator, [int]$ratio.Denominator)
        } else {
            switch ([string](Get-TPObjectField -Item $ratio -Key 'Reason' -Default '')) {
                'UsersNotComplete'          { 'The share was not established: the user enumeration did not complete.' }
                'AssignmentsNotEstablished' { 'The share was not established: the seat holders were not counted from a complete enumeration.' }
                'ZeroDenominator'           { 'The share was not established: the complete enumeration counted no enabled member account.' }
                'LicensingNotCollected'     { 'The share was not established: the subscription list was not read.' }
                'NoRecognizedSku'           { 'No share: the subscription list holds no SKU this tool recognizes as Microsoft Copilot.' }
                'StatusNotRecorded'         { 'The share was not established: this results file does not record whether the reads completed.' }
                default                     { 'The share was not established in this assessment.' }
            }
        }
        $groups.Observed.Add([ordered]@{
            ControlId    = $cid
            Title        = [string](Get-TPObjectField -Item $def -Key 'Title' -Default $cid)
            Severity     = [string](Get-TPObjectField -Item $def -Key 'Severity' -Default '')
            Relationship = 'AiSpecific'
            Scope        = 'Microsoft Copilot seat assignment share'
            Explanation  = [string]$obs.Why
            Reference    = $null
            State        = $state
            Group        = 'Observed'
            Reason       = 'Observation'
            ReasonText   = $share
            CoverageStatus = ''
            ScopeBucket  = (& $bucketOf $cid)
            Licensed     = $null
            LicenseRequirement = ''
            Impact       = $null
        })
    }

    # ── Observed configuration ───────────────────────────────────────────────
    $ms = Get-TPNestedProperty -Object $copilotRaw -Path 'Data.LicensingMeasurements' -Default $null
    $measure = { param([string] $key, [string] $kind, [string] $label, [string] $note)
        $m = Get-TPObjectField -Item $ms -Key $key -Default $null
        New-TPAiUseCount -Kind $kind -Label $label -Value (Get-TPObjectField -Item $m -Key 'Value' -Default $null) -Completeness ([string](Get-TPObjectField -Item $m -Key 'Completeness' -Default 'NotRead')) -Note $note
    }
    $assignmentText = switch ([string]$lic.Assignment) {
        'Assigned'     {
            if ($null -ne $lic.AssignedCount -and $lic.AssignedCountComplete) { [string]::Format([cultureinfo]::InvariantCulture, 'Copilot seats are assigned to {0} account(s).', [int]$lic.AssignedCount) }
            elseif ($null -ne $lic.AssignedCount -and [string]$lic.Basis -eq 'Legacy') { [string]::Format([cultureinfo]::InvariantCulture, 'An earlier run recorded Copilot seats assigned to {0} account(s); whether that count was complete is not recorded.', [int]$lic.AssignedCount) }
            elseif ($null -ne $lic.AssignedCount) { [string]::Format([cultureinfo]::InvariantCulture, 'Copilot seats are assigned to at least {0} account(s); the user enumeration did not complete.', [int]$lic.AssignedCount) }
            else { 'Copilot seats are assigned; the number of accounts holding them was not established.' }
        }
        'NoneAssigned' { 'A recognized Copilot subscription is present and no seat is assigned. This does not show that AI tools are unused.' }
        default        {
            switch ([string]$lic.Reason) {
                'NoRecognizedSku'       { 'The subscription list was read and holds no SKU this tool recognizes as Microsoft Copilot.' }
                'LicensingNotCollected' { 'The subscription list was not read, so whether any Copilot seat exists is unknown.' }
                'StatusNotRecorded'     { 'This results file does not record whether the subscription list was read, so the seat count is unknown.' }
                'MeasurementsDisagree'  { 'The readings disagree: the complete user enumeration found no account holding a seat while the subscriptions report consumed seats. Neither answer is established.' }
                'NoData'                { 'The Copilot collector did not run in this assessment.' }
                default                 { 'Whether any Copilot seat is assigned could not be determined from this assessment.' }
            }
        }
    }
    $observed = [ordered]@{
        Entitlement = @(
            (& $entitlement 'M365 Copilot add-on license' 'Microsoft Copilot (paid add-on)'),
            (& $entitlement 'Power Platform + Copilot Studio license' 'Copilot Studio')
        )
        LicensingRead  = $licenseRead
        Copilot        = [ordered]@{
            Basis              = [string]$lic.Basis
            LicensingRead      = [string]$lic.LicensingRead
            UsersRead          = [string]$lic.UsersRead
            RecognizedSku      = [string]$lic.RecognizedSku
            Assignment         = [string]$lic.Assignment
            AssignmentEvidence = [string]$lic.AssignmentEvidence
            Reason             = [string]$lic.Reason
            Summary            = $assignmentText
            Counts             = @(
                (& $measure 'PurchasedSeats' 'PurchasedCapacity' 'Copilot seats purchased' 'Capacity on the recognized subscriptions; not assignments and not usage.'),
                (& $measure 'SkuConsumedUnits' 'SkuAssignments' 'Seat assignments the subscriptions report' 'Summed over the recognized subscriptions; an account holding two counts twice.'),
                (& $measure 'AssignedUsers' 'UniqueAssignedAccounts' 'Distinct accounts holding a seat' 'From the user enumeration, each account once; guests and disabled accounts included.'),
                (& $measure 'AssignedEnabledMembers' 'UniqueAssignedAccounts' 'Enabled member accounts holding a seat' 'From the user enumeration, each account once.'),
                (& $measure 'EnabledMembers' 'EnumeratedAccounts' 'Enabled member accounts' 'From the user enumeration, each account once.')
            )
        }
        CopilotStudio  = (Get-TPAiUseCopilotStudioSummary -Summary (Get-TPObjectField -Item $Facts -Key 'CopilotStudio' -Default $null))
        Statements     = [ordered]@{
            Usage   = 'Configuration and licensing are not usage. This review does not measure whether anyone uses an AI tool, and it does not detect AI tools outside Microsoft 365.'
            Chat    = (Get-TPCopilotChatEligibilityNote)
            AddOn   = 'No paid Copilot add-on detected does not establish that AI is unavailable or unused.'
            Agents  = 'Agents, connectors and third-party AI tools follow their own terms and access models; nothing here assumes they match Copilot''s.'
        }
    }

    # ── Organizational review areas and evidence gaps ────────────────────────
    $organizational = @(foreach ($area in @($catalog.Organizational)) {
        $wording = if ($Hipaa -and $area.HipaaWording) { [string]$area.HipaaWording } elseif ($area.GeneralWording) { [string]$area.GeneralWording } else { [string]$area.Question }
        [ordered]@{
            Id             = [string]$area.Id
            Area           = [string]$area.Area
            Question       = [string]$area.Question
            Wording        = $wording
            EvidenceType   = [string]$area.EvidenceType
            SuggestedRoles = @($area.SuggestedRoles)
            Evidence       = 'Not recorded in this assessment'
            Status         = 'NotRecorded'
        }
    })
    $gapCounts = [ordered]@{}
    foreach ($it in $groups.NotVerified) { $r = [string]$it.Reason; if (-not $gapCounts.Contains($r)) { $gapCounts[$r] = 0 }; $gapCounts[$r]++ }

    # ── Next steps ───────────────────────────────────────────────────────────
    $steps = [ordered]@{ CurrentCapabilities = [System.Collections.Generic.List[object]]::new(); ClientDecisions = [System.Collections.Generic.List[object]]::new(); AdditionalCollection = [System.Collections.Generic.List[object]]::new(); LicensingOrProjects = [System.Collections.Generic.List[object]]::new() }
    $attention = @($groups.Attention | Sort-Object @{ Expression = { $sevRank[[string]$_.Severity] ?? 9 } }, ControlId)
    foreach ($it in $attention) {
        $impact = $it.Impact
        $effort = if ($null -ne $impact -and $impact.Effort) { [string]$impact.Effort } else { 'Operational impact not documented' }
        $summary = if ($null -ne $impact -and $impact.Summary) { [string]$impact.Summary } else { 'Operational impact not documented.' }
        $licensed = $it.Licensed
        $step = [ordered]@{
            Kind              = 'Control'
            ControlId         = [string]$it.ControlId
            Title             = [string]$it.Title
            Severity          = [string]$it.Severity
            Relationship      = [string]$it.Relationship
            EvidenceBasis     = "Recorded $($it.State) in this assessment ($($it.ControlId))."
            ResponsibleRole   = 'Security/IT administrator (suggested)'
            Dependency        = ''
            OperationalImpact = $summary
            Effort            = $effort
            Verification      = "A later full assessment records $($it.ControlId) as Satisfied."
        }
        if ($licensed -eq $false) {
            $step.Dependency = "License: $($it.LicenseRequirement)"
            $steps.LicensingOrProjects.Add($step)
        } elseif ($null -eq $licensed -and -not $licenseRead -and $it.LicenseRequirement -and $it.LicenseRequirement -notmatch '^Included') {
            $step.Dependency = "License not confirmed (licensing was not read): $($it.LicenseRequirement)"
            $steps.LicensingOrProjects.Add($step)
        } else {
            $track = Get-TPRemediationTrack -Licensed $true -Impact $impact
            $step.Dependency = if ($track -eq 'Do now') { 'None recorded' } else { 'Change planning: see the operational impact' }
            $steps.CurrentCapabilities.Add($step)
        }
    }
    foreach ($area in $organizational) {
        $steps.ClientDecisions.Add([ordered]@{
            Kind              = 'Decision'
            ControlId         = ''
            Title             = [string]$area.Area
            Severity          = ''
            Relationship      = ''
            EvidenceBasis     = 'Not recorded in this assessment.'
            ResponsibleRole   = (@($area.SuggestedRoles) -join ', ') + ' (suggested)'
            Dependency        = [string]$area.EvidenceType
            OperationalImpact = 'A decision and a record; no tenant change.'
            Effort            = 'Review only'
            Verification      = 'The decision or document is recorded and named in the next review.'
        })
    }
    foreach ($it in @($groups.NotVerified | Sort-Object Reason, ControlId)) {
        $reason = [string]$it.Reason
        if ($reason -in @('NotApplicableToTenant')) { continue }
        $dependency = switch ($reason) {
            'LicenseNotHeld'      { "License: $($it.LicenseRequirement)" }
            'ManualReview'        { 'A manual review by the administrator' }
            'StandardNotApproved' { 'An approved standard in Config/tp-standards.json' }
            'SkippedByOperator'   { 'A run without the -Skip flag for this workload' }
            default               { 'A run in which this read completes' }
        }
        $step = [ordered]@{
            Kind              = 'Collection'
            ControlId         = [string]$it.ControlId
            Title             = [string]$it.Title
            Severity          = [string]$it.Severity
            Relationship      = [string]$it.Relationship
            EvidenceBasis     = [string]$it.ReasonText
            ResponsibleRole   = 'Security/IT administrator (suggested)'
            Dependency        = $dependency
            OperationalImpact = 'Collection only; no tenant change.'
            Effort            = 'Review only'
            Verification      = "A later full assessment records a verdict for $($it.ControlId)."
        }
        if ($reason -eq 'LicenseNotHeld') { $steps.LicensingOrProjects.Add($step) } else { $steps.AdditionalCollection.Add($step) }
    }

    $counts = [ordered]@{}
    foreach ($k in $names.Keys) { $counts[$k] = $groups[$k].Count }
    $catalogTotal = @($catalog.Controls).Count + @($catalog.Observations).Count
    $time = ConvertTo-TPUtcDateTime (Get-TPObjectField -Item $Metadata -Key 'AssessmentTime' -Default $null)
    $client = if ($ClientName) { $ClientName } else { 'Your organization' }
    $sortRel = { param($list) @($list | Sort-Object @{ Expression = { switch ($_.Relationship) { 'AiSpecific' { 0 } 'DirectAccess' { 1 } 'SupportingGovernance' { 2 } default { 3 } } } }, @{ Expression = { $sevRank[[string]$_.Severity] ?? 9 } }, ControlId) }

    return [ordered]@{
        Available        = $true
        Refused          = $false
        Note             = ''
        ClientName       = $client
        PreparedBy       = $PreparedBy
        Hipaa            = [bool]$Hipaa
        AssessedAt       = $(if ($null -ne $time) { $time.ToString('MMMM d, yyyy', [cultureinfo]::InvariantCulture) } else { 'Not recorded' })
        AssessmentTimeUtc = $(if ($null -ne $time) { $time.ToString('o', [cultureinfo]::InvariantCulture) } else { '' })
        ToolVersion      = [string](Get-TPObjectField -Item $Metadata -Key 'ToolVersion' -Default '')
        CatalogVersion   = [string]$catalog.Version
        VendorFactsRetrieved = [string]$catalog.VendorFactsRetrieved
        CatalogControls  = $catalogTotal
        ControlsJsonTotal = [int]$catalog.ControlsJsonTotal
        RunScope         = $runScope
        Counts           = $counts
        GroupNames       = $names
        Relationships    = $catalog.Relationships
        Groups           = [ordered]@{
            Observed    = @($groups.Observed)
            Verified    = @(& $sortRel $groups.Verified)
            Attention   = @(& $sortRel $groups.Attention)
            Attested    = @(& $sortRel $groups.Attested)
            NotVerified = @(& $sortRel $groups.NotVerified)
        }
        Readiness        = $readiness
        Users            = $users
        Observed         = $observed
        Organizational   = $organizational
        EvidenceGaps     = $gapCounts
        NextSteps        = [ordered]@{
            CurrentCapabilities  = @($steps.CurrentCapabilities)
            ClientDecisions      = @($steps.ClientDecisions)
            AdditionalCollection = @($steps.AdditionalCollection)
            LicensingOrProjects  = @($steps.LicensingOrProjects)
        }
        VendorFacts      = @($catalog.VendorFacts)
        Reconciliation   = [ordered]@{
            FindingsSupplied   = @($Findings).Count
            FindingsKept       = $kept.Count
            FindingsDropped    = @($dropped).Count
            ControlsWithFinding = $byControl.Count
            DuplicateFindingsCollapsed = ($kept.Count - $byControl.Count)
        }
        Statements       = [ordered]@{
            Purpose  = "This review shows how $client's Microsoft 365 configuration stood in relation to AI use of its data on the date shown: what the assessment observed, which recorded settings support that use, which need attention, what the organization itself has to decide and record, and what to do next. Every technical statement comes from the saved assessment results; nothing was collected or re-evaluated to write it."
            NotThis  = 'It is not an AI risk assessment, not a determination of compliance with any law, regulation or standard, and not a statement that AI use is safe, approved or governed. It does not measure whether anyone uses an AI tool, and it has no score.'
            Scope    = 'Covered: the Microsoft 365 settings the assessment reads that relate to Microsoft Copilot, Copilot Studio agents, and what an account can reach in SharePoint, OneDrive, Exchange and Teams. Not covered: AI tools outside Microsoft 365, Copilot usage and prompt activity, Copilot connectors, Copilot Chat administrative settings, and your written policies.'
            Dates    = "Assessment date: $(if ($null -ne $time) { $time.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture) } else { 'not recorded' }). Vendor statements were read from Microsoft Learn on $($catalog.VendorFactsRetrieved); that is the date they were checked, not the date Microsoft published or changed them. Control mapping: catalog version $($catalog.Version), applied by the installed tool."
            Hipaa    = $(if ($Hipaa) { 'The HIPAA option was selected for this review, so the sensitive-information area uses ePHI wording. This review does not assess, verify or determine HIPAA compliance.' } else { '' })
        }
    }
}

# Counts and statuses from the Copilot Studio collector's recorded environment
# list, as read by Read-TPAiUseFacts. The actual contract (Collectors/
# PowerPlatform/Invoke-TPCollectCopilotStudio.ps1): SectionStatus.Environments
# is Collected / Failed / NotRun; each environment record carries HasDataverse,
# AgentsStatus (Collected / Truncated / Failed / NotRun), AgentCount and
# ManagedAgentCount; environments past the per-run cap are NotRun.
function Get-TPAiUseCopilotStudioSummary {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] [object] $Summary)
    $out = [ordered]@{
        Available               = $false
        ListStatus              = 'NotRecorded'
        EnvironmentsListed      = $null
        DataverseEnvironments   = $null
        EnvironmentsRead        = $null
        EnvironmentsTruncated   = $null
        EnvironmentsNotRead     = $null
        Cap                     = $null
        CapApplied              = $null
        Agents                  = (New-TPAiUseCount -Kind 'DiscoveredObjects' -Label 'Copilot Studio agents found' -Value $null)
        ManagedAgents           = (New-TPAiUseCount -Kind 'DiscoveredObjects' -Label 'Of which managed-solution agents' -Value $null)
        Summary                 = 'The Copilot Studio collector did not run in this assessment, so no agent inventory is recorded.'
    }
    if ($null -eq $Summary) { return $out }
    $out.Available = $true
    $out.ListStatus = [string](Get-TPObjectField -Item $Summary -Key 'ListStatus' -Default 'NotRecorded')
    $envs = @(Get-TPObjectField -Item $Summary -Key 'Environments' -Default @())
    $out.EnvironmentsListed = $envs.Count
    $dv = @($envs | Where-Object { [bool](Get-TPObjectField -Item $_ -Key 'HasDataverse' -Default $false) })
    $out.DataverseEnvironments = $dv.Count
    $statusOf = { param($e) [string](Get-TPObjectField -Item $e -Key 'AgentsStatus' -Default 'Unknown') }
    $out.EnvironmentsRead      = @($envs | Where-Object { (& $statusOf $_) -eq 'Collected' }).Count
    $out.EnvironmentsTruncated = @($envs | Where-Object { (& $statusOf $_) -eq 'Truncated' }).Count
    $out.EnvironmentsNotRead   = @($envs | Where-Object { (& $statusOf $_) -cnotin @('Collected', 'Truncated') }).Count
    $out.Cap = ConvertTo-TPAiUseCount (Get-TPObjectField -Item $Summary -Key 'MaxEnvironments' -Default $null)
    if ($null -ne $out.Cap) { $out.CapApplied = ($dv.Count -gt $out.Cap) }

    $readOrPart = @($envs | Where-Object { (& $statusOf $_) -cin @('Collected', 'Truncated') })
    $sumAgents = 0; $sumManaged = 0; $anyCount = $false
    foreach ($e in $readOrPart) {
        $a = ConvertTo-TPAiUseCount (Get-TPObjectField -Item $e -Key 'AgentCount' -Default $null)
        $m = ConvertTo-TPAiUseCount (Get-TPObjectField -Item $e -Key 'ManagedAgentCount' -Default $null)
        if ($null -ne $a) { $sumAgents += $a; $anyCount = $true }
        if ($null -ne $m) { $sumManaged += $m }
    }
    $complete = ($out.ListStatus -eq 'Collected') -and ($out.EnvironmentsTruncated -eq 0) -and ($out.EnvironmentsNotRead -eq 0)
    $completeness = if ($readOrPart.Count -eq 0 -or -not $anyCount) { 'NotRead' } elseif ($complete) { 'Complete' } else { 'Incomplete' }
    $note = if ($complete) { 'Every listed environment was read in full.' } elseif ($readOrPart.Count -gt 0) { 'Some environments were not read in full; this is not a tenant-wide total.' } else { 'No environment was read.' }
    $out.Agents = New-TPAiUseCount -Kind 'DiscoveredObjects' -Label 'Copilot Studio agents found' -Value $(if ($anyCount) { $sumAgents } else { $null }) -Completeness $completeness -Note $note
    $out.ManagedAgents = New-TPAiUseCount -Kind 'DiscoveredObjects' -Label 'Of which managed-solution agents' -Value $(if ($anyCount) { $sumManaged } else { $null }) -Completeness $completeness -Note 'Installed from a managed solution; set aside by the agent controls.'
    $out.Summary = switch ($out.ListStatus) {
        'Collected' {
            if ($complete) { 'The environment list was read and every Dataverse environment was read in full.' }
            else { "The environment list was read; $($out.EnvironmentsTruncated) environment(s) were read in part and $($out.EnvironmentsNotRead) not at all$(if ($out.CapApplied) { ' (the per-run environment cap applied)' }). Agent counts are lower bounds, not a tenant-wide total." }
        }
        'Failed'    { 'The environment list could not be read, so the agent inventory is unknown. This does not show that no agent exists.' }
        'NotRun'    { 'The environment list was not read in this run, so the agent inventory is unknown.' }
        default     { 'This results file does not record whether the environment list was read, so completeness is unknown.' }
    }
    return $out
}

# ── Per-account readiness (only for accounts the operator names) ─────────────

function Read-TPAiUseUserFacts {
    <#
    .SYNOPSIS
        Reads, for each account the operator names, the facts the saved results
        file holds about that one account: whether it exists, is enabled and is
        a member; the part numbers of its assigned licenses; its MFA
        registration; and how many non-compliant managed devices record it as
        primary user. No other account is materialized.
    .DESCRIPTION
        Same bounds as Read-TPAiUseFacts (one JsonDocument, Get-TPRunRecordMaxBytes).
        A name is matched as a user principal name, ordinal and case-insensitive.
        Each fact carries whether its read completed, so "not found in a
        truncated list" is never "does not exist".
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $UserPrincipalName
    )
    Set-StrictMode -Version Latest

    $wanted = [System.Collections.Generic.List[string]]::new()
    foreach ($n in @($UserPrincipalName)) {
        $t = ([string]$n).Trim()
        if (-not $t) { continue }
        if ($t.Length -gt 256 -or $t -cnotmatch '\A[A-Za-z0-9._%+''#-]+@[A-Za-z0-9.-]+\z') { throw 'A user name given to the AI use review is not a user principal name.' }
        if (-not ($wanted | Where-Object { [string]::Equals($_, $t, [System.StringComparison]::OrdinalIgnoreCase) })) { $wanted.Add($t) }
    }
    if ($wanted.Count -eq 0) { return @() }
    if ($wanted.Count -gt 25) { throw 'The AI use review reads at most 25 named accounts.' }

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($item -isnot [System.IO.FileInfo]) { throw 'The results path is not a file.' }
    if ($item.Length -gt (Get-TPRunRecordMaxBytes)) { throw 'The results file is larger than this tool reads.' }

    $kinds = [System.Text.Json.JsonValueKind]
    $prop = {
        param([object] $el, [string] $name)
        if ($null -eq $el -or $el.ValueKind -ne $kinds::Object) { return $null }
        $out = [System.Text.Json.JsonElement]::new()
        if ($el.TryGetProperty($name, [ref]$out)) { return $out }
        return $null
    }
    $text = { param([object] $el) if ($null -ne $el -and $el.ValueKind -eq $kinds::String) { $el.GetString() } else { '' } }
    $bool = { param([object] $el) if ($null -eq $el) { $null } elseif ($el.ValueKind -eq $kinds::True) { $true } elseif ($el.ValueKind -eq $kinds::False) { $false } else { $null } }
    $same = { param([string] $a, [string] $b) [string]::Equals($a, $b, [System.StringComparison]::OrdinalIgnoreCase) }

    $out = [ordered]@{}
    foreach ($w in $wanted) {
        $out[$w] = [ordered]@{
            UserPrincipalName = $w
            UsersRead = 'NotRecorded'; Found = $false; AccountEnabled = $null; UserType = ''
            AssignedSkuIds = @(); SkuCatalogRead = $false; AssignedPartNumbers = @(); UnnamedLicenses = 0
            MfaRead = 'NotRecorded'; MfaFound = $false; IsMfaRegistered = $null; IsMfaCapable = $null
            DevicesRead = 'NotRecorded'; DevicesTruncated = $null; NonCompliantDevices = $null
        }
    }
    $options = [System.Text.Json.JsonDocumentOptions]::new()
    $options.MaxDepth = 256
    $stream = [System.IO.File]::Open($item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        try { $doc = [System.Text.Json.JsonDocument]::Parse($stream, $options) } catch { throw 'The results file is not valid JSON.' }
        try {
            $root = $doc.RootElement
            if ($root.ValueKind -ne $kinds::Object) { throw 'The file is not an assessment results file.' }
            if ($null -ne (& $prop $root 'DeepDives')) { throw 'That file is an incident-response output, not an assessment.' }
            $rawData = & $prop $root 'RawData'

            # SKU id -> part number, from the subscription list.
            $skuNames = @{}
            $skus = & $prop (& $prop (& $prop $rawData 'AAD-Inventory') 'Data') 'SubscribedSkus'
            $skuRead = ($null -ne $skus -and $skus.ValueKind -eq $kinds::Array -and $skus.GetArrayLength() -gt 0)
            if ($skuRead) { foreach ($s in $skus.EnumerateArray()) { $id = & $text (& $prop $s 'SkuId'); $pn = & $text (& $prop $s 'SkuPartNumber'); if ($id -and $pn) { $skuNames[$id.ToLowerInvariant()] = $pn } } }

            $ud = & $prop (& $prop $rawData 'AAD-Users') 'Data'
            $ss = & $prop $ud 'SectionStatus'
            $usersStatus = & $text (& $prop $ss 'Users')
            $mfaStatus = & $text (& $prop $ss 'MFARegistration')
            $list = & $prop $ud 'Users'
            $haveUsers = ($null -ne $list -and $list.ValueKind -eq $kinds::Array)
            foreach ($w in $wanted) {
                $out[$w].UsersRead = if ($usersStatus -cin @('Collected', 'Truncated', 'Failed', 'NotRun')) { $usersStatus } elseif ($haveUsers) { 'NotRecorded' } else { 'NotRun' }
                $out[$w].MfaRead = if ($mfaStatus -cin @('Collected', 'Failed', 'NotRun')) { $mfaStatus } else { 'NotRecorded' }
                $out[$w].SkuCatalogRead = $skuRead
            }
            if ($haveUsers) {
                foreach ($u in $list.EnumerateArray()) {
                    $upn = & $text (& $prop $u 'UserPrincipalName')
                    if (-not $upn) { continue }
                    foreach ($w in $wanted) {
                        if (-not (& $same $upn $w)) { continue }
                        $rec = $out[$w]
                        $rec.Found = $true
                        $rec.AccountEnabled = & $bool (& $prop $u 'AccountEnabled')
                        $rec.UserType = & $text (& $prop $u 'UserType')
                        $ids = [System.Collections.Generic.List[string]]::new()
                        $a = & $prop $u 'AssignedSkuIds'
                        if ($null -ne $a -and $a.ValueKind -eq $kinds::Array) { foreach ($x in $a.EnumerateArray()) { $v = & $text $x; if ($v) { $ids.Add($v) } } }
                        elseif ($null -ne $a -and $a.ValueKind -eq $kinds::String) { $ids.Add($a.GetString()) }
                        $rec.AssignedSkuIds = $ids.ToArray()
                        $named = @($ids | ForEach-Object { $skuNames[$_.ToLowerInvariant()] } | Where-Object { $_ })
                        $rec.AssignedPartNumbers = @($named | Sort-Object -Unique)
                        $rec.UnnamedLicenses = $ids.Count - $named.Count
                    }
                }
            }
            $reg = & $prop (& $prop $ud 'MFARegistration') 'RegistrationDetails'
            if ($null -ne $reg -and $reg.ValueKind -eq $kinds::Array) {
                foreach ($r in $reg.EnumerateArray()) {
                    $upn = & $text (& $prop $r 'UserPrincipalName')
                    if (-not $upn) { continue }
                    foreach ($w in $wanted) {
                        if (-not (& $same $upn $w)) { continue }
                        $out[$w].MfaFound = $true
                        $out[$w].IsMfaRegistered = & $bool (& $prop $r 'IsMfaRegistered')
                        $out[$w].IsMfaCapable = & $bool (& $prop $r 'IsMfaCapable')
                    }
                }
            }
            $dc = & $prop (& $prop $rawData 'Intune-DeviceCompliance') 'Data'
            $summary = & $prop $dc 'OSComplianceSummary'
            $devStatus = & $text (& $prop (& $prop $dc 'SectionStatus') 'OSComplianceSummary')
            $nc = & $prop $summary 'NonCompliantDevices'
            $haveNc = ($null -ne $nc -and $nc.ValueKind -eq $kinds::Array)
            $trunc = & $bool (& $prop $summary 'NonCompliantTruncated')
            foreach ($w in $wanted) {
                $out[$w].DevicesRead = if ($devStatus -ceq 'Failed') { 'Failed' } elseif ($haveNc) { 'Collected' } else { 'NotRecorded' }
                $out[$w].DevicesTruncated = $trunc
                if ($haveNc -and $devStatus -cne 'Failed') { $out[$w].NonCompliantDevices = 0 }
            }
            if ($haveNc -and $devStatus -cne 'Failed') {
                foreach ($dv in $nc.EnumerateArray()) {
                    $upn = & $text (& $prop $dv 'UserPrincipalName')
                    foreach ($w in $wanted) { if ($upn -and (& $same $upn $w)) { $out[$w].NonCompliantDevices++ } }
                }
            }
        } finally { $doc.Dispose() }
    } finally { $stream.Dispose() }
    return @($out.Values)
}

# One named account's requirements for Microsoft Copilot, from the facts above.
# Row Status: Met / NotMet / Confirm (a fact was read and a person has to judge
# it) / NotEstablished (the read was incomplete or does not record it) / NotRead.
function Get-TPAiUseUserReadiness {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([Parameter(Mandatory)] [object] $UserFacts, [AllowEmptyCollection()] [object[]] $NotChecked = @())
    $f = $UserFacts
    $get = { param([string] $k, $d = $null) Get-TPObjectField -Item $f -Key $k -Default $d }
    $rows = [System.Collections.Generic.List[object]]::new()
    $row = { param([string] $req, [string] $status, [string] $detail, [string] $toAdd = '') $rows.Add([ordered]@{ Requirement = $req; Status = $status; Detail = $detail; ToAdd = $toAdd }) }
    $usersRead = [string](& $get 'UsersRead' 'NotRecorded')
    $found = [bool](& $get 'Found' $false)
    $copilotRx = Get-TPCopilotSkuPartNumberPattern

    if (-not $found) {
        $why = switch ($usersRead) {
            'Collected' { 'The complete user list in this assessment holds no account with this name.' }
            'Truncated' { 'The user list was cut short at its page limit and this account is not in the part that was read. That does not show the account is absent.' }
            'Failed'    { 'The user list could not be read in this assessment.' }
            default     { 'This results file does not record a completed user list, so the account could not be looked up.' }
        }
        & $row 'Work account in Microsoft Entra ID' $(if ($usersRead -eq 'Collected') { 'NotMet' } else { 'NotEstablished' }) $why $(if ($usersRead -eq 'Collected') { 'Create or correct the account name, then run a full assessment.' } else { 'Run a full assessment in which the user list completes.' })
    } else {
        $enabled = & $get 'AccountEnabled'
        $type = [string](& $get 'UserType' '')
        if ($type -eq 'Guest') { & $row 'Work account in Microsoft Entra ID' 'NotMet' 'The account is a guest. Microsoft states that guest accounts are not licensed to use Copilot.' 'Use a member account of this organization.' }
        elseif ($enabled -eq $false) { & $row 'Work account in Microsoft Entra ID' 'NotMet' 'The account exists and sign-in is blocked.' 'Enable sign-in for the account.' }
        elseif ($enabled -eq $true) { & $row 'Work account in Microsoft Entra ID' 'Met' 'A member account with sign-in enabled.' }
        else { & $row 'Work account in Microsoft Entra ID' 'NotEstablished' 'The account exists; whether sign-in is enabled is not recorded.' 'Confirm the account is enabled.' }

        $ids = @(& $get 'AssignedSkuIds' @())
        $parts = @(& $get 'AssignedPartNumbers' @())
        $unnamed = [int](& $get 'UnnamedLicenses' 0)
        $copilot = @($parts | Where-Object { $_ -match $copilotRx })
        $base = @($parts | Where-Object { $_ -notmatch $copilotRx })
        $catalogRead = [bool](& $get 'SkuCatalogRead' $false)
        $suffix = if ($unnamed -gt 0) { " $unnamed assigned license(s) could not be named from the recorded subscription list." } else { '' }
        if ($ids.Count -eq 0) {
            & $row 'Eligible Microsoft 365 base license' 'NotMet' 'No license is assigned to this account.' 'Assign a base license that Microsoft lists as a prerequisite for Microsoft Copilot.'
            & $row 'Microsoft Copilot license' 'NotMet' 'No license is assigned to this account.' 'Purchase and assign a Microsoft Copilot license.'
        } elseif (-not $catalogRead) {
            & $row 'Eligible Microsoft 365 base license' 'NotEstablished' "$($ids.Count) license(s) are assigned; the subscription list was not read, so they cannot be named." 'Run a full assessment in which the subscription list is read.'
            & $row 'Microsoft Copilot license' 'NotEstablished' 'The subscription list was not read, so whether one of the assigned licenses is Microsoft Copilot is unknown.' 'Run a full assessment in which the subscription list is read.'
        } else {
            if ($base.Count -gt 0) { & $row 'Eligible Microsoft 365 base license' 'Confirm' ("Assigned: $($base -join ', ').$suffix This review does not judge eligibility; compare with Microsoft's list of prerequisite licenses.") "Confirm one of these is on Microsoft's list of eligible prerequisite licenses." }
            elseif ($unnamed -gt 0) { & $row 'Eligible Microsoft 365 base license' 'NotEstablished' ("No named base license.$suffix").Trim() 'Confirm the assigned licenses in the Microsoft 365 admin center.' }
            else { & $row 'Eligible Microsoft 365 base license' 'NotMet' 'Only a Microsoft Copilot license is assigned; no base license was found.' 'Assign a base license that Microsoft lists as a prerequisite for Microsoft Copilot.' }
            if ($copilot.Count -gt 0) { & $row 'Microsoft Copilot license' 'Met' "Assigned: $($copilot -join ', ')." }
            elseif ($unnamed -gt 0) { & $row 'Microsoft Copilot license' 'NotEstablished' ("No assigned license is recognized as Microsoft Copilot.$suffix") 'Confirm the assigned licenses in the Microsoft 365 admin center.' }
            else { & $row 'Microsoft Copilot license' 'NotMet' 'No assigned license is recognized as Microsoft Copilot.' 'Purchase and assign a Microsoft Copilot license.' }
        }

        $mfaRead = [string](& $get 'MfaRead' 'NotRecorded')
        if ([bool](& $get 'MfaFound' $false)) {
            $capable = & $get 'IsMfaCapable'; $registered = & $get 'IsMfaRegistered'
            if ($capable -eq $true) { & $row 'Multifactor authentication registered' 'Met' 'The account has a usable multifactor method registered. Whether a policy requires it at sign-in is the tenant control AAD-1.2.' }
            elseif ($registered -eq $true) { & $row 'Multifactor authentication registered' 'NotMet' 'A method is registered, but Microsoft does not report the account as able to complete multifactor authentication.' 'Have the user register a method they can use, such as Microsoft Authenticator.' }
            else { & $row 'Multifactor authentication registered' 'NotMet' 'No multifactor method is registered for this account.' 'Have the user register a multifactor method before the license is assigned.' }
        } else {
            $why = if ($mfaRead -eq 'Collected') { 'The registration report was read and has no row for this account.' } elseif ($mfaRead -eq 'Failed') { 'The registration report could not be read (it needs Microsoft Entra ID P1 or P2).' } else { 'This results file does not record the registration report.' }
            & $row 'Multifactor authentication registered' 'NotEstablished' $why 'Confirm the account''s registered methods in the Microsoft Entra admin center.'
        }

        $devRead = [string](& $get 'DevicesRead' 'NotRecorded')
        $nc = & $get 'NonCompliantDevices'
        if ($devRead -eq 'Collected' -and $null -ne $nc -and [int]$nc -gt 0) { & $row 'Managed device compliant' 'NotMet' "$([int]$nc) managed device(s) recorded for this account are not compliant." 'Bring the device into compliance in Intune before the license is assigned.' }
        elseif ($devRead -eq 'Collected') { & $row 'Managed device compliant' 'NotEstablished' ("No non-compliant managed device is recorded for this account$(if ((& $get 'DevicesTruncated') -eq $true) { ' in the part of the device list that was read' }). The assessment keeps only non-compliant devices by account, so whether this person has a managed, compliant device is not shown.") 'Confirm the device this person will use is enrolled and compliant.' }
        else { & $row 'Managed device compliant' 'NotRead' 'The Intune device list was not read in this assessment.' 'Confirm the device this person will use is enrolled and compliant.' }
    }
    $rowList = $rows.ToArray()
    return [ordered]@{
        UserPrincipalName = [string](& $get 'UserPrincipalName' '')
        Found             = $found
        Rows              = $rowList
        ToAdd             = @($rowList | Where-Object { $_.Status -eq 'NotMet' } | ForEach-Object { [string]$_.ToAdd })
        ToConfirm         = @($rowList | Where-Object { $_.Status -cin @('Confirm', 'NotEstablished', 'NotRead') } | ForEach-Object { [string]$_.ToAdd } | Where-Object { $_ })
        NotChecked        = @($NotChecked)
    }
}
