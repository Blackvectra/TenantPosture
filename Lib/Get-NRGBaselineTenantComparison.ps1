#Requires -Version 7.0
#
# Get-NRGBaselineTenantComparison.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Compare two DIFFERENT tenants against the NRG Security Baseline,
#   offline, from the BaselineCompliance blocks of two results JSON files
#   (for example a prospective client against an existing client). It answers
#   one question: on the controls both runs could verify, do the two tenants
#   sit in the same place?
#
#   This is a VIEW, like Get-NRGBaseline / Get-NRGAssessmentScope: it emits no
#   finding, changes none, moves no score, and reads no module state (no
#   Get-NRGFindings, Get-NRGRawData or Get-NRGCoverage). Its only inputs are
#   the two parsed results objects handed to it. It connects to nothing; that
#   is enforced statically by NRG.TenantComparison.Tests.ps1.
#
#   It is NOT the run-over-run comparison. Get-NRGBaselineRegressions and
#   Publish-NRGDeltaReport compare one tenant with itself over time and refuse
#   a baseline from a different tenant on purpose; that guard is untouched.
#
# Data consumed: two results JSON objects: BaselineCompliance (Controls,
#   BaselineVersion, TargetTier, AsOf, EvidenceCoverage, EffectivenessCoverage),
#   Metadata (TenantDomain, TenantId, AssessmentTime), Connections (tenant
#   identity fallback), RawData.AAD-Inventory.Data.SubscribedSkus (licensing).
# Data set: none. Graph scopes / cmdlets required: none.
#
# Rules (each pinned by NRG.TenantComparison.Tests.ps1):
#   - Any tier may be compared. Only controls required at BOTH tenants are
#     compared; a Minimum run against a Standard run compares the Minimum
#     controls and lists the rest, with the tier that required them.
#   - A control is classified from ObservedState AND ReasonCode, never from
#     the display status: BothSatisfied, BothFailed, DiffersASatisfied,
#     DiffersBSatisfied, or NotComparable. NotComparable covers NotVerified,
#     NotApplicable, LicenseBlocked and ThirdPartyHandled on either side (and
#     a state that contradicts its own reason code), and is NEVER a match.
#   - The two definitions must be established as the same: the same baseline
#     version, or an identical expected state on both rows. A row with no
#     expected state under a different or unknown version is NotComparable
#     (cause DefinitionNotEstablished); different expected states are
#     DefinitionDiffers and not compared.
#   - The headline is a count of controls both tenants verified. There is no
#     score, no ranking and no "compliant".
#   - An approved exception is a disposition shown beside the observed state;
#     it never changes it.
#   - The model carries only control IDs, titles, states, reason codes, tiers,
#     versions, dates and counts. It never carries finding Detail, Reason,
#     exception text, UPNs or object names. With -Anonymize it carries no
#     tenant name, domain or ID either, and any identifier found inside a
#     rendered string is replaced.
#   - Every read goes through Get-NRGObjectField / Get-NRGNestedProperty, so a
#     results file written before a field existed replays without throwing.

$script:NRGComparisonTierOrder = @('Minimum', 'Standard', 'Hardened')

# A baseline control ID: the tool's AAD-1.1 shape, or the manual VM-VERIFY-01
# shape. Strict on purpose: the ID is copied into every output, and a
# permissive pattern would let a hostile file smuggle a tenant name through it.
$script:NRGComparisonControlIdPattern = '^[A-Z]{2,8}-(?:\d+\.\d+|[A-Z]+-\d+)$'

function ConvertTo-NRGComparisonText {
    <#
    .SYNOPSIS
        Turns an untrusted value into one safe line of text: no control
        characters, collapsed whitespace, bounded length, and (when a scrubber
        is supplied) every tenant identifier replaced.
    .DESCRIPTION
        Objects, arrays and dictionaries are never stringified: they return an
        empty string, so a results file cannot push a type name or a nested
        structure into a report.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [AllowNull()] [object] $Value,
        [int] $MaxLength = 200,
        [AllowNull()] [regex] $Scrubber
    )
    Set-StrictMode -Version Latest
    if ($null -eq $Value) { return '' }
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { return '' }
    if ($Value -isnot [string] -and $Value -isnot [ValueType]) { return '' }
    $t = [string]$Value
    $t = [regex]::Replace($t, '[\x00-\x1F\x7F\u0085  ]+', ' ')
    $t = ([regex]::Replace($t, '\s+', ' ')).Trim()
    if ($null -ne $Scrubber) { $t = $Scrubber.Replace($t, '[tenant]') }
    if ($t.Length -gt $MaxLength) { $t = $t.Substring(0, $MaxLength - 1).TrimEnd() + '…' }
    return $t
}

function New-NRGComparisonScrubber {
    <#
    .SYNOPSIS
        One regex that matches every identifier of the two tenants: full
        domains and IDs anywhere, and a domain's first label only as a whole
        word, so a short label cannot mangle unrelated words.
    #>
    [CmdletBinding()]
    [OutputType([regex])]
    param(
        [AllowNull()] [string[]] $Identifiers
    )
    Set-StrictMode -Version Latest
    $parts = [System.Collections.Generic.List[object]]::new()
    $seen  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($raw in @($Identifiers)) {
        if ([string]::IsNullOrWhiteSpace($raw)) { continue }
        $id = $raw.Trim()
        if ($id.Length -lt 3) { continue }
        if ($seen.Add($id)) { $parts.Add([pscustomobject]@{ Weight = $id.Length; Pattern = [regex]::Escape($id) }) }
        # The first label of a domain ("contoso" of contoso.onmicrosoft.com).
        if ($id -match '^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9-]+)+$') {
            $label = ($id -split '\.')[0]
            if ($label.Length -ge 3 -and $seen.Add("label:$label")) {
                $parts.Add([pscustomobject]@{ Weight = $label.Length; Pattern = '(?<![A-Za-z0-9])' + [regex]::Escape($label) + '(?![A-Za-z0-9])' })
            }
        }
    }
    if ($parts.Count -eq 0) { return $null }
    # Longest IDENTIFIER first (not longest pattern: a label's lookaround
    # pattern is longer than a short domain's), so a full domain is replaced
    # whole instead of leaving ".onmicrosoft.com" behind its first label.
    $ordered = @($parts | Sort-Object -Property Weight -Descending | ForEach-Object { $_.Pattern })
    return [regex]::new(($ordered -join '|'), ([System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant))
}

function ConvertTo-NRGComparisonInt {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)
    Set-StrictMode -Version Latest
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool]) { return $null }
    $n = 0
    if ($Value -is [int] -or $Value -is [long]) { $n = [long]$Value }
    elseif ($Value -is [double] -or $Value -is [decimal]) {
        if ([math]::Floor([double]$Value) -ne [double]$Value) { return $null }
        $n = [long]$Value
    }
    elseif ($Value -is [string] -and $Value -match '^\d{1,9}$') { $n = [long]$Value }
    else { return $null }
    if ($n -lt 0 -or $n -gt 1000000) { return $null }
    return [int]$n
}

function ConvertTo-NRGComparisonUtc {
    <#
    .SYNOPSIS
        A timestamp as UTC, from either a [datetime] (what ConvertFrom-Json
        produces for an ISO string) or a string, or $null when unreadable.
    #>
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)
    Set-StrictMode -Version Latest
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        $d = [datetime]$Value
        if ($d.Kind -eq [System.DateTimeKind]::Utc) { return $d }
        if ($d.Kind -eq [System.DateTimeKind]::Local) { return $d.ToUniversalTime() }
        return [datetime]::SpecifyKind($d, [System.DateTimeKind]::Utc)
    }
    if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$Value)) { return $null }
    $out = [datetime]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if ([datetime]::TryParse([string]$Value, [cultureinfo]::InvariantCulture, $styles, [ref]$out)) { return $out }
    return $null
}

function Get-NRGComparisonSideVerdict {
    <#
    .SYNOPSIS
        What one baseline row says about one control, reduced to what a
        comparison may rely on.
    .DESCRIPTION
        A row carries a verdict (Satisfied or Failed) only when ObservedState
        and ReasonCode agree and nothing says the control was not verified.
        LicenseBlocked (a constraint) and ThirdPartyHandled (attested by the
        assessor, not verified) carry no verdict, whatever else the row says.
        A state that contradicts its own reason code is Inconsistent, so a
        damaged or hand-edited file can never produce a match.
        The display status BaselineStatus is consulted only to recognize
        license blocking and an approved exception in a file that predates the
        Constraint and Disposition fields; it never supplies a verdict.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [object] $Row,
        [Parameter(Mandatory)] [System.Collections.Generic.HashSet[string]] $KnownCodes
    )
    Set-StrictMode -Version Latest
    $text = { param($k) ConvertTo-NRGComparisonText -Value (Get-NRGObjectField -Item $Row -Key $k -Default '') -MaxLength 80 }

    $stateRaw  = & $text 'ObservedState'
    $state     = if ($stateRaw -cin @('Satisfied', 'Failed', 'NotApplicable', 'NotVerified')) { $stateRaw } else { 'Unrecognized' }
    $constraint = & $text 'Constraint'
    $baseStatus = & $text 'BaselineStatus'
    $codeRaw   = & $text 'ReasonCode'
    $code      = if (-not $codeRaw) { 'NotRecorded' } elseif ($KnownCodes.Contains($codeRaw)) { $codeRaw } else { 'Unrecognized' }
    $disposition = if (((& $text 'Disposition') -ceq 'ApprovedException') -or ($baseStatus -ceq 'ApprovedException')) { 'ApprovedException' } else { 'Normal' }
    $licenseBlocked = ($constraint -ceq 'LicenseBlocked') -or ($baseStatus -ceq 'LicenseBlocked')

    $verdict = 'None'
    $label   = 'Unrecognized'
    if ($licenseBlocked) {
        $label = 'LicenseBlocked'
    } elseif ($code -ceq 'ThirdPartyHandled') {
        # Attested by the assessor, not verified. Only a NotApplicable row may
        # carry the code; anything else contradicts it.
        $label = if ($state -ceq 'NotApplicable') { 'NotApplicable' } else { 'Inconsistent' }
    } elseif ($state -ceq 'Satisfied') {
        if ($code -cin @('Satisfied', 'NotRecorded')) { $verdict = 'Satisfied'; $label = 'Satisfied' } else { $label = 'Inconsistent' }
    } elseif ($state -ceq 'Failed') {
        if ($code -cin @('ControlFailed', 'NotRecorded')) { $verdict = 'Failed'; $label = 'Failed' } else { $label = 'Inconsistent' }
    } elseif ($state -ceq 'NotApplicable') {
        $label = 'NotApplicable'
    } elseif ($state -ceq 'NotVerified') {
        $label = 'NotVerified'
    }
    return [ordered]@{
        Verdict     = $verdict
        State       = $label
        ReasonCode  = $code
        Disposition = $disposition
    }
}

function Get-NRGComparisonCoverageLine {
    <#
    .SYNOPSIS
        One sentence from a run's EvidenceCoverage or EffectivenessCoverage
        block, or an honest "not recorded" when the file predates it.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [AllowNull()] [object] $Block,
        [Parameter(Mandatory)] [ValidateSet('Evidence', 'Effectiveness')] [string] $Kind,
        [Parameter(Mandatory)] [System.Collections.Generic.HashSet[string]] $KnownCodes
    )
    Set-StrictMode -Version Latest
    $inv = [cultureinfo]::InvariantCulture
    $cov = [ordered]@{
        Available = $false
        Line      = 'Not recorded in this results file (it predates the coverage lines).'
        Known     = $null
        Of        = $null
    }
    if ($null -eq $Block) { return $cov }

    $known = ConvertTo-NRGComparisonInt -Value (Get-NRGObjectField -Item $Block -Key 'Known' -Default $null)
    $of    = ConvertTo-NRGComparisonInt -Value (Get-NRGObjectField -Item $Block -Key $(if ($Kind -eq 'Evidence') { 'Applicable' } else { 'Required' }) -Default $null)
    if ($null -eq $known -or $null -eq $of) { return $cov }

    $pctRaw = Get-NRGObjectField -Item $Block -Key 'Percent' -Default $null
    $pct = $null
    if ($pctRaw -is [double] -or $pctRaw -is [decimal] -or $pctRaw -is [int] -or $pctRaw -is [long]) { $pct = [double]$pctRaw }
    elseif ($pctRaw -is [string]) { $p = 0.0; if ([double]::TryParse($pctRaw, [System.Globalization.NumberStyles]::Float, $inv, [ref]$p)) { $pct = $p } }
    $pctText = if ($null -ne $pct -and $pct -ge 0 -and $pct -le 100) { " ($($pct.ToString('0.#', $inv))%)" } else { '' }

    if ($Kind -eq 'Evidence') {
        $line = "$known of $of applicable controls have usable evidence$pctText"
        $lb = ConvertTo-NRGComparisonInt -Value (Get-NRGObjectField -Item $Block -Key 'LicenseBlocked' -Default $null)
        if ($null -ne $lb -and $lb -gt 0) { $line += "; $lb license blocked" }
        $gapsRaw = Get-NRGObjectField -Item $Block -Key 'Gaps' -Default $null
        $gapParts = [System.Collections.Generic.List[string]]::new()
        if ($null -ne $gapsRaw) {
            $pairs = if ($gapsRaw -is [System.Collections.IDictionary]) { @($gapsRaw.Keys | ForEach-Object { [pscustomobject]@{ Name = [string]$_; Value = $gapsRaw[$_] } }) }
                     else { @($gapsRaw.PSObject.Properties | ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; Value = $_.Value } }) }
            foreach ($pair in $pairs) {
                $n = ConvertTo-NRGComparisonInt -Value $pair.Value
                if ($null -eq $n -or $n -le 0) { continue }
                $nm = if ($KnownCodes.Contains($pair.Name)) { $pair.Name } else { 'Other' }
                $gapParts.Add("$n $nm")
            }
        }
        if ($gapParts.Count -gt 0) { $line += "; evidence not obtained: $($gapParts -join ', ')" }
        $cov.Line = "$line."
    } else {
        $cov.Line = "$known of $of required controls have effectiveness evidence$pctText."
    }
    $cov.Available = $true
    $cov.Known = $known
    $cov.Of = $of
    return $cov
}

function Get-NRGComparisonLicense {
    <#
    .SYNOPSIS
        A tenant's licensing as the baseline sees it, from the SubscribedSkus
        stored in its own results file. Unread is unread, never "none".
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] [object] $Results)
    Set-StrictMode -Version Latest
    $unread = [ordered]@{ Read = $false; TierLabel = 'Not read'; Flags = [ordered]@{} }
    $inventory = Get-NRGNestedProperty -Object $Results -Path 'RawData.AAD-Inventory' -Default $null
    if ($null -eq $inventory) { return $unread }
    $ok = Get-NRGObjectField -Item $inventory -Key 'Success' -Default $null
    if ($null -ne $ok -and $ok -isnot [bool]) { return $unread }
    if ($ok -is [bool] -and -not $ok) { return $unread }
    $skus = @(Get-NRGNestedProperty -Object $inventory -Path 'Data.SubscribedSkus' -Default @())
    if ($skus.Count -eq 0) { return $unread }
    try {
        $licProfile = Get-NRGTenantLicenseProfile -SubscribedSkus $skus
    } catch {
        Write-Verbose "Licensing could not be profiled for the comparison: $($_.Exception.Message)"
        return $unread
    }
    if ($null -eq $licProfile -or (Get-NRGObjectField -Item $licProfile -Key 'HasLicenseData' -Default $false) -ne $true) { return $unread }
    $flags = [ordered]@{}
    foreach ($def in @(
        @('HasEntraP1', 'Entra ID P1 or higher'),
        @('HasEntraP2', 'Entra ID P2'),
        @('HasIntune',  'Intune'),
        @('HasMDEP1',   'Defender for Endpoint P1 or higher'),
        @('HasMDEP2',   'Defender for Endpoint P2'),
        @('HasDfOP1',   'Defender for Office 365 P1 or higher'),
        @('HasDfOP2',   'Defender for Office 365 P2'),
        @('HasMDCA',    'Defender for Cloud Apps')
    )) {
        $flags[$def[1]] = ((Get-NRGObjectField -Item $licProfile -Key $def[0] -Default $false) -eq $true)
    }
    return [ordered]@{
        Read      = $true
        TierLabel = (ConvertTo-NRGComparisonText -Value (Get-NRGObjectField -Item $licProfile -Key 'TierLabel' -Default '') -MaxLength 120)
        Flags     = $flags
    }
}

function New-NRGComparisonSide {
    <#
    .SYNOPSIS
        Reads one results file into the facts the comparison needs: identity
        (shown or hidden), run time, tier, version, coverage, freshness,
        licensing, and a lookup of its readable baseline rows.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [ValidateSet('A', 'B')] [string] $Label,
        [AllowNull()] [object] $Results,
        [bool] $Anonymize,
        [AllowNull()] [regex] $Scrubber,
        [Parameter(Mandatory)] [System.Collections.Generic.HashSet[string]] $KnownCodes
    )
    Set-StrictMode -Version Latest
    $meta = Get-NRGObjectField -Item $Results -Key 'Metadata' -Default $null
    $conn = Get-NRGObjectField -Item $Results -Key 'Connections' -Default $null
    $bc   = Get-NRGObjectField -Item $Results -Key 'BaselineCompliance' -Default $null

    $domain = ConvertTo-NRGComparisonText -Value (Get-NRGObjectField -Item $meta -Key 'TenantDomain' -Default '') -MaxLength 253
    if (-not $domain) { $domain = ConvertTo-NRGComparisonText -Value (Get-NRGObjectField -Item $conn -Key 'TenantDomain' -Default '') -MaxLength 253 }
    $tenantId = ConvertTo-NRGComparisonText -Value (Get-NRGObjectField -Item $meta -Key 'TenantId' -Default '') -MaxLength 64
    if (-not $tenantId) { $tenantId = ConvertTo-NRGComparisonText -Value (Get-NRGObjectField -Item $conn -Key 'TenantId' -Default '') -MaxLength 64 }
    $domainOk = ($domain -match '^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$')

    $name = if ($Anonymize) { "Tenant $Label" }
            elseif ($domainOk) { $domain }
            else { "Tenant $Label (domain not recorded)" }
    $fileTag = $Label
    if (-not $Anonymize -and $domainOk) {
        $first = ((($domain -split '\.')[0]) -replace '[^a-zA-Z0-9-]', '')
        if ($first.Length -gt 40) { $first = $first.Substring(0, 40) }
        if ($first) { $fileTag = $first }
    }

    # ── Run time: the assessment time, else the compliance view's own AsOf ──
    $runUtc = ConvertTo-NRGComparisonUtc -Value (Get-NRGObjectField -Item $meta -Key 'AssessmentTime' -Default $null)
    if ($null -eq $runUtc) { $runUtc = ConvertTo-NRGComparisonUtc -Value (Get-NRGObjectField -Item $bc -Key 'AsOf' -Default $null) }

    # Scrubbed before the shape check: a scrubbed value starts with "[" and so
    # fails it and reads as "not recorded", never as the identifier.
    $tier = ConvertTo-NRGComparisonText -Value (Get-NRGObjectField -Item $bc -Key 'TargetTier' -Default '') -MaxLength 24 -Scrubber $Scrubber
    if ($tier -notmatch '^[A-Za-z][A-Za-z0-9 -]{0,23}$') { $tier = '' }
    $version = ConvertTo-NRGComparisonText -Value (Get-NRGObjectField -Item $bc -Key 'BaselineVersion' -Default '') -MaxLength 24 -Scrubber $Scrubber
    if ($version -notmatch '^[0-9A-Za-z.+-]{1,24}$') { $version = '' }

    # ── Rows: valid ControlIds only, first occurrence wins ──
    $byId  = [ordered]@{}
    $unreadable = 0
    $duplicates = 0
    $freshness = [ordered]@{ Current = 0; Stale = 0; None = 0; NotRecorded = 0 }
    $stamps = [System.Collections.Generic.List[datetime]]::new()
    $bcAvailable = Get-NRGObjectField -Item $bc -Key 'Available' -Default $true
    $rawRows = @()
    if ($null -ne $bc -and -not ($bcAvailable -is [bool] -and -not $bcAvailable)) {
        $rawRows = @(Get-NRGObjectField -Item $bc -Key 'Controls' -Default @())
    }
    foreach ($rawRow in $rawRows) {
        if ($null -eq $rawRow) { $unreadable++; continue }
        $id = ConvertTo-NRGComparisonText -Value (Get-NRGObjectField -Item $rawRow -Key 'ControlId' -Default '') -MaxLength 40
        if ($id -cnotmatch $script:NRGComparisonControlIdPattern) { $unreadable++; continue }
        if ($byId.Contains($id)) { $duplicates++; continue }

        $rowTier = ConvertTo-NRGComparisonText -Value (Get-NRGObjectField -Item $rawRow -Key 'RequiredTier' -Default '') -MaxLength 24 -Scrubber $Scrubber
        if ($rowTier -notmatch '^[A-Za-z][A-Za-z0-9 -]{0,23}$') { $rowTier = '' }
        $byId[$id] = [pscustomobject]@{
            ControlId     = $id
            Title         = (ConvertTo-NRGComparisonText -Value (Get-NRGObjectField -Item $rawRow -Key 'Title' -Default '') -MaxLength 160 -Scrubber $Scrubber)
            RequiredTier  = $rowTier
            ExpectedState = (ConvertTo-NRGComparisonText -Value (Get-NRGObjectField -Item $rawRow -Key 'ExpectedState' -Default '') -MaxLength 2000)
            Verdict       = (Get-NRGComparisonSideVerdict -Row $rawRow -KnownCodes $KnownCodes)
        }

        $fr = ConvertTo-NRGComparisonText -Value (Get-NRGObjectField -Item $rawRow -Key 'EvidenceFreshness' -Default '') -MaxLength 24
        switch -CaseSensitive ($fr) {
            'Current' { $freshness.Current++ }
            'Stale'   { $freshness.Stale++ }
            'None'    { $freshness.None++ }
            default   { $freshness.NotRecorded++ }
        }
        $ts = ConvertTo-NRGComparisonUtc -Value (Get-NRGObjectField -Item $rawRow -Key 'EvidenceTimestamp' -Default $null)
        if ($null -ne $ts) { $stamps.Add($ts) }
    }
    $oldest = $null; $newest = $null
    if ($stamps.Count -gt 0) {
        $sorted = @($stamps | Sort-Object)
        $oldest = $sorted[0]; $newest = $sorted[$sorted.Count - 1]
    }

    return [ordered]@{
        Label              = $Label
        Name               = $name
        FileTag            = $fileTag
        HasBaseline        = ($byId.Count -gt 0)
        RunTimeUtc         = $runUtc
        RunDate            = $(if ($null -ne $runUtc) { $runUtc.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture) } else { '' })
        TargetTier         = $tier
        BaselineVersion    = $version
        RequiredControls   = $byId.Count
        UnreadableRows     = $unreadable
        DuplicateRows      = $duplicates
        Freshness          = [ordered]@{
            Current     = $freshness.Current
            Stale       = $freshness.Stale
            None        = $freshness.None
            NotRecorded = $freshness.NotRecorded
            Oldest      = $(if ($null -ne $oldest) { $oldest.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture) } else { '' })
            Newest      = $(if ($null -ne $newest) { $newest.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture) } else { '' })
        }
        License            = (Get-NRGComparisonLicense -Results $Results)
        EvidenceCoverage      = (Get-NRGComparisonCoverageLine -Block (Get-NRGObjectField -Item $bc -Key 'EvidenceCoverage' -Default $null) -Kind Evidence -KnownCodes $KnownCodes)
        EffectivenessCoverage = (Get-NRGComparisonCoverageLine -Block (Get-NRGObjectField -Item $bc -Key 'EffectivenessCoverage' -Default $null) -Kind Effectiveness -KnownCodes $KnownCodes)
        ApprovedExceptionsCompared = 0
        # Held only to compare the two sides and to build the scrubber; never
        # rendered, and removed from the model before it is returned.
        _Domain            = $domain
        _TenantId          = $tenantId
        _Rows              = $byId
    }
}

function Get-NRGBaselineTenantComparison {
    <#
    .SYNOPSIS
        Compares two tenants' NRG Security Baseline results, side by side,
        from two parsed results JSON objects. A view: no findings, no score.
    .DESCRIPTION
        See the header of this file for the rules. The headline counts controls
        BOTH tenants verified; a control either run could not verify is listed
        as not comparable with each side's reason code, and is never a match.
        Any tier may be compared: only controls required at both tenants are
        compared, and the rest are listed with the tier that required them.
    .PARAMETER ResultsA
        The parsed results JSON for the first tenant (ConvertFrom-Json).
    .PARAMETER ResultsB
        The parsed results JSON for the second tenant.
    .PARAMETER Anonymize
        Label the tenants A and B everywhere. The returned model then holds no
        tenant name, domain or ID, and any identifier found inside a title is
        replaced.
    .PARAMETER MaxRunGapDays
        Runs further apart than this draw a warning. Default 7: the baseline's
        own Weekly freshness class allows 8 days.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [AllowNull()] [object] $ResultsA,
        [Parameter(Mandatory)] [AllowNull()] [object] $ResultsB,
        [switch] $Anonymize,
        [ValidateRange(1, 3650)] [int] $MaxRunGapDays = 7
    )
    Set-StrictMode -Version Latest

    $codeSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($k in (Get-NRGBaselineReasonCodes).Keys) { $null = $codeSet.Add([string]$k) }

    # ── Identifiers to scrub from rendered strings (anonymized mode only) ──
    $scrubber = $null
    if ($Anonymize) {
        $ids = [System.Collections.Generic.List[string]]::new()
        foreach ($res in @($ResultsA, $ResultsB)) {
            $m = Get-NRGObjectField -Item $res -Key 'Metadata' -Default $null
            $c = Get-NRGObjectField -Item $res -Key 'Connections' -Default $null
            foreach ($o in @($m, $c)) {
                foreach ($k in @('TenantDomain', 'TenantId', 'TenantName', 'DisplayName')) {
                    $v = Get-NRGObjectField -Item $o -Key $k -Default ''
                    if ($v -is [string] -and -not [string]::IsNullOrWhiteSpace($v)) { $ids.Add($v.Trim()) }
                }
            }
        }
        $scrubber = New-NRGComparisonScrubber -Identifiers @($ids)
    }

    $sideA = New-NRGComparisonSide -Label 'A' -Results $ResultsA -Anonymize:$Anonymize -Scrubber $scrubber -KnownCodes $codeSet
    $sideB = New-NRGComparisonSide -Label 'B' -Results $ResultsB -Anonymize:$Anonymize -Scrubber $scrubber -KnownCodes $codeSet

    $model = [ordered]@{
        Available       = $false
        Anonymized      = [bool]$Anonymize
        Note            = ''
        Headline        = ''
        HeadlineDetail  = ''
        SideA           = $null
        SideB           = $null
        Context         = [ordered]@{}
        Counts          = [ordered]@{}
        Differences     = @()
        BothFailed      = @()
        BothSatisfied   = @()
        NotComparable   = @()
        NotCompared     = @()
        NotComparableBy = [ordered]@{ A = [ordered]@{}; B = [ordered]@{} }
        LicenseDifferences = @()
        Notes           = @()
        Warnings        = @()
        ReasonCodes     = @()
    }

    # Strip the private fields before anything leaves this function.
    $publish = {
        param($side)
        $out = [ordered]@{}
        foreach ($k in $side.Keys) { if (-not $k.StartsWith('_')) { $out[$k] = $side[$k] } }
        return $out
    }

    if (-not $sideA.HasBaseline -or -not $sideB.HasBaseline) {
        $missing = @(if (-not $sideA.HasBaseline) { 'A' }; if (-not $sideB.HasBaseline) { 'B' }) -join ' and '
        $model.Note = "Results $missing carry no NRG Security Baseline controls (the run predates the baseline, the baseline view failed, or the file lists no controls). There is nothing to compare."
        $model.SideA = & $publish $sideA
        $model.SideB = & $publish $sideB
        return $model
    }

    $rowsA = $sideA._Rows
    $rowsB = $sideB._Rows

    # ── Classify ──
    $differences = [System.Collections.Generic.List[object]]::new()
    $bothFailed  = [System.Collections.Generic.List[object]]::new()
    $bothSat     = [System.Collections.Generic.List[object]]::new()
    $notComp     = [System.Collections.Generic.List[object]]::new()
    $notCompared = [System.Collections.Generic.List[object]]::new()
    $byCause = @{ A = @{}; B = @{} }
    $excA = 0; $excB = 0
    # Two rows describe the same requirement only when that is established:
    # both runs used the same baseline version (the same definition file), or
    # both rows carry an expected state and the two are identical. A missing
    # expected state on either side, under different or unknown versions,
    # proves nothing, so the control is NotComparable — never compared on the
    # assumption that the definitions agree.
    $sameDefinitionFile = ($sideA.BaselineVersion -and $sideB.BaselineVersion -and ($sideA.BaselineVersion -ceq $sideB.BaselineVersion))

    foreach ($id in @($rowsA.Keys)) {
        $a = $rowsA[$id]
        if (-not $rowsB.Contains($id)) {
            $notCompared.Add([pscustomobject][ordered]@{
                ControlId = $id; Title = $a.Title; Basis = 'RequiredOnlyAtA'; RequiredBy = 'A'
                RequiredTierA = $a.RequiredTier; RequiredTierB = ''
            })
            continue
        }
        $b = $rowsB[$id]
        $tierDiffers  = ($a.RequiredTier -and $b.RequiredTier -and ($a.RequiredTier -cne $b.RequiredTier))
        $stateDiffers = ($a.ExpectedState -and $b.ExpectedState -and ($a.ExpectedState -cne $b.ExpectedState))
        if ($tierDiffers -or $stateDiffers) {
            $notCompared.Add([pscustomobject][ordered]@{
                ControlId = $id; Title = $(if ($a.Title) { $a.Title } else { $b.Title }); Basis = 'DefinitionDiffers'; RequiredBy = 'Both'
                RequiredTierA = $a.RequiredTier; RequiredTierB = $b.RequiredTier
            })
            continue
        }

        $va = $a.Verdict; $vb = $b.Verdict
        $definitionKnown = $sameDefinitionFile -or ($a.ExpectedState -and $b.ExpectedState)
        $cls = if (-not $definitionKnown) { 'NotComparable' }
               elseif ($va.Verdict -eq 'Satisfied' -and $vb.Verdict -eq 'Satisfied') { 'BothSatisfied' }
               elseif ($va.Verdict -eq 'Failed' -and $vb.Verdict -eq 'Failed') { 'BothFailed' }
               elseif ($va.Verdict -eq 'Satisfied' -and $vb.Verdict -eq 'Failed') { 'DiffersASatisfied' }
               elseif ($va.Verdict -eq 'Failed' -and $vb.Verdict -eq 'Satisfied') { 'DiffersBSatisfied' }
               else { 'NotComparable' }
        $row = [pscustomobject][ordered]@{
            ControlId     = $id
            Title         = $(if ($a.Title) { $a.Title } else { $b.Title })
            Classification = $cls
            RequiredTierA = $a.RequiredTier
            RequiredTierB = $b.RequiredTier
            StateA        = $va.State
            ReasonCodeA   = $va.ReasonCode
            DispositionA  = $va.Disposition
            StateB        = $vb.State
            ReasonCodeB   = $vb.ReasonCode
            DispositionB  = $vb.Disposition
        }
        if ($va.Disposition -eq 'ApprovedException') { $excA++ }
        if ($vb.Disposition -eq 'ApprovedException') { $excB++ }
        switch ($cls) {
            'BothSatisfied'     { $bothSat.Add($row) }
            'BothFailed'        { $bothFailed.Add($row) }
            'DiffersASatisfied' { $differences.Add($row) }
            'DiffersBSatisfied' { $differences.Add($row) }
            default {
                $notComp.Add($row)
                # What each side lacked: the expected state that would establish
                # the definition, else its recognized reason code, else its state.
                if (-not $definitionKnown) {
                    foreach ($pair in @(@('A', $a), @('B', $b))) {
                        if ($pair[1].ExpectedState) { continue }
                        $key = 'DefinitionNotEstablished'
                        if ($byCause[$pair[0]].ContainsKey($key)) { $byCause[$pair[0]][$key]++ } else { $byCause[$pair[0]][$key] = 1 }
                    }
                } else {
                    foreach ($pair in @(@('A', $va), @('B', $vb))) {
                        if ($pair[1].Verdict -ne 'None') { continue }
                        $key = if ($codeSet.Contains($pair[1].ReasonCode)) { $pair[1].ReasonCode } else { $pair[1].State }
                        if ($byCause[$pair[0]].ContainsKey($key)) { $byCause[$pair[0]][$key]++ } else { $byCause[$pair[0]][$key] = 1 }
                    }
                }
            }
        }
    }
    foreach ($id in @($rowsB.Keys)) {
        if ($rowsA.Contains($id)) { continue }
        $b = $rowsB[$id]
        $notCompared.Add([pscustomobject][ordered]@{
            ControlId = $id; Title = $b.Title; Basis = 'RequiredOnlyAtB'; RequiredBy = 'B'
            RequiredTierA = ''; RequiredTierB = $b.RequiredTier
        })
    }

    foreach ($s in @('A', 'B')) {
        $ordered = [ordered]@{}
        foreach ($e in @($byCause[$s].GetEnumerator() | Sort-Object -Property @{ Expression = 'Value'; Descending = $true }, @{ Expression = 'Key'; Descending = $false })) {
            $ordered[[string]$e.Key] = [int]$e.Value
        }
        $model.NotComparableBy[$s] = $ordered
    }

    # ── Counts: Compared = Verified + NotComparable, always ──
    $nBothS = $bothSat.Count
    $nBothF = $bothFailed.Count
    $nDiffA = @($differences | Where-Object { $_.Classification -eq 'DiffersASatisfied' }).Count
    $nDiffB = @($differences | Where-Object { $_.Classification -eq 'DiffersBSatisfied' }).Count
    $nNotComp = $notComp.Count
    $nOnlyA = @($notCompared | Where-Object { $_.Basis -eq 'RequiredOnlyAtA' }).Count
    $nOnlyB = @($notCompared | Where-Object { $_.Basis -eq 'RequiredOnlyAtB' }).Count
    $nDef   = @($notCompared | Where-Object { $_.Basis -eq 'DefinitionDiffers' }).Count
    $verified = $nBothS + $nBothF + $nDiffA + $nDiffB
    $same = $nBothS + $nBothF
    $model.Counts = [ordered]@{
        RequiredA          = $sideA.RequiredControls
        RequiredB          = $sideB.RequiredControls
        Compared           = $verified + $nNotComp
        Verified           = $verified
        SamePosture        = $same
        Different          = $nDiffA + $nDiffB
        BothSatisfied      = $nBothS
        BothFailed         = $nBothF
        DiffersASatisfied  = $nDiffA
        DiffersBSatisfied  = $nDiffB
        NotComparable      = $nNotComp
        RequiredOnlyAtA    = $nOnlyA
        RequiredOnlyAtB    = $nOnlyB
        DefinitionDiffers  = $nDef
        NotCompared        = $nOnlyA + $nOnlyB + $nDef
        ApprovedExceptionsA = $excA
        ApprovedExceptionsB = $excB
    }
    $sideA.ApprovedExceptionsCompared = $excA
    $sideB.ApprovedExceptionsCompared = $excB

    # ── Basis of comparison ──
    $notes    = [System.Collections.Generic.List[string]]::new()
    $warnings = [System.Collections.Generic.List[string]]::new()
    $ta = $sideA.TargetTier; $tb = $sideB.TargetTier
    $verA = $sideA.BaselineVersion; $verB = $sideB.BaselineVersion
    $versionsKnown  = ($verA -and $verB)
    $versionsDiffer = ($versionsKnown -and ($verA -cne $verB))
    $versionsMatch  = ($versionsKnown -and ($verA -ceq $verB))
    $tiersKnown  = ($ta -and $tb)
    $tiersDiffer = ($tiersKnown -and ($ta -cne $tb))

    $comparedTier = ''
    if ($tiersKnown) {
        if (-not $tiersDiffer) { $comparedTier = $ta }
        else {
            $ia = [array]::IndexOf($script:NRGComparisonTierOrder, $ta)
            $ib = [array]::IndexOf($script:NRGComparisonTierOrder, $tb)
            if ($ia -ge 0 -and $ib -ge 0) { $comparedTier = $script:NRGComparisonTierOrder[[math]::Min($ia, $ib)] }
        }
    }
    if (-not $tiersKnown) {
        $notes.Add('The target tier was not recorded for one or both runs. Only controls required in both runs are compared.')
    } elseif (-not $tiersDiffer) {
        $notes.Add("Both tenants were assessed at the $ta tier.")
    } else {
        $lowerText = if ($comparedTier) { " (the $comparedTier controls)" } else { '' }
        $notes.Add("A was assessed at the $ta tier and B at the $tb tier. Only controls required at both tenants' tiers are compared: $($model.Counts.Compared) controls$lowerText. Controls required at only one tenant's tier are listed below as not compared, with the tier that required them.")
    }
    if ($versionsDiffer) {
        $warnings.Add("The two runs used different versions of the NRG Security Baseline (A: v$verA, B: v$verB). The standard changed between them, so a difference can come from the standard rather than the tenant. Only controls required in both runs with the same required tier and expected state are compared; the rest are listed as not compared.")
    } elseif (-not $versionsMatch) {
        $which = if (-not $verA -and -not $verB) { 'either run' } elseif (-not $verA) { 'A' } else { 'B' }
        $warnings.Add("The baseline version was not recorded for $which, so the two runs cannot be confirmed to use the same standard. Only controls required in both runs with the same required tier and expected state are compared.")
    } else {
        $notes.Add("Both runs used NRG Security Baseline v$verA.")
    }

    # ── Run dates ──
    $apart = $null
    if ($null -ne $sideA.RunTimeUtc -and $null -ne $sideB.RunTimeUtc) {
        $apart = [math]::Round([math]::Abs(($sideA.RunTimeUtc - $sideB.RunTimeUtc).TotalDays), 1)
        if ($apart -gt $MaxRunGapDays) {
            $warnings.Add("The two runs are $($apart.ToString('0.#', [cultureinfo]::InvariantCulture)) days apart, more than the $MaxRunGapDays-day limit. Tenant configuration changes between runs, so a difference may reflect timing rather than the tenants.")
        }
    } else {
        $which = if ($null -eq $sideA.RunTimeUtc -and $null -eq $sideB.RunTimeUtc) { 'either run' } elseif ($null -eq $sideA.RunTimeUtc) { 'A' } else { 'B' }
        $warnings.Add("The run time was not recorded for $which, so it cannot be said how far apart the runs are.")
    }

    # ── Same tenant on both sides: allowed, but almost certainly a mistake ──
    $sameTenant = $false
    if ($sideA._TenantId -and $sideB._TenantId) { $sameTenant = ($sideA._TenantId -ieq $sideB._TenantId) }
    elseif ($sideA._Domain -and $sideB._Domain) { $sameTenant = ($sideA._Domain -ieq $sideB._Domain) }
    if ($sameTenant) {
        $warnings.Add('Both results files appear to come from the same tenant. This comparison is meant for two different tenants; to see one tenant change over time, use -BaselineResults on Invoke-NRGAssessment.ps1.')
    }

    # ── Skipped rows ──
    foreach ($s in @($sideA, $sideB)) {
        if ($s.UnreadableRows -gt 0 -or $s.DuplicateRows -gt 0) {
            $warnings.Add("$($s.UnreadableRows) control row(s) in $($s.Label) had no valid ControlId and $($s.DuplicateRows) were duplicates; they were skipped.")
        }
    }

    # ── Licensing ──
    $licDiffs = [System.Collections.Generic.List[string]]::new()
    $lA = $sideA.License; $lB = $sideB.License
    if (-not $lA.Read -or -not $lB.Read) {
        $which = if (-not $lA.Read -and -not $lB.Read) { 'either run' } elseif (-not $lA.Read) { 'A' } else { 'B' }
        $notes.Add("Licensing was not read for $which, so license differences cannot be stated. A control marked LicenseBlocked below is what each run itself recorded.")
    } else {
        foreach ($k in @($lA.Flags.Keys)) {
            if ($lA.Flags[$k] -ne $lB.Flags[$k]) {
                $licDiffs.Add("$k`: A $(if ($lA.Flags[$k]) { 'has it' } else { 'does not' }), B $(if ($lB.Flags[$k]) { 'has it' } else { 'does not' })")
            }
        }
        if ($lA.TierLabel -cne $lB.TierLabel) { $licDiffs.Insert(0, "Licensed tier: A is $($lA.TierLabel), B is $($lB.TierLabel).") }
    }

    # ── Headline: a count of what both verified; no score, no ranking ──
    $model.Headline = if ($verified -eq 0) {
        'No control was verified at both tenants, so there is no baseline posture to compare.'
    } else {
        "Same baseline posture on $same of $verified controls that both tenants verified ($nBothS satisfied at both, $nBothF failed at both); $($nDiffA + $nDiffB) differ."
    }
    $model.HeadlineDetail = "$nNotComp control(s) could not be compared because a run did not verify them, and $($model.Counts.NotCompared) control(s) were left out because only one tenant's tier or version required them."

    $model.Available = $true
    $model.SideA = & $publish $sideA
    $model.SideB = & $publish $sideB
    $model.Context = [ordered]@{
        BaselineVersionsDiffer = $versionsDiffer
        BaselineVersionsMatch  = $versionsMatch
        TargetTiersDiffer      = $tiersDiffer
        ComparedTier           = $comparedTier
        RunsApartDays          = $apart
        RunsFarApart           = ($null -ne $apart -and $apart -gt $MaxRunGapDays)
        MaxRunGapDays          = $MaxRunGapDays
        SameTenant             = $sameTenant
    }
    $model.Differences        = @($differences)
    $model.BothFailed         = @($bothFailed)
    $model.BothSatisfied      = @($bothSat)
    $model.NotComparable      = @($notComp)
    $model.NotCompared        = @($notCompared)
    $model.LicenseDifferences = @($licDiffs)
    $model.Notes              = @($notes)
    $model.Warnings           = @($warnings)

    # The legend: only the codes that appear, with the module's own meaning.
    $used = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($lr in (@($differences) + @($bothFailed) + @($bothSat) + @($notComp))) {
        foreach ($c in @($lr.ReasonCodeA, $lr.ReasonCodeB)) { if ($codeSet.Contains($c)) { $null = $used.Add($c) } }
    }
    $legend = [System.Collections.Generic.List[object]]::new()
    foreach ($entry in (Get-NRGBaselineReasonCodes).Values) {
        if ($used.Contains([string]$entry.Code)) { $legend.Add([pscustomobject][ordered]@{ Code = [string]$entry.Code; Meaning = [string]$entry.Meaning }) }
    }
    $model.ReasonCodes = @($legend)
    return $model
}
