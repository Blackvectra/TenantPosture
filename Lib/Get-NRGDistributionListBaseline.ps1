#Requires -Version 7.0
#
# Get-NRGDistributionListBaseline.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Loads the distribution-list recommendation catalog
#          (Config/distribution-list-baseline.json), parses the NRG standards
#          that catalog depends on, and builds the TEXT of the commands the
#          worksheet prints for an administrator.
#
# Data keys set/consumed: none (reads two config files; no raw data, no findings).
# Graph scopes / cmdlets: none. This file connects to nothing and changes nothing.
#
# THE COMMANDS ARE TEXT. A recommendation carries a command template such as
#   Set-DistributionGroup -Identity {Identity} -RequireSenderAuthenticationEnabled $true
# and Get-NRGDistributionListFixCommand returns a STRING. Nothing in the module
# evaluates that string: no expression evaluation, no call operator on it, no script block. The
# templates live in JSON (data), never in a .ps1 the module loads, so the
# read-only static tests keep passing for the right reason. NRG.DistributionLists
# .Tests.ps1 pins that, and defines a throwing Set-DistributionGroup to prove a
# full run never reaches it.
#
# The text is built so a pasted command cannot do more than it says. The list
# identity is always a single-quoted literal built from a conservative address
# pattern or a GUID; any other name falls back to a placeholder rather than being
# escaped into a command. A value that comes from Config/nrg-standards.json is
# validated against an allow-list before it is substituted.

$script:NRGDlBaselineCache = $null

# The scan-level entry (DL-0.1) is not a catalog recommendation, so it has no row in
# Config/distribution-list-baseline.json. The evaluator emits it and the worksheet
# renders it; both read this one definition so the id, title and source cannot drift.
$script:NRGDlScan = [pscustomobject]@{
    Id          = 'DL-0.1'
    Instance    = '(scan)'
    Title       = 'Distribution-list inventory was read'
    Setting     = 'Collector SectionStatus'
    Recommended = 'Every list and its members read in full'
    SourceUrl   = 'https://learn.microsoft.com/powershell/module/exchangepowershell/get-distributiongroup'
}

# Register-NRGException accepts 1 to 2000 characters: one call site that throws from inside
# a catch block would abandon every read after it, so messages are bounded below that.
$script:NRGDlExceptionMessageMax = 1900
# A per-list member-read error is shown beside the list, so it is kept short.
$script:NRGDlMemberErrorMax = 300

function Get-NRGDlArray {
    # A list field as a plain array: absent, null and empty all become "nothing", and the
    # caller wraps the call in @() so zero or one element is still an array. (Do not use
    # the unary-comma form here: @(f) around a function that returns ,@(...) nests the array.)
    [CmdletBinding()]
    param([AllowNull()] $Item, [Parameter(Mandatory)] [string] $Key)
    $v = Get-NRGRuleList -Item $Item -Key $Key
    if ($null -eq $v) { return }
    $v | Where-Object { $null -ne $_ }
}

function Get-NRGDistributionListBaseline {
    <#
    .SYNOPSIS
        Returns the recommendation catalog: Available, Version, FrameworkCoverage and
        Recommendations. A missing or unreadable file yields Available = $false and no
        recommendations, which the evaluator reports as not assessed, never as a pass.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([string] $Path)

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ($script:NRGDlBaselineCache -and -not $Path) { return $script:NRGDlBaselineCache }

    $empty = [ordered]@{ Available = $false; Version = ''; FrameworkCoverage = $null; Recommendations = @() }
    $moduleRoot = if ($script:NRGModuleRoot) { $script:NRGModuleRoot }
                  elseif ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot }
                  else { (Get-Location).Path }
    $file = if ($Path) { $Path } else { Join-Path $moduleRoot 'Config' 'distribution-list-baseline.json' }
    if (-not (Test-Path -LiteralPath $file)) { return $empty }
    if (-not $Path) {
        # Same containment check the other config loaders apply.
        $resolved     = [System.IO.Path]::GetFullPath($file)
        $resolvedRoot = [System.IO.Path]::GetFullPath($moduleRoot)
        if (-not $resolved.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "distribution-list-baseline.json resolved outside module root: $resolved"
        }
    }
    try {
        $json = Get-Content -LiteralPath $file -Raw -Encoding utf8 -ErrorAction Stop | ConvertFrom-Json -Depth 10 -ErrorAction Stop
    } catch {
        Write-Warning "Failed to load distribution-list-baseline.json: $($_.Exception.Message)"
        return $empty
    }

    $recs = [System.Collections.Generic.List[object]]::new()
    foreach ($r in @(Get-NRGObjectField -Item $json -Key 'Recommendations' -Default @())) {
        $id = [string](Get-NRGObjectField -Item $r -Key 'Id' -Default '')
        if (-not $id) { continue }
        $cmds = Get-NRGObjectField -Item $r -Key 'Commands' -Default $null
        $recs.Add([pscustomobject][ordered]@{
            Id                     = $id
            Title                  = [string](Get-NRGObjectField -Item $r -Key 'Title' -Default $id)
            Area                   = [string](Get-NRGObjectField -Item $r -Key 'Area' -Default '')
            Setting                = [string](Get-NRGObjectField -Item $r -Key 'Setting' -Default '')
            AppliesTo              = @(Get-NRGDlArray -Item $r -Key 'AppliesTo')
            RecommendedValue       = [string](Get-NRGObjectField -Item $r -Key 'RecommendedValue' -Default '')
            RecommendedValueSource = [string](Get-NRGObjectField -Item $r -Key 'RecommendedValueSource' -Default 'None')
            StandardKey            = [string](Get-NRGObjectField -Item $r -Key 'StandardKey' -Default '')
            Severity               = [string](Get-NRGObjectField -Item $r -Key 'Severity' -Default 'Informational')
            Why                    = [string](Get-NRGObjectField -Item $r -Key 'Why' -Default '')
            SourceUrl              = [string](Get-NRGObjectField -Item $r -Key 'SourceUrl' -Default '')
            AlsoSee                = @(Get-NRGDlArray -Item $r -Key 'AlsoSee')
            Nist80053              = @(Get-NRGDlArray -Item $r -Key 'Nist80053')
            NistMappingNote        = [string](Get-NRGObjectField -Item $r -Key 'NistMappingNote' -Default '')
            CommandDistribution    = [string](Get-NRGObjectField -Item $cmds -Key 'Distribution' -Default '')
            CommandDynamic         = [string](Get-NRGObjectField -Item $cmds -Key 'Dynamic' -Default '')
            FixNote                = [string](Get-NRGObjectField -Item $r -Key 'FixNote' -Default '')
        })
    }

    $out = [ordered]@{
        Available         = ($recs.Count -gt 0)
        Version           = [string](Get-NRGObjectField -Item $json -Key 'Version' -Default '')
        FrameworkCoverage = (Get-NRGObjectField -Item $json -Key 'FrameworkCoverage' -Default $null)
        Recommendations   = @($recs)
    }
    if (-not $Path) { $script:NRGDlBaselineCache = $out }
    return $out
}

function Get-NRGDistributionListStandards {
    <#
    .SYNOPSIS
        The approved NRG standards the distribution-list worksheet judges, parsed and
        validated. Every value is "not approved" until Config/nrg-standards.json holds a
        valid one; a value that fails validation is dropped and named in Notes, never
        guessed at.
    .OUTPUTS
        [ordered] MaxMembers ([int] or $null), AllowedJoin, AllowedDepart (canonical-case
        string arrays), ExternalMembersProhibited ([bool]), Notes (string array).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] $Standards)

    Set-StrictMode -Version Latest
    if ($null -eq $Standards) {
        $Standards = if (Get-Command Get-NRGStandards -ErrorAction SilentlyContinue) { Get-NRGStandards } else { $null }
    }
    $notes = [System.Collections.Generic.List[string]]::new()
    # A stubbed or older standards object may lack the keys: absent means not approved.
    $read = { param([string] $Key) Get-NRGDlArray -Item $Standards -Key $Key }

    $max = $null
    foreach ($v in (& $read 'DistributionListMaxMembers')) {
        $n = 0
        if ([int]::TryParse(([string]$v).Trim(), [System.Globalization.NumberStyles]::None, [cultureinfo]::InvariantCulture, [ref]$n) -and $n -ge 1 -and $n -le 1000000) {
            $max = $n
        } else {
            $notes.Add("DistributionListMaxMembers value '$v' is not a whole number from 1 to 1000000; treated as not approved.")
        }
        break
    }

    $canon = {
        param([string] $Key, [string[]] $Allowed)
        $keep = [System.Collections.Generic.List[string]]::new()
        foreach ($v in (& $read $Key)) {
            $match = @($Allowed | Where-Object { $_ -ieq ([string]$v).Trim() })
            if ($match.Count -eq 1) { if (-not $keep.Contains($match[0])) { $keep.Add($match[0]) } }
            else { $notes.Add("$Key value '$v' is not one of $($Allowed -join ', '); ignored.") }
        }
        $keep
    }
    $join   = @(& $canon 'DistributionListAllowedJoinRestrictions'   @('Open', 'Closed', 'ApprovalRequired'))
    $depart = @(& $canon 'DistributionListAllowedDepartRestrictions' @('Open', 'Closed'))

    $extProhibited = $false
    foreach ($v in (& $read 'DistributionListExternalMembers')) {
        if (([string]$v).Trim() -ieq 'Prohibited') { $extProhibited = $true }
        else { $notes.Add("DistributionListExternalMembers value '$v' is not 'Prohibited'; ignored.") }
    }

    return [ordered]@{
        MaxMembers                 = $max
        AllowedJoin                = @($join)
        AllowedDepart              = @($depart)
        ExternalMembersProhibited  = $extProhibited
        Notes                      = @($notes)
    }
}

function ConvertTo-NRGDlPsLiteral {
    <#
    .SYNOPSIS
        A value as a single-quoted PowerShell literal, or $null when it cannot be made
        safe. PowerShell reads the typographic quotes U+2018 to U+201B as single quotes
        too, so every one of them is doubled, not only the ASCII quote. A control
        character (a newline would end the line) returns $null.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [string] $Value)
    if ([string]::IsNullOrEmpty($Value)) { return $null }
    if ($Value -match '[\x00-\x1F\x7F  ]') { return $null }
    $q = $Value -replace "['‘’‚‛]", '$0$0'
    return "'$q'"
}

# ── How a finding is worded and how its status is read back ───────────────────
# A NotApplicable verdict is four different things to the reader. The evaluator says which by
# starting the finding's Detail with one of these labels followed by ". ", and the worksheet reads the
# label back from the START of the Detail only. It does not search the prose: the Detail contains the
# list's display name, which a user can set to anything, so a name reading "reported only" must not be
# able to change another row's status. Writer (Format-NRGDlDetail) and reader
# (Get-NRGDlKindFromDetail) share this one table; change them together.
$script:NRGDlKindLabels = [ordered]@{
    NoStandard   = 'Not assessed (no approved NRG standard)'
    DoesNotApply = 'Does not apply'
    ReportedOnly = 'Reported only'
    NotAssessed  = 'Not assessed'
}

function Get-NRGDlKindFromDetail {
    # The status label a Detail starts with, or '' when it carries none.
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [string] $Detail)
    if ([string]::IsNullOrEmpty($Detail)) { return '' }
    foreach ($label in $script:NRGDlKindLabels.Values) {
        if ($Detail.StartsWith("$label. ", [StringComparison]::Ordinal)) { return $label }
    }
    return ''
}

function Get-NRGDlSourceLabel {
    [CmdletBinding()]
    [OutputType([string])]
    param([string] $Source)
    switch ($Source) {
        'MicrosoftDefault'  { 'Microsoft documented default' }
        'MicrosoftGuidance' { 'Microsoft documented guidance' }
        'NRGStandard'       { 'NRG standard' }
        default             { 'no recommendation' }
    }
}

function Format-NRGDlRecommended {
    # The recommended value as a reader sees it. A Microsoft value names where it comes from;
    # an NRG standard or "no recommendation" already says so in its own words.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Rec)
    if ($Rec.RecommendedValueSource -in 'MicrosoftDefault', 'MicrosoftGuidance') {
        return ('{0} ({1})' -f $Rec.RecommendedValue, (Get-NRGDlSourceLabel -Source $Rec.RecommendedValueSource))
    }
    return [string]$Rec.RecommendedValue
}

function Get-NRGDlCitationText {
    # The NIST sentence for a recommendation, with each Rev 5 title. Computed once per recommendation
    # by the evaluator, not once per finding.
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] $Rec)
    $haveTitles = [bool](Get-Command Get-NRGNISTControlTitle -ErrorAction SilentlyContinue)
    $nist = @(@($Rec.Nist80053) | ForEach-Object {
        $t = if ($haveTitles) { Get-NRGNISTControlTitle -ControlId $_ } else { '' }
        if ($t) { "$_ $t" } else { [string]$_ } })
    if ($nist.Count -gt 0) { return "NIST SP 800-53 Rev 5 (this tool's mapping, not NIST text): $($nist -join '; ')." }
    return 'Framework: no framework item verified.'
}

function Format-NRGDlDetail {
    # [Kind label. ] verdict sentence, what was read, what was not, the source and the NIST mapping.
    # Every output prints this text unchanged. The recommended value is not repeated here: it travels
    # as the finding's RequiredValue and the worksheet's Recommended field.
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $Rec,
        [Parameter(Mandatory)] [string] $Lead,
        [string[]] $Read = @(),
        [string[]] $NotRead = @(),
        [ValidateSet('', 'NotAssessed', 'ReportedOnly', 'NoStandard', 'DoesNotApply')] [string] $Kind = '',
        [string] $CitationText
    )
    if (-not $CitationText) { $CitationText = Get-NRGDlCitationText -Rec $Rec }
    $Read = @($Read | Where-Object { $_ }); $NotRead = @($NotRead | Where-Object { $_ })
    $readText    = if ($Read.Count)    { ($Read -join '; ') }    else { 'nothing for this setting' }
    $notReadText = if ($NotRead.Count) { ($NotRead -join '; ') } else { 'nothing further for this setting' }
    $prefix = if ($Kind) { "$($script:NRGDlKindLabels[$Kind]). " } else { '' }
    return ("{0}{1} Read: {2}. Not read: {3}. Source: {4}. {5}" -f $prefix, $Lead.Trim(), $readText, $notReadText, $Rec.SourceUrl, $CitationText)
}

function Get-NRGDlListKey {
    <#
    .SYNOPSIS
        The one string that names a list in findings (Instance) and in the worksheet:
        its address, else its GUID, else its display name. The evaluator and the
        publisher both call this, so a finding always lands under its own list.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $List)
    foreach ($k in 'PrimarySmtpAddress', 'Guid', 'DisplayName', 'Name') {
        $v = [string](Get-NRGObjectField -Item $List -Key $k -Default '')
        if (-not [string]::IsNullOrWhiteSpace($v)) { return $v }
    }
    return ''
}

function Get-NRGDlListIdentity {
    <#
    .SYNOPSIS
        The token a command uses to name a list: its address when that matches a
        conservative pattern, else its GUID, else $null. A display name is never used,
        because it is free text an end user can influence.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $List)
    $addr = [string](Get-NRGObjectField -Item $List -Key 'PrimarySmtpAddress' -Default '')
    # \A...\z, not ^...$: in .NET $ also matches before a trailing newline.
    if ($addr -match '\A[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,255}\.[A-Za-z]{2,63}\z') { return $addr }
    $guid = [string](Get-NRGObjectField -Item $List -Key 'Guid' -Default '')
    if ($guid -match '\A[0-9A-Fa-f]{8}-([0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\z') { return $guid }
    return $null
}

function Get-NRGDistributionListFixCommand {
    <#
    .SYNOPSIS
        The command TEXT an administrator would run to bring a list to a recommendation,
        or $null when there is none (reported-only recommendation, a setting the list type
        does not have, or an NRG standard that is not approved). Returns a string. It is
        never executed by this module.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] $Recommendation,
        [Parameter(Mandatory)] $List,
        [AllowNull()] $Standards
    )
    $isDynamic = ([string](Get-NRGObjectField -Item $List -Key 'ListType' -Default '') -eq 'Dynamic')
    $template  = if ($isDynamic) { [string](Get-NRGObjectField -Item $Recommendation -Key 'CommandDynamic' -Default '') }
                 else            { [string](Get-NRGObjectField -Item $Recommendation -Key 'CommandDistribution' -Default '') }
    if ([string]::IsNullOrWhiteSpace($template)) { return $null }

    if ($template -match '\{Approved\}') {
        $key = [string](Get-NRGObjectField -Item $Recommendation -Key 'StandardKey' -Default '')
        $vals = @(switch ($key) {
            'DistributionListAllowedJoinRestrictions'   { @(Get-NRGDlArray -Item $Standards -Key 'AllowedJoin') }
            'DistributionListAllowedDepartRestrictions' { @(Get-NRGDlArray -Item $Standards -Key 'AllowedDepart') }
            default                                     { @() }
        })
        if (@($vals).Count -eq 0) { return $null }
        # Only an allow-listed word is ever substituted into the text.
        if ([string]$vals[0] -notmatch '^(Open|Closed|ApprovalRequired)$') { return $null }
        $template = $template.Replace('{Approved}', [string]$vals[0])
    }

    $identity = Get-NRGDlListIdentity -List $List
    $literal  = if ($identity) { ConvertTo-NRGDlPsLiteral -Value $identity } else { $null }
    if (-not $literal) { $literal = "'<identify this list by its address or GUID>'" }
    return $template.Replace('{Identity}', $literal)
}
