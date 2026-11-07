#Requires -Version 7.0
#
# Get-TPCopilotLicensingState.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: One reading of what the M365Copilot collector established about
#   Copilot seats, so a license read that failed is never mistaken for a
#   tenant with no Copilot. The collector, the Copilot evaluators (PPL-3.1,
#   3.2, 3.3, 3.5) and later views use these functions; none is exported.
#
# Data consumed: the 'M365Copilot' raw-data envelope (any vintage), passed in.
# Data set: none (pure functions). Graph scopes / cmdlets used: none.
#
# WHY (D1, 2026-11-06)
# --------------------
# The collector initialised CopilotLicensedUserCount to 0 and kept the 0 when
# the subscribedSkus read threw, while Success stayed true whenever the user
# read worked. PPL-3.1, 3.2 and 3.5 then said "No Microsoft 365 Copilot
# licenses detected" on a tenant whose licensing was never read. A default
# zero is not evidence. Every count is now a measurement that carries its
# availability, source and completeness, and a missing value stays $null.
#
# MEASUREMENTS (Data.LicensingMeasurements, written by the collector)
#   RecognizedSkuCount      subscribed SKUs this tool recognizes as Copilot
#   PurchasedSeats          sum of prepaidUnits.enabled on those SKUs (capacity)
#   SkuConsumedUnits        sum of consumedUnits on those SKUs (per-SKU
#                           assignments; an account holding two SKUs counts
#                           twice, so this is never a unique-user count)
#   EnabledMembers          enabled non-guest accounts enumerated
#   AssignedUsers           unique enumerated accounts holding a recognized SKU
#   AssignedEnabledMembers  unique enabled members holding a recognized SKU
# Each is @{ Kind; Value; Available; Completeness; Source; Note }.
# Completeness: Complete | Incomplete (a lower bound: some pages were read) |
# NotRead (no value). Assignments are not usage.

# One copy of the vendor fact the Copilot findings state. Source: Microsoft
# Learn, "Microsoft Copilot requirements" (Licensing requirements table:
# Copilot Chat is "available to users with an eligible Microsoft 365
# subscription"; a Copilot license is "Not required for eligible users"; a
# Microsoft Entra ID account is required), read 2026-11-06. The wording avoids
# the scope classifier's collection-gap words on purpose: it appears in
# not-applicable findings, which must stay filed as such.
function Get-TPCopilotChatEligibilityNote {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    return 'This does not show that AI tools are absent or unused: Microsoft documents Microsoft Copilot Chat as available to users with an eligible Microsoft 365 subscription and a Microsoft Entra work or school account without a Copilot license, and this assessment does not measure whether anyone uses it.'
}

function New-TPCopilotMeasurement {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [ValidateSet('RecognizedProducts', 'PurchasedCapacity', 'SkuAssignments', 'EnumeratedAccounts', 'UniqueAssignedAccounts')] [string] $Kind,
        [Parameter(Mandatory)] [string] $Source,
        [AllowNull()] [object] $Value = $null,
        [ValidateSet('Complete', 'Incomplete', 'NotRead')] [string] $Completeness = 'NotRead',
        [string] $Note = ''
    )
    # A value only when the completeness says something was read; NotRead never carries a number.
    $v = if ($Completeness -eq 'NotRead' -or $null -eq $Value) { $null } else { [int]$Value }
    $c = if ($null -eq $v) { 'NotRead' } else { $Completeness }
    return [ordered]@{
        Kind         = $Kind
        Value        = $v
        Available    = ($null -ne $v)
        Completeness = $c
        Source       = $Source
        Note         = $Note
    }
}

# A whole number read from an API field, or $null. An absent, empty or
# non-numeric value is $null, never 0: 0 is a reading, absence is not.
function ConvertTo-TPCopilotCount {
    [CmdletBinding()]
    param([AllowNull()] [object] $Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [int] -or $Value -is [long]) { return [int]$Value }
    if ($Value -is [double] -or $Value -is [decimal]) {
        if ([math]::Floor([double]$Value) -eq [double]$Value) { return [int]$Value }
        return $null
    }
    $s = [string]$Value
    if ($s -cmatch '\A[0-9]{1,9}\z') { return [int]$s }
    return $null
}

function Get-TPCopilotMeasurementField {
    # One measurement out of an envelope's LicensingMeasurements, normalised;
    # an absent or malformed one reads as NotRead.
    [CmdletBinding()]
    param([AllowNull()] [object] $Measurements, [Parameter(Mandatory)] [string] $Name)
    $m = Get-TPObjectField -Item $Measurements -Key $Name -Default $null
    $value = ConvertTo-TPCopilotCount (Get-TPObjectField -Item $m -Key 'Value' -Default $null)
    $comp  = [string](Get-TPObjectField -Item $m -Key 'Completeness' -Default 'NotRead')
    if ($comp -notin @('Complete', 'Incomplete')) { $comp = 'NotRead' }
    if ($null -eq $value) { $comp = 'NotRead' }
    return [ordered]@{ Value = $value; Completeness = $comp; Source = [string](Get-TPObjectField -Item $m -Key 'Source' -Default '') }
}

# The part-number rule the collector applies (one copy). A SKU is also
# recognized by its Copilot service plans, which a stored row does not keep,
# so this rule alone is what a stored row can be judged by.
function Get-TPCopilotSkuPartNumberPattern {
    [CmdletBinding()] param()
    return '^(Microsoft_365_Copilot|MICROSOFT_365_COPILOT|M365_Copilot|COPILOT)'
}

# Whether a stored row names a Copilot product by its part number. Used for an
# older results file, whose rows carry no recorded read status: a row whose
# part number is absent or names another product is not Copilot evidence.
function Test-TPCopilotSkuRowIdentified {
    [CmdletBinding()]
    param([AllowNull()] [object] $Row)
    if ($null -eq $Row -or $Row -is [string]) { return $false }
    $part = [string](Get-TPObjectField -Item $Row -Key 'SkuPartNumber' -Default '')
    return ($part -and $part -match (Get-TPCopilotSkuPartNumberPattern))
}

# The recognized-SKU rows an envelope carries. The collector only ever stored
# rows for SKUs it recognized, as objects carrying SkuId; anything else (a bare
# string) is not a recognized-SKU row and proves nothing about Copilot.
function Get-TPCopilotRecognizedSkuRows {
    [CmdletBinding()]
    param([AllowNull()] [object] $Data)
    return @(@(Get-TPObjectField -Item $Data -Key 'LicensedSkus' -Default @()) | Where-Object {
            $null -ne $_ -and $_ -isnot [string] -and ([string](Get-TPObjectField -Item $_ -Key 'SkuId' -Default '')).Trim()
        })
}

function Get-TPCopilotLicensingState {
    <#
    .SYNOPSIS
        What the M365Copilot raw data establishes about Copilot seats.
    .DESCRIPTION
        Basis 'Current': the envelope carries SectionStatus.Licensing (written
        since D1). Basis 'Legacy': it does not (an older results file). Basis
        'None': no envelope.
        RecognizedSku: Present | None | Unknown. None only from a collected
        subscription list holding no SKU this tool recognizes (never "no
        Copilot": the recognition list may lag Microsoft's SKU names).
        Assignment: Assigned | NoneAssigned | Unknown. NoneAssigned needs an
        explicit zero from a complete measurement (the enumerated accounts, or
        the consumed units of every recognized SKU). A legacy file never yields
        None or NoneAssigned: its zeros may be defaults.
        Ratio: the PPL-3.3 numerator (AssignedEnabledMembers) and denominator
        (EnabledMembers), Available only when both are complete and the
        denominator is above zero.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] [object] $Raw)

    $s = [ordered]@{
        Basis              = 'None'
        LicensingRead      = 'NotRecorded'
        LicensingError     = ''
        UsersRead          = 'NotRecorded'
        UsersError         = ''
        RecognizedSku      = 'Unknown'
        Assignment         = 'Unknown'
        AssignmentEvidence = 'None'
        AssignedCount      = $null
        AssignedCountComplete = $false
        Reason             = 'NoData'
        Ratio              = [ordered]@{ Available = $false; Numerator = $null; Denominator = $null; Reason = 'NoData' }
    }
    if ($null -eq $Raw) { return $s }
    $data = Get-TPObjectField -Item $Raw -Key 'Data' -Default $null
    if ($null -eq $data) { return $s }

    $status = Get-TPObjectField -Item $data -Key 'SectionStatus' -Default $null
    $licStatus = [string](Get-TPObjectField -Item $status -Key 'Licensing' -Default '')

    if (-not $licStatus) {
        # ── Legacy: no status recorded. Only positive evidence is kept. ─────
        $s.Basis = 'Legacy'
        # Only a structured row whose part number names a Copilot product is
        # Copilot evidence; a bare string (e.g. 'SPB') or a row naming another
        # product proves nothing, and no row proves a complete enumeration.
        $rows = @(Get-TPCopilotRecognizedSkuRows -Data $data | Where-Object { Test-TPCopilotSkuRowIdentified -Row $_ })
        if ($rows.Count -gt 0) { $s.RecognizedSku = 'Present' }
        $recorded = ConvertTo-TPCopilotCount (Get-TPObjectField -Item $data -Key 'CopilotLicensedUserCount' -Default $null)
        $consumed = @($rows | ForEach-Object { ConvertTo-TPCopilotCount (Get-TPObjectField -Item $_ -Key 'ConsumedUnits' -Default $null) } | Where-Object { $null -ne $_ })
        if ($null -ne $recorded -and $recorded -gt 0) {
            $s.Assignment = 'Assigned'; $s.AssignmentEvidence = 'LegacyRecordedCount'
            $s.AssignedCount = $recorded; $s.AssignedCountComplete = $false; $s.Reason = 'LegacyPositiveEvidence'
        } elseif (@($consumed | Where-Object { $_ -gt 0 }).Count -gt 0) {
            $s.Assignment = 'Assigned'; $s.AssignmentEvidence = 'LegacySkuConsumedUnits'; $s.Reason = 'LegacyPositiveEvidence'
        } else {
            # A recorded 0, rows with 0 consumed, or nothing at all: the old
            # collector wrote 0 whether or not a read happened.
            $s.Reason = 'StatusNotRecorded'
        }
        $s.Ratio.Reason = 'StatusNotRecorded'
        return $s
    }

    # ── Current: the collector recorded each read's outcome. ────────────────
    $s.Basis = 'Current'
    $errors = Get-TPObjectField -Item $data -Key 'SectionErrors' -Default $null
    $s.LicensingRead  = $licStatus
    $s.LicensingError = [string](Get-TPObjectField -Item $errors -Key 'Licensing' -Default '')
    $usersStatus = [string](Get-TPObjectField -Item $status -Key 'Users' -Default '')
    $s.UsersRead  = if ($usersStatus) { $usersStatus } else { 'NotRecorded' }
    $s.UsersError = [string](Get-TPObjectField -Item $errors -Key 'Users' -Default '')

    $ms = Get-TPObjectField -Item $data -Key 'LicensingMeasurements' -Default $null
    $sku      = Get-TPCopilotMeasurementField -Measurements $ms -Name 'RecognizedSkuCount'
    if ($licStatus -eq 'Collected' -and $sku.Completeness -eq 'NotRead' -and $null -eq (Get-TPObjectField -Item $ms -Key 'RecognizedSkuCount' -Default $null)) {
        # A collected subscription list without the measurement block: LicensedSkus
        # is then the complete list of recognized rows (the collector writes both).
        $sku = [ordered]@{ Value = @(Get-TPCopilotRecognizedSkuRows -Data $data).Count; Completeness = 'Complete'; Source = 'LicensedSkus' }
    }
    $consumed = Get-TPCopilotMeasurementField -Measurements $ms -Name 'SkuConsumedUnits'
    $assigned = Get-TPCopilotMeasurementField -Measurements $ms -Name 'AssignedUsers'
    $numer    = Get-TPCopilotMeasurementField -Measurements $ms -Name 'AssignedEnabledMembers'
    $denom    = Get-TPCopilotMeasurementField -Measurements $ms -Name 'EnabledMembers'

    if ($licStatus -ne 'Collected' -or $sku.Completeness -ne 'Complete') {
        $s.Reason = 'LicensingNotCollected'
        $s.Ratio.Reason = 'LicensingNotCollected'
        return $s
    }
    if ($sku.Value -eq 0) {
        $s.RecognizedSku = 'None'
        $s.Reason = 'NoRecognizedSku'
        $s.Ratio.Reason = 'NoRecognizedSku'
        return $s
    }
    $s.RecognizedSku = 'Present'

    if ($assigned.Completeness -eq 'Complete') {
        if ($assigned.Value -gt 0) {
            $s.Assignment = 'Assigned'; $s.AssignmentEvidence = 'EnumeratedUsers'
            $s.AssignedCount = $assigned.Value; $s.AssignedCountComplete = $true; $s.Reason = 'Established'
        } elseif ($consumed.Completeness -eq 'Complete' -and $consumed.Value -gt 0) {
            # The full enumeration found no holder while the SKUs report consumed
            # seats: the two readings disagree, so neither answer is established.
            $s.Reason = 'MeasurementsDisagree'
        } else {
            $s.Assignment = 'NoneAssigned'; $s.AssignmentEvidence = 'EnumeratedUsers'
            $s.AssignedCount = 0; $s.AssignedCountComplete = $true; $s.Reason = 'Established'
        }
    } elseif ($assigned.Completeness -eq 'Incomplete' -and $assigned.Value -gt 0) {
        $s.Assignment = 'Assigned'; $s.AssignmentEvidence = 'EnumeratedUsers'
        $s.AssignedCount = $assigned.Value; $s.AssignedCountComplete = $false; $s.Reason = 'AtLeast'
    } elseif ($consumed.Completeness -eq 'Complete') {
        if ($consumed.Value -gt 0) {
            $s.Assignment = 'Assigned'; $s.AssignmentEvidence = 'SkuConsumedUnits'; $s.Reason = 'Established'
        } else {
            $s.Assignment = 'NoneAssigned'; $s.AssignmentEvidence = 'SkuConsumedUnits'; $s.Reason = 'Established'
        }
    } else {
        $s.Reason = 'AssignmentEvidenceMissing'
    }

    # PPL-3.3's ratio: one population (enabled members) on both sides, both complete.
    if ($denom.Completeness -ne 'Complete') {
        $s.Ratio.Reason = 'UsersNotComplete'
    } elseif ($numer.Completeness -ne 'Complete') {
        $s.Ratio.Reason = 'AssignmentsNotEstablished'
    } elseif ($denom.Value -le 0) {
        $s.Ratio.Reason = 'ZeroDenominator'
        $s.Ratio.Denominator = $denom.Value
    } else {
        $s.Ratio.Available = $true; $s.Ratio.Reason = 'Established'
        $s.Ratio.Numerator = $numer.Value; $s.Ratio.Denominator = $denom.Value
    }
    return $s
}

# How a finding names the seats it relies on, from an Assigned state only.
function Get-TPCopilotAssignedPhrase {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $State)
    if ($null -ne $State.AssignedCount -and $State.AssignedCountComplete) { return "Copilot is licensed to $($State.AssignedCount) account(s)" }
    if ($null -ne $State.AssignedCount -and $State.Basis -eq 'Legacy') { return "Copilot was recorded as licensed to $($State.AssignedCount) account(s) (completeness not recorded)" }
    if ($null -ne $State.AssignedCount) { return "Copilot is licensed to at least $($State.AssignedCount) account(s) (the user enumeration did not complete)" }
    return 'Copilot seats are assigned (the number of accounts holding them was not established)'
}
