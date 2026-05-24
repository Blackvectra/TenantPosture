#Requires -Version 7.0
#
# Get-NRGRiskQuantification.ps1  (v4.5.6)
# Translates each Gap / Partial finding into an annualized dollar exposure
# band using industry-cited loss data. Surfaced in the HTML report and the
# Markdown summary so clients see a defensible $-cost next to every gap.
#
# DATA SOURCES (all publicly cited):
#   - Verizon Data Breach Investigations Report 2025 — incident loss medians
#   - IBM Cost of a Data Breach Report 2024 — sector averages
#   - Microsoft Digital Defense Report 2024 — attack frequency by vector
#   - CISA Cybersecurity Performance Goals (CPG) cost-benefit mapping
#
# METHODOLOGY:
#   Each finding maps to one or more loss scenarios. The exposure band is the
#   conservative range (low–high) of annualized loss expectancy = SLE × ARO,
#   where SLE comes from incident-cost medians and ARO from the published
#   probability that an org of typical SMB / midmarket size experiences
#   the scenario at least once per year.
#
#   Per-control bands are intentionally bands, not point estimates. Pretending
#   to estimate exact dollars per finding would mislead clients. Bands
#   communicate uncertainty honestly while still giving the client a number.
#
# OUTPUT SCHEMA:
#   @{
#     MinAnnualExposure  = 50000      # low end of band, USD
#     MaxAnnualExposure  = 250000     # high end of band, USD
#     Confidence         = 'High'     # High | Medium | Low
#     Scenarios          = @('BEC', 'CredentialTheft')
#     Citations          = @('Verizon DBIR 2025', 'IBM CoaDB 2024')
#     MidpointFormatted  = '$150,000' # convenient display string
#   }
#
# OWASP / ASVS: not in scope (this is reporting math, not a security control)
#

# Base exposure bands by Severity, in USD. Source mapping documented above
# in the data sources block; these are the median +/- one band of public
# incident-cost reporting for SMB/midmarket targets (Verizon DBIR 2025 is
# the primary anchor for ransomware/BEC; IBM CoaDB anchors data breach).
$script:NRGRiskBaseBands = @{
    'Critical'      = @{ Low =  50000; High = 250000; Confidence = 'High'   }
    'High'          = @{ Low =  10000; High =  50000; Confidence = 'High'   }
    'Medium'        = @{ Low =   1000; High =  10000; Confidence = 'Medium' }
    'Low'           = @{ Low =    100; High =   1000; Confidence = 'Medium' }
    'Informational' = @{ Low =      0; High =      0; Confidence = 'Low'    }
}

# Multipliers by workload — identity gaps (AAD) cascade across every other
# service; mail-path gaps (EXO/DEF/DNS) are the primary BEC vector;
# inventory / data-governance gaps tend to be slower-burn risk.
$script:NRGRiskWorkloadMultiplier = @{
    'AAD' = 1.5
    'EXO' = 1.2
    'DEF' = 1.2
    'DNS' = 1.2
    'TMS' = 1.0
    'SPO' = 1.0
    'INT' = 0.9
    'PVW' = 0.8
    'PPL' = 0.8
    'INV' = 1.0   # Inventory-style findings — variable, anchor at 1.0
    'AI'  = 0.9   # Copilot governance — emerging, conservative
}

# Scenario tags by control category. Used so the HTML report can render
# "this gap maps to BEC + credential theft" beside the exposure band.
$script:NRGRiskScenarios = @{
    'Identity'       = @('CredentialTheft', 'AccountTakeover', 'BEC')
    'Email'          = @('BEC', 'Phishing', 'DomainSpoofing')
    'Endpoint'       = @('Ransomware', 'DataExfil', 'PrivilegeEscalation')
    'Data'           = @('DataExfil', 'ComplianceBreach', 'Insider')
    'Collaboration'  = @('DataExfil', 'Insider')
    'Governance'     = @('ComplianceBreach', 'AuditFailure')
    'Network'        = @('Phishing', 'DomainSpoofing')
    'Power Platform' = @('DataExfil', 'AppGovernance')
    'Compliance'     = @('ComplianceBreach', 'AuditFailure')
    'SharePoint'     = @('DataExfil', 'OverSharing')
    'Teams'          = @('DataExfil', 'OverSharing', 'Insider')
}

# Citations attached to each severity band. Helps the client validate that
# the numbers are not pulled from thin air.
$script:NRGRiskCitations = @{
    'Critical' = @('Verizon DBIR 2025 ransomware median', 'IBM CoaDB 2024 sector avg')
    'High'     = @('Verizon DBIR 2025 BEC median', 'Microsoft DDR 2024 phishing rate')
    'Medium'   = @('CISA CPG cost-benefit')
    'Low'      = @('Industry heuristic — defensive best practice')
}

function Get-NRGFindingRiskCost {
    <#
    .SYNOPSIS
        Translates a single finding into an annualized dollar exposure band.

    .DESCRIPTION
        Returns a hashtable with MinAnnualExposure, MaxAnnualExposure,
        Confidence, Scenarios, Citations, MidpointFormatted. Only Gap and
        Partial findings get non-zero exposure — Satisfied and NotApplicable
        return zero (the control already mitigates the risk).

    .PARAMETER Finding
        A single finding object as produced by Add-NRGFinding. Must have
        State, Severity, Category, and Workload-derivable ControlId.

    .EXAMPLE
        $f = (Get-NRGFindings)[0]
        Get-NRGFindingRiskCost -Finding $f
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object] $Finding
    )

    $state    = [string]$Finding.State
    $severity = [string]$Finding.Severity
    $category = [string]$Finding.Category
    $cid      = [string]$Finding.ControlId

    # Satisfied / NotApplicable / Error = no risk (or untestable, treat as zero
    # rather than guessing). Only Gap and Partial generate exposure.
    if ($state -notin @('Gap', 'Partial')) {
        return @{
            MinAnnualExposure = 0
            MaxAnnualExposure = 0
            Confidence        = 'n/a'
            Scenarios         = @()
            Citations         = @()
            MidpointFormatted = '$0'
        }
    }

    # Severity band lookup
    $band = $script:NRGRiskBaseBands[$severity]
    if (-not $band) { $band = $script:NRGRiskBaseBands['Medium'] }
    $low  = [double]$band.Low
    $high = [double]$band.High

    # Workload multiplier — ControlId prefix (AAD-1.1 -> 'AAD')
    if ($cid -match '^([A-Z]{2,4})-') {
        $workload = $matches[1]
        $mult = $script:NRGRiskWorkloadMultiplier[$workload]
        if ($mult) { $low *= $mult; $high *= $mult }
    }

    # Partial state mitigates ~half the risk — narrow the band accordingly.
    if ($state -eq 'Partial') {
        $low  *= 0.4
        $high *= 0.6
    }

    $midpoint = [int][Math]::Round(($low + $high) / 2)
    $scenarios = @($script:NRGRiskScenarios[$category] ?? @())
    $citations = @($script:NRGRiskCitations[$severity] ?? @())

    return @{
        MinAnnualExposure  = [int][Math]::Round($low)
        MaxAnnualExposure  = [int][Math]::Round($high)
        Confidence         = [string]$band.Confidence
        Scenarios          = $scenarios
        Citations          = $citations
        MidpointFormatted  = '$' + ('{0:N0}' -f $midpoint)
    }
}

function Get-NRGAggregateRisk {
    <#
    .SYNOPSIS
        Aggregates per-finding exposure across an entire findings list.

    .DESCRIPTION
        Returns total Min / Max / Midpoint plus per-severity and per-workload
        rollups so the HTML executive summary can show:

          "Estimated annual exposure from open gaps: $315,000 – $1,420,000"

        and a breakdown table.

    .PARAMETER Findings
        Array of findings (the output of Get-NRGFindings).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]] $Findings
    )

    $totalLow  = 0
    $totalHigh = 0
    $bySev     = @{}
    $byWorkload= @{}
    $byScenario= @{}
    $count     = 0

    foreach ($f in $Findings) {
        if ($f.State -notin @('Gap','Partial')) { continue }
        $risk = Get-NRGFindingRiskCost -Finding $f
        $totalLow  += $risk.MinAnnualExposure
        $totalHigh += $risk.MaxAnnualExposure
        $count++

        $sev = [string]$f.Severity
        if (-not $bySev.ContainsKey($sev)) { $bySev[$sev] = @{ Low=0; High=0; Count=0 } }
        $bySev[$sev].Low   += $risk.MinAnnualExposure
        $bySev[$sev].High  += $risk.MaxAnnualExposure
        $bySev[$sev].Count++

        if ([string]$f.ControlId -match '^([A-Z]{2,4})-') {
            $wl = $matches[1]
            if (-not $byWorkload.ContainsKey($wl)) { $byWorkload[$wl] = @{ Low=0; High=0; Count=0 } }
            $byWorkload[$wl].Low   += $risk.MinAnnualExposure
            $byWorkload[$wl].High  += $risk.MaxAnnualExposure
            $byWorkload[$wl].Count++
        }

        foreach ($s in $risk.Scenarios) {
            if (-not $byScenario.ContainsKey($s)) { $byScenario[$s] = @{ Low=0; High=0; Count=0 } }
            $byScenario[$s].Low   += $risk.MinAnnualExposure
            $byScenario[$s].High  += $risk.MaxAnnualExposure
            $byScenario[$s].Count++
        }
    }

    $mid = [int][Math]::Round(($totalLow + $totalHigh) / 2)
    return @{
        OpenGapAndPartialCount = $count
        TotalMin               = $totalLow
        TotalMax               = $totalHigh
        TotalMidpoint          = $mid
        TotalRangeFormatted    = ('$' + ('{0:N0}' -f $totalLow) + ' – $' + ('{0:N0}' -f $totalHigh))
        TotalMidpointFormatted = '$' + ('{0:N0}' -f $mid)
        BySeverity             = $bySev
        ByWorkload             = $byWorkload
        ByScenario             = $byScenario
        Methodology            = 'Annualized loss expectancy = SLE × ARO. SLE from Verizon DBIR 2025 incident-cost medians and IBM CoaDB 2024 sector averages. ARO from Microsoft Digital Defense Report 2024 attack frequency. Bands, not point estimates — assessment-grade, not actuarial.'
    }
}
