#Requires -Version 7.0
#
# Get-NRGNISTFamilyCoverage.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Roll assessment findings up by NIST SP 800-53 Rev 5 control FAMILY
#          (AC, AU, IA, SC, SI, ...) rather than by M365 workload.
#
#          Every control in Config/controls.json carries a References.NIST
#          citation, which Get-NRGFrameworkCitations flattens onto each finding
#          as a single FrameworkIds entry of the form "NIST:IA-2, IA-5(1)".
#          Get-NRGCoverageScore can already filter on that prefix, but it scores
#          NIST as ONE aggregate number. A tenant sitting at 61% overall tells a
#          NIST-aligned reader nothing about WHICH families are weak — and
#          "AU is at 34%" is the sentence that actually drives remediation for
#          a customer working an 800-53 or CMMC assessment.
#
#          One finding may cite several NIST controls across several families
#          (e.g. "IA-2, AC-7"). It is counted once in EACH family it cites:
#          that is the correct semantics for family coverage — a gap in a
#          control that supports both IA and AC is genuinely a gap in both.
#          Family counts therefore do not sum to the assessment total, and the
#          Assessed field per family is the honest per-family denominator.
#
# Inputs:  -Findings        array of finding objects (hashtable, ordered, or
#                           PSCustomObject — read via Get-NRGObjectField).
#                           $null entries skipped. Empty/null returns an empty
#                           Families/Controls set, never throws.
#          -ErrorHandling   'Gap' (default here, matching the publishers) counts
#                           Error findings in the denominator. 'Exclude' drops
#                           them. Passed straight through to Get-NRGCoverageScore
#                           so family scores use the identical formula as every
#                           other score in the tool.
#
# Outputs: [ordered] hashtable:
#            Families          array of per-family [ordered] rows, sorted by
#                              family ID, each with:
#                                Family        'AU'
#                                Name          'Audit and Accountability'
#                                Assessed      findings citing this family
#                                Satisfied / Partial / Gap / NA / Error
#                                Scored        denominator per -ErrorHandling
#                                Score         0-100
#                                NistControls  distinct 800-53 IDs cited
#                                ControlIds    tool control IDs contributing
#            Controls          array of per-800-53-control rows (same counts,
#                              keyed on NistControl e.g. 'AC-6(9)')
#            FamilyCount       families with at least one assessed finding
#            NistControlCount  distinct 800-53 controls cited
#            Unmapped          findings carrying no parseable NIST citation
#
# Consumes: finding FrameworkIds only. No raw data, no Graph, no EXO.
#

# NIST SP 800-53 Rev 5 control families. All 20 are listed so an identifier
# added to controls.json later still renders with its proper name instead of a
# bare two-letter code; only families actually cited are returned.
$script:NRGNistFamilyNames = [ordered]@{
    AC = 'Access Control'
    AT = 'Awareness and Training'
    AU = 'Audit and Accountability'
    CA = 'Assessment, Authorization, and Monitoring'
    CM = 'Configuration Management'
    CP = 'Contingency Planning'
    IA = 'Identification and Authentication'
    IR = 'Incident Response'
    MA = 'Maintenance'
    MP = 'Media Protection'
    PE = 'Physical and Environmental Protection'
    PL = 'Planning'
    PM = 'Program Management'
    PS = 'Personnel Security'
    PT = 'PII Processing and Transparency'
    RA = 'Risk Assessment'
    SA = 'System and Services Acquisition'
    SC = 'System and Communications Protection'
    SI = 'System and Information Integrity'
    SR = 'Supply Chain Risk Management'
}

function Get-NRGNISTControlIdsFromFinding {
    <#
        Extracts the distinct NIST 800-53 control identifiers cited by one
        finding. Returns @() when the finding carries no NIST citation, which
        is a legitimate state (Email-IR heuristics emit findings with no
        controls.json row behind them) and never an error.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowNull()]
        [object] $Finding
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ($null -eq $Finding) { return @() }

    $fwIds = Get-NRGObjectField -Item $Finding -Key 'FrameworkIds' -Default @()
    if (-not $fwIds) { return @() }

    $ids = [System.Collections.Generic.List[string]]::new()
    foreach ($entry in @($fwIds)) {
        $text = [string]$entry
        # Only the NIST namespace. Matching on the bare pattern would also
        # swallow CMMC ("IA.L2-3.5.3") and ISO ("A.5.17") citations.
        if ($text -notmatch '^\s*NIST\s*:') { continue }
        $payload = $text -replace '^\s*NIST\s*:\s*', ''
        foreach ($part in ($payload -split ',')) {
            $token = $part.Trim()
            if (-not $token) { continue }
            # AC-2, AC-2(3), SC-8(1) — family, base number, optional enhancement.
            if ($token -match '^([A-Z]{2})-(\d{1,3})(\(\d{1,3}\))?$') {
                # Read the captures we know participated BEFORE any further
                # -match overwrites $Matches. The enhancement suffix is
                # re-derived from the token rather than read out of the
                # optional capture group: $Matches carries no key for a group
                # that did not participate, and under StrictMode a missing key
                # throws rather than yielding $null.
                $fam  = $Matches[1]
                $base = [int]$Matches[2]
                $enh  = ''
                if ($token -match '(\(\d{1,3}\))$') { $enh = $Matches[1] }
                $norm = "$fam-$base$enh"
                if (-not $ids.Contains($norm)) { $ids.Add($norm) }
            }
        }
    }
    return $ids.ToArray()
}

function Get-NRGNISTFamilyCoverage {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Findings,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Exclude','Gap')]
        [string] $ErrorHandling = 'Gap'
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # family -> list of findings; nistControl -> list of findings
    $byFamily  = [ordered]@{}
    $byControl = [ordered]@{}
    # family -> distinct 800-53 IDs, family -> distinct tool control IDs
    $famNist   = @{}
    $famCtrl   = @{}
    $unmapped  = 0

    foreach ($f in $Findings) {
        if ($null -eq $f) { continue }

        # Wrap in @(): a PowerShell function returning an empty array yields
        # $null to the caller once the pipeline unrolls it, and .Count on $null
        # under StrictMode is not a safe read.
        $nistIds = @(Get-NRGNISTControlIdsFromFinding -Finding $f)
        if ($nistIds.Count -eq 0) { $unmapped++; continue }

        $toolId = [string](Get-NRGObjectField -Item $f -Key 'ControlId' -Default '')

        # Distinct families for THIS finding — "IA-2, IA-5(1)" must not count
        # the finding twice against IA.
        $fams = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($nid in $nistIds) {
            $fam = ($nid -split '-')[0]
            [void]$fams.Add($fam)

            if (-not $byControl.Contains($nid)) {
                $byControl[$nid] = [System.Collections.Generic.List[object]]::new()
            }
            $byControl[$nid].Add($f)
        }

        foreach ($fam in $fams) {
            if (-not $byFamily.Contains($fam)) {
                $byFamily[$fam] = [System.Collections.Generic.List[object]]::new()
                $famNist[$fam]  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
                $famCtrl[$fam]  = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
            }
            $byFamily[$fam].Add($f)
            foreach ($nid in $nistIds) {
                if (($nid -split '-')[0] -eq $fam) { [void]$famNist[$fam].Add($nid) }
            }
            if ($toolId) { [void]$famCtrl[$fam].Add($toolId) }
        }
    }

    $families = [System.Collections.Generic.List[object]]::new()
    foreach ($fam in ($byFamily.Keys | Sort-Object)) {
        $group = @($byFamily[$fam])
        $cov   = Get-NRGCoverageScore -Findings $group -ErrorHandling $ErrorHandling
        $name  = if ($script:NRGNistFamilyNames.Contains($fam)) { $script:NRGNistFamilyNames[$fam] } else { $fam }
        $families.Add([ordered]@{
            Family       = $fam
            Name         = $name
            Assessed     = $cov.Total
            Satisfied    = $cov.Satisfied
            Partial      = $cov.Partial
            Gap          = $cov.Gap
            NA           = $cov.NA
            Error        = $cov.Error
            Scored       = $cov.Scored
            Score        = $cov.Score
            NistControls = @($famNist[$fam] | Sort-Object)
            ControlIds   = @($famCtrl[$fam] | Sort-Object)
        })
    }

    $controls = [System.Collections.Generic.List[object]]::new()
    foreach ($nid in ($byControl.Keys | Sort-Object)) {
        $group = @($byControl[$nid])
        $cov   = Get-NRGCoverageScore -Findings $group -ErrorHandling $ErrorHandling
        $fam   = ($nid -split '-')[0]
        $controls.Add([ordered]@{
            NistControl = $nid
            Family      = $fam
            FamilyName  = $(if ($script:NRGNistFamilyNames.Contains($fam)) { $script:NRGNistFamilyNames[$fam] } else { $fam })
            Assessed    = $cov.Total
            Satisfied   = $cov.Satisfied
            Partial     = $cov.Partial
            Gap         = $cov.Gap
            NA          = $cov.NA
            Error       = $cov.Error
            Scored      = $cov.Scored
            Score       = $cov.Score
            ControlIds  = @($group | ForEach-Object {
                                [string](Get-NRGObjectField -Item $_ -Key 'ControlId' -Default '')
                            } | Where-Object { $_ } | Sort-Object -Unique)
        })
    }

    [ordered]@{
        Families         = $families.ToArray()
        Controls         = $controls.ToArray()
        FamilyCount      = $families.Count
        NistControlCount = $controls.Count
        Unmapped         = $unmapped
    }
}
