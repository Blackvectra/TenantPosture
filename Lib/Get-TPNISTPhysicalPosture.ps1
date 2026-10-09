#Requires -Version 7.0
#
# Get-TPNISTPhysicalPosture.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Joins Config/nist-physical.json — the physical, media, maintenance
#          and endpoint-device 800-53 controls, with implementation options for
#          each — against the assessment's findings, so the report can state
#          plainly which of those controls this tool actually evidenced and
#          which the assessor still has to collect off-tenant.
#
#          A Microsoft 365 tenant scan can say a great deal about endpoint
#          posture (encryption, patch level, screen lock, EDR) and nothing at
#          all about a locked server room, a certificate of destruction, or a
#          returned badge. Those are real NIST controls that a client working an
#          800-53 or CMMC assessment must satisfy, and the failure mode this
#          function exists to prevent is a report that quietly omits them —
#          leaving a reader to infer from a clean NIST family table that the
#          physical families were assessed and passed.
#
#          So every item carries an explicit Scope:
#            Tenant   — fully evidenced by controls scored in this assessment.
#            Hybrid   — the tenant evidences part; the rest is off-tenant.
#            Attested — not observable from Microsoft 365 under any
#                       configuration. NEVER reports a compliance state. This is
#                       the same rule as "advisory controls never claim
#                       compliance" in CLAUDE.md, applied to an entire section:
#                       a control the tool cannot check must not contribute a
#                       verdict, and must not contribute to any score.
#
#          Nothing here feeds the compliance score. Tenant/Hybrid items reflect
#          findings that are ALREADY scored under their own control IDs;
#          counting them again would double-count. Attested items were never
#          assessed. The section is a coverage-and-options statement, not a
#          second scoreboard.
#
# Inputs:  -Findings   assessment findings (shape-agnostic).
#          -ConfigPath optional override for Config/nist-physical.json.
#
# Outputs: [ordered] hashtable:
#            Groups     array of groups, each with Id/Title/Description and
#                       Items, where each item adds to its config row:
#                         Status        'Met' | 'Partial' | 'Gap' |
#                                       'Not assessed' | 'Attestation required'
#                         Evidence      per-control {ControlId,State,Title}
#                         Satisfied/Partial/Gap/NA counts over Evidence
#            TenantItems / HybridItems / AttestedItems  counts
#            AttestationCount   items needing assessor-collected evidence
#            Available          $false when the config could not be loaded
#
# Consumes: findings + Config/nist-physical.json. No raw data, no Graph, no EXO.
#

# Module-scope cache. Declared explicitly: Set-StrictMode -Version Latest is
# active module-wide, and reading an undeclared variable throws rather than
# yielding $null.
$script:TPNistPhysical = $null

function Get-TPNISTPhysicalDefinitions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $ConfigPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ($script:TPNistPhysical -and -not $ConfigPath) { return $script:TPNistPhysical }

    $moduleRoot = $PSScriptRoot ? (Split-Path -Parent $PSScriptRoot) : (Get-Location).Path
    $path = if ($ConfigPath) { $ConfigPath } else { Join-Path $moduleRoot 'Config' 'nist-physical.json' }

    if (-not (Test-Path -LiteralPath $path)) {
        Write-Verbose "nist-physical.json not found at $path — physical/device section unavailable."
        return $null
    }

    # Same containment check the other config loaders apply: a config path that
    # resolves outside the module root is not a config file, it is an attempt to
    # have the tool read something else.
    if (-not $ConfigPath) {
        $resolved     = [System.IO.Path]::GetFullPath($path)
        $resolvedRoot = [System.IO.Path]::GetFullPath($moduleRoot)
        if (-not $resolved.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "nist-physical.json resolved outside module root: $resolved"
        }
    }

    try {
        $json = Get-Content -LiteralPath $path -Raw -Encoding utf8 -ErrorAction Stop
        $data = $json | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Write-Warning "Failed to load nist-physical.json: $($_.Exception.Message)"
        return $null
    }

    if (-not $ConfigPath) { $script:TPNistPhysical = $data }
    return $data
}

function Get-TPNISTPhysicalPosture {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]] $Findings,

        [Parameter(Mandatory = $false)]
        [string] $ConfigPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $empty = [ordered]@{
        Groups = @(); TenantItems = 0; HybridItems = 0; AttestedItems = 0
        AttestationCount = 0; Available = $false
    }

    $defs = if ($ConfigPath) {
        Get-TPNISTPhysicalDefinitions -ConfigPath $ConfigPath
    } else {
        Get-TPNISTPhysicalDefinitions
    }
    if (-not $defs) { return $empty }
    if (-not @(Get-TPObjectField -Item $defs -Key 'groups' -Default @())) { return $empty }

    # ControlId -> finding, for the evidence join.
    $byId = @{}
    foreach ($f in $Findings) {
        if ($null -eq $f) { continue }
        $cid = [string](Get-TPObjectField -Item $f -Key 'ControlId' -Default '')
        if ($cid) { $byId[$cid] = $f }
    }

    $groups   = [System.Collections.Generic.List[object]]::new()
    $nTenant  = 0; $nHybrid = 0; $nAttested = 0; $nAttestation = 0

    # Every field is read through Get-TPObjectField: this is a hand-edited
    # config file, StrictMode is active, and a group missing Items would
    # otherwise abort the whole section rather than skipping one group.
    foreach ($g in @(Get-TPObjectField -Item $defs -Key 'groups' -Default @())) {
        $items = [System.Collections.Generic.List[object]]::new()

        foreach ($it in @(Get-TPObjectField -Item $g -Key 'Items' -Default @())) {
            $scope = [string](Get-TPObjectField -Item $it -Key 'Scope' -Default 'Attested')
            $evIds = @(Get-TPObjectField -Item $it -Key 'EvidenceControls' -Default @())

            $evidence = [System.Collections.Generic.List[object]]::new()
            $sat = 0; $part = 0; $gap = 0; $na = 0; $absent = 0
            foreach ($cid in $evIds) {
                $key = [string]$cid
                if (-not $byId.ContainsKey($key)) {
                    # The control exists in controls.json but produced no
                    # finding this run — a skipped workload, most often. That
                    # is not evidence of anything, so it is tracked separately
                    # from a NotApplicable verdict the evaluator actually made.
                    # An Error state lands here too (via the switch default
                    # below): a thrown evaluator has produced no verdict either,
                    # and must not be read as any kind of result.
                    $absent++
                    $evidence.Add([ordered]@{ ControlId = $key; State = 'NotRun'; Title = '' })
                    continue
                }
                $f = $byId[$key]
                $st = [string](Get-TPObjectField -Item $f -Key 'State' -Default '')
                $evidence.Add([ordered]@{
                    ControlId = $key
                    State     = $st
                    Title     = [string](Get-TPObjectField -Item $f -Key 'Title' -Default '')
                })
                switch ($st) {
                    'Satisfied'     { $sat++ }
                    'Partial'       { $part++ }
                    'Gap'           { $gap++ }
                    'NotApplicable' { $na++ }
                    default         { $absent++ }
                }
            }

            # Status. An Attested item never receives a compliance verdict, no
            # matter what evidence happens to be attached — that is the whole
            # point of the scope. Anything else is derived only from findings
            # that were genuinely produced this run.
            $assessed = $sat + $part + $gap
            $status =
                if ($scope -eq 'Attested')  { 'Attestation required' }
                elseif ($assessed -eq 0)    { 'Not assessed' }
                elseif ($gap -eq 0 -and $part -eq 0) { 'Met' }
                elseif ($sat -eq 0 -and $part -eq 0) { 'Gap' }
                else { 'Partial' }

            switch ($scope) {
                'Tenant'   { $nTenant++ }
                'Hybrid'   { $nHybrid++; $nAttestation++ }
                default    { $nAttested++; $nAttestation++ }
            }

            $items.Add([ordered]@{
                NistControl       = [string](Get-TPObjectField -Item $it -Key 'NistControl'  -Default '')
                NistTitle         = [string](Get-TPObjectField -Item $it -Key 'NistTitle'    -Default '')
                Scope             = $scope
                DeviceAspect      = [string](Get-TPObjectField -Item $it -Key 'DeviceAspect' -Default '')
                OffTenantEvidence = [string](Get-TPObjectField -Item $it -Key 'OffTenantEvidence' -Default '')
                Options           = @(Get-TPObjectField -Item $it -Key 'Options' -Default @())
                Status            = $status
                Evidence          = $evidence.ToArray()
                Satisfied         = $sat
                Partial           = $part
                Gap               = $gap
                NA                = $na
                NotRun            = $absent
            })
        }

        $groups.Add([ordered]@{
            Id          = [string](Get-TPObjectField -Item $g -Key 'Id'          -Default '')
            Title       = [string](Get-TPObjectField -Item $g -Key 'Title'       -Default '')
            Description = [string](Get-TPObjectField -Item $g -Key 'Description' -Default '')
            Items       = $items.ToArray()
        })
    }

    [ordered]@{
        Groups           = $groups.ToArray()
        TenantItems      = $nTenant
        HybridItems      = $nHybrid
        AttestedItems    = $nAttested
        AttestationCount = $nAttestation
        Available        = $true
    }
}
