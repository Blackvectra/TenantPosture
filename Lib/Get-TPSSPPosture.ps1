#Requires -Version 7.0
#
# Get-TPSSPPosture.ps1
# Dependencies: Get-TPObjectField, Get-TPControlDefinitions,
#               Config/nist-800-171-r2.json, Config/device-controls.json,
#               Config/operational-impact.json
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Builds the System Security Plan view — all 110 NIST SP 800-171 Rev 2
#          requirements, each joined to whatever this assessment actually
#          evidenced, so a client working toward CMMC Level 2 can see, one row
#          at a time: is this in place, what proves it, how do we turn it on,
#          and what will that do to the business.
#
#          The join needs no mapping table. A CMMC Level 2 practice ID embeds
#          the 800-171 requirement number — IA.L2-3.5.3 is requirement 3.5.3 —
#          and every control in controls.json already carries a CMMC citation,
#          so the tenant side runs off curation that already exists. The
#          endpoint side uses the explicit Nist171 array in
#          device-controls.json, because DEV-* checks are not in controls.json
#          and carry no CMMC citation.
#
#          THE HONESTY RULE THIS FILE EXISTS TO ENFORCE. A System Security Plan
#          is a document a client signs and hands to an assessor or a prime
#          contractor. A false "implemented" in it is not a cosmetic defect —
#          it is a false claim in a compliance artifact, made under a
#          certification the client is personally attesting to. So:
#
#            * A requirement with no mapped control is NEVER derived as
#              implemented. It reports 'No automated evidence' and is counted
#              as requiring attestation. 69 of the 110 are in this state, and
#              that number is stated everywhere the posture is rendered.
#            * A mapped control that produced no finding this run (skipped
#              workload, unlicensed, evaluator error) is NotRun and contributes
#              nothing in either direction. It is never read as a pass.
#            * Even a requirement whose every mapped control is Satisfied is
#              reported as evidenced only to the extent the tool can see it.
#              Microsoft 365 does not observe the whole of 3.1.1; it observes
#              the part of 3.1.1 that lives in the tenant. Confidence records
#              which case a row is in.
#            * An answers file may assert a status the assessment cannot reach
#              — that is the legitimate purpose of an SSP — but the assertion
#              is stamped StatusSource 'Attested' / 'Inherited' and never
#              merges into the tool-verified count.
#
#          This is the "advisory controls never claim compliance" rule from
#          CLAUDE.md, applied to a document whose whole job is making claims.
#
# Inputs:  -Findings    assessment findings (shape-agnostic).
#          -Answers     optional client answers (see Get-TPSSPAnswers).
#          -ConfigPath  optional override for Config/nist-800-171-r2.json.
#          -ImpactPath  optional override for Config/operational-impact.json.
#
# Outputs: [ordered] hashtable — Requirements, Families, Summary, Available.
#
# Consumes: findings + Config/nist-800-171-r2.json + Config/controls.json +
#           Config/device-controls.json + Config/operational-impact.json.
#           No Graph, no EXO, no network.
#

# Module-scope caches. Declared explicitly — StrictMode is active module-wide
# and reading an undeclared variable throws rather than yielding $null.
$script:TPNist171Catalog = $null
$script:TPImpactCatalog  = $null

function Get-TPNIST171Catalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $ConfigPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ($script:TPNist171Catalog -and -not $ConfigPath) { return $script:TPNist171Catalog }

    $data = Get-TPSSPConfigFile -FileName 'nist-800-171-r2.json' -ConfigPath $ConfigPath
    if (-not $data) { return $null }

    if (-not $ConfigPath) { $script:TPNist171Catalog = $data }
    return $data
}

function Get-TPOperationalImpactCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $ConfigPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ($script:TPImpactCatalog -and -not $ConfigPath) { return $script:TPImpactCatalog }

    $data = Get-TPSSPConfigFile -FileName 'operational-impact.json' -ConfigPath $ConfigPath
    if (-not $data) { return $null }

    if (-not $ConfigPath) { $script:TPImpactCatalog = $data }
    return $data
}

function Get-TPSSPConfigFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $FileName,
        [Parameter(Mandatory = $false)] [string] $ConfigPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $moduleRoot = if ($script:TPModuleRoot) { $script:TPModuleRoot }
                  elseif ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot }
                  else { (Get-Location).Path }
    $path = if ($ConfigPath) { $ConfigPath } else { Join-Path $moduleRoot 'Config' $FileName }

    if (-not (Test-Path -LiteralPath $path)) {
        Write-Verbose "$FileName not found at $path."
        return $null
    }

    # Same containment check the other config loaders apply: a config path that
    # resolves outside the module root is not a config file.
    if (-not $ConfigPath) {
        $resolved     = [System.IO.Path]::GetFullPath($path)
        $resolvedRoot = [System.IO.Path]::GetFullPath($moduleRoot)
        if (-not $resolved.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw "$FileName resolved outside module root: $resolved"
        }
    }

    try {
        return (Get-Content -LiteralPath $path -Raw -Encoding utf8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop)
    } catch {
        Write-Warning "Failed to load ${FileName}: $($_.Exception.Message)"
        return $null
    }
}

function Get-TPNIST171RequirementIdsFromCmmc {
    <#
        Pulls 800-171 requirement numbers out of a CMMC citation string.

        Matched on the full practice-ID shape — two letters, a dot, L then a
        digit, a dash, then the requirement number. Never on the bare
        'd.d.d' shape: 'Req 8.3' and a dozen other citations in
        controls.json would match that, and a mis-parsed citation puts a
        control's evidence under a requirement it has nothing to do with.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowNull()] [AllowEmptyString()]
        [string] $Citation
    )

    Set-StrictMode -Version Latest
    if ([string]::IsNullOrWhiteSpace($Citation)) { return @() }

    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($m in [regex]::Matches($Citation, '\b[A-Z]{2}\.L\d-(\d+\.\d+\.\d+)\b')) {
        $id = $m.Groups[1].Value
        if (-not $out.Contains($id)) { $out.Add($id) }
    }
    return $out.ToArray()
}

function Get-TPSSPPosture {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()] [AllowEmptyCollection()]
        [object[]] $Findings,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object] $Answers,

        [Parameter(Mandatory = $false)]
        [string] $ConfigPath,

        [Parameter(Mandatory = $false)]
        [string] $ImpactPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $empty = [ordered]@{
        Requirements = @(); Families = @()
        Summary      = [ordered]@{
            Total = 0; Evidenced = 0; AttestationRequired = 0
            Implemented = 0; PartiallyImplemented = 0; NotImplemented = 0
            NotAssessed = 0; NotApplicable = 0; Inherited = 0; AttestedStatuses = 0
            ToolVerified = 0; PartialEvidence = 0; NoEvidenceCollected = 0
            AttestationOnly = 0; WithPoam = 0
        }
        Available = $false
    }

    $cat = if ($ConfigPath) { Get-TPNIST171Catalog -ConfigPath $ConfigPath } else { Get-TPNIST171Catalog }
    if (-not $cat) { return $empty }

    $reqs = @(Get-TPObjectField -Item $cat -Key 'requirements' -Default @())
    if ($reqs.Count -eq 0) { return $empty }

    $famTitles = @{}
    $famNode = Get-TPObjectField -Item $cat -Key 'families' -Default $null
    if ($famNode) {
        foreach ($p in $famNode.PSObject.Properties) { $famTitles[[string]$p.Name] = [string]$p.Value }
    }

    $impact = if ($ImpactPath) { Get-TPOperationalImpactCatalog -ConfigPath $ImpactPath } else { Get-TPOperationalImpactCatalog }

    # ── Requirement -> contributing controls ────────────────────────────────
    # Built once, from the two mapping sources. Tenant controls join through
    # their CMMC citation; endpoint controls through their explicit Nist171
    # array. A control naming a requirement that is not in the catalog is
    # dropped rather than silently creating a phantom row.
    $validIds = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($r in $reqs) { [void]$validIds.Add([string](Get-TPObjectField -Item $r -Key 'Id' -Default '')) }

    $map  = @{}   # requirement id -> list of control descriptors
    $meta = @{}   # control id     -> descriptor (title/remediation/severity/source)

    $tenantDefs = @()
    try { $tenantDefs = @(Get-TPControlDefinitions) } catch { Write-Verbose "controls.json unavailable to the SSP posture: $($_.Exception.Message)" }

    foreach ($c in $tenantDefs) {
        $cid = [string](Get-TPObjectField -Item $c -Key 'ControlId' -Default '')
        if (-not $cid) { continue }
        $refs = Get-TPObjectField -Item $c -Key 'References' -Default $null
        $cmmc = [string](Get-TPObjectField -Item $refs -Key 'CMMC' -Default '')
        $ids  = @(Get-TPNIST171RequirementIdsFromCmmc -Citation $cmmc)
        if ($ids.Count -eq 0) { continue }

        $meta[$cid] = [ordered]@{
            ControlId   = $cid
            Source      = 'Tenant'
            Title       = [string](Get-TPObjectField -Item $c -Key 'Title'       -Default '')
            Severity    = [string](Get-TPObjectField -Item $c -Key 'Severity'    -Default '')
            Remediation = [string](Get-TPObjectField -Item $c -Key 'Remediation' -Default '')
        }
        foreach ($id in $ids) {
            if (-not $validIds.Contains($id)) { continue }
            if (-not $map.ContainsKey($id)) { $map[$id] = [System.Collections.Generic.List[string]]::new() }
            if (-not $map[$id].Contains($cid)) { $map[$id].Add($cid) }
        }
    }

    $devCfg = Get-TPSSPConfigFile -FileName 'device-controls.json'
    foreach ($d in @(Get-TPObjectField -Item $devCfg -Key 'controls' -Default @())) {
        $cid = [string](Get-TPObjectField -Item $d -Key 'ControlId' -Default '')
        if (-not $cid) { continue }
        $ids = @(Get-TPObjectField -Item $d -Key 'Nist171' -Default @())
        if ($ids.Count -eq 0) { continue }

        $meta[$cid] = [ordered]@{
            ControlId   = $cid
            Source      = 'Endpoint'
            Title       = [string](Get-TPObjectField -Item $d -Key 'Title'       -Default '')
            Severity    = [string](Get-TPObjectField -Item $d -Key 'Severity'    -Default '')
            Remediation = [string](Get-TPObjectField -Item $d -Key 'Remediation' -Default '')
        }
        foreach ($id in @($ids | ForEach-Object { [string]$_ })) {
            if (-not $validIds.Contains($id)) { continue }
            if (-not $map.ContainsKey($id)) { $map[$id] = [System.Collections.Generic.List[string]]::new() }
            if (-not $map[$id].Contains($cid)) { $map[$id].Add($cid) }
        }
    }

    # ── Findings by control id ──────────────────────────────────────────────
    # One finding per control is the norm, but the per-instance evaluators
    # (DNS emits one finding per domain) can produce several for the same
    # ControlId. WORST STATE WINS — the same rule Get-TPAssessmentScope
    # applies and for the same reason: a Gap on one domain must not be
    # discarded just because a later domain came back Satisfied, or a
    # requirement backed by that control derives 'Implemented' on a tenant
    # that still has a live gap.
    $stateRank = Get-TPStateSeverityRank
    $byId = @{}
    foreach ($f in $Findings) {
        if ($null -eq $f) { continue }
        $cid = [string](Get-TPObjectField -Item $f -Key 'ControlId' -Default '')
        if (-not $cid) { continue }
        if (-not $byId.ContainsKey($cid)) { $byId[$cid] = $f; continue }
        $state     = [string](Get-TPObjectField -Item $f          -Key 'State' -Default '')
        $prevState = [string](Get-TPObjectField -Item $byId[$cid] -Key 'State' -Default '')
        $rank     = if ($stateRank.ContainsKey($state))     { $stateRank[$state] }     else { -1 }
        $prevRank = if ($stateRank.ContainsKey($prevState)) { $stateRank[$prevState] } else { -1 }
        if ($rank -gt $prevRank) { $byId[$cid] = $f }
    }

    # ── Client answers ──────────────────────────────────────────────────────
    $ansReqs = @{}
    if ($Answers) {
        $node = Get-TPObjectField -Item $Answers -Key 'Requirements' -Default $null
        if ($node -is [System.Collections.IDictionary]) {
            foreach ($k in $node.Keys) { $ansReqs[[string]$k] = $node[$k] }
        } elseif ($node) {
            foreach ($p in $node.PSObject.Properties) { $ansReqs[[string]$p.Name] = $p.Value }
        }
    }

    $rows = [System.Collections.Generic.List[object]]::new()

    foreach ($r in $reqs) {
        $id  = [string](Get-TPObjectField -Item $r -Key 'Id'     -Default '')
        $fam = [string](Get-TPObjectField -Item $r -Key 'Family' -Default '')

        # Two statements, not `$x = if (...) { @() } else { @() }`. An if-block
        # yielding an empty array enumerates it away and assigns $null, so the
        # .Count below would throw under StrictMode on every unmapped
        # requirement — which is 69 of the 110.
        $ctlIds = @()
        if ($map.ContainsKey($id)) { $ctlIds = @($map[$id]) }

        $evidence = [System.Collections.Generic.List[object]]::new()
        $sat = 0; $part = 0; $gap = 0; $na = 0; $notRun = 0
        foreach ($cid in $ctlIds) {
            $m  = $meta[$cid]
            $st = 'NotRun'
            $why = ''
            if ($byId.ContainsKey($cid)) {
                $st  = [string](Get-TPObjectField -Item $byId[$cid] -Key 'State'  -Default '')
                $why = [string](Get-TPObjectField -Item $byId[$cid] -Key 'Detail' -Default '')
            }
            switch ($st) {
                'Satisfied'     { $sat++ }
                'Partial'       { $part++ }
                'Gap'           { $gap++ }
                'NotApplicable' { $na++ }
                # An Error state lands here alongside a genuinely absent
                # finding. A thrown evaluator produced no verdict, so it must
                # not be read as a result in either direction.
                default         { $notRun++; $st = if ($st) { $st } else { 'NotRun' } }
            }
            $evidence.Add([ordered]@{
                ControlId   = $cid
                Source      = [string]$m['Source']
                Title       = [string]$m['Title']
                Severity    = [string]$m['Severity']
                State       = $st
                # Why a control produced no verdict (not licensed, declared
                # third-party EDR, not collected). A bare "NotApplicable" next
                # to an Implemented requirement read as a pass.
                Detail      = $(if ($st -ne 'Satisfied') { $why } else { '' })
                Remediation = [string]$m['Remediation']
                Impact      = Get-TPControlOperationalImpact -ControlId $cid -Catalog $impact
            })
        }

        # Evidence status — strictly what the assessment observed. 'None' is
        # its own value and never collapses into a pass.
        #
        # 'Met' requires EVERY mapped control to have passed. One Satisfied
        # control beside NotApplicable / NotRun ones (a declared third-party
        # EDR, an unlicensed feature, a collector that did not run) is
        # 'Partly assessed' — the rest of the requirement was never checked,
        # and in a document the client signs, "Implemented" for that is a
        # false statement.
        $assessed = $sat + $part + $gap
        $evidenceStatus =
            if ($ctlIds.Count -eq 0)                                  { 'None' }
            elseif ($assessed -eq 0)                                  { 'Not assessed' }
            elseif ($gap -eq 0 -and $part -eq 0 -and ($na + $notRun) -gt 0) { 'Partly assessed' }
            elseif ($gap -eq 0 -and $part -eq 0)                      { 'Met' }
            elseif ($sat -eq 0 -and $part -eq 0)                      { 'Gap' }
            else                                                      { 'Partial' }

        # Confidence — how much of the requirement the tool can actually see.
        # Even 'Tool-verified' means "every mapped control produced a real
        # verdict, and it was Satisfied", not "the requirement is fully
        # satisfied"; Microsoft 365 observes the tenant slice of a
        # requirement, never the whole of it.
        #
        # 'No evidence collected' is checked BEFORE 'Partial evidence' and is
        # its own value. A requirement whose every mapped control was skipped
        # produced nothing at all, and calling that partial evidence overstates
        # it — there is no evidence to be partial about.
        #
        # $na counts alongside $notRun here, not just $notRun. NotApplicable is
        # a control that produced no real verdict (unlicensed, uncollected,
        # advisory) — the same "the tool did not actually check this" fact as
        # NotRun, just spelled differently. A requirement with one Satisfied
        # control and seven NotApplicable ones has evidence for one eighth of
        # itself, not "every mapped control passed".
        $confidence =
            if ($ctlIds.Count -eq 0)             { 'Attestation only' }
            elseif ($assessed -eq 0)             { 'No evidence collected' }
            elseif ($notRun -gt 0 -or $na -gt 0) { 'Partial evidence' }
            else                                 { 'Tool-verified' }

        # Derived SSP status. Never 'Implemented' without evidence.
        $derived =
            switch ($evidenceStatus) {
                'Met'          { 'Implemented' }
                'Partly assessed' { 'Not assessed' }
                'Partial'      { 'Partially implemented' }
                'Gap'          { 'Not implemented' }
                'Not assessed' { 'Not assessed' }
                default        { 'No automated evidence' }
            }

        $status       = $derived
        $statusSource = if ($ctlIds.Count -eq 0) { 'None' } else { 'Assessment' }
        $narrative    = ''
        $role         = ''
        $poam         = $null
        $naReason     = ''
        $inheritedFrom = ''

        if ($ansReqs.ContainsKey($id)) {
            $a = $ansReqs[$id]
            $aStatus = [string](Get-TPObjectField -Item $a -Key 'Status' -Default '')
            $narrative = [string](Get-TPObjectField -Item $a -Key 'Narrative'       -Default '')
            $role      = [string](Get-TPObjectField -Item $a -Key 'ResponsibleRole' -Default '')
            $poam      =          Get-TPObjectField -Item $a -Key 'Poam'            -Default $null
            $naReason  = [string](Get-TPObjectField -Item $a -Key 'NotApplicableReason' -Default '')
            $inheritedFrom = [string](Get-TPObjectField -Item $a -Key 'InheritedFrom' -Default '')

            # An assertion in the answers file is the client's, not the tool's.
            # It sets the status and is stamped so no reader — and no count —
            # confuses it with something the assessment verified.
            if ($aStatus) {
                $status = $aStatus
                $statusSource =
                    if ($aStatus -eq 'Not applicable')   { 'Not applicable' }
                    elseif ($aStatus -eq 'Inherited')    { 'Inherited' }
                    elseif ($inheritedFrom)              { 'Inherited' }
                    else                                 { 'Attested' }
            }
        }

        # How to enable — the remediation for the controls that are not
        # currently passing. A requirement with nothing failing has nothing to
        # enable, and a requirement with no mapped control has no remediation
        # the tool can offer.
        $howTo = [System.Collections.Generic.List[object]]::new()
        foreach ($e in $evidence) {
            if ($e['State'] -in @('Gap', 'Partial') -and $e['Remediation']) {
                $howTo.Add([ordered]@{
                    ControlId   = [string]$e['ControlId']
                    Source      = [string]$e['Source']
                    Title       = [string]$e['Title']
                    State       = [string]$e['State']
                    Remediation = [string]$e['Remediation']
                    Impact      = $e['Impact']
                })
            }
        }

        $rows.Add([ordered]@{
            Id             = $id
            Family         = $fam
            FamilyTitle    = if ($famTitles.ContainsKey($fam)) { $famTitles[$fam] } else { '' }
            Statement      = [string](Get-TPObjectField -Item $r -Key 'Statement' -Default '')
            Objectives     = @(Get-TPObjectField -Item $r -Key 'Objectives' -Default @())
            Evidence       = $evidence.ToArray()
            EvidenceStatus = $evidenceStatus
            Confidence     = $confidence
            Status         = $status
            StatusSource   = $statusSource
            DerivedStatus  = $derived
            HowToEnable    = $howTo.ToArray()
            Narrative      = $narrative
            ResponsibleRole = $role
            Poam           = $poam
            NotApplicableReason = $naReason
            InheritedFrom  = $inheritedFrom
            MappedControls = $ctlIds.Count
            Satisfied      = $sat
            Partial        = $part
            Gap            = $gap
            NA             = $na
            NotRun         = $notRun
        })
    }

    # ── Family rollup ───────────────────────────────────────────────────────
    $families = [System.Collections.Generic.List[object]]::new()
    foreach ($famId in ($rows | ForEach-Object { $_['Family'] } | Select-Object -Unique | Sort-Object { [double](($_ -split '\.')[1]) })) {
        $fr = @($rows | Where-Object { $_['Family'] -eq $famId })
        $families.Add([ordered]@{
            Id                  = $famId
            Title               = if ($famTitles.ContainsKey($famId)) { $famTitles[$famId] } else { '' }
            Total               = $fr.Count
            Evidenced           = @($fr | Where-Object { $_['MappedControls'] -gt 0 }).Count
            AttestationRequired = @($fr | Where-Object { $_['MappedControls'] -eq 0 }).Count
            Implemented         = @($fr | Where-Object { $_['Status'] -eq 'Implemented' }).Count
            Partial             = @($fr | Where-Object { $_['Status'] -eq 'Partially implemented' }).Count
            NotImplemented      = @($fr | Where-Object { $_['Status'] -eq 'Not implemented' }).Count
            Open                = @($fr | Where-Object { $_['Status'] -in @('No automated evidence', 'Not assessed') }).Count
        })
    }

    $summary = [ordered]@{
        Total                = $rows.Count
        Evidenced            = @($rows | Where-Object { $_['MappedControls'] -gt 0 }).Count
        AttestationRequired  = @($rows | Where-Object { $_['MappedControls'] -eq 0 }).Count
        Implemented          = @($rows | Where-Object { $_['Status'] -eq 'Implemented' }).Count
        PartiallyImplemented = @($rows | Where-Object { $_['Status'] -eq 'Partially implemented' }).Count
        NotImplemented       = @($rows | Where-Object { $_['Status'] -eq 'Not implemented' }).Count
        NotAssessed          = @($rows | Where-Object { $_['Status'] -in @('No automated evidence', 'Not assessed') }).Count
        NotApplicable        = @($rows | Where-Object { $_['Status'] -eq 'Not applicable' }).Count
        Inherited            = @($rows | Where-Object { $_['StatusSource'] -eq 'Inherited' }).Count
        AttestedStatuses     = @($rows | Where-Object { $_['StatusSource'] -eq 'Attested' }).Count
        # Tool-verified STATUS: a row whose status the client asserted in the
        # answers file is theirs, however clean its evidence.
        ToolVerified         = @($rows | Where-Object { $_['Confidence'] -eq 'Tool-verified' -and $_['StatusSource'] -eq 'Assessment' }).Count
        PartialEvidence      = @($rows | Where-Object { $_['Confidence'] -eq 'Partial evidence' }).Count
        NoEvidenceCollected  = @($rows | Where-Object { $_['Confidence'] -eq 'No evidence collected' }).Count
        AttestationOnly      = @($rows | Where-Object { $_['Confidence'] -eq 'Attestation only' }).Count
        WithPoam             = @($rows | Where-Object { $null -ne $_['Poam'] }).Count
    }

    [ordered]@{
        Requirements = $rows.ToArray()
        Families     = $families.ToArray()
        Summary      = $summary
        Baseline     = [string](Get-TPObjectField -Item $cat -Key 'framework' -Default 'NIST SP 800-171 Rev 2')
        Available    = $true
    }
}

function Get-TPControlOperationalImpact {
    <#
        Resolves a control's operational impact — the "what will this do to the
        business" half of the SSP row.

        Returns $null when the control has no mapping. That is deliberate: the
        renderers print "Operational impact not documented" for a $null, and an
        undocumented impact must never render as "no impact". "No impact" is
        the answer that gets a change approved without anyone checking.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [string] $ControlId,
        [Parameter(Mandatory = $false)] [AllowNull()] [object] $Catalog
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not $Catalog) { return $null }

    $key = $null
    foreach ($section in @('controls', 'deviceControls')) {
        $node = Get-TPObjectField -Item $Catalog -Key $section -Default $null
        if (-not $node) { continue }
        $v = Get-TPObjectField -Item $node -Key $ControlId -Default $null
        if ($v) { $key = [string]$v; break }
    }
    if (-not $key) { return $null }

    $arch = Get-TPObjectField -Item (Get-TPObjectField -Item $Catalog -Key 'archetypes' -Default $null) -Key $key -Default $null
    if (-not $arch) { return $null }

    $out = [ordered]@{
        Archetype  = $key
        Effort     = [string](Get-TPObjectField -Item $arch -Key 'Effort'     -Default '')
        Summary    = [string](Get-TPObjectField -Item $arch -Key 'Summary'    -Default '')
        Users      = [string](Get-TPObjectField -Item $arch -Key 'Users'      -Default '')
        Admins     = [string](Get-TPObjectField -Item $arch -Key 'Admins'     -Default '')
        Watchouts  = [string](Get-TPObjectField -Item $arch -Key 'Watchouts'  -Default '')
        Reversible = [string](Get-TPObjectField -Item $arch -Key 'Reversible' -Default '')
        Overridden = $false
        Overrides  = [ordered]@{}
    }

    # An override is kept SEPARATE from the archetype rather than merged over
    # it. Merging produced near-duplicate blocks in the rendered document: two
    # controls sharing an archetype, one of them overriding a single field,
    # printed the whole statement twice with one sentence different. Keeping
    # them apart lets a renderer print the shared text once and attach the
    # control-specific difference to it, which is what the reader needs.
    $ov = Get-TPObjectField -Item (Get-TPObjectField -Item $Catalog -Key 'overrides' -Default $null) -Key $ControlId -Default $null
    if ($ov) {
        foreach ($f in @('Effort', 'Summary', 'Users', 'Admins', 'Watchouts', 'Reversible')) {
            $v = [string](Get-TPObjectField -Item $ov -Key $f -Default '')
            if ($v) { $out['Overrides'][$f] = $v; $out['Overridden'] = $true }
        }
    }

    return $out
}
