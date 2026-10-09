#Requires -Version 7.0
#
# Get-TPHipaaReadiness.ps1
# Dependencies: Get-TPObjectField, Get-TPControlDefinitions,
#               Get-TPSSPConfigFile,
#               Config/hipaa-security-rule.json
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Builds the HIPAA Security Rule readiness view. Every standard and
#          implementation specification of 45 CFR Part 164 Subpart C, marked
#          Required or Addressable, joined to whatever this Microsoft 365
#          assessment evidenced, so a readiness engagement starts from a list
#          that says which items the tenant scan covers and which need
#          documents, interviews or a walkthrough.
#
#          The join needs no mapping table: every control in controls.json
#          already carries a References.HIPAA citation (for example
#          "§164.312(d), §164.308(a)(4)(ii)(B)"). A citation of a standard
#          written without its "(i)" (164.308(a)(4) for the standard at
#          164.308(a)(4)(i)) means that standard. A citation outside Subpart C
#          (Breach Notification 164.4xx, Privacy 164.5xx) is counted and
#          named, never mapped; a bare Security Rule section (164.316) is
#          listed as unmatched.
#
#          The SSP's honesty rules, applied to HIPAA:
#            * An item whose requirement is a document, a process or an
#              organizational arrangement (catalog TenantEvidence 'None', with
#              the reason from the regulation text) takes no evidence from a
#              control: a citation to it is listed as cited but not counted.
#              Eight tenant-isolation controls used to cite the clearinghouse
#              specification, 164.308(a)(4)(ii)(A) (corrected; see
#              docs/HIPAA-CITATION-CORRECTIONS.md); counting such a citation
#              would print "met" for a requirement it has nothing to do with.
#            * An item no control cites is NEVER derived as met. It reports
#              'Attestation required'. That is most of the administrative,
#              physical and organizational items, the risk analysis
#              (164.308(a)(1)(ii)(A)) included, and every surface says so.
#            * A cited control that produced no finding, or an Error, is
#              NotRun and counts in neither direction.
#            * The strongest status is 'Mapped technical checks satisfied': every
#              check mapped to the item passed. A citation is not proof that
#              the checks cover the whole requirement, and no such review is
#              recorded, so the view never states regulatory fulfillment.
#            * A standard is reviewed separately from its implementation
#              specifications: its own checks passing while a specification
#              is open reads 'Mapped checks satisfied, specifications open'.
#            * Every finding's Detail is kept, Satisfied included.
#            * This is a VIEW: no findings, no score, no module state written.
#
# Inputs:  -Findings    assessment findings (shape-agnostic).
#          -ConfigPath  optional override for Config/hipaa-security-rule.json.
#
# Outputs: [ordered] hashtable — Items, Safeguards, Summary, Available.
#
# Consumes: findings + Config/hipaa-security-rule.json + Config/controls.json.
#           No Graph, no EXO, no network.
#

$script:TPHipaaCatalog = $null

# The row statuses, in one place: the publisher, the entry point and the tests
# read these rather than repeating the strings. None of them states regulatory
# fulfillment.
$script:TPHipaaStatus = [ordered]@{
    Satisfied   = 'Mapped technical checks satisfied'
    SpecsOpen   = 'Mapped checks satisfied, specifications open'
    Shortfall   = 'Technical check shortfall'
    NotAssessed = 'Not assessed'
    Attestation = 'Attestation required'
}

function Get-TPHipaaStatusNames {
    [CmdletBinding()]
    param()
    return $script:TPHipaaStatus
}

function Get-TPHipaaCatalog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)]
        [string] $ConfigPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if ($script:TPHipaaCatalog -and -not $ConfigPath) { return $script:TPHipaaCatalog }

    $data = Get-TPSSPConfigFile -FileName 'hipaa-security-rule.json' -ConfigPath $ConfigPath
    if (-not $data) { return $null }

    if (-not $ConfigPath) { $script:TPHipaaCatalog = $data }
    return $data
}

function Get-TPHipaaCitationsFromText {
    <#
        Every 45 CFR 164 paragraph cited in a References.HIPAA string, as
        "164.312(d)" style identifiers. Only the full shape is accepted: a
        section number with at least one paragraph, so a stray "164.3" or a
        PCI "Req 8.3" never becomes a citation.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()] [AllowEmptyString()]
        [string] $Citation
    )

    if ([string]::IsNullOrWhiteSpace($Citation)) { return @() }
    $ids = [System.Collections.Generic.List[string]]::new()
    # A section-level citation (164.402, 164.316) is a citation too: it is
    # reported as outside the Security Rule or unmatched, never dropped. The
    # lookahead rejects a longer number (164.3081) rather than truncating it;
    # a malformed short one (164.3) never matches.
    foreach ($m in [regex]::Matches($Citation, '164\.\d{3}(?![\d.])(?:\([0-9A-Za-z]{1,4}\))*')) {
        if (-not $ids.Contains($m.Value)) { $ids.Add($m.Value) }
    }
    return @($ids)
}

function Get-TPHipaaReadiness {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()] [AllowEmptyCollection()]
        [object[]] $Findings,

        [Parameter(Mandatory = $false)]
        [string] $ConfigPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $empty = [ordered]@{
        Items = @(); Safeguards = @()
        Summary = [ordered]@{
            Total = 0; Standards = 0; Specifications = 0; Required = 0; Addressable = 0
            Mapped = 0; EvidenceCollected = 0; AttestationRequired = 0; ChecksSatisfied = 0
            SpecificationsOpen = 0; Shortfall = 0; NotAssessed = 0
            ToolVerified = 0; OutsideSecurityRule = @(); UnmatchedCitations = @()
            NoTenantEvidence = 0; CitedNotCounted = @()
        }
        Framework = ''; Source = ''; Amendments = ''
        Available = $false
        UnavailableReason = 'hipaa-security-rule.json missing or empty'
    }

    $cat = if ($ConfigPath) { Get-TPHipaaCatalog -ConfigPath $ConfigPath } else { Get-TPHipaaCatalog }
    if (-not $cat) { return $empty }
    $items = @(Get-TPObjectField -Item $cat -Key 'items' -Default @())
    if ($items.Count -eq 0) { return $empty }

    # ── Citation -> catalog item ─────────────────────────────────────────────
    # Exact match, plus the "(i)"-less form of a standard (164.308(a)(4) for
    # the standard at 164.308(a)(4)(i)), which is how the controls cite a
    # standard as a whole.
    $byCitation = @{}
    $noTenantEvidence = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($it in $items) {
        $c = [string](Get-TPObjectField -Item $it -Key 'Citation' -Default '')
        if (-not $c) { continue }
        if ([string](Get-TPObjectField -Item $it -Key 'TenantEvidence' -Default '') -eq 'None') { [void]$noTenantEvidence.Add($c) }
        $byCitation[$c] = $c
        if ([string](Get-TPObjectField -Item $it -Key 'Kind' -Default '') -eq 'Standard' -and $c.EndsWith('(i)')) {
            $byCitation[$c.Substring(0, $c.Length - 3)] = $c
        }
    }

    $map = @{}    # catalog citation -> control ids
    $notCounted = @{}   # catalog citation -> control ids that cite it but cannot evidence it
    $meta = @{}   # control id -> title/remediation
    $outside = [System.Collections.Generic.List[string]]::new()
    $unmatched = [System.Collections.Generic.List[string]]::new()

    # Fail closed: without the control definitions every item would read
    # "Attestation required", a plausible report built on nothing.
    $defs = @()
    try { $defs = @(Get-TPControlDefinitions) } catch {
        $empty['UnavailableReason'] = "controls.json could not be loaded: $($_.Exception.Message)"
        return $empty
    }
    if (@($defs | Where-Object { $null -ne $_ }).Count -eq 0) {
        $empty['UnavailableReason'] = 'controls.json returned no control definitions'
        return $empty
    }
    foreach ($d in $defs) {
        $cid = [string](Get-TPObjectField -Item $d -Key 'ControlId' -Default '')
        if (-not $cid) { continue }
        $refs = Get-TPObjectField -Item $d -Key 'References' -Default $null
        $cites = @(Get-TPHipaaCitationsFromText -Citation ([string](Get-TPObjectField -Item $refs -Key 'HIPAA' -Default '')))
        foreach ($ci in $cites) {
            $section = ($ci -split '\(')[0]
            if ($section -notin @('164.308', '164.310', '164.312', '164.314', '164.316')) {
                $outside.Add("$cid ($ci)")
                continue
            }
            if (-not $byCitation.ContainsKey($ci)) {
                $unmatched.Add("$cid ($ci)")
                continue
            }
            $target = $byCitation[$ci]
            if ($noTenantEvidence.Contains($target)) {
                if (-not $notCounted.ContainsKey($target)) { $notCounted[$target] = [System.Collections.Generic.List[string]]::new() }
                if (-not $notCounted[$target].Contains($cid)) { $notCounted[$target].Add($cid) }
                continue
            }
            if (-not $map.ContainsKey($target)) { $map[$target] = [System.Collections.Generic.List[string]]::new() }
            if (-not $map[$target].Contains($cid)) { $map[$target].Add($cid) }
            $meta[$cid] = [ordered]@{
                Title       = [string](Get-TPObjectField -Item $d -Key 'Title'       -Default '')
                Remediation = [string](Get-TPObjectField -Item $d -Key 'Remediation' -Default '')
            }
        }
    }

    # ── Findings by control id: every instance kept ─────────────────────────
    # A control can report once per instance (DNS once per domain). Every
    # instance stays in the evidence, and the control's state for this view is
    # judged from all of them: any Gap or Partial instance is a known
    # shortfall and is never hidden behind another instance that could not be
    # evaluated (an Error is no verdict); otherwise any instance without a
    # verdict leaves the control without one; otherwise any NotApplicable;
    # Satisfied only when every instance passed.
    $byId = [ordered]@{}
    foreach ($f in @($Findings)) {
        if ($null -eq $f) { continue }
        $cid = [string](Get-TPObjectField -Item $f -Key 'ControlId' -Default '')
        if (-not $cid) { continue }
        if (-not $byId.Contains($cid)) { $byId[$cid] = [System.Collections.Generic.List[object]]::new() }
        $byId[$cid].Add($f)
    }
    $controlState = {
        param($list)
        $states = @($list | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'State' -Default '') })
        if ($states -contains 'Gap')     { return 'Gap' }
        if ($states -contains 'Partial') { return 'Partial' }
        if (@($states | Where-Object { $_ -notin @('Satisfied', 'NotApplicable') }).Count -gt 0) { return 'NotRun' }
        if ($states -contains 'NotApplicable') { return 'NotApplicable' }
        return 'Satisfied'
    }

    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($it in $items) {
        $cit = [string](Get-TPObjectField -Item $it -Key 'Citation' -Default '')

        # Two statements: an if-block yielding an empty array assigns $null.
        $ctlIds = @()
        if ($map.ContainsKey($cit)) { $ctlIds = @($map[$cit]) }
        $citedNotCounted = @()
        if ($notCounted.ContainsKey($cit)) { $citedNotCounted = @($notCounted[$cit]) }

        $evidence = [System.Collections.Generic.List[object]]::new()
        $sat = 0; $part = 0; $gap = 0; $na = 0; $notRun = 0
        foreach ($cid in $ctlIds) {
            $instances = @()
            if ($byId.Contains($cid)) { $instances = @($byId[$cid]) }
            $st = if ($instances.Count -gt 0) { & $controlState $instances } else { 'NotRun' }
            switch ($st) {
                'Satisfied'     { $sat++ }
                'Partial'       { $part++ }
                'Gap'           { $gap++ }
                'NotApplicable' { $na++ }
                # Error, absent or unrecognized: no verdict, counted in neither direction.
                default         { $notRun++ }
            }
            if ($instances.Count -eq 0) {
                $evidence.Add([ordered]@{
                    ControlId = $cid; Instance = ''; Title = [string]$meta[$cid]['Title']
                    State = 'NotRun'; Detail = ''; Remediation = ''
                })
            }
            foreach ($f in $instances) {
                $ist = [string](Get-TPObjectField -Item $f -Key 'State' -Default '')
                if (-not $ist) { $ist = 'NotRun' }
                $evidence.Add([ordered]@{
                    ControlId   = $cid
                    Instance    = [string](Get-TPObjectField -Item $f -Key 'Instance' -Default '')
                    Title       = [string]$meta[$cid]['Title']
                    State       = $ist
                    # Kept for every state and every instance, Satisfied included:
                    # a passing finding's Detail carries its qualifications (what
                    # was and was not read, partial scope), which a readiness
                    # reader must see.
                    Detail      = [string](Get-TPObjectField -Item $f -Key 'Detail' -Default '')
                    Remediation = $(if ($ist -in @('Gap', 'Partial')) { [string]$meta[$cid]['Remediation'] } else { '' })
                })
            }
        }

        $assessed = $sat + $part + $gap
        $evidenceStatus =
            if ($ctlIds.Count -eq 0)                                        { 'None' }
            elseif ($assessed -eq 0)                                        { 'Not assessed' }
            elseif ($gap -eq 0 -and $part -eq 0 -and ($na + $notRun) -gt 0) { 'Partly assessed' }
            elseif ($gap -eq 0 -and $part -eq 0)                            { 'Met' }
            elseif ($sat -eq 0 -and $part -eq 0)                            { 'Gap' }
            else                                                            { 'Partial' }

        $confidence =
            if ($ctlIds.Count -eq 0)             { 'Attestation only' }
            elseif ($assessed -eq 0)             { 'No evidence collected' }
            elseif ($notRun -gt 0 -or $na -gt 0) { 'Partial evidence' }
            else                                 { 'Tool-verified' }

        # A technical result, never a regulatory one. A citation says a check
        # bears on the item; it does not say the checks cover all of it, and no
        # coverage review has been recorded, so the strongest status is that the
        # MAPPED checks passed. Regulatory fulfillment is kept out of this view.
        $status =
            switch ($evidenceStatus) {
                'None'            { $script:TPHipaaStatus.Attestation }
                'Met'             { $script:TPHipaaStatus.Satisfied }
                'Partial'         { $script:TPHipaaStatus.Shortfall }
                'Gap'             { $script:TPHipaaStatus.Shortfall }
                default           { $script:TPHipaaStatus.NotAssessed }
            }

        $rows.Add([ordered]@{
            Citation       = $cit
            Name           = [string](Get-TPObjectField -Item $it -Key 'Name'        -Default '')
            Kind           = [string](Get-TPObjectField -Item $it -Key 'Kind'        -Default '')
            Requirement    = [string](Get-TPObjectField -Item $it -Key 'Requirement' -Default '')
            Standard       = [string](Get-TPObjectField -Item $it -Key 'Standard'    -Default '')
            Safeguard      = [string](Get-TPObjectField -Item $it -Key 'Safeguard'   -Default '')
            Text           = [string](Get-TPObjectField -Item $it -Key 'Text'        -Default '')
            TenantEvidence = [string](Get-TPObjectField -Item $it -Key 'TenantEvidence' -Default 'Possible')
            TenantEvidenceReason = [string](Get-TPObjectField -Item $it -Key 'TenantEvidenceReason' -Default '')
            CitedNotCounted = $citedNotCounted
            Evidence       = $evidence.ToArray()
            EvidenceStatus = $evidenceStatus
            Confidence     = $confidence
            Status         = $status
            MappedControls = $ctlIds.Count
            EvidenceCollected = ($assessed -gt 0)
            Satisfied = $sat; Partial = $part; Gap = $gap; NA = $na; NotRun = $notRun
            Specifications = $null
        })
    }

    # ── Standards are reviewed separately from their specifications ──────────
    # A control citing a parent standard bears on the standard as a whole and
    # says nothing about each implementation specification under it. A standard
    # whose own checks passed while any of its specifications is not
    # 'Mapped technical checks satisfied' is reported as such, never as
    # satisfied, and every standard carries its specifications' tally.
    foreach ($r in $rows) {
        if ($r['Kind'] -ne 'Standard') { continue }
        $specs = @($rows | Where-Object { $_['Kind'] -ne 'Standard' -and $_['Standard'] -eq $r['Citation'] })
        if ($specs.Count -eq 0) { continue }
        $tally = [ordered]@{ Total = $specs.Count }
        foreach ($st in @($script:TPHipaaStatus.Values)) { $tally[$st] = @($specs | Where-Object { $_['Status'] -eq $st }).Count }
        $r['Specifications'] = $tally
        if ($r['Status'] -eq $script:TPHipaaStatus.Satisfied -and $tally[$script:TPHipaaStatus.Satisfied] -lt $specs.Count) {
            $r['Status'] = $script:TPHipaaStatus.SpecsOpen
        }
    }

    $safeguards = [System.Collections.Generic.List[object]]::new()
    foreach ($sg in @($rows | ForEach-Object { $_['Safeguard'] } | Select-Object -Unique)) {
        $sr = @($rows | Where-Object { $_['Safeguard'] -eq $sg })
        $safeguards.Add([ordered]@{
            Name                = $sg
            Total               = $sr.Count
            Mapped              = @($sr | Where-Object { $_['MappedControls'] -gt 0 }).Count
            EvidenceCollected   = @($sr | Where-Object { $_['EvidenceCollected'] }).Count
            AttestationRequired = @($sr | Where-Object { $_['MappedControls'] -eq 0 }).Count
            ChecksSatisfied     = @($sr | Where-Object { $_['Status'] -eq $script:TPHipaaStatus.Satisfied }).Count
            SpecificationsOpen  = @($sr | Where-Object { $_['Status'] -eq $script:TPHipaaStatus.SpecsOpen }).Count
            Shortfall           = @($sr | Where-Object { $_['Status'] -eq $script:TPHipaaStatus.Shortfall }).Count
            NotAssessed         = @($sr | Where-Object { $_['Status'] -eq $script:TPHipaaStatus.NotAssessed }).Count
        })
    }

    $summary = [ordered]@{
        Total               = $rows.Count
        Standards           = @($rows | Where-Object { $_['Kind'] -eq 'Standard' }).Count
        Specifications      = @($rows | Where-Object { $_['Kind'] -ne 'Standard' }).Count
        Required            = @($rows | Where-Object { $_['Requirement'] -eq 'Required' }).Count
        Addressable         = @($rows | Where-Object { $_['Requirement'] -eq 'Addressable' }).Count
        # Mapped: a check bears on the item. EvidenceCollected: at least one of
        # those checks produced a verdict this run. A skipped or failed
        # collection leaves an item mapped and without evidence.
        Mapped              = @($rows | Where-Object { $_['MappedControls'] -gt 0 }).Count
        EvidenceCollected   = @($rows | Where-Object { $_['EvidenceCollected'] }).Count
        AttestationRequired = @($rows | Where-Object { $_['MappedControls'] -eq 0 }).Count
        ChecksSatisfied     = @($rows | Where-Object { $_['Status'] -eq $script:TPHipaaStatus.Satisfied }).Count
        SpecificationsOpen  = @($rows | Where-Object { $_['Status'] -eq $script:TPHipaaStatus.SpecsOpen }).Count
        Shortfall           = @($rows | Where-Object { $_['Status'] -eq $script:TPHipaaStatus.Shortfall }).Count
        NotAssessed         = @($rows | Where-Object { $_['Status'] -eq $script:TPHipaaStatus.NotAssessed }).Count
        ToolVerified        = @($rows | Where-Object { $_['Confidence'] -eq 'Tool-verified' }).Count
        OutsideSecurityRule = @($outside)
        UnmatchedCitations  = @($unmatched)
        NoTenantEvidence    = @($rows | Where-Object { $_['TenantEvidence'] -eq 'None' }).Count
        CitedNotCounted     = @($rows | Where-Object { @($_['CitedNotCounted']).Count -gt 0 } | ForEach-Object { "$($_['Citation']): $(@($_['CitedNotCounted']) -join ', ')" })
    }

    [ordered]@{
        Items      = $rows.ToArray()
        Safeguards = $safeguards.ToArray()
        Summary    = $summary
        Framework  = [string](Get-TPObjectField -Item $cat -Key 'framework'  -Default 'HIPAA Security Rule')
        Source     = [string](Get-TPObjectField -Item $cat -Key 'source'     -Default '')
        Amendments = [string](Get-TPObjectField -Item $cat -Key 'amendments' -Default '')
        CatalogVersion   = [string](Get-TPObjectField -Item $cat -Key 'version'          -Default '')
        SourceSnapshot   = [string](Get-TPObjectField -Item $cat -Key 'sourceSnapshot'   -Default '')
        SourceRetrieved  = [string](Get-TPObjectField -Item $cat -Key 'sourceRetrieved'  -Default '')
        Note       = [string](Get-TPObjectField -Item $cat -Key 'note'       -Default '')
        Available  = $true
    }
}
