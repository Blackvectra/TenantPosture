#Requires -Version 7.0
#
# Publish-NRGSSP.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: The System Security Plan — all 110 NIST SP 800-171 Rev 2
#          requirements as a worked checklist. For each one: is it in place,
#          what proves it, how do we turn it on, and what will that do to the
#          business.
#
#          That last question is the one this document exists for. Every other
#          deliverable in this repo answers "what is wrong". A client reading a
#          gap list asks one thing back — "if we fix that, what breaks?" — and
#          until now the tool had no answer, so remediation got scheduled on
#          guesswork or not scheduled at all. Config/operational-impact.json
#          holds the answer and this renders it beside every action.
#
#          Emits Markdown always, self-contained HTML alongside, and XLSX when
#          openpyxl is available. The HTML is what a client works through; the
#          Markdown is what diffs between assessments; the XLSX is what gets
#          filled in by whoever owns the 69 requirements no scan can reach.
#
#          WHAT THIS DOCUMENT IS NOT. It is not a completed SSP. 41 of the 110
#          requirements have automated evidence here; the other 69 are policy,
#          process, physical and personnel, and they are answered by the client
#          in Config/ssp/<client>.psd1, not by a scan. Every surface in this
#          publisher states that split, and a requirement with no evidence and
#          no answer renders as an open question rather than as anything else.
#          A false 'Implemented' in an SSP is a false statement in a document
#          the client signs and hands to an assessor.
#
# Inputs:  -Posture     output of Get-NRGSSPPosture.
#          -OutputPath  .md path. HTML and XLSX written alongside.
#          -Metadata    tenant domain, assessment date, tool version.
#          -Answers     output of Get-NRGSSPAnswers, for the system narrative.
#          -ClientName  optional; titles the document.
#
# Consumes: the posture only. No Graph, no EXO, no network.
#

function Get-NRGSSPImpactLabel {
    <# Field name to the words a reader wants to see beside it. #>
    [CmdletBinding()]
    param([Parameter(Mandatory, Position = 0)] [string] $Field)
    switch ($Field) {
        'Summary'    { 'in short' }
        'Users'      { 'users' }
        'Admins'     { 'administrators' }
        'Watchouts'  { 'watch out for' }
        'Reversible' { 'reversible' }
        default      { $Field.ToLowerInvariant() }
    }
}

function Group-NRGSSPImpact {
    <#
        Collapses a requirement's remediation actions into one impact block per
        archetype.

        A requirement can map to fifteen controls, and half of them share an
        operational impact — blocking legacy auth, disabling POP3, disabling
        IMAP and disabling SMTP AUTH all break the same class of old client in
        the same way. Printing that statement four times is noise that trains
        the reader to skip the section, which is the one section they most need
        to read before approving a change.

        So the shared statement prints once, naming every control it covers,
        and a control-specific override attaches to it as a short "AAD-1.2
        specifically" line rather than duplicating the whole block with one
        sentence different.

        Returns, per archetype: Base (the shared statement), ControlIds (every
        control it covers), Specifics (per-control override fields).
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()] [AllowEmptyCollection()]
        [object[]] $Actions
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $order  = [System.Collections.Generic.List[string]]::new()
    $groups = @{}

    foreach ($a in $Actions) {
        if ($null -eq $a) { continue }
        $im = $a['Impact']
        if (-not $im) { continue }
        $key = [string]$im['Archetype']
        if (-not $groups.ContainsKey($key)) {
            $order.Add($key)
            $groups[$key] = [ordered]@{
                Archetype  = $key
                Base       = $im
                ControlIds = [System.Collections.Generic.List[string]]::new()
                Specifics  = [System.Collections.Generic.List[object]]::new()
            }
        }
        $g = $groups[$key]
        $cid = [string]$a['ControlId']
        if (-not $g['ControlIds'].Contains($cid)) { $g['ControlIds'].Add($cid) }
        if ($im['Overridden'] -and @($im['Overrides'].Keys).Count -gt 0) {
            $g['Specifics'].Add([ordered]@{ ControlId = $cid; Fields = $im['Overrides'] })
        }
    }

    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $order) {
        $g = $groups[$k]
        $out.Add([ordered]@{
            Archetype  = $g['Archetype']
            Base       = $g['Base']
            ControlIds = $g['ControlIds'].ToArray()
            Specifics  = $g['Specifics'].ToArray()
        })
    }
    return $out.ToArray()
}

function Publish-NRGSSP {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Collections.Specialized.OrderedDictionary] $Posture,

        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -match '\.\.[\\\/]') { throw 'Path traversal not allowed.' }
            return $true
        })]
        [string] $OutputPath,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [hashtable] $Metadata,

        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object] $Answers,

        [Parameter(Mandatory = $false)]
        [AllowNull()] [AllowEmptyString()]
        [string] $ClientName
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    if (-not $Posture['Available']) {
        Write-Warning 'SSP posture unavailable (nist-800-171-r2.json missing or empty) — SSP not generated.'
        return
    }

    function EscMd { param([object]$v) ([string]$v) -replace '\|', '\|' -replace '[\r\n]+', ' ' }
    function Esc   { param([object]$v) ConvertTo-NRGHtmlSafe $v }

    $reqs     = @($Posture['Requirements'])
    $families = @($Posture['Families'])
    $sum      = $Posture['Summary']

    $brand   = if ($script:NRGBrand) { $script:NRGBrand } else { @{} }
    $company = if ($brand['CompanyName']) { [string]$brand['CompanyName'] } else { 'NRG Technology Services' }

    $tenant  = [string](Get-NRGObjectField -Item $Metadata -Key 'TenantDomain'   -Default '')
    $date    = [string](Get-NRGObjectField -Item $Metadata -Key 'AssessmentDate' -Default (Get-Date -Format 'yyyy-MM-dd'))
    $version = [string](Get-NRGObjectField -Item $Metadata -Key 'ToolVersion'    -Default '')

    $sysNode = Get-NRGObjectField -Item $Answers -Key 'System' -Default @{}
    $sysName = [string](Get-NRGObjectField -Item $sysNode -Key 'Name' -Default '')
    if (-not $sysName) { $sysName = if ($ClientName) { "$ClientName Microsoft 365 Environment" } elseif ($tenant) { "$tenant Microsoft 365 Environment" } else { 'Microsoft 365 Environment' } }

    $title = 'System Security Plan'
    if ($ClientName) { $title = "System Security Plan — $ClientName" }
    elseif ($tenant)  { $title = "System Security Plan — $tenant" }

    $answersAvailable = [bool](Get-NRGObjectField -Item $Answers -Key 'Available' -Default $false)

    # Requirements needing a written answer: no automated evidence AND no
    # narrative supplied. This is the worklist, and it is stated up front
    # rather than buried, because an SSP with 69 blanks is not a finished
    # document and a reader must not be able to mistake it for one.
    $needAnswer = @($reqs | Where-Object {
        $_['MappedControls'] -eq 0 -and -not $_['Narrative'] -and $_['StatusSource'] -eq 'None'
    })
    $withPoam = @($reqs | Where-Object { $null -ne $_['Poam'] })

    # ─────────────────────────────────────────────────────────────────────────
    # Markdown
    # ─────────────────────────────────────────────────────────────────────────
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("# $(EscMd $title)")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**Baseline:** $(EscMd $Posture['Baseline'])  ")
    $null = $sb.AppendLine("**System:** $(EscMd $sysName)  ")
    if ($tenant)  { $null = $sb.AppendLine("**Tenant:** $(EscMd $tenant)  ") }
    $null = $sb.AppendLine("**Assessed by:** $(EscMd $company)  ")
    $null = $sb.AppendLine("**Date:** $(EscMd $date)  ")
    if ($version) { $null = $sb.AppendLine("**Tool version:** $(EscMd $version)  ") }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('## Read this first')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("This is a **working System Security Plan, not a finished one**. Of the $($sum['Total']) requirements in $(EscMd $Posture['Baseline']), this assessment observed **$($sum['Evidenced'])** from the Microsoft 365 tenant and the endpoints. The remaining **$($sum['AttestationRequired'])** are policy, process, physical security and personnel — no scan reaches them, and they are answered by the organization, not by the tool.")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**$($needAnswer.Count) requirements are still unanswered.** They are listed at the end. Until each one carries a status and a narrative, this document is incomplete, and an assessor will read a blank as a gap.")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("Where the assessment reports a requirement implemented, every control this tool maps to it produced a verdict and passed — which is still not the requirement satisfied in full. Microsoft 365 observes the tenant slice of a requirement and nothing outside it. The **Confidence** column says which case each row is in.")
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('### Where the plan stands')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('| Status | Count |')
    $null = $sb.AppendLine('|---|---:|')
    foreach ($pair in @(
        @('Implemented',                    $sum['Implemented']),
        @('Partially implemented',          $sum['PartiallyImplemented']),
        @('Not implemented',                $sum['NotImplemented']),
        @('Unanswered / not assessed',      $sum['NotAssessed']),
        @('Inherited from a provider',      $sum['Inherited']),
        @('Not applicable',                 $sum['NotApplicable']))) {
        $null = $sb.AppendLine("| $($pair[0]) | $($pair[1]) |")
    }
    $null = $sb.AppendLine("| **Total** | **$($sum['Total'])** |")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("Of those, **$($sum['ToolVerified'])** are tool-verified, **$($sum['PartialEvidence'])** rest on partial evidence, **$($sum['NoEvidenceCollected'])** map to controls that produced no result this run, and **$($sum['AttestationOnly'])** have no automated evidence at all. **$($sum['AttestedStatuses'])** statuses are client-attested — asserted in the answers file, not verified here.")
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('### By family')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('| Family | Requirements | Evidenced here | Answered by you | Implemented | Partial | Not implemented | Open |')
    $null = $sb.AppendLine('|---|---:|---:|---:|---:|---:|---:|---:|')
    foreach ($f in $families) {
        $null = $sb.AppendLine("| $(EscMd $f['Id']) $(EscMd $f['Title']) | $($f['Total']) | $($f['Evidenced']) | $($f['AttestationRequired']) | $($f['Implemented']) | $($f['Partial']) | $($f['NotImplemented']) | $($f['Open']) |")
    }
    $null = $sb.AppendLine()

    $null = $sb.AppendLine('---')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('## The checklist')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('One line per requirement. Tick what is in place; everything unticked is either work to do or a question to answer.')
    $null = $sb.AppendLine()
    foreach ($f in $families) {
        $null = $sb.AppendLine("**$(EscMd $f['Id']) $(EscMd $f['Title'])**")
        $null = $sb.AppendLine()
        foreach ($r in @($reqs | Where-Object { $_['Family'] -eq $f['Id'] })) {
            $tick = if ($r['Status'] -in @('Implemented', 'Inherited', 'Not applicable')) { 'x' } else { ' ' }
            $bt = [char]0x60
            $null = $sb.AppendLine("- [$tick] $bt$(EscMd $r['Id'])$bt $(EscMd $r['Statement']) — _$(EscMd $r['Status'])_")
        }
        $null = $sb.AppendLine()
    }

    $null = $sb.AppendLine('---')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('## Requirement detail')
    $null = $sb.AppendLine()

    foreach ($f in $families) {
        $null = $sb.AppendLine("### $(EscMd $f['Id']) $(EscMd $f['Title'])")
        $null = $sb.AppendLine()

        foreach ($r in @($reqs | Where-Object { $_['Family'] -eq $f['Id'] })) {
            $null = $sb.AppendLine("#### $(EscMd $r['Id'])")
            $null = $sb.AppendLine()
            $null = $sb.AppendLine("$(EscMd $r['Statement'])")
            $null = $sb.AppendLine()

            $srcNote = switch ($r['StatusSource']) {
                'Assessment'     { 'from this assessment' }
                'Attested'       { '**client-attested** — asserted in the answers file, not verified by the assessment' }
                'Inherited'      { "inherited from $(EscMd $r['InheritedFrom'])" }
                'Not applicable' { 'declared not applicable' }
                default          { 'not answered' }
            }
            # An attested/inherited status is the client's claim, not the
            # tool's. When the assessment's own evidence derived a different
            # status, printing the tool's Confidence next to the attested
            # claim reads as the tool having verified that claim — it did
            # not. Say what the assessment actually found instead of letting
            # Confidence imply agreement it never gave.
            $attestedConflict = $r['StatusSource'] -in @('Attested', 'Inherited') -and
                $r['DerivedStatus'] -ne $r['Status'] -and
                $r['DerivedStatus'] -notin @('No automated evidence', 'Not assessed')
            $confNote = if ($attestedConflict) { 'not applicable — see assessment finding below' } else { $r['Confidence'] }
            $null = $sb.AppendLine("**In place?** $(EscMd $r['Status']) — $srcNote. Confidence: $(EscMd $confNote).")
            if ($attestedConflict) {
                $null = $sb.AppendLine("**Assessment found:** $(EscMd $r['DerivedStatus']). The automated evidence below disagrees with the status above — that status is the client's attestation, not something this assessment verified.")
            }
            $null = $sb.AppendLine()

            if ($r['NotApplicableReason']) {
                $null = $sb.AppendLine("**Why not applicable.** $(EscMd $r['NotApplicableReason'])")
                $null = $sb.AppendLine()
            }
            if ($r['ResponsibleRole']) {
                $null = $sb.AppendLine("**Responsible role.** $(EscMd $r['ResponsibleRole'])")
                $null = $sb.AppendLine()
            }

            if ($r['Narrative']) {
                $null = $sb.AppendLine("**How it is done here.** $(EscMd $r['Narrative'])")
            } elseif ($r['MappedControls'] -eq 0) {
                $null = $sb.AppendLine('**How it is done here.** _Not written yet. This requirement has no automated evidence — it needs a narrative in the answers file before the plan is complete._')
            } else {
                $null = $sb.AppendLine('**How it is done here.** _No narrative supplied. The evidence below stands on its own, but an assessor will want the description too._')
            }
            $null = $sb.AppendLine()

            if (@($r['Objectives']).Count -gt 0) {
                $null = $sb.AppendLine('**Assessment objectives (SP 800-171A).** An assessor works these one at a time.')
                $null = $sb.AppendLine()
                foreach ($o in @($r['Objectives'])) {
                    $lbl = [string](Get-NRGObjectField -Item $o -Key 'Label' -Default '')
                    $txt = [string](Get-NRGObjectField -Item $o -Key 'Text'  -Default '')
                    $null = $sb.AppendLine("- [ ] **$(EscMd $lbl)** $(EscMd $txt)")
                }
                $null = $sb.AppendLine()
            }

            $ev = @($r['Evidence'])
            if ($ev.Count -gt 0) {
                $null = $sb.AppendLine('**Evidence from this assessment.**')
                $null = $sb.AppendLine()
                $null = $sb.AppendLine('| Control | Source | Result | What it checks |')
                $null = $sb.AppendLine('|---|---|---|---|')
                foreach ($e in $ev) {
                    $null = $sb.AppendLine("| $(EscMd $e['ControlId']) | $(EscMd $e['Source']) | $(EscMd $e['State']) | $(EscMd $e['Title']) |")
                }
                $null = $sb.AppendLine()
                $unscored = [int]$r['NotRun'] + [int](Get-NRGObjectField -Item $r -Key 'NA' -Default 0)
                if ($unscored -gt 0) {
                    $null = $sb.AppendLine("_$unscored of the $($ev.Count) mapped controls produced no verdict this run — not collected, not licensed, declared to a third-party product, or not programmatically checkable. Those are not passes and not failures; they are unknowns, so this requirement is not reported implemented on their account._")
                    $null = $sb.AppendLine()
                    foreach ($e in @($ev | Where-Object { $_['State'] -notin @('Satisfied','Partial','Gap') -and $_['Detail'] })) {
                        $null = $sb.AppendLine("- $(EscMd $e['ControlId']): $(EscMd $e['Detail'])")
                    }
                    $null = $sb.AppendLine()
                }
            } else {
                $null = $sb.AppendLine('**Evidence from this assessment.** None. Nothing in a Microsoft 365 tenant or an endpoint scan evidences this requirement — it is satisfied by policy, process, physical control or personnel practice, and the evidence is whatever the organization retains.')
                $null = $sb.AppendLine()
            }

            $how = @($r['HowToEnable'])
            if ($how.Count -gt 0) {
                $null = $sb.AppendLine('**How to close it.**')
                $null = $sb.AppendLine()
                foreach ($h in $how) {
                    $null = $sb.AppendLine("- **$(EscMd $h['ControlId']) — $(EscMd $h['Title'])** ($(EscMd $h['State'])). $(EscMd $h['Remediation'])")
                }
                $null = $sb.AppendLine()

                $groups = Group-NRGSSPImpact -Actions $how
                $undocumented = @($how | Where-Object { -not $_['Impact'] })

                $null = $sb.AppendLine('**What that will affect.**')
                $null = $sb.AppendLine()
                foreach ($g in $groups) {
                    $im = $g['Base']
                    $null = $sb.AppendLine("- **$(EscMd $im['Summary'])** _($(EscMd (($g['ControlIds']) -join ', ')))_")
                    if ($im['Users'])      { $null = $sb.AppendLine("    - _Users:_ $(EscMd $im['Users'])") }
                    if ($im['Admins'])     { $null = $sb.AppendLine("    - _Administrators:_ $(EscMd $im['Admins'])") }
                    if ($im['Watchouts'])  { $null = $sb.AppendLine("    - _Watch out for:_ $(EscMd $im['Watchouts'])") }
                    if ($im['Reversible']) { $null = $sb.AppendLine("    - _Reversible:_ $(EscMd $im['Reversible'])") }
                    foreach ($o in @($g['Specifics'])) {
                        foreach ($k in $o['Fields'].Keys) {
                            $null = $sb.AppendLine("    - _$(EscMd $o['ControlId']) specifically — $(EscMd (Get-NRGSSPImpactLabel $k)):_ $(EscMd $o['Fields'][$k])")
                        }
                    }
                }
                if ($undocumented.Count -gt 0) {
                    $null = $sb.AppendLine("- _Operational impact not documented for $(EscMd ((@($undocumented | ForEach-Object { $_['ControlId'] })) -join ', ')). Assess the effect before scheduling — an undocumented impact is not the same as no impact._")
                }
                $null = $sb.AppendLine()
            }

            if ($null -ne $r['Poam']) {
                $p = $r['Poam']
                $null = $sb.AppendLine('**Plan of action and milestones.**')
                $null = $sb.AppendLine()
                foreach ($fld in @('Weakness', 'Remedy', 'Owner', 'DueDate', 'Resources')) {
                    $v = [string](Get-NRGObjectField -Item $p -Key $fld -Default '')
                    if ($v) { $null = $sb.AppendLine("- **$fld.** $(EscMd $v)") }
                }
                $null = $sb.AppendLine()
            }
        }
    }

    if ($withPoam.Count -gt 0) {
        $null = $sb.AppendLine('---')
        $null = $sb.AppendLine()
        $null = $sb.AppendLine('## Plan of action and milestones')
        $null = $sb.AppendLine()
        $null = $sb.AppendLine('| Requirement | Weakness | Remedy | Owner | Due |')
        $null = $sb.AppendLine('|---|---|---|---|---|')
        foreach ($r in $withPoam) {
            $p = $r['Poam']
            $null = $sb.AppendLine("| $(EscMd $r['Id']) | $(EscMd (Get-NRGObjectField -Item $p -Key 'Weakness' -Default '')) | $(EscMd (Get-NRGObjectField -Item $p -Key 'Remedy' -Default '')) | $(EscMd (Get-NRGObjectField -Item $p -Key 'Owner' -Default '')) | $(EscMd (Get-NRGObjectField -Item $p -Key 'DueDate' -Default '')) |")
        }
        $null = $sb.AppendLine()
    }

    $null = $sb.AppendLine('---')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('## Still to answer')
    $null = $sb.AppendLine()
    if ($needAnswer.Count -eq 0) {
        $null = $sb.AppendLine('Every requirement without automated evidence carries a written answer. The plan is complete in that respect — review the narratives for accuracy, not for gaps.')
    } else {
        $null = $sb.AppendLine("$($needAnswer.Count) requirements have neither automated evidence nor a written answer. Each needs a status and a narrative in the answers file$(if ($answersAvailable) { " ($(EscMd (Get-NRGObjectField -Item $Answers -Key 'Path' -Default ''))) " } else { ' — no answers file was supplied for this run' }).")
        $null = $sb.AppendLine()
        $null = $sb.AppendLine('| Requirement | Family | What it asks |')
        $null = $sb.AppendLine('|---|---|---|')
        foreach ($r in $needAnswer) {
            $null = $sb.AppendLine("| $(EscMd $r['Id']) | $(EscMd $r['FamilyTitle']) | $(EscMd $r['Statement']) |")
        }
    }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine('---')
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("_Prepared by $(EscMd $company). This plan records the state of the system on $(EscMd $date). Statuses marked client-attested were asserted by the organization and not verified by the assessment; statuses drawn from the assessment reflect what the tool could observe in the Microsoft 365 tenant and on scanned endpoints, which is a subset of each requirement._")

    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $OutputPath -Content $sb.ToString()
    } else {
        $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8
    }

    # ─────────────────────────────────────────────────────────────────────────
    # HTML
    # ─────────────────────────────────────────────────────────────────────────
    $statusClass = {
        param($s)
        switch ($s) {
            'Implemented'           { 'st-ok' }
            'Inherited'             { 'st-inh' }
            'Not applicable'        { 'st-na' }
            'Partially implemented' { 'st-part' }
            'Planned'               { 'st-part' }
            'Not implemented'       { 'st-gap' }
            default                 { 'st-open' }
        }
    }

    $famRows = ''
    foreach ($f in $families) {
        $famRows += "<tr><td class='fid'>$(Esc $f['Id'])</td><td class='fname'>$(Esc $f['Title'])</td><td class='n'>$($f['Total'])</td><td class='n'>$($f['Evidenced'])</td><td class='n'>$($f['AttestationRequired'])</td><td class='n ok'>$($f['Implemented'])</td><td class='n part'>$($f['Partial'])</td><td class='n gap'>$($f['NotImplemented'])</td><td class='n open'>$($f['Open'])</td></tr>"
    }

    $checklist = ''
    foreach ($f in $families) {
        $rows = ''
        foreach ($r in @($reqs | Where-Object { $_['Family'] -eq $f['Id'] })) {
            $checked = if ($r['Status'] -in @('Implemented', 'Inherited', 'Not applicable')) { ' on' } else { '' }
            $cls = & $statusClass $r['Status']
            $rows += "<tr><td class='cb'><span class='box$checked'></span></td><td class='rid'><a href='#r-$(Esc ($r['Id'] -replace '\.','-'))'>$(Esc $r['Id'])</a></td><td class='rst'>$(Esc $r['Statement'])</td><td class='rs'><span class='pill $cls'>$(Esc $r['Status'])</span></td><td class='rc'>$(Esc $r['Confidence'])</td></tr>"
        }
        $checklist += "<tr class='sh'><td colspan='5'>$(Esc $f['Id']) &nbsp; $(Esc $f['Title'])</td></tr>$rows"
    }

    $detail = ''
    foreach ($f in $families) {
        $items = ''
        foreach ($r in @($reqs | Where-Object { $_['Family'] -eq $f['Id'] })) {
            $cls = & $statusClass $r['Status']

            $srcNote = switch ($r['StatusSource']) {
                'Assessment'     { 'from this assessment' }
                'Attested'       { 'client-attested &mdash; asserted in the answers file, not verified by the assessment' }
                'Inherited'      { "inherited from $(Esc $r['InheritedFrom'])" }
                'Not applicable' { 'declared not applicable' }
                default          { 'not answered' }
            }
            # Same conflict the Markdown render guards against: an attested
            # status is the client's claim, and showing the tool's Confidence
            # beside it reads as the tool having verified that claim.
            $attestedConflict = $r['StatusSource'] -in @('Attested', 'Inherited') -and
                $r['DerivedStatus'] -ne $r['Status'] -and
                $r['DerivedStatus'] -notin @('No automated evidence', 'Not assessed')
            $confDisplay = if ($attestedConflict) { 'not applicable' } else { $r['Confidence'] }
            $conflictHtml = if ($attestedConflict) {
                "<div class='note'>Assessment found: <strong>$(Esc $r['DerivedStatus'])</strong>. The automated evidence disagrees with the status above &mdash; that status is the client's attestation, not something this assessment verified.</div>"
            } else { '' }

            $obj = ''
            foreach ($o in @($r['Objectives'])) {
                $obj += "<li><span class='box'></span> <span class='olbl'>$(Esc (Get-NRGObjectField -Item $o -Key 'Label' -Default ''))</span> $(Esc (Get-NRGObjectField -Item $o -Key 'Text' -Default ''))</li>"
            }

            $ev = @($r['Evidence'])
            $evHtml = ''
            if ($ev.Count -gt 0) {
                $evRows = ''
                foreach ($e in $ev) {
                    $sc = switch ($e['State']) {
                        'Satisfied'     { 'ev-ok' }
                        'Partial'       { 'ev-part' }
                        'Gap'           { 'ev-gap' }
                        'NotApplicable' { 'ev-na' }
                        default         { 'ev-nr' }
                    }
                    $whyTxt = if ($e['State'] -notin @('Satisfied','Partial','Gap') -and (Get-NRGObjectField -Item $e -Key 'Detail' -Default '')) { "<div class='why'>$(Esc $e['Detail'])</div>" } else { '' }
                    $evRows += "<tr><td class='ec'>$(Esc $e['ControlId'])</td><td class='es'>$(Esc $e['Source'])</td><td><span class='ev $sc'>$(Esc $e['State'])</span></td><td class='et'>$(Esc $e['Title'])$whyTxt</td></tr>"
                }
                $unscored = [int]$r['NotRun'] + [int](Get-NRGObjectField -Item $r -Key 'NA' -Default 0)
                $note = if ($unscored -gt 0) {
                    "<p class='note'>$unscored of the $($ev.Count) mapped controls produced no verdict this run &mdash; not collected, not licensed, declared to a third-party product, or not programmatically checkable. Those are not passes and not failures; they are unknowns, so this requirement is not reported implemented on their account.</p>"
                } else { '' }
                $evHtml = "<div class='blk'><div class='lbl'>Evidence from this assessment</div><table class='ev-t'><tbody>$evRows</tbody></table>$note</div>"
            } else {
                $evHtml = "<div class='blk'><div class='lbl'>Evidence from this assessment</div><p class='none'>None. Nothing in a Microsoft 365 tenant or an endpoint scan evidences this requirement &mdash; it is satisfied by policy, process, physical control or personnel practice, and the evidence is whatever the organization retains.</p></div>"
            }

            $narr = if ($r['Narrative']) {
                "<div class='blk narr'><div class='lbl'>How it is done here</div>$(Esc $r['Narrative'])</div>"
            } elseif ($r['MappedControls'] -eq 0) {
                "<div class='blk todo'><div class='lbl'>How it is done here</div>Not written yet. This requirement has no automated evidence &mdash; it needs a narrative in the answers file before the plan is complete.</div>"
            } else {
                "<div class='blk todo'><div class='lbl'>How it is done here</div>No narrative supplied. The evidence above stands on its own, but an assessor will want the description too.</div>"
            }

            $how = @($r['HowToEnable'])
            $howHtml = ''
            if ($how.Count -gt 0) {
                $li = ''
                foreach ($h in $how) {
                    $li += "<li><span class='hc'>$(Esc $h['ControlId'])</span> <strong>$(Esc $h['Title'])</strong> <span class='hs'>$(Esc $h['State'])</span><br>$(Esc $h['Remediation'])</li>"
                }
                $howHtml += "<div class='blk how'><div class='lbl'>How to close it</div><ul class='how-l'>$li</ul></div>"

                $imHtml = ''
                foreach ($g in (Group-NRGSSPImpact -Actions $how)) {
                    $im = $g['Base']
                    $lines = ''
                    if ($im['Users'])      { $lines += "<div class='ir'><span class='il'>Users</span>$(Esc $im['Users'])</div>" }
                    if ($im['Admins'])     { $lines += "<div class='ir'><span class='il'>Admins</span>$(Esc $im['Admins'])</div>" }
                    if ($im['Watchouts'])  { $lines += "<div class='ir wo'><span class='il'>Watch out</span>$(Esc $im['Watchouts'])</div>" }
                    if ($im['Reversible']) { $lines += "<div class='ir'><span class='il'>Reversible</span>$(Esc $im['Reversible'])</div>" }
                    foreach ($o in @($g['Specifics'])) {
                        foreach ($k in $o['Fields'].Keys) {
                            $lines += "<div class='ir sp'><span class='il'>$(Esc $o['ControlId'])</span><em>$(Esc (Get-NRGSSPImpactLabel $k)):</em> $(Esc $o['Fields'][$k])</div>"
                        }
                    }
                    $imHtml += "<div class='imp'><div class='isum'>$(Esc $im['Summary']) <span class='ifor'>$(Esc (($g['ControlIds']) -join ', '))</span></div>$lines</div>"
                }
                $und = @($how | Where-Object { -not $_['Impact'] })
                if ($und.Count -gt 0) {
                    $imHtml += "<p class='note'>Operational impact not documented for $(Esc ((@($und | ForEach-Object { $_['ControlId'] })) -join ', ')). Assess the effect before scheduling &mdash; an undocumented impact is not the same as no impact.</p>"
                }
                if ($imHtml) {
                    $howHtml += "<div class='blk'><div class='lbl'>What that will affect</div>$imHtml</div>"
                }
            }

            $poamHtml = ''
            if ($null -ne $r['Poam']) {
                $p = $r['Poam']
                $pl = ''
                foreach ($fld in @('Weakness', 'Remedy', 'Owner', 'DueDate', 'Resources')) {
                    $v = [string](Get-NRGObjectField -Item $p -Key $fld -Default '')
                    if ($v) { $pl += "<div class='ir'><span class='il'>$(Esc $fld)</span>$(Esc $v)</div>" }
                }
                $poamHtml = "<div class='blk poam'><div class='lbl'>Plan of action and milestones</div>$pl</div>"
            }

            $extra = ''
            if ($r['NotApplicableReason']) { $extra += "<div class='blk'><div class='lbl'>Why not applicable</div>$(Esc $r['NotApplicableReason'])</div>" }
            if ($r['ResponsibleRole'])     { $extra += "<div class='meta2'><span class='lbl2'>Responsible role</span>$(Esc $r['ResponsibleRole'])</div>" }

            $items += @"
<div class='req' id='r-$(Esc ($r['Id'] -replace '\.','-'))'>
  <div class='req-hd'>
    <span class='rid2'>$(Esc $r['Id'])</span>
    <span class='pill $cls'>$(Esc $r['Status'])</span>
    <span class='conf'>$(Esc $confDisplay)</span>
  </div>
  <div class='stmt'>$(Esc $r['Statement'])</div>
  <div class='src'>Status $srcNote.</div>
  $conflictHtml
  $extra
  $narr
  $(if ($obj) { "<div class='blk'><div class='lbl'>Assessment objectives (SP 800-171A)</div><ul class='obj'>$obj</ul></div>" })
  $evHtml
  $howHtml
  $poamHtml
</div>
"@
        }
        $detail += @"
<section class='fam' id='f-$(Esc ($f['Id'] -replace '\.','-'))'>
  <h2>$(Esc $f['Id']) &nbsp; $(Esc $f['Title'])</h2>
  <p class='fdesc'>$($f['Total']) requirements &middot; $($f['Evidenced']) evidenced by this assessment &middot; $($f['AttestationRequired']) answered by you</p>
  $items
</section>
"@
    }

    $nav = ''
    foreach ($f in $families) { $nav += "<a href='#f-$(Esc ($f['Id'] -replace '\.','-'))'>$(Esc $f['Id'])</a>" }

    $openRows = ''
    foreach ($r in $needAnswer) {
        $openRows += "<tr><td class='rid'>$(Esc $r['Id'])</td><td class='es'>$(Esc $r['FamilyTitle'])</td><td>$(Esc $r['Statement'])</td></tr>"
    }
    $openHtml = if ($needAnswer.Count -eq 0) {
        "<p class='lede'>Every requirement without automated evidence carries a written answer. The plan is complete in that respect &mdash; review the narratives for accuracy, not for gaps.</p>"
    } else {
        "<p class='lede'><strong>$($needAnswer.Count)</strong> requirements have neither automated evidence nor a written answer. Each needs a status and a narrative in the answers file before this plan can be signed.</p><table class='open-t'><thead><tr><th>Requirement</th><th>Family</th><th>What it asks</th></tr></thead><tbody>$openRows</tbody></table>"
    }

    $poamSection = ''
    if ($withPoam.Count -gt 0) {
        $pr = ''
        foreach ($r in $withPoam) {
            $p = $r['Poam']
            $pr += "<tr><td class='rid'>$(Esc $r['Id'])</td><td>$(Esc (Get-NRGObjectField -Item $p -Key 'Weakness' -Default ''))</td><td>$(Esc (Get-NRGObjectField -Item $p -Key 'Remedy' -Default ''))</td><td class='es'>$(Esc (Get-NRGObjectField -Item $p -Key 'Owner' -Default ''))</td><td class='es'>$(Esc (Get-NRGObjectField -Item $p -Key 'DueDate' -Default ''))</td></tr>"
        }
        $poamSection = @"
<div class="card">
  <h2>Plan of action and milestones</h2>
  <p class="lede">Every requirement not fully implemented needs one of these before an assessment. A POA&amp;M with no owner and no date is not a plan.</p>
  <table class="open-t"><thead><tr><th>Requirement</th><th>Weakness</th><th>Remedy</th><th>Owner</th><th>Due</th></tr></thead><tbody>$pr</tbody></table>
</div>
"@
    }

    $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>$(Esc $title)</title>
<style>
*{box-sizing:border-box}
body{margin:0;font:15px/1.65 -apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#111827;background:#eef2f8}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px 60px}
header{background:linear-gradient(138deg,#0f2544 0%,#061325 100%);color:#fff;padding:40px 0 0}
header .wrap{padding-bottom:0}
.eyebrow{font-size:.66rem;letter-spacing:.18em;text-transform:uppercase;color:#e8621a;font-weight:700;margin-bottom:8px}
h1{margin:0 0 8px;font-size:1.85rem;letter-spacing:-.03em;line-height:1.15}
.sub{color:rgba(255,255,255,.72);font-size:1rem;margin-bottom:12px;max-width:62ch}
.meta{font-size:.83rem;color:rgba(255,255,255,.5);margin-bottom:22px}
.meta strong{color:rgba(255,255,255,.85);font-weight:600}
nav{display:flex;flex-wrap:wrap;gap:2px;border-top:1px solid rgba(255,255,255,.08);padding-top:2px}
nav a{padding:10px 12px;font-size:.68rem;font-weight:700;letter-spacing:.05em;color:rgba(255,255,255,.42);text-decoration:none;border-bottom:2px solid transparent}
nav a:hover{color:#fff;border-bottom-color:#e8621a}
.card{background:#fff;border-radius:12px;padding:22px 26px;margin:26px 0 22px;box-shadow:0 1px 3px rgba(0,0,0,.05),0 4px 18px rgba(15,37,68,.07)}
h2{font-size:1.25rem;letter-spacing:-.02em;margin:0 0 6px}
.lede{font-size:.95rem;line-height:1.7;margin:0 0 10px;max-width:80ch}
.warn{background:#fffbeb;border-left:4px solid #f59e0b;border-radius:0 8px 8px 0;padding:14px 18px;margin:14px 0;font-size:.92rem;line-height:1.7}
.stats{display:flex;flex-wrap:wrap;gap:10px;margin:16px 0 4px}
.stat{flex:1 1 140px;background:#f8fafc;border-radius:9px;padding:12px 14px}
.stat b{display:block;font-size:1.5rem;letter-spacing:-.03em;line-height:1.2}
.stat span{font-size:.68rem;text-transform:uppercase;letter-spacing:.07em;color:#6b7280;font-weight:700}
table{width:100%;border-collapse:collapse;font-size:.86rem;margin-top:12px}
th{text-align:left;font-size:.64rem;text-transform:uppercase;letter-spacing:.08em;color:#6b7280;padding:6px 8px;border-bottom:2px solid #e2e8f0}
td{padding:7px 8px;border-bottom:1px solid #eef2f8;vertical-align:top}
td.n{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
td.ok{color:#065f46;font-weight:700}
td.part{color:#92400e;font-weight:700}
td.gap{color:#991b1b;font-weight:700}
td.open{color:#6b7280;font-weight:700}
tr.sh td{background:#0f2544;color:#fff;font-weight:800;font-size:.7rem;text-transform:uppercase;letter-spacing:.08em;padding:8px 10px;border:none}
.fid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:800;color:#4c1d95;white-space:nowrap}
.fname{font-weight:600}
.cb{width:26px}
.box{display:inline-block;width:15px;height:15px;border:1.5px solid #94a3b8;border-radius:3px;vertical-align:middle;position:relative}
.box.on{background:#065f46;border-color:#065f46}
.box.on::after{content:'';position:absolute;left:4px;top:1px;width:4px;height:8px;border:solid #fff;border-width:0 2px 2px 0;transform:rotate(45deg)}
.rid{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:800;white-space:nowrap;width:64px}
.rid a{color:#4c1d95;text-decoration:none}
.rid a:hover{text-decoration:underline}
.rst{font-size:.84rem}
.rs{width:150px}
.rc{width:130px;font-size:.72rem;color:#6b7280;white-space:nowrap}
.pill{display:inline-block;padding:2px 9px;border-radius:20px;font-size:.65rem;font-weight:800;letter-spacing:.02em;white-space:nowrap}
.st-ok{background:#d1fae5;color:#065f46}
.st-part{background:#fef3c7;color:#92400e}
.st-gap{background:#fee2e2;color:#991b1b}
.st-open{background:#e5e7eb;color:#4b5563}
.st-inh{background:#dbeafe;color:#1e40af}
.st-na{background:#ede9fe;color:#5b21b6}
.fam{margin-bottom:26px}
.fam>h2{padding:0 4px;margin-top:26px}
.fdesc{color:#6b7280;font-size:.82rem;margin:0 4px 14px}
.req{background:#fff;border-radius:12px;padding:18px 22px;margin-bottom:12px;box-shadow:0 1px 3px rgba(0,0,0,.05),0 4px 14px rgba(15,37,68,.05)}
.req-hd{display:flex;align-items:center;gap:11px;flex-wrap:wrap;margin-bottom:7px}
.rid2{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:900;color:#4c1d95;font-size:.95rem}
.conf{font-size:.68rem;color:#6b7280;letter-spacing:.03em}
.stmt{font-weight:600;font-size:.98rem;line-height:1.6;margin-bottom:5px}
.src{font-size:.75rem;color:#6b7280;margin-bottom:11px}
.blk{margin-bottom:11px;line-height:1.65;font-size:.88rem}
.lbl{font-size:.6rem;font-weight:800;text-transform:uppercase;letter-spacing:.09em;color:#6b7280;margin-bottom:5px}
.narr{background:#f0fdf4;border-left:3px solid #16a34a;border-radius:0 8px 8px 0;padding:11px 15px}
.todo{background:#f8fafc;border-left:3px solid #cbd5e1;border-radius:0 8px 8px 0;padding:11px 15px;color:#6b7280;font-style:italic}
.how{background:#f8fafc;border-left:3px solid #3b7dd8;border-radius:0 8px 8px 0;padding:11px 15px}
.poam{background:#fff7ed;border-left:3px solid #ea580c;border-radius:0 8px 8px 0;padding:11px 15px}
.how-l{margin:0;padding-left:18px}
.how-l li{margin-bottom:8px}
.hc{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;color:#1e40af;background:#dbeafe;padding:1px 6px;border-radius:4px;font-size:.74rem}
.hs{font-size:.66rem;font-weight:800;text-transform:uppercase;letter-spacing:.05em;color:#991b1b}
.obj{list-style:none;margin:0;padding:0}
.obj li{padding:3px 0;font-size:.84rem;line-height:1.55}
.olbl{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;color:#4c1d95;font-size:.76rem}
.ev-t td{font-size:.82rem;padding:5px 8px}
.ec{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;color:#4c1d95;white-space:nowrap;width:82px}
.es{color:#6b7280;font-size:.76rem;white-space:nowrap}
.et{color:#4b5563}
.ev{display:inline-block;padding:1px 8px;border-radius:20px;font-size:.63rem;font-weight:800;white-space:nowrap}
.ev-ok{background:#d1fae5;color:#065f46}
.ev-part{background:#fef3c7;color:#92400e}
.ev-gap{background:#fee2e2;color:#991b1b}
.ev-na{background:#e5e7eb;color:#4b5563}
.ev-nr{background:#f1f5f9;color:#64748b}
.none{color:#6b7280;font-size:.86rem;margin:0;line-height:1.65}
.note{color:#92400e;background:#fffbeb;border-radius:7px;padding:8px 12px;font-size:.79rem;margin:9px 0 0;line-height:1.6}
.why{color:#64748b;font-size:.74rem;margin-top:3px;line-height:1.5}
.imp{background:#fdf4ff;border-left:3px solid #a855f7;border-radius:0 8px 8px 0;padding:11px 15px;margin-bottom:8px}
.isum{font-weight:700;margin-bottom:6px;font-size:.9rem}
.ifor{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:600;font-size:.68rem;color:#7c3aed;letter-spacing:.02em}
.ir.sp{border-left:2px solid #e9d5ff;padding-left:9px;margin-top:6px}
.ir.sp .il{color:#7c3aed;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;text-transform:none;letter-spacing:0;font-size:.7rem}
.ir{font-size:.83rem;line-height:1.6;margin-top:4px}
.ir.wo{color:#92400e}
.il{display:inline-block;min-width:84px;font-size:.58rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em;color:#9ca3af;vertical-align:top}
.meta2{font-size:.79rem;color:#4b5563;line-height:1.6;margin:0 0 9px}
.lbl2{font-size:.58rem;font-weight:800;text-transform:uppercase;letter-spacing:.08em;color:#9ca3af;margin-right:7px}
.open-t td{font-size:.83rem}
footer{color:#6b7280;font-size:.78rem;line-height:1.6;padding:0 4px;max-width:90ch}
@media print{
  body{background:#fff}
  header{background:#0f2544 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
  nav{display:none}
  .card,.req{box-shadow:none;border:1px solid #e2e8f0}
  .req,tr{page-break-inside:avoid}
}
</style></head><body>
<header><div class="wrap">
  <div class="eyebrow">NIST SP 800-171 Rev 2 &middot; CMMC Level 2</div>
  <h1>$(Esc $title)</h1>
  <div class="sub">$(Esc $sysName)</div>
  <div class="meta">Assessed by <strong>$(Esc $company)</strong> &middot; $(Esc $date)$(if ($version) { " &middot; tool $(Esc $version)" }) &middot; <strong>$($sum['Total'])</strong> requirements &middot; <strong>$($sum['Evidenced'])</strong> evidenced here &middot; <strong>$($sum['AttestationRequired'])</strong> answered by you</div>
  <nav>$nav</nav>
</div></header>

<div class="wrap">
  <div class="card">
    <h2>Read this first</h2>
    <p class="lede">This is a <strong>working System Security Plan, not a finished one</strong>. Of the $($sum['Total']) requirements in $(Esc $Posture['Baseline']), this assessment observed <strong>$($sum['Evidenced'])</strong> from the Microsoft 365 tenant and the endpoints. The remaining <strong>$($sum['AttestationRequired'])</strong> are policy, process, physical security and personnel &mdash; no scan reaches them, and they are answered by the organization, not by the tool.</p>
    <div class="warn"><strong>$($needAnswer.Count) requirements are still unanswered.</strong> They are listed at the end. Until each one carries a status and a narrative, this document is incomplete, and an assessor will read a blank as a gap.</div>
    <p class="lede">Where the assessment reports a requirement implemented, every control this tool maps to it produced a verdict and passed &mdash; which is still not the requirement satisfied in full. Microsoft 365 observes the tenant slice of a requirement and nothing outside it. The <em>Confidence</em> column says which case each row is in.</p>
    <div class="stats">
      <div class="stat"><b>$($sum['Implemented'])</b><span>Implemented</span></div>
      <div class="stat"><b>$($sum['PartiallyImplemented'])</b><span>Partial</span></div>
      <div class="stat"><b>$($sum['NotImplemented'])</b><span>Not implemented</span></div>
      <div class="stat"><b>$($sum['NotAssessed'])</b><span>Open</span></div>
      <div class="stat"><b>$($sum['Inherited'])</b><span>Inherited</span></div>
      <div class="stat"><b>$($sum['NotApplicable'])</b><span>Not applicable</span></div>
    </div>
    <p class="lede" style="margin-top:12px">Of those, <strong>$($sum['ToolVerified'])</strong> are tool-verified, <strong>$($sum['PartialEvidence'])</strong> rest on partial evidence, <strong>$($sum['NoEvidenceCollected'])</strong> map to controls that produced no result this run, and <strong>$($sum['AttestationOnly'])</strong> have no automated evidence at all. <strong>$($sum['AttestedStatuses'])</strong> statuses are client-attested &mdash; asserted in the answers file, not verified here.</p>
  </div>

  <div class="card">
    <h2>By family</h2>
    <table><thead><tr><th>Family</th><th></th><th class="n">Reqs</th><th class="n">Evidenced</th><th class="n">Yours</th><th class="n">Impl</th><th class="n">Partial</th><th class="n">Not impl</th><th class="n">Open</th></tr></thead><tbody>$famRows</tbody></table>
  </div>

  <div class="card">
    <h2>The checklist</h2>
    <p class="lede">One line per requirement. A tick means implemented, inherited or declared not applicable; everything else is work to do or a question to answer. Click a requirement number for the detail.</p>
    <table><tbody>$checklist</tbody></table>
  </div>

  $detail

  $poamSection

  <div class="card">
    <h2>Still to answer</h2>
    $openHtml
  </div>

  <footer>Prepared by $(Esc $company). This plan records the state of the system on $(Esc $date). Statuses marked client-attested were asserted by the organization and not verified by the assessment; statuses drawn from the assessment reflect what the tool could observe in the Microsoft 365 tenant and on scanned endpoints, which is a subset of each requirement.</footer>
</div>
</body></html>
"@

    $htmlPath = [System.IO.Path]::ChangeExtension($OutputPath, '.html')
    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $htmlPath -Content $html
    } else {
        $html | Out-File -LiteralPath $htmlPath -Encoding utf8
    }

    # XLSX — best effort. A missing openpyxl must not fail the two documents
    # already written.
    try {
        $xlsxPath = [System.IO.Path]::ChangeExtension($OutputPath, '.xlsx')
        Publish-NRGSSPXlsx -Posture $Posture -Metadata @{
            TenantDomain = $tenant; AssessmentDate = $date; ToolVersion = $version
            SystemName = $sysName; Company = $company
        } -OutputPath $xlsxPath
    } catch {
        Write-Warning "SSP XLSX skipped: $($_.Exception.Message)"
    }
}

function Publish-NRGSSPXlsx {
    <#
        The working copy. One row per requirement with Status, Narrative and
        POA&M columns left editable, because the 69 requirements this tool
        cannot reach get filled in by a person and a spreadsheet is what that
        person will actually use.

        Same embedded-Python + openpyxl approach as the other matrix
        publishers: no Excel, no COM, and no tenant data interpolated into
        code — everything crosses the boundary as JSON.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [System.Collections.Specialized.OrderedDictionary] $Posture,
        [Parameter(Mandatory)] [hashtable] $Metadata,
        [Parameter(Mandatory)] [string] $OutputPath
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $pythonCmd = $null
    foreach ($py in @('python3', 'python')) {
        try {
            $null = & $py -c 'import openpyxl' 2>&1
            if ($LASTEXITCODE -eq 0) { $pythonCmd = $py; break }
        } catch { }
    }
    if (-not $pythonCmd) {
        Write-Verbose 'openpyxl not available — SSP XLSX skipped (Markdown and HTML were still written).'
        return
    }

    $sum = $Posture['Summary']

    $payload = @{
        Metadata = @{
            TenantDomain   = [string]$Metadata['TenantDomain']
            AssessmentDate = [string]$Metadata['AssessmentDate']
            ToolVersion    = [string]$Metadata['ToolVersion']
            SystemName     = [string]$Metadata['SystemName']
            Company        = [string]$Metadata['Company']
            Baseline       = [string]$Posture['Baseline']
        }
        Summary = @{
            Total = $sum['Total']; Evidenced = $sum['Evidenced']
            AttestationRequired = $sum['AttestationRequired']
            Implemented = $sum['Implemented']; Partial = $sum['PartiallyImplemented']
            NotImplemented = $sum['NotImplemented']; Open = $sum['NotAssessed']
            Inherited = $sum['Inherited']; NotApplicable = $sum['NotApplicable']
            ToolVerified = $sum['ToolVerified']; PartialEvidence = $sum['PartialEvidence']
            NoEvidenceCollected = $sum['NoEvidenceCollected']; AttestationOnly = $sum['AttestationOnly']
            Attested = $sum['AttestedStatuses']
        }
        Families = @($Posture['Families'] | ForEach-Object {
            @{
                Id = [string]$_['Id']; Title = [string]$_['Title']; Total = $_['Total']
                Evidenced = $_['Evidenced']; Attest = $_['AttestationRequired']
                Implemented = $_['Implemented']; Partial = $_['Partial']
                NotImplemented = $_['NotImplemented']; Open = $_['Open']
            }
        })
        Requirements = @($Posture['Requirements'] | ForEach-Object {
            $p = $_['Poam']
            $imp = @()
            foreach ($g in (Group-NRGSSPImpact -Actions @($_['HowToEnable']))) {
                $im = $g['Base']
                $line = "[$(($g['ControlIds']) -join ', ')] $([string]$im['Summary']) Watch out: $([string]$im['Watchouts'])"
                foreach ($o in @($g['Specifics'])) {
                    foreach ($k in $o['Fields'].Keys) {
                        $line += " ($($o['ControlId']) specifically — $(Get-NRGSSPImpactLabel $k): $($o['Fields'][$k]))"
                    }
                }
                $imp += $line
            }
            @{
                Id           = [string]$_['Id']
                Family       = [string]$_['Family']
                FamilyTitle  = [string]$_['FamilyTitle']
                Statement    = [string]$_['Statement']
                Status       = [string]$_['Status']
                StatusSource = [string]$_['StatusSource']
                Confidence   = [string]$_['Confidence']
                Evidence     = [string](@($_['Evidence'] | ForEach-Object { "$($_['ControlId']) ($($_['State']))" }) -join ', ')
                HowTo        = [string](@($_['HowToEnable'] | ForEach-Object { "$($_['ControlId']): $($_['Remediation'])" }) -join "`n")
                Impact       = [string]($imp -join "`n")
                Narrative    = [string]$_['Narrative']
                Role         = [string]$_['ResponsibleRole']
                NaReason     = [string]$_['NotApplicableReason']
                Inherited    = [string]$_['InheritedFrom']
                Objectives   = [string](@($_['Objectives'] | ForEach-Object { "$(Get-NRGObjectField -Item $_ -Key 'Label' -Default '') $(Get-NRGObjectField -Item $_ -Key 'Text' -Default '')" }) -join "`n")
                PoamWeakness = if ($null -ne $p) { [string](Get-NRGObjectField -Item $p -Key 'Weakness' -Default '') } else { '' }
                PoamRemedy   = if ($null -ne $p) { [string](Get-NRGObjectField -Item $p -Key 'Remedy'   -Default '') } else { '' }
                PoamOwner    = if ($null -ne $p) { [string](Get-NRGObjectField -Item $p -Key 'Owner'    -Default '') } else { '' }
                PoamDue      = if ($null -ne $p) { [string](Get-NRGObjectField -Item $p -Key 'DueDate'  -Default '') } else { '' }
                NeedsAnswer  = [bool]($_['MappedControls'] -eq 0 -and -not $_['Narrative'] -and $_['StatusSource'] -eq 'None')
            }
        })
    }

    $outputDir = Split-Path -Parent $OutputPath
    if (-not $outputDir -or -not (Test-Path -LiteralPath $outputDir)) {
        $outputDir = [System.IO.Path]::GetTempPath()
    }
    $base = [System.IO.Path]::GetFileNameWithoutExtension($OutputPath)
    if ([string]::IsNullOrWhiteSpace($base)) { $base = 'ssp' }
    $tmpJson = Join-Path $outputDir "$base-ssp-input.json"
    $pyTmp   = Join-Path $outputDir "$base-ssp-helper.py"

    try {
        if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileContent -Path $tmpJson -Content ($payload | ConvertTo-Json -Depth 6 -Compress)
        } else {
            $payload | ConvertTo-Json -Depth 6 -Compress | Out-File -LiteralPath $tmpJson -Encoding utf8
            if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
                Set-NRGSensitiveFileAcl -Path $tmpJson -ErrorAction SilentlyContinue
            }
        }

        $pyScript = @'
import json, sys
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

with open(sys.argv[1], encoding='utf-8') as fh:
    d = json.load(fh)

meta, summ = d['Metadata'], d['Summary']
NAVY, ORANGE, WHITE, PURPLE = '0F2544', 'E8621A', 'FFFFFF', '4C1D95'
GREY, INK, MUTED = 'F1F5F9', '111827', '6B7280'
ST_BG = {'Implemented':'D1FAE5','Partially implemented':'FEF3C7','Planned':'FEF3C7',
         'Not implemented':'FEE2E2','Not assessed':'F1F5F9','No automated evidence':'E5E7EB',
         'Inherited':'DBEAFE','Not applicable':'EDE9FE'}
ST_FG = {'Implemented':'065F46','Partially implemented':'92400E','Planned':'92400E',
         'Not implemented':'991B1B','Not assessed':'64748B','No automated evidence':'4B5563',
         'Inherited':'1E40AF','Not applicable':'5B21B6'}

thin = Side(style='thin', color='E2E8F0')
box = Border(left=thin, right=thin, top=thin, bottom=thin)
wrap = Alignment(wrap_text=True, vertical='top')
top = Alignment(vertical='top')

wb = Workbook()

def head(ws, cols, row=1):
    for i, (label, width) in enumerate(cols, start=1):
        c = ws.cell(row=row, column=i, value=label)
        c.font = Font(bold=True, color=WHITE, size=9)
        c.fill = PatternFill('solid', fgColor=NAVY)
        c.alignment = Alignment(wrap_text=True, vertical='center')
        c.border = box
        ws.column_dimensions[get_column_letter(i)].width = width
    ws.freeze_panes = ws.cell(row=row + 1, column=1)

# ── Summary ──────────────────────────────────────────────────────────────
ws = wb.active
ws.title = 'Summary'
ws.column_dimensions['A'].width = 46
ws.column_dimensions['B'].width = 62
t = ws.cell(row=1, column=1, value='System Security Plan')
t.font = Font(bold=True, size=16, color=NAVY)
ws.cell(row=2, column=1, value=meta['Baseline']).font = Font(size=10, color=MUTED)

r = 4
for k, v in [('System', meta['SystemName']), ('Tenant', meta['TenantDomain']),
             ('Assessed by', meta['Company']), ('Date', meta['AssessmentDate']),
             ('Tool version', meta['ToolVersion'])]:
    if not v:
        continue
    ws.cell(row=r, column=1, value=k).font = Font(bold=True, size=10)
    ws.cell(row=r, column=2, value=v).font = Font(size=10)
    r += 1

r += 1
n = ws.cell(row=r, column=1, value=(
    'This is a working plan, not a finished one. %d of the %d requirements were evidenced by the '
    'assessment; the other %d are policy, process, physical and personnel and are answered by the '
    'organization. A status left blank reads as a gap to an assessor.'
    % (summ['Evidenced'], summ['Total'], summ['AttestationRequired'])))
n.font = Font(size=9, italic=True, color='92400E')
n.fill = PatternFill('solid', fgColor='FFFBEB')
n.alignment = wrap
ws.merge_cells(start_row=r, start_column=1, end_row=r, end_column=2)
ws.row_dimensions[r].height = 46
r += 2

for label, val in [('Implemented', summ['Implemented']),
                   ('Partially implemented', summ['Partial']),
                   ('Not implemented', summ['NotImplemented']),
                   ('Open / unanswered', summ['Open']),
                   ('Inherited', summ['Inherited']),
                   ('Not applicable', summ['NotApplicable']),
                   ('', ''),
                   ('Tool-verified', summ['ToolVerified']),
                   ('Partial evidence', summ['PartialEvidence']),
                   ('No evidence collected', summ['NoEvidenceCollected']),
                   ('No automated evidence at all', summ['AttestationOnly']),
                   ('Client-attested statuses', summ['Attested'])]:
    if label:
        ws.cell(row=r, column=1, value=label).font = Font(size=10)
        ws.cell(row=r, column=2, value=val).font = Font(bold=True, size=10)
    r += 1

# ── Families ─────────────────────────────────────────────────────────────
ws = wb.create_sheet('By family')
head(ws, [('Family', 8), ('Name', 34), ('Requirements', 12), ('Evidenced here', 13),
          ('Answered by you', 14), ('Implemented', 11), ('Partial', 9),
          ('Not implemented', 14), ('Open', 8)])
for i, f in enumerate(d['Families'], start=2):
    vals = [f['Id'], f['Title'], f['Total'], f['Evidenced'], f['Attest'],
            f['Implemented'], f['Partial'], f['NotImplemented'], f['Open']]
    for j, v in enumerate(vals, start=1):
        c = ws.cell(row=i, column=j, value=v)
        c.border = box
        c.font = Font(size=9, bold=(j == 1), color=(PURPLE if j == 1 else INK))
        c.alignment = top

# ── Checklist — the working sheet ────────────────────────────────────────
ws = wb.create_sheet('Checklist')
head(ws, [('Req', 8), ('Family', 22), ('Requirement', 62), ('In place?', 20),
          ('Confidence', 18), ('Evidence', 30), ('Responsible role', 18),
          ('How it is done here (narrative)', 54), ('POA&M weakness', 30),
          ('POA&M remedy', 30), ('Owner', 14), ('Due', 12)])
for i, q in enumerate(d['Requirements'], start=2):
    vals = [q['Id'], q['FamilyTitle'], q['Statement'], q['Status'], q['Confidence'],
            q['Evidence'], q['Role'], q['Narrative'] or q['NaReason'] or q['Inherited'],
            q['PoamWeakness'], q['PoamRemedy'], q['PoamOwner'], q['PoamDue']]
    for j, v in enumerate(vals, start=1):
        c = ws.cell(row=i, column=j, value=v)
        c.border = box
        c.alignment = wrap
        c.font = Font(size=9, bold=(j == 1), color=(PURPLE if j == 1 else INK))
    sc = ws.cell(row=i, column=4)
    sc.fill = PatternFill('solid', fgColor=ST_BG.get(q['Status'], GREY))
    sc.font = Font(size=9, bold=True, color=ST_FG.get(q['Status'], INK))
    if q['StatusSource'] == 'Attested':
        ws.cell(row=i, column=5).font = Font(size=9, italic=True, color='92400E')
    if q['NeedsAnswer']:
        ws.cell(row=i, column=8).fill = PatternFill('solid', fgColor='FFFBEB')

# ── Detail: how to close it, and what that affects ───────────────────────
ws = wb.create_sheet('How and impact')
head(ws, [('Req', 8), ('Requirement', 50), ('Status', 20),
          ('How to close it', 66), ('What that will affect', 66)])
row = 2
for q in d['Requirements']:
    if not q['HowTo'] and not q['Impact']:
        continue
    vals = [q['Id'], q['Statement'], q['Status'], q['HowTo'], q['Impact']]
    for j, v in enumerate(vals, start=1):
        c = ws.cell(row=row, column=j, value=v)
        c.border = box
        c.alignment = wrap
        c.font = Font(size=9, bold=(j == 1), color=(PURPLE if j == 1 else INK))
    row += 1
if row == 2:
    c = ws.cell(row=2, column=1, value='Nothing to close: no mapped control reported a gap or a partial result this run.')
    c.font = Font(size=9, italic=True, color=MUTED)

# ── Assessment objectives ────────────────────────────────────────────────
ws = wb.create_sheet('Objectives')
head(ws, [('Req', 8), ('Status', 20), ('Assessment objectives (SP 800-171A)', 110)])
for i, q in enumerate(d['Requirements'], start=2):
    for j, v in enumerate([q['Id'], q['Status'], q['Objectives']], start=1):
        c = ws.cell(row=i, column=j, value=v)
        c.border = box
        c.alignment = wrap
        c.font = Font(size=9, bold=(j == 1), color=(PURPLE if j == 1 else INK))

# ── Still to answer ──────────────────────────────────────────────────────
ws = wb.create_sheet('Still to answer')
head(ws, [('Req', 8), ('Family', 24), ('What it asks', 78),
          ('Status (fill in)', 22), ('Narrative (fill in)', 60)])
open_rows = [q for q in d['Requirements'] if q['NeedsAnswer']]
for i, q in enumerate(open_rows, start=2):
    for j, v in enumerate([q['Id'], q['FamilyTitle'], q['Statement'], '', ''], start=1):
        c = ws.cell(row=i, column=j, value=v)
        c.border = box
        c.alignment = wrap
        c.font = Font(size=9, bold=(j == 1), color=(PURPLE if j == 1 else INK))
        if j >= 4:
            c.fill = PatternFill('solid', fgColor='FFFBEB')
if not open_rows:
    c = ws.cell(row=2, column=1, value='Every requirement without automated evidence carries a written answer.')
    c.font = Font(size=9, italic=True, color=MUTED)

wb.save(sys.argv[2])
print(f'SSP XLSX saved: {sys.argv[2]}')
'@

        if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileContent -Path $pyTmp -Content $pyScript
        } else {
            $pyScript | Out-File -LiteralPath $pyTmp -Encoding utf8
        }

        $out = & $pythonCmd $pyTmp $tmpJson $OutputPath 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "openpyxl helper failed: $out"
        }
        if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileAcl -Path $OutputPath -ErrorAction SilentlyContinue
        }
    } finally {
        # The JSON carries tenant findings — remove it whether or not the render
        # succeeded, rather than leaving it beside the deliverable.
        foreach ($t in @($tmpJson, $pyTmp)) {
            if (Test-Path -LiteralPath $t) { Remove-Item -LiteralPath $t -Force -ErrorAction SilentlyContinue }
        }
    }
}
