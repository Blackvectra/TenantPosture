#Requires -Version 7.0
#
# Publish-NRGDeltaReport.ps1  (v4.5.6)
# Compares current assessment findings + raw configuration data against a
# prior run baseline JSON. Produces a Markdown delta report showing:
#   - Finding state changes (new gaps, resolved, regressed, unchanged)
#   - Configuration drift (Phase 3):
#       * New / removed / state-changed Conditional Access policies
#       * New admin role assignments (high-priv roles tagged)
#       * New OAuth app registrations with elevated scopes
#       * DMARC policy regression (quarantine/reject -> none)
#   - Score delta
#
# Drift detection only fires when both the baseline AND the current run
# include $script:NRGRawData. The orchestrator now serializes RawData into
# every JSON output, so any baseline produced by v4.5.6+ is drift-capable.
# Older baselines degrade gracefully to a "baseline missing raw data" notice.
#
# Usage:
#   Publish-NRGDeltaReport -CurrentFindings $findings `
#     -CurrentRawData (Get-NRGRawData) `
#     -BaselineResultsPath ".\prior-run-results.json" `
#     -Metadata $meta -OutputPath ".\delta.md"
#
# NIST SP 800-53: CM-3 (configuration change control), AU-6 (audit review)
# MITRE ATT&CK:   T1098 (Account Manipulation), T1136 (Create Account),
#                 T1078 (Valid Accounts)
#

function Get-NRGRawDataDrift {
    [CmdletBinding()] param(
        [hashtable] $Baseline,
        [hashtable] $Current
    )

    $drift = [ordered]@{
        BaselineMissing       = (-not $Baseline -or $Baseline.Count -eq 0)
        CurrentMissing        = (-not $Current  -or $Current.Count  -eq 0)
        CAPoliciesAdded       = @()
        CAPoliciesRemoved     = @()
        CAPoliciesStateChange = @()
        NewAdminAssignments   = @()
        NewOAuthApps          = @()
        DMARCRegressions      = @()
    }
    if ($drift.BaselineMissing -or $drift.CurrentMissing) { return $drift }

    # Defensive extractor — drift only fires when both runs collected the
    # data. A missing collector or schema rename is treated as "no drift,"
    # not "everything is new." v4.10.1: switched to Get-NRGObjectField for
    # shape-agnostic reads. The prior $bag.Success / $bag.Data direct
    # property accesses were a latent StrictMode bug — a PSCustomObject
    # bag (from ConvertFrom-Json) without a Success/Data property would
    # have thrown rather than gracefully returning @().
    $getBag = {
        param([object] $root, [string] $key, [string] $field)
        if ($null -eq $root) { return @() }
        $bag = Get-NRGObjectField -Item $root -Key $key
        if ($null -eq $bag) { return @() }
        $success = Get-NRGObjectField -Item $bag -Key 'Success'
        if (-not $success) { return @() }
        $data = Get-NRGObjectField -Item $bag -Key 'Data'
        if ($null -eq $data) { return @() }
        $arr = Get-NRGObjectField -Item $data -Key $field
        if (-not $arr) { return @() }
        return @($arr)
    }

    # ── Conditional Access drift ─────────────────────────────────────────
    $bCA = & $getBag $Baseline 'AAD-CAPolicies' 'CAPolicies'
    $cCA = & $getBag $Current  'AAD-CAPolicies' 'CAPolicies'
    if ($bCA.Count -gt 0 -or $cCA.Count -gt 0) {
        $bMap = @{}; foreach ($p in $bCA) { if ($p.Id) { $bMap[[string]$p.Id] = $p } }
        $cMap = @{}; foreach ($p in $cCA) { if ($p.Id) { $cMap[[string]$p.Id] = $p } }
        foreach ($id in $cMap.Keys) {
            if (-not $bMap.ContainsKey($id)) {
                $drift.CAPoliciesAdded += @{
                    Id          = $id
                    DisplayName = [string]$cMap[$id].DisplayName
                    State       = [string]$cMap[$id].State
                }
            } elseif ([string]$bMap[$id].State -ne [string]$cMap[$id].State) {
                $drift.CAPoliciesStateChange += @{
                    Id          = $id
                    DisplayName = [string]$cMap[$id].DisplayName
                    From        = [string]$bMap[$id].State
                    To          = [string]$cMap[$id].State
                }
            }
        }
        foreach ($id in $bMap.Keys) {
            if (-not $cMap.ContainsKey($id)) {
                $drift.CAPoliciesRemoved += @{
                    Id          = $id
                    DisplayName = [string]$bMap[$id].DisplayName
                    State       = [string]$bMap[$id].State
                }
            }
        }
    }

    # ── New admin role assignments ───────────────────────────────────────
    $highPriv = @(
        'Global Administrator', 'Privileged Role Administrator',
        'Application Administrator', 'Cloud Application Administrator',
        'Exchange Administrator', 'SharePoint Administrator',
        'Security Administrator', 'User Administrator', 'Authentication Administrator'
    )
    $bRoles = & $getBag $Baseline 'AAD-DirectoryRoles' 'RoleAssignments'
    $cRoles = & $getBag $Current  'AAD-DirectoryRoles' 'RoleAssignments'
    if ($bRoles.Count -gt 0 -or $cRoles.Count -gt 0) {
        $assignKey = { param($r) "$([string]$r.PrincipalId)|$([string]$r.RoleDefinitionId)" }
        $bSet = @{}; foreach ($r in $bRoles) { $bSet[(& $assignKey $r)] = $true }
        foreach ($r in $cRoles) {
            $k = & $assignKey $r
            if (-not $bSet.ContainsKey($k)) {
                $roleName = [string]$r.RoleDisplayName
                $drift.NewAdminAssignments += @{
                    PrincipalUPN     = [string]$r.PrincipalUPN
                    PrincipalName    = [string]$r.PrincipalDisplayName
                    RoleDisplayName  = $roleName
                    AssignmentType   = [string]$r.AssignmentType   # Eligible | Active
                    HighPrivilege    = ($highPriv -contains $roleName)
                }
            }
        }
    }

    # ── New OAuth app registrations ──────────────────────────────────────
    $bOAuth = & $getBag $Baseline 'AAD-Inventory' 'OAuthApps'
    $cOAuth = & $getBag $Current  'AAD-Inventory' 'OAuthApps'
    if ($bOAuth.Count -eq 0 -and $cOAuth.Count -eq 0) {
        $bOAuth = & $getBag $Baseline 'AAD-Inventory' 'ServicePrincipals'
        $cOAuth = & $getBag $Current  'AAD-Inventory' 'ServicePrincipals'
    }
    if ($bOAuth.Count -gt 0 -or $cOAuth.Count -gt 0) {
        $bSet = @{}; foreach ($a in $bOAuth) { if ($a.AppId) { $bSet[[string]$a.AppId] = $true } }
        foreach ($a in $cOAuth) {
            if ($a.AppId -and -not $bSet.ContainsKey([string]$a.AppId)) {
                $scopes = @($a.OAuthScopes ?? $a.Scopes ?? @())
                $risky  = @($scopes | Where-Object {
                    $_ -match 'Mail\.|Files\.|Sites\.FullControl|Directory\.ReadWrite|RoleManagement\.|Application\.ReadWrite'
                })
                $drift.NewOAuthApps += @{
                    AppId        = [string]$a.AppId
                    DisplayName  = [string]$a.DisplayName
                    Publisher    = [string]($a.PublisherName ?? '')
                    Scopes       = $scopes
                    RiskyScopes  = $risky
                    HighRisk     = ($risky.Count -gt 0)
                }
            }
        }
    }

    # ── DMARC policy regression ──────────────────────────────────────────
    # v4.10.1: shape-checks consolidated through Get-NRGObjectField. The Keys
    # enumeration stays inline because it's a different operation (collect
    # all keys, not read one field) and a dedicated Get-NRGObjectKeys helper
    # would have one caller — over-extraction.
    $bDns = & $getBag $Baseline 'DNS-EmailRecords' 'Domains'
    $cDns = & $getBag $Current  'DNS-EmailRecords' 'Domains'
    if ($bDns -and $cDns) {
        $rank = @{ 'reject' = 2; 'quarantine' = 1; 'none' = 0 }
        $bKeys = if ($bDns -is [System.Collections.IDictionary]) { $bDns.Keys } else { $bDns.PSObject.Properties.Name }
        foreach ($dom in $bKeys) {
            $bd = Get-NRGObjectField -Item $bDns -Key $dom
            $cd = Get-NRGObjectField -Item $cDns -Key $dom
            if (-not $cd) { continue }
            $bP = [string](Get-NRGObjectField -Item $bd -Key 'DMARCPolicy' -Default '')
            $cP = [string](Get-NRGObjectField -Item $cd -Key 'DMARCPolicy' -Default '')
            if ($bP -and $cP -and $rank.ContainsKey($bP) -and $rank.ContainsKey($cP) -and ($rank[$cP] -lt $rank[$bP])) {
                $drift.DMARCRegressions += @{
                    Domain = $dom
                    From   = $bP
                    To     = $cP
                }
            }
        }
    }

    return $drift
}

function Publish-NRGDeltaReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [object[]]  $CurrentFindings,
        # Current run raw data — pass (Get-NRGRawData) at call time. Optional
        # for backwards compatibility: drift section degrades to a notice.
        [hashtable] $CurrentRawData,
        [Parameter(Mandatory)]
        [ValidateScript({
            if (-not (Test-Path -LiteralPath $_ -PathType Leaf)) { throw "Baseline file not found: $_" }
            return $true
        })]
        [string]    $BaselineResultsPath,
        [Parameter(Mandatory)] [hashtable] $Metadata,
        [Parameter(Mandatory)] [string]    $OutputPath
    )

    # Fail closed — require security helper for Markdown escaping of
    # tenant-attacker-controllable strings (CA names, UPNs, OAuth app names,
    # publisher names, scope strings, domain names, etc.).
    if (-not (Get-Command ConvertTo-NRGHtmlSafe -ErrorAction SilentlyContinue)) {
        throw "ConvertTo-NRGHtmlSafe not loaded — refusing to generate delta report without injection protection."
    }

    # Helper: standard Markdown escape (parity with Publish-NRGAssessmentSummary).
    # Markdown-safe only — escape characters that break markdown table or
    # code-span structure (pipe, backtick, raw newlines). Do NOT HTML-escape;
    # XSS belongs at the markdown→HTML render boundary, not in source markdown.
    function EscMd([object]$v) {
        if ($null -eq $v -or [string]::IsNullOrEmpty([string]$v)) { return '' }
        $safe = [string]$v
        $safe = $safe -replace '\|', '\|' -replace '`', '\`' -replace '[\r\n]+', ' '
        return $safe
    }

    # Helper: STRICT Markdown escape for untrusted baseline JSON. Strengthens
    # EscMd to also escape the markdown link/image/emphasis syntax characters
    # that an attacker controlling tenant DisplayNames / publisher strings
    # could otherwise smuggle into the report.
    function EscMdStrict([object]$v) {
        if ($null -eq $v -or [string]::IsNullOrEmpty([string]$v)) { return '' }
        $safe = [string]$v
        # Collapse CR/LF (and tabs) to a single space so attackers can't break
        # out of a table row or inject a new Markdown block.
        $safe = $safe -replace "[\r\n\t]+", ' '
        # Escape pipe + backtick (table cell + code) and the link/image/
        # emphasis/header/blockquote syntax characters.
        $safe = $safe `
            -replace '\\', '\\' `
            -replace '\|', '\|' `
            -replace '`',  '\`' `
            -replace '\[', '\[' `
            -replace '\]', '\]' `
            -replace '\(', '\(' `
            -replace '\)', '\)' `
            -replace '\*', '\*' `
            -replace '_',  '\_' `
            -replace '#',  '\#' `
            -replace '>',  '\>'
        return $safe
    }

    # ── Load baseline JSON ──────────────────────────────────────────────────
    # CWE-502 hardening — bounded -Depth caps deserialization so a recursive
    # JSON bomb cannot exhaust memory. Matches the write side's -Depth 10
    # with margin for evaluator additions.
    $baselineRaw  = Get-Content -LiteralPath $BaselineResultsPath -Encoding utf8 -Raw | ConvertFrom-Json -Depth 20
    $baseFindings = @($baselineRaw.Findings ?? $baselineRaw)

    # ── Tenant-ID guard ─────────────────────────────────────────────────────
    # Refuse to generate a delta report against the wrong client's baseline.
    # Silently producing nonsense from a mis-targeted baseline is worse than
    # erroring out — operators have no easy way to spot the mistake otherwise
    # (the delta report would just show every control as "new" or "regressed"
    # because the controls *exist in both* but the configuration is for a
    # different tenant entirely).
    $baseTenantId = $null
    $hasMetadata  = $false
    if ($baselineRaw.PSObject.Properties['Metadata'] -and $baselineRaw.Metadata) {
        $hasMetadata = $true
        if ($baselineRaw.Metadata.PSObject.Properties['TenantId']) {
            $baseTenantId = [string]$baselineRaw.Metadata.TenantId
        }
    }
    if (-not $hasMetadata) {
        throw "Baseline JSON has no Metadata — cannot verify TenantId. Re-run assessment to generate a new baseline."
    }
    if ([string]::IsNullOrWhiteSpace($baseTenantId)) {
        throw "Baseline JSON has no TenantId — cannot verify it matches the current tenant. Re-run assessment to generate a new baseline."
    }
    $currTenantId = [string]($Metadata.TenantId ?? '')
    if ($baseTenantId -ne $currTenantId) {
        throw "Baseline tenant ID '$baseTenantId' does not match current tenant ID '$currTenantId'. Refusing to generate delta report — wrong baseline?"
    }

    # ── Categorize findings by ControlId change ─────────────────────────────
    $base = @{}
    foreach ($f in $baseFindings)    { $base[[string]$f.ControlId] = $f }
    $curr = @{}
    foreach ($f in $CurrentFindings) { $curr[[string]$f.ControlId] = $f }

    $newGaps       = @()   # Was not Gap (or missing), now Gap
    $resolved      = @()   # Was Gap, now Satisfied
    $regressed     = @()   # Was Satisfied/Partial, now worse (but not new Gap)
    $improved      = @()   # Was Gap, now Partial (partial progress)
    $unchangedGaps = @()   # Was Gap, still Gap

    $sOrder = @{ 'Satisfied' = 0; 'Partial' = 1; 'Gap' = 2; 'NotApplicable' = 3 }

    foreach ($cid in ($curr.Keys | Sort-Object)) {
        $c = $curr[$cid]; $b = $base[$cid]
        $cState = [string]$c.State
        if (-not $b) {
            if ($cState -eq 'Gap') { $newGaps += $c }
            continue
        }
        $bState = [string]$b.State
        $bOrd = if ($sOrder.ContainsKey($bState)) { $sOrder[$bState] } else { 3 }
        $cOrd = if ($sOrder.ContainsKey($cState)) { $sOrder[$cState] } else { 3 }

        if     ($bState -eq 'Gap' -and $cState -eq 'Satisfied') { $resolved      += $c }
        elseif ($bState -eq 'Gap' -and $cState -eq 'Partial')   { $improved      += $c }
        elseif ($bState -eq 'Gap' -and $cState -eq 'Gap')       { $unchangedGaps += $c }
        elseif ($cState -eq 'Gap' -and $bState -ne 'Gap')       { $newGaps       += $c }
        elseif ($cOrd -gt $bOrd)                                { $regressed     += $c }
    }

    # ── Score computation ───────────────────────────────────────────────────
    # v4.10.1: replaced the nested Get-Score function with a canonical helper.
    # -ErrorHandling Gap preserves the prior Delta semantics (Error counted in
    # denominator). The current vs baseline scores use identical math so the
    # delta arrow stays meaningful even after the refactor.
    $currScore  = (Get-NRGCoverageScore -Findings $CurrentFindings -ErrorHandling 'Gap').Score
    $baseScore  = (Get-NRGCoverageScore -Findings $baseFindings    -ErrorHandling 'Gap').Score
    $scoreDelta = $currScore - $baseScore
    $scoreArrow = if ($scoreDelta -gt 0) { "&#9650; +$scoreDelta" }
                  elseif ($scoreDelta -lt 0) { "&#9660; $scoreDelta" }
                  else { "&#9654; 0" }

    # ── Header strings (operator + tenant controlled, strict-escape) ────────
    $baseDate = EscMdStrict ($baselineRaw.Metadata.AssessmentDate ?? 'prior run')
    $currDate = EscMdStrict ($Metadata.AssessmentDate ?? (Get-Date -Format 'MMMM dd, yyyy'))
    $client   = EscMdStrict ($Metadata.TenantDomain   ?? 'Client')

    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine("# Assessment Delta Report")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**Client:** $client  ")
    $null = $sb.AppendLine("**Current assessment:** $currDate  ")
    $null = $sb.AppendLine("**Baseline:** $baseDate  ")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("## Score Change")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("| | Baseline | Current | Change |")
    $null = $sb.AppendLine("|---|---|---|---|")
    $null = $sb.AppendLine("| Security Score | $baseScore/100 | $currScore/100 | **$scoreArrow** |")
    $baseGaps = @($baseFindings | Where-Object State -eq 'Gap').Count
    $currGaps = @($CurrentFindings | Where-Object State -eq 'Gap').Count
    $null = $sb.AppendLine("| Total Gaps | $baseGaps | $currGaps | $(if($currGaps -lt $baseGaps){"&#9650; -$($baseGaps-$currGaps)"}elseif($currGaps -gt $baseGaps){"&#9660; +$($currGaps-$baseGaps)"}else{"&#9654; 0"}) |")
    $null = $sb.AppendLine()

    function Write-Section {
        param([string]$title, [object[]]$items, [string]$icon, [string]$emptyMsg)
        $null = $sb.AppendLine("## $icon $title ($($items.Count))")
        $null = $sb.AppendLine()
        if ($items.Count -eq 0) { $null = $sb.AppendLine("*$emptyMsg*"); $null = $sb.AppendLine(); return }
        $null = $sb.AppendLine("| Control | Title | Severity |")
        $null = $sb.AppendLine("|---|---|---|")
        foreach ($f in ($items | Sort-Object @{Expression={ switch($_.Severity){'Critical'{0};'High'{1};'Medium'{2};'Low'{3};default{4}} }},ControlId)) {
            $null = $sb.AppendLine("| $(EscMdStrict $f.ControlId) | $(EscMdStrict $f.Title) | $(EscMdStrict $f.Severity) |")
        }
        $null = $sb.AppendLine()
    }

    Write-Section '&#x1F534; New Gaps'         $newGaps       '🔴' 'No new gaps — good.'
    Write-Section '&#x1F7E0; Regressed'         $regressed     '🟠' 'No regressions.'
    Write-Section '&#x1F7E1; Unchanged Gaps'    $unchangedGaps '🟡' 'No unchanged gaps.'
    Write-Section '&#x1F7E2; Resolved'          $resolved      '🟢' 'No gaps resolved this period.'
    Write-Section '&#x1F535; Partially Improved' $improved     '🔵' 'No partial improvements.'

    # ── Configuration Drift (Phase 3) ────────────────────────────────────
    $baseRaw = $null
    if ($baselineRaw.PSObject.Properties['RawData']) {
        $baseRaw = @{}
        foreach ($p in $baselineRaw.RawData.PSObject.Properties) {
            $baseRaw[$p.Name] = $p.Value
        }
    }
    $drift = Get-NRGRawDataDrift -Baseline $baseRaw -Current $CurrentRawData

    $null = $sb.AppendLine("## &#x1F501; Configuration Drift")
    $null = $sb.AppendLine()
    if ($drift.BaselineMissing) {
        $null = $sb.AppendLine("*Baseline run did not capture raw configuration data — drift detection unavailable. The next assessment cycle (after this run) will produce a drift-capable baseline.*")
        $null = $sb.AppendLine()
    } elseif ($drift.CurrentMissing) {
        $null = $sb.AppendLine("*Current run did not capture raw configuration data — drift detection unavailable.*")
        $null = $sb.AppendLine()
    } else {
        # CA policies
        $caAny = $drift.CAPoliciesAdded.Count + $drift.CAPoliciesRemoved.Count + $drift.CAPoliciesStateChange.Count
        $null = $sb.AppendLine("### Conditional Access Policies ($caAny change$(if($caAny -ne 1){'s'}))")
        $null = $sb.AppendLine()
        if ($caAny -eq 0) {
            $null = $sb.AppendLine("*No CA policy changes since baseline.*")
        } else {
            $null = $sb.AppendLine("| Change | Policy | Detail |")
            $null = $sb.AppendLine("|---|---|---|")
            foreach ($p in $drift.CAPoliciesAdded)       { $null = $sb.AppendLine("| Added         | $(EscMdStrict $p.DisplayName) | State: $(EscMdStrict $p.State) |") }
            foreach ($p in $drift.CAPoliciesRemoved)     { $null = $sb.AppendLine("| Removed       | $(EscMdStrict $p.DisplayName) | Was: $(EscMdStrict $p.State) |") }
            foreach ($p in $drift.CAPoliciesStateChange) { $null = $sb.AppendLine("| State changed | $(EscMdStrict $p.DisplayName) | $(EscMdStrict $p.From) -> $(EscMdStrict $p.To) |") }
        }
        $null = $sb.AppendLine()

        # New admin role assignments
        $null = $sb.AppendLine("### New Admin Role Assignments ($($drift.NewAdminAssignments.Count))")
        $null = $sb.AppendLine()
        if ($drift.NewAdminAssignments.Count -eq 0) {
            $null = $sb.AppendLine("*No new admin role assignments since baseline.*")
        } else {
            $null = $sb.AppendLine("| Privilege | Role | Assigned to | Type |")
            $null = $sb.AppendLine("|---|---|---|---|")
            foreach ($r in ($drift.NewAdminAssignments | Sort-Object @{Expression={if($_.HighPrivilege){0}else{1}}}, RoleDisplayName)) {
                $tag = if ($r.HighPrivilege) { '&#x1F534; High' } else { 'Standard' }
                $upnRaw = if ($r.PrincipalUPN) { $r.PrincipalUPN } else { $r.PrincipalName }
                $null = $sb.AppendLine("| $tag | $(EscMdStrict $r.RoleDisplayName) | $(EscMdStrict $upnRaw) | $(EscMdStrict $r.AssignmentType) |")
            }
        }
        $null = $sb.AppendLine()

        # New OAuth apps
        $null = $sb.AppendLine("### New OAuth App Registrations ($($drift.NewOAuthApps.Count))")
        $null = $sb.AppendLine()
        if ($drift.NewOAuthApps.Count -eq 0) {
            $null = $sb.AppendLine("*No new OAuth apps since baseline.*")
        } else {
            $null = $sb.AppendLine("| Risk | App | Publisher | Risky Scopes |")
            $null = $sb.AppendLine("|---|---|---|---|")
            foreach ($a in ($drift.NewOAuthApps | Sort-Object @{Expression={if($_.HighRisk){0}else{1}}}, DisplayName)) {
                $tag = if ($a.HighRisk) { '&#x1F534; High' } else { 'Standard' }
                $scopesRaw = if ($a.RiskyScopes.Count -gt 0) { ($a.RiskyScopes | ForEach-Object { EscMdStrict $_ }) -join ', ' } else { '—' }
                $null = $sb.AppendLine("| $tag | $(EscMdStrict $a.DisplayName) | $(EscMdStrict $a.Publisher) | $scopesRaw |")
            }
        }
        $null = $sb.AppendLine()

        # DMARC regressions
        $null = $sb.AppendLine("### DMARC Policy Regressions ($($drift.DMARCRegressions.Count))")
        $null = $sb.AppendLine()
        if ($drift.DMARCRegressions.Count -eq 0) {
            $null = $sb.AppendLine("*No DMARC policy regressions since baseline.*")
        } else {
            $null = $sb.AppendLine("| Domain | Policy regression |")
            $null = $sb.AppendLine("|---|---|")
            foreach ($d in $drift.DMARCRegressions) {
                $null = $sb.AppendLine("| $(EscMdStrict $d.Domain) | $(EscMdStrict $d.From) -> $(EscMdStrict $d.To) |")
            }
        }
        $null = $sb.AppendLine()
    }

    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("## Trend Summary")
    $null = $sb.AppendLine()
    if ($resolved.Count -gt 0 -and $newGaps.Count -eq 0) {
        $null = $sb.AppendLine("> **Positive trend.** $($resolved.Count) gap(s) resolved with no new gaps introduced.")
    } elseif ($newGaps.Count -gt $resolved.Count) {
        $null = $sb.AppendLine("> **Negative trend.** $($newGaps.Count) new gap(s) exceed $($resolved.Count) resolved gap(s). Security posture deteriorated this period.")
    } elseif ($resolved.Count -gt 0) {
        $null = $sb.AppendLine("> **Mixed trend.** $($resolved.Count) gap(s) resolved, $($newGaps.Count) new gap(s) introduced.")
    } else {
        $null = $sb.AppendLine("> **No change.** Posture unchanged from baseline.")
    }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("**Recommended next action:**")
    if ($newGaps.Count -gt 0) {
        $topNew = $newGaps | Sort-Object @{Expression={switch($_.Severity){'Critical'{0};'High'{1};default{2}}}} | Select-Object -First 3
        $topTitles = ($topNew | ForEach-Object { EscMdStrict $_.Title }) -join ', '
        $null = $sb.AppendLine("Address the $($newGaps.Count) new gap(s) first, prioritizing: $topTitles.")
    } elseif ($unchangedGaps.Count -gt 0) {
        $null = $sb.AppendLine("$($unchangedGaps.Count) gap(s) remain unresolved from prior assessment. Focus on completing Phase 1 remediation.")
    } else {
        $null = $sb.AppendLine("All prior gaps resolved. Schedule next full assessment in 90 days.")
    }
    $null = $sb.AppendLine()
    $null = $sb.AppendLine("---")
    $null = $sb.AppendLine("*NRG-Assessment v$(EscMdStrict ($Metadata.ToolVersion ?? '4.5.5')) · NRG Technology Services / NextLayerSec LLC · $currDate*")
    # Audit fix (v4.6.x LOW): the prior `$toolVer = EscMdStrict ...` assignment
    # on this line was dead — the value is already inlined into the footer
    # AppendLine above and no other consumer reads $toolVer. Removed to keep
    # the file lint-clean under PSReviewUnusedVariable.

    # Publisher self-hardens via Set-NRGSensitiveFileContent: the file is
    # pre-created and its ACL applied BEFORE tenant data lands. Writing with a
    # bare Out-File lets the file inherit the parent directory ACL for the
    # duration of the write, which on a shared MSP workstation or a synced
    # OneDrive folder is a window in which a co-resident process can read CA
    # policies, admin UPNs, OAuth grants and DMARC records. Hardening travels
    # with the terminal write so no caller can forget it. The Out-File fallback
    # preserves behavior if Lib/ has not been dot-sourced.
    if (Get-Command Set-NRGSensitiveFileContent -ErrorAction SilentlyContinue) {
        Set-NRGSensitiveFileContent -Path $OutputPath -Content $sb.ToString()
    } else {
        $sb.ToString() | Out-File -LiteralPath $OutputPath -Encoding utf8
        if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
            Set-NRGSensitiveFileAcl -Path $OutputPath -ErrorAction SilentlyContinue
        }
    }
}