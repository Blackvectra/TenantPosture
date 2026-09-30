#Requires -Version 7.0
#
# Publish-NRGReportSite.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: A multi-page HTML report organized the way an assessor navigates it: one landing
#          page with workload summaries and links, one page per workload grouped by security
#          topic, and an action-plan CSV. Each control row keeps FOUR things apart:
#            requirement   what the control asks for
#            observed      what the tenant is configured to do
#            NRG verdict   the baseline judgment (Satisfied / Partial / Gap / Not assessed ...)
#            independent   how an independent scan (ScubaGear) judged the mapped rule, when a
#                          results file is supplied. A difference is something to investigate,
#                          never a score to match.
#          Requirement strength (ScubaGear's SHALL / SHOULD) is shown apart from risk severity,
#          and the Automated / Manual / Declaration badge is separate from the verdict. Evidence,
#          exclusions, affected objects and collection limitations are expandable.
#
#          A VIEW over existing results: it computes no verdict, changes no finding and moves no
#          score. Self-contained HTML (inline CSS, no script, no external assets).
#
# Data consumed: findings, metadata, baseline compliance rows, scan results (all passed in).
# Graph scopes / cmdlets: none.

$script:NRGSiteWorkloadNames = [ordered]@{
    AAD = 'Identity (Entra ID)'; EXO = 'Exchange Online'; DNS = 'Email authentication (DNS)'; DEF = 'Defender for Office 365'
    TMS = 'Microsoft Teams'; SPO = 'SharePoint and OneDrive'; PVW = 'Purview (compliance)'; INT = 'Intune (devices)'
    PPL = 'Power Platform'; DEV = 'Endpoint checks'
}

function Get-NRGFindingLimitKind {
    <#
    .SYNOPSIS
        Presentation classification of WHY a finding is not a verdict, from the evaluator's own
        wording. Distinguishes a collection failure, a licensing limit, a manual check, an operator
        declaration and an unapproved NRG standard. Changes nothing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Finding)
    $state  = [string](Get-NRGObjectField -Item $Finding -Key 'State' -Default '')
    if ($state -ne 'NotApplicable') { return 'Verdict' }
    $detail = [string](Get-NRGObjectField -Item $Finding -Key 'Detail' -Default '')
    if ($detail.StartsWith('Third-party EDR declared:')) { return 'Declaration' }
    if ($detail -match 'requires manual verification|manual review required|no programmatic check') { return 'Manual' }
    if ($detail -match 'because (none|no [^,.;]*?) (is|are) (approved|configured)') { return 'StandardNotApproved' }
    if ($detail -match 'upgrade opportunity') { return 'Licensing' }
    if ($detail -match 'not collected|was not collected|did not complete|did not run|not assessed|unavailable|could not be retrieved|could not be determined|no data returned|produced data|not returned|not found in collected data|not available|was not read|not read\b|403|Forbidden|consent') { return 'Collection' }
    return 'NotApplicable'
}

function Get-NRGSiteVerdict {
    [CmdletBinding()]
    param([AllowNull()] $Finding, [string] $Kind)
    $state = [string](Get-NRGObjectField -Item $Finding -Key 'State' -Default '')
    switch ($state) {
        'Satisfied' { return @{ Label = 'Satisfied'; Css = 'ok' } }
        'Partial'   { return @{ Label = 'Partial'; Css = 'part' } }
        'Gap'       { return @{ Label = 'Gap'; Css = 'gap' } }
        'Error'     { return @{ Label = 'Error'; Css = 'gap' } }
    }
    switch ($Kind) {
        'Declaration'         { return @{ Label = 'Declared, not verified'; Css = 'na' } }
        'Licensing'           { return @{ Label = 'Not licensed (not scored)'; Css = 'na' } }
        'NotApplicable'       { return @{ Label = 'Not applicable'; Css = 'na' } }
        default               { return @{ Label = 'Not assessed'; Css = 'unk' } }
    }
}

function ConvertTo-NRGCsvCell {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $Value)
    $s = if ($null -eq $Value) { '' } elseif ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) { (@($Value) | ForEach-Object { [string]$_ }) -join '; ' } else { [string]$Value }
    $s = ($s -replace '[\r\n]+', ' ').Trim()
    # A cell starting with = + - @ is read as a formula by a spreadsheet; tenant-controlled text must not be.
    if ($s -match '^[=+\-@\t]') { $s = "'" + $s }
    return $s
}

function Get-NRGSiteRows {
    <#
    .SYNOPSIS
        One row per finding, joined to its control definition, baseline row, SCuBA alignment and
        (optionally) the independent scan's result.
    #>
    [CmdletBinding()]
    param([AllowNull()] [object[]] $Findings, [AllowNull()] $BaselineCompliance, [AllowNull()] $Scuba)
    $ctl = @{}
    $cpath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Config' 'controls.json'
    if (Test-Path -LiteralPath $cpath) {
        foreach ($c in @((Get-Content -LiteralPath $cpath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 30).controls)) { $ctl[[string]$c.ControlId] = $c }
    }
    $base = @{}
    foreach ($b in @(Get-NRGObjectField -Item $BaselineCompliance -Key 'Controls' -Default @())) { $base[[string](Get-NRGObjectField -Item $b -Key 'ControlId' -Default '')] = $b }
    $al = Get-NRGScubaAlignment
    foreach ($f in @($Findings | Where-Object { $null -ne $_ })) {
        $cid  = [string](Get-NRGObjectField -Item $f -Key 'ControlId' -Default '')
        $c    = $ctl[$cid]
        $kind = Get-NRGFindingLimitKind -Finding $f
        $v    = Get-NRGSiteVerdict -Finding $f -Kind $kind
        $prefix = ($cid -split '-')[0]
        $b    = $base[$cid]
        $disp = [string](Get-NRGObjectField -Item $b -Key 'Disposition' -Default '')
        $autoFlag = if ($c) { (Get-NRGObjectField -Item $c -Key 'Automated' -Default $true) -eq $true } else { $true }
        $type = if ($kind -eq 'Declaration' -or $disp -eq 'ApprovedException') { 'Declaration' } elseif ($kind -eq 'Manual' -or -not $autoFlag) { 'Manual' } else { 'Automated' }
        $m = $null; if ($al.Available -and $al.Mappings.Contains($cid)) { $m = $al.Mappings[$cid] }
        $scubaId = if ($m) { [string](Get-NRGObjectField -Item $m -Key 'Current' -Default '') } else { '' }
        $indep = if ($scubaId -and $Scuba -and $Scuba.ContainsKey($scubaId)) { [string]$Scuba[$scubaId] } else { '' }
        [pscustomobject]@{
            ControlId = $cid; Instance = [string](Get-NRGObjectField -Item $f -Key 'Instance' -Default '')
            Workload = $prefix; Topic = [string](Get-NRGObjectField -Item $f -Key 'Category' -Default 'General')
            Title = [string](Get-NRGObjectField -Item $f -Key 'Title' -Default ''); State = [string](Get-NRGObjectField -Item $f -Key 'State' -Default '')
            Kind = $kind; VerdictLabel = $v.Label; VerdictCss = $v.Css; Type = $type
            RiskSeverity = [string](Get-NRGObjectField -Item $f -Key 'Severity' -Default '')
            Tier = [string](Get-NRGObjectField -Item $b -Key 'RequiredTier' -Default '')
            Owner = [string](Get-NRGObjectField -Item $b -Key 'Owner' -Default '')
            Detail = [string](Get-NRGObjectField -Item $f -Key 'Detail' -Default '')
            Observed = [string](Get-NRGObjectField -Item $f -Key 'CurrentValue' -Default '')
            Required = [string](Get-NRGObjectField -Item $f -Key 'RequiredValue' -Default '')
            Remediation = [string](Get-NRGObjectField -Item $f -Key 'Remediation' -Default '')
            Affected = @(Get-NRGObjectField -Item $f -Key 'AffectedObjects' -Default @())
            Frameworks = [string](Get-NRGObjectField -Item $f -Key 'FrameworkIds' -Default '')
            ScubaId = $scubaId; ScubaRelation = $(if ($m) { [string](Get-NRGObjectField -Item $m -Key 'Relation' -Default '') } else { '' })
            ScubaStrength = $(if ($m) { [string](Get-NRGObjectField -Item $m -Key 'RequirementStrength' -Default '') } else { '' })
            ScubaNote = $(if ($m) { [string](Get-NRGObjectField -Item $m -Key 'Note' -Default '') } else { '' })
            IndependentResult = $indep
            ReasonCode = [string](Get-NRGObjectField -Item $b -Key 'ReasonCode' -Default '')
        }
    }
}

function Publish-NRGActionPlan {
    <#
    .SYNOPSIS
        Action-plan CSV: one row per finding that needs an action (a shortfall to fix, a
        component to verify, or an NRG standard to decide), with blank owner, target date,
        resolution status and evidence fields for the team to fill in.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object[]] $Rows, [Parameter(Mandatory)] [string] $Path)
    $need = @($Rows | Where-Object { $_.State -in @('Gap', 'Partial', 'Error') -or ($_.State -eq 'NotApplicable' -and $_.Kind -in @('Collection', 'StandardNotApproved', 'Manual')) })
    $out = foreach ($r in $need) {
        $action = if ($r.State -in @('Gap', 'Partial', 'Error')) { 'Remediate' } elseif ($r.Kind -eq 'StandardNotApproved') { 'Approve the NRG standard' } elseif ($r.Kind -eq 'Manual') { 'Verify manually' } else { 'Re-collect and verify' }
        [ordered]@{
            'Control ID' = $r.ControlId; 'Instance' = $r.Instance; 'Workload' = $r.Workload; 'Security topic' = $r.Topic; 'Control' = $r.Title
            'NRG verdict' = $r.VerdictLabel; 'Risk severity' = $r.RiskSeverity; 'Check type' = $r.Type; 'Action type' = $action
            'Observed' = $r.Observed; 'Required' = $r.Required; 'Why (verified / shortfall / not assessed)' = $r.Detail; 'Remediation' = $r.Remediation
            'Suggested owner area' = $r.Owner; 'Owner' = ''; 'Target date' = ''; 'Resolution status' = 'Open'; 'Evidence of resolution' = ''; 'Notes' = ''
        }
    }
    $lines = [System.Collections.Generic.List[string]]::new()
    $hdr = @('Control ID','Instance','Workload','Security topic','Control','NRG verdict','Risk severity','Check type','Action type','Observed','Required','Why (verified / shortfall / not assessed)','Remediation','Suggested owner area','Owner','Target date','Resolution status','Evidence of resolution','Notes')
    $lines.Add(($hdr | ForEach-Object { '"' + ($_ -replace '"', '""') + '"' }) -join ',')
    foreach ($o in @($out)) { $lines.Add((($hdr | ForEach-Object { '"' + ((ConvertTo-NRGCsvCell $o[$_]) -replace '"', '""') + '"' }) -join ',')) }
    [System.IO.File]::WriteAllLines($Path, $lines, [System.Text.UTF8Encoding]::new($true))
    return @($out).Count
}

function Publish-NRGReportSite {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [hashtable] $Metadata,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Findings,
        [Parameter(Mandatory)] [string] $OutputPath,
        [AllowNull()] $BaselineCompliance = $null,
        [AllowNull()] $Coverage = $null,
        [string] $ScubaResultsPath
    )
    foreach ($req in 'ConvertTo-NRGHtmlSafe', 'Get-NRGObjectField', 'Get-NRGScubaAlignment') {
        if (-not (Get-Command $req -ErrorAction SilentlyContinue)) { throw "$req not loaded: refusing to generate the report site without it." }
    }
    if ($OutputPath -match '\.\.[\\/]') { throw 'Path traversal not allowed in OutputPath.' }
    $null = [System.IO.Directory]::CreateDirectory($OutputPath)
    $hx = { param($v) ConvertTo-NRGHtmlSafe $v }

    $brand = @{ CompanyName = 'NRG Technology Services'; PrimaryColor = '#1a3a6b'; SecondaryColor = '#e87722'; AccentColor = '#4a7ba6'; Website = '' }
    $bp = Join-Path (Split-Path -Parent $PSScriptRoot) 'Config' 'branding.psd1'
    if (Test-Path -LiteralPath $bp) { try { $b = Import-PowerShellDataFile -LiteralPath $bp; foreach ($k in @($brand.Keys)) { if ($b.ContainsKey($k) -and $b[$k]) { $brand[$k] = [string]$b[$k] } } } catch { Write-Verbose "Branding unreadable: $($_.Exception.Message)" } }
    # Colors are interpolated into CSS: accept only a #rrggbb value.
    foreach ($k in 'PrimaryColor', 'SecondaryColor', 'AccentColor') { if ($brand[$k] -notmatch '^#[0-9a-fA-F]{6}$') { $brand[$k] = @{ PrimaryColor = '#1a3a6b'; SecondaryColor = '#e87722'; AccentColor = '#4a7ba6' }[$k] } }

    $scuba = $null
    if ($ScubaResultsPath -and (Test-Path -LiteralPath $ScubaResultsPath)) {
        $scuba = @{}
        foreach ($r in @(Import-Csv -LiteralPath $ScubaResultsPath -Encoding utf8)) { $id = [string]$r.'Control ID'; if ($id) { $scuba[$id] = [string]$r.Result } }
    }
    $rows = @(Get-NRGSiteRows -Findings $Findings -BaselineCompliance $BaselineCompliance -Scuba $scuba)

    $css = @"
:root{--p:$($brand.PrimaryColor);--s:$($brand.SecondaryColor);--a:$($brand.AccentColor);--bg:#f5f7fa;--fg:#1f2937;--mut:#6b7280;--card:#fff;--line:#e5e7eb}
@media (prefers-color-scheme:dark){:root{--bg:#0f172a;--fg:#e5e7eb;--mut:#9ca3af;--card:#1e293b;--line:#334155}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--fg)}
header{background:var(--p);color:#fff;padding:18px 24px;border-bottom:4px solid var(--s)}header h1{margin:0;font-size:1.25rem}header .sub{opacity:.85;font-size:.9rem}
nav{padding:10px 24px;background:var(--card);border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:6px 16px}nav a{color:var(--a);text-decoration:none;font-weight:600}
main{max-width:1200px;margin:0 auto;padding:20px 16px 48px}h2{margin:28px 0 8px;font-size:1.1rem;border-bottom:2px solid var(--s);padding-bottom:4px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin:12px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.stat{text-align:center;padding:10px;border:1px solid var(--line);border-radius:8px;background:var(--card)}.stat b{display:block;font-size:1.5rem}
table{width:100%;border-collapse:collapse;table-layout:auto;background:var(--card);font-size:.88rem}th,td{padding:7px 9px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top;overflow-wrap:anywhere}.scroll{overflow-x:auto}th{background:var(--p);color:#fff;position:sticky;top:0}
.pill{display:inline-block;padding:1px 9px;border-radius:999px;font-size:.78rem;font-weight:700;color:#fff;white-space:nowrap}.ok{background:#15803d}.part{background:#b45309}.gap{background:#b91c1c}.unk{background:#475569}.na{background:#64748b}
.badge{display:inline-block;padding:0 7px;border:1px solid var(--a);color:var(--a);border-radius:4px;font-size:.74rem;font-weight:700}.badge.m{border-color:#7c3aed;color:#7c3aed}.badge.d{border-color:#0e7490;color:#0e7490}
.mut{color:var(--mut)}.strength{font-size:.74rem;font-weight:700;color:var(--mut);border:1px solid var(--line);padding:0 6px;border-radius:4px}
details{margin:2px 0}summary{cursor:pointer;color:var(--a);font-weight:600}.ev{padding:8px 4px;font-size:.86rem}.ev dt{font-weight:700;margin-top:6px}.ev dd{margin:0 0 0 0}
.diff{border-left:4px solid var(--s);padding-left:10px}code{font-size:.85em}.note{font-size:.85rem;color:var(--mut)}
@media print{nav{display:none}details{display:block}details>summary{display:none}}
@media(max-width:700px){th:nth-child(n+5),td:nth-child(n+5){display:none}}
"@

    # Metadata may come from a replayed results file that lacks a key; read every key safely.
    $mv = { param($k) [string](Get-NRGObjectField -Item $Metadata -Key $k -Default '') }
    $tenant = & $hx (& $mv 'TenantDomain')
    $runAtRaw = & $mv 'AssessmentTime'; if (-not $runAtRaw) { $runAtRaw = & $mv 'AssessmentDate' }
    $runAt  = & $hx $runAtRaw
    $toolVer = & $hx (& $mv 'ToolVersion')
    $tenantId = & $hx (& $mv 'TenantId')
    $shell = {
        param($Title, $Body, $Active)
        $navLinks = "<a href='index.html'>Overview</a>" + ((@($rows | ForEach-Object { $_.Workload } | Sort-Object -Unique) | ForEach-Object { $n = $script:NRGSiteWorkloadNames[$_]; if ($n) { "<a href='$_.html'>$(& $hx $n)</a>" } }) -join '')
        "<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'><title>$(& $hx $Title) - $(& $hx $brand.CompanyName)</title><style>$css</style></head><body><header><h1>$(& $hx $brand.CompanyName) &middot; Microsoft 365 security assessment</h1><div class='sub'>$tenant &middot; run $runAt &middot; NRG-Assessment $toolVer</div></header><nav>$navLinks</nav><main>$Body</main></body></html>"
    }

    # ── Per-workload pages ────────────────────────────────────────────────────
    $written = [System.Collections.Generic.List[string]]::new()
    $counts = [ordered]@{}
    foreach ($wl in @($rows | ForEach-Object { $_.Workload } | Sort-Object -Unique)) {
        $wrows = @($rows | Where-Object { $_.Workload -eq $wl })
        $name = $script:NRGSiteWorkloadNames[$wl]; if (-not $name) { $name = $wl }
        $counts[$wl] = [ordered]@{ Name = $name; Total = $wrows.Count
            Satisfied = @($wrows | Where-Object { $_.State -eq 'Satisfied' }).Count; Partial = @($wrows | Where-Object { $_.State -eq 'Partial' }).Count
            Gap = @($wrows | Where-Object { $_.State -in @('Gap', 'Error') }).Count
            NotAssessed = @($wrows | Where-Object { $_.State -eq 'NotApplicable' -and $_.Kind -in @('Collection', 'StandardNotApproved', 'Manual') }).Count
            Other = @($wrows | Where-Object { $_.State -eq 'NotApplicable' -and $_.Kind -in @('Licensing', 'Declaration', 'NotApplicable') }).Count }
        $body = "<h2>$(& $hx $name)</h2><p class='note'>Grouped by security topic. The verdict is NRG's baseline judgment; the badge says how the check was made (automated, manual, or an operator declaration) and is not a verdict. Risk severity is NRG's; requirement strength (SHALL / SHOULD) is the independent baseline's and is shown only where a rule is mapped.</p>"
        foreach ($topic in @($wrows | ForEach-Object { $_.Topic } | Sort-Object -Unique)) {
            $trows = @($wrows | Where-Object { $_.Topic -eq $topic } | Sort-Object ControlId, Instance)
            $body += "<h2 style='font-size:1rem'>$(& $hx $topic)</h2><div class='scroll'><table><thead><tr><th>Control</th><th>Requirement</th><th>NRG verdict</th><th>Risk</th><th>Check</th><th>Observed</th><th>Independent comparison</th><th>Evidence</th></tr></thead><tbody>"
            foreach ($r in $trows) {
                $inst = if ($r.Instance) { " <span class='mut'>($(& $hx $r.Instance))</span>" } else { '' }
                $badgeCss = switch ($r.Type) { 'Manual' { 'badge m' } 'Declaration' { 'badge d' } default { 'badge' } }
                $req = "<b>$(& $hx $r.Title)</b>$(if ($r.Required) { "<div class='mut'>Required: $(& $hx $r.Required)</div>" })"
                $cmp = if ($r.ScubaId) {
                    $ind = if ($r.IndependentResult) { "<div>Independent scan: <b>$(& $hx $r.IndependentResult)</b></div>" } else { '' }
                    $diff = ''
                    if ($r.IndependentResult) {
                        if (($r.State -eq 'Satisfied' -and $r.IndependentResult -eq 'Fail') -or ($r.State -in @('Gap', 'Partial') -and $r.IndependentResult -eq 'Pass')) { $diff = " class='diff'" }
                    }
                    "<div$diff><code>$(& $hx $r.ScubaId)</code> <span class='strength'>$(& $hx $r.ScubaStrength)</span> &middot; $(& $hx $r.ScubaRelation)$ind</div>"
                } else { "<span class='mut'>no mapped rule</span>" }
                $ev = "<dl class='ev'><dt>Detail</dt><dd>$(& $hx $r.Detail)</dd>"
                if ($r.Observed) { $ev += "<dt>Observed</dt><dd>$(& $hx $r.Observed)</dd>" }
                if ($r.Kind -ne 'Verdict') { $ev += "<dt>Limitation</dt><dd>$(& $hx @{ Collection = 'Collection: the evidence was not read'; Manual = 'Manual check: no automated test'; Declaration = 'Operator declaration: not verified by this assessment'; Licensing = 'Licensing: not scored'; StandardNotApproved = 'An NRG standard is not approved or configured'; NotApplicable = 'Reported not applicable' }[$r.Kind])</dd>" }
                if (@($r.Affected).Count -gt 0) {
                    $aff = @($r.Affected | Select-Object -First 25 | ForEach-Object { if ($_ -is [System.Collections.IDictionary]) { ($_.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join ', ' } elseif ($_ -isnot [string] -and @($_.PSObject.Properties).Count -gt 0 -and $_ -isnot [ValueType]) { ($_.PSObject.Properties | ForEach-Object { "$($_.Name): $($_.Value)" }) -join ', ' } else { [string]$_ } })
                    $ev += "<dt>Affected objects ($(@($r.Affected).Count))</dt><dd>$((@($aff | ForEach-Object { & $hx $_ }) -join '<br>'))$(if (@($r.Affected).Count -gt 25) { '<br>...' })</dd>"
                }
                if ($r.Remediation -and $r.State -ne 'Satisfied') { $ev += "<dt>Remediation</dt><dd>$(& $hx $r.Remediation)</dd>" }
                if ($r.ScubaNote) { $ev += "<dt>How the independent rule relates</dt><dd>$(& $hx $r.ScubaNote)</dd>" }
                if ($r.Frameworks) { $ev += "<dt>Framework citations</dt><dd>$(& $hx $r.Frameworks)</dd>" }
                $ev += '</dl>'
                $body += "<tr><td><b>$(& $hx $r.ControlId)</b>$inst$(if ($r.Tier) { "<div class='mut'>$(& $hx $r.Tier) tier</div>" })</td><td>$req</td><td><span class='pill $($r.VerdictCss)'>$(& $hx $r.VerdictLabel)</span></td><td>$(& $hx $r.RiskSeverity)</td><td><span class='$badgeCss'>$(& $hx $r.Type)</span></td><td>$(& $hx $r.Observed)</td><td>$cmp</td><td><details><summary>Evidence</summary>$ev</details></td></tr>"
            }
            $body += '</tbody></table></div>'
        }
        $f = Join-Path $OutputPath "$wl.html"
        Set-Content -LiteralPath $f -Value (& $shell $name $body $wl) -Encoding utf8
        $written.Add($f)
    }

    # ── Landing page ──────────────────────────────────────────────────────────
    $tot = @{ Satisfied = 0; Partial = 0; Gap = 0; NotAssessed = 0; Other = 0 }
    foreach ($c in $counts.Values) { foreach ($k in @($tot.Keys)) { $tot[$k] += $c[$k] } }
    $bl = $BaselineCompliance
    $blText = if ($bl -and (Get-NRGObjectField -Item $bl -Key 'Available' -Default $false)) { "NRG Security Baseline $(& $hx (Get-NRGObjectField -Item $bl -Key 'BaselineVersion' -Default '')), target tier $(& $hx (Get-NRGObjectField -Item $bl -Key 'TargetTier' -Default ''))" } else { 'NRG Security Baseline: not resolved for this run' }
    $al = Get-NRGScubaAlignment
    $alText = if ($al.Available) { "Independent baseline mapping: $(& $hx $al.Source.Tool) $(& $hx $al.Source.ToolVersion), checked $(& $hx $al.Source.CheckedOn)" } else { 'Independent baseline mapping: not available' }
    $landing = "<h2>Tenant and run</h2><div class='card'><table><tbody><tr><th style='width:220px'>Tenant</th><td>$tenant</td></tr><tr><th>Tenant ID</th><td>$tenantId</td></tr><tr><th>Run time</th><td>$runAt</td></tr><tr><th>Tool version</th><td>NRG-Assessment $toolVer</td></tr><tr><th>Baseline versions</th><td>$blText<br>$alText$(if ($scuba) { '<br>Independent scan results supplied: shown beside each mapped control' })</td></tr></tbody></table></div>"
    $landing += "<h2>Summary</h2><div class='grid'><div class='stat'><b>$($tot.Satisfied)</b>Satisfied</div><div class='stat'><b>$($tot.Partial)</b>Partial</div><div class='stat'><b>$($tot.Gap)</b>Gap</div><div class='stat'><b>$($tot.NotAssessed)</b>Not assessed</div><div class='stat'><b>$($tot.Other)</b>Not scored (licensing, declared, not applicable)</div></div><p class='note'>These are counts of findings, not a compliance percentage. Not assessed means the tool could not establish the answer (evidence not read, a manual check, or an NRG standard that is not approved); it is neither a pass nor a failure.</p>"
    $landing += "<h2>Workloads</h2><table><thead><tr><th>Workload</th><th>Satisfied</th><th>Partial</th><th>Gap</th><th>Not assessed</th><th>Not scored</th></tr></thead><tbody>"
    foreach ($wl in $counts.Keys) { $c = $counts[$wl]; $landing += "<tr><td><a href='$wl.html'><b>$(& $hx $c.Name)</b></a> <span class='mut'>($($c.Total) findings)</span></td><td>$($c.Satisfied)</td><td>$($c.Partial)</td><td>$($c.Gap)</td><td>$($c.NotAssessed)</td><td>$($c.Other)</td></tr>" }
    $landing += '</tbody></table>'
    $kinds = [ordered]@{ Collection = 'Collection failures (evidence not read)'; Licensing = 'Licensing limits (not scored)'; Manual = 'Manual checks (no automated test)'; Declaration = 'Operator declarations (not verified)'; StandardNotApproved = 'NRG standards not approved or configured' }
    $landing += "<h2>Limitations, kept distinct</h2><div class='card'><ul>"
    foreach ($k in $kinds.Keys) { $n = @($rows | Where-Object { $_.Kind -eq $k }).Count; $landing += "<li><b>$n</b> $(& $hx $kinds[$k])$(if ($n -gt 0) { ': ' + ((@($rows | Where-Object { $_.Kind -eq $k } | Select-Object -First 12 | ForEach-Object { $_.ControlId } | Sort-Object -Unique) -join ', ') -replace '&', '&amp;') + $(if ($n -gt 12) { ', ...' }) })</li>" }
    $landing += "</ul></div>"
    if ($scuba) {
        $cmpRows = @($rows | Where-Object { $_.IndependentResult })
        $diffs = @($cmpRows | Where-Object { ($_.State -eq 'Satisfied' -and $_.IndependentResult -eq 'Fail') -or ($_.State -in @('Gap', 'Partial') -and $_.IndependentResult -eq 'Pass') })
        $landing += "<h2>Independent comparison</h2><div class='card'><p>$($cmpRows.Count) findings map to a rule in the supplied independent scan. <b>$($diffs.Count)</b> differ in direction (NRG satisfied where the scan failed, or NRG found a gap where the scan passed). A difference is a prompt to investigate the configuration, collection time, scope and requirement wording; it is not a score to match, and the two tools may judge the same configuration against different standards.</p>"
        if ($diffs.Count -gt 0) { $landing += '<ul>' + ((@($diffs | Sort-Object ControlId | ForEach-Object { "<li><b>$(& $hx $_.ControlId)</b> NRG $(& $hx $_.VerdictLabel) &middot; $(& $hx $_.ScubaId) independent $(& $hx $_.IndependentResult) &middot; $(& $hx $_.ScubaRelation)</li>" })) -join '') + '</ul>' }
        $landing += '</div>'
    }
    $landing += "<h2>Action plan</h2><div class='card'><p><a href='ActionPlan.csv'>ActionPlan.csv</a>: every shortfall to fix, component to verify and standard to approve, with blank owner, target date, resolution status and evidence columns.</p></div>"
    $lf = Join-Path $OutputPath 'index.html'
    Set-Content -LiteralPath $lf -Value (& $shell 'Overview' $landing '') -Encoding utf8
    $written.Add($lf)
    $planCount = Publish-NRGActionPlan -Rows $rows -Path (Join-Path $OutputPath 'ActionPlan.csv')
    $written.Add((Join-Path $OutputPath 'ActionPlan.csv'))
    return [ordered]@{ Files = @($written); Findings = $rows.Count; ActionPlanRows = $planCount; Workloads = @($counts.Keys) }
}
