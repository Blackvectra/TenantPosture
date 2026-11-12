#Requires -Version 7.0
#
# TP.AiUseReview.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Guards the client-facing AI use readiness review (Config/ai-use-review.json,
# Lib/Get-TPAiUseReview.ps1, Publishers/Publish-TPAiUseReview.ps1,
# New-TPAiUseReview.ps1):
#   - the catalog is valid and a duplicate id, an id not in controls.json, a
#     non-Microsoft or plaintext reference and a role outside the fixed set
#     are errors, never dropped
#   - every catalog control lands in exactly one group; PPL-3.3 is only ever
#     an observation; a control with no finding is named as such
#   - a partial, quick or incident-response file is refused (model and script)
#     while a full run with failed reads is rendered with its gaps visible
#   - counts: collected zero, complete count, lower bound, not established and
#     not read are five different renderings; missing inventory never reads
#     as zero; the Copilot Studio contract (list status, truncation, cap)
#   - licensing state comes from Get-TPCopilotLicensingState and the older
#     compatibility counts are never read
#   - the facts reader is an allowlist: no finding detail, account, object id,
#     agent or environment name, error text, operator or tenant identifier
#     reaches the model or the page; tenant text is escaped; the page loads
#     and runs nothing
#   - the offline scope matches Get-TPAssessmentScope on the same objects, the
#     source file is unchanged, no finding is emitted and the score is unmoved
#   - the PDF is optional: no browser is a note and the HTML stays
#   - the Copilot deployment gate: one shortfall on an approved blocker is
#     "not ready"; a missing verdict is "cannot be determined", never a pass;
#     "no blockers" is always beside what the assessment does not check; no
#     approved list means no verdict; nothing says safe
#   - named accounts appear only when the preparer names them, each requirement
#     as met, to add, confirm, not established or not read
# Data keys consumed: synthetic results files only. Graph scopes / cmdlets: none.

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    $script:Mod = Get-Module 'TenantPosture'
    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('tp-aiur-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    $null = New-Item -ItemType Directory -Path $script:Tmp -Force

    # Non-exported helpers are reached in module scope (the export list adds only the four public functions).
    $script:LoadCatalog = { param([string] $p = '') & $script:Mod { param($x) Get-TPAiUseReviewCatalog -ConfigPath $x } $p }
    $script:NewCount    = { param($v, [string] $c = 'NotRead') & $script:Mod { param($a, $b) New-TPAiUseCount -Kind k -Label l -Value $a -Completeness $b } $v $c }
    $script:Scoring     = { param([object[]] $f) & $script:Mod { param($x) Get-TPScoringFindings -Findings $x } $f }
    $script:ChatNote    = { & $script:Mod { Get-TPCopilotChatEligibilityNote } }
    $script:Catalog = & $script:LoadCatalog
    $script:CatalogIds = @(@($script:Catalog.Controls | ForEach-Object ControlId) + @($script:Catalog.Observations | ForEach-Object ControlId))
    $script:Defs = @{}
    foreach ($c in (Get-TPControlDefinitions)) { $script:Defs[$c.ControlId] = $c }

    # Sentinels: anything from the results file that must never reach the model or the page.
    $script:S = @{
        Marker   = 'DETAIL-MARKER-7a1f'
        Upn      = 'victim@contoso-sentinel.example'
        TenantId = '11111111-2222-3333-4444-555555555555'
        Operator = 'operator@msp-sentinel.example'
        Domain   = 'contoso-sentinel.onmicrosoft.com'
        EnvName  = 'ENV-NAME-SENTINEL'
        EnvId    = 'ENVID-SENTINEL-0001'
        Agent    = 'AGENT-NAME-SENTINEL'
        Error    = 'ERROR-TEXT-SENTINEL'
        SkuId    = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'
        Compat   = '31337'
    }
    $script:EdrMarker = & $script:Mod { $script:TPThirdPartyEdrMarker }

    $script:FullMeta = {
        @{ TenantDomain = $script:S.Domain; TenantId = $script:S.TenantId; Operator = $script:S.Operator
           AssessmentTime = '2026-11-01T14:30:00Z'; ToolVersion = '9.9.9'; QuickScan = $false }
    }
    $script:Finding = {
        param([string] $Id, [string] $State, [string] $Detail = '')
        $d = $script:Defs[$Id]
        @{ ControlId = $Id; State = $State; Severity = $(if ($d) { $d.Severity } else { 'Medium' }); Title = $(if ($d) { $d.Title } else { $Id })
           Category = 'Governance'; Detail = "$($script:S.Marker) $Detail"; CurrentValue = $script:S.Upn; RequiredValue = 'x'; FrameworkIds = 'NIST:AC-1' }
    }
    # The main scenario: a full run whose Purview collector failed, with every
    # kind of verdict the review has to place.
    $script:MainOverrides = @{
        'PPL-3.4' = @('Gap', 'no Copilot Studio DLP policy')
        'SPO-1.1' = @('Partial', 'anyone links allowed on one site')
        'PPL-4.1' = @('Gap', "agent $($script:S.Agent) allows anonymous access")
        'PPL-3.2' = @('NotApplicable', 'Not licensed (upgrade opportunity): original result Gap')
        'SPO-5.3' = @('NotApplicable', 'This control requires manual verification.')
        'AAD-6.4' = @('Error', "$($script:S.Error) 400")
        'PPL-3.3' = @('NotApplicable', 'share not established')
        'PVW-1.4' = @('NotApplicable', 'Purview was not collected; not assessed.')
        'PVW-4.3' = @('NotApplicable', 'Purview was not collected; not assessed.')
        'DEF-4.2' = @('NotApplicable', 'Purview was not collected; not assessed.')
        'DEF-4.5' = @('NotApplicable', 'Purview was not collected; not assessed.')
        'PVW-1.3' = @('NotApplicable', 'Purview was not collected; not assessed.')
        'DEF-4.3' = @('NotApplicable', 'Purview was not collected; not assessed.')
        'DEF-4.1' = @('Satisfied', 'stale pass beside a failed collector')
    }
    $script:MainFindings = {
        $list = [System.Collections.Generic.List[object]]::new()
        foreach ($id in $script:CatalogIds) {
            if ($id -eq 'TMS-2.2') { continue }   # no finding at all
            if ($id -eq 'AAD-6.3') { $list.Add((& $script:Finding $id 'NotApplicable' '')); $list[$list.Count - 1].Detail = "$($script:EdrMarker) Cortex XDR. Original result: Gap. $($script:S.Marker)"; continue }
            $o = $script:MainOverrides[$id]
            if ($o) { $list.Add((& $script:Finding $id $o[0] $o[1])) } else { $list.Add((& $script:Finding $id 'Satisfied' 'ok')) }
        }
        $list.Add((& $script:Finding 'AAD-4.1' 'Gap' 'duplicate row: worst state wins'))        # AAD-4.1 twice
        $list.Add((& $script:Finding 'AAD-1.1' 'Gap' 'outside the catalog'))
        $list.Add(@{ ControlId = 'bogus'; State = 'Gap'; Severity = 'High'; Title = 'malformed'; Category = 'Governance'; Detail = $script:S.Marker })
        $list.ToArray()
    }
    $script:MainCopilotData = {
        [ordered]@{
            SectionStatus = @{ Licensing = 'Collected'; Users = 'Truncated' }
            SectionErrors = @{ Users = "$($script:S.Error) page cap" }
            LicensingMeasurements = @{
                RecognizedSkuCount     = @{ Value = 1;   Completeness = 'Complete';   Source = 'SubscribedSkus' }
                PurchasedSeats         = @{ Value = 25;  Completeness = 'Complete';   Source = 'SubscribedSkus' }
                SkuConsumedUnits       = @{ Value = 12;  Completeness = 'Complete';   Source = 'SubscribedSkus' }
                EnabledMembers         = @{ Value = 100; Completeness = 'Incomplete'; Source = 'Users' }
                AssignedUsers          = @{ Value = 7;   Completeness = 'Incomplete'; Source = 'Users' }
                AssignedEnabledMembers = @{ Value = 6;   Completeness = 'Incomplete'; Source = 'Users' }
            }
            UserEnumeration = @{ StopReason = 'PageCap'; PagesRead = 200; DistinctAccounts = 100; DuplicateRows = 0; RowsWithoutId = 0; AccountEnabledUnknown = 0 }
            LicensedSkus = @(@{ SkuId = $script:S.SkuId; SkuPartNumber = 'Microsoft_365_Copilot'; PrepaidUnits = 25; ConsumedUnits = 12 })
            Users = @(@{ UserPrincipalName = $script:S.Upn; Id = $script:S.TenantId; AccountEnabled = $true })
            CopilotLicensedUserCount = [int]$script:S.Compat
            TotalUserCount = [int]$script:S.Compat
        }
    }
    $script:MainStudioData = {
        [ordered]@{
            SectionStatus = @{ Environments = 'Collected'; ($script:S.EnvId) = 'Collected' }
            SectionErrors = @{ ($script:S.EnvId + '-b') = $script:S.Error }
            Environments = @(
                @{ Id = $script:S.EnvId; DisplayName = $script:S.EnvName; HasDataverse = $true; AgentsStatus = 'Collected'; AgentCount = 2; ManagedAgentCount = 1 },
                @{ Id = $script:S.EnvId + '-b'; DisplayName = $script:S.EnvName + '-b'; HasDataverse = $true; AgentsStatus = 'Truncated'; AgentCount = 5; ManagedAgentCount = 0 },
                @{ Id = $script:S.EnvId + '-c'; DisplayName = $script:S.EnvName + '-c'; HasDataverse = $false; AgentsStatus = 'NotRun'; AgentCount = $null; ManagedAgentCount = $null }
            )
            Agents = @(@{ Name = $script:S.Agent; EnvironmentId = $script:S.EnvId; OwnerId = $script:S.TenantId })
            Limits = @{ MaxEnvironments = 50 }
        }
    }
    $script:Skus = @(
        @{ SkuPartNumber = 'Microsoft_365_Copilot'; SkuId = $script:S.SkuId; ServicePlans = @('M365_COPILOT_APPS', 'M365_COPILOT_BUSINESS_CHAT', 'M365_COPILOT_TEAMS') },
        @{ SkuPartNumber = 'SPB'; SkuId = $script:S.SkuId; ServicePlans = @('EXCHANGE_S_STANDARD', 'AAD_PREMIUM', 'INTUNE_A') }
    )
    $script:NewRun = {
        param([object] $Metadata, [object[]] $Findings, [object] $CopilotData, [object] $StudioData, [object[]] $Skus, [hashtable] $FailedCollectors = @{ Purview = $true })
        $deps = @($script:CatalogIds | ForEach-Object { $script:Defs[$_].CollectorDependency } | Sort-Object -Unique)
        $raw = [ordered]@{}; $cov = [ordered]@{}
        foreach ($k in $deps) {
            $ok = -not $FailedCollectors.ContainsKey($k)
            $raw[$k] = [ordered]@{ CollectorId = $k; CollectedAt = '2026-11-01T14:00:00Z'; Success = $ok; Data = [ordered]@{ Sentinel = $script:S.Upn } }
            $cov[$k] = @{ Status = $(if ($ok) { 'Collected' } else { 'Failed' }); Note = "$($script:S.Error) $k" }
        }
        if ($null -ne $CopilotData) { $raw['M365Copilot'].Data = $CopilotData } else { $raw.Remove('M365Copilot'); $cov.Remove('M365Copilot') }
        if ($null -ne $StudioData) { $raw['CopilotStudio'].Data = $StudioData } else { $raw.Remove('CopilotStudio'); $cov.Remove('CopilotStudio') }
        $raw['AAD-Inventory'].Data = [ordered]@{ SubscribedSkus = @($Skus); Users = @(@{ UserPrincipalName = $script:S.Upn }) }
        [ordered]@{ Metadata = $Metadata; Findings = @($Findings); Coverage = $cov; RawData = $raw; Exceptions = @(@{ Source = 'Purview'; Message = $script:S.Error }) }
    }
    $script:WriteRun = {
        param([object] $Run, [string] $Name)
        $p = Join-Path $script:Tmp $Name
        ($Run | ConvertTo-Json -Depth 24) | Set-Content -LiteralPath $p -Encoding utf8
        $p
    }
    $script:Hash = { param([string] $p) (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash }

    # Build the main scenario the way the standalone script does.
    $script:MainRun = & $script:NewRun (& $script:FullMeta) (& $script:MainFindings) (& $script:MainCopilotData) (& $script:MainStudioData) $script:Skus
    $script:MainPath = & $script:WriteRun $script:MainRun 'main-results.json'
    $script:MainHashBefore = & $script:Hash $script:MainPath
    $script:ScoreBefore = (& $script:Scoring @($script:MainRun.Findings) | ForEach-Object { "$($_.ControlId)=$($_.State)" }) -join ';'
    $script:FindingsInModuleBefore = @(Get-TPFindings).Count

    $script:Rec   = Read-TPRunRecord -Path $script:MainPath
    $script:Facts = Read-TPAiUseFacts -Path $script:MainPath
    $script:Scope = Get-TPAiUseReviewScope -Path $script:MainPath
    $script:M = Get-TPAiUseReview -Findings @($script:Rec.Findings) -Metadata $script:Rec.Metadata -Facts $script:Facts -ScopeBuckets $script:Scope.Buckets -ClientName 'Contoso <script>alert(1)</script> & Co' -PreparedBy 'NextLayerSec, LLC' -BlockerControlIds @('AAD-1.2', 'AAD-1.1', 'SPO-1.1', 'SPO-1.2', 'AAD-6.2', 'AAD-15.1', 'PVW-1.1', 'PPL-3.5', 'PPL-4.1', 'PPL-4.2')
    $script:GroupOf = { param([string] $id) @($script:M.Groups.Keys | Where-Object { @($script:M.Groups[$_] | ForEach-Object ControlId) -contains $id }) }
    $script:ItemOf  = { param([string] $id) @($script:M.Groups.Values | ForEach-Object { $_ } | Where-Object { $_.ControlId -eq $id })[0] }

    # In-memory facts for the count scenarios (no file; ScopeBuckets empty).
    $script:FactsWith = {
        param([object] $CopilotData, [object] $Studio = $null, [object[]] $Skus = @())
        [ordered]@{ Available = $true; IsIncidentResponse = $false
                    Copilot = $(if ($null -ne $CopilotData) { @{ Success = $true; Data = $CopilotData } } else { $null })
                    CopilotStudio = $Studio; SubscribedSkus = $Skus; Coverage = @{}; RawDataSuccess = @{} }
    }
    $script:ModelWith = {
        param([object] $CopilotData, [object] $Studio = $null)
        Get-TPAiUseReview -Findings @(& $script:MainFindings) -Metadata (& $script:FullMeta) -Facts (& $script:FactsWith $CopilotData $Studio) -ScopeBuckets @{}
    }
    $script:CountOf = { param($model, [string] $kind, [string] $label) @($model.Observed.Copilot.Counts | Where-Object { $_.Label -eq $label })[0] }
}

BeforeDiscovery {
    $script:Headless = @(
        $env:TP_PDF_BROWSER,
        '/opt/pw-browsers/chromium_headless_shell-1243/chrome-headless-shell-linux64/chrome-headless-shell'
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Select-Object -First 1
}

AfterAll {
    if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'AI use review: the catalog' {
    It 'is versioned, dated, and names 43 controls that all exist in controls.json' {
        $script:Catalog.Version | Should -Not -BeNullOrEmpty
        $script:Catalog.VendorFactsRetrieved | Should -Match '^\d{4}-\d{2}-\d{2}$'
        $script:CatalogIds.Count | Should -Be 43
        @($script:CatalogIds | Sort-Object -Unique).Count | Should -Be 43
        foreach ($id in $script:CatalogIds) { $script:Defs.ContainsKey($id) | Should -BeTrue -Because "$id must be a control" }
        $script:CatalogIds | Should -Contain 'PPL-3.3'
        @($script:Catalog.Observations | ForEach-Object ControlId) | Should -Be @('PPL-3.3')
        $script:Catalog.ControlsJsonTotal | Should -Be $script:Defs.Count
    }
    It 'every reference and vendor source is an https Microsoft URL with a retrieval date' {
        $refs = @($script:Catalog.Controls | ForEach-Object Reference | Where-Object { $_ }) + @($script:Catalog.VendorFacts | ForEach-Object Source)
        $refs.Count | Should -BeGreaterThan 5
        foreach ($r in $refs) {
            $r.Url | Should -Match '^https://([a-z0-9-]+\.)*microsoft\.com/'
            $r.Retrieved | Should -Match '^\d{4}-\d{2}-\d{2}$'
            $r.Title | Should -Not -BeNullOrEmpty
        }
    }
    It 'the five organizational areas carry an evidence type and roles from the fixed set; the sensitive-information area has both wordings' {
        $areas = @($script:Catalog.Organizational)
        $areas.Count | Should -Be 5
        $roles = & $script:Mod { Get-TPAiUseReviewRoles }
        foreach ($a in $areas) {
            $a.EvidenceType | Should -Not -BeNullOrEmpty
            @($a.SuggestedRoles).Count | Should -BeGreaterThan 0
            foreach ($r in $a.SuggestedRoles) { $roles | Should -Contain $r }
        }
        $si = @($areas | Where-Object Id -eq 'sensitive-information')[0]
        $si.HipaaWording | Should -Match 'ePHI'
        $si.GeneralWording | Should -Not -Match 'ePHI'
    }
    Context 'a defective catalog is an error, never a silent drop' {
        BeforeAll {
            $script:Raw = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config' 'ai-use-review.json') -Raw | ConvertFrom-Json -AsHashtable -Depth 32
            $script:Bad = {
                param([scriptblock] $Mutate, [string] $Name)
                $copy = $script:Raw | ConvertTo-Json -Depth 32 | ConvertFrom-Json -AsHashtable -Depth 32
                & $Mutate $copy
                $p = Join-Path $script:Tmp "catalog-$Name.json"
                ($copy | ConvertTo-Json -Depth 32) | Set-Content -LiteralPath $p -Encoding utf8
                $p
            }
        }
        It 'a control listed twice' {
            $p = & $script:Bad { param($c) $c.controls += @{ ControlId = 'SPO-1.1'; Relationship = 'General'; Scope = 's'; Explanation = 'e'; Reference = $null } } 'dup'
            { & $script:LoadCatalog $p } | Should -Throw '*lists SPO-1.1 twice*'
        }
        It 'an observation that repeats a control' {
            $p = & $script:Bad { param($c) $c.observations += @{ ControlId = 'SPO-1.1'; Why = 'w' } } 'dup2'
            { & $script:LoadCatalog $p } | Should -Throw '*lists SPO-1.1 twice*'
        }
        It 'an id not in controls.json' {
            $p = & $script:Bad { param($c) $c.controls += @{ ControlId = 'ZZZ-9.9'; Relationship = 'General'; Scope = 's'; Explanation = 'e'; Reference = $null } } 'unknown'
            { & $script:LoadCatalog $p } | Should -Throw '*ZZZ-9.9, which is not in controls.json*'
        }
        It 'an id that is not a control id' {
            $p = & $script:Bad { param($c) $c.controls += @{ ControlId = 'drop table'; Relationship = 'General'; Scope = 's'; Explanation = 'e'; Reference = $null } } 'shape'
            { & $script:LoadCatalog $p } | Should -Throw '*not a control id*'
        }
        It 'an unknown relationship' {
            $p = & $script:Bad { param($c) $c.controls[0].Relationship = 'Vibes' } 'rel'
            { & $script:LoadCatalog $p } | Should -Throw '*unknown relationship*'
        }
        It 'a reference that is not https or not Microsoft' {
            $plain = 'ht' + 'tp://learn.microsoft.com/x'
            $p = & $script:Bad { param($c) $c.controls[0].Reference = @{ Title = 't'; Url = $plain; Retrieved = '2026-11-10' } } 'http'
            { & $script:LoadCatalog $p } | Should -Throw '*not an https Microsoft URL*'
            $p = & $script:Bad { param($c) $c.vendorFacts[0].Source = @{ Title = 't'; Url = 'https://example.com/microsoft.com/x'; Retrieved = '2026-11-10' } } 'host'
            { & $script:LoadCatalog $p } | Should -Throw '*not an https Microsoft URL*'
        }
        It 'a reference without a retrieval date' {
            $p = & $script:Bad { param($c) $c.controls[0].Reference = @{ Title = 't'; Url = 'https://learn.microsoft.com/x' } } 'date'
            { & $script:LoadCatalog $p } | Should -Throw '*retrieval date*'
        }
        It 'a suggested role outside the fixed set' {
            $p = & $script:Bad { param($c) $c.organizational[0].SuggestedRoles = @('Business owner', 'Chief Vibes Officer') } 'role'
            { & $script:LoadCatalog $p } | Should -Throw '*outside the fixed set*'
        }
    }
}

Describe 'AI use review: placement' {
    It 'puts every catalog control in exactly one group and the counts sum to the catalog' {
        $script:M.Available | Should -BeTrue
        $script:M.CatalogControls | Should -Be 43
        ($script:M.Counts.Values | Measure-Object -Sum).Sum | Should -Be 43
        $all = @($script:M.Groups.Values | ForEach-Object { $_ } | ForEach-Object ControlId)
        $all.Count | Should -Be 43
        @($all | Group-Object | Where-Object Count -gt 1).Count | Should -Be 0
        foreach ($id in $script:CatalogIds) { @(& $script:GroupOf $id).Count | Should -Be 1 -Because "$id must be placed once" }
    }
    It 'PPL-3.3 is an observation and never a safeguard, whatever its finding says' {
        (& $script:GroupOf 'PPL-3.3') | Should -Be @('Observed')
        $passing = @(& $script:MainFindings | ForEach-Object { if ($_.ControlId -eq 'PPL-3.3') { $_.State = 'Satisfied' }; $_ })
        $m = Get-TPAiUseReview -Findings $passing -Metadata (& $script:FullMeta) -Facts $script:Facts -ScopeBuckets @{}
        @($m.Groups.Verified | ForEach-Object ControlId) | Should -Not -Contain 'PPL-3.3'
        @($m.Groups.Observed | ForEach-Object ControlId) | Should -Be @('PPL-3.3')
    }
    It 'Satisfied is in place; Gap and Partial need attention; a duplicate finding collapses to its worst state' {
        (& $script:GroupOf 'SPO-1.2') | Should -Be @('Verified')
        (& $script:GroupOf 'PPL-3.4') | Should -Be @('Attention')
        (& $script:GroupOf 'SPO-1.1') | Should -Be @('Attention')
        (& $script:ItemOf 'SPO-1.1').ReasonText | Should -Match 'only partly in place'
        (& $script:GroupOf 'AAD-4.1') | Should -Be @('Attention')
        (& $script:ItemOf 'AAD-4.1').State | Should -Be 'Gap'
        $script:M.Reconciliation.DuplicateFindingsCollapsed | Should -Be 1
    }
    It 'DEF-4.2, SPO-1.4 and SPO-3.4 are link-grouped for the score and still placed by their own finding here' {
        foreach ($id in 'DEF-4.2', 'SPO-1.4', 'SPO-3.4') { (& $script:ItemOf $id).State | Should -Not -Be 'NoFinding' -Because $id }
        (& $script:ItemOf 'DEF-4.2').Reason | Should -Be 'NotCollected'
        (& $script:GroupOf 'SPO-1.4') | Should -Be @('Verified')
    }
    It 'a malformed finding is dropped and counted; a finding outside the catalog is not reviewed' {
        # Through the record reader the malformed row is dropped before the model sees it (and counted there);
        # fed directly, the model applies the same replay rule itself.
        $script:Rec.DroppedFindings | Should -Be 1
        $script:M.Reconciliation.FindingsSupplied | Should -Be (@($script:MainRun.Findings).Count - 1)
        $script:M.Reconciliation.FindingsDropped | Should -Be 0
        $direct = Get-TPAiUseReview -Findings @(& $script:MainFindings) -Metadata (& $script:FullMeta) -Facts $script:Facts -ScopeBuckets @{}
        $direct.Reconciliation.FindingsDropped | Should -Be 1
        $direct.Reconciliation.DuplicateFindingsCollapsed | Should -Be 1
        $direct.Counts.Verified | Should -Be $script:M.Counts.Verified
        $all = @($script:M.Groups.Values | ForEach-Object { $_ } | ForEach-Object ControlId)
        $all | Should -Not -Contain 'AAD-1.1'
        $all | Should -Not -Contain 'bogus'
    }
    It 'a control with no finding is named as such, never dropped and never a pass' {
        (& $script:GroupOf 'TMS-2.2') | Should -Be @('NotVerified')
        $it = & $script:ItemOf 'TMS-2.2'
        $it.Reason | Should -Be 'NoFinding'
        $it.State | Should -Be 'NoFinding'
        $it.ReasonText | Should -Match 'No finding for this control'
    }
    It 'every NotApplicable reason comes from the scope classifier, and the attested one is its own group' {
        (& $script:ItemOf 'PVW-4.3').Reason | Should -Be 'NotCollected'
        (& $script:ItemOf 'PVW-4.3').ScopeBucket | Should -Be 'CollectionIncomplete'
        (& $script:ItemOf 'PVW-1.4').Reason | Should -Be 'NotCollected' -Because 'a failed collector is named before any license signal'
        (& $script:ItemOf 'PPL-3.2').Reason | Should -Be 'LicenseNotHeld'
        (& $script:ItemOf 'SPO-5.3').Reason | Should -Be 'ManualReview'
        (& $script:ItemOf 'AAD-6.4').Reason | Should -Be 'CheckErrored'
        (& $script:GroupOf 'AAD-6.3') | Should -Be @('Attested')
        (& $script:ItemOf 'AAD-6.3').Reason | Should -Be 'ThirdPartyDeclared'
        (& $script:ItemOf 'AAD-6.3').ReasonText | Should -Match 'not verified by this assessment'
        $script:M.Counts.Attested | Should -Be 1
    }
    It 'a Satisfied finding beside a collector that did not complete is a conflict, not a safeguard' {
        (& $script:GroupOf 'DEF-4.1') | Should -Be @('NotVerified')
        (& $script:ItemOf 'DEF-4.1').Reason | Should -Be 'EvidenceConflict'
        (& $script:ItemOf 'DEF-4.1').CoverageStatus | Should -Be 'Failed'
    }
    It 'the group counts follow from the scenario' {
        $script:M.Counts.Observed | Should -Be 1
        $script:M.Counts.Attention | Should -Be 4
        $script:M.Counts.Attested | Should -Be 1
        $script:M.Counts.NotVerified | Should -Be 11
        $script:M.Counts.Verified | Should -Be 26
        $script:M.EvidenceGaps.NotCollected | Should -Be 6
    }
    It 'refuses a partial run, a quick scan and an incident-response file with a reason' {
        foreach ($meta in @(
            @{ TenantDomain = 'x.com'; ControlSelection = @{ Partial = $true; SelectedCount = 1; TotalControls = 253 } },
            @{ TenantDomain = 'x.com'; QuickScan = $true })) {
            $m = Get-TPAiUseReview -Findings @(& $script:MainFindings) -Metadata $meta -Facts $script:Facts -ScopeBuckets @{}
            $m.Available | Should -BeFalse
            $m.Refused | Should -BeTrue
            $m.Note | Should -Match 'not written from a (partial run|quick scan)'
        }
        $ir = Get-TPAiUseReview -Findings @() -Metadata (& $script:FullMeta) -Facts @{ IsIncidentResponse = $true } -ScopeBuckets @{}
        $ir.Refused | Should -BeTrue
        $ir.Note | Should -Match 'incident-response'
    }
    It 'an eligible run whose reads failed is rendered, with the gaps visible' {
        $m = Get-TPAiUseReview -Findings @(& $script:MainFindings) -Metadata (& $script:FullMeta) -Facts (& $script:FactsWith @{ SectionStatus = @{ Licensing = 'Failed'; Users = 'NotRun' } } @{ Success = $false; ListStatus = 'Failed'; Environments = @(); MaxEnvironments = 50 }) -ScopeBuckets @{}
        $m.Available | Should -BeTrue
        $m.Observed.Copilot.Summary | Should -Match 'was not read, so whether any Copilot seat exists is unknown'
        $m.Observed.CopilotStudio.Summary | Should -Match 'could not be read, so the agent inventory is unknown'
        $m.Observed.CopilotStudio.Summary | Should -Match 'does not show that no agent exists'
    }
}

Describe 'AI use review: counts' {
    It 'the main scenario: a complete count, a lower bound and a truncated enumeration are told apart' {
        $cp = $script:M.Observed.Copilot
        $cp.Assignment | Should -Be 'Assigned'
        $cp.Reason | Should -Be 'AtLeast'
        $cp.Summary | Should -Match 'at least 7 account\(s\); the user enumeration did not complete'
        (& $script:CountOf $script:M 'x' 'Copilot seats purchased').Display | Should -Be '25'
        (& $script:CountOf $script:M 'x' 'Copilot seats purchased').Status | Should -Be 'Complete'
        (& $script:CountOf $script:M 'x' 'Distinct accounts holding a seat').Display | Should -Be 'at least 7'
        (& $script:CountOf $script:M 'x' 'Distinct accounts holding a seat').Status | Should -Be 'LowerBound'
        (& $script:CountOf $script:M 'x' 'Enabled member accounts').Display | Should -Be 'at least 100'
        $cp.UsersRead | Should -Be 'Truncated'
        (& $script:ItemOf 'PPL-3.3').ReasonText | Should -Match 'user enumeration did not complete'
    }
    It 'a collected zero is zero, stated with the Chat note and never as "no AI"' {
        $m = & $script:ModelWith @{
            SectionStatus = @{ Licensing = 'Collected'; Users = 'Collected' }
            LicensingMeasurements = @{
                RecognizedSkuCount = @{ Value = 1; Completeness = 'Complete' }; PurchasedSeats = @{ Value = 10; Completeness = 'Complete' }
                SkuConsumedUnits = @{ Value = 0; Completeness = 'Complete' }; EnabledMembers = @{ Value = 40; Completeness = 'Complete' }
                AssignedUsers = @{ Value = 0; Completeness = 'Complete' }; AssignedEnabledMembers = @{ Value = 0; Completeness = 'Complete' } } }
        $m.Observed.Copilot.Assignment | Should -Be 'NoneAssigned'
        $m.Observed.Copilot.Summary | Should -Match 'no seat is assigned\. This does not show that AI tools are unused'
        (& $script:CountOf $m 'x' 'Distinct accounts holding a seat').Display | Should -Be '0'
        (& $script:CountOf $m 'x' 'Distinct accounts holding a seat').Status | Should -Be 'Complete'
        (& $script:ItemOf 'PPL-3.3') | Out-Null
        @($m.Groups.Observed)[0].ReasonText | Should -Be '0 of 40 enabled member accounts hold a Copilot seat'
        $m.Observed.Statements.Chat | Should -Be (& $script:ChatNote)
    }
    It 'an incomplete read that found none is "not established", never zero' {
        $m = & $script:ModelWith @{
            SectionStatus = @{ Licensing = 'Collected'; Users = 'Truncated' }
            LicensingMeasurements = @{
                RecognizedSkuCount = @{ Value = 1; Completeness = 'Complete' }
                EnabledMembers = @{ Value = 40; Completeness = 'Incomplete' }
                AssignedUsers = @{ Value = 0; Completeness = 'Incomplete' }; AssignedEnabledMembers = @{ Value = 0; Completeness = 'Incomplete' } } }
        $m.Observed.Copilot.Assignment | Should -Be 'Unknown'
        $m.Observed.Copilot.Summary | Should -Match 'could not be determined'
        $c = & $script:CountOf $m 'x' 'Distinct accounts holding a seat'
        $c.Status | Should -Be 'NotEstablished'
        $c.Display | Should -Match 'Not established'
        $c.Value | Should -BeNullOrEmpty
        (& $script:CountOf $m 'x' 'Seat assignments the subscriptions report').Status | Should -Be 'NotRead'
    }
    It 'a failed subscription read is "not read" on every count and the state is unknown' {
        $m = & $script:ModelWith @{ SectionStatus = @{ Licensing = 'Failed'; Users = 'NotRun' }; SectionErrors = @{ Licensing = $script:S.Error } }
        $m.Observed.Copilot.Reason | Should -Be 'LicensingNotCollected'
        foreach ($c in $m.Observed.Copilot.Counts) { $c.Status | Should -Be 'NotRead'; $c.Display | Should -Be 'Not read' }
        ($m | ConvertTo-Json -Depth 20) | Should -Not -Match $script:S.Error
    }
    It 'a recognized SKU with nothing assigned is not "no AI": the Chat and add-on statements are always present' {
        $m = & $script:ModelWith @{
            SectionStatus = @{ Licensing = 'Collected'; Users = 'Collected' }
            LicensingMeasurements = @{ RecognizedSkuCount = @{ Value = 0; Completeness = 'Complete' } } }
        $m.Observed.Copilot.RecognizedSku | Should -Be 'None'
        $m.Observed.Copilot.Summary | Should -Match 'no SKU this tool recognizes as Microsoft Copilot'
        $m.Observed.Statements.AddOn | Should -Match 'does not establish that AI is unavailable or unused'
        $m.Observed.Statements.Usage | Should -Match 'not usage'
    }
    It 'an older file without read statuses is unknown completeness, and its compatibility counts are not read' {
        $legacy = & $script:NewRun (& $script:FullMeta) (& $script:MainFindings) ([ordered]@{
            LicensedSkus = @(@{ SkuId = $script:S.SkuId; SkuPartNumber = 'Microsoft_365_Copilot'; PrepaidUnits = 10; ConsumedUnits = 0 })
            CopilotLicensedUserCount = [int]$script:S.Compat; TotalUserCount = [int]$script:S.Compat }) $null $script:Skus
        $p = & $script:WriteRun $legacy 'legacy-results.json'
        $facts = Read-TPAiUseFacts -Path $p
        ($facts | ConvertTo-Json -Depth 20) | Should -Not -Match $script:S.Compat
        $m = Get-TPAiUseReview -Findings @(& $script:MainFindings) -Metadata (& $script:FullMeta) -Facts $facts -ScopeBuckets @{}
        $m.Observed.Copilot.Basis | Should -Be 'Legacy'
        $m.Observed.Copilot.Reason | Should -Be 'StatusNotRecorded'
        $m.Observed.Copilot.Summary | Should -Match 'does not record whether the subscription list was read'
        ($m | ConvertTo-Json -Depth 20) | Should -Not -Match "\b$($script:S.Compat)\b"
        $m.Observed.CopilotStudio.Available | Should -BeFalse
        $m.Observed.CopilotStudio.Agents.Display | Should -Be 'Not read'
    }
    It 'an older file whose SKU rows carry consumed seats is positive evidence of unknown completeness' {
        $m = & $script:ModelWith ([ordered]@{ LicensedSkus = @(@{ SkuId = 'x'; SkuPartNumber = 'Microsoft_365_Copilot'; ConsumedUnits = 3 }) })
        $m.Observed.Copilot.Assignment | Should -Be 'Assigned'
        $m.Observed.Copilot.Summary | Should -Match 'the number of accounts holding them was not established'
    }
    It 'the Copilot Studio inventory follows the collector contract' {
        $cs = $script:M.Observed.CopilotStudio
        $cs.ListStatus | Should -Be 'Collected'
        $cs.EnvironmentsListed | Should -Be 3
        $cs.DataverseEnvironments | Should -Be 2
        $cs.EnvironmentsRead | Should -Be 1
        $cs.EnvironmentsTruncated | Should -Be 1
        $cs.EnvironmentsNotRead | Should -Be 1
        $cs.CapApplied | Should -BeFalse
        $cs.Agents.Status | Should -Be 'LowerBound'
        $cs.Agents.Display | Should -Be 'at least 7'
        $cs.ManagedAgents.Display | Should -Be 'at least 1'
        $cs.Summary | Should -Match 'lower bounds, not a tenant-wide total'
    }
    It 'Copilot Studio: complete, capped, failed, unread-count and absent inventories render differently' {
        $sum = { param($s) & $script:Mod { param($x) Get-TPAiUseCopilotStudioSummary -Summary $x } $s }
        $complete = & $sum @{ ListStatus = 'Collected'; Environments = @(@{ HasDataverse = $true; AgentsStatus = 'Collected'; AgentCount = 2; ManagedAgentCount = 0 }, @{ HasDataverse = $true; AgentsStatus = 'Collected'; AgentCount = 3; ManagedAgentCount = 1 }); MaxEnvironments = 50 }
        $complete.Agents.Status | Should -Be 'Complete'; $complete.Agents.Display | Should -Be '5'; $complete.Summary | Should -Match 'read in full'
        $capped = & $sum @{ ListStatus = 'Collected'; Environments = @(@{ HasDataverse = $true; AgentsStatus = 'Collected'; AgentCount = 1 }, @{ HasDataverse = $true; AgentsStatus = 'Collected'; AgentCount = 1 }, @{ HasDataverse = $true; AgentsStatus = 'NotRun' }); MaxEnvironments = 2 }
        $capped.CapApplied | Should -BeTrue; $capped.Agents.Status | Should -Be 'LowerBound'; $capped.Summary | Should -Match 'environment cap applied'
        $failed = & $sum @{ ListStatus = 'Failed'; Environments = @(); MaxEnvironments = 50 }
        $failed.Agents.Status | Should -Be 'NotRead'; $failed.Summary | Should -Match 'could not be read'
        $noCount = & $sum @{ ListStatus = 'Collected'; Environments = @(@{ HasDataverse = $true; AgentsStatus = 'Collected' }); MaxEnvironments = 50 }
        $noCount.Agents.Status | Should -Be 'NotRead' -Because 'a read with no recorded count is not zero'
        $absent = & $sum $null
        $absent.Available | Should -BeFalse; $absent.Summary | Should -Match 'did not run'
        $zero = & $sum @{ ListStatus = 'Collected'; Environments = @(@{ HasDataverse = $true; AgentsStatus = 'Collected'; AgentCount = 0; ManagedAgentCount = 0 }); MaxEnvironments = 50 }
        $zero.Agents.Status | Should -Be 'Complete'; $zero.Agents.Display | Should -Be '0'
    }
    It 'New-TPAiUseCount: a value that is not a whole number is not read' {
        foreach ($bad in @('7a', 7.5, -1, '', $true)) { (& $script:NewCount $bad 'Complete').Status | Should -Be 'NotRead' -Because "'$bad'" }
        (& $script:NewCount '12' 'Complete').Value | Should -Be 12
        (& $script:NewCount 3 'Weird').Status | Should -Be 'NotRead'
    }
    It 'entitlement is read from the recorded SKUs through the license profile, and "not read" when there are none' {
        $ent = @($script:M.Observed.Entitlement)
        @($ent | Where-Object Label -eq 'Microsoft Copilot (paid add-on)')[0].Status | Should -Be 'Detected'
        @($ent | Where-Object Label -eq 'Copilot Studio')[0].Status | Should -Be 'NotDetected'
        $script:M.Observed.LicensingRead | Should -BeTrue
        $m = & $script:ModelWith (& $script:MainCopilotData)
        $m.Observed.LicensingRead | Should -BeFalse
        foreach ($e in $m.Observed.Entitlement) { $e.Status | Should -Be 'NotRead'; $e.Display | Should -Match 'not read' }
    }
}

Describe 'AI use review: organizational areas and next steps' {
    It 'the five areas are always present and never recorded by the assessment; roles are suggestions' {
        $areas = @($script:M.Organizational)
        $areas.Count | Should -Be 5
        foreach ($a in $areas) { $a.Status | Should -Be 'NotRecorded'; $a.Evidence | Should -Be 'Not recorded in this assessment' }
        $steps = @($script:M.NextSteps.ClientDecisions)
        $steps.Count | Should -Be 5
        foreach ($s in $steps) { $s.ResponsibleRole | Should -Match '\(suggested\)$'; $s.Effort | Should -Be 'Review only' }
    }
    It 'the HIPAA switch selects the ePHI wording only and says so' {
        $h = Get-TPAiUseReview -Findings @($script:Rec.Findings) -Metadata $script:Rec.Metadata -Facts $script:Facts -ScopeBuckets $script:Scope.Buckets -Hipaa
        @($h.Organizational | Where-Object Id -eq 'sensitive-information')[0].Wording | Should -Match 'ePHI'
        $h.Statements.Hipaa | Should -Match 'does not assess, verify or determine HIPAA compliance'
        @($script:M.Organizational | Where-Object Id -eq 'sensitive-information')[0].Wording | Should -Not -Match 'ePHI'
        $script:M.Statements.Hipaa | Should -Be ''
        ($h | ConvertTo-Json -Depth 20) | Should -Not -Match '(?i)HIPAA[- ]compliant|compliant with HIPAA'
    }
    It 'steps are grouped by what each needs, with an evidence basis and a verification' {
        $ns = $script:M.NextSteps
        @($ns.LicensingOrProjects | ForEach-Object ControlId) | Should -Contain 'PPL-3.4'
        @($ns.LicensingOrProjects | Where-Object ControlId -eq 'PPL-3.4')[0].Dependency | Should -Be 'License: Power Platform + Copilot Studio license'
        @($ns.LicensingOrProjects | ForEach-Object ControlId) | Should -Contain 'PPL-3.2'
        @($ns.CurrentCapabilities | ForEach-Object ControlId) | Should -Contain 'SPO-1.1'
        @($ns.CurrentCapabilities | ForEach-Object ControlId) | Should -Contain 'PPL-4.1'
        @($ns.AdditionalCollection | ForEach-Object ControlId) | Should -Contain 'DEF-4.1'
        @($ns.AdditionalCollection | ForEach-Object ControlId) | Should -Contain 'TMS-2.2'
        @($ns.AdditionalCollection | ForEach-Object ControlId) | Should -Not -Contain 'PPL-3.2'
        foreach ($s in @($ns.Values | ForEach-Object { $_ })) {
            $s.EvidenceBasis | Should -Not -BeNullOrEmpty
            $s.Verification | Should -Not -BeNullOrEmpty
            $s.Effort | Should -Not -Match '\d+\s*(h|hrs?|hours?|days?|weeks?)\b'
        }
    }
    It 'a control with no operational-impact entry says so, never "no impact"' {
        $it = @($script:M.Groups.Attention | Where-Object { $null -eq $_.Impact })
        foreach ($x in $it) { @($script:M.NextSteps.CurrentCapabilities + $script:M.NextSteps.LicensingOrProjects | Where-Object ControlId -eq $x.ControlId)[0].OperationalImpact | Should -Match 'not documented' }
        ($script:M | ConvertTo-Json -Depth 20) | Should -Not -Match '(?i)"no impact"'
    }
}

Describe 'AI use review: privacy' {
    It 'the facts reader keeps only the allowlisted aggregates' {
        $json = $script:Facts | ConvertTo-Json -Depth 20
        foreach ($k in 'Marker', 'Upn', 'TenantId', 'Operator', 'Domain', 'EnvName', 'EnvId', 'Agent', 'Error', 'SkuId', 'Compat') { $json | Should -Not -Match ([regex]::Escape($script:S[$k])) -Because "facts must not carry $k" }
        $script:Facts.Copilot.Data.LicensedSkus[0].SkuId | Should -Be 'present'
        $script:Facts.Coverage.Purview | Should -Be 'Failed'
        $script:Facts.RawDataSuccess.Purview | Should -BeFalse
        $script:Facts.RawDataSuccess.M365Copilot | Should -BeTrue
    }
    It 'the model carries no detail, account, identifier, name or error text' {
        $json = $script:M | ConvertTo-Json -Depth 24
        foreach ($k in 'Marker', 'Upn', 'TenantId', 'Operator', 'Domain', 'EnvName', 'EnvId', 'Agent', 'Error', 'SkuId', 'Compat') { $json | Should -Not -Match ([regex]::Escape($script:S[$k])) -Because "model must not carry $k" }
        $json | Should -Not -Match '(?i)TenantId|TenantDomain|Operator"'
    }
    It 'the scope helper returns bucket names only' {
        $json = $script:Scope | ConvertTo-Json -Depth 8
        foreach ($k in 'Marker', 'Upn', 'TenantId', 'Error') { $json | Should -Not -Match ([regex]::Escape($script:S[$k])) }
        $script:Scope.RunScope | Should -Be 'Full'
        $script:Scope.DroppedFindings | Should -Be 1
    }
    It 'refuses a file that is not JSON, not an object, or too large, with a fixed sentence' {
        $p = Join-Path $script:Tmp 'notjson.json'; Set-Content -LiteralPath $p -Value "{ not json $($script:S.Upn)" -Encoding utf8
        { Read-TPAiUseFacts -Path $p } | Should -Throw 'The results file is not valid JSON.'
        $p = Join-Path $script:Tmp 'array.json'; Set-Content -LiteralPath $p -Value "[1,2,`"$($script:S.Upn)`"]" -Encoding utf8
        { Read-TPAiUseFacts -Path $p } | Should -Throw 'The file is not an assessment results file.'
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib' 'Get-TPAiUseReview.ps1') -Raw
        $src | Should -Match 'Get-TPRunRecordMaxBytes'
        $src | Should -Match 'larger than this tool reads'
    }
    It 'an incident-response file is recognized by DeepDives or by EMAIL-/SIGNIN- findings' {
        $ir1 = & $script:WriteRun @{ Metadata = (& $script:FullMeta); DeepDives = @(@{ User = $script:S.Upn }); Findings = @() } 'ir1.json'
        (Read-TPAiUseFacts -Path $ir1).IsIncidentResponse | Should -BeTrue
        $ir2 = & $script:WriteRun @{ Metadata = (& $script:FullMeta); Findings = @(@{ ControlId = 'SIGNIN-1.1'; State = 'Gap'; Severity = 'High' }) } 'ir2.json'
        (Read-TPAiUseFacts -Path $ir2).IsIncidentResponse | Should -BeTrue
        (Read-TPAiUseFacts -Path $ir2).Available | Should -BeFalse
    }
}

Describe 'AI use review: the page' {
    BeforeAll {
        Mock -ModuleName 'TenantPosture' Find-TPPdfBrowser -MockWith { $null }
        $script:Files = Publish-TPAiUseReview -Model $script:M -OutputPath (Join-Path $script:Tmp 'contoso-ai-use-review.html') -Pdf -GeneratedAt ([datetime]::new(2041, 1, 2, 3, 4, 0, [DateTimeKind]::Utc))
        $script:Html = Get-Content -LiteralPath $script:Files.Html -Raw
        $h = Get-TPAiUseReview -Findings @($script:Rec.Findings) -Metadata $script:Rec.Metadata -Facts $script:Facts -ScopeBuckets $script:Scope.Buckets -ClientName 'Clinic' -Hipaa
        $script:HipaaHtml = Get-Content -LiteralPath (Publish-TPAiUseReview -Model $h -OutputPath (Join-Path $script:Tmp 'clinic-ai-use-review.html')).Html -Raw
    }
    It 'says what it is and is not before any number' {
        $not = $script:Html.IndexOf('What this is not.')
        $not | Should -BeGreaterThan 0
        $script:Html.IndexOf('class="tp-kpis"') | Should -BeGreaterThan $not
        $script:Html | Should -Match 'not an AI risk assessment'
        $script:Html | Should -Match 'not a determination of compliance'
        $script:Html | Should -Match 'not a statement that AI use is safe, approved or governed'
        $script:Html | Should -Match 'not a score'
    }
    It 'never claims compliance, safety, approval or readiness' {
        foreach ($page in @($script:Html, $script:HipaaHtml)) {
            $page | Should -Not -Match '(?i)\b(you are|organization is|tenant is|fully|now)\s+compliant\b|\bcompliant with\b|\bHIPAA[- ]compliant\b'
            $page | Should -Not -Match '(?i)\bAI[- ]ready\b|\bready for AI\b|\bsafe to (use|deploy|enable)\b|\bapproved for AI\b|\bis governed\b'
        }
    }
    It 'escapes tenant text and loads and runs nothing' {
        $script:Html | Should -Match 'Contoso &lt;script&gt;alert\(1\)&lt;/script&gt; &amp; Co'
        $script:Html | Should -Not -Match '(?i)<script|<link|<img|<iframe|@import|<object|<embed'
        $script:Html | Should -Match "default-src 'none'"
        foreach ($m in [regex]::Matches($script:Html, 'href="([^"]*)"')) { $m.Groups[1].Value | Should -Match '^https://([a-z0-9-]+\.)*microsoft\.com/' }
        ([regex]::Matches($script:Html, '<a ')).Count | Should -BeGreaterThan 3
    }
    It 'carries none of the sentinels' {
        foreach ($k in 'Marker', 'Upn', 'TenantId', 'Operator', 'Domain', 'EnvName', 'EnvId', 'Agent', 'Error', 'SkuId', 'Compat') { $script:Html | Should -Not -Match ([regex]::Escape($script:S[$k])) -Because "page must not carry $k" }
    }
    It 'renders every count with its status, and a lower bound as such' {
        $script:Html | Should -Match 'at least 7'
        $script:Html | Should -Match 'Lower bound'
        $script:Html | Should -Match 'Not established'
        $script:Html | Should -Match 'lower bounds, not a tenant-wide total'
        $script:Html | Should -Not -Match '>0</td>' -Because 'the main scenario has no collected zero'
    }
    It 'keeps technical evidence, third-party declarations and unrecorded organizational evidence apart' {
        $script:Html | Should -Match 'Declared by a third party, not verified here'
        $script:Html | Should -Match 'Not recorded in this assessment|Not recorded'
        $script:Html | Should -Match 'Safeguards in place'
        $script:Html | Should -Match 'No finding for this control is recorded'
        $script:Html | Should -Match 'The two records disagree'
        $script:Html | Should -Match 'Operational impact not documented|If changed:'
    }
    It 'carries the three dates as three things' {
        $script:Html | Should -Match 'Assessment date: 2026-11-01'
        $script:Html | Should -Match ([regex]::Escape("Read from Microsoft Learn on $($script:Catalog.VendorFactsRetrieved)"))
        $script:Html | Should -Match ([regex]::Escape("catalog version $($script:Catalog.Version)"))
        $script:Html | Should -Match 'TenantPosture 9\.9\.9'
        $script:Html | Should -Match '2041-01-02'
    }
    It 'the HIPAA page uses the ePHI wording and says it is wording only' {
        $script:HipaaHtml | Should -Match 'ePHI'
        $script:HipaaHtml | Should -Match 'does not assess, verify or determine HIPAA compliance'
        $script:Html | Should -Not -Match 'ePHI'
    }
    It 'with no browser, says the PDF was not written and keeps the HTML' {
        $script:Files.Pdf | Should -BeNullOrEmpty
        $script:Files.PdfNote | Should -Match '^HTML generated; PDF unavailable: '
        $script:Files.PdfNote | Should -Match 'print it to PDF'
        Test-Path -LiteralPath $script:Files.Html | Should -BeTrue
        if (-not $IsWindows) { (Get-Item -LiteralPath $script:Files.Html).UnixMode | Should -Be '-rw-------' }
    }
    It 'refuses to render a refused model' {
        { Publish-TPAiUseReview -Model @{ Available = $false; Note = 'refused' } -OutputPath (Join-Path $script:Tmp 'never.html') } | Should -Throw '*not generated*'
        Test-Path -LiteralPath (Join-Path $script:Tmp 'never.html') | Should -BeFalse
    }
    It 'prints a real PDF when a headless browser is available' -Skip:(-not $script:Headless) -ForEach @(@{ Browser = $script:Headless }) {
        $r = ConvertTo-TPPdf -HtmlPath $script:Files.Html -PdfPath (Join-Path $script:Tmp 'print.pdf') -Browser $Browser -TimeoutSeconds 60
        $r.Written | Should -BeTrue -Because $r.Reason
        [System.Text.Encoding]::ASCII.GetString([System.IO.File]::ReadAllBytes($r.Path)[0..4]) | Should -Be '%PDF-'
    }
}

Describe 'AI use review: parity, immutability and reuse' {
    It 'the offline scope equals Get-TPAssessmentScope on the same objects' {
        $full = Get-Content -LiteralPath $script:MainPath -Raw | ConvertFrom-Json -AsHashtable -Depth 64
        $dropped = @()
        $findings = @(Select-TPReplayedFinding -Findings @($full.Findings) -Dropped ([ref]$dropped))
        $cov = @{}
        foreach ($k in $full.Coverage.Keys) { $cov[$k] = @{ Status = $full.Coverage[$k].Status; Note = $full.Coverage[$k].Note } }
        $direct = Get-TPAssessmentScope -Findings $findings -Coverage $cov -RawData $full.RawData
        $expected = @{}
        foreach ($b in 'LicenceBlocked', 'CollectionIncomplete', 'NoProgrammaticCheck', 'ThirdPartyAttested', 'StandardNotApproved', 'NotApplicableToTenant', 'NotEvaluatedThisMode', 'NotSelected', 'SkippedByOperator', 'NoResult') {
            foreach ($row in @($direct[$b])) { if (-not $expected.ContainsKey($row.ControlId)) { $expected[$row.ControlId] = $b } }
        }
        $expected.Count | Should -BeGreaterThan 10
        foreach ($id in $expected.Keys) { $script:Scope.Buckets[$id] | Should -Be $expected[$id] -Because $id }
        foreach ($id in $script:Scope.Buckets.Keys) { $expected[$id] | Should -Be $script:Scope.Buckets[$id] -Because $id }
        $script:Scope.Buckets['AAD-6.3'] | Should -Be 'ThirdPartyAttested'
        $script:Scope.Buckets['TMS-2.2'] | Should -Be 'NoResult'
    }
    It 'the source file is unchanged, no finding was emitted and the score is unmoved' {
        (& $script:Hash $script:MainPath) | Should -Be $script:MainHashBefore
        @(Get-TPFindings).Count | Should -Be $script:FindingsInModuleBefore
        ((& $script:Scoring @($script:MainRun.Findings) | ForEach-Object { "$($_.ControlId)=$($_.State)" }) -join ';') | Should -Be $script:ScoreBefore
        $script:M.Keys | Should -Not -Contain 'Score'
        ($script:M | ConvertTo-Json -Depth 24) | Should -Not -Match '(?i)"(score|percent|rank|grade)"'
    }
    It 'licensing state is read through Get-TPCopilotLicensingState; no SKU regex, no compatibility count, no network' {
        $lib = Join-Path $script:RepoRoot 'Lib' 'Get-TPAiUseReview.ps1'
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($lib, [ref]$null, [ref]$null)
        $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        $cmds | Should -Contain 'Get-TPCopilotLicensingState'
        $cmds | Should -Contain 'Get-TPCopilotChatEligibilityNote'
        $cmds | Should -Contain 'Get-TPAssessmentScope'
        $cmds | Should -Contain 'Select-TPReplayedFinding'
        foreach ($bad in 'Invoke-TPGraphRequest', 'Connect-MgGraph', 'Invoke-RestMethod', 'Invoke-WebRequest', 'Connect-ExchangeOnline', 'Get-TPRawData', 'Add-TPFinding', 'Set-TPRawData') { $cmds | Should -Not -Contain $bad }
        foreach ($f in @($lib, (Join-Path $script:RepoRoot 'Publishers' 'Publish-TPAiUseReview.ps1'), (Join-Path $script:RepoRoot 'New-TPAiUseReview.ps1'))) {
            $text = Get-Content -LiteralPath $f -Raw
            $text | Should -Not -Match 'CopilotLicensed[U]serCount|Total[U]serCount' -Because (Split-Path -Leaf $f)
            $text | Should -Not -Match 'Microsoft_365_Copilot|M365_Copilot' -Because 'SKU recognition belongs to the collector'
        }
    }
    It 'the four public functions are exported and the headers are in place' {
        foreach ($fn in 'Get-TPAiUseReview', 'Publish-TPAiUseReview', 'Read-TPAiUseFacts', 'Get-TPAiUseReviewScope', 'Read-TPAiUseUserFacts') { (Get-Command $fn -Module TenantPosture -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty -Because $fn }
        $manifest = Import-PowerShellDataFile -Path (Join-Path $script:RepoRoot 'TenantPosture.psd1')
        $manifest.FunctionsToExport | Should -Contain 'Get-TPAiUseReview'
    }
}

Describe 'AI use review: the standalone script' {
    BeforeAll {
        $script:Script = Join-Path $script:RepoRoot 'New-TPAiUseReview.ps1'
        $script:Run = {
            param([string] $Results, [string[]] $More = @())
            $out = Join-Path $script:Tmp ('out-' + [Guid]::NewGuid().ToString('N').Substring(0, 6))
            $null = New-Item -ItemType Directory -Path $out -Force
            $log = & pwsh -NoProfile -NonInteractive -File $script:Script -ResultsPath $Results -OutputPath $out -ClientName 'Contoso & Co' @More 2>&1 | Out-String
            [ordered]@{ Exit = $LASTEXITCODE; Out = $out; Log = $log; Html = @(Get-ChildItem -LiteralPath $out -Filter '*.html' -File -ErrorAction SilentlyContinue) }
        }
    }
    It 'connects to nothing and proves the output folder first' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:Script, [ref]$null, [ref]$null)
        $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        foreach ($bad in 'Connect-TPServices', 'Connect-MgGraph', 'Invoke-TPGraphRequest', 'Invoke-RestMethod', 'Invoke-WebRequest', 'Connect-ExchangeOnline', 'Invoke-TPAssessment.ps1', 'Start-Process') { $cmds | Should -Not -Contain $bad }
        foreach ($need in 'Read-TPRunRecord', 'Read-TPAiUseFacts', 'Get-TPAiUseReviewScope', 'Get-TPAiUseReview', 'Publish-TPAiUseReview', 'Test-TPSensitiveOutputFolder') { $cmds | Should -Contain $need }
        $src = Get-Content -LiteralPath $script:Script -Raw
        $src | Should -Match '\[switch\] \$HIPAA'
        $src | Should -Match '\[switch\] \$Pdf'
        $src | Should -Not -Match 'Invoke-TPAssessment'
    }
    It 'writes the HTML from a full run (exit 0) and uses the ePHI wording with -HIPAA' {
        $r = & $script:Run $script:MainPath @('-HIPAA')
        $r.Exit | Should -Be 0 -Because $r.Log
        $r.Html.Count | Should -Be 1
        $r.Html[0].Name | Should -Match '^ContosoCo-ai-use-review-\d{8}-\d{6}\.html$'
        $html = Get-Content -LiteralPath $r.Html[0].FullName -Raw
        $html | Should -Match 'ePHI'
        $html | Should -Not -Match ([regex]::Escape($script:S.Upn))
        $r.Log | Should -Match 'connected to nothing and did not modify the results file'
        (& $script:Hash $script:MainPath) | Should -Be $script:MainHashBefore
    }
    It 'refuses a partial run (exit 4) and writes nothing' {
        $meta = & $script:FullMeta
        $meta.ControlSelection = @{ Partial = $true; SelectedCount = 3; TotalControls = 253; SelectedControlIds = @('SPO-1.1') }
        $p = & $script:WriteRun (& $script:NewRun $meta (& $script:MainFindings) (& $script:MainCopilotData) (& $script:MainStudioData) $script:Skus) 'partial-results.json'
        $r = & $script:Run $p
        $r.Exit | Should -Be 4
        $r.Html.Count | Should -Be 0
        $r.Log | Should -Match 'not written from a partial run'
    }
    It 'refuses an incident-response output (exit 4) and writes nothing' {
        $p = & $script:WriteRun @{ Metadata = (& $script:FullMeta); DeepDives = @(@{ User = $script:S.Upn }); Findings = @() } 'ir-results.json'
        $r = & $script:Run $p
        $r.Exit | Should -Be 4
        $r.Html.Count | Should -Be 0
        $r.Log | Should -Match 'incident-response output'
    }
}

Describe 'AI use review: Copilot deployment gate' {
    BeforeAll {
        $script:Blockers = @('AAD-1.2', 'AAD-1.1', 'SPO-1.1', 'SPO-1.2', 'AAD-6.2', 'AAD-15.1', 'PVW-1.1', 'PPL-3.5', 'PPL-4.1', 'PPL-4.2')
        $script:GateModel = {
            param([hashtable] $States, [hashtable] $Buckets = @{}, [object] $Ids = $script:Blockers)
            $f = @(foreach ($id in $script:Blockers) { $st = if ($States.ContainsKey($id)) { $States[$id] } else { 'Satisfied' }; if ($st) { & $script:Finding $id $st 'x' } })
            Get-TPAiUseReview -Findings $f -Metadata (& $script:FullMeta) -Facts (& $script:FactsWith $null) -ScopeBuckets $Buckets -BlockerControlIds $Ids
        }
    }
    It 'every listed blocker (approved or proposed) is a real control with a reason' {
        $s = Get-TPStandards -Path (Join-Path $script:RepoRoot 'Config' 'tp-standards.json')
        $std = @(@($s.CopilotReadinessBlockers) + @($s.CopilotReadinessBlockersProposed))
        $std.Count | Should -BeGreaterThan 0
        foreach ($id in $std) { $script:Defs.ContainsKey($id) | Should -BeTrue; $script:Catalog.Readiness.BlockerReasons[$id] | Should -Not -BeNullOrEmpty -Because $id }
        @($script:Catalog.Readiness.NotChecked | ForEach-Object Id) | Should -Contain 'internal-oversharing'
        foreach ($src in $script:Catalog.Readiness.Sources) { $src.Url | Should -Match '^https://learn\.microsoft\.com/' }
    }
    It 'one shortfall on a blocker is "not ready", whatever else passed' {
        $m = & $script:GateModel @{ 'SPO-1.2' = 'Partial' }
        $m.Readiness.Outcome | Should -Be 'BlockersFound'
        $m.Readiness.Label | Should -Be 'Not ready: blockers found'
        @($m.Readiness.Blockers | ForEach-Object ControlId) | Should -Be @('SPO-1.2')
        $m.Readiness.Passed.Count | Should -Be 9
        $m.Readiness.Summary | Should -Match '1 of the 10 blocker control'
    }
    It 'a missing verdict is "cannot be determined", never a pass' -ForEach @(
        @{ Label = 'no finding'; State = $null }, @{ Label = 'an errored check'; State = 'Error' }, @{ Label = 'an unclassified not-applicable'; State = 'NotApplicable' }
    ) {
        $m = & $script:GateModel @{ 'PVW-1.1' = $State }
        $m.Readiness.Outcome | Should -Be 'NotDetermined'
        @($m.Readiness.NotVerified | ForEach-Object ControlId) | Should -Be @('PVW-1.1')
        $m.Readiness.Summary | Should -Match 'never counted as a pass'
    }
    It 'a shortfall beats a missing verdict' {
        (& $script:GateModel @{ 'PVW-1.1' = $null; 'AAD-1.2' = 'Gap' }).Readiness.Outcome | Should -Be 'BlockersFound'
    }
    It 'a Satisfied blocker beside a failed collector is no verdict' {
        $f = @(foreach ($id in $script:Blockers) { & $script:Finding $id 'Satisfied' 'x' })
        $facts = & $script:FactsWith $null
        $facts.Coverage = @{ ($script:Defs['SPO-1.1'].CollectorDependency) = 'Failed' }
        $m = Get-TPAiUseReview -Findings $f -Metadata (& $script:FullMeta) -Facts $facts -ScopeBuckets @{} -BlockerControlIds $script:Blockers
        $m.Readiness.Outcome | Should -Be 'NotDetermined'
        @($m.Readiness.NotVerified | ForEach-Object Reason | Sort-Object -Unique) | Should -Be @('EvidenceConflict')
    }
    It 'every blocker in place reads "no blockers found in the controls checked", beside what is not checked' {
        $m = & $script:GateModel @{ 'PPL-4.1' = 'NotApplicable'; 'PPL-4.2' = 'NotApplicable' } @{ 'PPL-4.1' = 'NotApplicableToTenant'; 'PPL-4.2' = 'NotApplicableToTenant' }
        $m.Readiness.Outcome | Should -Be 'NoBlockersInCheckedControls'
        $m.Readiness.Label | Should -Be 'No blockers found in the controls checked'
        $m.Readiness.DoesNotApply.Count | Should -Be 2
        $m.Readiness.Passed.Count | Should -Be 8
        $m.Readiness.Summary | Should -Match 'only the controls checked'
        $m.Readiness.Statement | Should -Match 'makes no safety determination'
        @($m.Readiness.NotChecked).Count | Should -BeGreaterThan 3
    }
    It 'a populated list gates only with a recorded approval' {
        $w = { param($node) $p = Join-Path $TestDrive ([Guid]::NewGuid().ToString('N') + '.json'); @{ CopilotReadinessBlockers = $node } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $p -Encoding utf8; Get-TPStandards -Path $p }
        $prop = & $w @{ Values = @('SPO-1.1') }
        $prop.CopilotReadinessBlockersState | Should -Be 'Proposed'
        @($prop.CopilotReadinessBlockers).Count | Should -Be 0
        @($prop.CopilotReadinessBlockersProposed) | Should -Be @('SPO-1.1')
        (& $w @{ Values = @('SPO-1.1'); ApprovedBy = 'Owner'; ApprovedDate = '11/12/2026' }).CopilotReadinessBlockersState | Should -Be 'Proposed'
        (& $w @{ Values = @('SPO-1.1'); ApprovedBy = ''; ApprovedDate = '2026-11-12' }).CopilotReadinessBlockersState | Should -Be 'Proposed'
        $ok = & $w @{ Values = @('SPO-1.1'); ApprovedBy = 'Owner'; ApprovedDate = '2026-11-12' }
        $ok.CopilotReadinessBlockersState | Should -Be 'Approved'
        @($ok.CopilotReadinessBlockers) | Should -Be @('SPO-1.1')
        (Get-TPStandards -Path (Join-Path $TestDrive 'missing.json')).CopilotReadinessBlockersState | Should -Be 'Unreadable'
        $shipped = Get-TPStandards -Path (Join-Path $script:RepoRoot 'Config' 'tp-standards.json')
        $shipped.CopilotReadinessBlockersState | Should -BeIn @('Proposed', 'Approved', 'NotConfigured')
    }
    It 'the no-verdict summary names why: proposed, unreadable or empty' {
        foreach ($c in @(@{ S = 'Proposed'; R = 'no recorded approval' }, @{ S = 'Unreadable'; R = 'missing or could not be read' }, @{ S = 'NotConfigured'; R = 'No list of blocker controls is approved' })) {
            $st = [ordered]@{ CopilotReadinessBlockers = @(); CopilotReadinessBlockersProposed = @('SPO-1.1'); CopilotReadinessBlockersState = $c.S }
            Mock -ModuleName 'TenantPosture' Get-TPStandards -MockWith { $st }.GetNewClosure()
            $m = Get-TPAiUseReview -Findings @() -Metadata (& $script:FullMeta) -Facts (& $script:FactsWith $null) -ScopeBuckets @{}
            $m.Readiness.Outcome | Should -Be 'NotConfigured'
            $m.Readiness.GateState | Should -Be $c.S
            $m.Readiness.Summary | Should -Match $c.R
        }
    }
    It 'a satisfied blocker is never a pass when any collector it depends on did not complete' {
        $f = @(& $script:Finding 'AAD-1.2' 'Satisfied' 'x')
        $run = { param($cov, $ok) $fx = & $script:FactsWith $null; $fx.Coverage = $cov; $fx.RawDataSuccess = $ok
                 Get-TPAiUseReview -Findings $f -Metadata (& $script:FullMeta) -Facts $fx -ScopeBuckets @{} -BlockerControlIds @('AAD-1.2') }
        (& $run @{ 'AAD-CAPolicies' = 'Collected'; 'AAD-AuthPolicies' = 'Collected' } @{}).Readiness.Outcome | Should -Be 'NoBlockersInCheckedControls'
        foreach ($bad in @('Failed', 'Skipped', 'NotCollected')) {
            $m = & $run @{ 'AAD-CAPolicies' = 'Collected'; 'AAD-AuthPolicies' = $bad } @{}
            $m.Readiness.Outcome | Should -Be 'NotDetermined' -Because "second collector $bad"
            $m.Readiness.NotVerified[0].Reason | Should -Be 'EvidenceConflict'
        }
        (& $run @{ 'AAD-CAPolicies' = 'Collected'; 'AAD-AuthPolicies' = 'Collected' } @{ 'AAD-AuthPolicies' = $false }).Readiness.Outcome | Should -Be 'NotDetermined'
        (& $run @{ 'AAD-CAPolicies' = 'Collected'; 'AAD-AuthPolicies' = 'Collected' } @{ 'AAD-AuthPolicies' = $true }).Readiness.Outcome | Should -Be 'NoBlockersInCheckedControls'
    }
    It 'no approved list prints no verdict; an id that is not a control is never a pass' {
        $none = & $script:GateModel @{} @{} @()
        $none.Readiness.Outcome | Should -Be 'NotConfigured'
        $none.Readiness.Total | Should -Be 0
        $bad = & $script:GateModel @{} @{} @('SPO-1.1', 'ZZZ-9.9', '<b>x</b>')
        $bad.Readiness.Outcome | Should -Be 'NotDetermined'
        $bad.Readiness.InvalidIds.Count | Should -Be 2
        $dup = & $script:GateModel @{} @{} @('SPO-1.1', 'spo-1.1', 'SPO-1.1')
        $dup.Readiness.Total | Should -Be 1
    }
    It 'the main scenario is not ready, and the page shows the gate with what is not checked and never says safe' {
        $script:M.Readiness.Outcome | Should -Be 'BlockersFound'
        @($script:M.Readiness.Blockers | ForEach-Object ControlId | Sort-Object) | Should -Be @('AAD-1.1', 'PPL-4.1', 'SPO-1.1')
        @($script:M.Readiness.NotVerified | ForEach-Object ControlId | Sort-Object) | Should -Be @('AAD-1.2', 'PVW-1.1')
        Mock -ModuleName 'TenantPosture' Find-TPPdfBrowser -MockWith { $null }
        $html = Get-Content -LiteralPath (Publish-TPAiUseReview -Model $script:M -OutputPath (Join-Path $script:Tmp 'gate.html')).Html -Raw
        $html | Should -Match 'id="readiness"'
        $html | Should -Match 'Not ready: blockers found'
        $html | Should -Match 'Internal oversharing of sites and files'
        $html | Should -Match 'makes no safety determination'
        $html.IndexOf('What this is not.') | Should -BeLessThan $html.IndexOf('id="readiness"')
        $clean = & $script:GateModel @{}
        $page = Get-Content -LiteralPath (Publish-TPAiUseReview -Model $clean -OutputPath (Join-Path $script:Tmp 'gate-clean.html')).Html -Raw
        $page | Should -Match 'No blockers found in the controls checked'
        foreach ($p in @($html, $page)) {
            $p | Should -Not -Match '(?i)\bCopilot is safe\b|\bCopilot[- ]ready\b|\bready to deploy\b|\bsafe to (use|deploy|enable)\b|\bapproved for\b'
            $p | Should -Not -Match '(?i)<script|<img|<iframe'
        }
        $page | Should -Not -Match 'id="accounts"'
    }
}

Describe 'AI use review: named accounts' {
    BeforeAll {
        $run = & $script:NewRun (& $script:FullMeta) (& $script:MainFindings) (& $script:MainCopilotData) (& $script:MainStudioData) @(
            @{ SkuPartNumber = 'Microsoft_365_Copilot'; SkuId = 'c0000000-0000-0000-0000-000000000001'; ServicePlans = @('M365_COPILOT_APPS') },
            @{ SkuPartNumber = 'SPB'; SkuId = 'b0000000-0000-0000-0000-000000000002'; ServicePlans = @('AAD_PREMIUM') })
        $user = { param($upn, $enabled, $type, $skus) @{ Id = [guid]::NewGuid().ToString(); DisplayName = "DISPLAY-$upn"; UserPrincipalName = $upn; AccountEnabled = $enabled; UserType = $type; AssignedSkuIds = @($skus) } }
        $run.RawData['AAD-Users'] = @{ CollectorId = 'AAD-Users'; Success = $true; Data = @{
            SectionStatus = @{ Users = 'Collected'; MFARegistration = 'Collected' }
            Users = @(
                (& $user 'ready@contoso.example' $true 'Member' @('C0000000-0000-0000-0000-000000000001', 'b0000000-0000-0000-0000-000000000002')),
                (& $user 'needs@contoso.example' $true 'Member' @('b0000000-0000-0000-0000-000000000002')),
                (& $user 'bare@contoso.example' $false 'Member' @()),
                (& $user 'guest_x#EXT#@contoso.example' $true 'Guest' @()),
                (& $user 'odd@contoso.example' $true 'Member' @('dddddddd-0000-0000-0000-000000000009')),
                (& $user $script:S.Upn $true 'Member' @()))
            MFARegistration = @{ RegistrationDetails = @(
                @{ UserPrincipalName = 'READY@contoso.example'; IsMfaRegistered = $true; IsMfaCapable = $true },
                @{ UserPrincipalName = 'needs@contoso.example'; IsMfaRegistered = $false; IsMfaCapable = $false }) } } }
        $run.RawData['Intune-DeviceCompliance'] = @{ CollectorId = 'Intune-DeviceCompliance'; Success = $true; Data = @{
            SectionStatus = @{ OSComplianceSummary = 'Collected' }
            OSComplianceSummary = @{ NonCompliantTruncated = $false; NonCompliantDevices = @(
                @{ DeviceName = 'DEVICE-NAME-SENTINEL'; ComplianceState = 'noncompliant'; UserPrincipalName = 'needs@contoso.example' }) } } }
        $script:UserPath = & $script:WriteRun $run 'users-results.json'
        $script:UF = @(Read-TPAiUseUserFacts -Path $script:UserPath -UserPrincipalName @('Ready@Contoso.example', 'needs@contoso.example', 'bare@contoso.example', 'guest_x#EXT#@contoso.example', 'odd@contoso.example', 'absent@contoso.example', 'ready@contoso.example'))
        $script:UM = Get-TPAiUseReview -Findings @(& $script:MainFindings) -Metadata (& $script:FullMeta) -Facts (Read-TPAiUseFacts -Path $script:UserPath) -ScopeBuckets @{} -UserFacts $script:UF
        $script:Acct = { param([string] $upn) @($script:UM.Users | Where-Object { $_.UserPrincipalName -ieq $upn })[0] }
        $script:RowOf = { param([string] $upn, [string] $req) @((& $script:Acct $upn).Rows | Where-Object { $_.Requirement -like "$req*" })[0] }
    }
    It 'reads only the named accounts, once each, and nothing else about anyone' {
        $script:UF.Count | Should -Be 6
        $json = $script:UF | ConvertTo-Json -Depth 8
        $json | Should -Not -Match ([regex]::Escape($script:S.Upn))
        $json | Should -Not -Match 'DISPLAY-|DEVICE-NAME-SENTINEL'
        ($script:UM | ConvertTo-Json -Depth 24) | Should -Not -Match 'DISPLAY-|DEVICE-NAME-SENTINEL'
    }
    It 'an account with a base license, a Copilot license and usable MFA has nothing to add' {
        (& $script:RowOf 'Ready@Contoso.example' 'Work account').Status | Should -Be 'Met'
        (& $script:RowOf 'Ready@Contoso.example' 'Microsoft Copilot license').Status | Should -Be 'Met'
        $base = & $script:RowOf 'Ready@Contoso.example' 'Eligible'
        $base.Status | Should -Be 'Confirm' -Because 'the review names the license and does not judge eligibility'
        $base.Detail | Should -Match 'Assigned: SPB'
        (& $script:RowOf 'Ready@Contoso.example' 'Multifactor').Status | Should -Be 'Met'
        (& $script:RowOf 'Ready@Contoso.example' 'Managed device').Status | Should -Be 'NotEstablished' -Because 'only non-compliant devices are kept by account'
        @((& $script:Acct 'Ready@Contoso.example').ToAdd).Count | Should -Be 0
    }
    It 'names what to add: a Copilot license, MFA registration and a compliant device' {
        (& $script:RowOf 'needs@contoso.example' 'Microsoft Copilot license').Status | Should -Be 'NotMet'
        (& $script:RowOf 'needs@contoso.example' 'Multifactor').Status | Should -Be 'NotMet'
        (& $script:RowOf 'needs@contoso.example' 'Managed device').Status | Should -Be 'NotMet'
        @((& $script:Acct 'needs@contoso.example').ToAdd).Count | Should -Be 3
    }
    It 'a blocked account with no license, a guest, an unnamed license and an absent account are told apart' {
        (& $script:RowOf 'bare@contoso.example' 'Work account').Detail | Should -Match 'sign-in is blocked'
        (& $script:RowOf 'bare@contoso.example' 'Eligible').Status | Should -Be 'NotMet'
        (& $script:RowOf 'bare@contoso.example' 'Multifactor').Status | Should -Be 'NotEstablished'
        (& $script:RowOf 'guest_x#EXT#@contoso.example' 'Work account').Detail | Should -Match 'guest accounts are not licensed'
        (& $script:RowOf 'odd@contoso.example' 'Microsoft Copilot license').Status | Should -Be 'NotEstablished'
        $absent = & $script:Acct 'absent@contoso.example'
        $absent.Found | Should -BeFalse
        $absent.Rows.Count | Should -Be 1
        $absent.Rows[0].Status | Should -Be 'NotMet'
        $absent.Rows[0].Detail | Should -Match 'complete user list'
    }
    It 'an account missing from a truncated or unread user list is not established, never absent' {
        $get = { param($status) & $script:Mod { param($f) Get-TPAiUseUserReadiness -UserFacts $f } @{ UserPrincipalName = 'a@b.example'; UsersRead = $status; Found = $false } }
        foreach ($st in 'Truncated', 'Failed', 'NotRecorded') { (& $get $st).Rows[0].Status | Should -Be 'NotEstablished' -Because $st }
        (& $get 'Truncated').Rows[0].Detail | Should -Match 'does not show the account is absent'
    }
    It 'licenses cannot be named when the subscription list was not read' {
        $r = & $script:Mod { param($f) Get-TPAiUseUserReadiness -UserFacts $f } @{ UserPrincipalName = 'a@b.example'; UsersRead = 'Collected'; Found = $true; AccountEnabled = $true; UserType = 'Member'; AssignedSkuIds = @('x'); SkuCatalogRead = $false }
        @($r.Rows | Where-Object { $_.Requirement -like '*license' } | ForEach-Object Status | Sort-Object -Unique) | Should -Be @('NotEstablished')
    }
    It 'refuses a name that is not a user principal name, more than 25 names, and an incident-response file' {
        { Read-TPAiUseUserFacts -Path $script:UserPath -UserPrincipalName @('not a upn') } | Should -Throw '*not a user principal name*'
        { Read-TPAiUseUserFacts -Path $script:UserPath -UserPrincipalName @('<script>@x.example') } | Should -Throw '*not a user principal name*'
        { Read-TPAiUseUserFacts -Path $script:UserPath -UserPrincipalName @(1..26 | ForEach-Object { "u$_@x.example" }) } | Should -Throw '*at most 25*'
        @(Read-TPAiUseUserFacts -Path $script:UserPath -UserPrincipalName @(' ')).Count | Should -Be 0
        $ir = & $script:WriteRun @{ Metadata = (& $script:FullMeta); DeepDives = @(@{ User = 'x' }); Findings = @() } 'ir-users.json'
        { Read-TPAiUseUserFacts -Path $ir -UserPrincipalName @('a@b.example') } | Should -Throw '*incident-response*'
    }
    It 'the page names an account only when the preparer named it, and escapes it' {
        Mock -ModuleName 'TenantPosture' Find-TPPdfBrowser -MockWith { $null }
        $html = Get-Content -LiteralPath (Publish-TPAiUseReview -Model $script:UM -OutputPath (Join-Path $script:Tmp 'users.html')).Html -Raw
        $html | Should -Match 'id="accounts"'
        $html | Should -Match 'needs@contoso\.example'
        $html | Should -Match 'guest_x#EXT#@contoso\.example'
        $html | Should -Match 'What this account can reach'
        $html | Should -Not -Match ([regex]::Escape($script:S.Upn))
        $html | Should -Not -Match 'DISPLAY-|DEVICE-NAME-SENTINEL'
        $script:Html | Should -Not -Match 'id="accounts"'
    }
    It 'the script takes -User, prints the gate and leaves the file unchanged' {
        $before = & $script:Hash $script:UserPath
        $out = Join-Path $script:Tmp 'out-users'; $null = New-Item -ItemType Directory -Path $out -Force
        $log = & pwsh -NoProfile -NonInteractive -File (Join-Path $script:RepoRoot 'New-TPAiUseReview.ps1') -ResultsPath $script:UserPath -OutputPath $out -ClientName 'Contoso' -User 'needs@contoso.example' 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 0 -Because $log
        # The shipped list has no recorded approval, so the script prints no verdict.
        $log | Should -Match 'Copilot deployment gate: No deployment gate is approved'
        $log | Should -Match 'names 1 account'
        (Get-Content -LiteralPath (Get-ChildItem -LiteralPath $out -Filter '*.html')[0].FullName -Raw) | Should -Match 'needs@contoso\.example'
        (& $script:Hash $script:UserPath) | Should -Be $before
    }
}
