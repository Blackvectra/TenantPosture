#Requires -Version 7.0
#
# NRG.TenantComparison.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Guards Compare-NRGTenantBaseline.ps1, Get-NRGBaselineTenantComparison and
# Publish-NRGBaselineTenantComparison: the offline, tenant-versus-tenant view
# of the NRG Security Baseline.
#
# The acceptance question for this feature is the one the baseline view itself
# answers for a single tenant, asked of two: can the report ever say two
# tenants "match" on a control that either run did not actually verify? Every
# test here is a way of answering "no". The rest pin the owner's decisions:
# any tier may be compared (only controls required at both are), the output is
# internal by default and anonymizable on request, an approved exception is a
# disposition and never a state, and the tool connects to nothing.
#
# Fixtures carry the raw shapes the entry point writes: rows are built field
# for field like Get-NRGBaselineCompliance's, serialized with ConvertTo-Json
# and read back with ConvertFrom-Json, and one suite runs the REAL compliance
# function over real findings. A fixture that handed the comparison a
# pre-digested model would never exercise the parser.

BeforeDiscovery {
    # Every state a baseline row can carry, as a comparison sees it.
    $Kinds = @('Satisfied', 'Failed', 'NotVerified', 'NotApplicable', 'LicenseBlocked', 'ThirdParty', 'Inconsistent', 'Unrecognized')
    $script:Matrix = foreach ($ka in $Kinds) {
        foreach ($kb in $Kinds) {
            # Written independently of the implementation: only a verdict on
            # BOTH sides (Satisfied or Failed) can be anything but NotComparable.
            $expected = if ($ka -eq 'Satisfied' -and $kb -eq 'Satisfied') { 'BothSatisfied' }
                        elseif ($ka -eq 'Failed' -and $kb -eq 'Failed') { 'BothFailed' }
                        elseif ($ka -eq 'Satisfied' -and $kb -eq 'Failed') { 'DiffersASatisfied' }
                        elseif ($ka -eq 'Failed' -and $kb -eq 'Satisfied') { 'DiffersBSatisfied' }
                        else { 'NotComparable' }
            @{ KindA = $ka; KindB = $kb; Expected = $expected }
        }
    }
}

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
    $script:Module = Get-Module NRG-Assessment

    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('nrg-cmp-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    $null = New-Item -ItemType Directory -Force -Path $script:Tmp

    # ── One baseline row, field for field like Get-NRGBaselineCompliance ──
    $script:NewRow = {
        param(
            [string] $Id,
            [string] $Kind = 'Satisfied',
            [string] $Tier = 'Minimum',
            [string] $Title = '',
            [string] $Expected = 'The expected state.',
            [string] $Disposition = 'Normal',
            [string] $Code = ''
        )
        $r = [ordered]@{
            ControlId = $Id; Title = $(if ($Title) { $Title } else { "Title of $Id" }); RequiredTier = $Tier; Owner = 'SENTINEL-OWNER'
            ExpectedState = $Expected; SlaClass = 'Critical'
            ObservedState = 'NotVerified'; ObservedFindingState = ''; Constraint = 'None'; Disposition = $Disposition
            EffectivenessState = 'Unknown'; EffectivenessCapability = 'NotCollected'; EffectivenessDetail = ''
            DependsOn = @(); DependencyState = 'None'; EvidenceSource = 'SENTINEL-EVIDENCE-SOURCE'
            EvidenceTimestamp = '2026-10-01T10:00:00.0000000Z'; EvidenceFreshness = 'Current'; FreshnessClass = 'Daily'
            NotVerifiedCause = ''; ReasonCode = ''; Reason = 'SENTINEL-REASON'; Detail = 'SENTINEL-DETAIL'
            ExceptionSummary = $(if ($Disposition -eq 'ApprovedException') { 'SENTINEL-EXCEPTION compensating control' } else { '' })
            BaselineStatus = ''
        }
        switch ($Kind) {
            'Satisfied'      { $r.ObservedState = 'Satisfied'; $r.ObservedFindingState = 'Satisfied'; $r.ReasonCode = 'Satisfied' }
            'Failed'         { $r.ObservedState = 'Failed'; $r.ObservedFindingState = 'Gap'; $r.ReasonCode = 'ControlFailed' }
            'NotVerified'    { $r.ObservedState = 'NotVerified'; $r.NotVerifiedCause = 'Evidence not read'; $r.ReasonCode = 'EvidenceNotRead'; $r.EvidenceFreshness = 'None' }
            'NotApplicable'  { $r.ObservedState = 'NotApplicable'; $r.ObservedFindingState = 'NotApplicable'; $r.ReasonCode = 'NotApplicable' }
            'LicenseBlocked' { $r.ObservedState = 'NotApplicable'; $r.ObservedFindingState = 'NotApplicable'; $r.Constraint = 'LicenseBlocked'; $r.ReasonCode = 'LicenseBlocked' }
            'ThirdParty'     { $r.ObservedState = 'NotApplicable'; $r.ObservedFindingState = 'NotApplicable'; $r.ReasonCode = 'ThirdPartyHandled' }
            # A state that contradicts its own reason code: a damaged or hand-edited file.
            'Inconsistent'   { $r.ObservedState = 'Satisfied'; $r.ReasonCode = 'EvidenceStale' }
            'Unrecognized'   { $r.ObservedState = 'Bogus'; $r.ReasonCode = 'Satisfied' }
        }
        if ($Code) { $r.ReasonCode = $Code }
        $r.BaselineStatus = if ($r.Constraint -eq 'LicenseBlocked') { 'LicenseBlocked' } elseif ($Disposition -eq 'ApprovedException') { 'ApprovedException' } else { $r.ObservedState }
        return [pscustomobject]$r
    }

    # ── A whole results file as the entry point writes it, read back from JSON ──
    $script:NewResults = {
        param(
            [string] $Domain = 'tenant-a.example',
            [string] $TenantId = '',
            [string] $Tier = 'Standard',
            [string] $Version = '1.0',
            [object[]] $Rows = @(),
            [object] $Time = '2026-10-01T10:00:00Z',
            [hashtable] $Skus = $null,
            [string] $ExceptionsPath = '',
            [switch] $NoRoundTrip
        )
        $coverage = Get-NRGBaselineCoverage -Rows $Rows
        $meta = [ordered]@{ TenantDomain = $Domain; Operator = 'sentinel-operator@operator.example'; ToolVersion = '4.14.3'; TargetTier = $Tier; BaselineVersion = $Version }
        if ($TenantId) { $meta['TenantId'] = $TenantId }
        if ($null -ne $Time) { $meta['AssessmentTime'] = $Time }
        $res = [ordered]@{
            Metadata = $meta
            Findings = @()
            Connections = [ordered]@{ TenantDomain = $Domain; TenantId = $TenantId }
            BaselineCompliance = [ordered]@{
                Available = $true; BaselineVersion = $Version; TargetTier = $Tier
                AsOf = '2026-10-01T10:00:00.0000000Z'; ExceptionsPath = $ExceptionsPath
                EvidenceCoverage = $coverage.Evidence; EffectivenessCoverage = $coverage.Effectiveness
                Controls = @($Rows)
            }
        }
        if ($Skus) { $res['RawData'] = [ordered]@{ 'AAD-Inventory' = [ordered]@{ Success = $true; Data = [ordered]@{ SubscribedSkus = @($Skus.Skus) } } } }
        $o = [pscustomobject]$res
        if ($NoRoundTrip) { return $o }
        return ($o | ConvertTo-Json -Depth 12 | ConvertFrom-Json -Depth 20)
    }

    # ── The oldest shape: no coverage, no AsOf, no TenantId, no RawData ──
    $script:NewOldResults = {
        param([string] $Tier = 'Minimum', [string] $Version = '1.0', [object[]] $Rows)
        $o = [pscustomobject]@{
            BaselineCompliance = [pscustomobject]@{ BaselineVersion = $Version; TargetTier = $Tier; Controls = @($Rows) }
        }
        return ($o | ConvertTo-Json -Depth 8 | ConvertFrom-Json -Depth 20)
    }

    $script:Compare = {
        param($a, $b, [switch] $Anon, [int] $Gap = 7)
        Get-NRGBaselineTenantComparison -ResultsA $a -ResultsB $b -Anonymize:$Anon -MaxRunGapDays $Gap
    }
    $script:All = { param($c) @($c.Differences) + @($c.BothFailed) + @($c.BothSatisfied) + @($c.NotComparable) }
    $script:One = { param($c, $id) @(& $script:All $c | Where-Object { $_.ControlId -eq $id })[0] }

    $script:PublishTo = {
        param($cmp, [string] $Name)
        $dir = Join-Path $script:Tmp $Name
        $paths = Publish-NRGBaselineTenantComparison -Comparison $cmp -OutputPath $dir
        [pscustomobject]@{
            Paths = $paths
            Md    = (Get-Content -LiteralPath $paths.Markdown -Raw -Encoding utf8)
            Html  = (Get-Content -LiteralPath $paths.Html -Raw -Encoding utf8)
            Csv   = (Get-Content -LiteralPath $paths.Csv -Raw -Encoding utf8)
            Names = @(Get-ChildItem -LiteralPath $dir | ForEach-Object { $_.Name })
        }
    }

    # Code tokens of a source file with the comments removed, and its parse errors.
    $script:CodeOf = {
        param([string] $Path)
        $tokens = $null; $errs = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errs)
        [pscustomobject]@{
            Errors = @($errs).Count
            Ast    = $ast
            Code   = (@($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' ')
            Commands = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        }
    }
}

AfterAll {
    if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    Clear-NRGState
    Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue
}

Describe 'Tenant comparison: classification keys on ObservedState and ReasonCode' {

    It 'classifies <KindA> against <KindB> as <Expected>' -ForEach $script:Matrix {
        $a = & $script:NewResults -Domain 'a.example' -Rows @(& $script:NewRow 'AAD-1.1' $KindA)
        $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1' $KindB)
        $c = & $script:Compare $a $b
        (& $script:One $c 'AAD-1.1').Classification | Should -Be $Expected
        $c.Counts.Compared | Should -Be 1
    }

    It 'never counts a control that either run did not verify as a match' -ForEach $script:Matrix {
        # The acceptance test. Whatever the pair, SamePosture can only be built
        # from controls with a verdict (Satisfied or Failed) on BOTH sides.
        $a = & $script:NewResults -Domain 'a.example' -Rows @(& $script:NewRow 'AAD-1.1' $KindA)
        $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1' $KindB)
        $c = & $script:Compare $a $b
        $bothHaveVerdict = ($KindA -in @('Satisfied', 'Failed')) -and ($KindB -in @('Satisfied', 'Failed'))
        if (-not $bothHaveVerdict) {
            $c.Counts.SamePosture | Should -Be 0
            $c.Counts.Verified | Should -Be 0
            $c.Counts.NotComparable | Should -Be 1
            @($c.NotComparable).Count | Should -Be 1
            @($c.BothSatisfied).Count + @($c.BothFailed).Count | Should -Be 0
        }
    }

    It 'lists each side''s reason code beside a not-comparable control' {
        $a = & $script:NewResults -Domain 'a.example' -Rows @(& $script:NewRow 'AAD-1.1' 'LicenseBlocked')
        $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1' 'ThirdParty')
        $row = & $script:One (& $script:Compare $a $b) 'AAD-1.1'
        $row.ReasonCodeA | Should -Be 'LicenseBlocked'
        $row.ReasonCodeB | Should -Be 'ThirdPartyHandled'
        $row.StateA | Should -Be 'LicenseBlocked'
        $row.StateB | Should -Be 'NotApplicable'
    }

    It 'two NotVerified controls are not a match, however alike they look' {
        $a = & $script:NewResults -Domain 'a.example' -Rows @(& $script:NewRow 'AAD-1.1' 'NotVerified')
        $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1' 'NotVerified')
        $c = & $script:Compare $a $b
        $c.Counts.SamePosture | Should -Be 0
        (& $script:One $c 'AAD-1.1').Classification | Should -Be 'NotComparable'
    }

    It 'a LicenseBlocked constraint outranks a Satisfied state on the same row' {
        # A hand-edited or damaged row: the constraint says the tenant lacks
        # the license, so the verdict cannot be relied on.
        $row = & $script:NewRow 'AAD-1.1' 'Satisfied'
        $row.Constraint = 'LicenseBlocked'
        $a = & $script:NewResults -Domain 'a.example' -Rows @($row)
        $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1' 'Satisfied')
        (& $script:One (& $script:Compare $a $b) 'AAD-1.1').Classification | Should -Be 'NotComparable'
    }

    It 'a ThirdPartyHandled reason code carries no verdict even on a Satisfied row' {
        $row = & $script:NewRow 'AAD-1.1' 'Satisfied' -Code 'ThirdPartyHandled'
        $a = & $script:NewResults -Domain 'a.example' -Rows @($row)
        $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1' 'Satisfied')
        $r = & $script:One (& $script:Compare $a $b) 'AAD-1.1'
        $r.Classification | Should -Be 'NotComparable'
        $r.StateA | Should -Be 'Inconsistent'
    }

    It 'an unknown reason code on a verdict row is not trusted' {
        $row = & $script:NewRow 'AAD-1.1' 'Satisfied' -Code 'SomeFutureCode'
        $a = & $script:NewResults -Domain 'a.example' -Rows @($row)
        $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1' 'Satisfied')
        $r = & $script:Compare $a $b
        (& $script:One $r 'AAD-1.1').Classification | Should -Be 'NotComparable'
        (& $script:One $r 'AAD-1.1').ReasonCodeA | Should -Be 'Unrecognized'
    }

    It 'a row with no ObservedState carries no verdict, whatever its display status says' {
        $row = & $script:NewRow 'AAD-1.1' 'Satisfied'
        $row.PSObject.Properties.Remove('ObservedState')
        $a = & $script:NewResults -Domain 'a.example' -Rows @($row)
        $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1' 'Satisfied')
        (& $script:One (& $script:Compare $a $b) 'AAD-1.1').Classification | Should -Be 'NotComparable'
    }

    Context 'Approved exceptions are a disposition, never a state' {
        It 'a failed control with an approved exception is still Failed' {
            $a = & $script:NewResults -Domain 'a.example' -Rows @(& $script:NewRow 'AAD-1.1' 'Failed' -Disposition 'ApprovedException')
            $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1' 'Satisfied')
            $c = & $script:Compare $a $b
            $r = & $script:One $c 'AAD-1.1'
            $r.Classification | Should -Be 'DiffersBSatisfied'
            $r.StateA | Should -Be 'Failed'
            $r.DispositionA | Should -Be 'ApprovedException'
            $r.DispositionB | Should -Be 'Normal'
            $c.Counts.SamePosture | Should -Be 0
        }
        It 'failed at both with an exception on one side is BothFailed, exception shown' {
            $a = & $script:NewResults -Domain 'a.example' -Rows @(& $script:NewRow 'AAD-1.1' 'Failed' -Disposition 'ApprovedException')
            $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1' 'Failed')
            $c = & $script:Compare $a $b
            (& $script:One $c 'AAD-1.1').Classification | Should -Be 'BothFailed'
            $c.Counts.ApprovedExceptionsA | Should -Be 1
            $c.Counts.ApprovedExceptionsB | Should -Be 0
            $c.SideA.ApprovedExceptionsCompared | Should -Be 1
        }
        It 'an exception recorded only in the display status (an older file) still reads as a disposition' {
            $row = & $script:NewRow 'AAD-1.1' 'Failed'
            $row.PSObject.Properties.Remove('Disposition')
            $row.BaselineStatus = 'ApprovedException'
            $a = & $script:NewResults -Domain 'a.example' -Rows @($row)
            $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1' 'Satisfied')
            $r = & $script:One (& $script:Compare $a $b) 'AAD-1.1'
            $r.DispositionA | Should -Be 'ApprovedException'
            $r.StateA | Should -Be 'Failed'
        }
        It 'an exception never turns a failure into a match' {
            $a = & $script:NewResults -Domain 'a.example' -Rows @(& $script:NewRow 'AAD-1.1' 'Failed' -Disposition 'ApprovedException')
            $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1' 'Satisfied' -Disposition 'ApprovedException')
            (& $script:One (& $script:Compare $a $b) 'AAD-1.1').Classification | Should -Be 'DiffersBSatisfied'
        }
    }

    Context 'The counts add up' {
        It 'Compared = Verified + NotComparable, and each side''s required controls are fully accounted for' {
            $rowsA = @(
                & $script:NewRow 'AAD-1.1' 'Satisfied'; & $script:NewRow 'AAD-1.2' 'Failed'; & $script:NewRow 'AAD-1.3' 'Satisfied'
                & $script:NewRow 'EXO-1.1' 'NotVerified'; & $script:NewRow 'DEF-1.1' 'Failed'; & $script:NewRow 'DEF-1.2' 'Satisfied' -Tier 'Standard'
                & $script:NewRow 'INT-2.1' 'Satisfied' -Expected 'one wording'
            )
            $rowsB = @(
                & $script:NewRow 'AAD-1.1' 'Satisfied'; & $script:NewRow 'AAD-1.2' 'Satisfied'; & $script:NewRow 'AAD-1.3' 'Failed'
                & $script:NewRow 'EXO-1.1' 'Satisfied'; & $script:NewRow 'DEF-1.1' 'Failed'
                & $script:NewRow 'PVW-1.1' 'Satisfied' -Tier 'Standard'; & $script:NewRow 'SPO-1.1' 'Failed' -Tier 'Hardened'
                & $script:NewRow 'INT-2.1' 'Satisfied' -Expected 'another wording'
            )
            $c = & $script:Compare (& $script:NewResults -Domain 'a.example' -Rows $rowsA) (& $script:NewResults -Domain 'b.example' -Rows $rowsB)
            $n = $c.Counts
            $n.Compared | Should -Be ($n.Verified + $n.NotComparable)
            $n.Verified | Should -Be ($n.BothSatisfied + $n.BothFailed + $n.DiffersASatisfied + $n.DiffersBSatisfied)
            $n.SamePosture | Should -Be ($n.BothSatisfied + $n.BothFailed)
            $n.RequiredA | Should -Be ($n.Compared + $n.RequiredOnlyAtA + $n.DefinitionDiffers)
            $n.RequiredB | Should -Be ($n.Compared + $n.RequiredOnlyAtB + $n.DefinitionDiffers)
            $n.NotCompared | Should -Be ($n.RequiredOnlyAtA + $n.RequiredOnlyAtB + $n.DefinitionDiffers)
            @(& $script:All $c).Count | Should -Be $n.Compared
            @($c.NotCompared).Count | Should -Be $n.NotCompared
            # The concrete expectation, so the algebra above is not vacuous.
            $n.BothSatisfied | Should -Be 1
            $n.BothFailed | Should -Be 1
            $n.DiffersASatisfied | Should -Be 1
            $n.DiffersBSatisfied | Should -Be 1
            $n.NotComparable | Should -Be 1
            $n.RequiredOnlyAtA | Should -Be 1
            $n.RequiredOnlyAtB | Should -Be 2
            $n.DefinitionDiffers | Should -Be 1
        }
    }
}

Describe 'Tenant comparison: any tier may be compared' {

    BeforeAll {
        $script:MinRows = @(
            & $script:NewRow 'AAD-1.1' 'Satisfied'; & $script:NewRow 'AAD-1.2' 'Failed'; & $script:NewRow 'EXO-1.1' 'Satisfied'
        )
        $script:StdRows = $script:MinRows + @(
            & $script:NewRow 'DEF-1.1' 'Satisfied' -Tier 'Standard'; & $script:NewRow 'DEF-1.2' 'Failed' -Tier 'Standard'
        )
        $script:HardRows = $script:StdRows + @(& $script:NewRow 'PVW-1.1' 'Failed' -Tier 'Hardened')
    }

    It 'a Minimum run against a Standard run compares only the Minimum controls and lists the rest' {
        $a = & $script:NewResults -Domain 'a.example' -Tier 'Minimum' -Rows $script:MinRows
        $b = & $script:NewResults -Domain 'b.example' -Tier 'Standard' -Rows $script:StdRows
        $c = & $script:Compare $a $b
        $c.Available | Should -BeTrue
        $c.Counts.Compared | Should -Be 3
        @(& $script:All $c | ForEach-Object { $_.ControlId } | Sort-Object) | Should -Be @('AAD-1.1', 'AAD-1.2', 'EXO-1.1')
        $left = @($c.NotCompared)
        $left.Count | Should -Be 2
        @($left | ForEach-Object { $_.ControlId } | Sort-Object) | Should -Be @('DEF-1.1', 'DEF-1.2')
        foreach ($r in $left) {
            $r.Basis | Should -Be 'RequiredOnlyAtB'
            $r.RequiredTierB | Should -Be 'Standard'
            $r.RequiredTierA | Should -BeNullOrEmpty
        }
        $c.Context.ComparedTier | Should -Be 'Minimum'
        $c.Context.TargetTiersDiffer | Should -BeTrue
    }

    It 'the same pair the other way round lists the extra controls against A, with their tier' {
        $a = & $script:NewResults -Domain 'a.example' -Tier 'Standard' -Rows $script:StdRows
        $b = & $script:NewResults -Domain 'b.example' -Tier 'Minimum' -Rows $script:MinRows
        $c = & $script:Compare $a $b
        $c.Counts.Compared | Should -Be 3
        foreach ($r in @($c.NotCompared)) {
            $r.Basis | Should -Be 'RequiredOnlyAtA'
            $r.RequiredTierA | Should -Be 'Standard'
        }
        $c.Counts.RequiredOnlyAtA | Should -Be 2
        $c.Counts.RequiredOnlyAtB | Should -Be 0
    }

    It 'Hardened against Minimum compares the Minimum controls; Hardened against Standard compares the Standard controls' {
        $h = & $script:NewResults -Domain 'a.example' -Tier 'Hardened' -Rows $script:HardRows
        $m = & $script:NewResults -Domain 'b.example' -Tier 'Minimum' -Rows $script:MinRows
        $s = & $script:NewResults -Domain 'c.example' -Tier 'Standard' -Rows $script:StdRows
        (& $script:Compare $h $m).Counts.Compared | Should -Be 3
        (& $script:Compare $h $m).Context.ComparedTier | Should -Be 'Minimum'
        $hs = & $script:Compare $h $s
        $hs.Counts.Compared | Should -Be 5
        $hs.Context.ComparedTier | Should -Be 'Standard'
        @($hs.NotCompared).Count | Should -Be 1
        @($hs.NotCompared)[0].ControlId | Should -Be 'PVW-1.1'
        @($hs.NotCompared)[0].RequiredTierA | Should -Be 'Hardened'
    }

    It 'states the tier each tenant was assessed at, and does not refuse a tier difference' {
        $a = & $script:NewResults -Domain 'a.example' -Tier 'Minimum' -Rows $script:MinRows
        $b = & $script:NewResults -Domain 'b.example' -Tier 'Standard' -Rows $script:StdRows
        $c = & $script:Compare $a $b
        $c.SideA.TargetTier | Should -Be 'Minimum'
        $c.SideB.TargetTier | Should -Be 'Standard'
        $joined = (@($c.Notes) + @($c.Warnings)) -join ' '
        $joined | Should -Match 'A was assessed at the Minimum tier and B at the Standard tier'
        $joined | Should -Match 'required at both tenants'
        $joined | Should -Match 'Minimum controls'
        # The tier difference is a statement, not a warning to act on.
        @($c.Warnings | Where-Object { $_ -match 'tier' }) | Should -BeNullOrEmpty
    }

    It 'the same tier on both sides is stated and nothing is left out' {
        $a = & $script:NewResults -Domain 'a.example' -Tier 'Standard' -Rows $script:StdRows
        $b = & $script:NewResults -Domain 'b.example' -Tier 'Standard' -Rows $script:StdRows
        $c = & $script:Compare $a $b
        $c.Counts.NotCompared | Should -Be 0
        $c.Context.TargetTiersDiffer | Should -BeFalse
        (@($c.Notes) -join ' ') | Should -Match 'Both tenants were assessed at the Standard tier'
    }

    It 'compares a real Minimum run against a real Standard run: the Minimum set, with the Standard-only controls listed' {
        # The REAL compliance function over the REAL definition, so the tier
        # rule is pinned against the shipped baseline and not only fixtures.
        $def = Get-NRGBaselineDefinition -Force
        $noExc = [ordered]@{ Available = $false; Path = ''; Entries = @(); Approved = @{}; Rejected = @() }
        $f = @(foreach ($id in $def.Controls.Keys) {
            if ($id -ne 'VM-VERIFY-01') { [pscustomobject]@{ ControlId = $id; State = 'Satisfied'; Category = 'x'; Title = $id; Severity = 'High'; Detail = 'observed'; Timestamp = (Get-Date).ToString('o') } }
        })
        $bcMin = Get-NRGBaselineCompliance -Findings $f -TargetTier Minimum  -Exceptions $noExc -RawData @{} -Coverage @{}
        $bcStd = Get-NRGBaselineCompliance -Findings $f -TargetTier Standard -Exceptions $noExc -RawData @{} -Coverage @{}
        $mk = { param($bc, $d) ([pscustomobject]@{ Metadata = @{ TenantDomain = $d; AssessmentTime = (Get-Date).ToString('o') }; BaselineCompliance = $bc }) | ConvertTo-Json -Depth 12 | ConvertFrom-Json -Depth 20 }
        $c = & $script:Compare (& $mk $bcMin 'a.example') (& $mk $bcStd 'b.example')
        $minCount = @($def.Controls.Values | Where-Object { $_.Tier -eq 'Minimum' }).Count
        $stdCount = @($def.Controls.Values | Where-Object { $_.Tier -eq 'Standard' }).Count
        $c.Counts.Compared | Should -Be $minCount
        $c.Counts.RequiredOnlyAtB | Should -Be $stdCount
        @($c.NotCompared | Where-Object { $_.RequiredTierB -ne 'Standard' }) | Should -BeNullOrEmpty
        # VM-VERIFY-01 is manual: required at both, verified at neither.
        (& $script:One $c 'VM-VERIFY-01').Classification | Should -Be 'NotComparable'
        (& $script:One $c 'VM-VERIFY-01').ReasonCodeA | Should -Be 'ManualVerificationRequired'
        $c.Counts.SamePosture | Should -Be ($minCount - 1)
    }
}

Describe 'Tenant comparison: baseline version' {

    It 'says the standard changed when the versions differ' {
        $a = & $script:NewResults -Domain 'a.example' -Version '1.0' -Rows @(& $script:NewRow 'AAD-1.1')
        $b = & $script:NewResults -Domain 'b.example' -Version '1.1' -Rows @(& $script:NewRow 'AAD-1.1')
        $c = & $script:Compare $a $b
        $c.Context.BaselineVersionsDiffer | Should -BeTrue
        $c.SideA.BaselineVersion | Should -Be '1.0'
        $c.SideB.BaselineVersion | Should -Be '1.1'
        (@($c.Warnings) -join ' ') | Should -Match 'different versions of the NRG Security Baseline \(A: v1\.0, B: v1\.1\)'
        (@($c.Warnings) -join ' ') | Should -Match 'standard changed'
    }

    It 'compares only controls whose required tier and expected state are the same in both versions, and lists the rest' {
        $rowsA = @(
            & $script:NewRow 'AAD-1.1' 'Satisfied'                                   # unchanged: compared
            & $script:NewRow 'AAD-1.2' 'Satisfied' -Tier 'Minimum'                    # moved tier in v1.1
            & $script:NewRow 'EXO-1.1' 'Satisfied' -Expected 'Audit logging on.'      # reworded in v1.1
            & $script:NewRow 'DEF-1.1' 'Satisfied' -Tier 'Standard'                   # dropped in v1.1
        )
        $rowsB = @(
            & $script:NewRow 'AAD-1.1' 'Satisfied'
            & $script:NewRow 'AAD-1.2' 'Satisfied' -Tier 'Standard'
            & $script:NewRow 'EXO-1.1' 'Satisfied' -Expected 'Audit logging on for every mailbox.'
            & $script:NewRow 'PVW-1.1' 'Satisfied' -Tier 'Standard'                   # new in v1.1
        )
        $c = & $script:Compare (& $script:NewResults -Domain 'a.example' -Version '1.0' -Tier 'Standard' -Rows $rowsA) (& $script:NewResults -Domain 'b.example' -Version '1.1' -Tier 'Standard' -Rows $rowsB)
        @(& $script:All $c | ForEach-Object { $_.ControlId }) | Should -Be @('AAD-1.1')
        $byId = @{}; foreach ($r in @($c.NotCompared)) { $byId[$r.ControlId] = $r }
        $byId['AAD-1.2'].Basis | Should -Be 'DefinitionDiffers'
        $byId['AAD-1.2'].RequiredTierA | Should -Be 'Minimum'
        $byId['AAD-1.2'].RequiredTierB | Should -Be 'Standard'
        $byId['EXO-1.1'].Basis | Should -Be 'DefinitionDiffers'
        $byId['DEF-1.1'].Basis | Should -Be 'RequiredOnlyAtA'
        $byId['PVW-1.1'].Basis | Should -Be 'RequiredOnlyAtB'
        $c.Counts.DefinitionDiffers | Should -Be 2
        # A control moved to a different tier is not a regression, a match or a difference.
        $c.Counts.SamePosture | Should -Be 1
    }

    It 'a missing expected state on one side (an older file) does not stop a control being compared' {
        $rowsA = @(& $script:NewRow 'AAD-1.1' 'Satisfied' -Expected 'Some wording.')
        $rowB = & $script:NewRow 'AAD-1.1' 'Satisfied'
        $rowB.PSObject.Properties.Remove('ExpectedState')
        $c = & $script:Compare (& $script:NewResults -Domain 'a.example' -Version '1.0' -Rows $rowsA) (& $script:NewResults -Domain 'b.example' -Version '1.1' -Rows @($rowB))
        $c.Counts.Compared | Should -Be 1
        $c.Counts.DefinitionDiffers | Should -Be 0
    }

    It 'the same version draws no standard-changed warning' {
        $a = & $script:NewResults -Domain 'a.example' -Rows @(& $script:NewRow 'AAD-1.1')
        $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1')
        $c = & $script:Compare $a $b
        $c.Context.BaselineVersionsMatch | Should -BeTrue
        (@($c.Warnings) -join ' ') | Should -Not -Match 'standard changed'
        (@($c.Notes) -join ' ') | Should -Match 'Both runs used NRG Security Baseline v1\.0'
    }

    It 'a version missing from one file is stated, not assumed equal' {
        $a = & $script:NewResults -Domain 'a.example' -Version '' -Rows @(& $script:NewRow 'AAD-1.1')
        $b = & $script:NewResults -Domain 'b.example' -Version '1.0' -Rows @(& $script:NewRow 'AAD-1.1')
        $c = & $script:Compare $a $b
        $c.Context.BaselineVersionsMatch | Should -BeFalse
        (@($c.Warnings) -join ' ') | Should -Match 'version was not recorded for A'
        $c.Counts.Compared | Should -Be 1
    }
}

Describe 'Tenant comparison: the headline' {

    It 'counts controls both tenants verified, with the not-comparable and one-sided counts beside it' {
        $rowsA = @(
            & $script:NewRow 'AAD-1.1' 'Satisfied'; & $script:NewRow 'AAD-1.2' 'Satisfied'; & $script:NewRow 'AAD-1.3' 'Failed'
            & $script:NewRow 'EXO-1.1' 'NotVerified'; & $script:NewRow 'DEF-1.1' 'Satisfied' -Tier 'Standard'
        )
        $rowsB = @(
            & $script:NewRow 'AAD-1.1' 'Satisfied'; & $script:NewRow 'AAD-1.2' 'Failed'; & $script:NewRow 'AAD-1.3' 'Failed'
            & $script:NewRow 'EXO-1.1' 'Satisfied'
        )
        $c = & $script:Compare (& $script:NewResults -Domain 'a.example' -Tier 'Standard' -Rows $rowsA) (& $script:NewResults -Domain 'b.example' -Tier 'Minimum' -Rows $rowsB)
        $c.Headline | Should -Be 'Same baseline posture on 2 of 3 controls that both tenants verified (1 satisfied at both, 1 failed at both); 1 differ.'
        $c.HeadlineDetail | Should -Match '1 control\(s\) could not be compared'
        $c.HeadlineDetail | Should -Match '1 control\(s\) were left out'
    }

    It 'says plainly when nothing was verified at both tenants' {
        $a = & $script:NewResults -Domain 'a.example' -Rows @(& $script:NewRow 'AAD-1.1' 'NotVerified')
        $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1' 'Satisfied')
        $c = & $script:Compare $a $b
        $c.Headline | Should -Match '^No control was verified at both tenants'
        $c.Counts.Verified | Should -Be 0
    }

    It 'carries no score, no ranking and no verdict word, in the model or in any output' {
        $a = & $script:NewResults -Domain 'a.example' -Rows @(& $script:NewRow 'AAD-1.1' 'Satisfied'; & $script:NewRow 'AAD-1.2' 'Failed'; & $script:NewRow 'EXO-1.1' 'LicenseBlocked')
        $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1' 'Failed'; & $script:NewRow 'AAD-1.2' 'Failed'; & $script:NewRow 'EXO-1.1' 'ThirdParty')
        $c = & $script:Compare $a $b
        $c.Headline | Should -Not -Match '%'

        # No model key that names a score, a rank or a winner, at any depth.
        $names = [System.Collections.Generic.List[string]]::new()
        $walk = $null
        $walk = {
            param($o, [int] $depth)
            if ($null -eq $o -or $depth -gt 6 -or $o -is [string] -or $o -is [ValueType]) { return }
            if ($o -is [System.Collections.IDictionary]) { foreach ($k in $o.Keys) { $names.Add([string]$k); & $walk $o[$k] ($depth + 1) } }
            elseif ($o -is [System.Collections.IEnumerable]) { foreach ($i in $o) { & $walk $i ($depth + 1) } }
            else { foreach ($p in $o.PSObject.Properties) { $names.Add([string]$p.Name); & $walk $p.Value ($depth + 1) } }
        }
        & $walk $c 0
        @($names | Where-Object { $_ -match '(?i)score|rank|grade|winner|leader|percent|rating' }) | Should -BeNullOrEmpty

        $out = & $script:PublishTo $c 'noscore'
        foreach ($text in @($out.Md, $out.Html, $out.Csv)) {
            # The module's own reason-code meanings say a license-blocked or
            # third-party control is "not scored": a statement about a control,
            # not a score for a tenant. Everything else is checked.
            $t = $text -replace 'not scored', ''
            $t | Should -Not -Match '(?i)\bcompliant\b|\bnon-?compliant\b|\bcompliance\b'
            $t | Should -Not -Match '(?i)\bbetter\b|\bworse\b|\bwinner\b|\bahead\b|\bbehind\b|\bleader\b|\bgrade\b|\branked\b|\branking\b'
            $t | Should -Not -Match '(?i)\bscor(e|es|ed|ing)\b'
        }
    }
}

Describe 'Tenant comparison: metadata side by side' {

    It 'shows tenant, run date, tier, version, freshness, licensing and both coverage lines for each side' {
        $rowsA = @(& $script:NewRow 'AAD-1.1' 'Satisfied'; & $script:NewRow 'AAD-1.2' 'NotVerified')
        $rowsB = @(& $script:NewRow 'AAD-1.1' 'Satisfied')
        $rowsB[0].EvidenceFreshness = 'Stale'; $rowsB[0].EvidenceTimestamp = '2026-09-20T08:00:00Z'
        $a = & $script:NewResults -Domain 'a.example' -TenantId 'aaaaaaaa-0000-0000-0000-000000000001' -Tier 'Standard' -Time '2026-10-01T10:00:00Z' -Rows $rowsA
        $b = & $script:NewResults -Domain 'b.example' -TenantId 'bbbbbbbb-0000-0000-0000-000000000002' -Tier 'Minimum' -Time '2026-10-03T09:00:00Z' -Rows $rowsB
        $c = & $script:Compare $a $b
        $c.SideA.Name | Should -Be 'a.example'
        $c.SideB.Name | Should -Be 'b.example'
        $c.SideA.RunDate | Should -Be '2026-10-01'
        $c.SideB.RunDate | Should -Be '2026-10-03'
        $c.SideA.Freshness.Current | Should -Be 1
        $c.SideA.Freshness.None | Should -Be 1
        $c.SideB.Freshness.Stale | Should -Be 1
        $c.SideB.Freshness.Oldest | Should -Be '2026-09-20'
        $c.SideA.EvidenceCoverage.Available | Should -BeTrue
        $c.SideA.EvidenceCoverage.Line | Should -Match '^1 of 2 applicable controls have usable evidence \(50%\)'
        $c.SideA.EvidenceCoverage.Line | Should -Match 'evidence not obtained: 1 EvidenceNotRead'
        $c.SideA.EffectivenessCoverage.Line | Should -Match '^0 of 2 required controls have effectiveness evidence'

        $out = & $script:PublishTo $c 'sidebyside'
        foreach ($text in @($out.Md, $out.Html)) {
            $text | Should -Match 'a\.example'
            $text | Should -Match 'b\.example'
            $text | Should -Match '2026-10-01'
            $text | Should -Match '2026-10-03'
            $text | Should -Match 'Evidence freshness'
            $text | Should -Match 'Licensed tier'
            $text | Should -Match 'Evidence coverage'
            $text | Should -Match 'Effectiveness coverage'
            $text | Should -Match 'Baseline version'
            $text | Should -Match 'Target tier'
        }
    }

    It 'warns when the runs are far apart, and not when they are close' {
        $rows = @(& $script:NewRow 'AAD-1.1')
        $far = & $script:Compare (& $script:NewResults -Domain 'a.example' -Time '2026-09-01T10:00:00Z' -Rows $rows) (& $script:NewResults -Domain 'b.example' -Time '2026-10-01T10:00:00Z' -Rows $rows)
        $far.Context.RunsFarApart | Should -BeTrue
        $far.Context.RunsApartDays | Should -Be 30
        (@($far.Warnings) -join ' ') | Should -Match '30 days apart, more than the 7-day limit'
        $near = & $script:Compare (& $script:NewResults -Domain 'a.example' -Time '2026-09-30T10:00:00Z' -Rows $rows) (& $script:NewResults -Domain 'b.example' -Time '2026-10-01T10:00:00Z' -Rows $rows)
        $near.Context.RunsFarApart | Should -BeFalse
        (@($near.Warnings) -join ' ') | Should -Not -Match 'days apart'
        # The limit is the operator's to move.
        (& $script:Compare (& $script:NewResults -Domain 'a.example' -Time '2026-09-01T10:00:00Z' -Rows $rows) (& $script:NewResults -Domain 'b.example' -Time '2026-10-01T10:00:00Z' -Rows $rows) -Gap 60).Context.RunsFarApart | Should -BeFalse
    }

    It 'reads a run time from a string or a datetime alike, and falls back to the view''s own AsOf' {
        $rows = @(& $script:NewRow 'AAD-1.1')
        $str = & $script:NewResults -Domain 'a.example' -Time '2026-10-01T10:00:00Z' -Rows $rows -NoRoundTrip       # string
        $dt  = & $script:NewResults -Domain 'b.example' -Time '2026-10-01T10:00:00Z' -Rows $rows                    # DateTime after ConvertFrom-Json
        $dt.Metadata.AssessmentTime | Should -BeOfType [datetime]
        $str.Metadata.AssessmentTime | Should -BeOfType [string]
        $c = & $script:Compare $str $dt
        $c.Context.RunsApartDays | Should -Be 0
        $c.SideA.RunDate | Should -Be '2026-10-01'
        $c.SideB.RunDate | Should -Be '2026-10-01'
        $noTime = & $script:NewResults -Domain 'c.example' -Time $null -Rows $rows
        (& $script:Compare $noTime $dt).SideA.RunDate | Should -Be '2026-10-01'   # from BaselineCompliance.AsOf
    }

    It 'says so when a run time is not recorded' {
        $old = & $script:NewOldResults -Rows @(& $script:NewRow 'AAD-1.1')
        $c = & $script:Compare $old (& $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1'))
        (@($c.Warnings) -join ' ') | Should -Match 'run time was not recorded for A'
        $c.Context.RunsApartDays | Should -BeNullOrEmpty
    }

    Context 'Licensing' {
        It 'states license differences between two read tenants' {
            $bp  = @{ Skus = @(@{ SkuPartNumber = 'SPB'; ServicePlans = @('AAD_PREMIUM', 'INTUNE_A', 'ATP_ENTERPRISE', 'MDE_SMB') }) }
            $std = @{ Skus = @(@{ SkuPartNumber = 'O365_BUSINESS_PREMIUM'; ServicePlans = @('EXCHANGE_S_STANDARD') }) }
            $rows = @(& $script:NewRow 'AAD-1.1')
            $c = & $script:Compare (& $script:NewResults -Domain 'a.example' -Rows $rows -Skus $bp) (& $script:NewResults -Domain 'b.example' -Rows $rows -Skus $std)
            $c.SideA.License.Read | Should -BeTrue
            $c.SideA.License.TierLabel | Should -Be 'Microsoft 365 Business Premium'
            $c.SideB.License.TierLabel | Should -Be 'Microsoft 365 Business Standard'
            $c.SideA.License.Flags['Entra ID P1 or higher'] | Should -BeTrue
            $c.SideB.License.Flags['Entra ID P1 or higher'] | Should -BeFalse
            $diffs = @($c.LicenseDifferences) -join ' | '
            $diffs | Should -Match 'Licensed tier: A is Microsoft 365 Business Premium, B is Microsoft 365 Business Standard'
            $diffs | Should -Match 'Entra ID P1 or higher: A has it, B does not'
            $diffs | Should -Match 'Intune: A has it, B does not'
        }
        It 'identical licensing states no difference' {
            $bp = @{ Skus = @(@{ SkuPartNumber = 'SPB'; ServicePlans = @('AAD_PREMIUM', 'INTUNE_A') }) }
            $rows = @(& $script:NewRow 'AAD-1.1')
            $c = & $script:Compare (& $script:NewResults -Domain 'a.example' -Rows $rows -Skus $bp) (& $script:NewResults -Domain 'b.example' -Rows $rows -Skus $bp)
            @($c.LicenseDifferences).Count | Should -Be 0
            (& $script:PublishTo $c 'licsame').Md | Should -Match 'same licensed capabilities'
        }
        It 'unread licensing is not read, never "none", and no difference is invented' {
            $bp = @{ Skus = @(@{ SkuPartNumber = 'SPB'; ServicePlans = @('AAD_PREMIUM') }) }
            $rows = @(& $script:NewRow 'AAD-1.1')
            $c = & $script:Compare (& $script:NewResults -Domain 'a.example' -Rows $rows -Skus $bp) (& $script:NewResults -Domain 'b.example' -Rows $rows)
            $c.SideB.License.Read | Should -BeFalse
            $c.SideB.License.TierLabel | Should -Be 'Not read'
            @($c.LicenseDifferences).Count | Should -Be 0
            (@($c.Notes) -join ' ') | Should -Match 'Licensing was not read for B'
            (& $script:PublishTo $c 'licunread').Md | Should -Match 'Not stated: licensing was not read'
        }
    }

    Context 'Evidence coverage lines' {
        It 'a coverage block that is absent is stated as not recorded, never recomputed' {
            $old = & $script:NewOldResults -Rows @(& $script:NewRow 'AAD-1.1')
            $c = & $script:Compare $old (& $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1'))
            $c.SideA.EvidenceCoverage.Available | Should -BeFalse
            $c.SideA.EvidenceCoverage.Line | Should -Match 'Not recorded in this results file'
            $c.SideA.EffectivenessCoverage.Line | Should -Match 'Not recorded in this results file'
        }
        It 'a gap name that is not a known reason code is reported as Other, never as the file''s text' {
            $a = & $script:NewResults -Domain 'a.example' -Rows @(& $script:NewRow 'AAD-1.1')
            $a.BaselineCompliance.EvidenceCoverage.Gaps = [pscustomobject]@{ 'hostile-label-xyz' = 2; 'CollectorUnavailable' = 1 }
            $c = & $script:Compare $a (& $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1'))
            $c.SideA.EvidenceCoverage.Line | Should -Match '2 Other'
            $c.SideA.EvidenceCoverage.Line | Should -Match '1 CollectorUnavailable'
            $c.SideA.EvidenceCoverage.Line | Should -Not -Match 'hostile-label-xyz'
        }
    }
}

Describe 'Tenant comparison: identity, input shape and unavailable results' {

    It 'warns, but still compares, when both files come from the same tenant' {
        $rows = @(& $script:NewRow 'AAD-1.1')
        $c = & $script:Compare (& $script:NewResults -Domain 'a.example' -TenantId 'aaaaaaaa-0000-0000-0000-000000000001' -Rows $rows) (& $script:NewResults -Domain 'a2.example' -TenantId 'AAAAAAAA-0000-0000-0000-000000000001' -Rows $rows)
        $c.Context.SameTenant | Should -BeTrue
        (@($c.Warnings) -join ' ') | Should -Match 'same tenant'
        (@($c.Warnings) -join ' ') | Should -Match '-BaselineResults'
        $c.Available | Should -BeTrue
        $diff = & $script:Compare (& $script:NewResults -Domain 'a.example' -TenantId 'aaaaaaaa-0000-0000-0000-000000000001' -Rows $rows) (& $script:NewResults -Domain 'b.example' -TenantId 'bbbbbbbb-0000-0000-0000-000000000002' -Rows $rows)
        $diff.Context.SameTenant | Should -BeFalse
    }

    It 'skips rows with no valid ControlId and duplicates, and says so' {
        $rows = @(
            & $script:NewRow 'AAD-1.1' 'Satisfied'
            & $script:NewRow 'AAD-1.1' 'Failed'                          # duplicate: first wins
            & $script:NewRow 'not a control id' 'Satisfied'              # unreadable
            & $script:NewRow 'contoso.com' 'Satisfied'                   # not a baseline ID shape
        )
        $c = & $script:Compare (& $script:NewResults -Domain 'a.example' -Rows $rows) (& $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1' 'Satisfied'))
        $c.SideA.RequiredControls | Should -Be 1
        $c.SideA.UnreadableRows | Should -Be 2
        $c.SideA.DuplicateRows | Should -Be 1
        (& $script:One $c 'AAD-1.1').StateA | Should -Be 'Satisfied'
        (@($c.Warnings) -join ' ') | Should -Match '2 control row\(s\) in A had no valid ControlId and 1 were duplicates'
    }

    It 'reports not available, naming the side, when a file carries no baseline controls' {
        $good = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1')
        $none = [pscustomobject]@{ Metadata = [pscustomobject]@{ TenantDomain = 'a.example' }; Findings = @() }
        $c = & $script:Compare $none $good
        $c.Available | Should -BeFalse
        $c.Note | Should -Match 'Results A carry no NRG Security Baseline controls'
        (& $script:Compare $good $none).Note | Should -Match 'Results B carry'
        (& $script:Compare $none $none).Note | Should -Match 'Results A and B carry'
        (& $script:Compare $null $good).Available | Should -BeFalse
        $explicit = & $script:NewResults -Domain 'a.example' -Rows @(& $script:NewRow 'AAD-1.1')
        $explicit.BaselineCompliance.Available = $false
        (& $script:Compare $explicit $good).Available | Should -BeFalse
        $empty = & $script:NewResults -Domain 'a.example' -Rows @()
        (& $script:Compare $empty $good).Available | Should -BeFalse
    }

    It 'the publisher refuses an unavailable comparison' {
        $c = & $script:Compare $null $null
        { Publish-NRGBaselineTenantComparison -Comparison $c -OutputPath (Join-Path $script:Tmp 'unavail') } | Should -Throw '*Comparison not generated*'
    }
}

Describe 'Tenant comparison: privacy' {

    BeforeAll {
        # Hostile names and domains everywhere a tenant name could ride along.
        $script:DomA = 'hostile-contoso.example'; $script:LabelA = 'hostile-contoso'; $script:IdA = 'aaaaaaaa-1111-2222-3333-444444444444'
        $script:DomB = 'evilfabrikam.test';       $script:LabelB = 'evilfabrikam';       $script:IdB = 'bbbbbbbb-5555-6666-7777-888888888888'
        $mkRows = {
            param([string] $own, [string] $other, [string] $ownId)
            $r1 = & $script:NewRow 'AAD-1.1' 'Satisfied' -Title "Legacy auth for $own and $other"
            $r2 = & $script:NewRow 'AAD-1.2' 'Failed' -Title "MFA tenant $ownId <script>nrgprobe</script>" -Disposition 'ApprovedException'
            $r3 = & $script:NewRow 'EXO-1.1' 'NotVerified' -Title "Audit $($own.ToUpper())"
            $r4 = & $script:NewRow 'DEF-1.1' 'Satisfied' -Code $own             # a reason code that is really a name
            $r4.RequiredTier = $own                                                # a tier that is really a name
            foreach ($r in @($r1, $r2, $r3, $r4)) {
                $r.Detail = "SENTINEL-DETAIL $own $ownId"
                $r.Reason = "SENTINEL-REASON user@$own"
                $r.ExceptionSummary = "SENTINEL-EXCEPTION $own"
                $r.EvidenceSource = "SENTINEL-EVIDENCE $own"
                $r.Owner = "SENTINEL-OWNER $own"
            }
            return @($r1, $r2, $r3, $r4)
        }
        $script:HostA = & $script:NewResults -Domain $script:DomA -TenantId $script:IdA -Rows (& $mkRows $script:DomA $script:DomB $script:IdA) -ExceptionsPath "C:\NRG\Config\baseline-exceptions\$($script:DomA).psd1"
        $script:HostB = & $script:NewResults -Domain $script:DomB -TenantId $script:IdB -Rows (& $mkRows $script:DomB $script:DomA $script:IdB) -ExceptionsPath "C:\NRG\Config\baseline-exceptions\$($script:DomB).psd1"
        $script:HostA.Metadata.Operator = "sentinel-op@$($script:DomA)"
        $script:Names = @($script:DomA, $script:LabelA, $script:IdA, $script:DomB, $script:LabelB, $script:IdB, 'sentinel-op')
        $script:Sentinels = @('SENTINEL-DETAIL', 'SENTINEL-REASON', 'SENTINEL-EXCEPTION', 'SENTINEL-EVIDENCE', 'SENTINEL-OWNER', 'sentinel-operator', 'sentinel-op@', 'baseline-exceptions', 'C:\NRG')
    }

    It 'with -Anonymize, no tenant name, domain or ID appears in the model, the files or the file names' {
        $c = & $script:Compare $script:HostA $script:HostB -Anon
        $out = & $script:PublishTo $c 'anon'
        $c.Anonymized | Should -BeTrue
        $c.SideA.Name | Should -Be 'Tenant A'
        $c.SideB.Name | Should -Be 'Tenant B'
        $haystacks = @{
            Markdown = $out.Md; Html = $out.Html; Csv = $out.Csv
            Names = ($out.Names -join ' | '); Paths = (@($out.Paths.Markdown, $out.Paths.Html, $out.Paths.Csv | ForEach-Object { Split-Path -Leaf $_ }) -join ' | ')
            Model = ($c | ConvertTo-Json -Depth 10)
        }
        foreach ($k in $haystacks.Keys) {
            foreach ($n in $script:Names) {
                $haystacks[$k].IndexOf($n, [StringComparison]::OrdinalIgnoreCase) | Should -Be -1 -Because "$k must not contain '$n'"
            }
        }
        foreach ($f in $out.Names) { $f | Should -Match '^NRG-BaselineComparison-A-vs-B-\d{8}-\d{6}\.(md|html|csv)$' }
    }

    It 'replaces a whole domain inside a title, not just its first label' {
        # The scrubber must order by identifier length. Ordered by pattern length
        # a domain's first-label pattern wins and leaves ".example" behind: no
        # needle above is the leftover, so the exact result is pinned here.
        $c = & $script:Compare $script:HostA $script:HostB -Anon
        (& $script:One $c 'AAD-1.1').Title | Should -Be 'Legacy auth for [tenant] and [tenant]'
        (& $script:One $c 'EXO-1.1').Title | Should -Be 'Audit [tenant]'
        (& $script:One $c 'AAD-1.2').Title | Should -Match '^MFA tenant \[tenant\] <script>nrgprobe</script>$'
    }

    It 'in either mode, no finding Detail, reason, exception text, evidence source, owner, operator or exceptions path appears' {
        foreach ($anon in @($true, $false)) {
            $c = if ($anon) { & $script:Compare $script:HostA $script:HostB -Anon } else { & $script:Compare $script:HostA $script:HostB }
            $out = & $script:PublishTo $c "detail-$anon"
            $model = $c | ConvertTo-Json -Depth 10
            foreach ($s in $script:Sentinels) {
                foreach ($pair in @(@('Markdown', $out.Md), @('Html', $out.Html), @('Csv', $out.Csv), @('Model', $model))) {
                    $pair[1].IndexOf($s, [StringComparison]::OrdinalIgnoreCase) | Should -Be -1 -Because "$($pair[0]) (anonymized=$anon) must not contain '$s'"
                }
            }
        }
    }

    It 'in the default mode the files name both tenants, and the tenant ID is still never printed' {
        # Benign titles here: the hostile fixture deliberately puts a GUID inside
        # a title, and in the default mode a title is printed as it was given.
        $plain = {
            param([string] $dom, [string] $id)
            & $script:NewResults -Domain $dom -TenantId $id -Rows @(& $script:NewRow 'AAD-1.1' 'Satisfied'; & $script:NewRow 'AAD-1.2' 'Failed') -ExceptionsPath "C:\NRG\Config\baseline-exceptions\$dom.psd1"
        }
        $c = & $script:Compare (& $plain $script:DomA $script:IdA) (& $plain $script:DomB $script:IdB)
        $out = & $script:PublishTo $c 'named'
        $c.Anonymized | Should -BeFalse
        $out.Md | Should -Match ([regex]::Escape($script:DomA))
        $out.Md | Should -Match ([regex]::Escape($script:DomB))
        $out.Html | Should -Match ([regex]::Escape($script:DomA))
        ($out.Names -join ' ') | Should -Match 'hostile-contoso-vs-evilfabrikam'
        $out.Md | Should -Match 'Internal working document'
        foreach ($t in @($out.Md, $out.Html, $out.Csv)) {
            $t.IndexOf($script:IdA, [StringComparison]::OrdinalIgnoreCase) | Should -Be -1
            $t.IndexOf($script:IdB, [StringComparison]::OrdinalIgnoreCase) | Should -Be -1
        }
    }

    It 'a reason code that is not in the module''s catalog is shown as Unrecognized, never as the file''s text' {
        $c = & $script:Compare $script:HostA $script:HostB
        (& $script:One $c 'DEF-1.1').ReasonCodeA | Should -Be 'Unrecognized'
        (& $script:One $c 'DEF-1.1').ReasonCodeB | Should -Be 'Unrecognized'
    }

    It 'carries the standard banner for each mode' {
        $anon = & $script:PublishTo (& $script:Compare $script:HostA $script:HostB -Anon) 'banner-anon'
        $anon.Md | Should -Match 'Anonymized\. The tenants are labeled A and B throughout'
        $named = & $script:PublishTo (& $script:Compare $script:HostA $script:HostB) 'banner-named'
        $named.Md | Should -Match 'Internal working document'
        $named.Md | Should -Not -Match 'Anonymized\. The tenants'
    }

    It 'a tenant domain that is not a plain domain is not printed, in HTML or anywhere' {
        $a = & $script:NewResults -Domain '<img src=x onerror=nrgdomprobe>' -Rows @(& $script:NewRow 'AAD-1.1')
        $b = & $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1')
        $c = & $script:Compare $a $b
        $c.SideA.Name | Should -Be 'Tenant A (domain not recorded)'
        $out = & $script:PublishTo $c 'baddomain'
        foreach ($t in @($out.Md, $out.Html, $out.Csv, ($out.Names -join ' '))) { $t | Should -Not -Match 'nrgdomprobe' }
    }
}

Describe 'Tenant comparison: output formats' {

    BeforeAll {
        $rowsA = @(
            & $script:NewRow 'AAD-1.1' 'Satisfied' -Title '=cmd|''/C calc''!A0'
            & $script:NewRow 'AAD-1.2' 'Failed' -Title 'MFA <script>nrgcmpprobe</script> | pipe `tick` [link](x)'
            & $script:NewRow 'EXO-1.1' 'Satisfied' -Title '+SUM(1)'
            & $script:NewRow 'DEF-1.1' 'LicenseBlocked' -Title '@cmd'
            & $script:NewRow 'DEF-1.2' 'Satisfied' -Tier 'Standard' -Title '-1+1'
        )
        $rowsB = @(
            & $script:NewRow 'AAD-1.1' 'Failed' -Title '=cmd|''/C calc''!A0'
            & $script:NewRow 'AAD-1.2' 'Failed' -Title 'MFA <script>nrgcmpprobe</script> | pipe `tick` [link](x)'
            & $script:NewRow 'EXO-1.1' 'Satisfied' -Title '+SUM(1)'
            & $script:NewRow 'DEF-1.1' 'Satisfied' -Title '@cmd'
        )
        $script:FmtCmp = & $script:Compare (& $script:NewResults -Domain 'a.example' -Tier 'Standard' -Rows $rowsA) (& $script:NewResults -Domain 'b.example' -Tier 'Minimum' -Rows $rowsB)
        $script:Fmt = & $script:PublishTo $script:FmtCmp 'fmt'
    }

    It 'writes a Markdown, an HTML and a CSV file into the output folder, creating it' {
        $script:Fmt.Names.Count | Should -Be 3
        foreach ($ext in 'md', 'html', 'csv') { @($script:Fmt.Names | Where-Object { $_ -like "*.$ext" }).Count | Should -Be 1 }
        $script:Fmt.Names[0] | Should -Match '^NRG-BaselineComparison-a-vs-b-\d{8}-\d{6}\.'
    }

    It 'the HTML is self-contained: no script, no external asset, a strict CSP, print styling' {
        $h = $script:Fmt.Html
        $h | Should -Match '<!DOCTYPE html>'
        $h | Should -Match '</html>'
        $h | Should -Not -Match '<script'
        $h | Should -Not -Match 'src="http'
        $h | Should -Not -Match 'href="http'
        $h | Should -Not -Match '@import'
        $h | Should -Not -Match 'https?://'
        $h | Should -Match 'Content-Security-Policy'
        $h | Should -Match "default-src 'none'"
        $h | Should -Match '@media print'
    }

    It 'escapes hostile text in every format rather than emitting live markup' {
        $script:Fmt.Html | Should -Not -Match '<script>nrgcmpprobe'
        $script:Fmt.Html | Should -Match 'nrgcmpprobe'                    # present, but escaped
        $script:Fmt.Html | Should -Match '&lt;script&gt;nrgcmpprobe'
        $script:Fmt.Md | Should -Not -Match '<script>nrgcmpprobe'
        $script:Fmt.Md | Should -Match '&lt;script&gt;nrgcmpprobe'
        # A pipe in a title must not break the table row it sits in.
        $line = @($script:Fmt.Md -split "`n" | Where-Object { $_ -match 'AAD-1\.2' -and $_ -match 'nrgcmpprobe' })[0]
        $line | Should -Match '\\\|'
        $line | Should -Match '\\\[link\\\]'
    }

    It 'the CSV neutralizes formula-looking cells and parses back to one row per control' {
        $rows = @($script:Fmt.Csv | ConvertFrom-Csv)
        $rows.Count | Should -Be ($script:FmtCmp.Counts.Compared + $script:FmtCmp.Counts.NotCompared)
        @($rows | Where-Object { $_.Section -eq 'Compared' }).Count | Should -Be 4
        @($rows | Where-Object { $_.Section -eq 'NotCompared' }).Count | Should -Be 1
        foreach ($r in $rows) { $r.Title | Should -Not -Match '^[=+\-@]' }
        @($rows | Where-Object { $_.ControlId -eq 'AAD-1.1' })[0].Title | Should -Match '^''=cmd'
        @($rows | Where-Object { $_.ControlId -eq 'DEF-1.2' })[0].Title | Should -Match '^''-1\+1'
        @($rows | Where-Object { $_.ControlId -eq 'AAD-1.1' })[0].Classification | Should -Be 'DiffersASatisfied'
        @($rows | Where-Object { $_.ControlId -eq 'DEF-1.1' })[0].Classification | Should -Be 'NotComparable'
        @($rows | Where-Object { $_.ControlId -eq 'DEF-1.2' })[0].Classification | Should -Be 'RequiredOnlyAtA'
        ($script:Fmt.Csv -split "`r?`n")[0] | Should -Be '"Section","ControlId","Title","Classification","RequiredTierA","RequiredTierB","StateA","ReasonCodeA","DispositionA","StateB","ReasonCodeB","DispositionB"'
    }

    It 'the Markdown and HTML list the same controls under the same headings' {
        foreach ($h in 'Controls that differ', 'Failed at both tenants', 'Satisfied at both tenants', 'Not comparable', 'Not compared', 'Reason codes used', 'How to read this') {
            $script:Fmt.Md | Should -Match "## $h"
            $script:Fmt.Html | Should -Match "<h2>$h</h2>"
        }
        foreach ($id in 'AAD-1.1', 'AAD-1.2', 'EXO-1.1', 'DEF-1.1', 'DEF-1.2') {
            $script:Fmt.Md | Should -Match $id
            $script:Fmt.Html | Should -Match $id
        }
    }

    It 'explains every reason code it uses, from the module''s own catalog' {
        $script:FmtCmp.ReasonCodes | ForEach-Object { $_.Code } | Should -Contain 'LicenseBlocked'
        foreach ($l in $script:FmtCmp.ReasonCodes) { $l.Meaning | Should -Be ((Get-NRGBaselineReasonCodes)[$l.Code].Meaning) }
        $script:Fmt.Md | Should -Match 'Reason codes used'
    }

    It 'leaks no object-stringification artifact' {
        foreach ($t in @($script:Fmt.Md, $script:Fmt.Html, $script:Fmt.Csv)) {
            foreach ($leak in 'System\.Collections\.Hashtable', 'System\.Object\[\]', 'System\.Collections\.Generic', 'System\.Collections\.Specialized', 'OrderedDictionary', 'PSCustomObject') {
                $t | Should -Not -Match $leak
            }
        }
    }

    It 'rejects a traversal output path and a file where the folder should be' {
        { Publish-NRGBaselineTenantComparison -Comparison $script:FmtCmp -OutputPath '../../evil' } | Should -Throw
        $file = Join-Path $script:Tmp 'a-file.txt'
        Set-Content -LiteralPath $file -Value 'x'
        { Publish-NRGBaselineTenantComparison -Comparison $script:FmtCmp -OutputPath $file } | Should -Throw '*is a file, not a folder*'
    }

    It 'an output folder name with wildcard characters works' {
        $dir = Join-Path $script:Tmp 'odd [name]'
        $p = Publish-NRGBaselineTenantComparison -Comparison $script:FmtCmp -OutputPath $dir
        Test-Path -LiteralPath $p.Markdown | Should -BeTrue
    }
}

Describe 'Tenant comparison: older results replay' {

    It 'compares two files that predate every field added since the baseline first shipped' {
        # Rows carry only ControlId and ObservedState; no ReasonCode, Constraint,
        # Disposition, freshness, timestamp, tier, title or expected state; no
        # coverage, AsOf, tenant ID, metadata, connections or raw data at all.
        $old = {
            param($state)
            [pscustomobject]@{ ControlId = 'AAD-1.1'; ObservedState = $state }, [pscustomobject]@{ ControlId = 'AAD-1.2'; ObservedState = 'Failed' }
        }
        $a = & $script:NewOldResults -Tier 'Minimum' -Version '1.0' -Rows (& $old 'Satisfied')
        $b = & $script:NewOldResults -Tier 'Minimum' -Version '1.0' -Rows (& $old 'Failed')
        $c = { & $script:Compare $a $b }
        $c | Should -Not -Throw
        $r = & $c
        $r.Available | Should -BeTrue
        (& $script:One $r 'AAD-1.1').Classification | Should -Be 'DiffersASatisfied'
        (& $script:One $r 'AAD-1.2').Classification | Should -Be 'BothFailed'
        (& $script:One $r 'AAD-1.1').ReasonCodeA | Should -Be 'NotRecorded'
        $r.SideA.Name | Should -Be 'Tenant A (domain not recorded)'
        $r.SideA.RunDate | Should -Be ''
        $r.SideA.Freshness.NotRecorded | Should -Be 2
        $r.SideA.License.Read | Should -BeFalse
        { & $script:PublishTo $r 'replay' } | Should -Not -Throw
    }

    It 'a LicenseBlocked row recorded only in its display status is still not comparable' {
        $row = [pscustomobject]@{ ControlId = 'AAD-1.1'; ObservedState = 'NotApplicable'; BaselineStatus = 'LicenseBlocked' }
        $a = & $script:NewOldResults -Rows @($row)
        $b = & $script:NewOldResults -Rows @([pscustomobject]@{ ControlId = 'AAD-1.1'; ObservedState = 'Satisfied' })
        (& $script:One (& $script:Compare $a $b) 'AAD-1.1').StateA | Should -Be 'LicenseBlocked'
    }

    It 'a metadata block that is not an object is ignored, not trusted' {
        $a = & $script:NewResults -Domain 'a.example' -Rows @(& $script:NewRow 'AAD-1.1')
        $a.Metadata = 'a string where an object should be'
        $a.Connections = 42
        { & $script:Compare $a (& $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1')) } | Should -Not -Throw
    }

    It 'every read of an input object goes through Get-NRGObjectField or Get-NRGNestedProperty' {
        # An API (or an older file) omits optional properties rather than nulling
        # them, and StrictMode throws on a missing one. The library may not
        # dot-access any variable that holds the input.
        $src = & $script:CodeOf (Join-Path $script:RepoRoot 'Lib/Get-NRGBaselineTenantComparison.ps1')
        $src.Errors | Should -Be 0
        $rawVars = @('Results', 'ResultsA', 'ResultsB', 'Row', 'rawRow', 'bc', 'meta', 'conn', 'inventory', 'Block', 'licProfile', 'gapsRaw', 'res', 'm', 'o')
        $bad = @($src.Ast.FindAll({
            param($n)
            $n -is [System.Management.Automation.Language.MemberExpressionAst] -and
            $n.Expression -is [System.Management.Automation.Language.VariableExpressionAst] -and
            $n.Expression.VariablePath.UserPath -in $rawVars -and
            $n.Member.Extent.Text -notin @('Keys', 'PSObject', 'Contains', 'Count', 'Length')
        }, $true) | ForEach-Object { $_.Extent.Text })
        $bad | Should -BeNullOrEmpty -Because "direct access on input data: $($bad -join '; ')"
    }
}

Describe 'Tenant comparison: it is a view that connects to nothing' {

    It 'adds no finding, changes no raw data, and moves no coverage when it runs' {
        Clear-NRGState
        Add-NRGFinding -ControlId 'AAD-1.1' -State 'Gap' -Category 'Identity' -Title 'x' -Severity 'High' -Detail 'live finding'
        Set-NRGRawData -Key 'AAD-Inventory' -Data @{ Success = $true; Data = @{ marker = 'live' } }
        $before = @{ F = @(Get-NRGFindings).Count; K = (@((Get-NRGRawData).Keys) -join ','); C = @((Get-NRGCoverage).Keys).Count }
        $c = & $script:Compare (& $script:NewResults -Domain 'a.example' -Rows @(& $script:NewRow 'AAD-1.1')) (& $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1'))
        $null = & $script:PublishTo $c 'view'
        @(Get-NRGFindings).Count | Should -Be $before.F
        (@((Get-NRGRawData).Keys) -join ',') | Should -Be $before.K
        @((Get-NRGCoverage).Keys).Count | Should -Be $before.C
        # ...and the live module state never leaks into the comparison.
        (& $script:One $c 'AAD-1.1').Classification | Should -Be 'BothSatisfied'
        Clear-NRGState
    }

    It 'makes no network or tenant call when it runs' {
        Mock -ModuleName 'NRG-Assessment' Invoke-RestMethod -MockWith { throw 'network call from the comparison' }
        Mock -ModuleName 'NRG-Assessment' Invoke-WebRequest -MockWith { throw 'network call from the comparison' }
        Mock -ModuleName 'NRG-Assessment' Invoke-NRGGraphRequest -MockWith { throw 'Graph call from the comparison' }
        Mock -ModuleName 'NRG-Assessment' Resolve-NRGDns -MockWith { throw 'DNS lookup from the comparison' }
        Mock -ModuleName 'NRG-Assessment' Connect-NRGServices -MockWith { throw 'sign-in from the comparison' }
        Mock -ModuleName 'NRG-Assessment' Start-Process -MockWith { throw 'process from the comparison' }
        $bp = @{ Skus = @(@{ SkuPartNumber = 'SPB'; ServicePlans = @('AAD_PREMIUM') }) }
        $c = & $script:Compare (& $script:NewResults -Domain 'a.example' -Rows @(& $script:NewRow 'AAD-1.1') -Skus $bp) (& $script:NewResults -Domain 'b.example' -Rows @(& $script:NewRow 'AAD-1.1'))
        $null = & $script:PublishTo $c 'nonet'
        foreach ($cmd in 'Invoke-RestMethod', 'Invoke-WebRequest', 'Invoke-NRGGraphRequest', 'Resolve-NRGDns', 'Connect-NRGServices', 'Start-Process') {
            Should -Invoke -ModuleName 'NRG-Assessment' -CommandName $cmd -Times 0 -Exactly
        }
    }

    It '<File> makes no tenant, device, network or module-state call' -ForEach @(
        @{ File = 'Lib/Get-NRGBaselineTenantComparison.ps1' }
        @{ File = 'Publishers/Publish-NRGBaselineTenantComparison.ps1' }
        @{ File = 'Compare-NRGTenantBaseline.ps1' }
    ) {
        # Static, over code only (comments may name what the file refuses to do).
        $src = & $script:CodeOf (Join-Path $script:RepoRoot $File)
        $src.Errors | Should -Be 0
        $forbiddenCommands = '^Connect-', '^Disconnect-', '^Invoke-(RestMethod|WebRequest|NRGGraphRequest|NRGGraphAllPages|Expression|Command)$',
            '^Resolve-(NRGDns|DnsName|NRGTenantId)$', '^Test-(Connection|NetConnection)$', '^Start-(Process|Job|ThreadJob)$',
            '^Get-Mg', '^Get-(Mailbox|CsTenant|OrganizationConfig)', '^Send-MailMessage$',
            '^(Get|Set)-NRG(RawData|Findings|Coverage)$', '^Add-NRGFinding$', '^Register-NRG(Coverage|Exception)$', '^Clear-NRGState$',
            '^Get-NRGBaselineCompliance$', '^Get-NRGBaselineRegressions$', '^Publish-NRGDeltaReport$', '^Get-NRGAssessmentScope$'
        foreach ($cmd in $src.Commands) {
            foreach ($f in $forbiddenCommands) { $cmd | Should -Not -Match $f -Because "$File must not call $cmd" }
        }
        foreach ($t in 'System\.Net\.Http', 'HttpClient', 'WebClient', 'System\.Net\.Sockets', 'Net\.WebRequest', 'graph\.microsoft', 'login\.microsoftonline', 'outlook\.office', 'https?://') {
            $src.Code | Should -Not -Match $t -Because "$File must not reference $t"
        }
    }

    It 'the run-over-run guard is untouched: a delta against another tenant''s baseline is still refused' {
        $baseline = Join-Path $script:Tmp 'other-tenant.json'
        @{ Metadata = @{ TenantId = 'aaaaaaaa-0000-0000-0000-000000000001' }; Findings = @() } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $baseline -Encoding utf8
        { Publish-NRGDeltaReport -CurrentFindings @([pscustomobject]@{ ControlId = 'AAD-1.1'; State = 'Gap' }) -BaselineResultsPath $baseline -Metadata @{ TenantId = 'bbbbbbbb-0000-0000-0000-000000000002' } -OutputPath (Join-Path $script:Tmp 'delta.md') } |
            Should -Throw '*Refusing to generate delta report*'
        $guard = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Publishers/Publish-NRGDeltaReport.ps1') -Raw
        $guard | Should -Match 'does not match current tenant ID'
        # And the comparison does not borrow the delta or regression machinery to dodge it.
        foreach ($f in 'Lib/Get-NRGBaselineTenantComparison.ps1', 'Publishers/Publish-NRGBaselineTenantComparison.ps1', 'Compare-NRGTenantBaseline.ps1') {
            (& $script:CodeOf (Join-Path $script:RepoRoot $f)).Code | Should -Not -Match 'BaselineResultsPath|Publish-NRGDeltaReport|Get-NRGBaselineRegressions'
        }
    }

    It 'the two public functions are exported and listed in both export lists' {
        foreach ($fn in 'Get-NRGBaselineTenantComparison', 'Publish-NRGBaselineTenantComparison') {
            (Get-Command $fn -Module 'NRG-Assessment' -ErrorAction SilentlyContinue) | Should -Not -BeNullOrEmpty
            @((Import-PowerShellDataFile (Join-Path $script:RepoRoot 'NRG-Assessment.psd1')).FunctionsToExport) | Should -Contain $fn
            (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Raw) | Should -Match "'$fn'"
        }
    }
}

Describe 'Tenant comparison: the entry point' {

    BeforeAll {
        $script:Pwsh = (Get-Process -Id $PID).Path
        $script:Script = Join-Path $script:RepoRoot 'Compare-NRGTenantBaseline.ps1'
        $script:Run = {
            param([string[]] $Arguments)
            $text = & $script:Pwsh -NoProfile -File $script:Script @Arguments *>&1 | Out-String
            [pscustomobject]@{ Code = $LASTEXITCODE; Text = $text }
        }
        $write = { param($o, $name) $p = Join-Path $script:Tmp $name; $o | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $p -Encoding utf8; $p }
        $rowsA = @(& $script:NewRow 'AAD-1.1' 'Satisfied'; & $script:NewRow 'AAD-1.2' 'Failed'; & $script:NewRow 'DEF-1.1' 'Satisfied' -Tier 'Standard')
        $rowsB = @(& $script:NewRow 'AAD-1.1' 'Failed'; & $script:NewRow 'AAD-1.2' 'Failed')
        $script:FileA = & $write (& $script:NewResults -Domain 'entry-alpha.example' -TenantId 'aaaaaaaa-9999-0000-0000-000000000001' -Tier 'Standard' -Rows $rowsA) 'entry-a.json'
        $script:FileB = & $write (& $script:NewResults -Domain 'entry-bravo.example' -TenantId 'bbbbbbbb-9999-0000-0000-000000000002' -Tier 'Minimum' -Rows $rowsB) 'entry-b.json'
        $script:FileNone = & $write ([pscustomobject]@{ Metadata = @{ TenantDomain = 'entry-none.example' }; Findings = @() }) 'entry-none.json'
        $script:FileBad = Join-Path $script:Tmp 'entry-bad.json'
        Set-Content -LiteralPath $script:FileBad -Value '{ this is not json' -Encoding utf8
    }

    It 'writes the three files, prints the headline, and exits 0' {
        $out = Join-Path $script:Tmp 'entry-out'
        $r = & $script:Run @('-ResultsA', $script:FileA, '-ResultsB', $script:FileB, '-OutputPath', $out)
        $r.Code | Should -Be 0
        @(Get-ChildItem -LiteralPath $out).Count | Should -Be 3
        $r.Text | Should -Match 'Same baseline posture on 1 of 2 controls that both tenants verified'
        $r.Text | Should -Match 'entry-alpha\.example'
        $r.Text | Should -Match 'This script connected to nothing'
    }

    It 'with -Anonymize, neither the console nor the files nor their names carry a tenant name' {
        $out = Join-Path $script:Tmp 'entry-anon'
        $r = & $script:Run @('-ResultsA', $script:FileA, '-ResultsB', $script:FileB, '-OutputPath', $out, '-Anonymize')
        $r.Code | Should -Be 0
        $all = $r.Text + ((Get-ChildItem -LiteralPath $out | ForEach-Object { $_.Name + (Get-Content -LiteralPath $_.FullName -Raw) }) -join "`n")
        foreach ($n in 'entry-alpha', 'entry-bravo', 'aaaaaaaa-9999', 'bbbbbbbb-9999') { $all.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) | Should -Be -1 -Because "anonymized run must not print '$n'" }
        $r.Text | Should -Match 'Tenant A'
        @(Get-ChildItem -LiteralPath $out | ForEach-Object { $_.Name }) | ForEach-Object { $_ | Should -Match '^NRG-BaselineComparison-A-vs-B-' }
    }

    It 'exits 2 and writes nothing when a file carries no baseline controls' {
        $out = Join-Path $script:Tmp 'entry-none-out'
        $r = & $script:Run @('-ResultsA', $script:FileNone, '-ResultsB', $script:FileB, '-OutputPath', $out)
        $r.Code | Should -Be 2
        $r.Text | Should -Match 'Results A carry no NRG Security Baseline controls'
        Test-Path -LiteralPath $out | Should -BeFalse
    }

    It 'exits 4 on an unreadable file, naming the parameter and not the path' {
        $out = Join-Path $script:Tmp 'entry-bad-out'
        $r = & $script:Run @('-ResultsA', $script:FileBad, '-ResultsB', $script:FileB, '-OutputPath', $out)
        $r.Code | Should -Be 4
        $r.Text | Should -Match '-ResultsA could not be read as JSON'
        $r.Text | Should -Not -Match 'entry-bad'
    }

    It 'declares the parameters the owner specified, and nothing that signs in' {
        $params = (Get-Command $script:Script).Parameters
        foreach ($p in 'ResultsA', 'ResultsB', 'OutputPath', 'Anonymize') { $params.ContainsKey($p) | Should -BeTrue }
        $params['ResultsA'].Attributes.Where({ $_ -is [System.Management.Automation.ParameterAttribute] }).Mandatory | Should -BeTrue
        $params['Anonymize'].ParameterType | Should -Be ([switch])
        @($params.Keys | Where-Object { $_ -match 'Tenant(Domain|Id)$|Credential|Certificate|AppId|UserPrincipalName|Connect' }) | Should -BeNullOrEmpty
    }

    It 'is documented where an operator will look' {
        (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'README.md') -Raw) | Should -Match 'Compare-NRGTenantBaseline\.ps1'
        (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'CHANGELOG.md') -Raw) | Should -Match 'Compare-NRGTenantBaseline'
        (Get-Content -LiteralPath (Join-Path $script:RepoRoot 'CLAUDE.md') -Raw) | Should -Match 'Compare-NRGTenantBaseline'
    }
}
