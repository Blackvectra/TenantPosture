#Requires -Version 7.0
#
# TP.MspFixtures.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Fixture builders shared by TP.FleetDashboard, TP.RemediationProof
#   and TP.OnboardingReport (dot-sourced; not a suite). They write results
#   files in the shape Invoke-TPAssessment.ps1 writes them: Metadata
#   (TenantDomain, TenantId, AssessmentTime as ISO 8601, ToolVersion, Maturity,
#   ControlSelection, QuickScan), Findings and BaselineCompliance, serialized
#   with ConvertTo-Json and read back by the code under test. Every tenant is
#   fictional (contoso / fabrikam / northwind / adatum .example).
# Data keys consumed / set: none. Graph scopes / cmdlets used: none.

function New-TPMspFixtureResults {
    [CmdletBinding()]
    param(
        [string] $Domain = 'contoso.example',
        [AllowEmptyString()] [string] $TenantId = 'aaaaaaaa-1111-4111-8111-000000000001',
        [Parameter(Mandatory)] [datetime] $Time,
        # Each finding: @('AAD-1.1', 'Gap', 'High') or a hashtable with
        # ControlId, State, Severity and optionally Title, CurrentValue, Detail.
        [object[]] $Findings = @(),
        [AllowNull()] [object] $Score = 70,
        [string] $Label = 'Defined',
        [string] $ToolVersion = '4.14.3',
        [AllowNull()] [string[]] $SelectedControlIds = $null,
        [string[]] $Include = @(),
        [switch] $Quick,
        [switch] $NoMaturity,
        [switch] $NoBaseline,
        # Each row: @('AAD-1.1', 'Satisfied') or @('AAD-1.1', 'Failed', 'Standard', 'Weekly')
        [object[]] $BaselineRows = @(),
        [string] $BaselineVersion = '2.0',
        [string] $TargetTier = 'Standard',
        [int] $EvidencePercent = 80,
        [string] $Operator = 'operator@msp.example'
    )
    $fl = foreach ($f in $Findings) {
        if ($f -is [System.Collections.IDictionary]) {
            [ordered]@{ ControlId = $f.ControlId; State = $f.State; Severity = $f.Severity; Category = 'Fixture'
                Title = $(if ($f.Contains('Title')) { $f.Title } else { "Fixture $($f.ControlId)" })
                CurrentValue = $(if ($f.Contains('CurrentValue')) { $f.CurrentValue } else { "$($f.State) value" })
                RequiredValue = 'Required'; Detail = $(if ($f.Contains('Detail')) { $f.Detail } else { "Detail for $($f.ControlId) (alice@$Domain)" }) }
        } else {
            [ordered]@{ ControlId = $f[0]; State = $f[1]; Severity = $f[2]; Category = 'Fixture'; Title = "Fixture $($f[0])"
                CurrentValue = "$($f[1]) value"; RequiredValue = 'Required'; Detail = "Detail for $($f[0]) (alice@$Domain)" }
        }
    }
    $meta = [ordered]@{
        TenantDomain   = $Domain
        TenantId       = $TenantId
        Operator       = $Operator
        AssessmentDate = $Time.ToString('MMMM dd, yyyy', [cultureinfo]::InvariantCulture)
        AssessmentTime = $Time.ToUniversalTime().ToString('o', [cultureinfo]::InvariantCulture)
        ToolVersion    = $ToolVersion
        QuickScan      = [bool]$Quick
    }
    if (-not $NoMaturity) {
        $meta['Maturity'] = [ordered]@{ Tier = 3; Label = $Label; ObservedLabel = ($Label -replace ' \(.*\z', ''); Score = $Score; EvidenceComplete = ($Label -notmatch 'provisional') }
    }
    if ($null -ne $SelectedControlIds) {
        $meta['ControlSelection'] = [ordered]@{ Include = @($Include); Exclude = @(); SelectedCount = @($SelectedControlIds).Count; TotalControls = 253; Partial = $true; SelectedControlIds = @($SelectedControlIds) }
    }
    $obj = [ordered]@{
        Metadata   = $meta
        Findings   = @($fl)
        RawData    = [ordered]@{ 'AAD-Inventory' = [ordered]@{ Success = $true; Data = [ordered]@{ Secret = "rawdata-marker-$Domain" } } }
        Exceptions = @(@{ Source = 'x'; Message = "exception-marker-$Domain" })
    }
    if (-not $NoBaseline) {
        $rows = foreach ($r in $BaselineRows) {
            $status = [string]$r[1]
            $obs = switch ($status) { 'Satisfied' { 'Satisfied' } 'Failed' { 'Failed' } 'ApprovedException' { 'Failed' } default { 'NotVerified' } }
            $code = switch ($status) { 'Satisfied' { 'Satisfied' } 'Failed' { 'ControlFailed' } default { 'EvidenceNotRead' } }
            [ordered]@{
                ControlId = [string]$r[0]; Title = "Fixture $($r[0])"; RequiredTier = $(if ($r.Count -gt 2) { [string]$r[2] } else { 'Minimum' })
                BaselineStatus = $status; ObservedState = $obs; ReasonCode = $code; NotVerifiedCause = ''
                FreshnessClass = $(if ($r.Count -gt 3) { [string]$r[3] } else { 'Weekly' }); ExpectedState = 'Expected'; Owner = 'Identity'; SlaClass = 'High'; Reason = ''
            }
        }
        $obj['BaselineCompliance'] = [ordered]@{
            Available = $true; BaselineVersion = $BaselineVersion; TargetTier = $TargetTier
            EvidenceCoverage = [ordered]@{ Percent = $EvidencePercent; Known = $EvidencePercent; Applicable = 100 }
            Controls = @($rows)
        }
    }
    return $obj
}

function Write-TPMspFixture {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [object] $Object, [Parameter(Mandatory)] [string] $Path)
    $dir = Split-Path -Parent $Path
    if ($dir) { $null = [System.IO.Directory]::CreateDirectory($dir) }
    $Object | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $Path -Encoding utf8
    return $Path
}
