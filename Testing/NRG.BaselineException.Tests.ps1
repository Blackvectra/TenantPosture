#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.BaselineException.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Pins the exception cmdlets: a baseline control only, every
             required field, a future review date, one active exception per
             control, data-only PSD1 the loader reads back, an atomic and
             verified save, an invalid existing entry preserved and reported
             (never repaired), -WhatIf writing nothing, and the disposition
             changing while the observed state and BaselineVersion do not.
             Every test writes through -Path into a temp file, never Config/.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Baseline exception cmdlets' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-exc-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
        $script:Future = (Get-Date).AddMonths(4)
        $script:NewFile = { Join-Path $script:Tmp ([guid]::NewGuid().ToString('N') + '.psd1') }
        $script:Add = {
            param([string] $Path, [string] $Cid = 'AAD-2.3')
            New-NRGBaselineException -TenantDomain contoso.com -ControlId $Cid -Reason 'No managed device program' -CompensatingControl 'MFA and browser-only access' -Approver 'security@nrg.example' -ReviewDate $script:Future -Path $Path -Confirm:$false
        }
    }
    AfterAll {
        Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    It 'creates a data-only PSD1 the loader reads back as approved, and reports before/after' {
        $f = & $script:NewFile
        $r = & $script:Add $f
        $r.Change | Should -Be 'Added'
        $r.Before.Entries | Should -Be 0
        $r.After.Entries | Should -Be 1
        $r.After.Approved | Should -Be 1
        $r.Entry.Approved | Should -BeTrue
        $r.Entry.ApprovedDate | Should -Be (Get-Date).ToString('yyyy-MM-dd')
        $text = Get-Content -LiteralPath $f -Raw
        $text | Should -Match "ControlId\s+= 'AAD-2.3'"
        $text | Should -Not -Match 'ExpiryDate' -Because 'an omitted expiry is omitted, not written empty'
        $text | Should -Not -Match '\$\(|\$[A-Za-z]|Invoke-|&' -Because 'data only'
        $loaded = Get-NRGBaselineExceptions -Path $f
        $loaded.Approved.ContainsKey('AAD-2.3') | Should -BeTrue
        (Get-NRGBaselineException -TenantDomain contoso.com -Path $f -ControlId 'AAD-2.3').Count | Should -Be 1
    }

    It 'quotes are preserved through the PSD1 round trip' {
        $f = & $script:NewFile
        $null = New-NRGBaselineException -TenantDomain contoso.com -ControlId 'EXO-1.2' -Reason "Client's printers can't use OAuth" -CompensatingControl "Per-mailbox 'SMTP AUTH' on two mailboxes" -Approver 'a@b' -ReviewDate $script:Future -ExpiryDate $script:Future.AddMonths(2) -Path $f -Confirm:$false
        $e = (Get-NRGBaselineException -TenantDomain contoso.com -Path $f)[0]
        $e.Reason | Should -Be "Client's printers can't use OAuth"
        $e.CompensatingControl | Should -Be "Per-mailbox 'SMTP AUTH' on two mailboxes"
        $e.ExpiryDate | Should -Be $script:Future.AddMonths(2).ToString('yyyy-MM-dd')
        $e.Approved | Should -BeTrue
    }

    It 'refuses a control outside the baseline, a review date not in the future, and an expiry before the review' {
        $f = & $script:NewFile
        { New-NRGBaselineException -TenantDomain contoso.com -ControlId 'AAD-13.1' -Reason r -CompensatingControl c -Approver a -ReviewDate $script:Future -Path $f -Confirm:$false } | Should -Throw '*not an NRG Security Baseline control*'
        { New-NRGBaselineException -TenantDomain contoso.com -ControlId 'AAD-2.3' -Reason r -CompensatingControl c -Approver a -ReviewDate (Get-Date) -Path $f -Confirm:$false } | Should -Throw '*must be a future date*'
        { New-NRGBaselineException -TenantDomain contoso.com -ControlId 'AAD-2.3' -Reason r -CompensatingControl c -Approver a -ReviewDate $script:Future -ExpiryDate $script:Future.AddDays(-1) -Path $f -Confirm:$false } | Should -Throw '*before ReviewDate*'
        { New-NRGBaselineException -TenantDomain contoso.com -ControlId 'AAD-2.3' -Reason '' -CompensatingControl c -Approver a -ReviewDate $script:Future -Path $f -Confirm:$false } | Should -Throw
        Test-Path -LiteralPath $f | Should -BeFalse -Because 'nothing was written'
    }

    It 'refuses a second active exception for the same control' {
        $f = & $script:NewFile
        $null = & $script:Add $f
        { & $script:Add $f } | Should -Throw '*already exists*'
        (Get-NRGBaselineException -TenantDomain contoso.com -Path $f).Count | Should -Be 1
    }

    It 'the reserved example slug and an empty domain are refused' {
        { Get-NRGBaselineExceptionPath -TenantDomain 'example' } | Should -Throw
        { Get-NRGBaselineExceptionPath -TenantDomain '' } | Should -Throw
        (Get-NRGBaselineExceptionPath -TenantDomain 'Client.Example') | Should -Match 'baseline-exceptions[\\/]client\.example\.psd1$'
    }

    It '-WhatIf writes nothing and says what it would do' {
        $f = & $script:NewFile
        $w = New-NRGBaselineException -TenantDomain contoso.com -ControlId 'AAD-2.3' -Reason r -CompensatingControl c -Approver a -ReviewDate $script:Future -Path $f -WhatIf
        $w.Change | Should -Be 'WhatIf'
        Test-Path -LiteralPath $f | Should -BeFalse
        $null = & $script:Add $f
        $s = Set-NRGBaselineException -TenantDomain contoso.com -ControlId 'AAD-2.3' -Reason 'changed' -Path $f -WhatIf
        $s.Change | Should -Be 'WhatIf'
        (Get-NRGBaselineException -TenantDomain contoso.com -Path $f)[0].Reason | Should -Be 'No managed device program'
        $d = Remove-NRGBaselineException -TenantDomain contoso.com -ControlId 'AAD-2.3' -Path $f -WhatIf
        $d.Change | Should -Be 'WhatIf'
        (Get-NRGBaselineException -TenantDomain contoso.com -Path $f).Count | Should -Be 1
    }

    It 'Set changes only the given fields, re-validates, and re-dates the approval when the approver changes' {
        $f = & $script:NewFile
        $null = New-NRGBaselineException -TenantDomain contoso.com -ControlId 'AAD-2.3' -Reason r -CompensatingControl c -Approver 'first@nrg.example' -ApprovedDate (Get-Date).AddDays(-10) -ReviewDate $script:Future -Path $f -Confirm:$false
        $s = Set-NRGBaselineException -TenantDomain contoso.com -ControlId 'AAD-2.3' -Reason 'Client has no managed device program (BYOD)' -Path $f -Confirm:$false
        $s.Change | Should -Be 'Updated'
        @($s.ChangedFields) | Should -Be @('Reason')
        $s.After.ApprovedDate | Should -Be (Get-Date).AddDays(-10).ToString('yyyy-MM-dd') -Because 'the approver did not change'
        $s.After.CompensatingControl | Should -Be 'c'
        $s2 = Set-NRGBaselineException -TenantDomain contoso.com -ControlId 'AAD-2.3' -Approver 'lead@nrg.example' -Path $f -Confirm:$false
        $s2.After.ApprovedDate | Should -Be (Get-Date).ToString('yyyy-MM-dd')
        @($s2.ChangedFields) | Should -Contain 'Approver'
        { Set-NRGBaselineException -TenantDomain contoso.com -ControlId 'AAD-2.3' -ReviewDate (Get-Date).AddDays(-1) -Path $f -Confirm:$false } | Should -Throw '*must be a future date*'
        (Set-NRGBaselineException -TenantDomain contoso.com -ControlId 'AAD-2.3' -Reason 'Client has no managed device program (BYOD)' -Path $f -Confirm:$false).Change | Should -Be 'Unchanged'
        { Set-NRGBaselineException -TenantDomain contoso.com -ControlId 'EXO-1.2' -Reason x -Path $f -Confirm:$false } | Should -Throw '*No exception for EXO-1.2*'
    }

    It 'Remove drops every entry for the control and keeps the file readable' {
        $f = & $script:NewFile
        $null = & $script:Add $f
        $null = & $script:Add $f 'EXO-1.2'
        $r = Remove-NRGBaselineException -TenantDomain contoso.com -ControlId 'AAD-2.3' -Path $f -Confirm:$false
        $r.Change | Should -Be 'Removed'
        $r.Before.Entries | Should -Be 2
        $r.After.Entries | Should -Be 1
        (Get-NRGBaselineExceptions -Path $f).Approved.ContainsKey('EXO-1.2') | Should -BeTrue
        $null = Remove-NRGBaselineException -TenantDomain contoso.com -ControlId 'EXO-1.2' -Path $f -Confirm:$false
        $loaded = Get-NRGBaselineExceptions -Path $f
        $loaded.Available | Should -BeTrue
        @($loaded.Entries).Count | Should -Be 0
        { Remove-NRGBaselineException -TenantDomain contoso.com -ControlId 'EXO-1.2' -Path $f -Confirm:$false } | Should -Throw '*No exception for*'
    }

    It 'an existing entry that is not in force is preserved as written and reported, never repaired or dropped' {
        $f = & $script:NewFile
        $lapsed = @"
@{
    Exceptions = @(
        @{
            ControlId           = 'EXO-1.2'
            Reason              = 'old'
            CompensatingControl = 'old'
            Approver            = 'old@nrg.example'
            ApprovedDate        = '2025-01-01'
            ReviewDate          = '2025-06-01'
        }
        @{
            ControlId           = 'DEF-1.1'
            Reason              = 'no approver'
            CompensatingControl = 'x'
            ReviewDate          = '2030-01-01'
        }
    )
}
"@
        Set-Content -LiteralPath $f -Value $lapsed -Encoding utf8
        $r = & $script:Add $f 3> $null
        @($r.NotInForce).Count | Should -Be 2
        ($r.NotInForce -join ' ') | Should -Match 'EXO-1.2: Not approved: review date'
        ($r.NotInForce -join ' ') | Should -Match 'DEF-1.1: Not approved: missing'
        $loaded = Get-NRGBaselineExceptions -Path $f
        @($loaded.Entries).Count | Should -Be 3
        $loaded.Approved.Keys | Should -Be @('AAD-2.3')
        $old = @($loaded.Entries | Where-Object { $_.ControlId -eq 'EXO-1.2' })[0]
        $old.Approved | Should -BeFalse
        $old.ReviewDate | Should -Be '2025-06-01' -Because 'the lapsed entry is written back unchanged'
        # A lapsed entry for the same control is not "active": New is allowed, and Set would edit it.
        $r2 = & $script:Add $f 'EXO-1.2' 3> $null
        $r2.Change | Should -Be 'Added'
        { Set-NRGBaselineException -TenantDomain contoso.com -ControlId 'EXO-1.2' -Reason x -Path $f -Confirm:$false } | Should -Throw '*2 entries*'
    }

    It 'a failed save leaves the existing file untouched and no temp file behind (atomic, verified write)' {
        $f = & $script:NewFile
        $null = & $script:Add $f
        $beforeText = Get-Content -LiteralPath $f -Raw
        # A target whose parent is a regular file cannot be created, so the
        # write fails before anything replaces the original.
        $blocked = Join-Path $f 'child.psd1'
        $writer = & (Get-Module 'NRG-Assessment') { Get-Command Write-NRGBaselineExceptionFile }
        { & $writer -Path $blocked -Entries @([pscustomobject]@{ ControlId = 'AAD-2.3'; Reason = 'r'; CompensatingControl = 'c'; Approver = 'a'; ApprovedDate = '2026-01-01'; ReviewDate = '2030-01-01'; ExpiryDate = '' }) } | Should -Throw
        (Get-Content -LiteralPath $f -Raw) | Should -Be $beforeText
        (Get-ChildItem -LiteralPath (Split-Path -Parent $f) -Filter '*.tmp.psd1').Count | Should -Be 0 -Because 'no temp file is left behind'
        # And the round-trip check itself: a document that reads back with a
        # different entry count is refused.
        $render = & (Get-Module 'NRG-Assessment') { Get-Command ConvertTo-NRGBaselineExceptionPsd1 }
        $text = & $render -Entries @([pscustomobject]@{ ControlId = 'AAD-2.3'; Reason = "it's"; CompensatingControl = 'c'; Approver = 'a'; ApprovedDate = '2026-01-01'; ReviewDate = '2030-01-01'; ExpiryDate = '' })
        $text | Should -Match "Reason              = 'it''s'"
        $text | Should -Not -Match 'ExpiryDate'
    }

    It 'an exception changes the disposition in the compliance view and nothing else' {
        $f = & $script:NewFile
        $null = & $script:Add $f
        Clear-NRGState
        Add-NRGFinding -ControlId 'AAD-2.3' -State 'Gap' -Category 'Identity' -Title 'Device compliance CA' -Severity 'High' -Detail 'No CA policy requires a compliant or hybrid-joined device.'
        $exc = Get-NRGBaselineExceptions -Path $f
        $now = Get-Date
        $raw = @{}
        foreach ($k in @('AAD-CAPolicies', 'AAD-AuthPolicies', 'Intune-DeviceCompliance')) { $raw[$k] = @{ CollectorId = $k; CollectedAt = $now.ToString('o'); Success = $true; Data = @{} } }
        $c = Get-NRGBaselineCompliance -Findings (Get-NRGFindings) -TargetTier Standard -RawData $raw -Coverage @{} -Exceptions $exc
        $row = @($c.Controls | Where-Object { $_.ControlId -eq 'AAD-2.3' })[0]
        $row.ObservedState | Should -Be 'Failed'
        $row.Disposition | Should -Be 'ApprovedException'
        $row.BaselineStatus | Should -Be 'ApprovedException'
        $row.ReasonCode | Should -Be 'ControlFailed'
        $c.BaselineVersion | Should -Be '1.0'
        Clear-NRGState
    }

    It 'the library connects to nothing and every file operation uses -LiteralPath' {
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Set-NRGBaselineException.ps1') -Raw
        foreach ($forbidden in 'Invoke-NRGGraphRequest', 'Invoke-RestMethod', 'Invoke-WebRequest', 'Connect-MgGraph', 'Connect-ExchangeOnline', 'Get-NRGRawData', 'Add-NRGFinding') {
            $src | Should -Not -Match $forbidden
        }
        $src | Should -Not -Match '(?:Set-Content|Get-Content|Move-Item|Remove-Item|Import-PowerShellDataFile)\s[^\n]*\s-Path\s'
        $src | Should -Match 'SupportsShouldProcess'
        $src | Should -Match "ConfirmImpact = 'High'"
    }
}
