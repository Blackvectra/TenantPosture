#Requires -Version 7.0
<#
.SYNOPSIS
    Set-TPBaselineException.ps1 — TenantPosture
    Author: Matthew Levorson
    Purpose: Create, read, update and remove approved baseline exceptions for
             ONE client without hand-editing Config/baseline-exceptions/<tenant>.psd1.
             Deliberately boring and safe: the control must be a baseline
             control, every required field is required, the review date must
             be in the future, one active exception per control, the file
             stays data-only PSD1, every write is atomic and verified by
             re-reading it, and an invalid existing entry is preserved and
             reported, never silently approved or repaired.
    An exception changes a control's DISPOSITION only. It never changes the
    observed state, and BaselineVersion is untouched: exceptions are tenant
    state, not a change to the standard. This is one of the few places the
    assessment writes persistent client configuration, so New/Set/Remove
    support -WhatIf and -Confirm.
    Data keys consumed: none. Graph scopes / cmdlets: none — connects to nothing.
#>

Set-StrictMode -Version Latest

function Get-TPBaselineExceptionPath {
    <#
    .SYNOPSIS
        The exceptions file for a tenant domain, by the same slug rule the
        loader uses. The reserved 'example' slug is refused.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $TenantDomain)
    $slug = ConvertTo-TPBaselineClientSlug -TenantDomain $TenantDomain
    if (-not $slug) { throw "'$TenantDomain' does not resolve to a client slug (empty or the reserved 'example')." }
    $moduleRoot = if ((Get-Variable -Name TPModuleRoot -Scope Script -ErrorAction SilentlyContinue) -and $script:TPModuleRoot) { $script:TPModuleRoot }
                  elseif ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot }
                  else { (Get-Location).Path }
    return (Join-Path $moduleRoot 'Config' 'baseline-exceptions' "$slug.psd1")
}

function ConvertTo-TPBaselineExceptionPsd1 {
    <#
    .SYNOPSIS
        Renders entries as a data-only PSD1 document the loader reads with
        Import-PowerShellDataFile. Strings are single-quoted with quotes
        doubled; dates are written as yyyy-MM-dd.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Entries)
    $q = { param([string] $v) ConvertTo-TPPsd1String -Value ($v ?? '') }
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine('@{')
    $null = $sb.AppendLine('    # NRG Security Baseline — approved exceptions for ONE client.')
    $null = $sb.AppendLine('    # Written by New/Set/Remove-TPBaselineException; data only, never executed.')
    $null = $sb.AppendLine('    # An exception changes the baseline disposition only, never the observed state.')
    $null = $sb.AppendLine('    Exceptions = @(')
    foreach ($e in @($Entries | Where-Object { $null -ne $_ })) {
        $null = $sb.AppendLine('        @{')
        foreach ($k in @('ControlId', 'Reason', 'CompensatingControl', 'Approver', 'ApprovedDate', 'ReviewDate', 'ExpiryDate')) {
            $v = [string](Get-TPObjectField -Item $e -Key $k -Default '')
            if ($k -eq 'ExpiryDate' -and [string]::IsNullOrWhiteSpace($v)) { continue }
            $null = $sb.AppendLine(('            {0,-19} = {1}' -f $k, (& $q $v)))
        }
        $null = $sb.AppendLine('        }')
    }
    $null = $sb.AppendLine('    )')
    $null = $sb.AppendLine('}')
    return $sb.ToString()
}

function Write-TPBaselineExceptionFile {
    <#
    .SYNOPSIS
        Atomic, verified write: the document goes to a temp file beside the
        target, is re-read with Import-PowerShellDataFile and checked for the
        expected entry count, and only then replaces the target. A failed save
        leaves the existing file untouched.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Entries
    )
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $text = ConvertTo-TPBaselineExceptionPsd1 -Entries $Entries
    $tmp = Join-Path $dir ((Split-Path -Leaf $Path) + '.' + [guid]::NewGuid().ToString('N') + '.tmp.psd1')
    try {
        Set-Content -LiteralPath $tmp -Value $text -Encoding utf8 -NoNewline
        $check = Import-PowerShellDataFile -LiteralPath $tmp -ErrorAction Stop
        $n = @(Get-TPObjectField -Item $check -Key 'Exceptions' -Default @()).Count
        $expected = @($Entries | Where-Object { $null -ne $_ }).Count
        if ($n -ne $expected) { throw "Round-trip check failed: wrote $expected entr$(if ($expected -eq 1) { 'y' } else { 'ies' }), read back $n." }
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Get-TPBaselineException {
    <#
    .SYNOPSIS
        The exceptions on file for a tenant, each with its verdict (approved,
        or why not). -ControlId narrows to one control.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $TenantDomain,
        [ValidatePattern('^(?:[A-Z]{2,4}-\d+\.\d+|VM-VERIFY-\d+)$')] [string] $ControlId = '',
        [AllowNull()] [AllowEmptyString()] [string] $Path = '',
        [datetime] $AsOf = (Get-Date)
    )
    $file = if ($Path) { $Path } else { Get-TPBaselineExceptionPath -TenantDomain $TenantDomain }
    $exc = Get-TPBaselineExceptions -Path $file -AsOf $AsOf
    $rows = @(Get-TPObjectField -Item $exc -Key 'Entries' -Default @())
    if ($ControlId) { $rows = @($rows | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'ControlId' -Default '') -eq $ControlId }) }
    return $rows
}

function Test-TPBaselineExceptionInput {
    # Shared validation for New and Set: the control is a baseline control,
    # the dates parse, the review date is in the future, and an expiry date
    # is not before the review date.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ControlId,
        [Parameter(Mandatory)] [datetime] $ReviewDate,
        [AllowNull()] [Nullable[datetime]] $ExpiryDate,
        [datetime] $AsOf = (Get-Date)
    )
    $def = Get-TPBaselineDefinition
    if (-not $def.Controls.Contains($ControlId)) {
        throw "$ControlId is not an NRG Security Baseline control (v$($def.Version)); an assessment-only control needs no exception."
    }
    if ($ReviewDate.Date -le $AsOf.Date) {
        throw "ReviewDate $($ReviewDate.ToString('yyyy-MM-dd')) must be a future date; an exception is approved only until its review."
    }
    if ($null -ne $ExpiryDate) {
        if (([datetime]$ExpiryDate).Date -lt $ReviewDate.Date) { throw "ExpiryDate $(([datetime]$ExpiryDate).ToString('yyyy-MM-dd')) is before ReviewDate $($ReviewDate.ToString('yyyy-MM-dd'))." }
    }
}

function New-TPBaselineException {
    <#
    .SYNOPSIS
        Adds an approved exception for one baseline control on one client.
    .DESCRIPTION
        Refuses a control that is not in the baseline, a review date that is
        not in the future, an expiry before the review, and a second active
        exception for the same control (use Set- to change it or Remove- first).
        Existing entries, including ones no longer in force, are preserved
        as written and reported in NotInForce; nothing is repaired silently.
        Returns what changed: the entry as the loader now reads it, and the
        approved/total counts before and after.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $TenantDomain,
        [Parameter(Mandatory)] [ValidatePattern('^(?:[A-Z]{2,4}-\d+\.\d+|VM-VERIFY-\d+)$')] [string] $ControlId,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Reason,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $CompensatingControl,
        [Parameter(Mandatory)] [ValidateNotNullOrEmpty()] [string] $Approver,
        [datetime] $ApprovedDate = (Get-Date),
        [Parameter(Mandatory)] [datetime] $ReviewDate,
        [AllowNull()] [Nullable[datetime]] $ExpiryDate = $null,
        [AllowNull()] [AllowEmptyString()] [string] $Path = ''
    )
    Set-StrictMode -Version Latest
    $now = Get-Date
    Test-TPBaselineExceptionInput -ControlId $ControlId -ReviewDate $ReviewDate -ExpiryDate $ExpiryDate -AsOf $now
    $file = if ($Path) { $Path } else { Get-TPBaselineExceptionPath -TenantDomain $TenantDomain }
    $before = Get-TPBaselineExceptions -Path $file -AsOf $now
    $existing = @(Get-TPObjectField -Item $before -Key 'Entries' -Default @())
    $active = @($existing | Where-Object { [string]$_.ControlId -eq $ControlId -and [bool]$_.Approved })
    if ($active.Count -gt 0) {
        throw "An active exception for $ControlId already exists on $(Split-Path -Leaf $file) ($($active[0].Verdict)). Use Set-TPBaselineException to change it or Remove-TPBaselineException first."
    }
    $entry = [ordered]@{
        ControlId           = $ControlId
        Reason              = $Reason.Trim()
        CompensatingControl = $CompensatingControl.Trim()
        Approver            = $Approver.Trim()
        ApprovedDate        = $ApprovedDate.ToString('yyyy-MM-dd')
        ReviewDate          = $ReviewDate.ToString('yyyy-MM-dd')
        ExpiryDate          = $(if ($null -ne $ExpiryDate) { ([datetime]$ExpiryDate).ToString('yyyy-MM-dd') } else { '' })
    }
    $entries = @($existing) + @($entry)
    $result = [ordered]@{
        Path       = $file
        ControlId  = $ControlId
        Change     = 'Added'
        Before     = [ordered]@{ Entries = $existing.Count; Approved = @($existing | Where-Object { $_.Approved }).Count }
        After      = $null
        Entry      = $null
        NotInForce = @($existing | Where-Object { -not $_.Approved } | ForEach-Object { "$($_.ControlId): $($_.Verdict)" })
        Note       = 'Disposition only: the control''s observed state is unchanged and BaselineVersion is unchanged.'
    }
    if ($PSCmdlet.ShouldProcess($file, "Add baseline exception for $ControlId (approver $($entry.Approver), review $($entry.ReviewDate))")) {
        Write-TPBaselineExceptionFile -Path $file -Entries $entries
        $after = Get-TPBaselineExceptions -Path $file -AsOf $now
        $rows = @(Get-TPObjectField -Item $after -Key 'Entries' -Default @())
        $result.After = [ordered]@{ Entries = $rows.Count; Approved = @($rows | Where-Object { $_.Approved }).Count }
        $result.Entry = @($rows | Where-Object { [string]$_.ControlId -eq $ControlId -and [bool]$_.Approved })[0]
        if ($null -eq $result.Entry) { throw "The exception was written but does not read back as approved; the file was not changed further. Inspect $file." }
        Write-Verbose "Baseline exception added for $ControlId in ${file}: entries $($result.Before.Entries) -> $($result.After.Entries), approved $($result.Before.Approved) -> $($result.After.Approved)."
    } else {
        $result.Change = 'WhatIf'
        $result.Entry = [pscustomobject]$entry
        $result.After = [ordered]@{ Entries = $entries.Count; Approved = $result.Before.Approved + 1 }
    }
    foreach ($n in $result.NotInForce) { Write-Warning "Existing exception not in force (preserved as written): $n" }
    return $result
}

function Set-TPBaselineException {
    <#
    .SYNOPSIS
        Changes the one exception on file for a control. Only the fields given
        change; the result is validated the same way New- validates. Giving a
        new -Approver without -ApprovedDate re-dates the approval to today.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $TenantDomain,
        [Parameter(Mandatory)] [ValidatePattern('^(?:[A-Z]{2,4}-\d+\.\d+|VM-VERIFY-\d+)$')] [string] $ControlId,
        [AllowNull()] [AllowEmptyString()] [string] $Reason,
        [AllowNull()] [AllowEmptyString()] [string] $CompensatingControl,
        [AllowNull()] [AllowEmptyString()] [string] $Approver,
        [AllowNull()] [Nullable[datetime]] $ApprovedDate = $null,
        [AllowNull()] [Nullable[datetime]] $ReviewDate = $null,
        [AllowNull()] [Nullable[datetime]] $ExpiryDate = $null,
        [switch] $ClearExpiryDate,
        [AllowNull()] [AllowEmptyString()] [string] $Path = ''
    )
    Set-StrictMode -Version Latest
    $now = Get-Date
    $file = if ($Path) { $Path } else { Get-TPBaselineExceptionPath -TenantDomain $TenantDomain }
    $before = Get-TPBaselineExceptions -Path $file -AsOf $now
    if (-not $before.Available) { throw "No exceptions file for $TenantDomain at $file." }
    $existing = @(Get-TPObjectField -Item $before -Key 'Entries' -Default @())
    $mine = @($existing | Where-Object { [string]$_.ControlId -eq $ControlId })
    if ($mine.Count -eq 0) { throw "No exception for $ControlId on $(Split-Path -Leaf $file); use New-TPBaselineException." }
    if ($mine.Count -gt 1) { throw "$($mine.Count) entries for $ControlId on $(Split-Path -Leaf $file); remove them with Remove-TPBaselineException and add one." }
    $old = $mine[0]
    $parse = { param([string] $v) $d = [datetime]::MinValue; if ([datetime]::TryParse($v, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeLocal, [ref]$d)) { $d } else { $null } }
    $newReview = if ($null -ne $ReviewDate) { [datetime]$ReviewDate } else { & $parse ([string]$old.ReviewDate) }
    if ($null -eq $newReview) { throw "The existing ReviewDate '$($old.ReviewDate)' is not a date; pass -ReviewDate." }
    $newExpiry = if ($ClearExpiryDate) { $null } elseif ($null -ne $ExpiryDate) { [datetime]$ExpiryDate } elseif ([string]$old.ExpiryDate) { & $parse ([string]$old.ExpiryDate) } else { $null }
    if ($null -ne $ExpiryDate -and $ClearExpiryDate) { throw 'Give -ExpiryDate or -ClearExpiryDate, not both.' }
    Test-TPBaselineExceptionInput -ControlId $ControlId -ReviewDate $newReview -ExpiryDate $newExpiry -AsOf $now
    $newApprover = if ($PSBoundParameters.ContainsKey('Approver') -and $Approver) { $Approver.Trim() } else { [string]$old.Approver }
    $newApproved = if ($null -ne $ApprovedDate) { ([datetime]$ApprovedDate).ToString('yyyy-MM-dd') }
                   elseif ($PSBoundParameters.ContainsKey('Approver') -and $Approver -and $Approver.Trim() -ne [string]$old.Approver) { $now.ToString('yyyy-MM-dd') }
                   else { [string]$old.ApprovedDate }
    $entry = [ordered]@{
        ControlId           = $ControlId
        Reason              = $(if ($PSBoundParameters.ContainsKey('Reason') -and $Reason) { $Reason.Trim() } else { [string]$old.Reason })
        CompensatingControl = $(if ($PSBoundParameters.ContainsKey('CompensatingControl') -and $CompensatingControl) { $CompensatingControl.Trim() } else { [string]$old.CompensatingControl })
        Approver            = $newApprover
        ApprovedDate        = $newApproved
        ReviewDate          = $newReview.ToString('yyyy-MM-dd')
        ExpiryDate          = $(if ($null -ne $newExpiry) { $newExpiry.ToString('yyyy-MM-dd') } else { '' })
    }
    foreach ($k in 'Reason', 'CompensatingControl', 'Approver', 'ApprovedDate') {
        if ([string]::IsNullOrWhiteSpace([string]$entry[$k])) { throw "$k is required and the existing entry has none; pass -$k." }
    }
    $entries = @(foreach ($e in $existing) { if ([string]$e.ControlId -eq $ControlId) { $entry } else { $e } })
    $changed = @(foreach ($k in $entry.Keys) { if ([string]$entry[$k] -ne [string](Get-TPObjectField -Item $old -Key $k -Default '')) { $k } })
    $result = [ordered]@{
        Path          = $file
        ControlId     = $ControlId
        Change        = $(if ($changed.Count -gt 0) { 'Updated' } else { 'Unchanged' })
        ChangedFields = @($changed)
        Before        = $old
        After         = $null
        NotInForce    = @($existing | Where-Object { -not $_.Approved -and [string]$_.ControlId -ne $ControlId } | ForEach-Object { "$($_.ControlId): $($_.Verdict)" })
        Note          = 'Disposition only: the control''s observed state is unchanged and BaselineVersion is unchanged.'
    }
    if ($changed.Count -eq 0) { $result.After = $old; return $result }
    if ($PSCmdlet.ShouldProcess($file, "Change baseline exception for $ControlId ($($changed -join ', '))")) {
        Write-TPBaselineExceptionFile -Path $file -Entries $entries
        $after = Get-TPBaselineExceptions -Path $file -AsOf $now
        $result.After = @(Get-TPObjectField -Item $after -Key 'Entries' -Default @() | Where-Object { [string]$_.ControlId -eq $ControlId })[0]
        if ($null -eq $result.After -or -not [bool]$result.After.Approved) { throw "The exception was written but does not read back as approved; inspect $file." }
        Write-Verbose "Baseline exception for $ControlId changed in $file`: $($changed -join ', ')."
    } else {
        $result.Change = 'WhatIf'
        $result.After = [pscustomobject]$entry
    }
    foreach ($n in $result.NotInForce) { Write-Warning "Existing exception not in force (preserved as written): $n" }
    return $result
}

function Remove-TPBaselineException {
    <#
    .SYNOPSIS
        Removes every entry for a control from the client's exceptions file.
        The file is kept (with an empty list when nothing remains) so the
        loader keeps reading it.
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $TenantDomain,
        [Parameter(Mandatory)] [ValidatePattern('^(?:[A-Z]{2,4}-\d+\.\d+|VM-VERIFY-\d+)$')] [string] $ControlId,
        [AllowNull()] [AllowEmptyString()] [string] $Path = ''
    )
    Set-StrictMode -Version Latest
    $now = Get-Date
    $file = if ($Path) { $Path } else { Get-TPBaselineExceptionPath -TenantDomain $TenantDomain }
    $before = Get-TPBaselineExceptions -Path $file -AsOf $now
    if (-not $before.Available) { throw "No exceptions file for $TenantDomain at $file." }
    $existing = @(Get-TPObjectField -Item $before -Key 'Entries' -Default @())
    $mine = @($existing | Where-Object { [string]$_.ControlId -eq $ControlId })
    if ($mine.Count -eq 0) { throw "No exception for $ControlId on $(Split-Path -Leaf $file)." }
    $entries = @($existing | Where-Object { [string]$_.ControlId -ne $ControlId })
    $result = [ordered]@{
        Path      = $file
        ControlId = $ControlId
        Change    = 'Removed'
        Removed   = @($mine)
        Before    = [ordered]@{ Entries = $existing.Count; Approved = @($existing | Where-Object { $_.Approved }).Count }
        After     = [ordered]@{ Entries = $entries.Count; Approved = @($entries | Where-Object { $_.Approved }).Count }
        Note      = 'The control returns to its observed state in the baseline view on the next run (or -FromResults).'
    }
    if ($PSCmdlet.ShouldProcess($file, "Remove $($mine.Count) baseline exception entr$(if ($mine.Count -eq 1) { 'y' } else { 'ies' }) for $ControlId")) {
        Write-TPBaselineExceptionFile -Path $file -Entries $entries
        Write-Verbose "Baseline exception(s) for $ControlId removed from $file`: entries $($result.Before.Entries) -> $($result.After.Entries)."
    } else {
        $result.Change = 'WhatIf'
    }
    return $result
}
