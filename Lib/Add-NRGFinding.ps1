#Requires -Version 7.0
#
# Add-NRGFinding.ps1  (v4.5.5)
# Module-state helpers: findings, exceptions, coverage, raw data.
# All functions operate on $script: scoped variables set in NRG-Assessment.psm1.
#
# SECURITY:
#   - No external I/O — pure in-memory state
#   - ValidateSet on State prevents invalid states silently passing through evaluators
#   - ValidateSet on Severity prevents arbitrary strings reaching the HTML publisher
#   - LiteralPath not relevant here (no file ops)
#
# OWASP ASVS V5.1.3  — input validation on all parameters
# OWASP ASVS V16.4.1 — Set-StrictMode enforced by module loader
#


# Lazy-init helper. Under Set-StrictMode -Version Latest an unset module-scope
# variable throws on access. The .psm1 initialises these four variables at
# module load, but when this file is dot-sourced outside the module (test
# harness, ad-hoc REPL, Pester runtime context), the initialisation has not
# run yet. This helper guarantees the state containers exist before any
# accessor touches them, with no observable behaviour change for the normal
# module-import path. (v4.6.x audit HIGH #1)
function Initialize-NRGState {
    if (-not (Get-Variable -Name NRGFindings -Scope Script -ErrorAction SilentlyContinue)) {
        $script:NRGFindings = [System.Collections.Generic.List[object]]::new()
    }
    if (-not (Get-Variable -Name NRGExceptions -Scope Script -ErrorAction SilentlyContinue)) {
        $script:NRGExceptions = [System.Collections.Generic.List[object]]::new()
    }
    if (-not (Get-Variable -Name NRGCoverage -Scope Script -ErrorAction SilentlyContinue)) {
        $script:NRGCoverage = [System.Collections.Generic.Dictionary[string,string]]::new()
    }
    if (-not (Get-Variable -Name NRGRawData -Scope Script -ErrorAction SilentlyContinue)) {
        $script:NRGRawData = [System.Collections.Hashtable]::Synchronized(@{})
    }
}


# ── Finding state ─────────────────────────────────────────────────────────────

function Add-NRGFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Z]{2,4}-\d+\.\d+$')]
        [string] $ControlId,

        [Parameter(Mandatory)]
        [ValidateSet('Satisfied','Partial','Gap','NotApplicable','Error')]
        [string] $State,

        [Parameter(Mandatory)]
        [ValidateSet('Identity','Email','Endpoint','Data','Collaboration','Governance','Network','Power Platform','Compliance','SharePoint','Teams')]
        [string] $Category,

        [Parameter(Mandatory)]
        [ValidateLength(1,200)]
        [string] $Title,

        [ValidateSet('Critical','High','Medium','Low','Informational')]
        [string] $Severity = 'Informational',

        [string] $Detail       = '',
        [string] $CurrentValue = '',
        [string] $RequiredValue= '',
        [string] $Remediation  = '',
        [string] $Instance     = '',
        [string[]] $FrameworkIds = @(),

        # Named objects affected — users, mailboxes, apps, devices
        # Shown as a named table in the HTML report
        [object[]] $AffectedObjects = @()
    )

    Initialize-NRGState
    $finding = [PSCustomObject]@{
        ControlId     = $ControlId
        State         = $State
        Category      = $Category
        Title         = $Title
        Severity      = $Severity
        Detail        = $Detail
        CurrentValue  = $CurrentValue
        RequiredValue = $RequiredValue
        Remediation   = $Remediation
        AffectedObjects = @($AffectedObjects)
        Instance      = $Instance
        FrameworkIds  = $FrameworkIds
        Timestamp     = (Get-Date).ToString('o')
    }

    $script:NRGFindings.Add($finding)
}

function Get-NRGFindings {
    [CmdletBinding()] param()
    Initialize-NRGState
    return @($script:NRGFindings)
}

function Clear-NRGFindings {
    [CmdletBinding()] param()
    Initialize-NRGState
    $script:NRGFindings.Clear()
}

# Full state reset across all four module-scope collections.
#
# Required between batch clients (Invoke-NRGBatchAssessment.ps1). The batch
# loop runs collectors then evaluators per client; without this helper the
# raw data, coverage map, and exception log from the previous tenant would
# persist into the next tenant's evaluation pass, producing findings labeled
# with the wrong client. Clear-NRGFindings alone only resets the findings
# list — it leaves $NRGRawData populated. CLAUDE.md mandates Clear-NRGState
# specifically.
#
# Initialize-NRGState is called first so the helper is safe to invoke even
# before the first collector has run (idempotent, StrictMode-safe).
function Clear-NRGState {
    [CmdletBinding()] param()
    Initialize-NRGState
    $script:NRGFindings.Clear()
    $script:NRGRawData.Clear()
    $script:NRGCoverage.Clear()
    $script:NRGExceptions.Clear()
}

# ── Exception state ───────────────────────────────────────────────────────────

function Register-NRGException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1,100)]
        [string] $Source,

        [Parameter(Mandatory)]
        [ValidateLength(1,2000)]
        [string] $Message
    )

    Initialize-NRGState
    $script:NRGExceptions.Add([PSCustomObject]@{
        Source    = $Source
        Message   = $Message
        Timestamp = (Get-Date).ToString('o')
    })
}

function Get-NRGExceptions {
    [CmdletBinding()] param()
    Initialize-NRGState
    return @($script:NRGExceptions)
}

# ── Coverage state ────────────────────────────────────────────────────────────

function Register-NRGCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Family,

        [Parameter(Mandatory)]
        [ValidateSet('Collected','Partial','NotCollected','Failed')]
        [string] $Status,

        [string] $Note = ''
    )
    Initialize-NRGState
    $script:NRGCoverage[$Family] = "$Status|$Note"
}

function Get-NRGCoverage {
    [CmdletBinding()] param()
    Initialize-NRGState
    $result = @{}
    foreach ($k in $script:NRGCoverage.Keys) {
        $parts = $script:NRGCoverage[$k] -split '\|', 2
        $result[$k] = [PSCustomObject]@{
            Status = $parts[0]
            Note   = if ($parts.Count -gt 1) { $parts[1] } else { '' }
        }
    }
    return $result
}

# ── Raw data state ────────────────────────────────────────────────────────────

function Set-NRGRawData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Z][A-Za-z0-9\-]+$')]
        [string] $Key,

        [Parameter(Mandatory)]
        $Data
    )
    Initialize-NRGState
    $script:NRGRawData[$Key] = $Data
}

function Get-NRGRawData {
    [CmdletBinding()]
    param(
        [ValidatePattern('^[A-Z][A-Za-z0-9\-]+$')]
        [string] $Key
    )
    Initialize-NRGState
    if ($Key) { return $script:NRGRawData[$Key] }
    return $script:NRGRawData
}

function Get-NRGSafeProperty {
    [CmdletBinding()]
    param(
        [AllowNull()][object] $Object,
        [string] $Property,
        [object] $Default = $null
    )
    if ($null -eq $Object) { return $Default }
    $prop = $Object.PSObject.Properties[$Property]
    if ($null -eq $prop) { return $Default }
    $val = $prop.Value
    if ($null -eq $val) { return $Default }
    return $val
}

# Walks a dotted path safely under Set-StrictMode -Version Latest.
# Returns $Default if any segment is null, missing, or unreachable.
# Handles hashtables, pscustomobjects, and ordered dictionaries uniformly.
#
# Example:
#   Get-NRGNestedProperty -Object $raw -Path 'Data.MeetingPolicy.AutoAdmittedUsers' -Default 'Everyone'
#
# Used by evaluators to replace `$raw.Data.X.Y ?? $default` chains, which
# under StrictMode throw PropertyNotFoundException when any intermediate
# segment is missing (the `??` operator only coalesces $null — it cannot
# catch the exception).
function Get-NRGNestedProperty {
    [CmdletBinding()]
    param(
        [AllowNull()][object] $Object,
        [Parameter(Mandatory)][string] $Path,
        [object] $Default = $null
    )
    if ($null -eq $Object -or [string]::IsNullOrWhiteSpace($Path)) { return $Default }
    $cur = $Object
    foreach ($segment in ($Path -split '\.')) {
        if ($null -eq $cur) { return $Default }
        try {
            if ($cur -is [System.Collections.IDictionary]) {
                if (-not $cur.Contains($segment)) { return $Default }
                $cur = $cur[$segment]
            } else {
                $prop = $cur.PSObject.Properties[$segment]
                if ($null -eq $prop) { return $Default }
                $cur = $prop.Value
            }
        } catch {
            return $Default
        }
    }
    if ($null -eq $cur) { return $Default }
    return $cur
}
