#Requires -Version 7.0
#
# Add-TPFinding.ps1  (v4.5.5)
# Module-state helpers: findings, exceptions, coverage, raw data.
# All functions operate on $script: scoped variables set in TenantPosture.psm1.
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
# variable throws on access. The .psm1 initializes these four variables at
# module load, but when this file is dot-sourced outside the module (test
# harness, ad-hoc REPL, Pester runtime context), the initialization has not
# run yet. This helper guarantees the state containers exist before any
# accessor touches them, with no observable behavior change for the normal
# module-import path. (v4.6.x audit HIGH #1)
function Initialize-TPState {
    if (-not (Get-Variable -Name TPFindings -Scope Script -ErrorAction SilentlyContinue)) {
        $script:TPFindings = [System.Collections.Generic.List[object]]::new()
    }
    if (-not (Get-Variable -Name TPExceptions -Scope Script -ErrorAction SilentlyContinue)) {
        $script:TPExceptions = [System.Collections.Generic.List[object]]::new()
    }
    if (-not (Get-Variable -Name TPCoverage -Scope Script -ErrorAction SilentlyContinue)) {
        $script:TPCoverage = [System.Collections.Generic.Dictionary[string,string]]::new()
    }
    if (-not (Get-Variable -Name TPRawData -Scope Script -ErrorAction SilentlyContinue)) {
        $script:TPRawData = [System.Collections.Hashtable]::Synchronized(@{})
    }
}


# ── Finding state ─────────────────────────────────────────────────────────────

function Add-TPFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        # v4.12.0: widened from {2,4} to {2,8} to accept the EMAIL- and SIGNIN- prefixes
        [ValidatePattern('^[A-Z]{2,8}-\d+\.\d+$')]
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

    Initialize-TPState
    # Framework rollups (NIST families/matrix, CMMC, the 800-171 SSP) only see
    # a finding through prefixed citations ("NIST:IA-2(1)"). An evaluator that
    # omits -FrameworkIds, or passes bare IDs like 'IA-2(1)', made the finding
    # invisible to every one of them — on a live tenant that hid AAD-1.2 (a
    # Critical MFA Gap) and ten passing controls. Fall back to the control's
    # own citations from controls.json whenever no prefixed citation was given.
    $hasPrefixed = @($FrameworkIds | Where-Object { [string]$_ -match '^[A-Za-z0-9]+:' }).Count -gt 0
    if (-not $hasPrefixed -and $ControlId -match '^[A-Z]{2,4}-\d{1,3}\.\d{1,3}$' -and
        (Get-Command Get-TPFrameworkCitations -ErrorAction SilentlyContinue)) {
        $catalog = @(Get-TPFrameworkCitations -ControlId $ControlId)
        if ($catalog.Count -gt 0) { $FrameworkIds = $catalog }
    }

    # A verdict with no stated reason is not evidence. Several evaluators put
    # the observed value in CurrentValue only, and the report printed a bare
    # "Satisfied" with nothing under it; the observed value is the reason.
    if ([string]::IsNullOrWhiteSpace($Detail) -and -not [string]::IsNullOrWhiteSpace($CurrentValue)) {
        $Detail = $CurrentValue.TrimEnd('.') + '.'
    }

    # A control that shares its setting with others says so, and says it
    # counts once (Config/control-links.json).
    if (Get-Command Get-TPControlLinkNote -ErrorAction SilentlyContinue) {
        $linkNote = Get-TPControlLinkNote -ControlId $ControlId
        if ($linkNote -and $Detail -notlike "*$($linkNote.Trim())*") { $Detail = ($Detail.TrimEnd() + $linkNote).Trim() }
    }

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
        # Drop nulls: an evaluator passing an empty result (often $null, via the
        # if-block-yields-$null trap) stored [null], which counts as one item.
        AffectedObjects = @($AffectedObjects | Where-Object { $null -ne $_ })
        Instance      = $Instance
        FrameworkIds  = $FrameworkIds
        Timestamp     = (Get-Date).ToString('o')
    }

    $script:TPFindings.Add($finding)
}

function Get-TPFindings {
    [CmdletBinding()] param()
    Initialize-TPState
    return @($script:TPFindings)
}

function Clear-TPFindings {
    [CmdletBinding()] param()
    Initialize-TPState
    $script:TPFindings.Clear()
}

# Full state reset across all four module-scope collections.
#
# Required between batch clients (Invoke-TPBatchAssessment.ps1). The batch
# loop runs collectors then evaluators per client; without this helper the
# raw data, coverage map, and exception log from the previous tenant would
# persist into the next tenant's evaluation pass, producing findings labeled
# with the wrong client. Clear-TPFindings alone only resets the findings
# list — it leaves $TPRawData populated. CLAUDE.md mandates Clear-TPState
# specifically.
#
# Initialize-TPState is called first so the helper is safe to invoke even
# before the first collector has run (idempotent, StrictMode-safe).
function Clear-TPState {
    [CmdletBinding()] param()
    Initialize-TPState
    $script:TPFindings.Clear()
    $script:TPRawData.Clear()
    $script:TPCoverage.Clear()
    $script:TPExceptions.Clear()
}

# ── Exception state ───────────────────────────────────────────────────────────

function Register-TPException {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateLength(1,100)]
        [string] $Source,

        [Parameter(Mandatory)]
        [ValidateLength(1,2000)]
        [string] $Message
    )

    Initialize-TPState

    # CWE-117 log-injection guard. $Message often originates from a Graph
    # or EXO error text the attacker can influence (custom display name,
    # rejected request body, malformed response). Newlines + CR + NUL +
    # ESC sequences in $Message let an attacker inject what looks like a
    # second log line into downstream parsers (Sentinel, Splunk, the
    # serialized JSON Exceptions array). Collapse all control characters
    # to a single space here, at the single chokepoint, so the source
    # value is preserved for diagnostics but no parser can be tricked.
    $sanitizedSource  = ($Source  -replace '[\x00-\x1F\x7F]+', ' ').Trim()
    $sanitizedMessage = ($Message -replace '[\x00-\x1F\x7F]+', ' ').Trim()

    $script:TPExceptions.Add([PSCustomObject]@{
        Source    = $sanitizedSource
        Message   = $sanitizedMessage
        Timestamp = (Get-Date).ToString('o')
    })
}

function Get-TPExceptions {
    [CmdletBinding()] param()
    Initialize-TPState
    return @($script:TPExceptions)
}

# ── Coverage state ────────────────────────────────────────────────────────────

function Register-TPCoverage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string] $Family,

        [Parameter(Mandatory)]
        # 'Skipped' records an operator's -Skip flag, so the scope section can
        # tell a workload left out on purpose from one that failed to collect.
        [ValidateSet('Collected','Partial','NotCollected','Failed','Skipped')]
        [string] $Status,

        [string] $Note = ''
    )
    Initialize-TPState
    $script:TPCoverage[$Family] = "$Status|$Note"
}

function Get-TPCoverage {
    [CmdletBinding()] param()
    Initialize-TPState
    $result = @{}
    foreach ($k in $script:TPCoverage.Keys) {
        $parts = $script:TPCoverage[$k] -split '\|', 2
        $result[$k] = [PSCustomObject]@{
            Status = $parts[0]
            Note   = if ($parts.Count -gt 1) { $parts[1] } else { '' }
        }
    }
    return $result
}

# ── Raw data state ────────────────────────────────────────────────────────────

function Set-TPRawData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Z][A-Za-z0-9\-]+$')]
        [string] $Key,

        [Parameter(Mandatory)]
        $Data
    )
    Initialize-TPState
    $script:TPRawData[$Key] = $Data
}

function Get-TPRawData {
    [CmdletBinding()]
    param(
        [ValidatePattern('^[A-Z][A-Za-z0-9\-]+$')]
        [string] $Key
    )
    Initialize-TPState
    if ($Key) { return $script:TPRawData[$Key] }
    return $script:TPRawData
}

function Get-TPSafeProperty {
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
#   Get-TPNestedProperty -Object $raw -Path 'Data.MeetingPolicy.AutoAdmittedUsers' -Default 'Everyone'
#
# Used by evaluators to replace `$raw.Data.X.Y ?? $default` chains, which
# under StrictMode throw PropertyNotFoundException when any intermediate
# segment is missing (the `??` operator only coalesces $null — it cannot
# catch the exception).
function Get-TPNestedProperty {
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
