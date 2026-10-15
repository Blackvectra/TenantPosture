#Requires -Version 7.0
<#
.SYNOPSIS
    Runs the Pester suite and fails on anything that means "not verified" —
    including a test file that never parsed.

.DESCRIPTION
    The gate every local check and every CI job should go through, so that
    "tests pass" means the same thing in both places.

    A run is accepted only when every test file parses, Pester returns a run
    result, that result says Passed, at least one test actually ran, and no
    failed test, block or container is reported.

    This exists because `FailedCount` alone does not mean the suite passed. A
    container that fails DISCOVERY — a test file with a syntax error, a missing
    dot-sourced helper, a throw in `BeforeDiscovery` — runs no tests, so it
    reports zero failures. On 2026-10-15 a merge conflict resolution dropped one
    closing brace in `Testing/TP.IdentityTruth.Tests.ps1`; the local check read
    `FailedCount`, saw 0, and approved the merge. Pester on main then failed at
    parse before a single test ran (CI runs 554 and 556). The same blind spot
    passes a run whose test path is a typo: no files, no tests, no failures.

    The parse scan runs first and on its own, because a syntax error is a
    different fix from a failing assertion and reading it out of Pester's
    discovery output is harder than parsing the file.

.PARAMETER Path
    Test directories or files, repository-relative or absolute. Default: the
    two suites CI runs, `Testing` and `Email-IR/Testing`.

.PARAMETER ResultPath
    Write an NUnit XML result file here. Omitted: no result file.

.PARAMETER Output
    Pester console verbosity. Default `Normal`.

.PARAMETER DefinitionsOnly
    Define the functions and return without running anything. For dot-sourcing
    from tests: `. ./tools/Invoke-TPTestGate.ps1 -DefinitionsOnly`.

.OUTPUTS
    Exit code 0 when the run is accepted, 1 when it is not.

.EXAMPLE
    ./tools/Invoke-TPTestGate.ps1
.EXAMPLE
    ./tools/Invoke-TPTestGate.ps1 -Path ./Testing/TP.WebServer.Tests.ps1 -Output Detailed
#>

[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string[]] $Path = @('Testing', 'Email-IR/Testing'),

    [string] $ResultPath,

    [ValidateSet('None', 'Normal', 'Detailed', 'Diagnostic')]
    [string] $Output = 'Normal',

    [switch] $DefinitionsOnly
)

# StrictMode is set per function, never at script scope: a script-scope
# Set-StrictMode is inherited by the scopes Pester creates for discovery and
# run, and the suite is not written for it — with it on, TP.Security.Tests.ps1
# fails discovery on a `-Skip:(-not $script:ModuleLoaded)` whose variable is set
# in BeforeAll, and TP.BaselineException.Tests.ps1 fails on a `.Count` over one
# item. A gate must judge the suite, not change how it runs.

# Reads a property the object may not have. Pester's result shape differs
# between 5.x releases, and a test drives these functions with a synthetic
# object, so a bare `.Property` would throw under StrictMode on exactly the
# shape this gate exists to judge.
function Get-TPResultField {
    [CmdletBinding()]
    param(
        [AllowNull()] $InputObject,
        [Parameter(Mandatory)] [string] $Name
    )

    Set-StrictMode -Version Latest

    if ($null -eq $InputObject) { return $null }
    if ($InputObject -is [System.Collections.IDictionary]) {
        if ($InputObject.Contains($Name)) { return $InputObject[$Name] }
        return $null
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

# Every test file that does not parse, one record per parse error.
function Get-TPUnparsableTestFile {
    [CmdletBinding()]
    [OutputType([pscustomobject[]])]
    param(
        [Parameter(Mandatory)]
        [string[]] $Path
    )

    Set-StrictMode -Version Latest

    $problems = [System.Collections.Generic.List[pscustomobject]]::new()

    foreach ($entry in $Path) {
        if ([string]::IsNullOrWhiteSpace($entry)) { continue }

        if (-not (Test-Path -LiteralPath $entry)) {
            # A path that is not there is a gate failure, not an empty run: this
            # is how a typo'd test path reports "no failures" and passes.
            $problems.Add([pscustomobject]@{
                File    = $entry
                Line    = 0
                Message = 'Test path not found.'
            })
            continue
        }

        # @() wraps the whole conditional: an inner @() is unrolled by the
        # assignment, and one file would then be a scalar whose .Count throws
        # under StrictMode.
        $files = @(
            if (Test-Path -LiteralPath $entry -PathType Container) {
                Get-ChildItem -LiteralPath $entry -Filter '*.Tests.ps1' -File -Recurse
            } else {
                Get-Item -LiteralPath $entry
            }
        )

        if ($files.Count -eq 0) {
            $problems.Add([pscustomobject]@{
                File    = $entry
                Line    = 0
                Message = 'No *.Tests.ps1 files under this path.'
            })
            continue
        }

        foreach ($file in $files) {
            $tokens = $null
            $errors = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile(
                $file.FullName, [ref] $tokens, [ref] $errors)
            foreach ($parseError in @($errors)) {
                $problems.Add([pscustomobject]@{
                    File    = $file.FullName
                    Line    = $parseError.Extent.StartLineNumber
                    Message = $parseError.Message
                })
            }
        }
    }

    return $problems.ToArray()
}

# Every reason this run does not count as verified. Empty means accepted.
function Get-TPPesterRunProblem {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Result
    )

    Set-StrictMode -Version Latest

    $problems = [System.Collections.Generic.List[string]]::new()

    if ($null -eq $Result) {
        $problems.Add('Pester returned no run result, so nothing was verified.')
        return $problems.ToArray()
    }

    # FailedCount is the one count every Pester 5 release reports; its absence
    # means this object is not a run result and nothing can be concluded.
    $failedValue = Get-TPResultField -InputObject $Result -Name 'FailedCount'
    $failed = 0
    if ($null -eq $failedValue) {
        $problems.Add('Pester reported no FailedCount, so this is not a run result.')
    } elseif (-not [int]::TryParse([string] $failedValue, [ref] $failed)) {
        $problems.Add("Pester reported FailedCount as '$failedValue', which is not a count.")
    } elseif ($failed -gt 0) {
        $problems.Add("FailedCount is $failed.")
    }

    # The counts that carry a discovery failure. Absent on a Pester version that
    # does not report them, which is not itself a failure — the per-container
    # scan below is the backstop, and losing both is.
    $blockOrContainerCountSeen = $false
    foreach ($countName in 'FailedBlocksCount', 'FailedContainersCount') {
        $value = Get-TPResultField -InputObject $Result -Name $countName
        if ($null -eq $value) { continue }
        $blockOrContainerCountSeen = $true
        $count = 0
        if (-not [int]::TryParse([string] $value, [ref] $count)) {
            $problems.Add("Pester reported $countName as '$value', which is not a count.")
        } elseif ($count -gt 0) {
            $problems.Add("$countName is $count.")
        }
    }

    # Zero tests is the other way a FailedCount check passes a run that verified
    # nothing: a failed discovery, an empty directory, a wrong path, a filter
    # that matched nothing.
    $totalValue = Get-TPResultField -InputObject $Result -Name 'TotalCount'
    $total = 0
    if ($null -eq $totalValue) {
        $problems.Add('Pester reported no TotalCount, so it is unknown whether any test ran.')
    } elseif (-not [int]::TryParse([string] $totalValue, [ref] $total)) {
        $problems.Add("Pester reported TotalCount as '$totalValue', which is not a count.")
    } elseif ($total -le 0) {
        $problems.Add('No tests ran.')
    }

    $runResult = Get-TPResultField -InputObject $Result -Name 'Result'
    if ($null -eq $runResult) {
        $problems.Add('Pester reported no overall Result.')
    } elseif ([string] $runResult -ne 'Passed') {
        $problems.Add("Pester's overall Result is '$runResult'.")
    }

    # Per container, because a discovery failure lands here first: the container
    # is Failed and carries the error, while the test counts stay at zero.
    $containers = @(Get-TPResultField -InputObject $Result -Name 'Containers' | Where-Object { $null -ne $_ })
    if ($containers.Count -eq 0 -and -not $blockOrContainerCountSeen) {
        $problems.Add('Pester reported neither container results nor container counts, so a file that failed to load cannot be ruled out.')
    }
    foreach ($container in $containers) {

        $name = $null
        foreach ($nameField in 'Name', 'Item', 'Path') {
            $candidate = Get-TPResultField -InputObject $container -Name $nameField
            if ($candidate) { $name = [string] $candidate; break }
        }
        if (-not $name) { $name = '(unnamed container)' }

        # Skipped and NotRun are accepted: a suite whose whole context is
        # skipped (Pode absent on the Ubuntu job, Windows ACLs on Linux) is not
        # a failure, and failing on it would make the gate the thing people
        # route around. Failed — and any state this list does not know — is not.
        $containerResult = Get-TPResultField -InputObject $container -Name 'Result'
        if ($containerResult -and [string] $containerResult -notin @('Passed', 'Skipped', 'NotRun')) {
            $problems.Add("Container '$name' result is '$containerResult'.")
        }

        foreach ($errorRecord in @(Get-TPResultField -InputObject $container -Name 'ErrorRecord')) {
            if ($null -eq $errorRecord) { continue }
            $problems.Add("Container '$name' errored: $errorRecord")
        }
    }

    return $problems.ToArray()
}

if ($DefinitionsOnly) { return }

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$resolvedPaths = foreach ($entry in $Path) {
    if ([System.IO.Path]::IsPathRooted($entry)) { $entry } else { Join-Path $repoRoot $entry }
}

Write-Host ''
Write-Host 'Test gate — parse scan' -ForegroundColor Cyan
$unparsable = @(Get-TPUnparsableTestFile -Path $resolvedPaths)
if ($unparsable.Count -gt 0) {
    foreach ($problem in $unparsable) {
        if ($problem.Line -gt 0) {
            Write-Host ('  {0}:{1}  {2}' -f $problem.File, $problem.Line, $problem.Message) -ForegroundColor Red
        } else {
            Write-Host ('  {0}  {1}' -f $problem.File, $problem.Message) -ForegroundColor Red
        }
    }
    Write-Host ''
    Write-Host 'FAILED: fix the above before Pester can run — a file that does not parse runs no tests and reports no failures.' -ForegroundColor Red
    exit 1
}
Write-Host '  every test file parses.' -ForegroundColor Green

Import-Module Pester -MinimumVersion 5.5.0 -Force -ErrorAction Stop
$pester = Get-Module Pester
Write-Host ('  Pester {0}' -f $pester.Version)

$config = New-PesterConfiguration
$config.Run.Path = $resolvedPaths
# This script decides the outcome, so Pester neither exits nor throws for it.
$config.Run.PassThru = $true
$config.Run.Exit = $false
$config.Run.Throw = $false
$config.Output.Verbosity = $Output
if ($ResultPath) {
    $config.TestResult.Enabled = $true
    $config.TestResult.OutputPath = $ResultPath
    $config.TestResult.OutputFormat = 'NUnitXml'
}

$result = Invoke-Pester -Configuration $config

Write-Host ''
Write-Host 'Test gate — run result' -ForegroundColor Cyan
foreach ($field in 'Result', 'TotalCount', 'PassedCount', 'FailedCount', 'SkippedCount', 'FailedBlocksCount', 'FailedContainersCount') {
    $value = Get-TPResultField -InputObject $result -Name $field
    Write-Host ('  {0,-22} {1}' -f $field, $(if ($null -eq $value) { '(not reported)' } else { $value }))
}

$problems = @(Get-TPPesterRunProblem -Result $result)
Write-Host ''
if ($problems.Count -gt 0) {
    foreach ($problem in $problems) { Write-Host ('  {0}' -f $problem) -ForegroundColor Red }
    Write-Host ''
    Write-Host 'FAILED: the suite did not verify this tree.' -ForegroundColor Red
    exit 1
}

Write-Host 'PASSED: every test file parsed, tests ran, and nothing failed.' -ForegroundColor Green
exit 0
