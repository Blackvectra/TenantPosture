#Requires -Version 7.0
#
# Get-TPControlDefinitions.ps1  (v4.5.5)
# Loads controls.json and frameworks.json into module state.
# Provides lookup helpers for evaluators and publishers.
#
# SECURITY HARDENING:
#   OWASP A01 / ASVS V12.3.1  — LiteralPath on all file reads
#                              — Config files verified to resolve inside $PSScriptRoot
#                              — Path traversal blocked at load time
#   OWASP A03 / ASVS V5.1.3   — All ControlId lookups validated via ValidatePattern
#                              — Severity, Workload, Category values validated against
#                                known-good allowlists (supply chain / tamper detection)
#                              — ControlId format validated against regex before use
#   OWASP A08                  — controls.json content integrity enforced:
#                                tampered or injected values throw before any evaluator
#                                sees the data — fail-closed on bad input
#   ASVS V16.4.1               — Set-StrictMode enforced
#

# ── Allowlists — the single source of truth for valid control field values ────
# If a value in controls.json is not in these sets, the loader throws.
# This prevents tampered JSON from injecting arbitrary strings into
# evaluator logic or publisher output.
$script:ValidSeverities = [System.Collections.Generic.HashSet[string]]@(
    'Critical', 'High', 'Medium', 'Low', 'Informational'
)
$script:ValidWorkloads  = [System.Collections.Generic.HashSet[string]]@(
    'AAD', 'EXO', 'DNS', 'DEF', 'SPO', 'TMS', 'INT', 'PVW', 'PPL', 'AI', 'INV'
)
$script:ValidCategories = [System.Collections.Generic.HashSet[string]]@(
    'Identity', 'Email', 'Endpoint', 'Data', 'Collaboration', 'Governance', 'Network'
)
$script:ValidControlIdPattern = '^[A-Z]{2,4}-\d{1,3}\.\d{1,3}$'

# Module-scoped cache — populated once, shared across all evaluators
$script:TPControls   = $null
$script:TPFrameworks = $null

function Get-TPControlDefinitions {
    [CmdletBinding()] param()

    if ($script:TPControls -and $script:TPControls.Count -gt 0) {
        return $script:TPControls
    }

    # ── Locate and verify the file ─────────────────────────────────────────
    $moduleRoot   = $PSScriptRoot ? (Split-Path -Parent $PSScriptRoot) : (Get-Location).Path
    $controlsPath = Join-Path $moduleRoot 'Config' 'controls.json'

    if (-not (Test-Path -LiteralPath $controlsPath)) {
        throw "controls.json not found at: $controlsPath"
    }

    # Path traversal check — file must resolve inside module root
    # OWASP A01 / ASVS V12.3.1
    $resolved     = [System.IO.Path]::GetFullPath($controlsPath)
    $resolvedRoot = [System.IO.Path]::GetFullPath($moduleRoot)
    if (-not $resolved.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "controls.json resolved outside module root (path traversal?): $resolved"
    }

    # ── Parse JSON ────────────────────────────────────────────────────────
    try {
        $json = Get-Content -LiteralPath $controlsPath -Raw -Encoding utf8 -ErrorAction Stop
        $data = $json | ConvertFrom-Json -ErrorAction Stop
    } catch {
        throw "Failed to parse controls.json: $($_.Exception.Message)"
    }

    if (-not $data.PSObject.Properties['controls'] -or $data.controls.Count -eq 0) {
        throw "controls.json has no 'controls' array or it is empty."
    }

    # ── Field presence validation ─────────────────────────────────────────
    # All required fields must exist and be non-empty
    $requiredFields = @('ControlId','Title','Severity','Workload','Category',
                        'CollectorDependency','EvaluatorFunction','Remediation')
    $missingFields  = [System.Collections.Generic.List[string]]::new()

    foreach ($ctrl in $data.controls) {
        foreach ($field in $requiredFields) {
            if (-not $ctrl.PSObject.Properties[$field] -or
                [string]::IsNullOrWhiteSpace([string]$ctrl.$field)) {
                $missingFields.Add("$($ctrl.ControlId ?? '<no-id>'): missing '$field'")
            }
        }
    }
    if ($missingFields.Count -gt 0) {
        throw "controls.json schema violations ($($missingFields.Count)):`n$($missingFields -join "`n")"
    }

    # ── Content validation — allowlist enforcement ────────────────────────
    # OWASP A03 / ASVS V5.1.3 / OWASP A08
    # Tampered values (wrong Severity, invalid Workload, malformed ControlId)
    # are caught HERE before any evaluator or publisher sees them.
    # Fail-closed: any violation throws; the tool does not run with bad data.
    $contentErrors = [System.Collections.Generic.List[string]]::new()

    foreach ($ctrl in $data.controls) {
        $id = [string]($ctrl.ControlId ?? '<no-id>')

        # ControlId must match strict format (e.g. AAD-1.1, SPO-1.10)
        if ($id -notmatch $script:ValidControlIdPattern) {
            $contentErrors.Add("$id — ControlId format invalid (expected WORKLOAD-N.N, e.g. AAD-1.1)")
        }

        # Severity must be in the known set — prevents arbitrary strings reaching
        # report severity logic or HTML publisher badge rendering
        $sev = [string]($ctrl.Severity ?? '')
        if (-not $script:ValidSeverities.Contains($sev)) {
            $contentErrors.Add("$id — Severity '$sev' not in allowed set: $($script:ValidSeverities -join ', ')")
        }

        # Workload must be a known service code — prevents unknown workloads
        # from reaching collector/evaluator routing logic
        $wl = [string]($ctrl.Workload ?? '')
        if (-not $script:ValidWorkloads.Contains($wl)) {
            $contentErrors.Add("$id — Workload '$wl' not in allowed set: $($script:ValidWorkloads -join ', ')")
        }

        # Category must be a known classification — used in report grouping
        $cat = [string]($ctrl.Category ?? '')
        if (-not $script:ValidCategories.Contains($cat)) {
            $contentErrors.Add("$id — Category '$cat' not in allowed set: $($script:ValidCategories -join ', ')")
        }

        # ControlId prefix must match declared Workload (e.g. AAD-1.1 must have Workload AAD)
        if ($id -match '^([A-Z]{2,4})-') {
            $idPrefix = $matches[1]
            if ($idPrefix -ne $wl -and $wl -in $script:ValidWorkloads) {
                $contentErrors.Add("$id — ControlId prefix '$idPrefix' does not match Workload '$wl'")
            }
        }

        # Remediation string must not contain script injection patterns
        # HTML publisher escapes this, but defense-in-depth at the data layer
        $remedy = [string]($ctrl.Remediation ?? '')
        if ($remedy -match '<script|javascript:|vbscript:|\bon(click|load|error|mouseover|submit|focus|blur|change|keydown|keyup|input|ready)\s*=') {
            $contentErrors.Add("$id — Remediation contains suspected injection pattern")
        }

        # Title length cap — prevents memory/rendering issues from absurdly long titles
        $title = [string]($ctrl.Title ?? '')
        if ($title.Length -gt 200) {
            $contentErrors.Add("$id — Title exceeds 200 characters ($($title.Length))")
        }

        # Duplicate ControlId detection — ensures single source of truth
        # (checked after the loop — see below)
    }

    # Duplicate ControlId check
    $allIds    = @($data.controls | ForEach-Object { [string]$_.ControlId })
    $dupeIds   = $allIds | Group-Object | Where-Object { $_.Count -gt 1 } | Select-Object -ExpandProperty Name
    foreach ($dupe in $dupeIds) {
        $contentErrors.Add("Duplicate ControlId: '$dupe' appears $( ($allIds | Where-Object {$_ -eq $dupe}).Count ) times")
    }

    if ($contentErrors.Count -gt 0) {
        throw "controls.json content validation failed ($($contentErrors.Count) error(s)):`n$($contentErrors -join "`n")"
    }

    $script:TPControls = $data.controls
    Write-Verbose "controls.json loaded: $($script:TPControls.Count) controls validated."
    return $script:TPControls
}

function Get-TPControlById {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Z]{2,4}-\d{1,3}\.\d{1,3}$')]
        [string] $ControlId
    )

    $controls = Get-TPControlDefinitions
    return $controls | Where-Object { $_.ControlId -eq $ControlId } | Select-Object -First 1
}

function Get-TPFrameworkCitations {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Z]{2,4}-\d{1,3}\.\d{1,3}$')]
        [string] $ControlId
    )

    $control = Get-TPControlById -ControlId $ControlId
    if (-not $control -or -not $control.PSObject.Properties['References']) { return @() }

    $ids = [System.Collections.Generic.List[string]]::new()
    foreach ($prop in $control.References.PSObject.Properties) {
        foreach ($v in @($prop.Value)) {
            # Sanitize citation value — strip any chars that could escape into report output
            $safeVal = [string]$v -replace '[<>"''&]', ''
            # Skip empty citations (e.g. "SCuBA": "" for controls with no ScubaGear mapping) —
            # a bare "SCuBA:" token would otherwise satisfy Get-TPCoverageScore's prefix match
            # and pull unmapped controls into that framework's denominator.
            if ([string]::IsNullOrWhiteSpace($safeVal)) { continue }
            $ids.Add("$($prop.Name):$safeVal")
        }
    }
    return $ids.ToArray()
}

function Get-TPFrameworkDefinitions {
    [CmdletBinding()] param()

    if ($script:TPFrameworks -and $script:TPFrameworks.Count -gt 0) {
        return $script:TPFrameworks
    }

    $moduleRoot     = $PSScriptRoot ? (Split-Path -Parent $PSScriptRoot) : (Get-Location).Path
    $frameworksPath = Join-Path $moduleRoot 'Config' 'frameworks.json'

    if (-not (Test-Path -LiteralPath $frameworksPath)) {
        Write-Warning "frameworks.json not found — framework metadata unavailable."
        return @{}
    }

    $resolved     = [System.IO.Path]::GetFullPath($frameworksPath)
    $resolvedRoot = [System.IO.Path]::GetFullPath($moduleRoot)
    if (-not $resolved.StartsWith($resolvedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "frameworks.json resolved outside module root: $resolved"
    }

    try {
        $json = Get-Content -LiteralPath $frameworksPath -Raw -Encoding utf8 -ErrorAction Stop
        $script:TPFrameworks = ($json | ConvertFrom-Json -ErrorAction Stop).frameworks
    } catch {
        Write-Warning "Failed to load frameworks.json: $($_.Exception.Message)"
        $script:TPFrameworks = @{}
    }

    return $script:TPFrameworks
}
