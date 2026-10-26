#Requires -Version 7.0
#
# Get-TPIntuneOfficeMacroBaseline.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Judge the assigned Intune Office policies against the approved macro and
#          active-content core of the CIS Microsoft Intune for Office Benchmark v1.1.0,
#          Level 1 (Config/cis-intune-office-macro.json), for INT-2.6.
#
#          Pure functions, no Graph call:
#          Get-TPOfficeSettingCapture reads a Settings Catalog settings payload (read with
#            $expand=settingDefinitions) and keeps only the Office settings: each value keyed
#            by its lower-case setting definition id, and the display name Graph returns for
#            each Office definition and each of its options.
#          Get-TPIntuneOfficeMacroBaseline returns the catalog only while the owner's approval
#            in Config/tp-standards.json (IntuneOfficeMacroBaseline) names its exact benchmark
#            and version; the tool applies no configuration standard nobody approved.
#          Get-TPOfficeMacroBaselineRows judges each catalog setting across every assigned
#            Office policy: Met when some policy sets it and every policy that sets it sets
#            the accepted state; Below when any sets another documented state; NotSet when
#            none sets it; Unrecognized when a value is not one Microsoft documents for the
#            setting, which is never taken to be compliant.
#
#          Office settings are ADMX-backed: the definition id carries the app's ADMX namespace
#          (user_vendor_msft_policy_config_excel16v2~policy~...) and the policy name at its
#          end. Microsoft publishes no Graph sample of these ids, so a catalog setting is
#          matched by the app namespace and the definition's display name (or the ADMX policy
#          name, best effort), and Enabled / Disabled by the option's display name before the
#          _1 / _0 suffix. Not yet verified against a live tenant (docs/TP-DETECTION-LIMITS.md).
#
# Data consumed: Config/cis-intune-office-macro.json, Config/tp-standards.json.
# Graph scopes / cmdlets: none (parsing and judgment only).

# The Office ADMX namespaces in a Settings Catalog definition id.
$script:TPOfficeDefinitionPattern = '^(user|device)_vendor_msft_policy_config_(access16v2|excel16v2|ppt16v2|word16v2|visio16v2|outlk16v2|proj16v2|pub16v2|onent16v2|office16v2)~'

function ConvertTo-TPOfficeSettingKey {
    <#
    .SYNOPSIS
        A display name reduced for comparison: lower case, a trailing (User), (Device) or
        (Deprecated) dropped, letters and digits only.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] [AllowEmptyString()] [string] $Name)
    if ([string]::IsNullOrWhiteSpace($Name)) { return '' }
    $n = $Name.ToLowerInvariant()
    $n = [regex]::Replace($n, '(\s*\((user|device|deprecated)\))+\s*$', '')
    return [regex]::Replace($n, '[^a-z0-9]', '')
}

function Get-TPOfficeSettingCapture {
    <#
    .SYNOPSIS
        The Office settings of one Settings Catalog payload: Values (lower-case definition
        id -> lower-case value) and Labels (lower-case definition id or option item id ->
        display name, from the expanded settingDefinitions). Empty maps when the policy sets
        no Office setting.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([AllowNull()] $Settings)

    $values = [ordered]@{}
    foreach ($e in (Get-TPAvSettingValues -Settings $Settings).GetEnumerator()) {
        if ([string]$e.Key -match $script:TPOfficeDefinitionPattern) { $values[[string]$e.Key] = [string]$e.Value }
    }
    $labels = [ordered]@{}
    foreach ($s in @($Settings)) {
        if ($null -eq $s) { continue }
        foreach ($def in @(Get-TPObjectField -Item $s -Key 'settingDefinitions' -Default @())) {
            if ($null -eq $def) { continue }
            $id = ([string](Get-TPObjectField -Item $def -Key 'id' -Default '')).ToLowerInvariant()
            if (-not $id -or $id -notmatch $script:TPOfficeDefinitionPattern) { continue }
            $dn = [string](Get-TPObjectField -Item $def -Key 'displayName' -Default '')
            if ($dn) { $labels[$id] = $dn }
            foreach ($o in @(Get-TPObjectField -Item $def -Key 'options' -Default @())) {
                if ($null -eq $o) { continue }
                $item = ([string](Get-TPObjectField -Item $o -Key 'itemId' -Default '')).ToLowerInvariant()
                $odn = [string](Get-TPObjectField -Item $o -Key 'displayName' -Default '')
                if ($item -and $odn) { $labels[$item] = $odn }
            }
        }
    }
    return @{ Values = $values; Labels = $labels }
}

function Get-TPIntuneOfficeMacroBaseline {
    <#
    .SYNOPSIS
        The approved Office macro catalog, or $null when the owner's approval in
        tp-standards.json is absent, empty, unreadable or names another benchmark or version,
        or the catalog cannot be read. $null means "no standard is approved" (not assessed),
        never "nothing is required".
    #>
    [CmdletBinding()]
    param([string] $CatalogPath, [string] $StandardsPath)

    $root = Split-Path -Parent $PSScriptRoot
    if (-not $CatalogPath)   { $CatalogPath   = Join-Path $root 'Config' 'cis-intune-office-macro.json' }
    if (-not $StandardsPath) { $StandardsPath = Join-Path $root 'Config' 'tp-standards.json' }
    if (-not (Test-Path -LiteralPath $StandardsPath) -or -not (Test-Path -LiteralPath $CatalogPath)) { return $null }
    try {
        $std = Get-Content -LiteralPath $StandardsPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 10
        $cat = Get-Content -LiteralPath $CatalogPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 10
    } catch { return $null }
    $approval = Get-TPObjectField -Item $std -Key 'IntuneOfficeMacroBaseline' -Default $null
    $approved = [string](Get-TPObjectField -Item $approval -Key 'Benchmark' -Default '')
    if ([string]::IsNullOrWhiteSpace($approved)) { return $null }
    $catName = '{0} v{1}' -f (Get-TPObjectField -Item $cat -Key 'Benchmark' -Default ''), (Get-TPObjectField -Item $cat -Key 'Version' -Default '')
    if ($approved.Trim() -ne $catName) { return $null }
    $settings = @(Get-TPObjectField -Item $cat -Key 'Settings' -Default @() | Where-Object { $null -ne $_ })
    if ($settings.Count -eq 0) { return $null }
    return [pscustomobject]@{
        Name     = $catName
        Profile  = [string](Get-TPObjectField -Item $cat -Key 'Profile' -Default '')
        Subset   = [string](Get-TPObjectField -Item $cat -Key 'Subset' -Default '')
        Settings = $settings
    }
}

function Get-TPOfficeMacroBaselineRows {
    <#
    .SYNOPSIS
        One row per catalog setting: Cis, App, Title, Status (Met / Below / NotSet /
        Unrecognized), Observed (what each policy sets, named), Required, NotConfigured.
        Policies are objects with DisplayName, Values and Labels (Get-TPOfficeSettingCapture).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $Policies,
        [Parameter(Mandatory)] $Catalog
    )
    $keysOf = { param($m) if ($null -eq $m) { @() } elseif ($m -is [System.Collections.IDictionary]) { @($m.Keys) } else { @($m.PSObject.Properties.Name) } }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($s in @($Catalog.Settings)) {
        $appKey = ([string]$s.AppKey).ToLowerInvariant()
        $appRx = [regex]::new('^(user|device)_vendor_msft_policy_config_' + [regex]::Escape($appKey) + '~')
        $node = ([string](Get-TPObjectField -Item $s -Key 'Node' -Default '')).ToLowerInvariant()
        $names = @([string]$s.Title) + @(Get-TPObjectField -Item $s -Key 'AlternateNames' -Default @())
        $nameKeys = @($names | ForEach-Object { ConvertTo-TPOfficeSettingKey $_ } | Where-Object { $_ })
        $valueLabels = Get-TPObjectField -Item $s -Key 'Values' -Default $null
        $option = Get-TPObjectField -Item $s -Key 'Option' -Default $null
        $observed = @(); $statuses = @()
        foreach ($p in @($Policies)) {
            if ($null -eq $p) { continue }
            $pname = [string](Get-TPObjectField -Item $p -Key 'DisplayName' -Default 'unnamed policy')
            $values = Get-TPObjectField -Item $p -Key 'Values' -Default $null
            $labels = Get-TPObjectField -Item $p -Key 'Labels' -Default $null
            $label = { param($k) if ($null -eq $labels) { '' } else { [string](Get-TPObjectField -Item $labels -Key $k -Default '') } }
            $ids = @(& $keysOf $values | ForEach-Object { ([string]$_).ToLowerInvariant() })
            foreach ($id in $ids) {
                if (-not $appRx.IsMatch($id)) { continue }
                # A child setting (the option under a dropdown) is judged with its parent, never alone.
                if (@($ids | Where-Object { $_ -ne $id -and $id.StartsWith("${_}_") }).Count -gt 0) { continue }
                $byName = $nameKeys -contains (ConvertTo-TPOfficeSettingKey (& $label $id))
                $byNode = $node -and $id.EndsWith("_$node")
                if (-not ($byName -or $byNode)) { continue }
                $raw = ([string](Get-TPObjectField -Item $values -Key $id -Default '')).ToLowerInvariant()
                # Enabled / Disabled: the option's display name first, the _1 / _0 suffix second.
                $state = $null
                $optKey = ConvertTo-TPOfficeSettingKey (& $label $raw)
                if ($optKey -eq 'enabled') { $state = '1' } elseif ($optKey -eq 'disabled') { $state = '0' }
                elseif ($raw.StartsWith("${id}_")) { $t = $raw.Substring($id.Length + 1); if ($t -in @('0', '1')) { $state = $t } }
                if ($null -eq $state) { $observed += "$pname ($raw)"; $statuses += 'Unrecognized'; continue }
                $stateLabel = [string](Get-TPObjectField -Item $valueLabels -Key $state -Default $state)
                if ($state -notin @($s.Compliant)) { $observed += "$pname ($stateLabel)"; $statuses += 'Below'; continue }
                if ([string]$s.Kind -ne 'Dropdown') { $observed += "$pname ($stateLabel)"; $statuses += 'Met'; continue }
                # The option chosen under an enabled dropdown setting: a child of this definition,
                # judged by its display name only (the suffix may be an index, not the value).
                $childIds = @($ids | Where-Object { $_.StartsWith("${id}_") })
                $childLabels = @(foreach ($c in $childIds) {
                    $cv = ([string](Get-TPObjectField -Item $values -Key $c -Default '')).ToLowerInvariant()
                    & $label $cv })
                $childLabels = @($childLabels | Where-Object { $_ })
                if ($childLabels.Count -eq 0) { $observed += "$pname (Enabled; option not read)"; $statuses += 'Unrecognized'; continue }
                $ck = ConvertTo-TPOfficeSettingKey $childLabels[0]
                $ok   = @(@($option.Compliant)  | ForEach-Object { ConvertTo-TPOfficeSettingKey $_ })
                $more = @(@($option.Stricter)   | ForEach-Object { ConvertTo-TPOfficeSettingKey $_ })
                $doc  = @(@($option.Documented) | ForEach-Object { ConvertTo-TPOfficeSettingKey $_ })
                if ($ck -in $ok) { $observed += "$pname ($($childLabels[0]))"; $statuses += 'Met' }
                # Stricter than CIS's audited value (no macro runs at all): accepted as Met by
                # the owner's decision of 2026-10-26, so these items cite the benchmark as Stricter.
                elseif ($ck -in $more) { $observed += "$pname ($($childLabels[0]), stricter than the benchmark's audited value; accepted)"; $statuses += 'Met' }
                elseif ($ck -in $doc) { $observed += "$pname ($($childLabels[0]))"; $statuses += 'Below' }
                else { $observed += "$pname ($($childLabels[0]))"; $statuses += 'Unrecognized' }
            }
        }
        $status = if ($statuses.Count -eq 0) { 'NotSet' }
                  elseif ($statuses -contains 'Below') { 'Below' }
                  elseif ($statuses -contains 'Unrecognized') { 'Unrecognized' }
                  else { 'Met' }
        $req = [string](Get-TPObjectField -Item $valueLabels -Key ([string]@($s.Compliant)[0]) -Default '')
        if ([string]$s.Kind -eq 'Dropdown' -and $null -ne $option) { $req = "$req`: $([string]$option.Required)" }
        $rows.Add([pscustomobject][ordered]@{
            Cis           = [string]$s.Cis
            App           = [string]$s.App
            Title         = [string]$s.Title
            Status        = $status
            Observed      = @($observed | Select-Object -Unique)
            Required      = $req
            NotConfigured = [string](Get-TPObjectField -Item $s -Key 'NotConfigured' -Default '')
        })
    }
    return @($rows)
}
