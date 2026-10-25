#Requires -Version 7.0
#
# Get-TPIntuneAvBaseline.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Judge an assigned Intune Defender Antivirus policy against the CIS Microsoft
#          Intune for Microsoft Defender Antivirus Benchmark v1.0.0, Level 1 - Workstation
#          (Config/cis-intune-defender-av.json), for INT-1.5.
#
#          Three pieces, each a pure function:
#          Get-TPAvSettingValues reads every setting value a Settings Catalog payload
#            carries, keyed by its setting definition id, so a newer judgment can be
#            made from a stored policy without another Graph read.
#          Get-TPIntuneAvBaseline returns the catalog only while the owner's approval in
#            Config/tp-standards.json (IntuneAntivirusBaseline) stands; the tool applies
#            no configuration standard nobody approved.
#          Get-TPAvBaselineRows judges each catalog setting across every assigned policy:
#            Met when at least one policy sets it and every policy that sets it sets a
#            compliant value; Below when any policy sets a value the benchmark does not
#            accept; NotSet when no policy sets it (the benchmark requires each setting
#            managed; the Windows default is named, never credited); Unrecognized when a
#            value is not one Microsoft documents, which is never taken to be compliant.
#
#          Setting definition ids are matched by the CSP node at their end, after an
#          underscore. Microsoft's own Graph sample of an Antivirus policy shows the
#          Policy CSP form (device_vendor_msft_policy_config_defender_<node>, choice value
#          <id>_<n>, integers as simpleSettingValue, threat actions as children of
#          ..._threatseveritydefaultaction); the Defender CSP nodes have no published
#          sample, so matching the node, not a full prefix, keeps them readable. Not yet
#          verified against a live tenant (docs/TP-DETECTION-LIMITS.md).
#
# Data consumed: Config/cis-intune-defender-av.json, Config/tp-standards.json.
# Graph scopes / cmdlets: none (parsing and judgment only).

function Get-TPAvSettingValues {
    <#
    .SYNOPSIS
        Every setting value in a Settings Catalog settings payload, keyed by the lower-case
        setting definition id: a choice setting's value id, or an integer setting's value
        as a string. Nested children (group collections, choice children) are included.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] $Settings)

    $out = [ordered]@{}
    $walk = $null
    $walk = {
        param($Node)
        if ($null -eq $Node) { return }
        if ($Node -is [System.Collections.IDictionary] -or $Node -is [pscustomobject]) {
            $defId = ([string](Get-TPObjectField -Item $Node -Key 'settingDefinitionId' -Default '')).ToLowerInvariant()
            if ($defId) {
                $choice = Get-TPObjectField -Item $Node -Key 'choiceSettingValue' -Default $null
                $simple = Get-TPObjectField -Item $Node -Key 'simpleSettingValue' -Default $null
                if ($null -ne $choice) {
                    $v = [string](Get-TPObjectField -Item $choice -Key 'value' -Default '')
                    if ($v) { $out[$defId] = $v.ToLowerInvariant() }
                } elseif ($null -ne $simple) {
                    $v = Get-TPObjectField -Item $simple -Key 'value' -Default $null
                    if ($null -ne $v -and "$v" -ne '') { $out[$defId] = [string]$v }
                }
            }
            $keys = if ($Node -is [System.Collections.IDictionary]) { @($Node.Keys) } else { @($Node.PSObject.Properties.Name) }
            foreach ($k in $keys) { & $walk (Get-TPObjectField -Item $Node -Key $k -Default $null) }
        } elseif ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
            foreach ($child in $Node) { & $walk $child }
        }
    }
    & $walk $Settings
    return $out
}

function Get-TPIntuneAvBaseline {
    <#
    .SYNOPSIS
        The approved antivirus configuration catalog, or $null when the owner's approval in
        tp-standards.json is absent, empty or unreadable, or the catalog cannot be read.
        $null means "judge the legacy three settings only", never "nothing is required".
    #>
    [CmdletBinding()]
    param([string] $CatalogPath, [string] $StandardsPath)

    $root = Split-Path -Parent $PSScriptRoot
    if (-not $CatalogPath)   { $CatalogPath   = Join-Path $root 'Config' 'cis-intune-defender-av.json' }
    if (-not $StandardsPath) { $StandardsPath = Join-Path $root 'Config' 'tp-standards.json' }
    if (-not (Test-Path -LiteralPath $StandardsPath) -or -not (Test-Path -LiteralPath $CatalogPath)) { return $null }
    try {
        $std = Get-Content -LiteralPath $StandardsPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 10
        $cat = Get-Content -LiteralPath $CatalogPath -Raw -Encoding utf8 | ConvertFrom-Json -Depth 10
    } catch { return $null }
    $approval = Get-TPObjectField -Item $std -Key 'IntuneAntivirusBaseline' -Default $null
    $approved = [string](Get-TPObjectField -Item $approval -Key 'Benchmark' -Default '')
    if ([string]::IsNullOrWhiteSpace($approved)) { return $null }
    # The approval names the benchmark and version it approved; a catalog of another
    # version is not what was approved.
    $catName = '{0} v{1}' -f (Get-TPObjectField -Item $cat -Key 'Benchmark' -Default ''), (Get-TPObjectField -Item $cat -Key 'Version' -Default '')
    if ($approved.Trim() -ne $catName) { return $null }
    $settings = @(Get-TPObjectField -Item $cat -Key 'Settings' -Default @())
    if ($settings.Count -eq 0) { return $null }
    return [pscustomobject]@{
        Name     = $catName
        Profile  = [string](Get-TPObjectField -Item $cat -Key 'Profile' -Default '')
        Settings = $settings
    }
}

function Get-TPAvBaselineValueLabel {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Setting, [AllowNull()] [string] $Token)
    if ($null -eq $Token) { return 'not set' }
    $labels = Get-TPObjectField -Item $Setting -Key 'Values' -Default $null
    $label = if ($null -ne $labels) { [string](Get-TPObjectField -Item $labels -Key $Token -Default '') } else { '' }
    if ($label) { return $label }
    return $Token
}

function Get-TPAvBaselineRequirement {
    [CmdletBinding()]
    param([Parameter(Mandatory)] $Setting)
    switch ([string]$Setting.Kind) {
        'Integer' {
            $mn = [int]$Setting.Minimum; $mx = [int]$Setting.Maximum
            if ($mn -eq $mx) { return "$mn" }
            return "$mn to $mx"
        }
        'ThreatAction' { return 'Quarantine or Remove' }
        default {
            $ok = @($Setting.Compliant | ForEach-Object { Get-TPAvBaselineValueLabel -Setting $Setting -Token ([string]$_) })
            return ($ok -join ' or ')
        }
    }
}

function Get-TPAvBaselineRows {
    <#
    .SYNOPSIS
        One row per catalog setting: Cis, Title, Status (Met / Below / NotSet / Unrecognized),
        Observed (labels of every value the assigned policies set), Required, WindowsDefault.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [object[]] $SettingMaps,
        [Parameter(Mandatory)] $Catalog
    )
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($s in @($Catalog.Settings)) {
        $node = ([string]$s.Node).ToLowerInvariant()
        $kind = [string]$s.Kind
        $tail = [regex]::new('(^|_)' + [regex]::Escape($node) + '$')
        $observed = @(); $statuses = @()
        foreach ($map in $SettingMaps) {
            if ($null -eq $map) { continue }
            $keys = if ($map -is [System.Collections.IDictionary]) { @($map.Keys) } else { @($map.PSObject.Properties.Name) }
            foreach ($k in $keys) {
                $id = ([string]$k).ToLowerInvariant()
                if (-not $tail.IsMatch($id)) { continue }
                $raw = ([string](Get-TPObjectField -Item $map -Key $k -Default '')).ToLowerInvariant()
                # The token is what follows "<definition id>_" in a choice value; an integer
                # setting stores the number itself.
                $token = if ($raw.StartsWith("${id}_")) { $raw.Substring($id.Length + 1) } else { $raw }
                switch ($kind) {
                    'Integer' {
                        $n = 0
                        if ($token -match '^\d+$' -and [int]::TryParse($token, [System.Globalization.NumberStyles]::None, [cultureinfo]::InvariantCulture, [ref]$n)) {
                            $observed += "$n"
                            $statuses += $(if ($n -ge [int]$s.Minimum -and $n -le [int]$s.Maximum) { 'Met' } else { 'Below' })
                        } else { $observed += $token; $statuses += 'Unrecognized' }
                    }
                    'ThreatAction' {
                        $known = @('clean', 'quarantine', 'remove', 'allow', 'userdefined', 'block')
                        if ($token -in $known) {
                            $observed += $token
                            $statuses += $(if ($token -in @($s.Compliant)) { 'Met' } else { 'Below' })
                        } else { $observed += $token; $statuses += 'Unrecognized' }
                    }
                    default {
                        # A choice token Microsoft does not document for this node is not judged.
                        $documented = @()
                        $labels = Get-TPObjectField -Item $s -Key 'Values' -Default $null
                        if ($null -ne $labels) { $documented += @(if ($labels -is [System.Collections.IDictionary]) { $labels.Keys } else { $labels.PSObject.Properties.Name }) }
                        $documented += @($s.Compliant)
                        if ($token -match '^\d+$' -and $token -in $documented) {
                            $observed += (Get-TPAvBaselineValueLabel -Setting $s -Token $token)
                            $statuses += $(if ($token -in @($s.Compliant)) { 'Met' } else { 'Below' })
                        } else { $observed += $token; $statuses += 'Unrecognized' }
                    }
                }
            }
        }
        $status = if ($statuses.Count -eq 0) { 'NotSet' }
                  elseif ($statuses -contains 'Below') { 'Below' }
                  elseif ($statuses -contains 'Unrecognized') { 'Unrecognized' }
                  else { 'Met' }
        $default = Get-TPObjectField -Item $s -Key 'WindowsDefault' -Default $null
        $rows.Add([pscustomobject][ordered]@{
            Cis            = [string]$s.Cis
            Title          = [string]$s.Title
            Status         = $status
            Observed       = @($observed | Select-Object -Unique)
            Required       = Get-TPAvBaselineRequirement -Setting $s
            WindowsDefault = $(if ($null -ne $default) { Get-TPAvBaselineValueLabel -Setting $s -Token ([string]$default) } else { $null })
        })
    }
    return @($rows)
}
