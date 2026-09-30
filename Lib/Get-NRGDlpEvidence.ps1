#Requires -Version 7.0
#
# Get-NRGDlpEvidence.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Keep three DLP questions apart, and claim only what the collected policies
#          and rules prove:
#            COVERAGE    which workloads an ENFORCING policy (Mode = Enable) is scoped to
#            DETECTION   which enabled rules in an enforcing policy match sensitive
#                        information types
#            ENFORCEMENT whether those rules block, or only notify / audit (BlockAccess;
#                        $null when the collector did not read it)
#          A policy in test mode (TestWithNotifications / TestWithoutNotifications) or
#          turned off detects nothing that is enforced, so its workloads and its
#          sensitive information types do not count; they are reported as test mode.
#
# Data consumed: Purview (DLPPolicies, DLPRules).  Graph scopes / cmdlets: none.

function Get-NRGDlpRuleStates {
    <#
    .SYNOPSIS
        Joins each DLP rule to its parent policy and classifies it Enforcing (enabled
        rule in a policy whose Mode is Enable), TestMode (enabled rule in a policy in
        test mode or off) or Disabled, with the rule's sensitive information types and
        whether it blocks.
    #>
    [CmdletBinding()]
    [OutputType([object[]])]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $Policies, [AllowNull()] [AllowEmptyCollection()] [object[]] $Rules)
    $mode = @{}
    foreach ($p in @($Policies | Where-Object { $null -ne $_ })) {
        $n = [string](Get-NRGObjectField -Item $p -Key 'Name' -Default '')
        if ($n) { $mode[$n] = [string](Get-NRGObjectField -Item $p -Key 'Mode' -Default '') }
    }
    foreach ($r in @($Rules | Where-Object { $null -ne $_ })) {
        $parent = [string](Get-NRGObjectField -Item $r -Key 'ParentPolicyName' -Default '')
        $pm = if ($parent -and $mode.ContainsKey($parent)) { $mode[$parent] } else { '' }
        $disabled = (Get-NRGObjectField -Item $r -Key 'Disabled' -Default $false) -eq $true
        $state = if ($disabled) { 'Disabled' }
                 elseif ($pm -eq 'Enable') { 'Enforcing' }
                 elseif ($pm) { 'TestMode' }
                 else { 'Unknown' }
        $blocks = Get-NRGObjectField -Item $r -Key 'BlockAccess' -Default $null
        [pscustomobject]@{
            Rule = [string](Get-NRGObjectField -Item $r -Key 'Name' -Default ''); Policy = $parent; PolicyMode = $pm; State = $state
            SITs = @(@(Get-NRGObjectField -Item $r -Key 'SensitiveInfoTypes' -Default @()) | Where-Object { $_ } | ForEach-Object { [string]$_ })
            Blocks = $(if ($null -eq $blocks) { $null } else { [bool]$blocks })
        }
    }
}

function Get-NRGDlpSensitiveTypeNames {
    <#
    .SYNOPSIS
        Names of the sensitive information types a DLP rule matches, read from
        ContentContainsSensitiveInformation in either shape Exchange returns: a flat list of type
        entries, or grouped conditions (template rules such as HIPAA nest the types under groups).
        Walks every nested node and takes the name of any entry that carries the fields a sensitive
        information type carries (id, minimum count or confidence); a group's own name is not a type.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param([AllowNull()] $Conditions)
    $names = [System.Collections.Generic.List[string]]::new()
    $walk = $null
    $walk = {
        param($Node, [bool] $TopLevel)
        if ($null -eq $Node) { return }
        if ($Node -is [System.Collections.IDictionary] -or ($Node -is [psobject] -and $Node -isnot [string] -and $Node -isnot [System.Collections.IEnumerable] -and @($Node.PSObject.Properties).Count -gt 0)) {
            $get = { param($k) Get-NRGObjectField -Item $Node -Key $k -Default $null }
            $n = & $get 'name'; if (-not $n) { $n = & $get 'Name' }
            $hasTypeFields = $false
            foreach ($k in 'id', 'Id', 'mincount', 'Mincount', 'minconfidence', 'Minconfidence', 'confidencelevel', 'Confidencelevel', 'classifiertype', 'Classifiertype') { if ($null -ne (& $get $k)) { $hasTypeFields = $true; break } }
            $hasGroups = ($null -ne (& $get 'groups')) -or ($null -ne (& $get 'Groups')) -or ($null -ne (& $get 'sensitivetypes')) -or ($null -ne (& $get 'SensitiveTypes'))
            if ($n -and ($hasTypeFields -or ($TopLevel -and -not $hasGroups))) { $names.Add([string]$n) }
            $props = if ($Node -is [System.Collections.IDictionary]) { @($Node.Keys | ForEach-Object { $Node[$_] }) } else { @($Node.PSObject.Properties | ForEach-Object { $_.Value }) }
            foreach ($child in $props) { if ($child -is [System.Collections.IEnumerable] -and $child -isnot [string] -or $child -is [System.Collections.IDictionary] -or ($child -is [psobject] -and $child -isnot [string] -and $child -isnot [ValueType])) { & $walk $child $false } }
        } elseif ($Node -is [System.Collections.IEnumerable] -and $Node -isnot [string]) {
            foreach ($child in $Node) { & $walk $child $TopLevel }
        }
    }
    & $walk $Conditions $true
    return @($names | Sort-Object -Unique)
}

function Get-NRGDlpLocationScope {
    <#
    .SYNOPSIS
        Per workload, what a DLP policy is scoped to: Include (names, 'All' when the whole workload)
        and Exclude. $null Include means the location fields were not returned (an older result).
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] $Policy)
    $map = [ordered]@{}
    $fields = [ordered]@{ Exchange = 'ExchangeLocation'; SharePoint = 'SharePointLocation'; OneDriveForBusiness = 'OneDriveLocation'; Teams = 'TeamsLocation' }
    $asNames = { param($v) @(@($v) | Where-Object { $null -ne $_ -and "$_" -ne '' } | ForEach-Object { $n = Get-NRGObjectField -Item $_ -Key 'Name' -Default $null; if ($n) { [string]$n } else { [string]$_ } }) }
    foreach ($w in $fields.Keys) {
        $inc = Get-NRGObjectField -Item $Policy -Key $fields[$w] -Default $null
        $exc = Get-NRGObjectField -Item $Policy -Key ($fields[$w] + 'Exception') -Default $null
        $map[$w] = [ordered]@{ Include = $(if ($null -eq $inc) { $null } else { & $asNames $inc }); Exclude = @(& $asNames $exc) }
    }
    return $map
}
