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
