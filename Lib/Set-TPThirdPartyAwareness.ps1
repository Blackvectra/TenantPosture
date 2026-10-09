#Requires -Version 7.0
#
# Set-TPThirdPartyAwareness.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Purpose: When a client's phishing simulation and security awareness training
#   run on a third-party platform (e.g. KnowBe4), take the check that assumes
#   Microsoft Attack Simulation Training out of the score, and say why.
#
# Data keys: none. Operates on the module findings list after evaluation.
# Graph / cmdlets: none.
#
# The same contract as Set-TPThirdPartyEdr. Microsoft 365 cannot see a
# third-party training platform, so without this a client phishing-tested
# through KnowBe4 reads as "users are never phishing-tested" (a Gap), or, on a
# tenant without Defender for Office 365 Plan 2, as a license upgrade it does
# not need. The declaration is the operator's, not evidence the tool
# collected, so:
#   - A check that PASSED keeps its verdict: Microsoft's own simulations ran,
#     and that is evidence.
#   - Anything else becomes NotApplicable, excluded from the score, with a
#     detail that says the program is DECLARED, NOT VERIFIED, names the
#     evidence to keep from the platform, and keeps the original result.
#   - A finding license gating already moved (a -FromResults republish of a
#     run without the declaration) is unwrapped to the evaluator's own result
#     first, so the rewritten detail never carries the upgrade-opportunity
#     marker the license sections key on.
#   - Get-TPAssessmentScope files these in the same ThirdPartyAttested bucket
#     as the EDR declaration, keyed on this detail prefix. The finding never
#     claims compliance.

# The checks that only make sense when Microsoft Attack Simulation Training is
# the phishing-simulation platform, and the evidence to keep from the
# third-party platform instead.
$script:TPAwarenessChecks = [ordered]@{
    'DEF-4.6' = 'phishing simulation campaigns run regularly and reach every user, and keep the campaign reports (recipients, click and report rates) as evidence'
}

# The detail prefix Get-TPAssessmentScope keys on. Change both together.
$script:TPThirdPartyAwarenessMarker = 'Third-party security awareness declared:'

function Get-TPAwarenessCheckIds {
    [CmdletBinding()] param()
    @($script:TPAwarenessChecks.Keys)
}

function Set-TPThirdPartyAwareness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9 .&()+/-]{1,59}$')]
        [string] $Product,

        # Findings to rewrite in place. Defaults to the module's findings;
        # -FromResults passes the findings it loaded from the results JSON.
        [object[]] $Findings
    )
    Initialize-TPState
    $targets = if ($PSBoundParameters.ContainsKey('Findings')) { @($Findings | Where-Object { $null -ne $_ }) } else { @($script:TPFindings) }
    $changed = 0
    foreach ($f in $targets) {
        $cid = [string](Get-TPObjectField -Item $f -Key 'ControlId' -Default '')
        if (-not $script:TPAwarenessChecks.Contains($cid)) { continue }
        $state = [string](Get-TPObjectField -Item $f -Key 'State' -Default '')
        if ($state -eq 'Satisfied') { continue }
        $before = [string](Get-TPObjectField -Item $f -Key 'Detail' -Default '')
        if ($before.StartsWith($script:TPThirdPartyAwarenessMarker)) { continue }
        # Unwrap license gating's detail to the evaluator's own result.
        if ($before -match 'upgrade opportunity' -and $before -match 'Result before the license check: (\w+)(?: — (.*))?$') {
            $state  = $Matches[1]
            $before = if ($Matches.Count -gt 2 -and $Matches[2]) { $Matches[2] } else { '' }
        }
        $verify = $script:TPAwarenessChecks[$cid]
        $f.State        = 'NotApplicable'
        $f.Severity     = 'Informational'
        $f.Detail       = "$script:TPThirdPartyAwarenessMarker phishing simulation and security awareness training for this client run on $Product, as declared by the assessor. Microsoft 365 cannot see $Product, so this was NOT verified by this assessment and is not scored; this Microsoft Attack Simulation Training check does not apply. Confirm in $Product that $verify. Result of the Microsoft check before the declaration: $state$(if ($before) { " — $before" })"
        $f.CurrentValue = "Run on $Product (declared, not verified)"
        $f.Remediation  = "Confirm in $Product that $verify."
        $changed++
    }
    return $changed
}
