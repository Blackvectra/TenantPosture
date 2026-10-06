#Requires -Version 7.0
#
# Set-NRGThirdPartyEdr.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: When a client's endpoint protection is a third-party EDR (e.g.
#   Cortex XDR), take the checks that assume Microsoft Defender is the
#   endpoint protection out of the score, and say why.
#
# Data keys: none. Operates on the module findings list after evaluation.
# Graph / cmdlets: none.
#
# Microsoft 365 cannot see a third-party EDR, so without this a client
# protected by Cortex reads as "no antivirus policy, no EDR, no ASR rules" —
# a Gap on every Defender check, which is false. The declaration is the
# operator's, not evidence the tool collected, so the rules are:
#   - A check that PASSED keeps its verdict: Defender really is configured,
#     and that is evidence.
#   - The declaration explains ABSENT Defender configuration, never a Defender
#     policy that is assigned and was read as falling short. INT-2.2 with a
#     `Shortfall:` (assigned ASR policies whose required rules were read and
#     are not all in Block mode) keeps its verdict and gains a note: the
#     policy is deployed, so either Defender runs those rules on some devices
#     or the policy is dead configuration, and the declaration answers
#     neither.
#   - Anything else becomes NotApplicable, excluded from the score, with a
#     detail that says the coverage is DECLARED, NOT VERIFIED, names what to
#     confirm in the third-party console, and keeps the original result.
#   - Get-NRGAssessmentScope files these in their own ThirdPartyAttested
#     bucket, so the report states them rather than implying they passed.
#     The finding never claims compliance.

# The checks that only make sense when Microsoft Defender is the endpoint
# protection, and what to confirm in the third-party console instead.
$script:NRGDefenderEndpointChecks = [ordered]@{
    'INT-1.5' = 'an antivirus / malware-prevention policy is assigned to every managed endpoint'
    'INT-2.1' = 'the EDR agent is installed and reporting on every managed endpoint'
    'INT-2.2' = 'exploit and behavioral protection is enabled (Defender attack surface reduction rules do not run while a third-party antivirus is active)'
    'DEV-2.1' = 'real-time malware protection is on for every endpoint'
    'DEV-2.2' = 'agent tamper protection (uninstall protection) is on'
    'DEV-2.3' = 'agent content and signature updates are current'
    'DEV-2.4' = 'cloud-based analysis is enabled'
    'DEV-2.8' = 'every endpoint runs the agent and checks in'
}

# The detail prefix Get-NRGAssessmentScope keys on. Change both together.
$script:NRGThirdPartyEdrMarker = 'Third-party EDR declared:'

# Appended (never prefixed) to an INT-2.2 shortfall the declaration leaves
# scored, so the finding still reads as the evaluator's verdict.
$script:NRGThirdPartyEdrShortfallNote = 'Not excused by the third-party EDR declaration: an assigned ASR policy was read and falls short.'

function Get-NRGDefenderEndpointCheckIds {
    [CmdletBinding()] param()
    @($script:NRGDefenderEndpointChecks.Keys)
}

function Set-NRGThirdPartyEdr {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9 .&()+/-]{1,59}$')]
        [string] $Product,

        # Findings to rewrite in place. Defaults to the module's findings;
        # -FromResults passes the findings it loaded from the results JSON.
        [object[]] $Findings
    )
    Initialize-NRGState
    $targets = if ($PSBoundParameters.ContainsKey('Findings')) { @($Findings | Where-Object { $null -ne $_ }) } else { @($script:NRGFindings) }
    $changed = 0
    foreach ($f in $targets) {
        $cid = [string](Get-NRGObjectField -Item $f -Key 'ControlId' -Default '')
        if (-not $script:NRGDefenderEndpointChecks.Contains($cid)) { continue }
        $state = [string](Get-NRGObjectField -Item $f -Key 'State' -Default '')
        if ($state -eq 'Satisfied') { continue }
        $verify = $script:NRGDefenderEndpointChecks[$cid]
        $before = [string](Get-NRGObjectField -Item $f -Key 'Detail' -Default '')
        if ($cid -eq 'INT-2.2' -and $before -match '\bShortfall:') {
            if ($before -notmatch [regex]::Escape($script:NRGThirdPartyEdrShortfallNote)) {
                $f.Detail = "$before $script:NRGThirdPartyEdrShortfallNote $Product is declared as the endpoint protection: if Microsoft Defender Antivirus is passive on the devices this policy targets, these rules do not run there; confirm which devices run Defender actively, and remove the policy where it does not apply."
            }
            continue
        }
        $f.State        = 'NotApplicable'
        $f.Severity     = 'Informational'
        $f.Detail       = "$script:NRGThirdPartyEdrMarker endpoint protection for this client is provided by $Product, as declared by the assessor. Microsoft 365 cannot see $Product, so this was NOT verified by this assessment and is not scored; this Microsoft Defender check does not apply. Confirm in the $Product console that $verify. Result of the Defender check before the declaration: $state$(if ($before) { " — $before" })"
        $f.CurrentValue = "Covered by $Product (declared, not verified)"
        $f.Remediation  = "Confirm in the $Product console that $verify."
        $changed++
    }
    return $changed
}
