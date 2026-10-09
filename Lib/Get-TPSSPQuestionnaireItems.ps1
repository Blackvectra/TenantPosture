#Requires -Version 7.0
#
# Get-TPSSPQuestionnaireItems.ps1
# Dependencies: Get-TPObjectField, Get-TPSSPPosture output.
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: Picks the SSP posture rows that still need a human answer and
#          shapes each into a question, for Publish-TPSSPQuestionnaire to
#          render as a fillable client questionnaire.
#
#          "Still needs a human answer" is Confidence -ne 'Tool-verified' —
#          the same three states Get-TPSSPPosture already computes
#          (Attestation only / No evidence collected / Partial evidence).
#          A Tool-verified row is left out on purpose: re-asking a question
#          the assessment already evidenced would invite the client to
#          overwrite a finding with a guess, which is exactly what the SSP
#          honesty rules in Get-TPSSPPosture.ps1 exist to prevent. A row
#          that already carries a client-attested answer is NOT excluded —
#          it is included with its current answer pre-filled, because an
#          attested status still needs periodic re-attestation and this is
#          also the tool's only way to let a client review and update one.
#
#          The question text is the NIST requirement Statement verbatim,
#          never an invented per-requirement question — SP 800-171 Rev 2
#          already states each requirement in plain, testable language, and
#          paraphrasing it risks asking something subtly different from what
#          the framework actually requires.
#
# Inputs:  -Posture  the [ordered] hashtable from Get-TPSSPPosture.
#          -Family   optional filter to one 800-171 family (e.g. '3.9'), so a
#                     questionnaire can be sent to the person who actually
#                     owns that domain (HR for 3.9, facilities for 3.10)
#                     instead of handing everyone all 110 rows.
#
# Outputs: array of [ordered] hashtables, one per item needing an answer.
#          Always an array, never $null, even when nothing qualifies.
#
# Consumes: Get-TPSSPPosture output only. No Graph, no EXO, no network.
#

function Get-TPSSPQuestionnaireItems {
    [CmdletBinding()]
    [OutputType([object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.Specialized.OrderedDictionary] $Posture,

        [Parameter(Mandatory = $false)]
        [AllowNull()] [AllowEmptyString()]
        [string] $Family
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # Built with a generic List and returned via .ToArray() throughout — never
    # `$x = if (...) { @(...) } else { @() }`, which assigns $null instead of
    # an empty array when the branch taken yields one, and would throw under
    # StrictMode the first time a caller reads .Count on a tenant with nothing
    # left to ask.
    $items = [System.Collections.Generic.List[object]]::new()

    $available = $false
    if ($Posture -and $Posture.Contains('Available')) { $available = [bool]$Posture['Available'] }
    if (-not $available) { return $items.ToArray() }

    foreach ($r in @(Get-TPObjectField -Item $Posture -Key 'Requirements' -Default @())) {
        $confidence = [string](Get-TPObjectField -Item $r -Key 'Confidence' -Default '')
        if ($confidence -eq 'Tool-verified') { continue }

        $fam = [string](Get-TPObjectField -Item $r -Key 'Family' -Default '')
        if ($Family -and $fam -ne $Family) { continue }

        $poam = Get-TPObjectField -Item $r -Key 'Poam' -Default $null

        $items.Add([ordered]@{
            Id                   = [string](Get-TPObjectField -Item $r -Key 'Id' -Default '')
            Family               = $fam
            FamilyTitle          = [string](Get-TPObjectField -Item $r -Key 'FamilyTitle' -Default '')
            Question             = [string](Get-TPObjectField -Item $r -Key 'Statement' -Default '')
            Confidence           = $confidence
            EvidenceStatus       = [string](Get-TPObjectField -Item $r -Key 'EvidenceStatus' -Default '')
            CurrentStatus        = [string](Get-TPObjectField -Item $r -Key 'Status' -Default '')
            CurrentStatusSource  = [string](Get-TPObjectField -Item $r -Key 'StatusSource' -Default '')
            CurrentNarrative     = [string](Get-TPObjectField -Item $r -Key 'Narrative' -Default '')
            CurrentRole          = [string](Get-TPObjectField -Item $r -Key 'ResponsibleRole' -Default '')
            CurrentNaReason      = [string](Get-TPObjectField -Item $r -Key 'NotApplicableReason' -Default '')
            CurrentInheritedFrom = [string](Get-TPObjectField -Item $r -Key 'InheritedFrom' -Default '')
            CurrentPoamWeakness  = if ($null -ne $poam) { [string](Get-TPObjectField -Item $poam -Key 'Weakness' -Default '') } else { '' }
            CurrentPoamRemedy    = if ($null -ne $poam) { [string](Get-TPObjectField -Item $poam -Key 'Remedy'   -Default '') } else { '' }
            CurrentPoamOwner     = if ($null -ne $poam) { [string](Get-TPObjectField -Item $poam -Key 'Owner'    -Default '') } else { '' }
            CurrentPoamDueDate   = if ($null -ne $poam) { [string](Get-TPObjectField -Item $poam -Key 'DueDate'  -Default '') } else { '' }
        })
    }

    return $items.ToArray()
}
