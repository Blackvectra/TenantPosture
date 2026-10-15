#Requires -Version 7.0
#
# Resolve-TPExoRecipient.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Resolves the identifier an inbox rule or a forwarding setting carries to
# the directory object it names, and tells apart "the directory holds no
# such object" from "the directory could not be asked".
#
# Sets:     nothing (pure function over the command the caller passes)
# Consumes: nothing
# Cmdlets:  Get-Recipient (read-only), only through the injected command.
#
# THE CONTRACT: THREE ANSWERS, NEVER TWO
# --------------------------------------
# Resolve-TPExoRecipient returns:
#   an object  the directory holds a recipient for the identifier;
#   $null      the directory ANSWERED and holds none. For a legacy Exchange
#              DN that means no object carries it as LegacyExchangeDN (the
#              Identity lookup) and none carries it as an X500 proxy address
#              (the Filter lookup), the two attributes Exchange routes a
#              legacy DN by, so mail to it is not delivered (IMCEAEX NDR,
#              5.1.1);
#   a throw    the directory could not be asked: no Exchange Online session,
#              the session is gone, throttling, an identifier refused before
#              it reached the directory, or a failure whose shape is not the
#              documented not-found error.
#
# The second and third used to be one answer, 'Unresolved', and the
# classifier turned any such recipient into "not assessed" on EXO-7.2. A
# tenant whose only unresolvable rule recipients are former employees (a
# deleted mailbox, a pre-migration organization that no object maps to)
# therefore never reached a verdict on the primary BEC persistence check,
# run after run. The distinction is what ends that.
#
# WHAT COUNTS AS "NOT FOUND"
# --------------------------
# Only the Exchange not-found error, recognized by its type name
# ManagementObjectNotFoundException in the error id, the exception chain
# or the message (the Exchange Online module renders server errors as
# `|Type|Message`). The error CATEGORY is not consulted: ObjectNotFound is
# also what a missing command reports, and reading that as "no such
# recipient" would turn a broken session into a clean finding. A failure
# the test does not recognize stays a throw, so the recipient stays
# Unresolved and the control stays not assessed, which is the only honest
# answer to a read that failed.

function Test-TPExoNotFoundError {
    <#
    .SYNOPSIS
        True when an error record is Exchange's "object couldn't be found".
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [object] $ErrorRecord
    )

    if ($null -eq $ErrorRecord) { return $false }
    $texts = [System.Collections.Generic.List[string]]::new()
    $fq = [string](Get-TPObjectField -Item $ErrorRecord -Key 'FullyQualifiedErrorId' -Default '')
    if ($fq) { $texts.Add($fq) }
    $ex = Get-TPObjectField -Item $ErrorRecord -Key 'Exception' -Default $null
    if ($null -eq $ex -and $ErrorRecord -is [System.Exception]) { $ex = $ErrorRecord }
    $depth = 0
    while ($null -ne $ex -and $depth -lt 8) {
        $texts.Add($ex.GetType().FullName)
        $msg = [string](Get-TPObjectField -Item $ex -Key 'Message' -Default '')
        if ($msg) { $texts.Add($msg) }
        $ex = Get-TPObjectField -Item $ex -Key 'InnerException' -Default $null
        $depth++
    }
    # Two shapes. The RPS-era module renders the server error as |Type|Message
    # and puts the exception type in the FailureCategory of the error id. The
    # REST-backed cmdlets of module 3.x render it as ||Message with the type
    # BLANK (2026-10-15 live run), so the only not-found evidence left is
    # Exchange's own sentence: "The operation couldn't be performed because
    # object '<id>' couldn't be found on '<server>'." That sentence belongs to
    # ManagementObjectNotFoundException alone; a folder, a command or a server
    # error is worded differently and stays "could not ask".
    $rsq = [string][char]0x2019   # the typographic apostrophe Exchange uses; built from its code point, never typed into a script
    $notFoundSentence = "couldn['$rsq]t be performed because object .+ couldn['$rsq]t be found"
    foreach ($t in $texts) {
        if ($t -match 'ManagementObjectNotFoundException') { return $true }
        if ($t -match $notFoundSentence) { return $true }
    }
    return $false
}

function Resolve-TPExoRecipient {
    <#
    .SYNOPSIS
        Resolves a recipient identifier through Get-Recipient; $null only when
        the directory answered that no object carries it; throws when it
        could not be asked.
    #>
    [CmdletBinding()]
    [OutputType([object])]
    param(
        # The identifier: a legacy Exchange DN (the body of `[EX:...]`) or a
        # display name / alias Exchange rendered with no address.
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Lookup,

        # Get-Recipient as Get-TPExoCommand resolved it for the Exchange Online
        # session. $null means there is no session to ask.
        [AllowNull()]
        [object] $Command
    )

    if (-not $Command) { throw 'Get-Recipient is not available: no Exchange Online session.' }
    $id = [string]$Lookup
    if ([string]::IsNullOrWhiteSpace($id)) { throw 'The recipient identifier is blank.' }
    # A reviewer must see what was sent to the directory; an identifier that
    # carries a control, format or line-separator character is refused
    # before it becomes a filter string.
    if ($id -match '[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]') {
        throw 'The recipient identifier holds a control or format character and was not sent to the directory.'
    }
    $isLegacyDn = ($id -match '^(?i)/o=')

    $notFound      = $false
    $identityError = $null
    try {
        $hit = @(& $Command -Identity $id -ErrorAction Stop | Where-Object { $null -ne $_ } | Select-Object -First 1)
        if ($hit.Count -gt 0) { return $hit[0] }
        $notFound = $true
    } catch {
        if (Test-TPExoNotFoundError -ErrorRecord $_) { $notFound = $true } else { $identityError = $_ }
    }

    if (-not $isLegacyDn) {
        if ($notFound) { return $null }
        throw $identityError
    }

    # A legacy DN that no object carries as LegacyExchangeDN can still be
    # routed: Exchange also matches it against X500 proxy addresses, which is
    # Microsoft's own fix for the IMCEAEX NDR after a migration. An object
    # found this way is classified by its address like any other; only when
    # this lookup also returns nothing has the directory said "no object".
    # The filter is asked even when the Identity lookup failed for a reason
    # other than not-found, because a hit here is evidence either way.
    $filter = "EmailAddresses -eq 'X500:$($id -replace "'", "''")'"
    $x500 = @(& $Command -Filter $filter -ResultSize 1 -ErrorAction Stop | Where-Object { $null -ne $_ })
    if ($x500.Count -gt 0) { return $x500[0] }
    if ($notFound) { return $null }
    throw $identityError
}
