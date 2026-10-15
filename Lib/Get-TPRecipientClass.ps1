#Requires -Version 7.0
#
# Get-TPRecipientClass.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Classifies a mail recipient string as External / Internal / Orphaned /
# Unresolved against the tenant's accepted-domain set.
#
# Sets:     nothing (pure function)
# Consumes: nothing (callers pass the accepted-domain list)
# Cmdlets:  Get-Recipient (read-only), only via the injected resolver.
#
# WHY THIS IS ITS OWN FILE
# ------------------------
# This parser lived inline in Invoke-TPCollectEXOInventory and had no test
# coverage, because every fixture fed the evaluators a pre-computed IsExternal
# flag and never exercised the parser at all. It was wrong for the single most
# common real input and looked correct for a year.
#
# Exchange renders rule recipients as:
#     "Display Name" [SMTP:user@dom.tld]      <- the address appears TWICE
#     "Display Name" [EX:/o=ExchangeLabs/...] <- legacy DN, no address at all
# while ForwardingSmtpAddress is a bare  smtp:user@dom.tld.
#
# The original did  ($addr -split '@').Count -ne 2  and returned "internal" on
# anything else. The bracketed SMTP form has two '@' and therefore three parts,
# so EVERY genuine external rule recipient was classified internal. Mailbox
# forwarding parsed correctly only by luck of having one '@'.
#
# THE TRI-STATE IS THE POINT
# --------------------------
# A boolean collapses "known internal" and "could not tell" into the same
# answer, and the safe-looking one. A legacy DN can be an in-tenant user or a
# mail contact that resolves somewhere external, and the string cannot say
# which. 'Unresolved' keeps that distinction so the evaluator can report
# NotApplicable instead of a clean bill of health — the same rule SectionStatus
# applies to an empty list.
#
# ORPHANED IS NOT UNRESOLVED
# --------------------------
# 'Unresolved' used to cover two different facts: the directory could not be
# asked, and the directory was asked and holds no such object. The second is
# an answer. A legacy DN that no object carries (as LegacyExchangeDN or as an
# X500 proxy address, the two attributes Exchange routes it by) is a former
# employee or a pre-migration identity: mail the rule forwards to it is not
# delivered, so it is not an external forward, and it is not a blind spot
# either. Filing it as Unresolved made EXO-7.2 "not assessed" on every run of
# a tenant with one deleted mailbox in an old rule, for months. 'Orphaned' is
# that answer, and it is given ONLY for the legacy-DN form and ONLY when the
# resolver returned $null (its contract: the directory answered). A resolver
# that threw, or a bare display name the directory did not know (a name is
# not an identifier), stays Unresolved.

function Get-TPRecipientClass {
    [CmdletBinding()]
    param(
        # The raw recipient string exactly as Exchange returned it.
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Recipient,

        # Accepted domains for the tenant, lower-cased. Anything outside this
        # set is external.
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [string[]] $AcceptedDomains,

        # Optional memo across calls. Resolution costs an EXO round trip and
        # the same recipient recurs across mailboxes.
        [hashtable] $Cache,

        # Resolver for legacy DNs and unparseable names. Takes the lookup
        # string and returns an object with ExternalEmailAddress /
        # PrimarySmtpAddress; returns $null ONLY when the directory answered
        # that no object carries the identifier (Resolve-TPExoRecipient's
        # contract); THROWS when the directory could not be asked. Injected so
        # this is testable without a live Exchange session.
        [scriptblock] $Resolver
    )

    if ([string]::IsNullOrWhiteSpace($Recipient)) { return 'Internal' }
    if ($Cache -and $Cache.ContainsKey($Recipient)) { return $Cache[$Recipient] }

    $domains = @($AcceptedDomains | ForEach-Object { ([string]$_).ToLowerInvariant().Trim() } |
                 Where-Object { $_ })

    # Returns $true / $false, or $null when the string is not an address shape.
    $addressIsExternal = {
        param([string] $Address)
        $a = ([string]$Address).Trim()
        $a = $a -replace '^(?i)\s*smtp:\s*', ''
        $a = $a.Trim('"', '<', '>', ' ')
        $parts = $a -split '@'
        if ($parts.Count -ne 2) { return $null }
        $domain = $parts[1].ToLowerInvariant().Trim()
        if ([string]::IsNullOrWhiteSpace($domain)) { return $null }
        return ($domains -notcontains $domain)
    }

    $raw        = $Recipient.Trim()
    $verdict    = $null
    $orphaned   = $false
    $isLegacyDn = ($raw -match '\[EX:([^\]]+)\]')
    $legacyDn   = if ($isLegacyDn) { $Matches[1] } else { '' }

    if ($raw -match '\[SMTP:([^\]]+)\]') {
        # Bracketed form — the authoritative address is inside the brackets,
        # never the display half, which may itself contain an '@'.
        $verdict = & $addressIsExternal $Matches[1]
    } elseif ($raw -notmatch '\[EX:') {
        $verdict = & $addressIsExternal $raw
    }

    if ($null -eq $verdict -and $Resolver) {
        $lookup = if ($isLegacyDn) { $legacyDn } else { $raw.Trim('"', ' ') }
        if (-not [string]::IsNullOrWhiteSpace($lookup)) {
            try {
                $rcpt = & $Resolver $lookup
                if ($rcpt) {
                    # ExternalEmailAddress first: on a MailUser the primary
                    # address can be in-tenant while mail actually leaves to
                    # the external one. Taking the primary first would call
                    # that internal.
                    $target = [string](Get-TPObjectField -Item $rcpt -Key 'ExternalEmailAddress' -Default '')
                    if ([string]::IsNullOrWhiteSpace($target)) {
                        $target = [string](Get-TPObjectField -Item $rcpt -Key 'PrimarySmtpAddress' -Default '')
                    }
                    $verdict = & $addressIsExternal $target
                } elseif ($isLegacyDn) {
                    # The directory answered: no object carries this DN. Only
                    # the legacy-DN form earns this; a display name the
                    # directory does not know proves nothing about delivery.
                    $orphaned = $true
                }
            } catch {
                # Could not ask. Not an answer, so not Orphaned.
                $verdict  = $null
                $orphaned = $false
            }
        }
    }

    $label = if ($null -ne $verdict) { if ($verdict) { 'External' } else { 'Internal' } }
             elseif ($orphaned) { 'Orphaned' }
             else { 'Unresolved' }
    if ($Cache) { $Cache[$Recipient] = $label }
    return $label
}
