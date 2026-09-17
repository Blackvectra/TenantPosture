#Requires -Version 7.0
#
# Resolve-NRGDns.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: resolve public DNS records reliably from any host, for the DNS
#   email-auth controls (SPF/DKIM/DMARC/MTA-STS/TLS-RPT/CAA/DNSSEC).
#
# Why not Resolve-DnsName: three real defects observed on a client run —
#   1) it queries the MACHINE'S LOCAL resolver, which on a corporate / split-DNS
#      network returns NXDOMAIN for external _dmarc / _domainkey records that
#      resolve fine on public DNS (false "no DMARC / no DKIM");
#   2) TXT answers can arrive as objects without a .Strings property, throwing
#      "The property 'Strings' cannot be found" and losing a record that WAS
#      returned (false "no SPF");
#   3) older Windows DnsClient modules don't know the CAA record type and throw
#      "Cannot convert value 'CAA' to type RecordType".
#   It is also Windows-only, so DNS silently produced nothing off-Windows.
#
# This helper uses DNS-over-HTTPS against PUBLIC resolvers (Cloudflare, then
# Google) so the answer is independent of the client's resolver, works on every
# OS, supports every record type, and returns a stable string shape. If both DoH
# providers are unreachable it falls back to Resolve-DnsName pinned to a public
# server (1.1.1.1) where that cmdlet exists.
#
# Dependencies: (none — self-contained; optional Resolve-DnsName fallback)
#
# Outbound: https://cloudflare-dns.com , https://dns.google (DoH JSON API).

function Resolve-NRGDns {
    [CmdletBinding()]
    [OutputType([string[]])]
    param(
        [Parameter(Mandatory)] [string] $Name,
        [Parameter(Mandatory)]
        [ValidateSet('A','AAAA','TXT','CNAME','MX','CAA','DS','NS','SOA')]
        [string] $Type,
        [int] $TimeoutSeconds = 6,

        # Receives 'Answered' / 'NoRecord' / 'LookupFailed'.
        #
        # An empty return is ambiguous exactly the way an empty collector
        # section is: it can mean "the name genuinely has no record of this
        # type" or "every resolver we asked failed". For DNS that difference
        # decides a client-facing verdict — an absent SPF/DMARC record is a
        # Gap, so a failed lookup reported as absent tells a client their
        # email authentication is missing when it is not.
        #
        # Optional, so every existing caller keeps its current behaviour.
        [ref] $Outcome
    )

    Set-StrictMode -Version Latest

    $setOutcome = {
        param([string] $State)
        if ($null -ne $Outcome) { $Outcome.Value = $State }
    }
    & $setOutcome 'LookupFailed'

    # DoH Status codes we treat as an AUTHORITATIVE "no such record":
    #   0 NoError  — name resolves; an absent Answer means NODATA for this type
    #   3 NXDOMAIN — name does not exist
    # Anything else (2 SERVFAIL, 5 REFUSED, …) means the resolver could not
    # answer, which is not evidence of absence — fall through to the next
    # provider rather than reporting "no record".
    $authoritativeNoRecord = @(0, 3)

    # DoH numeric type codes (RFC 1035 / 6844).
    $typeCode = @{ A = 1; NS = 2; SOA = 6; CNAME = 5; MX = 15; TXT = 16; AAAA = 28; DS = 43; CAA = 257 }[$Type]

    # ── DoH against public resolvers (inline; no inner scriptblock so variable
    #    scoping is unambiguous). Cloudflare first, then Google. ───────────────
    foreach ($baseUrl in @('https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve')) {
        try {
            $uri  = "${baseUrl}?name=$([uri]::EscapeDataString($Name))&type=$Type"
            $resp = Invoke-RestMethod -Uri $uri -Headers @{ accept = 'application/dns-json' } `
                        -TimeoutSec $TimeoutSeconds -ErrorAction Stop
            if ($null -eq $resp) { continue }

            # Read Status. Previously it was only described in a comment and
            # never consulted, so a SERVFAIL — which Cloudflare returns as
            # HTTP 200 with a Status of 2 and no Answer — was indistinguishable
            # from NXDOMAIN, AND the bare `return` short-circuited the Google
            # fallback and the Resolve-DnsName fallback beneath it. One failing
            # resolver therefore produced a confident "no DMARC record".
            $statusProp = $resp.PSObject.Properties['Status']
            $status = if ($statusProp) { [int]$statusProp.Value } else { $null }
            if ($null -ne $status -and $status -notin $authoritativeNoRecord) {
                continue   # not an answer — ask the next provider
            }

            if (-not $resp.PSObject.Properties['Answer']) {
                # Status 0 with no Answer is NODATA; Status 3 is NXDOMAIN.
                # Both are real answers meaning "no record of this type".
                & $setOutcome 'NoRecord'
                return @()
            }
            $out = @($resp.Answer | Where-Object { $_.type -eq $typeCode } | ForEach-Object {
                $data = [string]$_.data
                if ($Type -eq 'TXT') {
                    # TXT data arrives as one or more quoted segments, e.g.
                    # "v=spf1 ..." or "part1" "part2". Join the segment contents.
                    $segs = [regex]::Matches($data, '"([^"]*)"')
                    if ($segs.Count -gt 0) { -join ($segs | ForEach-Object { $_.Groups[1].Value }) }
                    else { $data.Trim('"') }
                } else {
                    $data
                }
            })
            # An Answer that contained no record of the requested type (e.g. a
            # CNAME-only chain) is still a real answer: no record of this type.
            & $setOutcome $(if (@($out).Count -gt 0) { 'Answered' } else { 'NoRecord' })
            return @($out)
        } catch {
            continue   # try the next provider
        }
    }

    # ── Fallback: Resolve-DnsName pinned to a PUBLIC resolver (never the local
    #    one). Only where the cmdlet exists; CAA is skipped if the module's enum
    #    doesn't know it. ─────────────────────────────────────────────────────
    if (Get-Command Resolve-DnsName -ErrorAction SilentlyContinue) {
        try {
            $recs = @(Resolve-DnsName -Name $Name -Type $Type -Server '1.1.1.1' -DnsOnly -ErrorAction Stop)
            $fallback = @($recs | ForEach-Object {
                if ($Type -eq 'TXT') {
                    $s = $_.PSObject.Properties['Strings']
                    if ($s) { -join @($s.Value) } else { $null }
                } elseif ($_.PSObject.Properties['NameHost']) { [string]$_.NameHost }
                elseif ($_.PSObject.Properties['NameExchange']) { [string]$_.NameExchange }
                else { [string]$_ }
            } | Where-Object { $_ })
            & $setOutcome $(if ($fallback.Count -gt 0) { 'Answered' } else { 'NoRecord' })
            return @($fallback)
        } catch {
            # Resolve-DnsName throws on NXDOMAIN as well as on a genuine
            # failure, and the exception does not reliably distinguish them.
            # Leave the outcome as LookupFailed: claiming "no record" from an
            # error we cannot read is the guess this whole change removes.
            & $setOutcome 'LookupFailed'
            return @()
        }
    }

    # Every provider failed and Resolve-DnsName is unavailable.
    & $setOutcome 'LookupFailed'
    return @()
}
