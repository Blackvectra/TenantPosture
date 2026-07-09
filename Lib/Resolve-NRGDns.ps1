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
        [int] $TimeoutSeconds = 6
    )

    Set-StrictMode -Version Latest

    # DoH numeric type codes (RFC 1035 / 6844).
    $typeCode = @{ A = 1; NS = 2; SOA = 6; CNAME = 5; MX = 15; TXT = 16; AAAA = 28; DS = 43; CAA = 257 }[$Type]

    # ── DoH against public resolvers (inline; no inner scriptblock so variable
    #    scoping is unambiguous). Cloudflare first, then Google. ───────────────
    foreach ($baseUrl in @('https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve')) {
        try {
            $uri  = "${baseUrl}?name=$([uri]::EscapeDataString($Name))&type=$Type"
            $resp = Invoke-RestMethod -Uri $uri -Headers @{ accept = 'application/dns-json' } `
                        -TimeoutSec $TimeoutSeconds -ErrorAction Stop
            # Status 0 = NoError (Answer may still be empty = record absent);
            # Status 3 = NXDOMAIN. Either way return whatever matched (possibly none).
            if ($null -eq $resp -or -not $resp.PSObject.Properties['Answer']) { return @() }
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
            return @($recs | ForEach-Object {
                if ($Type -eq 'TXT') {
                    $s = $_.PSObject.Properties['Strings']
                    if ($s) { -join @($s.Value) } else { $null }
                } elseif ($_.PSObject.Properties['NameHost']) { [string]$_.NameHost }
                elseif ($_.PSObject.Properties['NameExchange']) { [string]$_.NameExchange }
                else { [string]$_ }
            } | Where-Object { $_ })
        } catch {
            return @()
        }
    }

    return @()
}
