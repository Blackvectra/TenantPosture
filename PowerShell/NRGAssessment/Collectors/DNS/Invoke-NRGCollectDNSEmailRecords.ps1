#
# Invoke-NRGCollectDNSEmailRecords.ps1
# Collects SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC for accepted domains.
# COLLECTION ONLY - no scoring.
#
# PS7 compatibility: Resolve-DnsName returns .Strings OR .Text depending on module version.
# Uses PSObject.Properties check to avoid StrictMode PropertyNotFoundException.
#

function Invoke-NRGCollectDNSEmailRecords {
    [CmdletBinding()]
    param(
        [string[]] $Domains,
        # Public DNS servers - bypasses corporate DNS that may block external TXT lookups
        # Falls back to machine default if all public servers fail
        [string[]] $DnsServers = @('8.8.8.8', '1.1.1.1', '9.9.9.9')
    )

    $result = @{
        Source     = 'DNS-EmailRecords'
        Timestamp  = [DateTime]::UtcNow.ToString('o')
        Success    = $false
        Data       = @{}
        Exceptions = @()
    }

    # DNS resolver with public server fallback
    function Resolve-DnsWithFallback {
        param([string]$Name, [string]$Type = 'TXT')
        foreach ($server in $DnsServers) {
            try {
                $r = @(Resolve-DnsName -Name $Name -Type $Type -Server $server -ErrorAction Stop)
                if ($r.Count -gt 0) { return $r }
            } catch { }
        }
        # Fallback to machine default DNS
        try { return @(Resolve-DnsName -Name $Name -Type $Type -ErrorAction Stop) } catch { return @() }
    }

    # Safe TXT value extractor - handles .Strings (PS5/older) and .Text (PS7/newer)
    # Uses PSObject.Properties to avoid StrictMode throws
    function Get-TxtValue {
        param($record)
        if ($null -eq $record) { return $null }
        $props = $record.PSObject.Properties.Name
        if ('Strings'  -in $props -and $null -ne $record.Strings)  { return ($record.Strings  -join '') }
        if ('Text'     -in $props -and $null -ne $record.Text)      { return ($record.Text     -join '') }
        if ('TextData' -in $props -and $null -ne $record.TextData)  { return "$($record.TextData)" }
        if ('Data'     -in $props -and $null -ne $record.Data)      { return "$($record.Data)" }
        return $null
    }

    # Get domains from EXO accepted domains if not supplied
    if (-not $Domains -or $Domains.Count -eq 0) {
        try {
            $accepted = @(Get-AcceptedDomain -ErrorAction Stop)
            $Domains  = @($accepted |
                Where-Object { $_.DomainName -notlike '*.onmicrosoft.com' } |
                Select-Object -ExpandProperty DomainName)
        } catch {
            $result.Exceptions += "GetAcceptedDomains: $($_.Exception.Message)"
        }
    }

    $domainResults = @{}

    foreach ($domain in $Domains) {
        $d = @{
            Domain = $domain
            SPF    = $null
            DKIM   = @{ Selector1 = $null; Selector2 = $null }
            DMARC  = $null
            MTASTS = @{ TxtRecord = $null; Policy = $null; Mode = $null }
            TLSRPT = $null
            DNSSEC = $false
        }

        # ── SPF ───────────────────────────────────────────────────────────────
        try {
            $spfRecs = @(Resolve-DnsWithFallback -Name $domain -Type 'TXT')
            $spfMatch = $spfRecs | Where-Object {
                $val = Get-TxtValue $_
                $null -ne $val -and $val -like 'v=spf1*'
            } | Select-Object -First 1
            if ($spfMatch) { $d.SPF = Get-TxtValue $spfMatch }
        } catch {
            # SPF lookup failure is non-fatal
            $result.Exceptions += "SPF-$domain`: $($_.Exception.Message)"
        }

        # ── DKIM (selector1 + selector2) ──────────────────────────────────────
        foreach ($selector in @('selector1','selector2')) {
            try {
                $cnRecs = @(Resolve-DnsWithFallback -Name "$selector._domainkey.$domain" -Type 'CNAME')
                $cname  = $cnRecs | Where-Object {
                    $props = $_.PSObject.Properties.Name
                    'Type' -in $props -and $_.Type -eq 'CNAME'
                } | Select-Object -First 1
                if (-not $cname) { $cname = $cnRecs | Select-Object -First 1 }
                if ($cname) {
                    $props  = $cname.PSObject.Properties.Name
                    $target = if ('NameHost'  -in $props) { $cname.NameHost }
                              elseif ('NameAlias' -in $props) { $cname.NameAlias }
                              else { "$cname" }
                    $key = if ($selector -eq 'selector1') { 'Selector1' } else { 'Selector2' }
                    $d.DKIM[$key] = $target
                }
            } catch { } # DKIM not configured is normal
        }

        # ── DMARC ─────────────────────────────────────────────────────────────
        try {
            $dmarcRecs = @(Resolve-DnsWithFallback -Name "_dmarc.$domain" -Type 'TXT')
            $dmarcMatch = $dmarcRecs | Where-Object {
                $val = Get-TxtValue $_
                $null -ne $val -and $val -like 'v=DMARC1*'
            } | Select-Object -First 1
            if ($dmarcMatch) { $d.DMARC = Get-TxtValue $dmarcMatch }
        } catch { }

        # ── MTA-STS TXT record ────────────────────────────────────────────────
        try {
            $stsRecs = @(Resolve-DnsWithFallback -Name "_mta-sts.$domain" -Type 'TXT')
            $stsMatch = $stsRecs | Where-Object {
                $val = Get-TxtValue $_
                $null -ne $val -and $val -like 'v=STSv1*'
            } | Select-Object -First 1
            if ($stsMatch) {
                $d.MTASTS.TxtRecord = Get-TxtValue $stsMatch
                # Parse mode from policy file
                $stsUrl = "https://mta-sts.$domain/.well-known/mta-sts.txt"
                try {
                    $policy = Invoke-WebRequest -Uri $stsUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
                    $d.MTASTS.Policy = $policy.Content
                    if ($policy.Content -match 'mode:\s*(\S+)') { $d.MTASTS.Mode = $Matches[1].Trim() }
                } catch { }
            }
        } catch { }

        # ── TLS-RPT ───────────────────────────────────────────────────────────
        try {
            $tlsRecs = @(Resolve-DnsWithFallback -Name "_smtp._tls.$domain" -Type 'TXT')
            $tlsMatch = $tlsRecs | Where-Object {
                $val = Get-TxtValue $_
                $null -ne $val -and $val -like 'v=TLSRPTv1*'
            } | Select-Object -First 1
            if ($tlsMatch) { $d.TLSRPT = Get-TxtValue $tlsMatch }
        } catch { }

        # ── DNSSEC ────────────────────────────────────────────────────────────
        try {
            $dsRecs = @(Resolve-DnsWithFallback -Name $domain -Type 'DS')
            if ($dsRecs.Count -gt 0) { $d.DNSSEC = $true }
        } catch { }

        $domainResults[$domain] = $d
    }

    $result.Data['Domains']     = $domainResults
    $result.Data['DomainCount'] = $Domains.Count
    $result.Success = $true
    Register-NRGCoverage -Family 'DNS-EmailRecords' -Status 'Collected'
    Set-NRGRawData -Key 'DNS-EmailRecords' -Data $result
    return $result
}
