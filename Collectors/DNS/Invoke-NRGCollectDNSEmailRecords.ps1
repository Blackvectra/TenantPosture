#
# Invoke-NRGCollectDNSEmailRecords.ps1
# Collects SPF, DKIM, DMARC, MTA-STS, TLS-RPT, DNSSEC for tenant's accepted domains.
# COLLECTION ONLY - no scoring.
#

# DNS TXT helper - Resolve-DnsName returns .Strings in PS5, .Text in some PS7 versions
$script:GetTxtValue = {
    param($record)
    if ($record.Strings)      { return ($record.Strings -join '') }
    if ($record.Text)         { return ($record.Text -join '') }
    if ($record.TextData)     { return "$($record.TextData)" }
    return "$record"
}

function Invoke-NRGCollectDNSEmailRecords {
    [CmdletBinding()]
    param([string[]] $Domains)

    $result = @{
        Source     = 'DNS-EmailRecords'
        Timestamp  = [DateTime]::UtcNow.ToString('o')
        Success    = $false
        Data       = @{}
        Exceptions = @()
    }

    # Get domains from EXO if not provided
    if (-not $Domains) {
        try {
            $accepted = @(Get-AcceptedDomain -ErrorAction Stop)
            $Domains = @($accepted | Where-Object { $_.DomainName -notlike '*.onmicrosoft.com' } | Select-Object -ExpandProperty DomainName)
        } catch {
            $result.Exceptions += "Could not retrieve accepted domains: $($_.Exception.Message)"
            $Domains = @()
        }
    }

    $domainResults = @{}
    foreach ($domain in $Domains) {
        $d = @{
            Domain  = $domain
            SPF     = $null
            DKIM    = @{ Selector1 = $null; Selector2 = $null }
            DMARC   = $null
            MTASTS  = @{ TxtRecord = $null; Policy = $null }
            TLSRPT  = $null
            DNSSEC  = $false
        }

        # SPF (TXT at apex)
        try {
            $spfRecords = @(Resolve-DnsName -Name $domain -Type TXT -ErrorAction Stop)
            $spfMatch = $spfRecords | Where-Object {
                $val = & $script:GetTxtValue $_
                $val -like 'v=spf1*'
            } | Select-Object -First 1
            if ($spfMatch) { $d.SPF = (& $script:GetTxtValue $spfMatch) }
        } catch { $d.SPF = "[lookup failed: $($_.Exception.Message)]" }

        # DKIM (CNAME at selector1/2._domainkey)
        foreach ($selector in @('selector1','selector2')) {
            try {
                $name = "$selector._domainkey.$domain"
                $cnRecords = @(Resolve-DnsName -Name $name -Type CNAME -ErrorAction Stop)
                $cname = $cnRecords | Where-Object Type -eq 'CNAME' | Select-Object -First 1
                if ($cname) {
                    $target = if ($cname.NameHost)  { $cname.NameHost }
                              elseif ($cname.NameAlias) { $cname.NameAlias }
                              else { '[CNAME]' }
                    $d.DKIM[(Get-Culture).TextInfo.ToTitleCase($selector)] = $target
                }
            } catch { } # DKIM not configured is normal, no error
        }

        # DMARC (TXT at _dmarc subdomain)
        try {
            $dmarcRecords = @(Resolve-DnsName -Name "_dmarc.$domain" -Type TXT -ErrorAction Stop)
            $dmarcMatch = $dmarcRecords | Where-Object {
                $val = & $script:GetTxtValue $_
                $val -like 'v=DMARC1*'
            } | Select-Object -First 1
            if ($dmarcMatch) { $d.DMARC = (& $script:GetTxtValue $dmarcMatch) }
        } catch { $d.DMARC = $null }

        # MTA-STS
        try {
            $mtaStsRecords = @(Resolve-DnsName -Name "_mta-sts.$domain" -Type TXT -ErrorAction Stop)
            $mtaStsMatch = $mtaStsRecords | Where-Object {
                $val = & $script:GetTxtValue $_
                $val -like 'v=STSv1*'
            } | Select-Object -First 1
            if ($mtaStsMatch) { $d.MTASTS.TxtRecord = (& $script:GetTxtValue $mtaStsMatch) }
        } catch { }

        # MTA-STS policy file (HTTPS)
        try {
            $stsUrl = "https://mta-sts.$domain/.well-known/mta-sts.txt"
            $stsContent = Invoke-WebRequest -Uri $stsUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
            $d.MTASTS.Policy = $stsContent.Content
        } catch { }

        # TLS-RPT
        try {
            $tlsRptRecords = @(Resolve-DnsName -Name "_smtp._tls.$domain" -Type TXT -ErrorAction Stop)
            $tlsRptMatch = $tlsRptRecords | Where-Object {
                $val = & $script:GetTxtValue $_
                $val -like 'v=TLSRPTv1*'
            } | Select-Object -First 1
            if ($tlsRptMatch) { $d.TLSRPT = (& $script:GetTxtValue $tlsRptMatch) }
        } catch { }

        # DNSSEC (presence of DS or RRSIG records)
        try {
            $dsRecords = @(Resolve-DnsName -Name $domain -Type DS -ErrorAction SilentlyContinue)
            if ($dsRecords.Count -gt 0) { $d.DNSSEC = $true }
        } catch { }

        $domainResults[$domain] = $d
    }

    $result.Data['Domains']  = $domainResults
    $result.Data['DomainCount'] = $Domains.Count
    $result.Success = $true
    Register-NRGCoverage -Family 'DNS-EmailRecords' -Status 'Collected'

    Set-NRGRawData -Key 'DNS-EmailRecords' -Data $result
    return $result
}
