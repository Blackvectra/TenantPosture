#Requires -Version 7.0
#
# New-TPProfile.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Purpose: Create and list profiles. A profile (Config/profiles/<name>.psd1)
#   holds one practice's data: company name and contact for the reports,
#   colors, the default report framework, the DMARC reporting address, the
#   EDR and awareness platforms declared across its clients, monitoring
#   addresses and rates. It changes nothing about what is assessed or how it
#   is scored. Anyone can make one; the NRG and NLS profiles ship as examples.
#
# Data keys: none. Graph / cmdlets: none (writes one data file).
#
# The file is data only, written as single-quoted PSD1 (quotes doubled) and
# read back with Import-PowerShellDataFile before it replaces anything, the
# same atomic, verified write the baseline exceptions use. A profile name is
# a short lower-case token, never a path: the loader in TenantPosture.psm1
# builds the path from the name, so nothing here may let a name carry one.

$script:TPProfileNamePattern = '\A[a-z0-9][a-z0-9-]{0,31}\z'
$script:TPProfileKeys = @(
    'CompanyName', 'Phone', 'Website', 'Email', 'Address', 'CityStateZip',
    'PrimaryColor', 'SecondaryColor', 'AccentColor', 'LogoUrl',
    'DefaultFramework', 'DmarcReportingAddresses', 'EdrStack', 'AwarenessStack',
    'MonitoringAddresses', 'HourlyRate', 'AssessmentFee', 'RegulatedFee', 'GovernanceFee'
)

function Get-TPProfileDirectory {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    Join-Path (Split-Path -Parent $PSScriptRoot) 'Config' 'profiles'
}

function ConvertTo-TPProfilePsd1 {
    <#
    .SYNOPSIS
        Renders a profile as a data-only PSD1 document: strings single-quoted
        with quotes doubled, lists as @('a', 'b'), numbers bare.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [System.Collections.IDictionary] $Data)
    $q = { param([string] $v) ConvertTo-TPPsd1String -Value ($v ?? '') }
    $lit = {
        param($v)
        if ($v -is [int] -or $v -is [long] -or $v -is [double] -or $v -is [decimal]) { return [string]$v }
        if ($v -is [array] -or $v -is [System.Collections.IList]) {
            $items = @($v | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_) } | ForEach-Object { & $q ([string]$_).Trim() })
            return '@(' + ($items -join ', ') + ')'
        }
        return & $q ([string]$v)
    }
    $sb = [System.Text.StringBuilder]::new()
    $null = $sb.AppendLine('@{')
    $null = $sb.AppendLine('    # TenantPosture profile: one practice''s data for the reports. Written by')
    $null = $sb.AppendLine('    # New-TPProfile; data only, never executed. Select it with -Profile <name>')
    $null = $sb.AppendLine('    # or TP_PROFILE=<name>. Nothing here changes what is assessed or scored.')
    foreach ($k in $script:TPProfileKeys) {
        if (-not $Data.Contains($k)) { continue }
        $null = $sb.AppendLine(('    {0,-23} = {1}' -f $k, (& $lit $Data[$k])))
    }
    $null = $sb.AppendLine('}')
    return $sb.ToString()
}

function Write-TPProfileFile {
    <#
    .SYNOPSIS
        Atomic, verified write: the document goes to a temp file beside the
        target, is re-read with Import-PowerShellDataFile and checked for the
        company name, and only then replaces the target.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [Parameter(Mandatory)] [System.Collections.IDictionary] $Data
    )
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $text = ConvertTo-TPProfilePsd1 -Data $Data
    $tmp = Join-Path $dir ((Split-Path -Leaf $Path) + '.' + [guid]::NewGuid().ToString('N') + '.tmp.psd1')
    try {
        Set-Content -LiteralPath $tmp -Value $text -Encoding utf8 -NoNewline
        $check = Import-PowerShellDataFile -LiteralPath $tmp -ErrorAction Stop
        $name = [string](Get-TPObjectField -Item $check -Key 'CompanyName' -Default '')
        # The writer normalizes curly quotes and line breaks, so compare with what it wrote.
        $wrote = ConvertTo-TPPsd1String -Value ([string]$Data['CompanyName'])
        $expected = $wrote.Substring(1, $wrote.Length - 2) -replace "''", "'"
        if ($name -ne $expected) { throw "Round-trip check failed: CompanyName read back as '$name'." }
        Move-Item -LiteralPath $tmp -Destination $Path -Force
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function New-TPProfile {
    <#
    .SYNOPSIS
        Creates Config/profiles/<name>.psd1 for your practice. Select it with
        -Profile <name> on Invoke-TPAssessment.ps1 or TP_PROFILE=<name>.
    .DESCRIPTION
        Only -Name and -CompanyName are required. Everything else defaults to
        the neutral value: no contact, All framework cards, no DMARC reporting
        address, no declared EDR or awareness platform, no monitoring address,
        no rates. A profile holds data for the reports and never changes what
        is assessed or how it is scored.
    .EXAMPLE
        New-TPProfile -Name acme -CompanyName 'Acme Managed IT' -Email 'security@acme.example' -DefaultFramework CIS -DmarcReportingAddress 'dmarc@acme.example'
    #>
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Low')]
    [OutputType([string])]
    param(
        # Lower-case letters, digits and hyphens; this becomes the file name.
        [Parameter(Mandatory)]
        [ValidatePattern('\A[a-z0-9][a-z0-9-]{0,31}\z', Options = 'None')]
        [string] $Name,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [ValidateLength(1, 120)]
        [string] $CompanyName,

        [ValidateLength(0, 40)]  [string] $Phone = '',
        [ValidatePattern('^$|^https?://[^\s''"<>]{1,200}$')] [string] $Website = '',
        [ValidatePattern('^$|^[^\s@''"<>]{1,64}@[^\s@''"<>]{1,255}$')] [string] $Email = '',
        [ValidateLength(0, 120)] [string] $Address = '',
        [ValidateLength(0, 120)] [string] $CityStateZip = '',

        [ValidatePattern('^#[0-9A-Fa-f]{6}$')] [string] $PrimaryColor   = '#1a3a6b',
        [ValidatePattern('^#[0-9A-Fa-f]{6}$')] [string] $SecondaryColor = '#e87722',
        [ValidatePattern('^#[0-9A-Fa-f]{6}$')] [string] $AccentColor    = '#4a7ba6',
        [ValidatePattern('^$|^https://[^\s''"<>]{1,300}$')] [string] $LogoUrl = '',

        # Which framework cards the HTML report shows when -Framework is not given.
        [ValidateSet('All', 'NIST', 'CIS', 'SCuBA', 'CMMC')]
        [string] $DefaultFramework = 'All',

        # Address(es) or @domains that must appear in every managed domain's DMARC rua (DNS-1.3).
        [ValidatePattern('^(?:[^\s@''"<>]{1,64})?@[^\s@''"<>]{1,255}$')]
        [string[]] $DmarcReportingAddress = @(),

        # Third-party EDR and phishing-simulation platform declared across every client.
        [ValidatePattern('^$|^[A-Za-z0-9][A-Za-z0-9 .&()+/-]{1,59}$')] [string] $EdrStack = '',
        [ValidatePattern('^$|^[A-Za-z0-9][A-Za-z0-9 .&()+/-]{1,59}$')] [string] $AwarenessStack = '',

        # Address(es) or @domains alert policies should notify (DEF-3.4, EXO-3.3).
        [ValidatePattern('^(?:[^\s@''"<>]{1,64})?@[^\s@''"<>]{1,255}$')]
        [string[]] $MonitoringAddress = @(),

        [ValidateRange(0, 100000)] [int] $HourlyRate    = 0,
        [ValidateRange(0, 10000000)] [int] $AssessmentFee = 0,
        [ValidateRange(0, 10000000)] [int] $RegulatedFee  = 0,
        [ValidateRange(0, 10000000)] [int] $GovernanceFee = 0,

        # Write somewhere other than Config/profiles (tests, a staging copy).
        [AllowEmptyString()] [string] $Path = '',

        # Replace an existing profile of the same name.
        [switch] $Force
    )
    $dir = if ($Path) { $Path } else { Get-TPProfileDirectory }
    $file = Join-Path $dir "$Name.psd1"
    if ((Test-Path -LiteralPath $file) -and -not $Force) {
        throw "Profile '$Name' already exists at $file. Use -Force to replace it."
    }
    $spec = [ordered]@{
        CompanyName             = $CompanyName
        Phone                   = $Phone
        Website                 = $Website
        Email                   = $Email
        Address                 = $Address
        CityStateZip            = $CityStateZip
        PrimaryColor            = $PrimaryColor
        SecondaryColor          = $SecondaryColor
        AccentColor             = $AccentColor
        LogoUrl                 = $LogoUrl
        DefaultFramework        = $DefaultFramework
        DmarcReportingAddresses = @($DmarcReportingAddress)
        EdrStack                = $EdrStack
        AwarenessStack          = $AwarenessStack
        MonitoringAddresses     = @($MonitoringAddress)
        HourlyRate              = $HourlyRate
        AssessmentFee           = $AssessmentFee
        RegulatedFee            = $RegulatedFee
        GovernanceFee           = $GovernanceFee
    }
    if ($PSCmdlet.ShouldProcess($file, "Create profile '$Name' ($CompanyName)")) {
        Write-TPProfileFile -Path $file -Data $spec
        Write-Verbose "Profile '$Name' written to $file. Select it with -Profile $Name or TP_PROFILE=$Name."
        return $file
    }
}

function Get-TPProfile {
    <#
    .SYNOPSIS
        Lists the profiles in Config/profiles (or -Path) with their company
        name and default framework, and which one the module has loaded.
    #>
    [CmdletBinding()]
    param(
        [ValidatePattern('^$|\A[a-z0-9][a-z0-9-]{0,31}\z', Options = 'None')] [string] $Name = '',
        [AllowEmptyString()] [string] $Path = ''
    )
    $dir = if ($Path) { $Path } else { Get-TPProfileDirectory }
    if (-not (Test-Path -LiteralPath $dir)) { return @() }
    $active = if ((Get-Variable -Name TPProfileName -Scope Script -ErrorAction SilentlyContinue)) { [string]$script:TPProfileName } else { '' }
    $rows = foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter '*.psd1' -File | Sort-Object Name)) {
        $n = $f.BaseName
        if ($n -cnotmatch $script:TPProfileNamePattern) { continue }
        if ($Name -and $n -ne $Name) { continue }
        $d = $null
        try { $d = Import-PowerShellDataFile -LiteralPath $f.FullName -ErrorAction Stop } catch { Write-Verbose "Profile $n unreadable: $($_.Exception.Message)" }
        [pscustomobject]@{
            Name             = $n
            CompanyName      = [string](Get-TPObjectField -Item $d -Key 'CompanyName' -Default '')
            DefaultFramework = [string](Get-TPObjectField -Item $d -Key 'DefaultFramework' -Default '')
            Readable         = ($null -ne $d)
            Active           = ($n -eq $active)
            Path             = $f.FullName
        }
    }
    @($rows)
}
