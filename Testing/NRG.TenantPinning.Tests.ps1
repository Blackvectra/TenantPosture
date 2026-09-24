#Requires -Version 7.0
#
# NRG.TenantPinning.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# A scan run for a named tenant (-TenantDomain, or a client picked in the Web
# GUI) must assess THAT tenant or nothing. Before this, interactive sign-in
# connected to whatever tenant the account belonged to — an MSP operator's own
# tenant, under GDAP — nothing checked it against the tenant asked for, the
# GUI passed a made-up "scan@<domain>" UPN, and the clients.json lookup read
# the { "clients": [...] } wrapper as the list and never matched.

Describe 'Resolve-NRGTenantId' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
    }
    It 'returns the tenant GUID from the OpenID issuer' {
        Mock -CommandName Invoke-RestMethod -ModuleName NRG-Assessment -MockWith {
            [pscustomobject]@{ issuer = 'https://login.microsoftonline.com/375E7ED2-25CC-4BEC-BC68-890DC9095311/v2.0' } }
        Resolve-NRGTenantId -Domain 'contoso.com' | Should -Be '375e7ed2-25cc-4bec-bc68-890dc9095311'
    }
    It 'returns $null, never a guess, when the domain is unknown' {
        Mock -CommandName Invoke-RestMethod -ModuleName NRG-Assessment -MockWith { throw '400 Bad Request' }
        Resolve-NRGTenantId -Domain 'no-such-tenant.example' | Should -BeNullOrEmpty
    }
    It 'rejects a malformed domain before any request is made' {
        { Resolve-NRGTenantId -Domain 'evil.com/../x' } | Should -Throw
    }
}

Describe 'Connect-NRGServices refuses a session for the wrong tenant' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'
        # Stub the Graph cmdlets inside module scope; the signed-in context
        # belongs to a DIFFERENT tenant than the one requested.
        & $script:Mod {
            Set-Item -Path 'function:script:Connect-MgGraph' -Value { param([Parameter(ValueFromRemainingArguments)] $rest) }
            Set-Item -Path 'function:script:Get-MgContext'   -Value { [pscustomobject]@{ TenantId = '11111111-1111-1111-1111-111111111111'; Account = 'op@msp.com'; Scopes = @() } }
            Set-Item -Path 'function:script:Connect-ExchangeOnline'    -Value { param([Parameter(ValueFromRemainingArguments)] $rest) }
            Set-Item -Path 'function:script:Get-ConnectionInformation' -Value { @([pscustomobject]@{ State = 'Connected'; IsEopSession = $false; TenantID = '11111111-1111-1111-1111-111111111111' }) }
        }
    }
    It 'marks Graph unusable when the signed-in tenant is not the expected one' {
        $r = & $script:Mod {
            Connect-NRGServices -ExpectedTenantId '375e7ed2-25cc-4bec-bc68-890dc9095311' -SkipTeams -SkipPurview -SkipSharePoint 6>$null 3>$null
        } | Where-Object { $_ -is [hashtable] } | Select-Object -Last 1
        $r.Graph | Should -BeFalse
        $r.EXO   | Should -BeFalse -Because 'the Exchange session is also for the wrong tenant'
    }
}

Describe 'Entry points pin the scan to the requested tenant' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:Entry = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1') -Raw
        $script:Web   = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Start-NRGWebServer.ps1') -Raw
    }
    It 'the Web GUI launches scans with -TenantDomain, never a fabricated UPN' {
        $script:Web | Should -Not -Match '-UserPrincipalName\s+"scan@'
        $script:Web | Should -Match '-TenantDomain \$domain'
    }
    It 'the entry script passes the resolved tenant to Connect-NRGServices' {
        $script:Entry | Should -Match "\`$connectParams\['ExpectedTenantId'\]\s*=\s*\`$targetTenantId"
        $script:Entry | Should -Match "\`$connectParams\['DelegatedOrganization'\]\s*=\s*\`$targetDelegatedOrg"
    }
    It 'the entry script aborts before collection on a tenant mismatch' {
        $script:Entry | Should -Match 'Tenant mismatch'
        $iAbort   = $script:Entry.IndexOf('Tenant mismatch')
        $iCollect = $script:Entry.IndexOf('[-] Running collectors')
        $iAbort | Should -BeLessThan $iCollect
    }
    It 'reads clients.json through its { "clients": [...] } wrapper' {
        $script:Entry | Should -Match "PSObject\.Properties\['clients'\]"
    }
}
