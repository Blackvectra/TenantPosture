#Requires -Version 7.0
#
# TP.TenantPinning.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# A scan run for a named tenant (-TenantDomain, or a client picked in the Web
# GUI) must assess THAT tenant or nothing. Before this, interactive sign-in
# connected to whatever tenant the account belonged to — an MSP operator's own
# tenant, under GDAP — nothing checked it against the tenant asked for, the
# GUI passed a made-up "scan@<domain>" UPN, and the clients.json lookup read
# the { "clients": [...] } wrapper as the list and never matched.

Describe 'Resolve-TPTenantId' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    }
    It 'returns the tenant GUID from the OpenID issuer' {
        Mock -CommandName Invoke-RestMethod -ModuleName TenantPosture -MockWith {
            [pscustomobject]@{ issuer = 'https://login.microsoftonline.com/ABCDEF01-2345-4678-9ABC-DEF012345678/v2.0' } }
        Resolve-TPTenantId -Domain 'contoso.com' | Should -Be 'abcdef01-2345-4678-9abc-def012345678'
    }
    It 'returns $null, never a guess, when the domain is unknown' {
        Mock -CommandName Invoke-RestMethod -ModuleName TenantPosture -MockWith { throw '400 Bad Request' }
        Resolve-TPTenantId -Domain 'no-such-tenant.example' | Should -BeNullOrEmpty
    }
    It 'rejects a malformed domain before any request is made' {
        { Resolve-TPTenantId -Domain 'evil.com/../x' } | Should -Throw
    }
}

Describe 'Connect-TPServices refuses a session for the wrong tenant' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
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
            Connect-TPServices -ExpectedTenantId 'abcdef01-2345-4678-9abc-def012345678' -SkipTeams -SkipPurview -SkipSharePoint 6>$null 3>$null
        } | Where-Object { $_ -is [hashtable] } | Select-Object -Last 1
        $r.Graph | Should -BeFalse
        $r.EXO   | Should -BeFalse -Because 'the Exchange session is also for the wrong tenant'
    }
}

Describe 'Entry points pin the scan to the requested tenant' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:Entry = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
        $script:Web   = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Lib/Start-TPWebServer.ps1') -Raw
    }
    It 'the Web GUI launches scans with -TenantDomain, never a fabricated UPN' {
        $script:Web | Should -Not -Match '-UserPrincipalName\s+"scan@'
        $script:Web | Should -Match '-TenantDomain \$domain'
    }
    It 'the entry script passes the resolved tenant to Connect-TPServices' {
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

# Issue #79. The batch runner switched Graph to each client but ran the
# assessment without naming the client, so tenant pinning never applied in
# batch mode, Security & Compliance opened without -DelegatedOrganization, and
# the assessment's own cleanup closed the shared Graph session after every
# client (a fresh sign-in per client, reconnecting without the scopes).
Describe 'GDAP batch runner pins every client' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $script:BatchPath = Join-Path $script:RepoRoot 'Invoke-TPBatchAssessment.ps1'
        $script:Batch     = Get-Content -LiteralPath $script:BatchPath -Raw
        $script:BatchAst  = [System.Management.Automation.Language.Parser]::ParseFile($script:BatchPath, [ref]$null, [ref]$null)

        # String literals of the array assigned to $Name in a file's AST.
        function script:Get-AssignedStrings([System.Management.Automation.Language.Ast]$Ast, [string]$Name) {
            $a = $Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and
                    "$($n.Left)" -eq "`$$Name" }, $true) | Select-Object -First 1
            @($a.Right.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true).Value)
        }
    }

    It 'passes the client TenantDomain and -KeepSession to the assessment' {
        $script:Batch | Should -Match '\$params = @\{[^}]*TenantDomain = \$client\.TenantDomain'
        $script:Batch | Should -Match '\$params = @\{[^}]*KeepSession = \$true'
    }

    It 'switches Graph to each client with the full scope list, not a bare -TenantId' {
        $script:Batch | Should -Match 'Connect-MgGraph -TenantId \$client\.TenantId -Scopes \$batchScopes'
    }

    It 'requests exactly the scopes Connect-TPServices requests' {
        $svcAst = [System.Management.Automation.Language.Parser]::ParseFile(
            (Join-Path $script:RepoRoot 'Lib/Connect-TPServices.ps1'), [ref]$null, [ref]$null)
        $batch = @(Get-AssignedStrings $script:BatchAst 'batchScopes' | Sort-Object)
        $svc   = @(Get-AssignedStrings $svcAst 'scopes' | Sort-Object)
        $batch.Count | Should -Be 24
        ($batch -join ',') | Should -Be ($svc -join ',')
    }

    It 'closes the per-client Exchange, Security & Compliance and Teams sessions before the next client' {
        $script:Batch | Should -Match 'Disconnect-ExchangeOnline -Confirm:\$false'
        $script:Batch | Should -Match 'Disconnect-MicrosoftTeams'
    }
}
