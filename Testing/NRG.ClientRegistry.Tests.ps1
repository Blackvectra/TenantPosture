#Requires -Version 7.0
#
# NRG.ClientRegistry.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# -RegisterApp records each onboarded tenant in Config/clients.json, whose
# shape is { "clients": [ ... ] }. An unparseable file used to be replaced by
# a new one holding only the tenant just onboarded — every other client's
# record gone — and that happened after the app registration had already
# been created in the customer tenant.

Describe 'Update-NRGClientRecord' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        # Onboarding is not in the module (it writes to a tenant); the entry
        # script dot-sources it for -RegisterApp, and so does this test.
        . (Join-Path $script:RepoRoot 'Onboard' 'Register-NRGTenantApp.ps1')
        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-cr-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
        function Invoke-Upsert([string]$File, [string]$Domain) {
            Update-NRGClientRecord -ClientsFile $File -TenantDomain $Domain `
                -ClientId '22222222-2222-2222-2222-222222222222' -TenantId '33333333-3333-3333-3333-333333333333' `
                -CertThumbprint ('A' * 40) -Confirm:$false 3>$null
        }
    }
    AfterAll { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }

    It 'adds a client and keeps every existing one, in the { clients: [...] } shape' {
        $f = Join-Path $script:Tmp 'ok.json'
        '{ "clients": [ { "ClientName": "A", "TenantDomain": "a.com" }, { "ClientName": "B", "TenantDomain": "b.com" } ] }' | Set-Content -LiteralPath $f -Encoding utf8
        Invoke-Upsert $f 'new.com'
        $after = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json
        @($after.clients).TenantDomain | Should -Be @('a.com', 'b.com', 'new.com')
    }

    It 'refuses to overwrite a clients.json it cannot parse' {
        $f = Join-Path $script:Tmp 'bad.json'
        $garbage = '{ "clients": [ { "TenantDomain": "a.com" }, '
        Set-Content -LiteralPath $f -Value $garbage -Encoding utf8 -NoNewline
        { Invoke-Upsert $f 'new.com' } | Should -Throw
        Get-Content -LiteralPath $f -Raw | Should -Be $garbage -Because 'the existing client records must survive'
    }
}

Describe 'Tenant onboarding is outside the read-only module' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
    }
    It 'the module exports nothing that creates an app' {
        (Get-Module 'NRG-Assessment').ExportedCommands.Keys | Should -Not -Contain 'Register-NRGTenantApp'
    }
    It 'no file the module loads calls a Microsoft Graph write cmdlet' {
        $folders = 'Lib', 'Collectors', 'Evaluators', 'Publishers', 'Email-IR/Lib', 'Email-IR/Collectors', 'Email-IR/Evaluators', 'Email-IR/Publishers'
        $hits = foreach ($d in $folders) {
            # Parsed command invocations only: remediation text that NAMES a
            # write cmdlet for the reader is fine; calling one is not.
            foreach ($f in Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot $d) -Recurse -Filter '*.ps1' -ErrorAction SilentlyContinue) {
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
                $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and
                               "$($n.GetCommandName())" -match '^(New|Update|Remove|Set)-Mg[A-Z]' }, $true) |
                    ForEach-Object { "$($f.FullName):$($_.Extent.StartLineNumber) $($_.GetCommandName())" }
            }
        }
        @($hits) | Should -BeNullOrEmpty -Because 'tenant writes belong in Onboard/ or Apply/, never in the read-only module'
    }
    It '-RegisterApp still works: the entry script loads the onboarding file for that path' {
        $entry = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1') -Raw
        $entry | Should -Match "\. \(Join-Path \`$scriptDir 'Onboard' 'Register-NRGTenantApp\.ps1'\)"
    }
}
