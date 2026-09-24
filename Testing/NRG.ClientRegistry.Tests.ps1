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
        $script:Mod = Get-Module 'NRG-Assessment'
        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("nrg-cr-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
        function Invoke-Upsert([string]$File, [string]$Domain) {
            & $script:Mod { param($f, $d) Update-NRGClientRecord -ClientsFile $f -TenantDomain $d `
                -ClientId '22222222-2222-2222-2222-222222222222' -TenantId '33333333-3333-3333-3333-333333333333' `
                -CertThumbprint ('A' * 40) -Confirm:$false 3>$null } $File $Domain
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
