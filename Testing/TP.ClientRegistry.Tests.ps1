#Requires -Version 7.0
#
# TP.ClientRegistry.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# -RegisterApp records each onboarded tenant in Config/clients.json, whose
# shape is { "clients": [ ... ] }. An unparseable file used to be replaced by
# a new one holding only the tenant just onboarded — every other client's
# record gone — and that happened after the app registration had already
# been created in the customer tenant.

Describe 'Update-TPClientRecord' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        # Onboarding is not in the module (it writes to a tenant); the entry
        # script dot-sources it for -RegisterApp, and so does this test.
        . (Join-Path $script:RepoRoot 'Onboard' 'Register-TPTenantApp.ps1')
        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("tp-cr-" + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $script:Tmp -Force | Out-Null
        function Invoke-Upsert([string]$File, [string]$Domain, [string]$Org = '') {
            Update-TPClientRecord -ClientsFile $File -TenantDomain $Domain `
                -ClientId '22222222-2222-2222-2222-222222222222' -TenantId '33333333-3333-3333-3333-333333333333' `
                -CertThumbprint ('A' * 40) -DelegatedOrg $Org -Confirm:$false 3>$null
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

    It 'a NEW client record carries every field the batch runner and schema require' {
        # A -RegisterApp record used to hold only the app fields; the batch
        # runner validates DelegatedOrg on every client before auth and so
        # refused to run for ANY client once one such record existed.
        $f = Join-Path $script:Tmp 'new.json'
        '{ "clients": [] }' | Set-Content -LiteralPath $f -Encoding utf8
        Invoke-Upsert $f 'new.com' 'newco.onmicrosoft.com'
        $raw = Get-Content -LiteralPath $f -Raw
        $rec = @(($raw | ConvertFrom-Json).clients)[0]
        foreach ($k in 'ClientName','TenantDomain','TenantId','DelegatedOrg','DnsDomains','SkipPurview','SkipTeams',
                       'SkipSharePoint','SkipIntune','SkipPowerPlatform','SkipDNS','Notes','Active') {
            $rec.PSObject.Properties[$k] | Should -Not -BeNullOrEmpty -Because "$k is required"
        }
        $rec.DelegatedOrg | Should -Be 'newco.onmicrosoft.com'
        $errs = $null
        Test-Json -Json $raw -SchemaFile (Join-Path $script:RepoRoot 'Config/schema/clients.schema.json') -ErrorVariable errs -ErrorAction SilentlyContinue |
            Should -BeTrue -Because "schema errors: $($errs -join '; ')"
    }

    It 'the batch runner reports a record missing DelegatedOrg instead of crashing on it' {
        $batch = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPBatchAssessment.ps1') -Raw
        $batch | Should -Match "PSObject\.Properties\['DelegatedOrg'\]"
        $batch | Should -Not -Match '\$c\.DelegatedOrg -notmatch'
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
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    }
    It 'the module exports nothing that creates an app' {
        (Get-Module 'TenantPosture').ExportedCommands.Keys | Should -Not -Contain 'Register-TPTenantApp'
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
        $entry = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
        $entry | Should -Match "\. \(Join-Path \`$scriptDir 'Onboard' 'Register-TPTenantApp\.ps1'\)"
    }
}
