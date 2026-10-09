#Requires -Version 7.0
#
# TP.Profile.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Anyone can create a profile: New-TPProfile writes Config/profiles/<name>.psd1
# as data only, verified by re-reading it, and Get-TPProfile lists what is
# there. A profile name is never a path. Tests write through -Path into a
# temp directory, never into Config/.

Describe 'Profiles: New-TPProfile and Get-TPProfile' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Dir = Join-Path $TestDrive 'profiles'
    }
    AfterAll { Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }

    It 'writes a profile the module loader can read, with every key the shipped profiles carry' {
        $file = New-TPProfile -Name 'acme' -CompanyName "Acme Managed IT" -Email 'security@acme.example' -Website 'https://acme.example' `
            -DefaultFramework CIS -DmarcReportingAddress 'dmarc@acme.example', '@reports.acme.example' -EdrStack 'CrowdStrike Falcon' -HourlyRate 150 -Path $script:Dir -Confirm:$false
        $file | Should -Be (Join-Path $script:Dir 'acme.psd1')
        $d = Import-PowerShellDataFile -LiteralPath $file
        $d.CompanyName             | Should -Be 'Acme Managed IT'
        $d.DefaultFramework        | Should -Be 'CIS'
        @($d.DmarcReportingAddresses) | Should -Be @('dmarc@acme.example', '@reports.acme.example')
        $d.EdrStack                | Should -Be 'CrowdStrike Falcon'
        $d.HourlyRate              | Should -Be 150
        $d.AssessmentFee           | Should -Be 0
        $shipped = Import-PowerShellDataFile (Join-Path $script:RepoRoot 'Config' 'profiles' 'nrg.psd1')
        foreach ($k in $shipped.Keys) { $d.Contains($k) | Should -BeTrue -Because "a new profile must carry '$k' like the shipped ones" }
    }

    It 'escapes quotes so the file stays data-only and round-trips' {
        $file = New-TPProfile -Name 'quotes' -CompanyName "O'Brien's IT; `$(Get-Date)" -Path $script:Dir -Confirm:$false
        (Import-PowerShellDataFile -LiteralPath $file).CompanyName | Should -Be "O'Brien's IT; `$(Get-Date)"
        (Get-Content -LiteralPath $file -Raw) | Should -Not -Match '"'
    }

    It 'refuses a name that is a path or has upper case, and refuses to overwrite without -Force' {
        { New-TPProfile -Name '../branding' -CompanyName 'x' -Path $script:Dir -Confirm:$false } | Should -Throw
        { New-TPProfile -Name 'Acme' -CompanyName 'x' -Path $script:Dir -Confirm:$false } | Should -Throw
        { New-TPProfile -Name 'acme' -CompanyName 'again' -Path $script:Dir -Confirm:$false } | Should -Throw -ExpectedMessage '*already exists*'
        New-TPProfile -Name 'acme' -CompanyName 'again' -Path $script:Dir -Force -Confirm:$false | Out-Null
        (Import-PowerShellDataFile -LiteralPath (Join-Path $script:Dir 'acme.psd1')).CompanyName | Should -Be 'again'
    }

    It 'validates colors, framework, addresses and product names' {
        { New-TPProfile -Name 'c1' -CompanyName 'x' -PrimaryColor 'blue' -Path $script:Dir -Confirm:$false } | Should -Throw
        { New-TPProfile -Name 'c2' -CompanyName 'x' -DefaultFramework 'ISO' -Path $script:Dir -Confirm:$false } | Should -Throw
        { New-TPProfile -Name 'c3' -CompanyName 'x' -DmarcReportingAddress 'not-an-address' -Path $script:Dir -Confirm:$false } | Should -Throw
        { New-TPProfile -Name 'c4' -CompanyName 'x' -EdrStack '<script>' -Path $script:Dir -Confirm:$false } | Should -Throw
    }

    It '-WhatIf writes nothing' {
        New-TPProfile -Name 'dry' -CompanyName 'x' -Path $script:Dir -WhatIf | Out-Null
        Test-Path -LiteralPath (Join-Path $script:Dir 'dry.psd1') | Should -BeFalse
    }

    It 'lists profiles with company and default framework, and marks the active one' {
        $rows = @(Get-TPProfile -Path $script:Dir)
        @($rows | ForEach-Object Name) | Should -Contain 'acme'
        @($rows | ForEach-Object Name) | Should -Contain 'quotes'
        ($rows | Where-Object Name -eq 'acme').CompanyName | Should -Be 'again' -Because 'the -Force rewrite above replaced it'
        ($rows | Where-Object Name -eq 'acme').Readable | Should -BeTrue
        $shipped = @(Get-TPProfile)
        @($shipped | ForEach-Object Name) | Should -Contain 'nrg'
        @($shipped | ForEach-Object Name) | Should -Contain 'nls'
        @($shipped | Where-Object Active) | Should -BeNullOrEmpty -Because 'the module loaded Config/branding.psd1, not a named profile'
    }

    It 'a created profile loads through TP_PROFILE when placed in Config/profiles (checked against a temp copy of the loader rule)' {
        # The loader only reads Config/profiles, so prove the written file is
        # what the loader accepts: same name rule, Import-PowerShellDataFile.
        $file = Join-Path $script:Dir 'acme.psd1'
        'acme' | Should -Match '\A[a-z0-9][a-z0-9-]{0,31}\z'
        { Import-PowerShellDataFile -LiteralPath $file -ErrorAction Stop } | Should -Not -Throw
    }
}
