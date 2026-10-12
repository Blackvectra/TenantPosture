#Requires -Version 7.0
#
# TP.BatchClientsFile.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# The batch runner reads the clients file it is given (-ClientsFile), but every assessment it
# launched read Config/clients.json beside the script, so a batch run from a file kept anywhere
# else lost each client's declared EDR and awareness product, monitoring addresses, baseline tier,
# opt-in collectors and routing domain without a word. Nothing let one client in a batch use a
# different practice's profile, and a misspelled product name stopped a client only after its
# whole assessment had run. These tests pin: one reader of the record, the file passed down to
# each run, a client's own profile, everything judged before any sign-in, and what -WhatIf shows.

Describe 'Batch clients file' {

    BeforeAll {
        $script:Root = Split-Path -Parent $PSScriptRoot
        . (Join-Path $script:Root 'Lib' 'Get-TPClientRecord.ps1')
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-clients-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path $script:Tmp -Force
        $script:Pwsh = (Get-Process -Id $PID).Path
        $script:EntrySrc = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-TPAssessment.ps1') -Raw
        $script:BatchSrc = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-TPBatchAssessment.ps1') -Raw

        # The batch script requires Microsoft.Graph.Authentication and ExchangeOnlineManagement at parse time;
        # -WhatIf exits before either is used, so empty stand-ins on the module path are all it needs.
        $script:Mods = Join-Path $script:Tmp 'mods'
        foreach ($m in @(@('Microsoft.Graph.Authentication', '2.40.0', 'b0b0b0b0-1111-4222-8333-444444444444'), @('ExchangeOnlineManagement', '3.10.1', 'c0c0c0c0-1111-4222-8333-555555555555'))) {
            $dir = Join-Path $script:Mods $m[0] $m[1]
            $null = New-Item -ItemType Directory -Path $dir -Force
            Set-Content -LiteralPath (Join-Path $dir "$($m[0]).psd1") -Encoding utf8 -Value "@{ RootModule = '$($m[0]).psm1'; ModuleVersion = '$($m[1])'; GUID = '$($m[2])'; FunctionsToExport = @(); CmdletsToExport = @(); AliasesToExport = @() }"
            Set-Content -LiteralPath (Join-Path $dir "$($m[0]).psm1") -Encoding utf8 -Value '# stand-in'
        }
        $script:RunBatch = {
            param($File)
            $old = $env:PSModulePath
            try {
                $env:PSModulePath = $script:Mods + [System.IO.Path]::PathSeparator + $old
                $text = & $script:Pwsh -NoProfile -File (Join-Path $script:Root 'Invoke-TPBatchAssessment.ps1') -ClientsFile $File -WhatIf 2>&1 | Out-String
                $script:BatchExit = $LASTEXITCODE
                $text
            } finally { $env:PSModulePath = $old }
        }

        # Fixture records are made of obviously fake values; the GUIDs are not tenants.
        $script:Write = {
            param($Name, $Clients)
            $path = Join-Path $script:Tmp $Name
            (@{ clients = $Clients } | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $path -Encoding utf8
            $path
        }
        $script:Rec = {
            param($Domain, $Extra)
            $r = [ordered]@{
                ClientName = "Client $Domain"; TenantDomain = $Domain
                TenantId = '11111111-2222-3333-4444-555555555555'
                DelegatedOrg = ($Domain.Split('.')[0] + '.onmicrosoft.com')
                DnsDomains = @($Domain); Active = $true
            }
            foreach ($k in @($Extra.Keys)) { $r[$k] = $Extra[$k] }
            $r
        }
    }

    AfterAll {
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    Context 'Get-TPClientRecord' {

        It 'finds the record by tenant domain in a { clients: [...] } file, whatever the case' {
            $f = & $script:Write 'a.json' @((& $script:Rec 'one.example' @{ ThirdPartyEDR = 'Cortex XDR' }), (& $script:Rec 'two.example' @{}))
            $r = Get-TPClientRecord -Path $f -TenantDomain 'TWO.example'
            $r.Status | Should -Be 'Found'
            $r.Record.TenantDomain | Should -Be 'two.example'
            (Get-TPClientRecord -Path $f -TenantDomain 'one.example').Record.ThirdPartyEDR | Should -Be 'Cortex XDR'
        }

        It 'accepts a bare array too' {
            $f = Join-Path $script:Tmp 'bare.json'
            (@((& $script:Rec 'bare.example' @{})) | ConvertTo-Json -Depth 6) | Set-Content -LiteralPath $f -Encoding utf8
            (Get-TPClientRecord -Path $f -TenantDomain 'bare.example').Status | Should -Be 'Found'
        }

        It 'says NotListed for a domain with no record, and NoFile for a path with no file' {
            $f = & $script:Write 'b.json' @((& $script:Rec 'one.example' @{}))
            (Get-TPClientRecord -Path $f -TenantDomain 'other.example').Status | Should -Be 'NotListed'
            (Get-TPClientRecord -Path (Join-Path $script:Tmp 'missing.json') -TenantDomain 'one.example').Status | Should -Be 'NoFile'
        }

        It 'says Unreadable, never "no record", for a file that is not JSON or is empty' {
            $bad = Join-Path $script:Tmp 'bad.json'
            Set-Content -LiteralPath $bad -Value '{ "clients": [ oops' -Encoding utf8
            $r = Get-TPClientRecord -Path $bad -TenantDomain 'one.example'
            $r.Status | Should -Be 'Unreadable'
            $r.Message | Should -Match 'not valid JSON'
            $empty = Join-Path $script:Tmp 'empty.json'
            Set-Content -LiteralPath $empty -Value '' -Encoding utf8
            (Get-TPClientRecord -Path $empty -TenantDomain 'one.example').Status | Should -Be 'Unreadable'
        }

        It 'checks a file with no domain given: readable is NotListed with no record, unreadable still says so' {
            $f = & $script:Write 'c.json' @((& $script:Rec 'one.example' @{}))
            $r = Get-TPClientRecord -Path $f
            $r.Status | Should -Be 'NotListed'
            $r.Record | Should -BeNullOrEmpty
            (Get-TPClientRecord -Path (Join-Path $script:Tmp 'bad.json')).Status | Should -Be 'Unreadable'
        }
    }

    Context 'the product-name rule has one definition' {

        It 'accepts real product names and rejects what is not one' {
            $p = Get-TPProductNamePattern
            foreach ($ok in @('Cortex XDR', 'KnowBe4', 'Huntress SAT', 'Microsoft Defender for Endpoint (P2)')) { $ok -cmatch $p | Should -BeTrue -Because $ok }
            foreach ($bad in @('', 'x', ' Cortex', "Cortex`n", 'a;b', 'Cortex|XDR', ('x' * 61))) { $bad -cmatch $p | Should -BeFalse -Because ("[" + ($bad -replace "`n", '\n') + "]") }
        }

        It 'is the same character class as the parameters and the two declaration functions' {
            $body = '[A-Za-z0-9][A-Za-z0-9 .&()+/-]{1,59}'
            (Get-TPProductNamePattern) | Should -Be ('\A' + $body + '\z')
            foreach ($file in @('Lib/Set-TPThirdPartyEdr.ps1', 'Lib/Set-TPThirdPartyAwareness.ps1', 'Invoke-TPAssessment.ps1')) {
                (Get-Content -LiteralPath (Join-Path $script:Root $file) -Raw).Contains($body) | Should -BeTrue -Because "$file must carry the same product-name character class"
            }
        }
    }

    Context 'the entry point' {

        It 'takes -ClientsFile and has no second reader of the default file' {
            $script:EntrySrc | Should -Match '\[string\] \$ClientsFile'
            ([regex]::Matches($script:EntrySrc, [regex]::Escape("Join-Path `$scriptDir 'Config' 'clients.json'"))).Count | Should -Be 1
            $script:EntrySrc | Should -Match 'Get-TPClientRecord -Path \$clientsPath -TenantDomain \$TenantDomain'
            $script:EntrySrc | Should -Not -Match 'ConvertFrom-Json[^\r\n]*\r?\n[^\r\n]*\$rawClients'
        }

        It 'stops with exit code 4 on a named clients file that does not exist, before anything connects' {
            $out = & $script:Pwsh -NoProfile -File (Join-Path $script:Root 'Invoke-TPAssessment.ps1') -TenantDomain 'one.example' -ClientsFile (Join-Path $script:Tmp 'nowhere.json') -NonInteractive 2>&1 | Out-String
            $LASTEXITCODE | Should -Be 4
            $out | Should -Match 'There is no clients file'
            $out | Should -Match 'Nothing was run'
        }

        It 'stops with exit code 4 on a named clients file that is not valid JSON' {
            $bad = Join-Path $script:Tmp 'bad-entry.json'
            Set-Content -LiteralPath $bad -Value 'not json' -Encoding utf8
            $out = & $script:Pwsh -NoProfile -File (Join-Path $script:Root 'Invoke-TPAssessment.ps1') -TenantDomain 'one.example' -ClientsFile $bad -NonInteractive 2>&1 | Out-String
            $LASTEXITCODE | Should -Be 4
            $out | Should -Match 'not valid JSON'
        }

        It 'rejects a path with a traversal sequence' {
            $null = & $script:Pwsh -NoProfile -File (Join-Path $script:Root 'Invoke-TPAssessment.ps1') -TenantDomain 'one.example' -ClientsFile '../x.json' -NonInteractive 2>&1
            $LASTEXITCODE | Should -Not -Be 0
        }

        It 'judges a product name taken from the record before connecting, and lets -RegisterApp name a file that is not there yet' {
            $script:EntrySrc | Should -Match 'Get-TPProductNamePattern'
            $script:EntrySrc | Should -Match "-not \`$RegisterApp"
            $script:EntrySrc | Should -Match "\`$regParams\['ClientsFile'\] = \`$clientsPath"
        }
    }

    Context 'the batch runner' {

        It 'hands every assessment the file it was given, and the client''s own profile when the record names one' {
            $script:BatchSrc | Should -Match 'ClientsFile = \$resolvedCfg'
            $script:BatchSrc | Should -Match "\`$params\['Profile'\] = \[string\]\`$client\.Profile"
        }

        It '-WhatIf lists each client with what its record sets, and exits 0 without signing in' {
            $f = & $script:Write 'whatif.json' @(
                (& $script:Rec 'one.example' @{ Profile = 'nls'; ThirdPartyEDR = 'Cortex XDR'; ThirdPartyAwareness = 'KnowBe4' }),
                (& $script:Rec 'two.example' @{}))
            $out = & $script:RunBatch $f
            $script:BatchExit | Should -Be 0
            $out | Should -Match 'profile: nls\s+EDR: Cortex XDR\s+awareness: KnowBe4'
            $out | Should -Match 'profile: -\s+EDR: -\s+awareness: -'
            $out | Should -Match 'WhatIf'
        }

        It 'refuses, before any sign-in, a client whose Profile is not a profile' {
            $f = & $script:Write 'badprofile.json' @((& $script:Rec 'one.example' @{ Profile = 'nosuchprofile' }))
            $out = & $script:RunBatch $f
            $script:BatchExit | Should -Be 1
            $out | Should -Match "Profile 'nosuchprofile'"
            $out | Should -Match 'Available profiles:'
        }

        It 'refuses, before any sign-in, a declared product that is not a product name' {
            $f = & $script:Write 'badproduct.json' @((& $script:Rec 'one.example' @{ ThirdPartyEDR = 'Cortex;XDR' }))
            $out = & $script:RunBatch $f
            $script:BatchExit | Should -Be 1
            $out | Should -Match "ThirdPartyEDR 'Cortex;XDR' is not a product name"
        }
    }
}
