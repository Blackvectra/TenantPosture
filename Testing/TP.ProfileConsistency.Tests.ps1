#Requires -Version 7.0
#
# TP.ProfileConsistency.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# A profile is the practice a run belongs to. Before this, the profile was
# honored by the module's own branding and nothing else: the entry point read
# EdrStack, AwarenessStack and MonitoringAddresses from Config/branding.psd1 a
# second time (so -Profile nrg dropped its declared EDR), the report site and
# tenant onboarding did the same, a misspelled name warned and ran with the
# neutral defaults, TP_PROFILE stayed set in the console after -Profile, and an
# explicit -Path to Get-TPStandards still had the profile's DMARC address put
# over it. These tests pin each, and the one place a profile name is judged.

Describe 'Profile consistency' {

    BeforeAll {
        $script:Root = Split-Path -Parent $PSScriptRoot
        . (Join-Path $script:Root 'Lib' 'Get-TPObjectField.ps1')
        . (Join-Path $script:Root 'Lib' 'Resolve-TPProfilePath.ps1')
        . (Join-Path $script:Root 'Lib' 'Get-TPProfileDeclaration.ps1')
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("tp-prof-" + [guid]::NewGuid().ToString('N'))
        $null = New-Item -ItemType Directory -Path (Join-Path $script:Tmp 'Config' 'profiles') -Force
        Set-Content -LiteralPath (Join-Path $script:Tmp 'Config' 'branding.psd1') -Value "@{ CompanyName = 'Neutral' }" -Encoding utf8
        Set-Content -LiteralPath (Join-Path $script:Tmp 'Config' 'profiles' 'acme.psd1') -Value "@{ CompanyName = 'Acme' }" -Encoding utf8
        Set-Content -LiteralPath (Join-Path $script:Tmp 'Config' 'profiles' 'zeta-2.psd1') -Value "@{ CompanyName = 'Zeta' }" -Encoding utf8
        Set-Content -LiteralPath (Join-Path $script:Tmp 'Config' 'profiles' 'README.md') -Value 'not a profile' -Encoding utf8
        $script:EntrySrc = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-TPAssessment.ps1') -Raw
        $script:Pwsh = (Get-Process -Id $PID).Path
    }
    AfterAll { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }

    Context 'Resolve-TPProfilePath: the one definition of which file a profile name selects' {

        It 'no name selects Config/branding.psd1' {
            $r = Resolve-TPProfilePath -Root $script:Tmp -Name ''
            $r.Status | Should -Be 'Default'
            $r.Path | Should -Be (Join-Path $script:Tmp 'Config' 'branding.psd1')
            (Resolve-TPProfilePath -Root $script:Tmp).Status | Should -Be 'Default'
        }

        It 'a name that exists selects Config/profiles/<name>.psd1' {
            $r = Resolve-TPProfilePath -Root $script:Tmp -Name 'acme'
            $r.Status | Should -Be 'Ok'
            $r.Name | Should -Be 'acme'
            $r.Path | Should -Be (Join-Path $script:Tmp 'Config' 'profiles' 'acme.psd1')
        }

        It 'a name that is not a profile is an error that lists the profiles that exist: <Label>' -ForEach @(
            @{ Label = 'misspelled';       Name = 'acmee';          Status = 'NotFound' }
            @{ Label = 'upper case';       Name = 'Acme';           Status = 'BadName' }
            @{ Label = 'a path';           Name = '../branding';    Status = 'BadName' }
            @{ Label = 'a nested path';    Name = 'profiles/acme';  Status = 'BadName' }
            @{ Label = 'a trailing line feed'; Name = "acme`n";     Status = 'BadName' }
            @{ Label = 'a dot';            Name = 'acme.psd1';      Status = 'BadName' }
            @{ Label = 'too long';         Name = ('a' * 33);       Status = 'BadName' }) {
            $r = Resolve-TPProfilePath -Root $script:Tmp -Name $Name
            $r.Status | Should -Be $Status
            $r.Path | Should -BeNullOrEmpty
            $r.Message | Should -Match 'Available profiles: acme, zeta-2'
        }

        It 'lists only files whose names are profile names' {
            (Resolve-TPProfilePath -Root $script:Tmp -Name 'nosuch').Available | Should -Be @('acme', 'zeta-2')
        }

        It 'the name rule exists once, as a function, and nothing else in the product spells it' {
            $hits = @(Get-ChildItem -LiteralPath $script:Root -Recurse -File -Include *.ps1, *.psm1 |
                Where-Object { $_.FullName -notmatch '[\\/](Testing|\.git|output)[\\/]' } |
                Select-String -Pattern '\[a-z0-9\]\[a-z0-9-\]\{0,31\}' -SimpleMatch:$false)
            @($hits | ForEach-Object { $_.Path } | Sort-Object -Unique | ForEach-Object { Split-Path -Leaf $_ }) |
                Should -Be @('Invoke-TPAssessment.ps1', 'New-TPProfile.ps1', 'Resolve-TPProfilePath.ps1') -Because 'the two parameter ValidatePattern attributes (-Profile, New-TPProfile -Name) cannot call a function; everything else asks the resolver'
        }
    }

    Context 'the module refuses a name that is not a profile' {

        It 'importing with a misspelled TP_PROFILE fails and names the profiles that exist' {
            $out = & $script:Pwsh -NoProfile -Command "`$env:TP_PROFILE = 'nrgg'; try { Import-Module '$($script:Root)/TenantPosture.psm1' -Force -ErrorAction Stop; 'LOADED' } catch { 'FAILED: ' + `$_.Exception.Message }" 2>&1 | Out-String
            $out | Should -Match 'FAILED:'
            $out | Should -Match "no profile 'nrgg'"
            $out | Should -Match 'Available profiles:.*nrg'
            $out | Should -Not -Match 'LOADED'
        }

        It 'a valid TP_PROFILE still loads' {
            $out = & $script:Pwsh -NoProfile -Command "`$env:TP_PROFILE = 'nrg'; Import-Module '$($script:Root)/TenantPosture.psm1' -Force -ErrorAction Stop; `$TPBrand['ProfileName']" 2>&1 | Out-String
            $out.Trim() | Should -Be 'nrg'
        }
    }

    Context 'the entry point' {

        It 'stops with exit code 4 on a profile that does not exist, before anything else runs' {
            $out = & $script:Pwsh -NoProfile -File (Join-Path $script:Root 'Invoke-TPAssessment.ps1') -Profile nosuchprofile -NonInteractive 2>&1 | Out-String
            $LASTEXITCODE | Should -Be 4
            $out | Should -Match "Profile 'nosuchprofile'"
            $out | Should -Match 'Available profiles:'
        }

        It 'stops with exit code 4 on a TP_PROFILE that does not exist' {
            $null = & $script:Pwsh -NoProfile -Command "`$env:TP_PROFILE = 'nosuchprofile'; & '$($script:Root)/Invoke-TPAssessment.ps1' -NonInteractive; exit `$LASTEXITCODE" 2>&1
            $LASTEXITCODE | Should -Be 4
        }

        It '-Profile is validated with \A and \z, so a trailing line feed is not a name' {
            $script:EntrySrc | Should -Match ([regex]::Escape('[ValidatePattern(''\A(?:|[a-z0-9][a-z0-9-]{0,31})\z'', Options = ''None'')]'))
            $script:EntrySrc | Should -Not -Match ([regex]::Escape('^$|^[a-z0-9]'))
        }

        It 'reads no profile data from Config/branding.psd1 itself: the declared products and monitoring addresses come from the loaded profile' {
            $script:EntrySrc | Should -Not -Match ([regex]::Escape('Join-Path $scriptDir ''Config'' ''branding.psd1'''))
            $script:EntrySrc | Should -Match ([regex]::Escape('Get-TPProfileDeclaration -Brand $TPBrand -Key EdrStack'))
            $script:EntrySrc | Should -Match ([regex]::Escape('Get-TPProfileDeclaration -Brand $TPBrand -Key AwarenessStack'))
            $script:EntrySrc | Should -Match ([regex]::Escape('Get-TPObjectField -Item $TPBrand -Key ''MonitoringAddresses'''))
        }

        It 'puts TP_PROFILE back after the import, so a later run in the same console does not keep this run''s practice' {
            $script:EntrySrc | Should -Match '\$profileEnvBefore = \$env:TP_PROFILE'
            $script:EntrySrc | Should -Match 'Remove-Item -LiteralPath Env:TP_PROFILE'
            $script:EntrySrc | Should -Match '\$env:TP_PROFILE = \$profileEnvBefore'
        }
    }

    Context 'Get-TPProfileDeclaration' {

        It 'returns a plain product name' {
            Get-TPProfileDeclaration -Brand @{ EdrStack = 'Cortex XDR'; ProfileName = 'acme' } -Key EdrStack | Should -Be 'Cortex XDR'
            Get-TPProfileDeclaration -Brand @{ AwarenessStack = '  KnowBe4  ' } -Key AwarenessStack | Should -Be 'KnowBe4'
        }

        It 'returns nothing when the profile declares none, whatever the shape of the profile' {
            Get-TPProfileDeclaration -Brand @{ CompanyName = 'x' } -Key EdrStack | Should -Be ''
            Get-TPProfileDeclaration -Brand $null -Key EdrStack | Should -Be ''
            Get-TPProfileDeclaration -Brand @{ EdrStack = '' } -Key EdrStack | Should -Be ''
        }

        It 'ignores an unusable value with a warning that names the profile and the key' {
            $w = $null
            $v = Get-TPProfileDeclaration -Brand @{ EdrStack = 'rm -rf /; $(x)'; ProfileName = 'acme' } -Key EdrStack -WarningVariable w -WarningAction SilentlyContinue
            $v | Should -Be ''
            ($w -join ' ') | Should -Match "Ignoring EdrStack .* in the acme profile"
        }
    }

    Context 'the other readers of the profile' {

        It 'the report site and tenant onboarding read the loaded profile, not a second copy of branding.psd1' {
            $site = Get-Content -LiteralPath (Join-Path $script:Root 'Publishers' 'Publish-TPReportSite.ps1') -Raw
            $site | Should -Not -Match "'branding\.psd1'"
            $site | Should -Match '\$script:TPBrand'
            $site | Should -Not -Match "CompanyName = 'NRG Technology Services'" -Because 'the neutral default is TenantPosture'
            $onboard = Get-Content -LiteralPath (Join-Path $script:Root 'Onboard' 'Register-TPTenantApp.ps1') -Raw
            $onboard | Should -Not -Match "'branding\.psd1'"
            $onboard | Should -Match 'Resolve-TPProfilePath'
        }

        It 'the web server passes its profile to the scan it launches, since TP_PROFILE is no longer left set' {
            $web = Get-Content -LiteralPath (Join-Path $script:Root 'Lib' 'Start-TPWebServer.ps1') -Raw
            $web | Should -Match ([regex]::Escape('@(''-Profile'', $profileName)'))
            $web | Should -Match ([regex]::Escape('ProfileName = $activeProfileName'))
        }
    }

    Context 'Get-TPStandards: the profile completes the shared file, never an explicit one' {

        BeforeAll {
            Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
            $script:StdFile = Join-Path $script:Tmp 'std.json'
            Set-Content -LiteralPath $script:StdFile -Value '{ "DmarcReportingAddresses": { "Values": [] } }' -Encoding utf8
        }

        It 'with an explicit -Path, the file is the whole truth (a profile address is not put over it)' {
            $m = Get-Module TenantPosture
            $r = & $m {
                param($file)
                $script:TPBrand = @{ DmarcReportingAddresses = @('profile@example.test'); ProfileName = 'acme' }
                @((Get-TPStandards -Path $file).DmarcReportingAddresses)
            } $script:StdFile
            @($r).Count | Should -Be 0
        }

        It 'with the shared default file, the profile supplies the address it names' {
            $m = Get-Module TenantPosture
            $r = & $m {
                $script:TPBrand = @{ DmarcReportingAddresses = @('profile@example.test'); ProfileName = 'acme' }
                @((Get-TPStandards).DmarcReportingAddresses)
            }
            @($r) | Should -Be @('profile@example.test')
        }
    }
}
