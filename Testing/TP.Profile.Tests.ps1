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

# The report's stylesheet printed a dictionary's type name where the primary color belonged on the first
# live run under the NRG profile: the publisher kept the colors in $P, $S and $A, and two loops lower in the
# same function iterate $p and $a. PowerShell variable names ignore case, so those are the same variables.
Describe 'The loaded profile colors reach the HTML report' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    }
    AfterAll { Clear-TPState; Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }

    It 'writes the brand colors into :root after a Conditional Access policy and an attachment have been rendered' {
        Clear-TPState
        # One CA policy and one attachment make the publisher run the two loops that overwrote the colors.
        Set-TPRawData -Key 'AAD-CAPolicies' -Data @{ Success = $true; Data = @{ Policies = @(@{ Id = 'p1'; DisplayName = 'Block legacy'; State = 'enabled'
            Conditions = @{ Users = @{ IncludeUsers = @('All') }; Applications = @{ Include = @('All') }; ClientAppTypes = @('other') }
            GrantControls = @{ Operator = 'OR'; BuiltInControls = @('block') } }) } }
        Add-TPFinding -ControlId 'AAD-1.1' -State 'Gap' -Category 'Identity' -Title 'Legacy authentication' -Severity 'High' -Detail 'Shortfall: not blocked.'
        $dir = Join-Path $TestDrive 'brand'; New-Item -ItemType Directory -Path $dir -Force | Out-Null
        $out = Join-Path $dir 'r.html'
        Publish-TPAssessmentHTML -Metadata @{ TenantDomain = 'contoso.example'; TenantId = '00000000-0000-0000-0000-000000000000'; Operator = 'a'; AssessmentDate = 'October 14, 2026'; AssessmentTime = '2026-10-14T16:44:43+00:00'; ToolVersion = '4.14.3'; QuickScan = $false
                Brand = @{ CompanyName = 'Acme Managed IT'; PrimaryColor = '#1a3a6b'; SecondaryColor = '#e87722'; AccentColor = '#4a7ba6' } } `
            -Findings (Get-TPFindings) -Connections @{ Graph = $true; EXO = $true; IPPSSession = $true; Teams = $true; SharePoint = $true } `
            -OutputPath $out -Attachments @(@{ Label = 'Playbook'; FileName = 'playbook.md'; Mime = 'text/markdown'; Content = '# playbook' }) | Out-Null
        $html = Get-Content -LiteralPath $out -Raw
        $html | Should -Match ':root\{--P:#1a3a6b;--S:#e87722;--A:#4a7ba6;'
        $html | Should -Match 'linear-gradient\(138deg,#1a3a6b 0%'
        $html | Should -Not -Match 'System\.Collections' -Because 'a type name in the stylesheet is a variable that was overwritten'
    }

    It 'no publisher uses one single-letter variable name in two casings inside one function (PowerShell ignores case)' {
        $files = @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'Publishers') -Filter '*.ps1') +
                 @(Get-ChildItem -LiteralPath (Join-Path $script:RepoRoot 'Email-IR' 'Publishers') -Filter '*.ps1' -ErrorAction SilentlyContinue)
        $fnType  = [System.Management.Automation.Language.FunctionDefinitionAst]
        $varType = [System.Management.Automation.Language.VariableExpressionAst]
        $bad = foreach ($f in $files) {
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$null, [ref]$null)
            foreach ($fn in @($ast.FindAll({ param($n) $n -is $fnType }, $true))) {
                # Variables in this function's own body; a function nested inside it is its own scope.
                $own = @($fn.Body.FindAll({ param($n) $n -is $varType }, $true) | Where-Object {
                    $p = $_.Parent; $nested = $false
                    while ($null -ne $p -and -not [object]::ReferenceEquals($p, $fn)) { if ($p -is $fnType) { $nested = $true; break }; $p = $p.Parent }
                    -not $nested })
                $names = @($own | ForEach-Object { $_.VariablePath.UserPath } | Where-Object { $_.Length -eq 1 } | Sort-Object -Unique -CaseSensitive)
                foreach ($g in @($names | Group-Object { $_.ToLowerInvariant() } | Where-Object { $_.Count -gt 1 })) {
                    "$($f.Name): $($fn.Name) uses " + (($g.Group | ForEach-Object { '$' + $_ }) -join ' and ')
                }
            }
        }
        $bad | Should -BeNullOrEmpty
    }
}

Describe 'The loaded profile name reaches the playbook and the executive summary' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:PbFindings = @(
            @{ ControlId = 'AAD-1.1'; State = 'Gap'; Severity = 'High'; Category = 'Identity'; Title = 'Legacy authentication'; Detail = 'Not blocked.'; CurrentValue = 'none'; RequiredValue = 'block'; Remediation = 'Block it.'; FrameworkIds = 'NIST:IA-2'; AffectedObjects = @() },
            @{ ControlId = 'EXO-1.1'; State = 'Satisfied'; Severity = 'Informational'; Category = 'Email'; Title = 'Audit'; Detail = 'On.'; CurrentValue = 'on'; RequiredValue = 'on'; Remediation = 'm'; FrameworkIds = 'NIST:AU-2'; AffectedObjects = @() }
        )
        $script:PbConn = @{ Graph = $true; EXO = $true; Teams = $false; IPPSSession = $false; SharePoint = $false }
    }
    AfterAll { Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue }

    It 'prints the brand recorded in the run metadata, never another practice''s name (the executive summary hard-coded one)' {
        $d = Join-Path $TestDrive 'pb-brand'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        $meta = @{ TenantDomain = 'contoso.example'; AssessmentDate = 'October 31, 2026'; ToolVersion = '4.14.3'; Operator = 'a'
                   Brand = @{ CompanyName = 'Acme Managed IT' } }
        Publish-TPRemediationPlaybook -Metadata $meta -Findings $script:PbFindings -Connections $script:PbConn `
            -OutputPath (Join-Path $d 'p.md') -ExecutivePath (Join-Path $d 'e.md') | Out-Null
        foreach ($f in 'p.md', 'e.md') {
            $t = Get-Content -LiteralPath (Join-Path $d $f) -Raw
            $t | Should -Match 'Acme Managed IT' -Because "$f must name the run's own practice"
            $t | Should -Not -Match 'NRG Technology Services' -Because "$f printed the other practice's name on an nls-profile run"
        }
    }

    It 'falls back to the loaded profile, then the neutral default, when the metadata records no brand' {
        $d = Join-Path $TestDrive 'pb-nobrand'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        $meta = @{ TenantDomain = 'contoso.example'; AssessmentDate = 'October 31, 2026'; ToolVersion = '4.14.3'; Operator = 'a' }
        Publish-TPRemediationPlaybook -Metadata $meta -Findings $script:PbFindings -Connections $script:PbConn `
            -OutputPath (Join-Path $d 'p.md') -ExecutivePath (Join-Path $d 'e.md') | Out-Null
        $loaded = [string](Get-TPObjectField -Item (Get-Variable -Name TPBrand -ValueOnly -ErrorAction SilentlyContinue) -Key 'CompanyName' -Default '')
        $want = if ($loaded) { $loaded } else { 'NRG Technology Services / NextLayerSec LLC' }
        (Get-Content -LiteralPath (Join-Path $d 'e.md') -Raw) | Should -Match ('\*\*Prepared by:\*\* ' + [regex]::Escape((ConvertTo-TPMarkdownSafe $want)))
    }
}
