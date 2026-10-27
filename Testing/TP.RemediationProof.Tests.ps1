#Requires -Version 7.0
#
# TP.RemediationProof.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Guards the proof of fix: Lib/Get-TPRemediationProof.ps1,
# Publishers/Publish-TPRemediationProof.ps1, New-TPRemediationProof.ps1 and
# Invoke-TPAssessment.ps1 -ProofAgainst. The certificate goes to a client, so:
#   - every verdict is pinned, and Not verifiable is never Resolved
#   - two tenants, or an "after" that is not newer, are refused
#   - the hashes are the SHA-256 of the files on disk
#   - the evidence names run times, versions and patterns, never the operator,
#     the tenant id or a finding's detail
#   - the real entry point with stub modules writes it after a -ControlId run
# Data keys consumed: none live. Graph scopes / cmdlets: none (stubs only).

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    $script:Mod = Get-Module TenantPosture
    . (Join-Path $script:RepoRoot 'Testing' 'TP.MspFixtures.ps1')
    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('tp-proof-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    $null = [IO.Directory]::CreateDirectory($script:Tmp)
    $script:T0 = [datetime]::new(2030, 6, 1, 9, 0, 0, [DateTimeKind]::Utc)
    $script:Tid = 'aaaaaaaa-1111-4111-8111-000000000001'

    $script:Write = {
        param([string] $Name, [object[]] $Findings, [datetime] $Time, [string] $TenantId = $script:Tid, [string[]] $Selected = $null, [string[]] $Include = @(), [string] $Version = '4.14.3')
        $o = New-TPMspFixtureResults -TenantId $TenantId -Time $Time -Findings $Findings -SelectedControlIds $Selected -Include $Include -ToolVersion $Version
        Write-TPMspFixture -Object $o -Path (Join-Path $script:Tmp $Name)
    }
    $script:Proof = {
        param([string] $Before, [string] $After, [string[]] $Patterns = @())
        $b = Read-TPRunRecord -Path $Before -Hash
        $a = Read-TPRunRecord -Path $After -Hash
        Get-TPRemediationProof -Before $b -After $a -ControlId $Patterns
    }
    $script:Fb = @(
        @{ ControlId = 'AAD-1.1'; State = 'Gap'; Severity = 'Critical'; CurrentValue = 'No CA policy blocks legacy auth' }
        @{ ControlId = 'AAD-1.2'; State = 'Gap'; Severity = 'Critical'; CurrentValue = 'Admins only' }
        @{ ControlId = 'AAD-1.3'; State = 'Partial'; Severity = 'High' }
        @{ ControlId = 'DNS-1.3'; State = 'Gap'; Severity = 'High' }
        @{ ControlId = 'SPO-1.1'; State = 'Satisfied'; Severity = 'High' }
        @{ ControlId = 'EXO-1.6'; State = 'Satisfied'; Severity = 'High' }
        @{ ControlId = 'DEF-1.5'; State = 'Partial'; Severity = 'High' }
        @{ ControlId = 'AAD-1.4'; State = 'NotApplicable'; Severity = 'High' }
        @{ ControlId = 'AAD-1.5'; State = 'Gap'; Severity = 'High' }
        @{ ControlId = 'TMS-1.1'; State = 'Gap'; Severity = 'Medium' }
    )
    $script:Fa = @(
        @{ ControlId = 'AAD-1.1'; State = 'Satisfied'; Severity = 'Critical'; CurrentValue = 'Blocked for all users' }
        @{ ControlId = 'AAD-1.2'; State = 'Partial'; Severity = 'Critical' }
        @{ ControlId = 'AAD-1.3'; State = 'Partial'; Severity = 'High' }
        @{ ControlId = 'DNS-1.3'; State = 'NotApplicable'; Severity = 'High' }
        @{ ControlId = 'SPO-1.1'; State = 'Satisfied'; Severity = 'High' }
        @{ ControlId = 'EXO-1.6'; State = 'Gap'; Severity = 'High' }
        @{ ControlId = 'DEF-1.5'; State = 'Gap'; Severity = 'High' }
        @{ ControlId = 'AAD-1.4'; State = 'Satisfied'; Severity = 'High' }
        @{ ControlId = 'AAD-1.5'; State = 'Error'; Severity = 'High' }
        @{ ControlId = 'PVW-1.1'; State = 'Satisfied'; Severity = 'High' }
    )
    $script:Before = & $script:Write 'before-results.json' $script:Fb $script:T0
    $script:AfterIds = @('AAD-1.1', 'AAD-1.2', 'AAD-1.3', 'DNS-1.3', 'SPO-1.1', 'EXO-1.6', 'DEF-1.5', 'AAD-1.4', 'AAD-1.5', 'PVW-1.1', 'TMS-1.1')
    $script:After = & $script:Write 'after-results.json' $script:Fa $script:T0.AddDays(10) -Selected $script:AfterIds -Include @('AAD-1.*', 'DNS-1.3', 'SPO-1.1', 'EXO-1.6', 'DEF-1.5', 'PVW-1.1', 'TMS-1.1') -Version '4.14.4'
    $script:P = & $script:Proof $script:Before $script:After
    $script:Row = { param([string] $Id) @($script:P.Controls | Where-Object { $_.ControlId -eq $Id })[0] }
}

AfterAll {
    if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    Remove-Module 'TenantPosture' -Force -ErrorAction SilentlyContinue
}

Describe 'Proof of fix: verdicts' {
    It '<Before> then <After> is <Verdict>' -ForEach @(
        @{ Before = 'Gap'; After = 'Satisfied'; Verdict = 'Resolved' }
        @{ Before = 'Partial'; After = 'Satisfied'; Verdict = 'Resolved' }
        @{ Before = 'Gap'; After = 'Partial'; Verdict = 'Improved' }
        @{ Before = 'Gap'; After = 'Gap'; Verdict = 'Not resolved' }
        @{ Before = 'Partial'; After = 'Partial'; Verdict = 'Not resolved' }
        @{ Before = 'Satisfied'; After = 'Gap'; Verdict = 'Regressed' }
        @{ Before = 'Satisfied'; After = 'Partial'; Verdict = 'Regressed' }
        @{ Before = 'Partial'; After = 'Gap'; Verdict = 'Regressed' }
        @{ Before = 'Satisfied'; After = 'Satisfied'; Verdict = 'Already met' }
        @{ Before = 'NotApplicable'; After = 'Satisfied'; Verdict = 'No earlier verdict' }
        @{ Before = 'Error'; After = 'Gap'; Verdict = 'No earlier verdict' }
        @{ Before = 'Gap'; After = 'NotApplicable'; Verdict = 'Not verifiable' }
        @{ Before = 'Gap'; After = 'Error'; Verdict = 'Not verifiable' }
        @{ Before = 'Partial'; After = ''; Verdict = 'Not verifiable' }
        @{ Before = 'Satisfied'; After = 'NotApplicable'; Verdict = 'Not verifiable' }
    ) {
        (& $script:Mod { param($b, $a) Get-TPRemediationProofVerdict -Before $b -After $a } $Before $After) | Should -Be $Verdict
    }
    It 'judges the real files: each control lands where the rule says' {
        (& $script:Row 'AAD-1.1').Verdict | Should -Be 'Resolved'
        (& $script:Row 'AAD-1.2').Verdict | Should -Be 'Improved'
        (& $script:Row 'AAD-1.3').Verdict | Should -Be 'Not resolved'
        (& $script:Row 'EXO-1.6').Verdict | Should -Be 'Regressed'
        (& $script:Row 'DEF-1.5').Verdict | Should -Be 'Regressed'
        (& $script:Row 'SPO-1.1').Verdict | Should -Be 'Already met'
        (& $script:Row 'AAD-1.4').Verdict | Should -Be 'No earlier verdict'
    }
    It 'a control the after run could not judge is Not verifiable, never resolved' {
        (& $script:Row 'DNS-1.3').Verdict | Should -Be 'Not verifiable'
        (& $script:Row 'AAD-1.5').Verdict | Should -Be 'Not verifiable'
        $tms = & $script:Row 'TMS-1.1'
        $tms.Verdict | Should -Be 'Not verifiable' -Because 'selected in the after run but it produced no finding'
        $tms.AfterState | Should -Be 'No finding'
        $script:P.Counts['Resolved'] | Should -Be 1
        $script:P.Headline | Should -Be '1 of 10 listed control(s) resolved'
    }
    It 'compares the after run''s selection that the before run also assessed, and lists the rest' {
        @($script:P.Controls).Count | Should -Be 10
        @($script:P.NotInBefore) | Should -Be @('PVW-1.1')
        ($script:P.Notes -join ' ') | Should -Match 'PVW-1\.1'
    }
    It '-ControlId narrows the controls, and a bad pattern is refused' {
        $p = & $script:Proof $script:Before $script:After @('AAD-1.1', 'DNS-*')
        @($p.Controls | ForEach-Object { $_.ControlId }) | Should -Be @('AAD-1.1', 'DNS-1.3')
        (& $script:Proof $script:Before $script:After @('A[1]')).Refused | Should -BeTrue
    }
}

Describe 'Proof of fix: refusals' {
    It 'refuses two different tenants' {
        $other = & $script:Write 'other-tenant-results.json' $script:Fa $script:T0.AddDays(10) -TenantId 'bbbbbbbb-2222-4222-8222-000000000002'
        $p = & $script:Proof $script:Before $other
        $p.Available | Should -BeFalse
        $p.Refused | Should -BeTrue
        $p.Note | Should -Match 'different tenants'
    }
    It 'refuses a file with no TenantId' {
        $none = & $script:Write 'no-tenant-results.json' $script:Fa $script:T0.AddDays(10) -TenantId ''
        (& $script:Proof $script:Before $none).Note | Should -Match 'no TenantId'
    }
    It 'refuses an after run that is older than, or as old as, the before run' {
        $older = & $script:Write 'older-results.json' $script:Fa $script:T0.AddDays(-1)
        $p = & $script:Proof $script:Before $older
        $p.Refused | Should -BeTrue
        $p.Note | Should -Match 'not newer'
        (& $script:Proof $script:Before $script:Before).Refused | Should -BeTrue
    }
    It 'refuses an incident-response output' {
        $ir = Write-TPMspFixture -Object ([ordered]@{ Metadata = @{ TenantId = $script:Tid }; DeepDives = @(@{ U = 1 }); Findings = @() }) -Path (Join-Path $script:Tmp 'u-email-results.json')
        (& $script:Proof $script:Before $ir).Refused | Should -BeTrue
    }
}

Describe 'Proof of fix: evidence and the certificate' {
    BeforeAll {
        $script:Out = Join-Path $script:Tmp 'cert'
        $script:Files = Publish-TPRemediationProof -Proof $script:P -OutputPath $script:Out -GeneratedAt ([datetime]::new(2030, 6, 11, 8, 30, 0, [DateTimeKind]::Utc)) -Brand @{ CompanyName = 'Fabrikam Managed IT'; PrimaryColor = '#0f766e' }
        $script:Html = Get-Content -LiteralPath $script:Files.Html -Raw
        $script:Md = Get-Content -LiteralPath $script:Files.Markdown -Raw
    }
    It 'the hashes are the SHA-256 of the files on disk' {
        $script:P.Before.Sha256 | Should -Be (Get-FileHash -LiteralPath $script:Before -Algorithm SHA256).Hash.ToLowerInvariant()
        $script:P.After.Sha256 | Should -Be (Get-FileHash -LiteralPath $script:After -Algorithm SHA256).Hash.ToLowerInvariant()
        $script:Html | Should -Match $script:P.Before.Sha256
        $script:Md | Should -Match $script:P.After.Sha256
    }
    It 'names both run times in UTC, both tool versions and the exact selection patterns' {
        $script:Html | Should -Match '2030-06-01 09:00:00 UTC'
        $script:Html | Should -Match '2030-06-11 09:00:00 UTC'
        $script:Html | Should -Match '4\.14\.3'
        $script:Html | Should -Match '4\.14\.4'
        $script:Html | Should -Match '-ControlId AAD-1\.\*, DNS-1\.3'
        ($script:P.Notes -join ' ') | Should -Match 'different tool versions'
    }
    It 'states that it covers only the listed controls and what the tool observed' {
        $script:Html | Should -Match 'covers only the 10 control\(s\) listed below, and only what TenantPosture observed'
        $script:Md | Should -Match 'covers only the 10 control'
    }
    It 'never carries the operator, the tenant id or a finding''s detail' {
        foreach ($text in $script:Html, $script:Md) {
            $text | Should -Not -Match 'operator@msp\.example|alice@|rawdata-marker|exception-marker'
            $text | Should -Not -Match ([regex]::Escape($script:Tid))
        }
    }
    It 'is named <tenant>-proof-<time>, branded, printable and self-contained' {
        (Split-Path -Leaf $script:Files.Html) | Should -Be 'contoso-proof-20300611-083000.html'
        (Split-Path -Leaf $script:Files.Markdown) | Should -Be 'contoso-proof-20300611-083000.md'
        $script:Html | Should -Match 'Fabrikam Managed IT'
        $script:Html | Should -Match '@media print'
        $script:Html | Should -Not -Match '(?i)<script|(https?:)?//[a-z0-9]'
    }
    It 'never says compliant and never draws Not verifiable as fixed' {
        foreach ($text in $script:Html, $script:Md) { $text | Should -Not -Match '(?i)\bcompliant\b' }
        $script:Html | Should -Match 'tp-pill--neutral"><span class="tp-pill-icon" aria-hidden="true">&#8211;</span>Not verifiable'
    }
    It 'escapes a hostile current value' {
        $hb = & $script:Write 'h-before-results.json' @(, @{ ControlId = 'AAD-1.1'; State = 'Gap'; Severity = 'High'; CurrentValue = '<img src=x onerror=alert(1)>[x](javascript:y)' }) $script:T0
        $ha = & $script:Write 'h-after-results.json' @(, @{ ControlId = 'AAD-1.1'; State = 'Satisfied'; Severity = 'High' }) $script:T0.AddDays(1)
        $f = Publish-TPRemediationProof -Proof (& $script:Proof $hb $ha) -OutputPath (Join-Path $script:Tmp 'hostile')
        (Get-Content -LiteralPath $f.Html -Raw) | Should -Not -Match '<img'
        $md = Get-Content -LiteralPath $f.Markdown -Raw
        $md | Should -Match '\\\[x\\\]' -Because 'the brackets are escaped, so no link can form'
        $md | Should -Not -Match '(?<!\\)\[x(?<!\\)\]\('
    }
    It 'a value that is not a control id never reaches the table' {
        $bad = & $script:Write 'bad-before-results.json' @(@{ ControlId = 'AAD-1.1'; State = 'Gap'; Severity = 'High' }, @{ ControlId = '`x|y'; State = 'Gap'; Severity = 'High' }) $script:T0
        $rec = Read-TPRunRecord -Path $bad
        $rec.DroppedFindings | Should -Be 1
        @($rec.Findings).Count | Should -Be 1
    }
}

Describe 'Proof of fix: the standalone script' {
    BeforeAll {
        $script:Script = Join-Path $script:RepoRoot 'New-TPRemediationProof.ps1'
        $script:Run = {
            param([string[]] $Arguments)
            $text = & (Get-Process -Id $PID).Path -NoProfile -File $script:Script @Arguments *>&1 | Out-String
            [pscustomobject]@{ Code = $LASTEXITCODE; Text = $text }
        }
    }
    It 'writes the certificate and exits 0' {
        $out = Join-Path $script:Tmp 'cli'
        $r = & $script:Run @('-BeforeResults', $script:Before, '-AfterResults', $script:After, '-OutputPath', $out, '-ControlId', 'AAD-1.1')
        $r.Code | Should -Be 0 -Because $r.Text
        @(Get-ChildItem -LiteralPath $out -Filter 'contoso-proof-*').Count | Should -Be 2
        $r.Text | Should -Match '1 of 1 listed control\(s\) resolved'
        $r.Text | Should -Match 'connected to nothing'
    }
    It 'exits 4 and writes nothing for two tenants' {
        $other = Join-Path $script:Tmp 'other-tenant-results.json'
        $out = Join-Path $script:Tmp 'cli-refused'
        $r = & $script:Run @('-BeforeResults', $script:Before, '-AfterResults', $other, '-OutputPath', $out)
        $r.Code | Should -Be 4
        $r.Text | Should -Match 'different tenants'
        Test-Path -LiteralPath $out | Should -BeFalse
    }
    It 'exits 2 when no control is in both runs' {
        $only = & $script:Write 'only-results.json' @(, @{ ControlId = 'PVW-1.1'; State = 'Satisfied'; Severity = 'High' }) $script:T0.AddDays(2)
        $r = & $script:Run @('-BeforeResults', $script:Before, '-AfterResults', $only, '-OutputPath', (Join-Path $script:Tmp 'cli-none'))
        $r.Code | Should -Be 2
    }
    It 'makes no tenant or network call (static)' {
        foreach ($file in 'Lib/Get-TPRemediationProof.ps1', 'Publishers/Publish-TPRemediationProof.ps1', 'New-TPRemediationProof.ps1') {
            $tokens = $null; $errs = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:RepoRoot $file), [ref]$tokens, [ref]$errs)
            @($errs).Count | Should -Be 0
            $cmds = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
            foreach ($cmd in $cmds) { $cmd | Should -Not -Match '^(Connect-|Invoke-(RestMethod|WebRequest|TPGraphRequest)$|Get-Mg|Resolve-TPDns$|Start-Process$|Add-TPFinding$|Get-TPRawData$)' }
            (@($tokens | Where-Object { $_.Kind -ne 'Comment' } | ForEach-Object { $_.Text }) -join ' ') | Should -Not -Match 'https?://'
        }
    }
}

Describe 'Proof of fix: Invoke-TPAssessment.ps1 -ProofAgainst' {
    BeforeAll {
        $script:Mods = Join-Path $script:Tmp 'mods'
        $exoVersion = [string](& $script:Mod { Get-TPExoModuleFloor }).Min
        $stub = {
            param([string] $Name, [string] $Version, [string] $Guid, [string] $Body)
            $d = Join-Path $script:Mods $Name $Version
            $null = [IO.Directory]::CreateDirectory($d)
            Set-Content -LiteralPath (Join-Path $d "$Name.psd1") -Encoding utf8 -Value "@{ RootModule = '$Name.psm1'; ModuleVersion = '$Version'; GUID = '$Guid'; FunctionsToExport = '*'; CmdletsToExport = @(); AliasesToExport = @() }"
            Set-Content -LiteralPath (Join-Path $d "$Name.psm1") -Encoding utf8 -Value $Body
        }
        & $stub 'Microsoft.Graph.Authentication' '2.40.0' 'b0b0b0b0-1111-4222-8333-444444444444' @'
function Connect-MgGraph { [CmdletBinding()] param($Scopes, $ContextScope, [switch] $NoWelcome, $TenantId, $Environment) }
function Disconnect-MgGraph { [CmdletBinding()] param() }
function Get-MgContext { [pscustomobject]@{ Account = 'admin@proof.example'; TenantId = '00000000-0000-0000-0000-00000000abcd'; Scopes = @(); Environment = 'Global' } }
function Invoke-MgGraphRequest { [CmdletBinding()] param($Uri, $Method, $OutputType, $Headers, $Body) @{ value = @() } }
'@
        & $stub 'ExchangeOnlineManagement' $exoVersion 'c0c0c0c0-1111-4222-8333-555555555555' @'
function Connect-ExchangeOnline { [CmdletBinding()] param([switch] $ShowBanner, [switch] $DisableWAM, $Organization, $UserPrincipalName, $DelegatedOrganization, [switch] $SkipLoadingFormatData) }
function Disconnect-ExchangeOnline { [CmdletBinding()] param($Confirm) }
function Get-ConnectionInformation { @() }
'@
        & $stub 'MicrosoftTeams' '5.9.0' 'd0d0d0d0-1111-4222-8333-666666666666' 'function Connect-MicrosoftTeams { }'
        $script:RunEntry = {
            param([string] $ArgText)
            $old = $env:PSModulePath
            try {
                $env:PSModulePath = $script:Mods + [System.IO.Path]::PathSeparator + $env:PSModulePath
                $cmd = "& '$(Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1')' $ArgText; exit `$LASTEXITCODE"
                $text = (& (Get-Process -Id $PID).Path -NoProfile -NonInteractive -Command $cmd *>&1 | Out-String)
                $code = $LASTEXITCODE
            } finally { $env:PSModulePath = $old }
            [pscustomobject]@{ Output = ($text -replace "\e\[[0-9;]*m", ''); ExitCode = $code }
        }
        # The stub tenant's id; the before run predates now.
        $script:StubBefore = & $script:Write 'stub-before-results.json' @(, @{ ControlId = 'AAD-1.2'; State = 'Gap'; Severity = 'Critical' }) ([datetime]::UtcNow.AddDays(-3)) -TenantId '00000000-0000-0000-0000-00000000abcd'
        $script:StubOther = & $script:Write 'stub-other-results.json' @(, @{ ControlId = 'AAD-1.2'; State = 'Gap'; Severity = 'Critical' }) ([datetime]::UtcNow.AddDays(-3)) -TenantId 'bbbbbbbb-2222-4222-8222-000000000002'
    }
    It 'after a -ControlId re-check, writes the certificate comparing it with the before file' {
        $out = Join-Path $script:Tmp 'entry'
        $r = & $script:RunEntry "-NonInteractive -ControlId AAD-1.2 -JsonOnly -ProofAgainst '$script:StubBefore' -OutputPath '$out'"
        $r.ExitCode | Should -BeIn @(0, 3) -Because $r.Output
        $r.Output | Should -Match 'Proof of fix \(html\)'
        $cert = @(Get-ChildItem -LiteralPath $out -Filter '*-proof-*.html')
        $cert.Count | Should -Be 1
        $html = Get-Content -LiteralPath $cert[0].FullName -Raw
        $html | Should -Match 'AAD-1\.2'
        $html | Should -Match '-ControlId AAD-1\.2'
        $html | Should -Not -Match 'admin@proof\.example' -Because 'the operator is never printed'
        $results = @(Get-ChildItem -LiteralPath $out -Filter '*-results.json')[0]
        $html | Should -Match (Get-FileHash -LiteralPath $results.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    It 'refuses another tenant''s file after the run, writing no certificate' {
        $out = Join-Path $script:Tmp 'entry-other'
        $r = & $script:RunEntry "-NonInteractive -ControlId AAD-1.2 -JsonOnly -ProofAgainst '$script:StubOther' -OutputPath '$out'"
        $r.ExitCode | Should -BeIn @(0, 3) -Because $r.Output
        $r.Output | Should -Match 'Proof of fix not written: .*different tenants'
        @(Get-ChildItem -LiteralPath $out -Filter '*-proof-*' -ErrorAction SilentlyContinue).Count | Should -Be 0
    }
    It 'stops before any sign-in when the file cannot serve as the before run (exit 4)' {
        $bad = Join-Path $script:Tmp 'not-results.json'
        Set-Content -LiteralPath $bad -Value '{ "Metadata": { "TenantDomain": "x.example" }, "Findings": [] }' -Encoding utf8
        $r = & $script:RunEntry "-NonInteractive -ControlId AAD-1.2 -JsonOnly -ProofAgainst '$bad' -OutputPath '$(Join-Path $script:Tmp 'entry-bad')'"
        $r.ExitCode | Should -Be 4
        $r.Output | Should -Match 'ProofAgainst cannot be used: it records no TenantId'
        $r.Output | Should -Not -Match 'Connecting to M365'
    }
}
