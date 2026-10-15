#Requires -Version 7.0
<#
    TP.OutputFolderProbe.Tests.ps1
    NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: The output folder is proven to hold a protected file before any sign-in
             (Test-TPSensitiveOutputFolder), a refusal names the volume and the remedy,
             the probe file never survives, and every entry point probes before it connects.
    Data keys: none.  Cmdlets: none (local file system only).
#>

Describe 'Output folder probe: the writer is proven before any sign-in' {
    BeforeAll {
        $script:Root = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module TenantPosture
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('tp-probe-' + [guid]::NewGuid().ToString('N'))
        $null = [System.IO.Directory]::CreateDirectory($script:Tmp)
        $script:OrigHandleAcl = & $script:Mod { ${function:script:Set-TPSensitiveHandleAcl} }
        $script:OrigFormat    = & $script:Mod { ${function:script:Get-TPVolumeFormat} }
        $script:Inject = {
            param([scriptblock] $HandleAcl, [scriptblock] $Format)
            & $script:Mod { param($a, $f) if ($a) { Set-Item -Path function:script:Set-TPSensitiveHandleAcl -Value $a }; if ($f) { Set-Item -Path function:script:Get-TPVolumeFormat -Value $f } } $HandleAcl $Format
        }
    }
    AfterAll { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    AfterEach { & $script:Inject $script:OrigHandleAcl $script:OrigFormat }

    It 'passes on a folder the writer can protect and leaves no probe file behind' {
        $r = Test-TPSensitiveOutputFolder -Path $script:Tmp
        $r.Ok | Should -BeTrue
        @(Get-ChildItem -LiteralPath $script:Tmp -Force -Filter '.tp-write-probe-*').Count | Should -Be 0
    }

    It 'refuses a folder whose file cannot be hardened, names the volume and the remedy, and leaves no probe file behind' {
        & $script:Inject { param($Stream) throw 'Attempted to perform an unauthorized operation.' } { param($Path) 'exFAT' }
        $msg = $null
        try { $null = Test-TPSensitiveOutputFolder -Path $script:Tmp } catch { $msg = $_.Exception.Message }
        $msg | Should -Not -BeNullOrEmpty
        $msg | Should -Match 'cannot hold a protected results file'
        $msg | Should -Match "reports 'exFAT'"
        $msg | Should -Match 'cannot hold an access control list'
        $msg | Should -Match 'unauthorized operation'
        $msg | Should -Match '-OutputPath'
        @(Get-ChildItem -LiteralPath $script:Tmp -Force -Filter '.tp-write-probe-*').Count | Should -Be 0
    }

    It 'an NTFS volume is not blamed: the refusal still carries the reason and the remedy' {
        & $script:Inject { param($Stream) throw 'boom' } { param($Path) 'NTFS' }
        $msg = $null
        try { $null = Test-TPSensitiveOutputFolder -Path $script:Tmp } catch { $msg = $_.Exception.Message }
        $msg | Should -Match "reports 'NTFS'"
        $msg | Should -Not -Match 'cannot hold an access control list'
        $msg | Should -Match 'boom'
        $msg | Should -Match '-OutputPath'
    }

    It 'a refused probe is not reported as a pass' {
        & $script:Inject { param($Stream) throw 'no' } $null
        { Test-TPSensitiveOutputFolder -Path $script:Tmp } | Should -Throw
    }

    It 'the writer itself names the volume format when it refuses, and writes nothing' {
        & $script:Inject { param($Stream) throw 'Attempted to perform an unauthorized operation.' } { param($Path) 'FAT32' }
        $target = Join-Path $script:Tmp 'results.json'
        $msg = $null
        try { Set-TPSensitiveFileContent -Path $target -Content '{}' } catch { $msg = $_.Exception.Message }
        $msg | Should -Match "reports 'FAT32'"
        $msg | Should -Match '-OutputPath'
        Test-Path -LiteralPath $target | Should -BeFalse
        @(Get-ChildItem -LiteralPath $script:Tmp -Force).Count | Should -Be 0 -Because 'the temp file is removed on refusal'
    }

    It 'Get-TPVolumeFormat never throws: a string or nothing for a local folder, "network share" for a UNC path' {
        $f = & $script:Mod { param($p) Get-TPVolumeFormat -Path $p } $script:Tmp
        ($null -eq $f -or $f -is [string]) | Should -BeTrue
        (& $script:Mod { Get-TPVolumeFormat -Path '\\server\share\folder' }) | Should -Be 'network share'
        (& $script:Mod { Get-TPVolumeFormat -Path "$([char]0)bad" }) | Should -BeNullOrEmpty
    }

    Context 'every entry point proves its output folder before its first sign-in' {
        It '<Name>' -ForEach @(
            @{ Name = 'Invoke-TPAssessment.ps1';       SignIn = @('Connect-TPServices', 'Connect-TPExchangeOnly', 'Connect-MgGraph', 'Connect-ExchangeOnline') }
            @{ Name = 'Invoke-TPBatchAssessment.ps1';  SignIn = @('Connect-MgGraph', 'Connect-TPServices') }
            @{ Name = 'Invoke-TPSignInTriage.ps1';     SignIn = @('Connect-TPServices', 'Connect-MgGraph') }
            @{ Name = 'Invoke-TPEmailAssessment.ps1';  SignIn = @('Connect-TPServices', 'Connect-MgGraph') }
            @{ Name = 'Invoke-TPBatchSignInTriage.ps1'; SignIn = @('Connect-MgGraph', 'Connect-TPServices') }
        ) {
            $path = Join-Path $script:Root $Name
            $t = $null; $e = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$t, [ref]$e)
            @($e).Count | Should -Be 0
            $calls = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
            $probe = @($calls | Where-Object { $_.GetCommandName() -eq 'Test-TPSensitiveOutputFolder' })
            $probe.Count | Should -BeGreaterOrEqual 1 -Because "$Name must prove its output folder"
            $first = ($probe | ForEach-Object { $_.Extent.StartLineNumber } | Measure-Object -Minimum).Minimum
            foreach ($s in $SignIn) {
                foreach ($c in @($calls | Where-Object { $_.GetCommandName() -eq $s })) {
                    $c.Extent.StartLineNumber | Should -BeGreaterThan $first -Because "$Name must prove the output folder before $s (line $($c.Extent.StartLineNumber))"
                }
            }
        }
    }
}
