#Requires -Version 7.0
#
# TP.SensitiveFileWriter.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# The first live Windows run after the handle-based sensitive writer (#136) ended at the
# results write: "could not restrict access ... Attempted to perform an unauthorized
# operation", and nothing was written. Setting a DACL through a handle needs WRITE_DAC, and
# a FileStream opened for read and write (GENERIC_READ | GENERIC_WRITE) does not carry it.
# No suite had run the writer on Windows. These tests pin the Windows open (the file is
# created with the protected DACL by a handle that can change permissions), run the writer
# on every host, and on Windows read the DACL back. The Windows CI job runs this file.

Describe 'Sensitive file writer' {

    BeforeAll {
        $script:Root = Split-Path -Parent $PSScriptRoot
        Import-Module (Join-Path $script:Root 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Src = Get-Content -LiteralPath (Join-Path $script:Root 'Lib' 'Set-TPSensitiveFileAcl.ps1') -Raw
    }

    It 'on Windows the temp file is created with the protected DACL by a handle that can change permissions (static)' {
        $script:Src | Should -Match 'if \(\$IsWindows\) \{ \$fs = New-TPSensitiveFileStream -Path \$tmp \}'
        $script:Src | Should -Match '\[System\.IO\.FileSystemAclExtensions\]::Create\('
        $script:Src | Should -Match 'FileSystemRights\]::ChangePermissions'
        $script:Src | Should -Match '\[System\.IO\.FileOptions\]::None, \(New-TPSensitiveFileSecurity\)\)' -Because 'the security descriptor goes to CreateFile, not to a later call'
    }

    It 'this runtime has the Create overload the writer calls' {
        $sig = [type[]]@([System.IO.FileInfo], [System.IO.FileMode], [System.Security.AccessControl.FileSystemRights], [System.IO.FileShare], [int], [System.IO.FileOptions], [System.Security.AccessControl.FileSecurity])
        [System.IO.FileSystemAclExtensions].GetMethod('Create', $sig) | Should -Not -BeNullOrEmpty
    }

    It 'writes the content, replaces an existing file, and leaves nothing beside it' {
        $d = Join-Path $TestDrive 'w'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        $p = Join-Path $d 'results.json'
        Set-TPSensitiveFileContent -Path $p -Content '{"a":1}'
        Set-TPSensitiveFileContent -Path $p -Content '{"a":2}'
        (Get-Content -LiteralPath $p -Raw) | Should -Be '{"a":2}'
        @(Get-ChildItem -LiteralPath $d -Force | Where-Object { $_.Name -ne 'results.json' }) | Should -BeNullOrEmpty
    }

    It 'on Windows the written file carries only the current user, SYSTEM and Administrators, nothing inherited' -Skip:(-not $IsWindows) {
        $d = Join-Path $TestDrive 'acl'; New-Item -ItemType Directory -Path $d -Force | Out-Null
        $p = Join-Path $d 'results.json'
        Set-TPSensitiveFileContent -Path $p -Content 'x'
        $acl = Get-Acl -LiteralPath $p
        $acl.AreAccessRulesProtected | Should -BeTrue
        $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        $rules.Count | Should -Be 3
        @($rules | Where-Object { $_.IsInherited }) | Should -BeNullOrEmpty
        $sids = @($rules | ForEach-Object { $_.IdentityReference.Value })
        $sids | Should -Contain 'S-1-5-18'
        $sids | Should -Contain 'S-1-5-32-544'
        $sids | Should -Contain ([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)
        foreach ($r in $rules) {
            [string]$r.FileSystemRights | Should -Be 'FullControl'
            [string]$r.AccessControlType | Should -Be 'Allow'
        }
    }

    It 'on Windows a handle opened for read and write alone cannot take a DACL, which is the bug class' -Skip:(-not $IsWindows) {
        $p = Join-Path $TestDrive 'plain.bin'
        $fs = [System.IO.FileStream]::new($p, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        try {
            $sec = [System.Security.AccessControl.FileSecurity]::new()
            $sec.SetAccessRuleProtection($true, $false)
            $sec.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.WindowsIdentity]::GetCurrent().User, 'FullControl', 'Allow'))
            { [System.IO.FileSystemAclExtensions]::SetAccessControl($fs, $sec) } | Should -Throw -ExpectedMessage '*unauthorized operation*'
        } finally { $fs.Dispose() }
    }
}
