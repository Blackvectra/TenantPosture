#Requires -Version 7.0
#
# Set-TPSensitiveFileAcl.ps1  (v4.6.2)
# TenantPosture
# Author: Matthew Levorson
#
# Purpose: Restrict the ACL on a sensitive output file (assessment baseline
#   JSON, apply rollback log, apply results JSON/MD) to current user +
#   SYSTEM + Administrators. These files contain a complete tenant inventory
#   — every CA policy, every admin assignment with UPNs, every OAuth app,
#   every DMARC record, every applied/skipped remediation. On a shared MSP
#   workstation or a synced OneDrive folder, default inherited permissions
#   would make the file world-readable.
#
# Data keys set/consumed: none — pure filesystem helper.
# Required Graph scopes / cmdlets: none.
#
# Cross-platform safety:
#   - On Linux / non-Windows: Set-Acl / FileSystemAccessRule are unavailable.
#     The helper emits a Write-Verbose notice and returns. It MUST NOT throw
#     on non-Windows hosts — the apply tool and assessor both call this from
#     a finally-style write path and should not abort.
#
# Error handling:
#   - On Windows, any failure (file gone, permission denied, identity lookup
#     failure) is surfaced via Write-Warning. The caller continues — file
#     ACL hardening is defense-in-depth, not the load-bearing protection.
#
# OWASP A01 (broken access control). Mirrors the inline block formerly in
# Invoke-TPAssessment.ps1.
#

# The three access rules every sensitive file gets on Windows: the current user,
# SYSTEM and Administrators, full control, nothing else.
function Get-TPSensitiveFileAccessRules {
    [CmdletBinding()]
    param()
    $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    return @(
        [System.Security.AccessControl.FileSystemAccessRule]::new($currentUser, 'FullControl', 'Allow')
        [System.Security.AccessControl.FileSystemAccessRule]::new('NT AUTHORITY\SYSTEM', 'FullControl', 'Allow')
        [System.Security.AccessControl.FileSystemAccessRule]::new('BUILTIN\Administrators', 'FullControl', 'Allow')
    )
}

# Hardens an OPEN file through its own handle, never through its name: on
# Windows the FileSecurity goes to the handle (FileSystemAclExtensions), on
# other hosts the mode is set on the handle (File.SetUnixFileMode). Nothing
# here reopens the path, so no entry swapped in after the open is affected.
function Set-TPSensitiveHandleAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.IO.FileStream] $Stream)
    if (-not $IsWindows) {
        # File.SetUnixFileMode on a handle exists from .NET 7 (PowerShell 7.3). On an
        # older runtime chmod is applied to the still-open, randomly named temp file,
        # and a chmod that fails is an error, never a warning.
        $setMode = [System.IO.File].GetMethod('SetUnixFileMode', [type[]]@([Microsoft.Win32.SafeHandles.SafeFileHandle], [System.IO.UnixFileMode]))
        if ($null -ne $setMode) {
            $null = $setMode.Invoke($null, @($Stream.SafeFileHandle, [System.IO.UnixFileMode]([int]0x180)))   # 0600; a void Invoke still emits $null
            return
        }
        & chmod 600 $Stream.Name 2>$null
        if ($LASTEXITCODE -ne 0) { throw "chmod 600 returned exit code $LASTEXITCODE" }
        return
    }
    $sec = [System.Security.AccessControl.FileSecurity]::new()
    $sec.SetAccessRuleProtection($true, $false)
    foreach ($r in (Get-TPSensitiveFileAccessRules)) { $sec.AddAccessRule($r) }
    [System.IO.FileSystemAclExtensions]::SetAccessControl($Stream, $sec)
}

function Set-TPSensitiveFileAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Path
    )

    # Non-Windows host: Set-Acl is a no-op shim that returns $null; the
    # FileSystemAccessRule constructor will fail because Windows identity
    # types are unavailable. **ASVS V12.3 / NIST AC-3 / CWE-732** —
    # previously the helper silently returned here, leaving the file with
    # whatever the parent directory's umask granted (typically 0644 =
    # group/other readable). Tenant findings (UPN, CA policies, OAuth
    # apps, DMARC posture) would then be readable by any user on shared
    # Linux/macOS hosts. Set 0600 (owner read/write only) before returning.
    if (-not $IsWindows) {
        Write-Verbose "Set-TPSensitiveFileAcl: applying POSIX 0600 mode on non-Windows host (Path: $Path)"
        try {
            if (Test-Path -LiteralPath $Path -PathType Leaf) {
                # chmod is the most portable surface across Linux + macOS.
                & chmod 600 $Path 2>$null
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "Set-TPSensitiveFileAcl: chmod 600 returned exit code $LASTEXITCODE on $Path"
                }
            }
        } catch {
            Write-Warning "Set-TPSensitiveFileAcl: failed to set POSIX 0600 on $Path : $($_.Exception.Message)"
        }
        return
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Warning "Set-TPSensitiveFileAcl: file not found, cannot harden ACL: $Path"
        return
    }

    try {
        $acl = Get-Acl -LiteralPath $Path
        # Disable inheritance, drop any inherited rules
        $acl.SetAccessRuleProtection($true, $false)
        # Remove any non-inherited rules that survived (defense in depth)
        foreach ($existing in @($acl.Access)) {
            if (-not $existing.IsInherited) {
                [void]$acl.RemoveAccessRule($existing)
            }
        }
        foreach ($r in (Get-TPSensitiveFileAccessRules)) { $acl.AddAccessRule($r) }
        Set-Acl -LiteralPath $Path -AclObject $acl
    } catch {
        Write-Warning "Set-TPSensitiveFileAcl: failed to restrict ACL on '$Path': $($_.Exception.Message). File may be readable by other users on this host — review permissions manually."
    }
}

# Writes content to a sensitive file with the ACL applied BEFORE any data is
# written. Closes a TOCTOU window where a co-resident process on a shared MSP
# workstation could read tenant data between Out-File completing and Set-Acl
# running. On Windows: creates the file empty, hardens the ACL, then writes
# the content via [System.IO.File]::WriteAllText. On non-Windows: behaves like
# a normal write (ACL helper is a no-op there anyway).
#
# Usage:
#   Set-TPSensitiveFileContent -Path $jsonPath -Content $bigJson
#
# Notes:
#   - $Content can be $null or empty — we still pre-create + ACL the file so
#     a subsequent appender writes into a hardened file.
#   - Uses UTF-8 without BOM (matches existing [System.IO.File]::WriteAllText
#     usage in Apply-TPBaseline).
#   - Path validation: $Path must already be a valid OS path; caller is
#     responsible for path-traversal checks at the entry point.
#
# v4.6.3 P2 — TOCTOU fix for the assessment JSON + apply rollback log.
function Set-TPSensitiveFileContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Path,

        [Parameter(Mandatory, Position = 1)]
        [AllowEmptyString()]
        [AllowNull()]
        [string] $Content,

        [System.Text.Encoding] $Encoding = [System.Text.UTF8Encoding]::new($false)
    )

    # The content is written to a new, randomly named file beside the target,
    # opened once with CreateNew (the handle is ours, never a link someone
    # planted), hardened THROUGH THAT HANDLE before any tenant data lands, written
    # through the same handle, and then moved over the target name. The move
    # replaces the target name itself, so a symbolic link, junction or mount
    # point planted at the output name is replaced, never followed; nothing in
    # between reopens a path.
    if (Test-Path -LiteralPath $Path -PathType Container) { throw "Set-TPSensitiveFileContent: '$Path' is a directory." }
    $dir = Split-Path -Parent $Path
    if ([string]::IsNullOrEmpty($dir)) { $dir = (Get-Location).ProviderPath }
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { throw "Set-TPSensitiveFileContent: folder '$dir' does not exist." }
    $leaf = Split-Path -Leaf $Path
    $tmp = Join-Path $dir ('.' + $leaf + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
    $fs = $null
    try {
        $fs = [System.IO.FileStream]::new($tmp, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
        # A file that cannot be hardened is not written: tenant data never lands
        # under the folder's inherited permissions.
        try { Set-TPSensitiveHandleAcl -Stream $fs }
        catch { throw "Set-TPSensitiveFileContent: could not restrict access on '$Path', so it was not written: $($_.Exception.Message)" }
        $pre = $Encoding.GetPreamble()   # the caller's BOM (Excel needs one on the action-plan CSV)
        if ($pre.Length -gt 0) { $fs.Write($pre, 0, $pre.Length) }
        $bytes = $Encoding.GetBytes([string]$Content)
        $fs.Write($bytes, 0, $bytes.Length)
        $fs.Flush($true)
        $fs.Dispose(); $fs = $null
        [System.IO.File]::Move($tmp, $Path, $true)
    } catch {
        if ($fs) { $fs.Dispose(); $fs = $null }
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        throw
    }
}
