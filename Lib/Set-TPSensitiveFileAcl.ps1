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
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $rules = @(
            [System.Security.AccessControl.FileSystemAccessRule]::new($currentUser, 'FullControl', 'Allow')
            [System.Security.AccessControl.FileSystemAccessRule]::new('NT AUTHORITY\SYSTEM', 'FullControl', 'Allow')
            [System.Security.AccessControl.FileSystemAccessRule]::new('BUILTIN\Administrators', 'FullControl', 'Allow')
        )
        foreach ($r in $rules) { $acl.AddAccessRule($r) }
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

    # Pre-create empty file then harden ACL so the ACL is applied BEFORE any
    # tenant data lands. Without this step, the file inherits the parent
    # directory's ACL during the Out-File / WriteAllText call, giving a
    # co-resident process a small window to read the data.
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            # File already exists — truncate before hardening so leftover content
            # doesn't bleed across runs.
            [System.IO.File]::WriteAllText($Path, '', $Encoding)
        } else {
            # Create empty file. [System.IO.File]::Create returns a FileStream;
            # we wrap in try/finally to ensure it's closed before Set-Acl.
            $fs = $null
            try {
                $fs = [System.IO.File]::Create($Path)
            } finally {
                if ($fs) { $fs.Dispose() }
            }
        }
    } catch {
        Write-Warning "Set-TPSensitiveFileContent: could not pre-create '$Path': $($_.Exception.Message)"
        # Fall through — caller may still want the write to happen even if
        # pre-creation failed (e.g. parent dir issues). The next step will
        # re-throw if it fails too.
    }

    # Harden ACL BEFORE writing tenant data. No-op on non-Windows.
    Set-TPSensitiveFileAcl -Path $Path

    # Now write the actual content. ACL is in place; tenant data is restricted
    # the moment it lands on disk.
    if ($null -ne $Content) {
        [System.IO.File]::WriteAllText($Path, $Content, $Encoding)
    }
}
