#Requires -Version 7.0
#
# Set-NRGSensitiveFileAcl.ps1  (v4.6.2)
# NRG Technology Services / NextLayerSec LLC
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
# Invoke-NRGAssessment.ps1.
#

function Set-NRGSensitiveFileAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position = 0)]
        [string] $Path
    )

    # Non-Windows host: Set-Acl is a no-op shim that returns $null; the
    # FileSystemAccessRule constructor will fail because Windows identity
    # types are unavailable. Detect early and skip cleanly so the helper
    # remains safe to call from cross-platform smoke tests.
    if (-not $IsWindows) {
        Write-Verbose "Set-NRGSensitiveFileAcl: skipping ACL hardening on non-Windows host (Path: $Path)"
        return
    }

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        Write-Warning "Set-NRGSensitiveFileAcl: file not found, cannot harden ACL: $Path"
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
        Write-Warning "Set-NRGSensitiveFileAcl: failed to restrict ACL on '$Path': $($_.Exception.Message). File may be readable by other users on this host — review permissions manually."
    }
}
