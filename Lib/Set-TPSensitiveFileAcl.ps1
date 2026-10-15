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
# Returns $true when the handle was hardened and $false when this runtime has
# no handle API (the caller then relies on an owner-only staging directory).
function Set-TPSensitiveHandleAcl {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [System.IO.FileStream] $Stream)
    if (-not $IsWindows) {
        # File.SetUnixFileMode(SafeFileHandle, UnixFileMode) exists from .NET 7
        # (PowerShell 7.3). Both the enum and the overload are resolved at run
        # time, because a type literal for an enum an older runtime does not have
        # throws before any fallback can run. Without the handle overload the
        # caller has staged the file inside an owner-only directory (see
        # Set-TPSensitiveFileContent), so no path is chmod'ed here.
        $modeType = [System.Type]::GetType('System.IO.UnixFileMode', $false)
        $setMode = if ($null -ne $modeType) { [System.IO.File].GetMethod('SetUnixFileMode', [type[]]@([Microsoft.Win32.SafeHandles.SafeFileHandle], $modeType)) } else { $null }
        if ($null -eq $setMode) { return $false }
        $null = $setMode.Invoke($null, @($Stream.SafeFileHandle, [System.Enum]::ToObject($modeType, 0x180)))   # 0600; a void Invoke still emits $null
        return $true
    }
    [System.IO.FileSystemAclExtensions]::SetAccessControl($Stream, (New-TPSensitiveFileSecurity))
    return $true
}

# The protected DACL every sensitive file gets on Windows: inheritance off, the
# three rules above and nothing else.
function New-TPSensitiveFileSecurity {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.FileSecurity])]
    param()
    $sec = [System.Security.AccessControl.FileSecurity]::new()
    $sec.SetAccessRuleProtection($true, $false)
    foreach ($r in (Get-TPSensitiveFileAccessRules)) { $sec.AddAccessRule($r) }
    return $sec
}

# Opens the temp file on Windows. The file is CREATED with the protected DACL
# (CreateFile takes the security descriptor, so there is no moment in which it
# carries the folder's inherited permissions), and the handle requests
# ChangePermissions beside read and write: setting a DACL through a handle needs
# WRITE_DAC, which a plain FileStream (GENERIC_READ | GENERIC_WRITE) does not
# carry, so the first live Windows run after the handle-based writer (#136)
# ended at the results write with "Attempted to perform an unauthorized
# operation" and wrote nothing. Nothing here reopens the path.
function New-TPSensitiveFileStream {
    [CmdletBinding()]
    [OutputType([System.IO.FileStream])]
    param([Parameter(Mandatory)] [string] $Path)
    $rights = [System.Security.AccessControl.FileSystemRights]::Read -bor
        [System.Security.AccessControl.FileSystemRights]::Write -bor
        [System.Security.AccessControl.FileSystemRights]::ChangePermissions
    return [System.IO.FileSystemAclExtensions]::Create(
        [System.IO.FileInfo]::new($Path), [System.IO.FileMode]::CreateNew, $rights,
        [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::None, (New-TPSensitiveFileSecurity))
}

# True when this runtime can set a Unix mode through an open handle (so a temp
# file can be hardened without touching its path); always true on Windows.
function Test-TPHandleModeSupported {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    if ($IsWindows) { return $true }
    $modeType = [System.Type]::GetType('System.IO.UnixFileMode', $false)
    if ($null -eq $modeType) { return $false }
    return ($null -ne [System.IO.File].GetMethod('SetUnixFileMode', [type[]]@([Microsoft.Win32.SafeHandles.SafeFileHandle], $modeType)))
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
    # planted; on Windows it is created WITH the protected DACL by a handle that
    # can also change permissions), hardened THROUGH THAT HANDLE before any
    # tenant data lands, written
    # through the same handle, and then moved over the target name. The move
    # replaces the target name itself, so a symbolic link, junction or mount
    # point planted at the output name is replaced, never followed; nothing in
    # between reopens a path.
    if (Test-Path -LiteralPath $Path -PathType Container) { throw "Set-TPSensitiveFileContent: '$Path' is a directory." }
    $dir = Split-Path -Parent $Path
    if ([string]::IsNullOrEmpty($dir)) { $dir = (Get-Location).ProviderPath }
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { throw "Set-TPSensitiveFileContent: folder '$dir' does not exist." }
    $leaf = Split-Path -Leaf $Path
    # Where the runtime cannot harden through the handle (no File.SetUnixFileMode
    # overload, PowerShell before 7.3 on Linux/macOS) the temp file is created
    # inside a fresh owner-only directory (mkdir -m 700), so no other account can
    # open or replace it between creation and the move; nothing is chmod'ed by path.
    $stageDir = $null
    if (-not (Test-TPHandleModeSupported)) {
        $stageDir = Join-Path $dir ('.' + $leaf + '.' + [guid]::NewGuid().ToString('N') + '.stage')
        & mkdir -m 700 $stageDir 2>$null
        if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $stageDir -PathType Container)) { throw "Set-TPSensitiveFileContent: could not create an owner-only staging folder beside '$Path', so it was not written." }
    }
    $tmp = Join-Path ($(if ($stageDir) { $stageDir } else { $dir })) ('.' + $leaf + '.' + [guid]::NewGuid().ToString('N') + '.tmp')
    $fs = $null
    try {
        if ($IsWindows) { $fs = New-TPSensitiveFileStream -Path $tmp }
        else { $fs = [System.IO.FileStream]::new($tmp, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) }
        # A file that cannot be hardened is not written: tenant data never lands
        # under the folder's inherited permissions.
        $hardened = $false
        try { $hardened = Set-TPSensitiveHandleAcl -Stream $fs }
        catch {
            # A volume without access control lists (exFAT, FAT32) accepts the
            # create and refuses the DACL with "Attempted to perform an unauthorized
            # operation", which reads like a permissions problem; name the volume.
            $fmt = Get-TPVolumeFormat -Path $dir
            $note = if (Test-TPVolumeFormatLacksAcl -Format $fmt) { " The volume holding it reports '$fmt', which cannot hold an access control list; write to a folder on a volume that can (NTFS on Windows), with -OutputPath or, on the batch runners, -OutputRoot." } elseif ($fmt) { " (volume: $fmt)" } else { '' }
            throw "Set-TPSensitiveFileContent: could not restrict access on '$Path', so it was not written: $($_.Exception.Message)$note"
        }
        if (-not $hardened -and -not $stageDir) { throw "Set-TPSensitiveFileContent: this runtime cannot harden '$Path' before writing, so it was not written." }
        $pre = $Encoding.GetPreamble()   # the caller's BOM (Excel needs one on the action-plan CSV)
        if ($pre.Length -gt 0) { $fs.Write($pre, 0, $pre.Length) }
        $bytes = $Encoding.GetBytes([string]$Content)
        $fs.Write($bytes, 0, $bytes.Length)
        $fs.Flush($true)
        $fs.Dispose(); $fs = $null
        if (-not $hardened) {
            # Still inside the owner-only staging folder, so a chmod by name cannot be
            # raced; it must succeed before the file is published under the target name.
            & chmod 600 $tmp 2>$null
            if ($LASTEXITCODE -ne 0) { throw "Set-TPSensitiveFileContent: chmod 600 on the staged file returned exit code $LASTEXITCODE, so '$Path' was not written." }
        }
        [System.IO.File]::Move($tmp, $Path, $true)
    } catch {
        if ($fs) { $fs.Dispose(); $fs = $null }
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        throw
    } finally {
        if ($stageDir) { Remove-Item -LiteralPath $stageDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

# The file system of the volume holding a path, as .NET reports it ('NTFS',
# 'ReFS', 'exFAT', 'FAT32', ...), 'network share' for a UNC path, or $null when
# it cannot be read. Never throws: it only sharpens a refusal message.
function Get-TPVolumeFormat {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)] [string] $Path)
    try {
        # Judge a UNC path on the text given: GetFullPath on Linux reads backslashes
        # as ordinary characters and would root it under the current directory.
        if ($Path -match '^(\\\\|//)') { return 'network share' }
        $full = [System.IO.Path]::GetFullPath($Path)
        $root = [System.IO.Path]::GetPathRoot($full)
        if ([string]::IsNullOrEmpty($root)) { return $null }
        $di = [System.IO.DriveInfo]::new($root)
        if (-not $di.IsReady) { return $null }
        $fmt = [string]$di.DriveFormat
        if ([string]::IsNullOrWhiteSpace($fmt)) { return $null }
        return $fmt
    } catch { return $null }
}

# True only for the file systems known to hold no access control list at all (the
# FAT family: FAT12/16/32, exFAT, vfat, msdos). ext4, XFS, APFS, NTFS over FUSE or
# an SMB share can protect a file, so a failure there is reported with the format
# and the writer's reason, never blamed on the volume.
function Test-TPVolumeFormatLacksAcl {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] [AllowEmptyString()] [string] $Format)
    if ([string]::IsNullOrWhiteSpace($Format)) { return $false }
    return [bool]($Format -match '^(v?fat(12|16|32)?|exfat|fat64|msdos)$')
}

# One sentence set for every refusal of an output folder: the folder, what the
# volume reports, why that matters where it does, the reason the writer gave, and
# the remedy for the entry point in use (-OutputPath; -OutputRoot on the batch runners).
function Format-TPOutputFolderRefusal {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [AllowNull()] [AllowEmptyString()] [string] $Format,
        [Parameter(Mandatory)] [string] $Reason
    )
    $fmtText = if ($Format) { " The volume holding it reports '$Format'." } else { '' }
    $hint = if (Test-TPVolumeFormatLacksAcl -Format $Format) { " $Format volumes cannot hold an access control list, so no results file can be protected there." } else { '' }
    return "The output folder '$Path' cannot hold a protected results file, so the assessment would end at the results write with nothing written.$fmtText$hint Reason: $Reason. Choose a folder on a volume that can hold file permissions (NTFS on Windows) with -OutputPath, or -OutputRoot on the batch runners, for example C:\TenantPosture\output on Windows. The results JSON holds tenant data and is written only where the signed-in user, SYSTEM and Administrators alone can read it."
}

# Proves, BEFORE any sign-in, that the output folder can hold a protected file:
# a throwaway file is written through Set-TPSensitiveFileContent (the same path
# the results JSON takes), its protection is read back, and it is removed. A
# folder that fails is refused with the remedy, instead of the run ending at
# the results write after the whole collection with nothing written, which is
# what an exFAT drive did on the 2026-10-15 live run. Throws on refusal; the
# probe file never survives either outcome.
function Test-TPSensitiveOutputFolder {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [string] $Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "Test-TPSensitiveOutputFolder: '$Path' is not a folder." }
    $format = Get-TPVolumeFormat -Path $Path
    $probe = Join-Path $Path ('.tp-write-probe-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        try { Set-TPSensitiveFileContent -Path $probe -Content 'TenantPosture output-folder probe; safe to delete.' }
        catch { throw (Format-TPOutputFolderRefusal -Path $Path -Format $format -Reason $_.Exception.Message) }
        if ($IsWindows) {
            $acl = Get-Acl -LiteralPath $probe
            $expected = @(Get-TPSensitiveFileAccessRules | ForEach-Object { [string]$_.IdentityReference.Value })
            $extra = @($acl.Access | ForEach-Object { [string]$_.IdentityReference.Value } | Where-Object { $_ -notin $expected })
            if (-not $acl.AreAccessRulesProtected) { throw (Format-TPOutputFolderRefusal -Path $Path -Format $format -Reason 'the file came back inheriting the folder permissions after the protection was applied') }
            if ($extra.Count -gt 0) { throw (Format-TPOutputFolderRefusal -Path $Path -Format $format -Reason "the file came back readable by $($extra -join ', ') after the protection was applied") }
        } else {
            $item = Get-Item -LiteralPath $probe -Force   # a dot-file is hidden on Unix; without -Force Get-Item reports it missing
            $modeProp = $item.PSObject.Properties['UnixMode']
            $mode = if ($modeProp) { [string]$modeProp.Value } else { '' }
            # Fail closed: a mode that cannot be read back is a protection that is not proven.
            if (-not $mode) { throw (Format-TPOutputFolderRefusal -Path $Path -Format $format -Reason 'the file mode could not be read back (this runtime exposes no UnixMode), so the protection is not proven') }
            if ($mode -notmatch '^-rw-------') { throw (Format-TPOutputFolderRefusal -Path $Path -Format $format -Reason "the file came back with mode $mode") }
        }
        return [ordered]@{ Path = $Path; Format = $format; Ok = $true }
    } finally {
        Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue
    }
}
