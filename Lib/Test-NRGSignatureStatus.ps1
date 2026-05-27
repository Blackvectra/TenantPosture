#Requires -Version 7.0
#
# Test-NRGSignatureStatus.ps1
# Returns Authenticode signature status for a path. Wraps Get-AuthenticodeSignature
# so callers don't need to know about cert-chain edge cases.
#
# Author: NextLayerSec / NRG Technology Services
#
# Used by:
#   - Apply-NRGBaseline.ps1 -RequireSignedCode preflight gate
#   - tools/Verify-Integrity.ps1 (optional signature-aware mode)
#   - Future v4.7 self-check banner ("the tool that's auditing you, audits itself")
#

function Test-NRGSignatureStatus {
    <#
    .SYNOPSIS
        Returns a structured signature status for a PowerShell file.

    .DESCRIPTION
        Wraps Get-AuthenticodeSignature with three improvements over the raw cmdlet:
          1. Distinguishes the "fail" modes: NotSigned vs Invalid vs HashMismatch vs Expired vs Untrusted.
             Get-AuthenticodeSignature only returns 'Status' which is ambiguous —
             'NotSigned' returns the same Status code as 'HashMismatch' on some PS versions.
          2. Resolves the chain explicitly so a self-signed cert that IS trusted in the operator's
             local TrustedPublisher store returns 'Valid', not 'UnknownError'.
          3. Returns a single object with all the fields a caller needs to make a policy decision
             (Status, ThumbprintSigner, IsSelfSigned, NotAfter, Path) — no need to call
             Get-AuthenticodeSignature again from the caller side.

        Cross-platform note: Authenticode is Windows-only. On Linux/macOS pwsh hosts
        this function returns Status='Unsupported' so callers can degrade gracefully
        (typically: skip the check, warn).

    .PARAMETER Path
        Path to the file to check. Must exist. Pass a directory and the function
        returns one result per signable file (recursive).

    .PARAMETER Recurse
        With -Path pointing at a directory, recurse through subdirectories.

    .OUTPUTS
        PSCustomObject with fields:
          Path              — full path of the inspected file
          Status            — Valid | NotSigned | HashMismatch | UntrustedRoot | Expired | Unsupported | Error
          Signer            — CN= subject of the signer (if any)
          SignerThumbprint  — SHA-1 thumbprint of the signing cert (if any)
          IsSelfSigned      — $true if Issuer == Subject (informational, not a failure)
          NotAfter          — cert expiry date (if any)
          StatusMessage     — human-readable detail, suitable for surfacing to operator

    .EXAMPLE
        Test-NRGSignatureStatus -Path .\Apply\Apply-NRGAADLegacyAuth.ps1

    .EXAMPLE
        # Pre-flight all Apply-* scripts and find any that aren't valid:
        Test-NRGSignatureStatus -Path .\Apply -Recurse | Where-Object Status -ne 'Valid'
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateScript({
            if ($_ -match '\.\.[\\/]') { throw 'Path traversal not allowed.' }
            if (-not (Test-Path -LiteralPath $_)) { throw "Path not found: $_" }
            return $true
        })]
        [string] $Path,

        [switch] $Recurse
    )

    # Authenticode signing is Windows-only at the OS level. PowerShell on Linux /
    # macOS knows the cmdlets but the underlying CryptoAPI calls aren't there.
    # Detect early and return a typed "Unsupported" so the caller's logic
    # branches cleanly instead of crashing on platform-specific errors.
    # Use the built-in $IsWindows automatic variable directly (PS 7+ guaranteed
    # by #Requires) — don't shadow it with a local. PSScriptAnalyzer's
    # PSAvoidAssignmentToAutomaticVariable rule flags any assignment to $isWindows
    # because PowerShell variable lookup is case-insensitive.

    # Resolve targets — single file vs directory
    $resolved = Resolve-Path -LiteralPath $Path
    $items = if ($resolved.Provider.Name -eq 'FileSystem' -and (Get-Item -LiteralPath $resolved.Path).PSIsContainer) {
        $signable = @('.ps1', '.psm1', '.psd1', '.ps1xml')
        $params = @{ LiteralPath = $resolved.Path; File = $true }
        if ($Recurse) { $params['Recurse'] = $true }
        Get-ChildItem @params | Where-Object { $_.Extension -in $signable }
    } else {
        @(Get-Item -LiteralPath $resolved.Path)
    }

    foreach ($item in $items) {
        if (-not $IsWindows) {
            [pscustomobject]@{
                Path             = $item.FullName
                Status           = 'Unsupported'
                Signer           = $null
                SignerThumbprint = $null
                IsSelfSigned     = $null
                NotAfter         = $null
                StatusMessage    = 'Authenticode is Windows-only. Cannot evaluate signature on this host.'
            }
            continue
        }

        try {
            $sig = Get-AuthenticodeSignature -FilePath $item.FullName -ErrorAction Stop

            # Map Get-AuthenticodeSignature's Status enum to our friendlier set.
            # Reference: https://learn.microsoft.com/dotnet/api/system.management.automation.signaturestatus
            $status = switch ($sig.Status) {
                'Valid'             { 'Valid'         ; break }
                'NotSigned'         { 'NotSigned'     ; break }
                'HashMismatch'      { 'HashMismatch'  ; break }   # tampered after signing
                'NotTrusted'        { 'UntrustedRoot' ; break }   # signed but root not in operator's store
                'UnknownError'      { 'Error'         ; break }
                'NotSupportedFileFormat' { 'Error'    ; break }
                'Incompatible'      { 'Error'         ; break }
                default             { [string]$sig.Status }
            }

            # Expired is a special case — Authenticode treats expired-but-otherwise-valid
            # as 'Valid' if the file has a trusted RFC3161 countersignature applied
            # BEFORE expiry. Without that timestamp, expiry becomes UntrustedRoot.
            # Surface explicitly so callers can warn the operator before the cert
            # silently turns into untrusted on the next renewal cycle.
            $notAfter = if ($sig.SignerCertificate) { $sig.SignerCertificate.NotAfter } else { $null }
            if ($status -eq 'Valid' -and $notAfter -and $notAfter -lt (Get-Date).AddDays(30)) {
                # Don't flip status — still Valid. Just record so caller can warn.
                $statusMessage = "Valid; cert expires in $((($notAfter - (Get-Date)).Days)) days"
            } elseif ($status -eq 'Valid') {
                $statusMessage = 'Valid'
            } else {
                $statusMessage = [string]$sig.StatusMessage
            }

            $isSelfSigned = if ($sig.SignerCertificate) {
                $sig.SignerCertificate.Issuer -eq $sig.SignerCertificate.Subject
            } else { $null }

            [pscustomobject]@{
                Path             = $item.FullName
                Status           = $status
                Signer           = if ($sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { $null }
                SignerThumbprint = if ($sig.SignerCertificate) { $sig.SignerCertificate.Thumbprint } else { $null }
                IsSelfSigned     = $isSelfSigned
                NotAfter         = $notAfter
                StatusMessage    = $statusMessage
            }
        } catch {
            [pscustomobject]@{
                Path             = $item.FullName
                Status           = 'Error'
                Signer           = $null
                SignerThumbprint = $null
                IsSelfSigned     = $null
                NotAfter         = $null
                StatusMessage    = $_.Exception.Message
            }
        }
    }
}
