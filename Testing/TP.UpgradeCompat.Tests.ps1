#Requires -Version 7.0
#
# TP.UpgradeCompat.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# What an upgrade from the NRG-named version must not break. The endpoint
# collector's output folder is covered with the device tests (TP.DeviceCompliance);
# the earlier schema tag by TP.DeviceIdentity. This pins the signing side: a
# workstation set up before the rename saved its signing thumbprint under
# ~/.nrg-assessment, and the signer now looks there too, with the same ownership
# and ACL checks, instead of failing with "no saved thumbprint". Authenticode and
# the ACL APIs are Windows-only, so the pointer logic is checked in the source.

Describe 'Upgrade compatibility: the signing thumbprint pointer' {

    BeforeAll {
        $script:Root = Split-Path -Parent $PSScriptRoot
        $script:SignSrc = Get-Content -LiteralPath (Join-Path $script:Root 'Build' 'Sign-Release.ps1') -Raw
        $script:CertSrc = Get-Content -LiteralPath (Join-Path $script:Root 'Build' 'New-TPCodeSigningCert.ps1') -Raw
    }

    It 'the signer reads the current location first, then the earlier one, and tells the operator to move it' {
        $script:SignSrc | Should -Match ([regex]::Escape("'.tp-assessment/signing-thumbprint.txt'"))
        $script:SignSrc | Should -Match ([regex]::Escape("'.nrg-assessment/signing-thumbprint.txt'"))
        $cur = $script:SignSrc.IndexOf(".tp-assessment/signing-thumbprint.txt'")
        $old = $script:SignSrc.IndexOf(".nrg-assessment/signing-thumbprint.txt'")
        $cur | Should -BeLessThan $old -Because 'the current location wins when both exist'
        $script:SignSrc | Should -Match 'Write-Warning "Using the signing thumbprint an earlier version saved'
    }

    It 'the file it falls back to goes through the same ownership and ACL checks as the current one' {
        # One $thumbFile variable feeds the checks, whichever location it points at.
        $script:SignSrc | Should -Match ([regex]::Escape('$thumbFile = $earlierThumb'))
        $script:SignSrc | Should -Match ([regex]::Escape('foreach ($target in @($thumbFile, (Split-Path -Parent $thumbFile)))'))
    }

    It 'new certificates are still saved to the current location only' {
        $script:CertSrc | Should -Match ([regex]::Escape("'.tp-assessment'"))
        $script:CertSrc | Should -Not -Match 'nrg-assessment'
    }
}
