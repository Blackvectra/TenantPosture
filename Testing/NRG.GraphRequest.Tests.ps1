#Requires -Version 7.0
#
# NRG.GraphRequest.Tests.ps1
#
# Pins behavior of Lib/Invoke-NRGGraphRequest.ps1 — the shape-pinning proxy
# over Invoke-MgGraphRequest introduced in v4.12.2.
#
# Root-cause regression guard for the clienta.org 2026-07-07 mass-false-gap run:
# newer Microsoft.Graph SDK builds return PSCustomObject, on which a bare
# `$resp.'@odata.nextLink'` throws under Set-StrictMode -Version Latest when the
# property is absent (every single-page / small-tenant response). The proxy must
# force -OutputType HashTable so absent keys read as $null, not throw.

Describe 'Invoke-NRGGraphRequest' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Invoke-NRGGraphRequest.ps1')
    }

    Context 'Forces HashTable output shape' {
        BeforeEach {
            # Capture the OutputType the proxy actually passes downstream.
            $script:capturedOutputType = $null
            $script:capturedUri        = $null
            $script:capturedMethod     = $null
            function Invoke-MgGraphRequest {
                param(
                    [string] $Uri, [string] $Method,
                    [object] $Body, [System.Collections.IDictionary] $Headers,
                    [string] $OutputType
                )
                $script:capturedOutputType = $OutputType
                $script:capturedUri        = $Uri
                $script:capturedMethod     = $Method
                # Emulate the SDK's HashTable output: a single-page response with
                # NO '@odata.nextLink' key (the exact shape that broke collectors).
                return @{ value = @(@{ id = '1' }) }
            }
        }

        It 'Defaults OutputType to HashTable' {
            $null = Invoke-NRGGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization'
            $script:capturedOutputType | Should -Be 'HashTable'
        }

        It 'Forwards Uri and Method verbatim' {
            $null = Invoke-NRGGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/users'
            $script:capturedUri    | Should -Be 'https://graph.microsoft.com/v1.0/users'
            $script:capturedMethod | Should -Be 'GET'
        }

        It 'Returns a hashtable whose absent @odata.nextLink reads as $null via indexer (no throw under StrictMode)' {
            Set-StrictMode -Version Latest
            $resp = Invoke-NRGGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/users'
            $resp | Should -BeOfType [System.Collections.IDictionary]
            # This is the exact access pattern the collectors use for paging.
            # INDEXER, not dot-access: on PowerShell 7.0-7.4, StrictMode throws
            # on dot-access to a MISSING hashtable key ($h.'absent'); only the
            # indexer ($h['absent']) reads as $null on every supported version.
            # PowerShell 7.5 relaxed the dot-access behavior, which is why the
            # original fix appeared to work on 7.5 workstations while still
            # crashing 7.0-7.4 operators. Collectors must use the indexer.
            { $resp['@odata.nextLink'] } | Should -Not -Throw
            $resp['@odata.nextLink']     | Should -BeNullOrEmpty
            @($resp.value).Count         | Should -Be 1
        }
    }

    Context 'Method validation' {
        It 'Rejects an unsupported HTTP method' {
            { Invoke-NRGGraphRequest -Method FROBNICATE -Uri 'https://x' } | Should -Throw
        }
    }
}
