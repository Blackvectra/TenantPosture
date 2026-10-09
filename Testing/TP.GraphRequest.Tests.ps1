#Requires -Version 7.0
#
# TP.GraphRequest.Tests.ps1
#
# Pins behavior of Lib/Invoke-TPGraphRequest.ps1 — the shape-pinning proxy
# over Invoke-MgGraphRequest introduced in v4.12.2.
#
# Root-cause regression guard for a July-2026 client mass-false-gap run:
# newer Microsoft.Graph SDK builds return PSCustomObject, on which a bare
# `$resp.'@odata.nextLink'` throws under Set-StrictMode -Version Latest when the
# property is absent (every single-page / small-tenant response). The proxy must
# force -OutputType HashTable so absent keys read as $null, not throw.

Describe 'Invoke-TPGraphRequest' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Invoke-TPGraphRequest.ps1')
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
            $null = Invoke-TPGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/organization'
            $script:capturedOutputType | Should -Be 'HashTable'
        }

        It 'Forwards Uri and Method verbatim' {
            $null = Invoke-TPGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/users'
            $script:capturedUri    | Should -Be 'https://graph.microsoft.com/v1.0/users'
            $script:capturedMethod | Should -Be 'GET'
        }

        It 'Returns a hashtable whose absent @odata.nextLink reads as $null via indexer (no throw under StrictMode)' {
            Set-StrictMode -Version Latest
            $resp = Invoke-TPGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/users'
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
            { Invoke-TPGraphRequest -Method FROBNICATE -Uri 'https://x' } | Should -Throw
        }

        It 'Rejects write verbs — the tool is read-only without exception' {
            { Invoke-TPGraphRequest -Method POST -Uri 'https://x' }   | Should -Throw
            { Invoke-TPGraphRequest -Method PUT -Uri 'https://x' }    | Should -Throw
            { Invoke-TPGraphRequest -Method PATCH -Uri 'https://x' }  | Should -Throw
            { Invoke-TPGraphRequest -Method DELETE -Uri 'https://x' } | Should -Throw
        }

        It 'Has no -Body parameter — a write verb has no way to carry a payload' {
            (Get-Command Invoke-TPGraphRequest).Parameters.ContainsKey('Body') | Should -BeFalse
        }
    }
}

# A list read from its first page alone is reported as a full enumeration, so
# Get-TPGraphAllPages must follow @odata.nextLink, and must throw rather than
# return a partial or malformed list: the caller's catch then marks the
# section unread instead of reading "none found".
Describe 'Get-TPGraphAllPages' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Get-TPObjectField.ps1')
        . (Join-Path $script:RepoRoot 'Lib' 'Invoke-TPGraphRequest.ps1')
        $script:Pages   = @{}
        $script:Calls   = [System.Collections.Generic.List[string]]::new()
        $script:Headers = [System.Collections.Generic.List[object]]::new()
        # Emulates Invoke-MgGraphRequest -OutputType HashTable, one page per URI.
        function Invoke-MgGraphRequest {
            param([string] $Uri, [string] $Method, [System.Collections.IDictionary] $Headers, [string] $OutputType)
            $script:Calls.Add($Uri)
            $script:Headers.Add($Headers)
            return $script:Pages[$Uri]
        }
    }
    BeforeEach { $script:Pages = @{}; $script:Calls.Clear(); $script:Headers.Clear() }

    It 'follows @odata.nextLink and returns every item across pages' {
        $script:Pages['https://g/p1'] = @{ value = @(@{ id = 'a' }, @{ id = 'b' }); '@odata.nextLink' = 'https://g/p2' }
        $script:Pages['https://g/p2'] = @{ value = @(@{ id = 'c' }) }
        $items = @(Get-TPGraphAllPages -Uri 'https://g/p1')
        $items.Count | Should -Be 3
        (@($items | ForEach-Object { $_['id'] }) -join ',') | Should -Be 'a,b,c'
        $script:Calls.Count | Should -Be 2
    }

    It 'sends the caller''s headers on every page, not only the first' {
        $script:Pages['https://g/p1'] = @{ value = @(@{ id = 'a' }); '@odata.nextLink' = 'https://g/p2' }
        $script:Pages['https://g/p2'] = @{ value = @(@{ id = 'b' }) }
        $null = Get-TPGraphAllPages -Uri 'https://g/p1' -Headers @{ Prefer = 'include-unknown-enum-members' }
        $script:Headers.Count | Should -Be 2
        foreach ($h in $script:Headers) { $h['Prefer'] | Should -Be 'include-unknown-enum-members' }
    }

    It 'returns an empty list for an empty collection, never an error' {
        $script:Pages['https://g/e'] = @{ value = @() }
        @(Get-TPGraphAllPages -Uri 'https://g/e').Count | Should -Be 0
    }

    It 'returns a one-item collection as one item' {
        $script:Pages['https://g/one'] = @{ value = @(@{ id = 'only' }) }
        $items = @(Get-TPGraphAllPages -Uri 'https://g/one')
        $items.Count | Should -Be 1
        $items[0]['id'] | Should -Be 'only'
    }

    It 'throws on a response with no value collection (absent or null), so it can never read as empty' {
        $script:Pages['https://g/x'] = @{ error = @{ code = 'Unexpected' } }
        { Get-TPGraphAllPages -Uri 'https://g/x' } | Should -Throw '*no ''value'' collection*'
        $script:Pages['https://g/n'] = @{ value = $null }
        { Get-TPGraphAllPages -Uri 'https://g/n' } | Should -Throw '*no ''value'' collection*'
    }

    It 'throws on a malformed later page instead of returning the pages before it' {
        $script:Pages['https://g/p1'] = @{ value = @(@{ id = 'a' }); '@odata.nextLink' = 'https://g/p2' }
        $script:Pages['https://g/p2'] = @{ error = @{ code = 'Unexpected' } }
        { Get-TPGraphAllPages -Uri 'https://g/p1' } | Should -Throw
    }

    It 'throws when the page cap is reached with pages still pending, never returning a partial list' {
        $script:Pages['https://g/loop'] = @{ value = @(@{ id = 'a' }); '@odata.nextLink' = 'https://g/loop' }
        { Get-TPGraphAllPages -Uri 'https://g/loop' -MaxPages 3 } | Should -Throw '*incomplete*'
        $script:Calls.Count | Should -Be 3
    }
}
