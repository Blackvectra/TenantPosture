#Requires -Version 7.0
#
# NRG.ObjectField.Tests.ps1
#
# Pins behavior of Lib/Get-NRGObjectField.ps1 — the shape-agnostic field
# reader extracted in v4.10.1. The helper must never throw on missing keys
# under StrictMode, must handle hashtable / ordered / PSCustomObject /
# Synchronized hashtable / null inputs uniformly, and must return the
# supplied default for any miss.

Describe 'Get-NRGObjectField' {
    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }
        . (Join-Path $script:RepoRoot 'Lib' 'Get-NRGObjectField.ps1')
    }

    Context 'Hashtable inputs' {
        It 'Returns the value when the key is present' {
            $h = @{ Foo = 'bar' }
            Get-NRGObjectField -Item $h -Key 'Foo' | Should -Be 'bar'
        }

        It 'Returns the default when the key is missing' {
            $h = @{ Foo = 'bar' }
            Get-NRGObjectField -Item $h -Key 'Missing' -Default 'fallback' | Should -Be 'fallback'
        }

        It 'Returns $null by default when key is missing and no -Default given' {
            $h = @{ Foo = 'bar' }
            Get-NRGObjectField -Item $h -Key 'Missing' | Should -BeNullOrEmpty
        }

        It 'Returns the value when it is explicitly $null (does not coalesce)' {
            $h = @{ Foo = $null }
            $v = Get-NRGObjectField -Item $h -Key 'Foo' -Default 'fallback'
            $v | Should -BeNullOrEmpty
        }
    }

    Context 'OrderedDictionary inputs' {
        It 'Reads from [ordered]@{} under StrictMode' {
            $o = [ordered]@{ A = 1; B = 2 }
            Get-NRGObjectField -Item $o -Key 'B' | Should -Be 2
        }
    }

    Context 'PSCustomObject inputs (ConvertFrom-Json shape)' {
        It 'Returns the property value when present' {
            $p = [pscustomobject]@{ Foo = 'bar' }
            Get-NRGObjectField -Item $p -Key 'Foo' | Should -Be 'bar'
        }

        It 'Returns the default when the property is missing under StrictMode' {
            Set-StrictMode -Version Latest
            $p = [pscustomobject]@{ Foo = 'bar' }
            Get-NRGObjectField -Item $p -Key 'Missing' -Default 'fallback' | Should -Be 'fallback'
        }

        It 'Reads from real ConvertFrom-Json output' {
            $p = '{"alpha":1,"beta":"two"}' | ConvertFrom-Json
            Get-NRGObjectField -Item $p -Key 'beta' | Should -Be 'two'
        }
    }

    Context 'Synchronized hashtable inputs (module-state shape)' {
        It 'Reads from a Synchronized hashtable like $script:NRGRawData' {
            $sync = [System.Collections.Hashtable]::Synchronized(@{ key1 = 'val1' })
            Get-NRGObjectField -Item $sync -Key 'key1' | Should -Be 'val1'
        }
    }

    Context 'Null and edge inputs' {
        It 'Returns the default when -Item is $null' {
            Get-NRGObjectField -Item $null -Key 'anything' -Default 'd' | Should -Be 'd'
        }

        It 'Does not throw under StrictMode when reading a property that does not exist' {
            Set-StrictMode -Version Latest
            $p = [pscustomobject]@{ A = 1 }
            { Get-NRGObjectField -Item $p -Key 'Missing' } | Should -Not -Throw
        }
    }
}
