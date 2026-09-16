#Requires -Version 7.0
#
# NRG.ExternalShapes.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Pins the OMITTED-PROPERTY shapes the Microsoft APIs actually return.
#
# The recurring failure in this tool is not "the query failed" — SectionStatus
# covers that. It is "the query succeeded and we read the answer wrong", and the
# commonest form is an OPTIONAL property that the API omits entirely rather than
# returning null. Under the module-wide StrictMode a nested dot-access on an
# absent intermediate THROWS, and `?? default` never runs, so the enclosing
# try/catch marks the section Failed and the control reports NotApplicable
# forever — silently non-functional rather than visibly broken.
#
# The case that motivated this file: Graph does not return `signInActivity` at
# all for a user who never signed in or last signed in before April 2020. That
# is documented on the user resource type, and it means the property was absent
# on precisely the stale and never-signed-in accounts the guest and
# stale-account collectors exist to find. One such guest — which nearly every
# real tenant has — failed the whole section.
#
# Every fixture below is an omission, not a null. A fixture that sets the
# property to $null passes against the broken code.

Describe 'External API shapes — omitted properties' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
    }

    Context 'the premise: an omitted property is not a null property' {

        It 'nested dot-access on an absent intermediate throws under StrictMode' {
            $noActivity = [pscustomobject]@{ id = '1'; displayName = 'Never signed in' }
            { & { Set-StrictMode -Version Latest
                  $null = $noActivity.signInActivity.lastSignInDateTime } } | Should -Throw
        }

        It 'and ?? does not rescue it — the throw happens first' {
            $noActivity = [pscustomobject]@{ id = '1' }
            { & { Set-StrictMode -Version Latest
                  $null = [string]($noActivity.signInActivity.lastSignInDateTime ?? '') } } | Should -Throw
        }

        It 'a null-valued intermediate throws too, so neither shape is safe' {
            # Worth stating explicitly: the omission is what production sends,
            # but an explicit null fails the same way. There is no shape of
            # "absent" that bare dot-access survives, which is why the guard
            # below is absolute rather than advisory.
            $nulled = [pscustomobject]@{ signInActivity = $null }
            { & { Set-StrictMode -Version Latest
                  $null = [string]($nulled.signInActivity.lastSignInDateTime ?? '') } } | Should -Throw
        }
    }

    Context 'Get-NRGNestedProperty absorbs the omission' {

        It 'returns the default when the intermediate is absent' {
            $u = [pscustomobject]@{ id = '1'; displayName = 'Never signed in' }
            Get-NRGNestedProperty -Object $u -Path 'signInActivity.lastSignInDateTime' -Default '' | Should -Be ''
        }

        It 'returns the default when the leaf is absent but the intermediate exists' {
            $u = [pscustomobject]@{ signInActivity = [pscustomobject]@{ lastNonInteractiveSignInDateTime = '2026-01-01T00:00:00Z' } }
            Get-NRGNestedProperty -Object $u -Path 'signInActivity.lastSignInDateTime' -Default '' | Should -Be ''
        }

        It 'returns the value when present' {
            $u = [pscustomobject]@{ signInActivity = [pscustomobject]@{ lastSignInDateTime = '2026-09-01T00:00:00Z' } }
            Get-NRGNestedProperty -Object $u -Path 'signInActivity.lastSignInDateTime' -Default '' | Should -Be '2026-09-01T00:00:00Z'
        }

        It 'absorbs a three-level omission (Power Platform properties.states.management.id)' {
            $env1 = [pscustomobject]@{ name = 'e1'; properties = [pscustomobject]@{ displayName = 'Default' } }
            Get-NRGNestedProperty -Object $env1 -Path 'properties.states.management.id' -Default '' | Should -Be ''
            Get-NRGNestedProperty -Object $env1 -Path 'properties.displayName'          -Default '' | Should -Be 'Default'
        }
    }

    Context 'no collector reads a nested API property by bare dot-access' {

        It 'nested $_.<a>.<b> access in Collectors goes through a helper' {
            # Static guard. The behavioural tests above only cover the shapes we
            # already know are omitted; this catches the next one before a tenant
            # does. $_.Exception.* is the PowerShell error record, not API data.
            $offenders = [System.Collections.Generic.List[string]]::new()
            foreach ($f in Get-ChildItem (Join-Path $script:RepoRoot 'Collectors') -Filter '*.ps1' -Recurse) {
                $lines = Get-Content -LiteralPath $f.FullName
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    $line = $lines[$i]
                    if ($line -match '^\s*#') { continue }
                    if ($line -match 'Get-NRGNestedProperty|Get-NRGObjectField') { continue }
                    if ($line -match '\$_\.Exception\.') { continue }
                    if ($line -match '\$_\.[a-zA-Z]+\.[a-zA-Z]') {
                        $offenders.Add("$($f.Name):$($i + 1): $($line.Trim())")
                    }
                }
            }
            $offenders -join "`n" | Should -BeNullOrEmpty -Because @'
Microsoft APIs OMIT optional properties rather than returning null. Under
StrictMode a nested read on an absent intermediate throws before ?? applies,
failing the whole section. Use Get-NRGNestedProperty -Object $_ -Path 'a.b'.
'@
        }
    }

    Context 'sign-in dates parse in any culture and any omission' {

        It 'an ISO 8601 Graph timestamp parses to the right age regardless of culture' {
            # Graph returns ISO 8601 UTC. Parsing without InvariantCulture is a
            # latent misread on a non-en-US operator machine, and this tool runs
            # on whatever workstation the MSP happens to use.
            $ts = ([datetime]::UtcNow.AddDays(-100)).ToString('o')
            $parsed = [datetime]::MinValue
            [datetime]::TryParse($ts, [cultureinfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed) | Should -BeTrue
            [int]([datetime]::UtcNow - $parsed.ToUniversalTime()).TotalDays | Should -BeGreaterOrEqual 99
        }

        It 'an unparseable timestamp does not crash the caller' {
            $parsed = [datetime]::MinValue
            [datetime]::TryParse('not-a-date', [cultureinfo]::InvariantCulture,
                [System.Globalization.DateTimeStyles]::RoundtripKind, [ref]$parsed) | Should -BeFalse
        }
    }
}
