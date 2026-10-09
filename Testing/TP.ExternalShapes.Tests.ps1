#Requires -Version 7.0
#
# TP.ExternalShapes.Tests.ps1
# TenantPosture
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
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
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

    Context 'Get-TPNestedProperty absorbs the omission' {

        It 'returns the default when the intermediate is absent' {
            $u = [pscustomobject]@{ id = '1'; displayName = 'Never signed in' }
            Get-TPNestedProperty -Object $u -Path 'signInActivity.lastSignInDateTime' -Default '' | Should -Be ''
        }

        It 'returns the default when the leaf is absent but the intermediate exists' {
            $u = [pscustomobject]@{ signInActivity = [pscustomobject]@{ lastNonInteractiveSignInDateTime = '2026-01-01T00:00:00Z' } }
            Get-TPNestedProperty -Object $u -Path 'signInActivity.lastSignInDateTime' -Default '' | Should -Be ''
        }

        It 'returns the value when present' {
            $u = [pscustomobject]@{ signInActivity = [pscustomobject]@{ lastSignInDateTime = '2026-09-01T00:00:00Z' } }
            Get-TPNestedProperty -Object $u -Path 'signInActivity.lastSignInDateTime' -Default '' | Should -Be '2026-09-01T00:00:00Z'
        }

        It 'absorbs a three-level omission (Power Platform properties.states.management.id)' {
            $env1 = [pscustomobject]@{ name = 'e1'; properties = [pscustomobject]@{ displayName = 'Default' } }
            Get-TPNestedProperty -Object $env1 -Path 'properties.states.management.id' -Default '' | Should -Be ''
            Get-TPNestedProperty -Object $env1 -Path 'properties.displayName'          -Default '' | Should -Be 'Default'
        }
    }

    Context 'no collector reads a nested API property by bare dot-access' {

        It 'nested <var>.<a>.<b> access in Collectors goes through a helper' {
            # Static guard. The behavioural tests above only cover the shapes we
            # already know are omitted; this catches the next one before a tenant
            # does. <var>.Exception.* is a PowerShell error record, not API data.
            # Matches any variable, not just $_ — a nested read through a named
            # loop variable (e.g. $s.principal.userPrincipalName) is the exact
            # shape this guard exists to forbid and must not be invisible to it.
            #
            # A line-based regex cannot tell a read of untrusted external API
            # data apart from a read/write of the TOOL'S OWN, always-present
            # internal state — e.g. $result.Data.Foo = ... (the collector's own
            # accumulator, built entirely by its own code) or $aad.Data.Users
            # (another collector's result, fetched via Get-TPRawData, whose
            # top-level CollectorId/CollectedAt/Success/Data shape is a fixed
            # contract this tool guarantees, not an optional API property). A
            # first pass that matched ANY variable without this distinction
            # flagged 371 lines across 23 of 24 collector files, nearly all of
            # them such false positives — turning a narrow, high-signal guard
            # into one that fails almost everywhere, which is worse than the
            # tautology it replaced. $SafeVars below are verified by hand
            # (grep each one's assignment) to be either this tool's own
            # accumulator/contract or a local .NET object (Stopwatch,
            # X509Certificate2, IAsyncResult, a Get-Command result) — never
            # data read from Graph/EXO/Power Platform. Anything else matching
            # the pattern is a genuine candidate and must go through the helper.
            $safeVars = @(
                'result', 'results',        # every collector's own accumulator
                'recentBag',                # Email-IR sign-in collector's own local bag
                'd',                         # DNS collector's own per-domain accumulator
                'aad', 'purview', 'exoData', 'exoRaw', 'rawRoles', 'caPolicies',
                                             # another collector's result via Get-TPRawData —
                                             # this tool's own CollectorId/CollectedAt/Success/Data
                                             # contract, not raw external API shape
                'policy',                   # loop var over $caPolicies.Data.Policies — same
                                             # internal contract, built entirely by AADCAPolicies.ps1
                'sw', 'x509', 'iar', 'gcInboxRule'
                                             # local .NET/reflection objects (Stopwatch,
                                             # X509Certificate2, IAsyncResult, Get-Command), not API data
            )
            $offenders = [System.Collections.Generic.List[string]]::new()
            $scanPaths = @(
                (Join-Path $script:RepoRoot 'Collectors'),
                (Join-Path $script:RepoRoot 'Email-IR/Collectors')
            ) | Where-Object { Test-Path -LiteralPath $_ }
            foreach ($f in Get-ChildItem $scanPaths -Filter '*.ps1' -Recurse) {
                $lines = Get-Content -LiteralPath $f.FullName
                for ($i = 0; $i -lt $lines.Count; $i++) {
                    $line = $lines[$i]
                    if ($line -match '^\s*#') { continue }
                    if ($line -match 'Get-TPNestedProperty|Get-TPObjectField') { continue }
                    if ($line -match '\$[A-Za-z_]\w*\.Exception\.') { continue }
                    if ($line -match '\.PSObject\.') { continue }
                    if ($line -match '\$([A-Za-z_]\w*)\.([A-Za-z_]\w*)\.([A-Za-z_]\w*)') {
                        if ($safeVars -contains $matches[1]) { continue }
                        $offenders.Add("$($f.Name):$($i + 1): $($line.Trim())")
                    }
                }
            }
            $offenders -join "`n" | Should -BeNullOrEmpty -Because @'
Microsoft APIs OMIT optional properties rather than returning null. Under
StrictMode a nested read on an absent intermediate throws before ?? applies,
failing the whole section. Use Get-TPNestedProperty -Object <var> -Path 'a.b'.
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

    # PowerShell allows '?' in a variable name, so "…/servicePrincipals/$cid?`$select=…"
    # reads the unset variable $cid? (StrictMode throws) and never builds the
    # URL: every consented app was reported by object ID. Write ${cid}?.
    Context 'no variable name swallows a URL query mark' {
        It 'no module file references a variable whose name contains "?" (other than the automatic $?)' {
            $offenders = [System.Collections.Generic.List[string]]::new()
            $files = Get-ChildItem -LiteralPath $script:RepoRoot -Recurse -Include '*.ps1', '*.psm1' -File |
                Where-Object { $_.FullName -notmatch '[\\/](Testing|output|\.git)[\\/]' }
            foreach ($f in $files) {
                $tokens = $null; $errs = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errs)
                foreach ($v in $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true)) {
                    $name = $v.VariablePath.UserPath
                    if ($name -ne '?' -and $name.Contains('?')) {
                        $offenders.Add("$($f.Name):$($v.Extent.StartLineNumber) `$$name")
                    }
                }
            }
            $offenders | Should -BeNullOrEmpty -Because 'write ${name}? when a URL query follows a variable'
        }
    }
}
