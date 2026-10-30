#Requires -Version 7.0
#
# TPFuzz.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: A small, deterministic mutation fuzzer for the parsers that read
#   untrusted input (results JSON, MCP JSON-RPC, SCAP XML, ScubaGear results,
#   DNS TXT data, endpoint result files, web path segments, the output
#   escapers). Dot-sourced by Testing/TP.Fuzz.Tests.ps1.
#
# Every case comes from System.Random seeded with one number, so a failure is
# reproduced by running with the same TP_FUZZ_SEED (and TP_FUZZ_ITERATIONS for
# a longer run). No network, no file outside the caller's temp folder.
# Data consumed: none. Graph scopes / cmdlets used: none.

function Get-TPFuzzSettings {
    # Seed and iteration count from the environment, with fixed defaults so
    # every CI run tests the same cases unless asked otherwise.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $seed = 20261030
    $iter = 120
    $s = 0; if ($env:TP_FUZZ_SEED -and [int]::TryParse($env:TP_FUZZ_SEED, [ref]$s)) { $seed = $s }
    $n = 0; if ($env:TP_FUZZ_ITERATIONS -and [int]::TryParse($env:TP_FUZZ_ITERATIONS, [ref]$n) -and $n -gt 0) { $iter = [math]::Min($n, 100000) }
    return @{ Seed = $seed; Iterations = $iter }
}

function Get-TPFuzzTokens {
    # Inputs that break parsers more often than random bytes do.
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @(
        '"', "'", '\', '\"', '\\', '<', '>', '&', '&amp;', ']]>', '<!--', '-->', '<![CDATA[', '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>',
        '{', '}', '[', ']', ':', ',', 'null', 'true', 'false', '-0', '1e309', '-1e309', 'NaN', '9223372036854775808', '-1',
        [string][char]0, [string][char]0x1F, [string][char]0x7F, [string][char]0x202E, [string][char]0x200B, [string][char]0xFEFF,
        [string][char]0x2028, [string][char]0x0085, [string][char]0x2019, [string][char]0x201B, [string][char]0xFFFF,
        [string][char]0xD800, [string][char]0xDC00, "`r`n", "`n", "`t", '%00', '%2e%2e%2f', '..', '../', '..\', '/', '\\?\', 'C:\', '~',
        '$(Get-Process)', '`', '|', '*', '_flat', 'IR-Triage', 'x-email-results.json', '=cmd|calc', '@SUM(1)', '[x](evil.example/p)', '![i](evil.example/i.png)',
        '<script>alert(1)</script>', '<img src=x onerror=alert(1)>', 'javascript:alert(1)', '\u0000', '\ud800', '"jsonrpc":"2.0"', '"id":', '"method":"tools/call"'
    )
}

function Get-TPFuzzCase {
    <#
    .SYNOPSIS
        One mutated string from a seed input. Several mutations stack, so a
        case can be truncated, spliced and stuffed with hostile tokens at once.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [AllowEmptyString()] [string] $Seed,
        [Parameter(Mandatory)] [System.Random] $Random,
        [AllowNull()] [string[]] $Others = @()
    )
    $tokens = Get-TPFuzzTokens
    $s = $Seed
    $rounds = 1 + $Random.Next(4)
    for ($r = 0; $r -lt $rounds; $r++) {
        $len = $s.Length
        $at = if ($len -gt 0) { $Random.Next($len + 1) } else { 0 }
        switch ($Random.Next(10)) {
            0 { if ($len -gt 0) { $s = $s.Substring(0, $at) } }                                     # truncate
            1 { $s = $s.Insert($at, $tokens[$Random.Next($tokens.Count)]) }                           # hostile token
            2 { if ($len -gt 0) { $n = [math]::Min($len - $at, 1 + $Random.Next(16)); if ($n -gt 0) { $s = $s.Remove($at, $n) } } }  # delete a span
            3 { if ($len -gt 0) { $n = [math]::Min($len - $at, 1 + $Random.Next(64)); if ($n -gt 0) { $s = $s.Insert($at, $s.Substring($at, $n)) } } }  # duplicate a span
            4 { $s = $s.Insert($at, ([string][char]$Random.Next(0, 0x2FFF))) }                          # one random character
            5 { $s = $s.Insert($at, ([string]$tokens[$Random.Next($tokens.Count)]) * (1 + $Random.Next(200))) }  # a long run
            6 { $c = @('[', '{', '<a>', '(')[$Random.Next(4)]; $s = $s.Insert($at, $c * (50 + $Random.Next(400))) }  # deep nesting
            7 { if (@($Others).Count) { $o = $Others[$Random.Next(@($Others).Count)]; $cut = $Random.Next($o.Length + 1); $s = $s.Substring(0, $at) + $o.Substring($cut) } }  # splice another seed
            8 { $s = [regex]::Replace($s, '\d+', { param($m) @('0', '-1', '99999999999999999999', '1e309', 'NaN')[$Random.Next(5)] }, 'None', [timespan]::FromSeconds(2)) }  # bad numbers
            9 { $s = $s -replace '(?i)\btrue\b', 'false' -replace '"Satisfied"', '"Gap"' }             # flip meaning
        }
        if ($s.Length -gt 200000) { $s = $s.Substring(0, 200000) }
    }
    return $s
}

function Format-TPFuzzRepro {
    # A short, safe description of a failing case for an assertion message:
    # the seed, the iteration and the first bytes as base64.
    [CmdletBinding()]
    [OutputType([string])]
    param([int] $Seed, [int] $Iteration, [AllowEmptyString()] [string] $Case)
    $head = if ($Case.Length -gt 600) { $Case.Substring(0, 600) } else { $Case }
    return "TP_FUZZ_SEED=$Seed iteration $Iteration, input (base64, first 600 chars): $([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($head)))"
}
