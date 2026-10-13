#Requires -Version 7.0
#
# Read-TPQuestionnaireFields.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Purpose: The one place a client-returned questionnaire PDF is parsed. The PDF comes
#          back from the client by email, so it is untrusted input, and pypdf has
#          shipped fixes for crafted files that loop or exhaust memory. The read is
#          therefore bounded: the file is judged BEFORE Python starts (size cap, not
#          empty, a %PDF- header), a watchdog thread inside the helper ends the
#          interpreter at the time limit (os._exit from a timer thread; signal.alarm
#          does not exist on Windows), only the AcroForm field values are read (never
#          page content), and a pypdf below the floor is refused with its version
#          named. Memory is not bounded on Windows. A refusal throws with the reason;
#          the importers turn that into exit code 4 and import nothing.
#
# Data keys: none.
# Graph scopes / cmdlets: none. Python runs through Lib/Invoke-TPPython.ps1 only.

$script:TPQuestionnairePdfMaxBytes   = 32MB      # a filled questionnaire is kilobytes
$script:TPQuestionnairePdfTimeoutSec = 60
$script:TPQuestionnairePypdfFloor    = '4.0.0'   # the 2023 crafted-input fixes are all below this

# The Python helper. Single-quoted: nothing is interpolated into Python source. The
# PDF path, the output path, the time limit and the floor arrive as argv.
$script:TPQuestionnairePythonReader = @'
import json, os, sys, threading

limit = int(sys.argv[3])
def _stop():
    sys.stderr.write("questionnaire read exceeded %d s\n" % limit)
    sys.stderr.flush()
    os._exit(124)
_watchdog = threading.Timer(limit, _stop)
_watchdog.daemon = True
_watchdog.start()

import pypdf
def _ver(v):
    parts = []
    for p in str(v).split('.')[:3]:
        digits = ''.join(ch for ch in p if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)
floor = sys.argv[4]
have = getattr(pypdf, '__version__', '0')
if _ver(have) < _ver(floor):
    sys.stderr.write("pypdf %s is older than the %s floor\n" % (have, floor))
    sys.exit(3)

from pypdf import PdfReader
reader = PdfReader(sys.argv[1])
fields = reader.get_fields() or {}
out = {}
for name, f in fields.items():
    v = f.get('/V')
    out[str(name)] = '' if v is None else str(v)
with open(sys.argv[2], 'w', encoding='utf-8') as fh:
    json.dump(out, fh)
_watchdog.cancel()
'@

function Read-TPQuestionnaireFields {
    <#
    .SYNOPSIS
        The AcroForm field values of a questionnaire PDF, as a hashtable of field
        name to string, read under the bounds above. Throws, naming the reason,
        for a file it will not read; never returns a partial map.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [string] $PdfPath,
        [Parameter(Mandatory)] [string] $Python,
        [ValidateRange(1024, 1073741824)] [long] $MaxBytes = $script:TPQuestionnairePdfMaxBytes,
        [ValidateRange(1, 3600)] [int] $TimeoutSeconds = $script:TPQuestionnairePdfTimeoutSec
    )
    $item = Get-Item -LiteralPath $PdfPath -ErrorAction Stop
    if ($item.PSIsContainer) { throw "'$PdfPath' is a folder, not a questionnaire PDF. Nothing was read." }
    if ($item.Length -eq 0) { throw "'$PdfPath' is empty. Nothing was read." }
    if ($item.Length -gt $MaxBytes) {
        throw ("'{0}' is {1:N1} MB, above the {2} MB the questionnaire importer reads; a filled questionnaire is far smaller, so this file is not one. Nothing was read." -f $PdfPath, ($item.Length / 1MB), [int]($MaxBytes / 1MB))
    }
    # The header: %PDF- within the first 1024 bytes (the specification allows a short preamble).
    $head = [byte[]]::new([Math]::Min(1024, $item.Length))
    $fs = [System.IO.File]::Open($PdfPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try { $read = $fs.Read($head, 0, $head.Length) } finally { $fs.Dispose() }
    if (([System.Text.Encoding]::ASCII.GetString($head, 0, $read)).IndexOf('%PDF-', [System.StringComparison]::Ordinal) -lt 0) {
        throw "'$PdfPath' is not a PDF (no %PDF- header). Nothing was read."
    }

    $tmpOut = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "tp-questionnaire-$([guid]::NewGuid().ToString('N')).json")
    try {
        $out = Invoke-TPPython -Python $Python -Script $script:TPQuestionnairePythonReader `
            -Arguments @($PdfPath, $tmpOut, [string]$TimeoutSeconds, $script:TPQuestionnairePypdfFloor)
        $code = $LASTEXITCODE
        $text = (@($out) | ForEach-Object { [string]$_ }) -join "`n"
        switch ($code) {
            0   { }
            124 { throw "reading '$PdfPath' took longer than $TimeoutSeconds s and was stopped; a filled questionnaire reads in well under that, so the file is damaged or crafted. Nothing was imported." }
            3   { throw "pypdf is older than the $($script:TPQuestionnairePypdfFloor) the importer requires ($($text.Trim())). Run 'pip install --upgrade pypdf', then re-run. Nothing was imported." }
            default { throw "pypdf could not read '$PdfPath' (exit $code): $($text.Trim()). Nothing was imported." }
        }
        $values = Get-Content -LiteralPath $tmpOut -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop
        $map = @{}
        if ($null -ne $values) {
            foreach ($p in $values.PSObject.Properties) { $map[[string]$p.Name] = [string]$p.Value }
        }
        return $map
    } finally {
        if (Test-Path -LiteralPath $tmpOut) { Remove-Item -LiteralPath $tmpOut -Force -ErrorAction SilentlyContinue }
    }
}
