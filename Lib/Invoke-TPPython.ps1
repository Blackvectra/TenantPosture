#Requires -Version 7.0
#
# Invoke-TPPython.ps1
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: The one way the tool runs Python. The script goes to the interpreter
#   on stdin, so no helper file is written into a folder another local account
#   could also write to, and the first thing the script does is drop the
#   current directory ('' or '.') from sys.path, so a module planted beside the
#   operator's shell (openpyxl.py, pypdf.py, json.py) is never imported in
#   place of the real one. Only `sys` is touched before that line, and `sys` is
#   built into the interpreter, so nothing on disk can shadow it. The user site
#   and PYTHONPATH are left alone on purpose: `-I` would discard them, and a
#   non-administrator's `pip install --user openpyxl` lives there. UTF-8 mode is
#   forced so a box-drawing character in a script survives a Windows code page.
# Data keys: none. Graph / cmdlets: none (one child process).

$script:TPPythonPrologue = "import sys; sys.path[:] = [p for p in sys.path if p not in ('', '.')]`n"

function Test-TPPythonModule {
    <#
    .SYNOPSIS
        True when the interpreter can import the module under the same rules
        the helpers run with (current directory off sys.path, user site kept).
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [string] $Python,
        [Parameter(Mandatory)] [ValidatePattern('^[A-Za-z_][A-Za-z0-9_]{0,63}$')] [string] $Module
    )
    try {
        $null = & $Python -X utf8=1 -c ($script:TPPythonPrologue + "import $Module") 2>&1
        return ($LASTEXITCODE -eq 0)
    } catch { return $false }
}

function Invoke-TPPython {
    <#
    .SYNOPSIS
        Runs a Python script from a string with the arguments given, returning
        the process output. The caller reads $LASTEXITCODE as it would after
        any native command.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Python,
        [Parameter(Mandatory)] [string] $Script,
        [AllowEmptyCollection()] [string[]] $Arguments = @()
    )
    $full = $script:TPPythonPrologue + $Script
    return @($full | & $Python -X utf8=1 - @Arguments 2>&1)
}
