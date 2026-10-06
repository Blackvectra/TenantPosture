#Requires -Version 7.0
#
# Get-NRGWebApiError.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# The failure contract for the local web GUI's API (Start-NRGWebServer), as a
# pure table so it is tested without a server. Every refusal under /api/ is a
# JSON object with a stable machine-readable code and a fixed sentence:
#
#   { "error": "InvalidDomain", "message": "The domain is not a valid domain name." }
#
# A caller (the GUI, a test, later an integration) branches on `error`, never on
# the wording. The message is fixed text and never echoes the request, so a
# refusal cannot reflect attacker-chosen input back into a response or a log.
# The HTTP status travels with the code, so a route cannot pair a code with the
# wrong status.
#
# Outside /api/ (the static files, the report site) a refusal is a plain-text
# sentence: those routes serve documents, and their callers are a browser.
#
# Consumed:  nothing. Reads no file, makes no call.
# Graph scopes / cmdlets used: none.

function Get-NRGWebApiError {
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('DomainRequired', 'InvalidDomain', 'UnknownRunId', 'InvalidPath', 'NotFound', 'Forbidden')]
        [string] $Code
    )

    $table = @{
        DomainRequired = @{ HttpStatus = 400; Message = 'A domain is required.' }
        InvalidDomain  = @{ HttpStatus = 400; Message = 'The domain is not a valid domain name.' }
        UnknownRunId   = @{ HttpStatus = 404; Message = 'No scan with that run id.' }
        InvalidPath    = @{ HttpStatus = 400; Message = 'Invalid path segment.' }
        NotFound       = @{ HttpStatus = 404; Message = 'Not found.' }
        Forbidden      = @{ HttpStatus = 403; Message = 'Forbidden.' }
    }

    [pscustomobject]@{
        HttpStatus = [int]$table[$Code].HttpStatus
        Body       = [ordered]@{ error = $Code; message = [string]$table[$Code].Message }
    }
}
