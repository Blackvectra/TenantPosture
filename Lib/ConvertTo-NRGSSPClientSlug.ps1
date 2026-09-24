#Requires -Version 7.0
#
# ConvertTo-NRGSSPClientSlug.ps1
# Dependencies: none.
#
# Author: Matthew Levorson, NRG Technology Services / NextLayerSec LLC
# Purpose: The ONE place that turns a client name/domain into the filename
#          Config/ssp/<slug>.psd1 answers files live at. Get-NRGSSPAnswers and
#          Import-NRGSSPQuestionnaire.ps1 both need to resolve the exact same
#          file for the exact same client, so the slugging rule is extracted
#          here rather than copy-pasted — two copies drifting apart would
#          mean an importer silently writing answers a reader never sees
#          because Get-NRGSSPAnswers looks in a different file.
#
# Inputs:  -ClientName  string (tenant domain or free-form client name).
#
# Outputs: string slug, or '' when ClientName is blank/slugs to nothing.
#
# Consumes: nothing. No Graph, no EXO, no network, no filesystem.
#

function ConvertTo-NRGSSPClientSlug {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory = $false, Position = 0)]
        [AllowNull()] [AllowEmptyString()]
        [string] $ClientName
    )

    Set-StrictMode -Version Latest

    if (-not $ClientName) { return '' }
    ($ClientName.ToLowerInvariant() -replace '[^a-z0-9._-]+', '-').Trim('-')
}
