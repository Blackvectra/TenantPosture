#Requires -Version 7.0
#
# ConvertTo-TPPdf.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Print one of the tool's own self-contained HTML reports to PDF with
#   the Chromium-based browser already on the workstation (Microsoft Edge on
#   Windows, else Chrome or Chromium), headless. No new module and nothing to
#   install: every supported Windows has Edge.
#
# Rules (pinned by TP.Pdf.Tests.ps1):
#   - Never throws. It returns Written = $false with the reason (no browser,
#     the browser failed, timed out, or wrote no PDF), and the caller says so;
#     the HTML stays the deliverable and prints to PDF from any browser.
#   - The browser runs with a throwaway profile in a fresh temp folder, every
#     host name resolving nowhere, and no first-run, extensions or sync. The
#     page's own policy (default-src 'none') blocks every script and load;
#     scripts are not switched off in the browser because its print-to-PDF
#     pipeline needs them and writes nothing without them. Arguments go through ProcessStartInfo.ArgumentList, one per entry,
#     never a command line a path could break out of.
#   - The browser writes to the temp folder; the bytes are checked for a PDF
#     header and written to the target through Set-TPSensitiveFileContent, so
#     the PDF gets the same owner-only protection as every other output.
#   - Only a browser named msedge/chrome/chromium (or Microsoft Edge / Google
#     Chrome on macOS) is accepted, including through TP_PDF_BROWSER.
#
# Data consumed: one HTML file. Graph scopes / cmdlets used: none. No network.

function Find-TPPdfBrowser {
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $nameOk = { param([string] $p) [System.IO.Path]::GetFileNameWithoutExtension($p) -match '\A(msedge|chrome|chromium|chromium-browser|google-chrome|google-chrome-stable|Microsoft Edge|Google Chrome|headless_shell|chrome-headless-shell)\z' }
    $override = [string]$env:TP_PDF_BROWSER
    if ($override) {
        if ((& $nameOk $override) -and (Test-Path -LiteralPath $override -PathType Leaf)) { return (Resolve-Path -LiteralPath $override).Path }
        Write-Verbose "TP_PDF_BROWSER is not a Chromium-based browser executable; ignored."
    }
    $candidates = [System.Collections.Generic.List[string]]::new()
    if ($IsWindows) {
        foreach ($root in @(${env:ProgramFiles(x86)}, $env:ProgramFiles, $env:LOCALAPPDATA) | Where-Object { $_ }) {
            $candidates.Add((Join-Path $root 'Microsoft\Edge\Application\msedge.exe'))
            $candidates.Add((Join-Path $root 'Google\Chrome\Application\chrome.exe'))
        }
    } elseif ($IsMacOS) {
        $candidates.Add('/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge')
        $candidates.Add('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome')
    } else {
        foreach ($n in 'microsoft-edge', 'google-chrome', 'google-chrome-stable', 'chromium', 'chromium-browser') {
            $c = Get-Command $n -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($c) { $candidates.Add([string]$c.Source) }
        }
    }
    foreach ($c in $candidates) {
        if ((Test-Path -LiteralPath $c -PathType Leaf)) {
            # A package-manager wrapper (/usr/bin/microsoft-edge) is a link to the real binary.
            $real = (Get-Item -LiteralPath $c).ResolvedTarget
            $path = if ($real) { [string]$real } else { $c }
            if ((& $nameOk $path) -or (& $nameOk $c)) { return $path }
        }
    }
    return $null
}

function ConvertTo-TPPdf {
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $HtmlPath,
        [Parameter(Mandatory)] [string] $PdfPath,
        [ValidateRange(10, 600)] [int] $TimeoutSeconds = 90,
        [AllowEmptyString()] [string] $Browser = ''
    )
    $fail = { param([string] $why) [ordered]@{ Written = $false; Path = ''; Browser = $Browser; Reason = $why } }
    try {
        if (-not (Test-Path -LiteralPath $HtmlPath -PathType Leaf)) { return (& $fail 'The HTML report was not found.') }
        if (-not $Browser) { $Browser = Find-TPPdfBrowser }
        if (-not $Browser) { return (& $fail 'No Microsoft Edge, Chrome or Chromium was found on this computer.') }

        $work = Join-Path ([System.IO.Path]::GetTempPath()) ('tp-pdf-' + [guid]::NewGuid().ToString('N'))
        $null = [System.IO.Directory]::CreateDirectory($work)
        try {
            $out = Join-Path $work 'report.pdf'
            $psi = [System.Diagnostics.ProcessStartInfo]::new($Browser)
            $psi.UseShellExecute = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.CreateNoWindow = $true
            $browserArgs = @(
                '--headless', '--disable-gpu', '--no-first-run', '--no-default-browser-check',
                '--disable-extensions', '--disable-sync', '--disable-background-networking',
                '--host-resolver-rules=MAP * ~NOTFOUND',
                '--no-pdf-header-footer', '--print-to-pdf-no-header',
                "--user-data-dir=$(Join-Path $work 'profile')", "--print-to-pdf=$out"
            )
            # The browser's sandbox refuses to start as root; that case is a CI
            # container, never an operator's workstation.
            if (-not $IsWindows -and (& id -u 2>$null) -eq '0') { $browserArgs += '--no-sandbox' }
            foreach ($a in $browserArgs) { $psi.ArgumentList.Add($a) }
            $psi.ArgumentList.Add(([System.Uri]::new((Resolve-Path -LiteralPath $HtmlPath).Path)).AbsoluteUri)

            $proc = [System.Diagnostics.Process]::Start($psi)
            $stdout = $proc.StandardOutput.ReadToEndAsync()
            $stderr = $proc.StandardError.ReadToEndAsync()
            if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
                try { $proc.Kill($true) } catch { Write-Verbose "Browser already exited: $($_.Exception.Message)" }
                return (& $fail "The browser did not finish within $TimeoutSeconds seconds.")
            }
            $null = $stdout.Result; $null = $stderr.Result
            if (-not (Test-Path -LiteralPath $out -PathType Leaf)) { return (& $fail "The browser wrote no PDF (exit code $($proc.ExitCode)).") }
            $bytes = [System.IO.File]::ReadAllBytes($out)
            if ($bytes.Length -lt 5 -or [System.Text.Encoding]::ASCII.GetString($bytes, 0, 5) -ne '%PDF-') { return (& $fail 'The browser wrote a file that is not a PDF.') }
            Set-TPSensitiveFileContent -Path $PdfPath -Bytes $bytes
            return [ordered]@{ Written = $true; Path = $PdfPath; Browser = $Browser; Reason = '' }
        } finally {
            Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
        }
    } catch {
        return (& $fail "The PDF could not be produced: $($_.Exception.Message)")
    }
}
