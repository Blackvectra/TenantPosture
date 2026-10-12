#Requires -Version 7.0
#
# Install-TPPrerequisites.ps1  (v4.5.5)
#
# One-shot setup for a fresh machine. Run this once after extracting the tool.
# Checks and installs everything TenantPosture needs to run cleanly.
#
# Usage:
#   .\Install-TPPrerequisites.ps1
#   .\Install-TPPrerequisites.ps1 -SkipPython     # skip Python/openpyxl for XLSX
#   .\Install-TPPrerequisites.ps1 -Force          # reinstall everything
#

[CmdletBinding()]
param(
    [switch] $SkipPython,
    [switch] $Force
)

# Audit fix (v4.6.x LOW): EAP=Stop module-wide. Individual install steps
# below wrap their own try/catch so a single package failure (e.g.
# MicrosoftTeams) doesn't abort the prerequisites checklist — but the
# default fall-through behavior is now fail-fast instead of fail-silent.
$ErrorActionPreference = 'Stop'

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " TenantPosture Prerequisites Installer"                          -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# ── PowerShell version check ─────────────────────────────────────────────────
Write-Host "[1/6] Checking PowerShell version..." -ForegroundColor Cyan
if ($PSVersionTable.PSVersion.Major -lt 7) {
    Write-Host "  [!] PowerShell 7+ required (you have $($PSVersionTable.PSVersion))" -ForegroundColor Red
    Write-Host "  [!] Install: winget install Microsoft.PowerShell" -ForegroundColor Yellow
    exit 1
}
Write-Host "  [+] PowerShell $($PSVersionTable.PSVersion) — OK" -ForegroundColor Green

# ── Execution policy ─────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[2/6] Checking execution policy..." -ForegroundColor Cyan
$policy = Get-ExecutionPolicy -Scope CurrentUser
$effective = Get-ExecutionPolicy
if ($policy -eq 'AllSigned' -or $effective -eq 'AllSigned') {
    # AllSigned is a deliberate choice, often set by policy. The installer
    # never lowers it: the operator signs the tool (Build/Sign-Release.ps1)
    # or changes the policy knowingly.
    Write-Host "  [!] Execution policy is AllSigned (CurrentUser: $policy, effective: $effective). Not changed." -ForegroundColor Yellow
    Write-Host "      Either sign the tool: Build/New-TPCodeSigningCert.ps1 then Build/Sign-Release.ps1" -ForegroundColor DarkGray
    Write-Host "      or, if your organization allows it: Set-ExecutionPolicy RemoteSigned -Scope CurrentUser" -ForegroundColor DarkGray
} elseif ($policy -in @('Restricted', 'Undefined') -and $effective -in @('Restricted', 'Undefined', 'RemoteSigned', 'Unrestricted', 'Bypass')) {
    Write-Host "  [*] Setting CurrentUser policy to RemoteSigned (was $policy)..." -ForegroundColor Yellow
    try {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
        Write-Host "  [+] Execution policy set" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "  [+] Policy is $policy (effective $effective) — OK" -ForegroundColor Green
}

# ── Unblock files ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[3/6] Unblocking files (Zone.Identifier from downloads)..." -ForegroundColor Cyan
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
# Removing the download mark is an authorization: with the policy set to
# RemoteSigned above, that mark is what stops a downloaded script from running,
# and the module dot-sources every *.ps1 under Lib, Collectors, Evaluators and
# Publishers on import. So only a script whose Authenticode signature verifies
# on this workstation AND was made by the release signer is unblocked. A Valid
# status alone is not that: it says a chain this workstation trusts signed the
# file, and a script planted in a tampered archive and signed by any publisher
# the workstation happens to trust is Valid too. The release signer is pinned
# to the signer of this installer's own signature, which the operator already
# relied on to run it; an installer that does not carry a valid signature
# cannot vouch for any file, so nothing is unblocked. A hash record that
# travels inside the archive (FILES.sha256, the integrity manifest) proves
# nothing here: whoever changed the archive rewrites it. It is used only to
# name files that are not part of the release. An unsigned release keeps its
# marks, and the operator is told how to clear them after a review; a git
# clone carries none.
$scriptExt = @('.ps1', '.psm1', '.psd1', '.ps1xml')
try {
    $scripts = @(Get-ChildItem -LiteralPath $scriptDir -Recurse -File -Force -ErrorAction SilentlyContinue |
        Where-Object { $_.Extension -in $scriptExt -and $_.FullName -notmatch '[\\/](output|\.git)([\\/]|$)' })
    $pin = ''
    $selfStatus = 'not on disk'
    if ($PSCommandPath -and (Test-Path -LiteralPath $PSCommandPath -PathType Leaf)) {
        $selfSig = Get-AuthenticodeSignature -LiteralPath $PSCommandPath -ErrorAction SilentlyContinue
        $selfStatus = if ($selfSig) { [string]$selfSig.Status } else { 'unreadable' }
        if ($selfSig -and $selfSig.Status -eq 'Valid' -and $selfSig.SignerCertificate) {
            $pin = [string]$selfSig.SignerCertificate.Thumbprint
        }
    }
    # The release record (FILES.sha256 inside an archive, else the committed
    # manifest) is read BEFORE anything is unblocked: a script the record does
    # not name is never part of this release, so it keeps its mark even when
    # the release signer signed it (a script copied from another signed release
    # into Lib\ would otherwise be unblocked, and the module loader dot-sources
    # every *.ps1 under its folders on import). The record's hashes are not
    # what gates here (whoever changed the archive rewrites them); its names
    # are, beside the signer pin. With no record nothing can be told apart, so
    # nothing is unblocked.
    $record = $null
    foreach ($candidate in @((Join-Path $scriptDir 'FILES.sha256'), (Join-Path $scriptDir 'tools' 'integrity-manifest.txt'))) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { $record = $candidate; break }
    }
    $recorded = $null
    if ($record) {
        $recorded = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($line in (Get-Content -LiteralPath $record | Where-Object { $_ -and -not $_.StartsWith('#') })) {
            $parts = $line -split '\s+', 2
            if ($parts.Count -eq 2) { [void]$recorded.Add((Join-Path $scriptDir ($parts[1].Trim() -replace '/', [string][System.IO.Path]::DirectorySeparatorChar))) }
        }
    }
    $unblocked = 0; $kept = @(); $stray = @()
    foreach ($f in $scripts) {
        $sig = Get-AuthenticodeSignature -LiteralPath $f.FullName -ErrorAction SilentlyContinue
        $status = if ($sig) { [string]$sig.Status } else { 'unreadable' }
        $tp = if ($sig -and $sig.SignerCertificate) { [string]$sig.SignerCertificate.Thumbprint } else { '' }
        $rel = $f.FullName.Substring($scriptDir.Length + 1)
        $inRecord = ($null -ne $recorded -and $recorded.Contains($f.FullName))
        if (-not $inRecord) { $stray += $rel }
        if ($pin -and $status -eq 'Valid' -and $tp -eq $pin -and $inRecord) {
            Unblock-File -LiteralPath $f.FullName -ErrorAction SilentlyContinue
            $unblocked++
        } elseif ($pin -and $status -eq 'Valid' -and $tp -eq $pin) {
            $kept += "$rel [signed by the release signer but not named by the release record]"
        } elseif ($pin -and $status -eq 'Valid') {
            $kept += "$rel [Valid, signer $tp is not the release signer]"
        } else {
            $kept += "$rel [$status]"
        }
    }
    if (-not $record) {
        Write-Host "  [i] No release record (FILES.sha256 or tools\integrity-manifest.txt) is beside this installer, so nothing was unblocked: a file the release does not name is never unblocked, and without the record none can be told apart." -ForegroundColor Yellow
    } elseif ($pin) {
        Write-Host "  [+] $unblocked script file(s) named by $(Split-Path -Leaf $record) and signed by the release signer ($pin, the signer of this installer) unblocked" -ForegroundColor Green
    } else {
        Write-Host "  [i] This installer carries no valid Authenticode signature ($selfStatus), so it cannot vouch for any file: nothing was unblocked." -ForegroundColor Yellow
    }
    if ($kept.Count -gt 0) {
        $shown = if ($kept.Count -le 12) { $kept -join ', ' } else { (($kept | Select-Object -First 12) -join ', ') + ", and $($kept.Count - 12) more" }
        Write-Host "  [i] Left as downloaded ($($kept.Count) file(s) not named by the release record, not signed by the release signer, or with no signature this workstation verifies): $shown" -ForegroundColor Yellow
        Write-Host "      An in-house signature verifies once the signing certificate is in this workstation's TrustedPublisher and Root stores (Build/New-TPCodeSigningCert.ps1 does that where it ran). For an unsigned release, review the files, then: Get-ChildItem -Recurse -Include *.ps1,*.psm1,*.psd1,*.ps1xml | Unblock-File" -ForegroundColor DarkGray
    }
    # Files no release record names are never part of the release; they were
    # never unblocked above, and they are named so the operator removes them.
    if ($record -and $stray.Count -gt 0) {
        Write-Host "  [!] Not in the release record $(Split-Path -Leaf $record) (the module would load them on import; left blocked, remove what you did not put there): $($stray -join ', ')" -ForegroundColor Red
    }
} catch {
    Write-Host "  [!] Unblock step failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# The helpers this installer loads next (Lib\Get-TPModuleInstallScope.ps1 and
# Lib\Invoke-TPPython.ps1) are subject to the same policy as every other
# script. In an unsigned release the operator may have unblocked only this
# file, and dot-sourcing a helper that is still marked as downloaded then
# fails under RemoteSigned with nothing installed. So the run stops HERE when
# the policy would refuse a helper, names the files and asks for the review
# before the relaunch, instead of failing half-way with a policy error.
$helperPaths = @((Join-Path $scriptDir 'Lib' 'Get-TPModuleInstallScope.ps1'), (Join-Path $scriptDir 'Lib' 'Invoke-TPPython.ps1'))
$policyNow = [string](Get-ExecutionPolicy)
if ($policyNow -in @('RemoteSigned', 'AllSigned')) {
    $refused = @(foreach ($h in $helperPaths) {
        if (-not (Test-Path -LiteralPath $h -PathType Leaf)) { continue }
        $hSig = $null
        try { $hSig = Get-AuthenticodeSignature -LiteralPath $h -ErrorAction Stop } catch { $hSig = $null }
        $hValid = ($null -ne $hSig -and $hSig.Status -eq 'Valid')
        $hMarked = $false
        try { $hMarked = [bool](Get-Item -LiteralPath $h -Stream Zone.Identifier -ErrorAction Stop) } catch { $hMarked = $false }
        if (-not $hValid -and ($policyNow -eq 'AllSigned' -or $hMarked)) { $h.Substring($scriptDir.Length + 1) }
    })
    if ($refused.Count -gt 0) {
        Write-Host "  [!] Stopping: the helper file(s) this installer loads next carry no signature this workstation verifies, and the $policyNow policy would refuse to load them: $($refused -join ', ')" -ForegroundColor Red
        Write-Host "      For an unsigned release, review the files, then: Get-ChildItem -Recurse -Include *.ps1,*.psm1,*.psd1,*.ps1xml | Unblock-File — and run this installer again. A signed release is unblocked by this step once its certificate is in the workstation's TrustedPublisher and Root stores." -ForegroundColor Yellow
        exit 1
    }
}

# ── PowerShell modules ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "[4/6] Checking PowerShell modules..." -ForegroundColor Cyan

# Specific version requirements:
# - ExchangeOnlineManagement 3.7.2 or later: 3.7.2 added -DisableWAM, the
#   supported way around the WAM broker crash the old 3.2.0 pin worked
#   around. Microsoft's module notes: 3.5.0-3.9.x need PowerShell 7.4,
#   3.10.0+ need PowerShell 7.6, so the ceiling follows the PowerShell in use.
# - Graph.Authentication 2.x for modern MSAL flow
# - Teams 5.x+ for device code auth
# ── Module install scope: avoid OneDrive-synced paths ────────────────────────
# The CurrentUser module directory lives under Documents, and on machines with
# Known Folder Move enabled Documents is redirected into OneDrive. OneDrive then
# syncs, locks and sometimes partially materialises the module DLLs, which is a
# documented cause of "Could not load file or assembly Microsoft.Identity.Client"
# at Exchange connect. Get-TPModuleHealth already flags this at run time; there
# is no point in this installer creating the condition it will later warn about.
#
# Get-TPModuleInstallScope.ps1 makes this decision (AllUsers, which is never
# OneDrive-redirected, when synced AND elevated; CurrentUser otherwise) so
# Invoke-TPAssessment.ps1's own "Install/fix modules now?" prompt reaches the
# same conclusion — that prompt previously hardcoded CurrentUser with no
# OneDrive check at all, silently recreating the exact condition this
# installer exists to avoid.
. (Join-Path $PSScriptRoot 'Lib/Get-TPModuleInstallScope.ps1')
. (Join-Path $PSScriptRoot 'Lib/Invoke-TPPython.ps1')
$scopeInfo    = Get-TPModuleInstallScope
$installScope = $scopeInfo.Scope

if ($scopeInfo.UserPathIsSynced) {
    Write-Host "  [!] Your PowerShell module folder is inside OneDrive:" -ForegroundColor Yellow
    Write-Host "      $($scopeInfo.UserModuleDir)" -ForegroundColor DarkYellow
    Write-Host "      OneDrive locks and partially syncs module DLLs, which causes the" -ForegroundColor DarkYellow
    Write-Host "      'Could not load file or assembly Microsoft.Identity.Client' error." -ForegroundColor DarkYellow
    if (-not $scopeInfo.StillSynced) {
        Write-Host "  [+] Elevated session detected — installing to AllUsers instead" -ForegroundColor Green
        Write-Host "      ($env:ProgramFiles\PowerShell\Modules is never OneDrive-synced)." -ForegroundColor DarkGray
    } else {
        Write-Host "  [!] Not elevated, so modules will still install into OneDrive." -ForegroundColor Yellow
        Write-Host "      Fix it with ONE of:" -ForegroundColor Yellow
        Write-Host "        1. Re-run this script from an elevated PowerShell 7 window" -ForegroundColor DarkYellow
        Write-Host "           (installs to AllUsers, outside OneDrive)." -ForegroundColor DarkYellow
        Write-Host "        2. OneDrive > Settings > Sync and back up > Manage backup —" -ForegroundColor DarkYellow
        Write-Host "           turn OFF backup for Documents, then move" -ForegroundColor DarkYellow
        Write-Host "           <OneDrive>\Documents\PowerShell back to $HOME\Documents\PowerShell." -ForegroundColor DarkYellow
        Write-Host "        3. Right-click the PowerShell folder in OneDrive >" -ForegroundColor DarkYellow
        Write-Host "           'Always keep on this device' (mitigates, does not remove the lock)." -ForegroundColor DarkYellow
    }
} else {
    Write-Host "  [+] Module path is not OneDrive-synced: $($scopeInfo.UserModuleDir)" -ForegroundColor Green
}
Write-Host ""

$psVer    = $PSVersionTable.PSVersion
$exoFloor = Get-TPExoModuleFloor
if (-not $exoFloor.Supported) {
    Write-Host "  [!] $($exoFloor.Reason)" -ForegroundColor Red
}
if ($exoFloor.StoreBuild) {
    Write-Host "  [!] This is the Microsoft Store build of PowerShell (`$PSHOME is under WindowsApps)." -ForegroundColor Yellow
    Write-Host "      The Exchange Online module has failed to import from it. Install the MSI build:" -ForegroundColor Yellow
    Write-Host "      winget install --id Microsoft.PowerShell --source winget   (then use 'PowerShell 7 (x64)' from the Start menu)" -ForegroundColor DarkYellow
}
$moduleSpecs = @(
    @{ Name='Microsoft.Graph.Authentication'; MinVersion='2.0.0';        PinVersion=$null; MaxVersion=$null          }
    @{ Name='ExchangeOnlineManagement';       MinVersion=$exoFloor.Min;  PinVersion=$null; MaxVersion=$exoFloor.Max }
    @{ Name='MicrosoftTeams';                 MinVersion='5.0.0';  PinVersion=$null; MaxVersion=$null   }
)

foreach ($spec in $moduleSpecs) {
    $name = $spec.Name
    $installed = Get-Module -ListAvailable -Name $name -ErrorAction SilentlyContinue |
        Sort-Object Version -Descending | Select-Object -First 1

    if ($spec.PinVersion) {
        # Pin to a specific known-good version
        $target = [version]$spec.PinVersion
        if (-not $installed) {
            Write-Host "  [*] Installing $name $target..." -ForegroundColor Yellow
            try {
                Install-PSResource -Name $name -Version $spec.PinVersion -TrustRepository -Scope $installScope -Reinstall -ErrorAction Stop
                Write-Host "  [+] $name $target installed" -ForegroundColor Green
            } catch {
                Write-Host "  [!] Install failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        } elseif ($installed.Version -ne $target) {
            $current = $installed.Version
            Write-Host "  [!] $name $current installed — recommended: $target" -ForegroundColor Yellow
            if ($current -gt $target) {
                Write-Host "      Version $current has the WAM broker crash bug." -ForegroundColor Yellow
                Write-Host "      Downgrading to $target..." -ForegroundColor Yellow
                try {
                    Uninstall-PSResource -Name $name -ErrorAction SilentlyContinue
                    Install-PSResource -Name $name -Version $spec.PinVersion -TrustRepository -Scope $installScope -Reinstall -ErrorAction Stop
                    Write-Host "  [+] $name downgraded to $target" -ForegroundColor Green
                } catch {
                    Write-Host "  [!] Downgrade failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            } else {
                Write-Host "      Installing recommended version $target..." -ForegroundColor Yellow
                try {
                    Install-PSResource -Name $name -Version $spec.PinVersion -TrustRepository -Scope $installScope -Reinstall -ErrorAction Stop
                    Write-Host "  [+] $name $target installed" -ForegroundColor Green
                } catch {
                    Write-Host "  [!] Install failed: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        } else {
            Write-Host "  [+] $name $current — OK (pinned)" -ForegroundColor Green
        }
    } else {
        # Any version meeting minimum is fine -- but "fine" is about the version
        # NUMBER only. This branch inspects the newest installed version alone,
        # so a second, older copy sitting beside it passed as OK and was left in
        # place. For a MSAL carrier that duplicate is the assembly conflict, and
        # the preflight was sending operators here to fix exactly it.
        $min = [version]$spec.MinVersion
        $max = $spec.MaxVersion
        if ($max -and [version]$max -lt $min) {
            Write-Host "  [!] $name $min or later cannot be installed on PowerShell $psVer; skipped." -ForegroundColor Red
            continue
        }
        if ($installed -and $max -and $installed.Version -gt [version]$max) {
            Write-Host "  [!] $name $($installed.Version) is newer than PowerShell $psVer supports (up to $max). Upgrade PowerShell, or install a version in [$min,$max]." -ForegroundColor Yellow
        }
        if ($installed -and $installed.Version -lt $min -and $name -eq 'ExchangeOnlineManagement') {
            Write-Host "  [!] $name $($installed.Version) is below the floor for PowerShell $psVer ($min). $($exoFloor.Reason)" -ForegroundColor Yellow
        }
        if (-not $installed -or $installed.Version -lt $min -or $Force) {
            $range = if ($max) { "[$min,$max]" } else { "[$min,)" }
            Write-Host "  [*] Installing $name $range..." -ForegroundColor Yellow
            try {
                Install-PSResource -Name $name -Version $range -TrustRepository -Scope $installScope -ErrorAction Stop
                $newest = Get-Module -ListAvailable -Name $name | Sort-Object Version -Descending | Select-Object -First 1
                Write-Host "  [+] $name $($newest.Version) installed" -ForegroundColor Green
            } catch {
                Write-Host "  [!] Install failed: $($_.Exception.Message)" -ForegroundColor Red
            }
        } else {
            Write-Host "  [+] $name $($installed.Version) — OK" -ForegroundColor Green
        }
    }
}

# ── Duplicate MSAL-carrier versions ──────────────────────────────────────────
# The loop above reconciles version NUMBERS. It does not remove a second copy
# living beside the one it approved, and that duplicate is what makes which
# Microsoft.Identity.Client wins nondeterministic. Repair-TPModuleHealth is the
# one place that removes it, and it asks before it does.
Write-Host ""
Write-Host "[-] Checking for duplicate MSAL carrier versions..." -ForegroundColor Cyan
try {
    $repairLib = Join-Path $PSScriptRoot 'Lib/Repair-TPModuleHealth.ps1'
    $healthLib = Join-Path $PSScriptRoot 'Lib/Get-TPModuleHealth.ps1'
    if ((Test-Path -LiteralPath $repairLib) -and (Test-Path -LiteralPath $healthLib)) {
        . $healthLib
        . $repairLib
        $plan = Repair-TPModuleHealth -PlanOnly
        if (@($plan.Planned).Count -eq 0) {
            Write-Host "  [+] No duplicate versions of the MSAL carriers — OK" -ForegroundColor Green
        } else {
            foreach ($item in $plan.Planned) {
                Write-Host ("  [!] {0}: remove {1}, keep {2}" -f $item.Name, $item.Version, $item.Keeping) -ForegroundColor Yellow
            }
            # -Force means the operator already opted into changes on this run.
            # Without it, ask -- removing modules is not a side effect anyone
            # should get by accident from a prerequisites check.
            if ($Force) {
                $result = Repair-TPModuleHealth -Confirm:$false
                foreach ($r in $result.Removed) {
                    Write-Host ("  [+] Removed {0} {1}" -f $r.Name, $r.Version) -ForegroundColor Green
                }
                foreach ($f in $result.Failed) {
                    Write-Host ("  [!] Could not remove {0} {1}: {2}" -f $f.Name, $f.Version, $f.Reason) -ForegroundColor Red
                }
                if ($result.RestartRequired) {
                    Write-Host "  [!] MSAL is already loaded in THIS session — start a new PowerShell window before running an assessment." -ForegroundColor Yellow
                }
            } else {
                Write-Host "      Run 'Repair-TPModuleHealth' to remove them, or re-run this script with -Force." -ForegroundColor DarkYellow
            }
        }
    }
} catch {
    Write-Host "  [!] Duplicate check skipped: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

# ── SharePoint module (optional — only if not using Graph-only SharePoint collection) ─
Write-Host ""
Write-Host "[5/6] Optional: SharePoint PowerShell..." -ForegroundColor Cyan
$spo = Get-Module -ListAvailable -Name 'Microsoft.Online.SharePoint.PowerShell' -ErrorAction SilentlyContinue |
    Sort-Object Version -Descending | Select-Object -First 1
if ($spo) {
    Write-Host "  [+] SharePoint module $($spo.Version) — present" -ForegroundColor Green
} else {
    Write-Host "  [-] SharePoint module not installed — assessment uses Graph API instead. OK." -ForegroundColor DarkGray
}

# Power Platform (PPL-*) needs no module: the assessment signs in to the
# Power Platform admin API in-process and calls its REST endpoints.
Write-Host "  [+] Power Platform — no module needed (in-process sign-in to the admin API)" -ForegroundColor Green

# ── Python + openpyxl for XLSX compliance matrix ─────────────────────────────
Write-Host ""
Write-Host "[6/6] Optional: Python + openpyxl (for XLSX compliance matrix)..." -ForegroundColor Cyan
if ($SkipPython) {
    Write-Host "  [-] Skipped (XLSX matrix will not be generated)" -ForegroundColor DarkGray
} else {
    $pythonCmd = $null
    foreach ($py in @('python','python3','py')) {
        if (Get-Command $py -ErrorAction SilentlyContinue) { $pythonCmd = $py; break }
    }
    if ($pythonCmd) {
        $ver = & $pythonCmd --version 2>&1
        Write-Host "  [+] Python found: $ver" -ForegroundColor Green
        # Check openpyxl
        $openpyxlOk = $false
        try {
            if (Test-TPPythonModule -Python $pythonCmd -Module 'openpyxl') { $openpyxlOk = $true }
        } catch { }
        $openpyxlPin = '3.1.5'
        if ($openpyxlOk) {
            # The pin applies to an existing install too: a different version is
            # replaced, so the publishers run against the version the tool was tested with.
            $have = [string](@(Invoke-TPPython -Python $pythonCmd -Script "import openpyxl; print(openpyxl.__version__)") | Select-Object -Last 1)
            if ($have.Trim() -ne $openpyxlPin) {
                Write-Host "  [*] openpyxl $($have.Trim()) found; installing the pinned $openpyxlPin..." -ForegroundColor Yellow
                $openpyxlOk = $false
            }
        }
        if ($openpyxlOk) {
            Write-Host "  [+] openpyxl $openpyxlPin installed — XLSX matrix enabled" -ForegroundColor Green
        } else {
            Write-Host "  [*] Installing openpyxl..." -ForegroundColor Yellow
            try {
                # pip runs through the same helper as every other Python call: the
                # current directory is off sys.path (no planted pip.py) and the user
                # site stays, so an unelevated install can fall back to --user.
                $null = Invoke-TPPython -Python $pythonCmd -Script "import sys, runpy; sys.argv = ['pip', 'install', 'openpyxl==$openpyxlPin', '--quiet']; runpy.run_module('pip', run_name='__main__', alter_sys=True)"
                if ($LASTEXITCODE -eq 0 -and (Test-TPPythonModule -Python $pythonCmd -Module 'openpyxl')) {
                    Write-Host "  [+] openpyxl installed" -ForegroundColor Green
                } elseif ($LASTEXITCODE -eq 0) {
                    Write-Host "  [!] pip reported success but openpyxl still cannot be imported the way the tool imports it (XLSX matrix will be skipped at runtime)" -ForegroundColor Yellow
                } else {
                    Write-Host "  [!] openpyxl install failed (XLSX matrix will be skipped at runtime)" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "  [!] $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  [-] Python not found. Install from python.org or 'winget install Python.Python.3.12'" -ForegroundColor Yellow
        Write-Host "      XLSX compliance matrix will be skipped at runtime (other reports still work)" -ForegroundColor DarkGray
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host " Setup complete. Run:"                                            -ForegroundColor Cyan
Write-Host "   .\Invoke-TPAssessment.ps1 -UserPrincipalName admin@client"    -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
