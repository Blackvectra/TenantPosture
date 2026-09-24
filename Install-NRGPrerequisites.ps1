#Requires -Version 7.0
#
# Install-NRGPrerequisites.ps1  (v4.5.5)
#
# One-shot setup for a fresh machine. Run this once after extracting the tool.
# Checks and installs everything NRG-Assessment needs to run cleanly.
#
# Usage:
#   .\Install-NRGPrerequisites.ps1
#   .\Install-NRGPrerequisites.ps1 -SkipPython     # skip Python/openpyxl for XLSX
#   .\Install-NRGPrerequisites.ps1 -Force          # reinstall everything
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
Write-Host " NRG-Assessment Prerequisites Installer"                          -ForegroundColor Cyan
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
if ($policy -in @('Restricted','AllSigned','Undefined')) {
    Write-Host "  [*] Setting CurrentUser policy to RemoteSigned..." -ForegroundColor Yellow
    try {
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
        Write-Host "  [+] Execution policy set" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Failed: $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Host "  [+] Policy is $policy — OK" -ForegroundColor Green
}

# ── Unblock files ────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "[3/6] Unblocking files (Zone.Identifier from downloads)..." -ForegroundColor Cyan
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
try {
    Get-ChildItem -Path $scriptDir -Recurse -ErrorAction SilentlyContinue | Unblock-File -ErrorAction SilentlyContinue
    Write-Host "  [+] Files unblocked" -ForegroundColor Green
} catch {
    Write-Host "  [!] Unblock failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# ── PowerShell modules ───────────────────────────────────────────────────────
Write-Host ""
Write-Host "[4/6] Checking PowerShell modules..." -ForegroundColor Cyan

# Specific version requirements:
# - EOM pinned to 3.2.0 because 3.4.0 has the WAM broker NullReferenceException
# - Graph.Authentication 2.x for modern MSAL flow
# - Teams 5.x+ for device code auth
# ── Module install scope: avoid OneDrive-synced paths ────────────────────────
# The CurrentUser module directory lives under Documents, and on machines with
# Known Folder Move enabled Documents is redirected into OneDrive. OneDrive then
# syncs, locks and sometimes partially materialises the module DLLs, which is a
# documented cause of "Could not load file or assembly Microsoft.Identity.Client"
# at Exchange connect. Get-NRGModuleHealth already flags this at run time; there
# is no point in this installer creating the condition it will later warn about.
#
# Get-NRGModuleInstallScope.ps1 makes this decision (AllUsers, which is never
# OneDrive-redirected, when synced AND elevated; CurrentUser otherwise) so
# Invoke-NRGAssessment.ps1's own "Install/fix modules now?" prompt reaches the
# same conclusion — that prompt previously hardcoded CurrentUser with no
# OneDrive check at all, silently recreating the exact condition this
# installer exists to avoid.
. (Join-Path $PSScriptRoot 'Lib/Get-NRGModuleInstallScope.ps1')
$scopeInfo    = Get-NRGModuleInstallScope
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

$moduleSpecs = @(
    @{ Name='Microsoft.Graph.Authentication'; MinVersion='2.0.0';  PinVersion=$null   }
    @{ Name='ExchangeOnlineManagement';       MinVersion='3.0.0';  PinVersion='3.2.0' }
    @{ Name='MicrosoftTeams';                 MinVersion='5.0.0';  PinVersion=$null   }
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
        if (-not $installed -or $installed.Version -lt $min -or $Force) {
            Write-Host "  [*] Installing $name (min $min)..." -ForegroundColor Yellow
            try {
                Install-PSResource -Name $name -TrustRepository -Scope $installScope -ErrorAction Stop
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
# Microsoft.Identity.Client wins nondeterministic. Repair-NRGModuleHealth is the
# one place that removes it, and it asks before it does.
Write-Host ""
Write-Host "[-] Checking for duplicate MSAL carrier versions..." -ForegroundColor Cyan
try {
    $repairLib = Join-Path $PSScriptRoot 'Lib/Repair-NRGModuleHealth.ps1'
    $healthLib = Join-Path $PSScriptRoot 'Lib/Get-NRGModuleHealth.ps1'
    if ((Test-Path -LiteralPath $repairLib) -and (Test-Path -LiteralPath $healthLib)) {
        . $healthLib
        . $repairLib
        $plan = Repair-NRGModuleHealth -PlanOnly
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
                $result = Repair-NRGModuleHealth -Confirm:$false
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
                Write-Host "      Run 'Repair-NRGModuleHealth' to remove them, or re-run this script with -Force." -ForegroundColor DarkYellow
            }
        }
    }
} catch {
    Write-Host "  [!] Duplicate check skipped: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

# ── SharePoint module (optional — only if not using Graph-only SharePoint collection) ─
Write-Host ""
Write-Host "[5/6] Optional: SharePoint and Power Platform PowerShell..." -ForegroundColor Cyan
$spo = Get-Module -ListAvailable -Name 'Microsoft.Online.SharePoint.PowerShell' -ErrorAction SilentlyContinue |
    Sort-Object Version -Descending | Select-Object -First 1
if ($spo) {
    Write-Host "  [+] SharePoint module $($spo.Version) — present" -ForegroundColor Green
} else {
    Write-Host "  [-] SharePoint module not installed — assessment uses Graph API instead. OK." -ForegroundColor DarkGray
}

# Power Platform (PPL-*): Microsoft.PowerApps.Administration.PowerShell is a
# Windows PowerShell 5.1 module (.NET Framework), so the assessment runs it in
# a powershell.exe child process. It must be installed for WINDOWS PowerShell,
# not for this pwsh. Checked, not installed here: CurrentUser scope for
# Windows PowerShell is Documents\WindowsPowerShell, which OneDrive may sync.
if ($IsWindows -and (Get-Command 'powershell.exe' -CommandType Application -ErrorAction SilentlyContinue)) {
    $ppl = & powershell.exe -NoProfile -Command '[bool](Get-Module -ListAvailable -Name Microsoft.PowerApps.Administration.PowerShell)' 2>$null
    if ("$ppl" -match 'True') {
        Write-Host "  [+] Power Platform admin module (Windows PowerShell) — present" -ForegroundColor Green
    } else {
        Write-Host "  [-] Power Platform admin module not installed for Windows PowerShell — PPL controls will be 'not assessed'." -ForegroundColor Yellow
        Write-Host "      To enable them, from a Windows PowerShell 5.1 prompt (not pwsh), run as administrator:" -ForegroundColor DarkGray
        Write-Host "        Install-Module Microsoft.PowerApps.Administration.PowerShell -Scope AllUsers" -ForegroundColor DarkGray
    }
} else {
    Write-Host "  [-] Power Platform controls need Windows PowerShell 5.1 (Windows only) — they will be 'not assessed' here." -ForegroundColor DarkGray
}

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
            $null = & $pythonCmd -c 'import openpyxl' 2>&1
            if ($LASTEXITCODE -eq 0) { $openpyxlOk = $true }
        } catch { }
        if ($openpyxlOk) {
            Write-Host "  [+] openpyxl installed — XLSX matrix enabled" -ForegroundColor Green
        } else {
            Write-Host "  [*] Installing openpyxl..." -ForegroundColor Yellow
            try {
                & $pythonCmd -m pip install openpyxl --quiet
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "  [+] openpyxl installed" -ForegroundColor Green
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
Write-Host "   .\Invoke-NRGAssessment.ps1 -UserPrincipalName admin@client"    -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
