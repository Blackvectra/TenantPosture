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
Write-Host "   .\Invoke-TPAssessment.ps1 -UserPrincipalName admin@client"    -ForegroundColor White
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""
