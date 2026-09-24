#Requires -Version 7.0
#
# Register-NRGTenantApp.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# ONE-TIME tenant onboarding for unattended (app-only) assessment.
#
# Problem this solves:
#   Interactive / device-code auth gets blocked by Conditional Access
#   "Authentication Flows" policies (error AADSTS530036), and requires an
#   operator to be present at the keyboard for every scan. App-only auth with
#   a certificate bypasses both: a registered enterprise app holds read-only
#   Graph permissions, and the scanner authenticates as that app with a cert.
#   No device codes, no CA flow blocks, reproducible from Task Scheduler.
#
# What this function does (all writes are -WhatIf/-Confirm gated):
#   1. Generates a self-signed client-auth certificate in Cert:\CurrentUser\My.
#   2. Resolves the read-only Graph application-permission role IDs AT RUNTIME
#      from the target tenant's own Microsoft Graph service principal — no GUID
#      is ever hardcoded, so the permission set can never be silently wrong.
#   3. Creates an app registration (NRG-Assessment-Scanner by default) with
#      the cert as its credential and those application permissions requested.
#   4. Creates the service principal for the app.
#   5. Either grants admin consent programmatically (-GrantConsent, requires the
#      operator to be Global Administrator or Privileged Role Administrator) OR
#      emits the admin-consent URL to hand to a Global Admin (the default —
#      works regardless of the operator's role).
#   6. Records ClientId / TenantId / CertThumbprint in Config/clients.json so
#      future scans run app-only automatically.
#
# PREREQUISITE: an interactive Graph connection with WRITE scopes — this is a
#   privileged one-time operation, distinct from the read-only scopes the
#   scanner itself uses. Connect first with:
#       Connect-MgGraph -Scopes 'Application.ReadWrite.All','AppRoleAssignment.ReadWrite.All','Directory.Read.All'
#   (the orchestrator does this for you when you pass -RegisterApp).
#
# Read-only invariant: the APP this creates is read-only (all requested Graph
#   permissions are *.Read.All). This onboarding function itself writes to the
#   directory (creates an app) — that is the one sanctioned exception, isolated
#   here and gated behind -RegisterApp + ShouldProcess. It never touches tenant
#   security configuration.
#
# Graph cmdlets used: Get-MgServicePrincipal, New-MgApplication,
#   New-MgServicePrincipal, New-MgServicePrincipalAppRoleAssignment, Get-MgContext.

function Register-NRGTenantApp {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
    param(
        # The customer's primary or .onmicrosoft.com domain. Used for the
        # clients.json record and the EXO -Organization value.
        [Parameter(Mandatory)]
        [ValidatePattern('^[a-zA-Z0-9][a-zA-Z0-9.-]*\.[a-zA-Z]{2,}$')]
        [string] $TenantDomain,

        # Display name of the app registration the customer will see in their
        # Entra portal. Pulled from branding when available so it is consistent
        # and recognizable across every tenant you onboard.
        [Parameter()]
        [string] $DisplayName,

        # Certificate lifetime. App-only certs can be long-lived since you
        # control them, but a 2-year default forces a rotation discipline.
        [Parameter()]
        [ValidateRange(1, 5)]
        [int] $CertValidYears = 2,

        # Programmatically grant admin consent. Requires the signed-in operator
        # to be Global Administrator or Privileged Role Administrator in the
        # target tenant. When omitted (default), the function instead prints an
        # admin-consent URL that any Global Admin can open — this works even if
        # the operator's role cannot grant consent directly.
        [Parameter()]
        [switch] $GrantConsent,

        # Path to clients.json to update with the onboarding record.
        [Parameter()]
        [ValidateScript({
            if ($_ -match '\.\.[\\/]') { throw 'Path traversal not allowed in ClientsFile.' }
            return $true
        })]
        [string] $ClientsFile = (Join-Path $script:NRGModuleRoot 'Config\clients.json')
    )

    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    # ── Platform precondition ───────────────────────────────────────────────
    # New-SelfSignedCertificate and the Cert:\CurrentUser\My provider are
    # Windows-only. If we discover this mid-flight (after creating the app
    # registration) we'd leave the customer tenant in a half-onboarded state:
    # the app exists, has no cert, and clients.json has no record. Fail at the
    # top, before any write.
    #
    # PS7's `$IsWindows` is authoritative — the older `-or $env:OS = Windows_NT`
    # fallback was over-permissive (WSL or any shell with that env var inherited
    # bypassed the guard). #Requires -Version 7.0 at the file head guarantees
    # `$IsWindows` exists; no PS5.1 reach-through is possible.
    #
    # Skip the throw under -WhatIf so operators can preview from non-Windows
    # dev machines. -WhatIf is read-only by SupportsShouldProcess contract.
    if (-not $IsWindows -and -not $WhatIfPreference) {
        throw 'Register-NRGTenantApp requires Windows: it uses New-SelfSignedCertificate and the Cert:\ provider, which only ship in PowerShell on Windows. Run this from a Windows workstation (or use -WhatIf to preview from any host).'
    }

    # ── clients.json must be readable BEFORE any tenant write ────────────────
    # The record is written after the app registration and service principal
    # are created; a file that fails to parse at that point would strand an
    # orphaned app in the customer tenant. Check it up front.
    if (Test-Path -LiteralPath $ClientsFile) {
        try { $null = Get-Content -LiteralPath $ClientsFile -Raw -Encoding utf8 | ConvertFrom-Json -ErrorAction Stop }
        catch { throw "clients.json ($ClientsFile) is not valid JSON; nothing was created in the tenant. Fix the file, then re-run. ($($_.Exception.Message))" }
    }

    # ── Resolve display name from branding if not supplied ───────────────────
    if (-not $DisplayName) {
        $brandCo = if ($script:NRGBrand -and $script:NRGBrand['CompanyName']) { $script:NRGBrand['CompanyName'] } else { 'NRG' }
        $DisplayName = "$brandCo-Assessment-Scanner"
    }

    # ── Preconditions: Graph connected with write scopes ─────────────────────
    $ctx = $null
    try { $ctx = Get-MgContext -ErrorAction Stop } catch { }
    if (-not $ctx) {
        throw 'No Microsoft Graph context. Connect first with: Connect-MgGraph -Scopes Application.ReadWrite.All,AppRoleAssignment.ReadWrite.All,Directory.Read.All'
    }
    $haveScopes = @($ctx.Scopes)
    $needWrite  = 'Application.ReadWrite.All'
    if ($haveScopes -notcontains $needWrite) {
        Write-Warning "Current Graph context is missing '$needWrite'. App creation will likely fail with Authorization_RequestDenied. Reconnect with the write scopes listed in this function's header."
    }

    # ── Tenant context binding (ATT&CK T1078.003 / T1098 hardening) ──────────
    # Pen-test finding: previously this function trusted the currently-
    # connected Get-MgContext.TenantId without verifying it matches the
    # supplied -TenantDomain. An operator who left a prior tenant connected
    # (or a malicious local hook intercepting -TenantDomain) could end up
    # registering the customer's app registration in the WRONG tenant, with
    # clients.json then mapping the wrong domain → wrong tenant for every
    # future scan. Resolve the domain to its TenantId via the well-known
    # OpenID Configuration endpoint (anonymous, read-only) and fail loudly
    # on mismatch before any tenant write.
    try {
        $oidcUrl = "https://login.microsoftonline.com/$([uri]::EscapeDataString($TenantDomain))/.well-known/openid-configuration"
        $oidcResp = Invoke-RestMethod -Uri $oidcUrl -Method GET -TimeoutSec 15 -ErrorAction Stop
        $expectedTenantId = $null
        if ($oidcResp.issuer -match '/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/') {
            $expectedTenantId = $Matches[1]
        }
        if (-not $expectedTenantId) {
            throw "Could not parse a TenantId from the issuer for '$TenantDomain' (issuer='$($oidcResp.issuer)')."
        }
        if ([string]$ctx.TenantId -ne [string]$expectedTenantId) {
            throw "Tenant-context mismatch: -TenantDomain '$TenantDomain' resolves to TenantId $expectedTenantId, but the connected Graph context is $($ctx.TenantId). REFUSING to onboard the wrong tenant. Reconnect to the correct tenant: Disconnect-MgGraph; Connect-MgGraph -TenantId $expectedTenantId -Scopes Application.ReadWrite.All,AppRoleAssignment.ReadWrite.All,Directory.Read.All"
        }
        Write-Host "  [+] Tenant binding verified: $TenantDomain -> $expectedTenantId matches connected context" -ForegroundColor Green
    } catch [System.Net.WebException], [System.Net.Http.HttpRequestException] {
        throw "Cannot verify tenant binding (network failure reaching login.microsoftonline.com for '$TenantDomain'): $($_.Exception.Message). Refusing to onboard without a verified tenant match."
    }

    Write-Host ''
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host " Tenant onboarding — app-only assessment registration"          -ForegroundColor Cyan
    Write-Host '================================================================' -ForegroundColor Cyan
    Write-Host "  Tenant:    $TenantDomain"
    Write-Host "  App name:  $DisplayName"
    Write-Host "  Cert:      Cert:\CurrentUser\My (valid $CertValidYears years)"
    Write-Host "  Consent:   $(if ($GrantConsent) { 'auto-grant (operator must be Global Admin)' } else { 'emit URL for a Global Admin' })"
    Write-Host ''

    # ── Resolve the Microsoft Graph service principal in THIS tenant ─────────
    # Graph's well-known appId is constant across all tenants; its SP object id
    # and app-role GUIDs are per-tenant, so we resolve them live. This is what
    # makes the permission mapping correct-by-construction.
    $graphAppId = '00000003-0000-0000-c000-000000000000'
    Write-Host '  [*] Resolving Microsoft Graph application roles in tenant...' -ForegroundColor Cyan
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'" -ErrorAction Stop
    if (-not $graphSp) { throw "Could not resolve the Microsoft Graph service principal (appId $graphAppId) in this tenant." }

    # The read-only scopes the scanner needs, as APPLICATION permissions. These
    # names are matched against $graphSp.AppRoles[].Value where the role allows
    # application member type. Any name with no application-permission
    # equivalent is reported and skipped (it simply won't be granted app-only;
    # the affected workload degrades to NotApplicable in app-only mode).
    $wantedAppPerms = @(
        'User.Read.All','Group.Read.All','Directory.Read.All',
        'Policy.Read.All','AuditLog.Read.All','Application.Read.All',
        'RoleManagement.Read.Directory','SecurityEvents.Read.All',
        'IdentityRiskyUser.Read.All','Reports.Read.All',
        'Organization.Read.All','Sites.Read.All',
        'DeviceManagementConfiguration.Read.All',
        'DeviceManagementApps.Read.All',
        'DeviceManagementManagedDevices.Read.All',
        'DeviceManagementServiceConfig.Read.All',
        'UserAuthenticationMethod.Read.All',
        'SharePointTenantSettings.Read.All',
        'PrivilegedAccess.Read.AzureAD',
        'TeamSettings.Read.All',
        'Policy.Read.PermissionGrant',
        # Without these three, AAD-11.3 / DEF-4.6 / AAD-8.2 never assess in
        # app-only mode.
        'IdentityRiskyServicePrincipal.Read.All',
        'AttackSimulation.Read.All',
        'AccessReview.Read.All'
    )

    $resolved   = @()
    $unresolved = @()
    foreach ($perm in $wantedAppPerms) {
        $role = $graphSp.AppRoles | Where-Object {
            $_.Value -eq $perm -and $_.AllowedMemberTypes -contains 'Application'
        } | Select-Object -First 1
        if ($role) {
            $resolved += [pscustomobject]@{ Name = $perm; Id = $role.Id }
        } else {
            $unresolved += $perm
        }
    }
    Write-Host ("  [+] Resolved {0} of {1} application permissions." -f $resolved.Count, $wantedAppPerms.Count) -ForegroundColor Green
    if ($unresolved.Count -gt 0) {
        Write-Warning ("These permissions have no application-permission equivalent and will be skipped: {0}" -f ($unresolved -join ', '))
    }
    if ($resolved.Count -eq 0) {
        throw 'No application permissions could be resolved — aborting before any write.'
    }

    # ── Idempotency guard: refuse if an app of this name already exists ──────
    # OData filter escape: a single apostrophe in the value (e.g. "O'Brien
    # Consulting") breaks the filter syntax. The convention is to double it.
    #
    # -ErrorAction Stop (not SilentlyContinue): a throttled or 403 duplicate
    # check must abort the run, not be read as "no existing app" — otherwise a
    # transient Graph error silently creates a second app registration.
    $escapedName = $DisplayName -replace "'", "''"
    try {
        $existing = Get-MgApplication -Filter "displayName eq '$escapedName'" -ErrorAction Stop
    } catch {
        throw "Could not verify whether an app named '$DisplayName' already exists (duplicate-check query failed): $($_.Exception.Message). Refusing to proceed without confirming no duplicate exists."
    }
    if ($existing) {
        Write-Warning "An app named '$DisplayName' already exists (appId $($existing.AppId)). Refusing to create a duplicate. Delete it in Entra or use a different -DisplayName if you intend to re-onboard."
        return
    }

    # ── Generate the client-auth certificate ─────────────────────────────────
    # cA=false + DigitalSignature only: this is an authentication cert, not a CA.
    if (-not $PSCmdlet.ShouldProcess("Cert:\CurrentUser\My", "Generate self-signed client-auth certificate 'CN=$DisplayName'")) {
        Write-Host '  [WhatIf] Would generate certificate, create app registration, and update clients.json.' -ForegroundColor Yellow
        return
    }

    Write-Host '  [*] Generating client-auth certificate...' -ForegroundColor Cyan
    # NonExportable: only the public cert bytes ($cert.RawData, used below for
    # the app's keyCredential) need to leave the store. An exportable private
    # key lets anyone who can read the operator's CurrentUser store export a
    # credential that authenticates app-only — no MFA, no Conditional Access —
    # to every client tenant this cert was registered against.
    $cert = New-SelfSignedCertificate `
        -Subject "CN=$DisplayName" `
        -CertStoreLocation 'Cert:\CurrentUser\My' `
        -KeyExportPolicy NonExportable `
        -KeySpec Signature `
        -KeyUsage DigitalSignature `
        -KeyAlgorithm RSA -KeyLength 2048 `
        -NotAfter (Get-Date).AddYears($CertValidYears) `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.2', '2.5.29.19={text}cA=false')
    Write-Host "  [+] Cert thumbprint: $($cert.Thumbprint)" -ForegroundColor Green

    # ── Build requiredResourceAccess + keyCredentials ────────────────────────
    $resourceAccess = @($resolved | ForEach-Object { @{ Id = $_.Id; Type = 'Role' } })
    $requiredResourceAccess = @(
        @{
            ResourceAppId  = $graphAppId
            ResourceAccess = $resourceAccess
        }
    )

    $keyCredential = @(
        @{
            Type  = 'AsymmetricX509Cert'
            Usage = 'Verify'
            Key   = $cert.RawData          # public cert bytes; private key stays in the store
        }
    )

    # ── Create the application ───────────────────────────────────────────────
    Write-Host '  [*] Creating app registration...' -ForegroundColor Cyan
    $app = New-MgApplication `
        -DisplayName $DisplayName `
        -SignInAudience 'AzureADMyOrg' `
        -RequiredResourceAccess $requiredResourceAccess `
        -KeyCredentials $keyCredential `
        -ErrorAction Stop
    Write-Host "  [+] App created. AppId (ClientId): $($app.AppId)" -ForegroundColor Green

    # ── Create the service principal ─────────────────────────────────────────
    Write-Host '  [*] Creating service principal...' -ForegroundColor Cyan
    $sp = New-MgServicePrincipal -AppId $app.AppId -ErrorAction Stop
    Write-Host "  [+] Service principal object id: $($sp.Id)" -ForegroundColor Green

    # ── Consent ──────────────────────────────────────────────────────────────
    $consentUrl = "https://login.microsoftonline.com/$TenantDomain/adminconsent?client_id=$($app.AppId)"
    if ($GrantConsent) {
        Write-Host '  [*] Granting admin consent (app-role assignments)...' -ForegroundColor Cyan
        $granted = 0
        foreach ($r in $resolved) {
            try {
                New-MgServicePrincipalAppRoleAssignment `
                    -ServicePrincipalId $sp.Id `
                    -PrincipalId $sp.Id `
                    -ResourceId $graphSp.Id `
                    -AppRoleId $r.Id -ErrorAction Stop | Out-Null
                $granted++
            } catch {
                Write-Warning "  Could not grant '$($r.Name)': $($_.Exception.Message)"
            }
        }
        Write-Host ("  [+] Granted {0} of {1} permissions." -f $granted, $resolved.Count) -ForegroundColor Green
        if ($granted -lt $resolved.Count) {
            Write-Host "  [!] Some grants failed — complete consent manually at:" -ForegroundColor Yellow
            Write-Host "      $consentUrl" -ForegroundColor Yellow
        }
    } else {
        Write-Host ''
        Write-Host '  [!] Admin consent required. Send this URL to a Global Administrator' -ForegroundColor Yellow
        Write-Host '      of the customer tenant (they sign in once and click Accept):' -ForegroundColor Yellow
        Write-Host ''
        Write-Host "      $consentUrl" -ForegroundColor Cyan
        Write-Host ''
    }

    # ── Update clients.json ──────────────────────────────────────────────────
    $tenantId = $ctx.TenantId
    Update-NRGClientRecord -ClientsFile $ClientsFile -TenantDomain $TenantDomain `
        -ClientId $app.AppId -TenantId $tenantId -CertThumbprint $cert.Thumbprint

    # ── EXO note: app-only EXO needs one more manual step ────────────────────
    Write-Host '  [i] Exchange Online app-only access needs one manual step in the' -ForegroundColor DarkGray
    Write-Host '      customer tenant: assign the new app the "Global Reader" directory' -ForegroundColor DarkGray
    Write-Host '      role (Entra > Roles > Global Reader > Add assignment > the app).' -ForegroundColor DarkGray
    Write-Host '      Graph-based collectors work as soon as consent is granted; EXO' -ForegroundColor DarkGray
    Write-Host '      collectors work once the role is assigned.' -ForegroundColor DarkGray

    Write-Host ''
    Write-Host '  [+] Onboarding complete. Run an unattended scan with:' -ForegroundColor Green
    Write-Host "      .\Invoke-NRGAssessment.ps1 -TenantDomain $TenantDomain" -ForegroundColor Cyan
    Write-Host '      (the orchestrator reads ClientId + CertThumbprint from clients.json)' -ForegroundColor DarkGray
    Write-Host ''

    return [pscustomobject]@{
        DisplayName    = $DisplayName
        ClientId       = $app.AppId
        TenantId       = $tenantId
        TenantDomain   = $TenantDomain
        CertThumbprint = $cert.Thumbprint
        PermissionsRequested = $resolved.Count
        ConsentUrl     = $consentUrl
        ConsentGranted = [bool]$GrantConsent
    }
}

# ── Helper: upsert the onboarding record into clients.json ───────────────────
function Update-NRGClientRecord {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string] $ClientsFile,
        [Parameter(Mandatory)][string] $TenantDomain,
        [Parameter(Mandatory)][string] $ClientId,
        [Parameter(Mandatory)][string] $TenantId,
        [Parameter(Mandatory)][string] $CertThumbprint
    )
    Set-StrictMode -Version Latest

    # The shipped clients.json (and every other reader — Invoke-NRGBatchAssessment.ps1,
    # Start-NRGWebServer.ps1) is a { "clients": [...] } wrapper object, not a
    # bare array. Read through Get-NRGObjectField (never bare dot-access under
    # StrictMode) and fall back to treating the parsed value itself as the
    # list only for a legacy bare-array file.
    $clients = @()
    if (Test-Path -LiteralPath $ClientsFile) {
        try {
            $raw = Get-Content -LiteralPath $ClientsFile -Raw -Encoding utf8 | ConvertFrom-Json
            $clientsProp = Get-NRGObjectField -Item $raw -Key 'clients' -Default $null
            if ($null -ne $clientsProp) {
                $clients = @($clientsProp)
            } elseif ($null -ne $raw) {
                $clients = @($raw)
            }
        } catch {
            # Never overwrite: a fresh file here would hold ONLY this tenant and
            # silently drop every other client's record.
            throw "clients.json could not be parsed, so it was left untouched: $($_.Exception.Message). Fix the file, then re-run."
        }
    }

    $now = (Get-Date).ToString('o')
    $existing = $clients | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'TenantDomain' -Default '') -eq $TenantDomain } | Select-Object -First 1
    if ($existing) {
        $existing | Add-Member -NotePropertyName ClientId       -NotePropertyValue $ClientId       -Force
        $existing | Add-Member -NotePropertyName TenantId       -NotePropertyValue $TenantId       -Force
        $existing | Add-Member -NotePropertyName CertThumbprint -NotePropertyValue $CertThumbprint -Force
        $existing | Add-Member -NotePropertyName AuthMode       -NotePropertyValue 'AppOnly'        -Force
        $existing | Add-Member -NotePropertyName OnboardedAt    -NotePropertyValue $now            -Force
    } else {
        $clients += [pscustomobject][ordered]@{
            ClientName     = $TenantDomain
            TenantDomain   = $TenantDomain
            TenantId       = $TenantId
            ClientId       = $ClientId
            CertThumbprint = $CertThumbprint
            AuthMode       = 'AppOnly'
            OnboardedAt    = $now
            Active         = $true
        }
    }

    if ($PSCmdlet.ShouldProcess($ClientsFile, 'Write onboarding record')) {
        $dir = Split-Path -Parent $ClientsFile
        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            [void][System.IO.Directory]::CreateDirectory($dir)
        }
        # Always write back the { "clients": [...] } wrapper shape — the shape
        # every other reader in this codebase expects — even if the file that
        # was read was the legacy bare-array form.
        [ordered]@{ clients = $clients } | ConvertTo-Json -Depth 8 | Out-File -LiteralPath $ClientsFile -Encoding utf8
        Write-Host "  [+] Recorded onboarding in $ClientsFile" -ForegroundColor Green
        # clients.json now holds tenant ClientIds + cert thumbprints — restrict ACL.
        if (Get-Command Set-NRGSensitiveFileAcl -ErrorAction SilentlyContinue) {
            try { Set-NRGSensitiveFileAcl -Path $ClientsFile } catch { }
        }
    }
}
