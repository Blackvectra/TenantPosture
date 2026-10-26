#Requires -Version 7.0

# Safe property accessor — prevents throw on null nested object access

# ── Collection Guard ────────────────────────────────────────────────────────
# Returns $true if AAD data was successfully collected
function Test-TPAADDataAvailable {
    $ca   = Get-TPRawData -Key 'AAD-CAPolicies'
    $auth = Get-TPRawData -Key 'AAD-AuthPolicies'
    $usr  = Get-TPRawData -Key 'AAD-Users'
    # 'AAD-DirectoryRoles' is the key Invoke-TPCollectAADRoles actually writes.
    # This previously read 'AAD-Roles', which no collector sets, so the clause
    # below was always false — the helper could not see role data even when it
    # had been collected successfully.
    $rol  = Get-TPRawData -Key 'AAD-DirectoryRoles'
    # At least one AAD collector must have succeeded
    return ($ca   -and $ca.Success)   -or
           ($auth -and $auth.Success) -or
           ($usr  -and $usr.Success)  -or
           ($rol  -and $rol.Success)
}


# Returns $true only when the named AAD-DirectoryRoles section was collected.
#
# Invoke-TPCollectAADRoles sets Success = (assignments -OR- eligibility), so a
# tenant whose permanent-assignment read failed while eligibility succeeded
# still reports Success = $true with RoleAssignments and PrivRoles empty. Every
# real tenant has at least one privileged assignment, so an empty list there is
# a failed read — never a clean tenant — and reporting "no guest admins" or "no
# synced admins" from it is a false pass on the tenant-takeover controls.
#
# Absent SectionStatus (older captured data) is treated as collected so a
# replayed results JSON keeps its previous behavior.
function Test-TPRoleSectionCollected {
    [CmdletBinding()]
    param(
        [AllowNull()] $Roles,
        [Parameter(Mandatory)] [string] $Section
    )
    $status = Get-TPNestedProperty -Object $Roles -Path "Data.SectionStatus.$Section" -Default $null
    if ($null -eq $status) { return $true }
    return ($status -eq 'Collected')
}

# Returns $true when every RoleAssignment's RoleDefinitionName resolved to a
# human-readable name, $false if any degraded to the raw role-template GUID.
#
# Invoke-TPCollectAADRoles builds $roleMap from a SEPARATE roleDefinitions
# sub-query; when that query fails, the catch only registers an exception (no
# SectionStatus flag for it), RoleDefinitionName falls back to the bare GUID
# for every assignment, and IsPriv is computed against that GUID so it never
# matches a role name — every name-based privileged-role filter then matches
# nothing while RoleAssignments itself still reports 'Collected', because the
# assignments read succeeded. The GUID-shaped name is the only evaluator-side
# signal of that failure without a collector change.
function Test-TPRoleNamesResolved {
    [CmdletBinding()]
    param([AllowNull()] $Assignments)
    # Service-principal rows are excluded: Microsoft first-party apps (e.g.
    # "Microsoft Office 365 Portal") hold hidden internal roles that the
    # roleDefinitions endpoint never lists, so their names never resolve even
    # when the lookup worked. Both callers assess USER principals only, and a
    # genuinely failed lookup degrades the user rows too, so it is still caught.
    $list = @(@($Assignments) | Where-Object {
        [string](Get-TPObjectField -Item $_ -Key 'PrincipalType' -Default '') -notmatch 'servicePrincipal'
    })
    if ($list.Count -eq 0) { return $true }
    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $unresolved = @($list | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'RoleDefinitionName') -match $guidPattern })
    return ($unresolved.Count -eq 0)
}

# Three-tier verdict for "is there a Conditional Access policy doing X":
#   enabled                              -> Satisfied  ('Enabled')
#   only report-only (audit mode)        -> Partial    ('Audit mode (report-only)')
#   none, or only disabled policies      -> Gap        ('None')
# Report-only logs what the policy would do but blocks nothing, so it earns
# half credit — it is real progress toward enforcement. Nothing configured
# earns none: half credit for an absent control inflates the score.
function Add-TPCAPolicyTierFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$ControlId,
        [Parameter(Mandatory)] $Control,
        [AllowNull()] $FrameworkIds,
        [AllowNull()] $Policies,
        [Parameter(Mandatory)] [scriptblock]$Match,
        [Parameter(Mandatory)] [string]$What,
        [Parameter(Mandatory)] [string]$EnabledDetail,
        [Parameter(Mandatory)] [string]$MissingDetail,
        [Parameter(Mandatory)] [string]$RequiredValue
    )
    $matched  = @(@($Policies) | Where-Object { $null -ne $_ } | Where-Object $Match)
    $enabled  = @($matched | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'State') -eq 'enabled' })
    $auditing = @($matched | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'State') -eq 'enabledForReportingButNotEnforced' })
    $names    = { param($list) (@($list) | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'DisplayName') } | Select-Object -First 5) -join ', ' }
    if ($enabled.Count -gt 0) {
        Add-TPFinding -ControlId $ControlId -State 'Satisfied' -Category $Control.Category -Title $Control.Title `
            -Severity 'Informational' -FrameworkIds $FrameworkIds `
            -Detail "Enabled: $EnabledDetail Policies: $(& $names $enabled)." `
            -CurrentValue "Enabled ($($enabled.Count) policy(ies))" -RequiredValue $RequiredValue
    } elseif ($auditing.Count -gt 0) {
        Add-TPFinding -ControlId $ControlId -State 'Partial' -Category $Control.Category -Title $Control.Title `
            -Severity $Control.Severity -FrameworkIds $FrameworkIds `
            -Detail "Audit mode: $What is configured only in report-only mode ($(& $names $auditing)). Sign-ins are logged against it but nothing is enforced. Review the report-only results, then switch the policy to On." `
            -CurrentValue "Audit mode (report-only, $($auditing.Count) policy(ies))" -RequiredValue $RequiredValue `
            -Remediation $Control.Remediation
    } else {
        Add-TPFinding -ControlId $ControlId -State 'Gap' -Category $Control.Category -Title $Control.Title `
            -Severity $Control.Severity -FrameworkIds $FrameworkIds `
            -Detail "None: $MissingDetail" `
            -CurrentValue 'None' -RequiredValue $RequiredValue `
            -Remediation $Control.Remediation
    }
}

# Is a CA grant's authentication strength phishing-resistant? $true / $false,
# or $null when the allowed methods are not visible. Built-in strength IDs are
# Microsoft constants (…0002 MFA, …0003 passwordless MFA, …0004 phishing-
# resistant). A custom strength passes only if EVERY allowed combination is
# made solely of FIDO2/passkey, Windows Hello for Business, or certificate MFA.
function Test-TPAuthStrengthPhishResistant {
    [CmdletBinding()]
    param([AllowNull()] $GrantControls)
    $id = [string](Get-TPObjectField -Item $GrantControls -Key 'AuthStrengthId' -Default '')
    if (-not $id) { return $null }
    switch ($id) {
        '00000000-0000-0000-0000-000000000004' { return $true }
        '00000000-0000-0000-0000-000000000002' { return $false }
        '00000000-0000-0000-0000-000000000003' { return $false }
    }
    $combos = @(Get-TPObjectField -Item $GrantControls -Key 'AuthStrengthCombinations' -Default @() | Where-Object { $_ })
    if ($combos.Count -eq 0) { return $null }
    $strong = @('fido2', 'windowsHelloForBusiness', 'x509CertificateMultiFactor')
    foreach ($c in $combos) {
        foreach ($factor in ([string]$c -split '\s*,\s*' | Where-Object { $_ })) {
            if ($strong -notcontains $factor) { return $false }
        }
    }
    return $true
}

# PIM policies scoped to PRIVILEGED directory roles, with role names attached.
# Needs RoleDefinitionId on each policy (collector's policy-assignment map) and
# the IsPriv role catalog from AAD-DirectoryRoles. When either is missing it
# returns every policy with Scoped = $false, so callers can say what they scored.
function Get-TPPIMScopedPolicies {
    [CmdletBinding()]
    param([AllowNull()] $Policies)
    $all = @($Policies)
    $roles = Get-TPRawData -Key 'AAD-DirectoryRoles'
    $defs = @{}
    foreach ($d in @(Get-TPNestedProperty -Object $roles -Path 'Data.RoleDefinitions' -Default @())) {
        $id = [string](Get-TPObjectField -Item $d -Key 'Id' -Default '')
        if ($id) { $defs[$id] = $d }
    }
    $mapped = @($all | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'RoleDefinitionId' -Default '') })
    if ($mapped.Count -eq 0 -or $defs.Count -eq 0) {
        return [pscustomobject]@{ Scoped = $false; Policies = $all }
    }
    $priv = foreach ($p in $mapped) {
        $d = $defs[[string]$p.RoleDefinitionId]
        if ($d -and (Get-TPObjectField -Item $d -Key 'IsPriv' -Default $false) -eq $true) {
            @{
                PolicyId              = Get-TPObjectField -Item $p -Key 'PolicyId'
                RoleDefinitionId      = [string]$p.RoleDefinitionId
                RoleName              = [string](Get-TPObjectField -Item $d -Key 'DisplayName' -Default '')
                RequiresMFA           = Get-TPObjectField -Item $p -Key 'RequiresMFA'
                MfaViaEnablement      = Get-TPObjectField -Item $p -Key 'MfaViaEnablement' -Default $null
                AuthContextEnabled    = Get-TPObjectField -Item $p -Key 'AuthContextEnabled' -Default $null
                AuthContextClaimValue = [string](Get-TPObjectField -Item $p -Key 'AuthContextClaimValue' -Default '')
                RequiresJustification = Get-TPObjectField -Item $p -Key 'RequiresJustification'
                RequiresApproval      = Get-TPObjectField -Item $p -Key 'RequiresApproval'
                MaxDurationHours      = Get-TPObjectField -Item $p -Key 'MaxDurationHours'
            }
        }
    }
    return [pscustomobject]@{ Scoped = $true; Policies = @($priv) }
}

# ── Conditional Access reading helpers ───────────────────────────────────────
# A grant with operator OR is satisfied by ANY of its controls, so "requires
# MFA" holds only when every alternative is MFA (or an authentication
# strength). "compliantDevice OR mfa" requires neither. A custom control
# (grantControls.customAuthenticationFactors, a third-party MFA provider) is
# an alternative like any other: "mfa OR custom control" lets the custom
# provider satisfy the grant, so it does not require Entra MFA; left out of
# this list, that grant read as MFA mandatory.
function Get-TPCAGrantAlternatives {
    [CmdletBinding()]
    param([AllowNull()] $Policy)
    $builtIn = @(Get-TPNestedProperty -Object $Policy -Path 'GrantControls.BuiltInControls' -Default @() | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $alts = [System.Collections.Generic.List[string]]::new()
    foreach ($b in $builtIn) { $alts.Add($b) }
    if ([string](Get-TPNestedProperty -Object $Policy -Path 'GrantControls.AuthStrengthId' -Default '')) { $alts.Add('authStrength') }
    foreach ($t in @(Get-TPNestedProperty -Object $Policy -Path 'GrantControls.TermsOfUse' -Default @() | Where-Object { $_ })) { $alts.Add('termsOfUse') }
    foreach ($c in @(Get-TPNestedProperty -Object $Policy -Path 'GrantControls.CustomControls' -Default @() | Where-Object { $_ })) { $alts.Add('customControl') }
    $op = [string](Get-TPNestedProperty -Object $Policy -Path 'GrantControls.Operator' -Default '')
    [pscustomobject]@{ Operator = $(if ($alts.Count -le 1) { 'AND' } else { $op.ToUpperInvariant() }); Controls = @($alts) }
}

function Test-TPCAGrantRequires {
    <# True when satisfying the grant NECESSARILY involves one of $Any. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] $Policy, [Parameter(Mandatory)] [string[]] $Any)
    $g = Get-TPCAGrantAlternatives -Policy $Policy
    if ($g.Controls.Count -eq 0) { return $false }
    if ($g.Operator -eq 'OR') { return (@($g.Controls | Where-Object { $_ -notin $Any }).Count -eq 0) }
    return (@($g.Controls | Where-Object { $_ -in $Any }).Count -gt 0)
}

# Is a field present on a collected object, whatever its value? Separates "the
# collector wrote an empty list" from "a results file from before the field was
# collected" (Get-TPObjectField returns an empty array as $null, so it cannot).
function Test-TPFieldPresent {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] $Item, [Parameter(Mandatory)] [string] $Key)
    if ($null -eq $Item) { return $false }
    if ($Item -is [System.Collections.IDictionary]) { return [bool]$Item.Contains($Key) }
    return ($null -ne $Item.PSObject.Properties[$Key])
}

function Test-TPCAAllUsers {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] $Policy)
    return (@(Get-TPNestedProperty -Object $Policy -Path 'Conditions.Users.IncludeUsers' -Default @()) -contains 'All')
}

function Test-TPCAAllApps {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] $Policy)
    return (@(Get-TPNestedProperty -Object $Policy -Path 'Conditions.Applications.Include' -Default @()) -contains 'All')
}

function Get-SafeProp {
    param($obj, [string]$prop, $default = $null)
    if ($null -eq $obj) { return $default }
    try {
        $val = $obj.$prop
        if ($null -eq $val) { return $default }
        return $val
    } catch { return $default }
}

#
# Test-TPControl-AAD.ps1  (v4.5.5)
# Evaluates Entra ID (AAD) security controls.
# SCORING ONLY — no API calls, no data collection.
# Reads from module state via Get-TPRawData; writes findings via Add-TPFinding.
#
# NIST SP 800-53: IA-2, IA-5, AC-6, AC-2, AC-7
# MITRE ATT&CK:   T1078, T1110, T1621, T1528
#

# ── AAD-1.1 Legacy Authentication Block ──────────────────────────────────────
function Get-TPLegacyAuthBlockState {
    <#
    .SYNOPSIS
        Whether password ("Basic") sign-in through legacy protocols is blocked
        tenant-wide, read from Security Defaults and Conditional Access exactly as
        AAD-1.1 judges it. Returns an [ordered] Kind and Detail:
          Blocked         Security Defaults is on, or an enabled CA policy blocks
                          the 'other' client-app type (IMAP, POP, SMTP AUTH and the
                          rest) for all users
          PartlyBlocked   a block exists only for some users or only in report-only
          NotBlocked      the CA read succeeded and nothing blocks legacy clients
          Unknown         CA data absent, or the Security Defaults state unresolved
        Used by EXO-1.6, which must not infer "passwords are allowed" from SMTP AUTH
        being enabled: SMTP AUTH also carries OAuth.
    #>
    [CmdletBinding()] param()
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        return [ordered]@{ Kind = 'Blocked'; Detail = 'Security Defaults is on and blocks legacy authentication tenant-wide' }
    }
    $ca = Get-TPRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not (Get-TPObjectField -Item $ca -Key 'Success' -Default $false)) {
        return [ordered]@{ Kind = 'Unknown'; Detail = 'Conditional Access data was not collected' }
    }
    if (Test-TPSecurityDefaultsUnresolved) {
        return [ordered]@{ Kind = 'Unknown'; Detail = 'the Security Defaults state was not read and no Conditional Access policy is On' }
    }
    $legacy = @($ca.Data['Policies'] | Where-Object {
        @($_.Conditions.ClientAppTypes) -contains 'other' -and (Test-TPCAGrantRequires -Policy $_ -Any @('block'))
    })
    $cov = Get-TPCAEffectiveCoverage -Policies @($legacy | Where-Object { $_.State -eq 'enabled' })
    if ($cov.Kind -eq 'Full') {
        return [ordered]@{ Kind = 'Blocked'; Detail = "Conditional Access blocks legacy authentication (Other clients) for all users on all applications: $($cov.FullNames -join ', ')" }
    }
    if ($cov.Kind -eq 'Exceptions') {
        return [ordered]@{ Kind = 'PartlyBlocked'; Detail = "Conditional Access blocks legacy authentication but every qualifying policy excludes $($cov.Exceptions -join ', ')" }
    }
    if ($cov.Kind -eq 'Unproven') {
        return [ordered]@{ Kind = 'PartlyBlocked'; Detail = 'Conditional Access blocks legacy authentication but each qualifying policy excludes different users or groups, so combined coverage is unproven' }
    }
    if ($legacy.Count -gt 0) {
        return [ordered]@{ Kind = 'PartlyBlocked'; Detail = 'a legacy-authentication block exists only for some users or applications, or only in report-only mode' }
    }
    return [ordered]@{ Kind = 'NotBlocked'; Detail = 'no Conditional Access policy blocks legacy authentication and Security Defaults is off' }
}

function Test-TPControlAADLegacyAuth {
    [CmdletBinding()] param()

    $controlId = 'AAD-1.1'
    $control   = Get-TPControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-TPFrameworkCitations -ControlId $controlId

    # Security Defaults blocks legacy authentication tenant-wide and cannot be
    # scoped, which is exactly what this control requires. It runs before the
    # CA gate: no CA policy can be turned on beside it, so CA data cannot
    # change this verdict.
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        Add-TPSecurityDefaultsFinding -ControlId $controlId -Category $control.Category -Title $control.Title -FrameworkIds $citations `
            -State 'Satisfied' -Severity 'Informational' `
            -Detail 'Legacy authentication is blocked by Security Defaults: Microsoft documents that it blocks every authentication request made by an older protocol tenant-wide, including clients that do not use modern authentication, IMAP, SMTP and POP3, and Exchange ActiveSync basic authentication, and that it cannot be scoped or customized.' `
            -CurrentValue 'Legacy authentication blocked for all users by Security Defaults' `
            -RequiredValue 'Legacy authentication blocked for all users (Conditional Access policy blocking Other clients, or Security Defaults)'
        return
    }

    $caData = Get-TPRawData -Key 'AAD-CAPolicies'
    if (-not $caData -or -not $caData.Success) {
        Add-TPFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'Conditional Access data not collected'
        return
    }
    # Security Defaults not read and no CA policy On: it may be on (Satisfied)
    # or off (the CA verdict below). An unread state is never "disabled".
    if (Test-TPSecurityDefaultsUnresolved) {
        Add-TPSecurityDefaultsUnreadFinding -ControlId $controlId -Category $control.Category -Title $control.Title -FrameworkIds $citations `
            -Question 'whether legacy authentication is blocked' `
            -IfOn 'it blocks every authentication request made by an older protocol tenant-wide' `
            -IfOff 'no Conditional Access policy blocks it'
        return
    }

    # 'other' is the client-app type that carries IMAP, POP, SMTP AUTH and the
    # other legacy protocols. A policy blocking only exchangeActiveSync leaves
    # them open, and one scoped to a pilot group leaves everyone else open —
    # both were reported "Legacy auth blocked".
    $legacy = @($caData.Data['Policies'] | Where-Object {
        @($_.Conditions.ClientAppTypes) -contains 'other' -and (Test-TPCAGrantRequires -Policy $_ -Any @('block'))
    })
    # Combined coverage (Get-TPCAEffectiveCoverage): a policy must cover all users on all
    # applications with no extra condition to count; user exclusions are judged across
    # every qualifying policy, so one policy excluding a break-glass account is not a gap
    # when another covers them, and is reported as an exception when none does.
    $cov     = Get-TPCAEffectiveCoverage -Policies @($legacy | Where-Object { $_.State -eq 'enabled' })
    $scoped  = @($cov.Narrowed)
    $audit   = @($legacy | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' })
    $names   = { param($l) (@($l) | ForEach-Object { $_.DisplayName }) -join ', ' }

    if ($cov.Kind -ne 'None') {
        $cv = Get-TPCACoverageVerdict -Coverage $cov -What 'Legacy authentication (Other clients) is blocked'
        Add-TPExpectedStateFinding -ControlId $controlId -Control $control -FrameworkIds $citations `
            -Verified $cv.Verified -Shortfalls $cv.Shortfalls -NotEstablished $cv.NotEstablished -AffectedObjects $cv.AffectedObjects `
            -CurrentValue "Legacy block: $($cov.Kind) coverage by $($cov.Names -join ', ')" `
            -RequiredValue 'CA policy blocking Other clients for all users on all applications, or Security Defaults'
    } elseif ($scoped.Count -gt 0 -or $audit.Count -gt 0) {
        $why = if ($scoped.Count -gt 0) { "blocked only for a subset of users, groups or applications, or under a narrowing condition ($(($scoped | ForEach-Object { "$($_.Name): $($_.Why)" }) -join '; ')); everyone else can still use legacy protocols" } else { "configured only in report-only mode ($(& $names $audit)); nothing is blocked" }
        Add-TPFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail "Legacy authentication is $why." `
            -CurrentValue 'Legacy auth block not enforced for all users' -RequiredValue 'CA policy blocking Other clients for all users' `
            -Remediation $control.Remediation
    } else {
        Add-TPFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail 'No Conditional Access policy found that blocks legacy authentication (Other clients).' `
            -CurrentValue 'No blocking CA policy' -RequiredValue 'CA policy blocking Other clients for all users' `
            -Remediation $control.Remediation
    }
}

# ── AAD-1.3 Phishing-Resistant MFA for Admins ────────────────────────────────
function Test-TPControlAADPhishResistantMFA {
    [CmdletBinding()] param()

    $controlId = 'AAD-1.3'
    $control   = Get-TPControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-TPFrameworkCitations -ControlId $controlId

    # Security Defaults requires MFA of 16 administrator roles at every
    # sign-in; it has them register Authenticator notifications (or use OATH
    # TOTP codes) and requires no phishing-resistant method. Standard admin
    # MFA scores Partial (Medium) on the CA path below, so it scores the same
    # here — never the Critical "no MFA for admins" Gap.
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        Add-TPSecurityDefaultsFinding -ControlId $controlId -Category $control.Category -Title $control.Title -FrameworkIds $citations `
            -State 'Partial' -Severity 'Medium' `
            -Detail 'The 16 administrator roles Security Defaults names (among them Global Administrator, Privileged Role Administrator, Security Administrator, Exchange Administrator and SharePoint Administrator) must complete MFA at every sign-in. Security Defaults requires them to register for Microsoft Authenticator notifications (or use OATH TOTP codes) and does not require a phishing-resistant method: Microsoft''s phishing-resistant MFA strength allows only Windows Hello for Business or platform credential, FIDO2 security keys and certificate-based MFA. Requiring it for administrators is done with a Conditional Access authentication-strength policy.' `
            -CurrentValue 'Security Defaults: MFA at every sign-in for 16 administrator roles; no phishing-resistant method required' `
            -RequiredValue 'CA policy with Authentication Strength targeting admin roles' `
            -Remediation $control.Remediation -NeedsConditionalAccess
        return
    }

    $caData = Get-TPRawData -Key 'AAD-CAPolicies'
    if (-not $caData -or -not $caData.Success) {
        Add-TPFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'Conditional Access data not collected'
        return
    }
    # Security Defaults not read and no CA policy On: it may be on (Partial,
    # admin MFA at every sign-in) or off (the Critical Gap below).
    if (Test-TPSecurityDefaultsUnresolved) {
        Add-TPSecurityDefaultsUnreadFinding -ControlId $controlId -Category $control.Category -Title $control.Title -FrameworkIds $citations `
            -Question 'whether administrators are required to complete MFA' `
            -IfOn 'the 16 administrator roles it names must complete MFA at every sign-in, with no requirement that the method be phishing-resistant' `
            -IfOff 'no Conditional Access policy requires MFA of administrators'
        return
    }

    # Any authentication strength used to count as phishing-resistant — but the
    # built-in "Multifactor authentication" strength and custom strengths can
    # allow SMS, voice or push. Classify each admin-role strength: $true /
    # $false / $null (methods not visible). Only $true is a pass.
    # A policy for ALL users covers admins too (admins are users); only
    # role-targeted policies used to count, so a tenant enforcing
    # phishing-resistant MFA for everyone read "no MFA for admins".
    $coversAdmins = { param($p) @($p.Conditions.Users.IncludeRoles).Count -gt 0 -or (Test-TPCAAllUsers $p) }
    $roleStrengthPolicies = @($caData.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and (& $coversAdmins $_) -and
        (-not [string]::IsNullOrEmpty($_.GrantControls.AuthStrengthId)) -and
        (Test-TPCAGrantRequires -Policy $_ -Any @('authStrength'))
    })
    $phishResistantPolicies = @($roleStrengthPolicies | Where-Object { (Test-TPAuthStrengthPhishResistant -GrantControls $_.GrantControls) -eq $true })
    $weakStrengthPolicies   = @($roleStrengthPolicies | Where-Object { (Test-TPAuthStrengthPhishResistant -GrantControls $_.GrantControls) -eq $false })
    $unknownStrengthPolicies = @($roleStrengthPolicies | Where-Object { $null -eq (Test-TPAuthStrengthPhishResistant -GrantControls $_.GrantControls) })

    # Also check for policies targeting roles with MFA (lower bar — Partial)
    $mfaForRolePolicies = @($caData.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and (& $coversAdmins $_) -and
        (Test-TPCAGrantRequires -Policy $_ -Any @('mfa','authStrength'))
    })

    if ($phishResistantPolicies.Count -gt 0) {
        # Coverage of the administrator population, not just "a policy exists": an
        # all-users policy covers admins; a role-scoped one must include every privileged
        # role this tenant's own role catalog lists (never Microsoft's fixed list, which
        # the tool cannot verify here); exclusions are judged across every qualifying policy.
        $privIds = $null
        $roleRaw = Get-TPRawData -Key 'AAD-DirectoryRoles'
        if ($roleRaw -and (Get-TPObjectField -Item $roleRaw -Key 'Success' -Default $null) -eq $true) {
            $defs = @(Get-TPNestedProperty -Object $roleRaw -Path 'Data.RoleDefinitions' -Default @())
            if ($defs.Count -gt 0) {
                $privIds = @{}
                foreach ($d in $defs) { if ((Get-TPObjectField -Item $d -Key 'IsPriv' -Default $false) -eq $true) { $privIds[[string](Get-TPObjectField -Item $d -Key 'Id' -Default '')] = $true } }
            }
        }
        $cands = @(); $narrowed = @(); $roleUnverified = @()
        foreach ($p in $phishResistantPolicies) {
            $nm = [string]$p.DisplayName
            # Role scope is judged below; a policy that reaches only the browser (or
            # only the desktop clients) leaves the other sign-ins unprotected.
            $nar = @(Get-TPCANarrowing -Policy $p -RequiredClientAppTypes (Get-TPCAInteractiveClientAppTypes) -Ignore @('applies to only some users, groups or roles'))
            if (-not (Test-TPCAAllUsers $p)) {
                $rc = Get-TPCAAdminRoleCoverage -Policy $p -PrivRoleIds $privIds
                if ($null -eq $rc) { $roleUnverified += $nm }
                elseif ($rc.CoveredCount -lt $rc.TotalPriv) { $nar += "it covers $($rc.CoveredCount) of $($rc.TotalPriv) privileged roles" }
            }
            if ($nar.Count -gt 0) { $narrowed += [pscustomobject]@{ Name = $nm; Why = ($nar -join '; ') } }
            else { $cands += [pscustomobject]@{ Name = $nm; Exclusions = @(Get-TPCAPrincipalExclusions -Policy $p) } }
        }
        $cov = Get-TPExclusionCoverage -Candidates $cands
        $cov['Narrowed'] = @($narrowed)
        $cv = Get-TPCACoverageVerdict -Coverage $cov -What 'Phishing-resistant MFA (Authentication Strength) is required for admin roles'
        if ($cov.Kind -ne 'None' -and $roleUnverified.Count -gt 0 -and @($cov.FullNames | Where-Object { $_ -notin $roleUnverified }).Count -eq 0) {
            $cv.NotEstablished = @($cv.NotEstablished) + "whether $($roleUnverified -join ', ') covers every privileged role, because this tenant's role catalog was not read."
        }
        Add-TPExpectedStateFinding -ControlId $controlId -Control $control -FrameworkIds $citations `
            -Verified $cv.Verified -Shortfalls $cv.Shortfalls -NotEstablished $cv.NotEstablished -AffectedObjects $cv.AffectedObjects `
            -CurrentValue "Phishing-resistant MFA for admins: $($cov.Kind) coverage" `
            -RequiredValue 'CA policy with a phishing-resistant authentication strength covering every privileged role'
    } elseif ($unknownStrengthPolicies.Count -gt 0) {
        # A strength is required, but which methods it allows could not be
        # read, so phishing resistance is unverified in either direction.
        Add-TPFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail "Admin roles require an authentication strength ($(($unknownStrengthPolicies | ForEach-Object { "$($_.DisplayName) [$(Get-TPObjectField -Item $_.GrantControls -Key 'AuthStrengthName' -Default 'custom strength')]" }) -join ', ')), but its allowed methods could not be read, so whether it is phishing-resistant is not assessed. Verify in Entra > Protection > Authentication methods > Authentication strengths."
    } elseif ($weakStrengthPolicies.Count -gt 0) {
        Add-TPFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail "Admin roles require an authentication strength that is NOT phishing-resistant — it allows methods such as SMS, voice, or app push that AiTM phishing can relay: $(($weakStrengthPolicies | ForEach-Object { "$($_.DisplayName) [$(Get-TPObjectField -Item $_.GrantControls -Key 'AuthStrengthName' -Default 'custom strength')]" }) -join ', ')." `
            -CurrentValue 'Authentication strength for admins allows non-phishing-resistant methods' `
            -RequiredValue 'Phishing-resistant MFA strength (FIDO2/passkey, Windows Hello for Business, certificate-based MFA) for admin roles' `
            -Remediation $control.Remediation
    } elseif ($mfaForRolePolicies.Count -gt 0) {
        Add-TPFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail 'Admin roles have MFA required via CA, but not using Authentication Strength (phishing-resistant). AiTM attacks can bypass standard MFA.' `
            -CurrentValue 'CA requires standard MFA for admin roles' `
            -RequiredValue 'CA using Authentication Strength (phishing-resistant MFA) for admin roles' `
            -Remediation $control.Remediation
    } else {
        Add-TPFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail 'No CA policy found that requires MFA for privileged directory roles.' `
            -CurrentValue 'No phishing-resistant MFA for admins' `
            -RequiredValue 'CA policy with Authentication Strength targeting admin roles' `
            -Remediation $control.Remediation
    }
}

# ── AAD-1.4 Sign-in Risk CA Policy ───────────────────────────────────────────
function Test-TPControlAADSignInRisk {
    [CmdletBinding()] param()
    $cid = 'AAD-1.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        Add-TPSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No Conditional Access sign-in risk policy can be in force while Security Defaults is enabled, and Security Defaults has no configurable sign-in risk policy of its own: it prompts registered users for MFA when Microsoft decides it is necessary. Conditional Access risk policies need Microsoft Entra ID P2. The legacy Identity Protection sign-in risk policy (retiring October 1, 2026) is not read by this tool.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access sign-in risk policy in force' -RequiredValue 'CA policy: signInRiskLevels = high/medium + require MFA' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca  = Get-TPRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    $riskPolicies = @($ca.Data['Policies'] | Where-Object {
        # Block is the strongest response to a risky sign-in, not a miss.
        $_.State -eq 'enabled' -and @($_.Conditions.SignInRiskLevels).Count -gt 0 -and
        (Test-TPCAGrantRequires -Policy $_ -Any @('mfa','authStrength','block'))
    })
    # Risk levels are discrete: a policy applies only to the levels it
    # selects. Microsoft's template selects High and Medium. Each level is
    # judged on WHO the policies selecting it protect (Get-TPRiskLevelCoverage):
    # all users on all applications, every interactive client app type, no
    # platform, location or device-filter narrowing, with exclusions combined
    # across the policies that select the level. Merging the levels of every
    # enabled policy, whatever its scope, credited a pilot-group policy and a
    # policy excluding a group with tenant-wide protection.
    $levels = @($riskPolicies | ForEach-Object { @($_.Conditions.SignInRiskLevels) } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $names = (@($riskPolicies | ForEach-Object { [string]$_.DisplayName }) -join ', ')
    $perLevel = Get-TPRiskLevelCoverage -Policies $riskPolicies -Condition 'SignInRiskLevels' -RequiredLevels @('high', 'medium')
    $fullLevels = @($perLevel.Keys | Where-Object { $perLevel[$_].Kind -eq 'Full' })
    $ro14 = Get-TPRiskReportOnlyPolicies -Policies $ca.Data['Policies'] -Condition 'SignInRiskLevels' -RequiredLevels @('high','medium') -GrantAny @('mfa','authStrength','block')
    if ($fullLevels.Count -lt 2 -and (Get-TPPolicyListIncomplete -CA $ca)) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "Not assessed: the Conditional Access policy list could not be read in full (the beta list failed and the v1.0 list withholds some policies), so whether a complete sign-in risk policy exists was not established.$(if ($names) { " Enabled sign-in risk policies read: $names." })"
        return
    }
    if ($riskPolicies.Count -gt 0 -and @($perLevel.Keys | Where-Object { @($perLevel[$_].Selecting).Count -gt 0 }).Count -gt 0) {
        $cv = Get-TPRiskCoverageVerdict -PerLevel $perLevel -Noun 'sign-in risk' -Consequence 'is let through without a challenge'
        Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit `
            -Verified $cv.Verified -Shortfalls $cv.Shortfalls -NotEstablished $cv.NotEstablished -AffectedObjects $cv.AffectedObjects `
            -CurrentValue "signInRiskLevels = $($levels -join ', '); all-user coverage: $(($perLevel.Keys | ForEach-Object { "$_ $($perLevel[$_].Kind)" }) -join ', ')" `
            -RequiredValue 'CA policy in force for all users on all applications: signInRiskLevels = high/medium + require MFA'
    } elseif ($riskPolicies.Count -eq 0 -and @($ro14.Qualifying).Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "A sign-in risk policy meets every requirement (high and medium sign-in risk, all users and applications, a responding control) but is in report-only mode, which collects evaluation data and enforces nothing: $(@($ro14.Qualifying) -join ', '). Until it is turned on, a risky sign-in is let through without a challenge; Partial is still a failed baseline requirement.$(Get-TPRiskReportOnlyNote -ReportOnly $ro14)" `
            -CurrentValue "Report-only: $(@($ro14.Qualifying) -join ', ')" -RequiredValue 'CA policy in force: signInRiskLevels = high/medium + require MFA' -Remediation $ctrl.Remediation
    } elseif ($riskPolicies.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "The enabled sign-in risk policies ($names) apply to $($levels -join ', ') risk only, so a medium- or high-risk sign-in (password spray, anonymous IP, token replay) is let through without a challenge." `
            -CurrentValue "signInRiskLevels = $($levels -join ', ')" -RequiredValue 'CA policy: signInRiskLevels = high/medium + require MFA' -Remediation $ctrl.Remediation
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail ('No enabled Conditional Access policy uses the sign-in risk condition, so a sign-in Identity Protection rates risky (password spray, anonymous IP, token replay) is let through without a challenge. (Sign-in risk policies need Entra ID P2; on a tenant without it this control is not scored.)' + (Get-TPRiskReportOnlyNote -ReportOnly $ro14)) -CurrentValue 'No sign-in risk policy' -RequiredValue 'CA policy: signInRiskLevels = high/medium + require MFA' -Remediation $ctrl.Remediation
    }
}

# Risk-based Conditional Access policies in report-only (audit) mode. Report-only collects evaluation
# telemetry and enforces nothing, so it is never a pass. One that would satisfy the requirement if it were
# enforced (every required risk level, a responding grant, and a scope of all users and all applications with no
# platform, location, device-filter or application-exclusion narrowing) is part-way (Partial); anything else
# is a Gap. Both remain failed baseline requirements.
# True only when the collector says the Conditional Access list could not be proven complete. A key that is
# absent (results collected before the beta merge existed) counts as complete, so older results replay unchanged.
function Get-TPPolicyListIncomplete {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] $CA)
    $st = [string](Get-TPNestedProperty -Object $CA -Path 'Data.SectionStatus.PolicyCompleteness' -Default '')
    return ($st -in @('Failed', 'NotRun'))
}

function Get-TPRiskReportOnlyPolicies {
    [CmdletBinding()]
    param([AllowNull()] [object[]] $Policies, [Parameter(Mandatory)] [ValidateSet('SignInRiskLevels', 'UserRiskLevels')] [string] $Condition,
          [Parameter(Mandatory)] [string[]] $RequiredLevels, [Parameter(Mandatory)] [string[]] $GrantAny)
    $qualifying = [System.Collections.Generic.List[string]]::new()
    $other = [System.Collections.Generic.List[string]]::new()
    foreach ($pol in @($Policies)) {
        if ($null -eq $pol) { continue }
        if ([string](Get-TPObjectField -Item $pol -Key 'State' -Default '') -ne 'enabledForReportingButNotEnforced') { continue }
        $levels = @(Get-TPNestedProperty -Object $pol -Path "Conditions.$Condition" -Default @() | ForEach-Object { [string]$_ } | Where-Object { $_ })
        if ($levels.Count -eq 0) { continue }
        $name = [string](Get-TPObjectField -Item $pol -Key 'DisplayName' -Default '')
        $why = [System.Collections.Generic.List[string]]::new()
        $missing = @($RequiredLevels | Where-Object { $_ -notin $levels })
        if ($missing.Count -gt 0) { $why.Add("does not select $($missing -join '/') risk") }
        if (-not (Test-TPCAGrantRequires -Policy $pol -Any $GrantAny)) { $why.Add('does not require a responding control') }
        foreach ($n in @(Get-TPCANarrowing -Policy $pol -RequiredClientAppTypes (Get-TPCAInteractiveClientAppTypes) -Ignore @('applies only at certain risk levels'))) { $why.Add($n) }
        if ($why.Count -eq 0) { $qualifying.Add($name) } else { $other.Add("$name ($($why -join '; '))") }
    }
    [pscustomobject]@{ Qualifying = @($qualifying); Other = @($other) }
}

function Get-TPRiskReportOnlyNote {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $ReportOnly)
    if ($null -eq $ReportOnly -or @($ReportOnly.Other).Count -eq 0) { return '' }
    return " Report-only (audit mode, not enforcing) and not meeting the full requirement: $(@($ReportOnly.Other) -join '; ')."
}

function Get-TPRiskLevelCoverage {
    <#
    .SYNOPSIS
        Per required risk level, the combined coverage (Get-TPCAEffectiveCoverage) of the
        enabled, responding policies that select that level: a policy counts for a level
        only when it selects it AND covers all users on all applications and every
        interactive client app type with no platform, location or device-filter
        narrowing; exclusions are judged across the policies selecting the level. The
        risk condition itself is expected and not a narrowing. Each entry also carries
        Selecting, the names of the policies that select the level at all.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param([AllowNull()] [AllowEmptyCollection()] [object[]] $Policies, [Parameter(Mandatory)] [ValidateSet('SignInRiskLevels', 'UserRiskLevels')] [string] $Condition,
          [Parameter(Mandatory)] [string[]] $RequiredLevels)
    $out = [ordered]@{}
    foreach ($lvl in $RequiredLevels) {
        $sel = @($Policies | Where-Object { $null -ne $_ -and (@(Get-TPNestedProperty -Object $_ -Path "Conditions.$Condition" -Default @() | ForEach-Object { [string]$_ }) -contains $lvl) })
        $cov = Get-TPCAEffectiveCoverage -Policies $sel -RequiredClientAppTypes (Get-TPCAInteractiveClientAppTypes) -Ignore @('applies only at certain risk levels')
        $cov['Selecting'] = @($sel | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'DisplayName' -Default '') })
        $out[$lvl] = $cov
    }
    return $out
}

function Get-TPRiskCoverageVerdict {
    <#
    .SYNOPSIS
        Verified / Shortfalls / NotEstablished statements for a per-level coverage map
        (Get-TPRiskLevelCoverage). A level no enabled policy selects is a shortfall; a
        level selected only by narrower policies, or excluded for the same principals
        everywhere, is a shortfall (Get-TPCACoverageVerdict); different exclusions leave
        it not established.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)] $PerLevel, [Parameter(Mandatory)] [string] $Noun, [Parameter(Mandatory)] [string] $Consequence)
    $v = @(); $s = @(); $u = @(); $ao = @(); $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($lvl in @($PerLevel.Keys)) {
        $cov = $PerLevel[$lvl]
        if (@($cov.Selecting).Count -eq 0) {
            $s += "No enabled policy responds to $lvl $Noun; a policy applies only to the risk levels it selects, so a $lvl-risk sign-in $Consequence."
            continue
        }
        $cv = Get-TPCACoverageVerdict -Coverage $cov -What "A responding policy applies to $lvl $Noun"
        $v += @($cv.Verified); $s += @($cv.Shortfalls); $u += @($cv.NotEstablished)
        # One structured entry per excluded principal per level sentence, so every
        # exclusion sentence a level produced stays matched to its principals.
        foreach ($o in @($cv.AffectedObjects)) { if ($seen.Add("$([string]$o.Principal)|$([string]$o.Sentence)")) { $ao += $o } }
    }
    return [ordered]@{ Verified = $v; Shortfalls = $s; NotEstablished = $u; AffectedObjects = $ao }
}

# ── AAD-1.5 User Risk CA Policy ───────────────────────────────────────────────
function Test-TPControlAADUserRisk {
    [CmdletBinding()] param()
    $cid = 'AAD-1.5'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        Add-TPSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No Conditional Access user risk policy can be in force while Security Defaults is enabled, and Security Defaults has no configurable user risk policy of its own, so neither forces an account Identity Protection rates as likely compromised to change its password or blocks it. Conditional Access risk policies need Microsoft Entra ID P2. The legacy Identity Protection user risk policy (retiring October 1, 2026) is not read by this tool.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access user risk policy in force' -RequiredValue 'CA policy: userRiskLevels = high + require password change or risk remediation' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca  = Get-TPRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    $riskPolicies = @($ca.Data['Policies'] | Where-Object {
        # riskRemediation ("require risk remediation", Microsoft's current
        # template) arrives as unknownFutureValue from data collected without
        # the Prefer header; block and auth strengths are responses too.
        $_.State -eq 'enabled' -and @($_.Conditions.UserRiskLevels).Count -gt 0 -and
        (Test-TPCAGrantRequires -Policy $_ -Any @('mfa','authStrength','passwordChange','riskRemediation','unknownFutureValue','block'))
    })
    # Microsoft's template is "Require password change for high-risk users":
    # a policy without the High level never applies to those accounts, and
    # one that selects High is judged on who it protects (Get-TPRiskLevelCoverage),
    # as for AAD-1.4.
    $levels = @($riskPolicies | ForEach-Object { @($_.Conditions.UserRiskLevels) } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $names = (@($riskPolicies | ForEach-Object { [string]$_.DisplayName }) -join ', ')
    $perLevel = Get-TPRiskLevelCoverage -Policies $riskPolicies -Condition 'UserRiskLevels' -RequiredLevels @('high')
    $ro15 = Get-TPRiskReportOnlyPolicies -Policies $ca.Data['Policies'] -Condition 'UserRiskLevels' -RequiredLevels @('high') -GrantAny @('mfa','authStrength','passwordChange','riskRemediation','unknownFutureValue','block')
    # Microsoft's v1.0 list withholds some policies (the risk-remediation ones were withheld on the first full
    # run), so with the beta list unread, "no qualifying policy" is not a conclusion the evidence supports.
    if ($perLevel['high'].Kind -ne 'Full' -and (Get-TPPolicyListIncomplete -CA $ca)) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "Not assessed: the Conditional Access policy list could not be read in full (the beta list failed and the v1.0 list withholds some policies), so whether a user risk policy exists was not established.$(if ($names) { " Enabled user risk policies read: $names." })"
        return
    }
    if (@($perLevel['high'].Selecting).Count -gt 0) {
        $cv = Get-TPRiskCoverageVerdict -PerLevel $perLevel -Noun 'user risk' -Consequence 'is not forced to change its password or blocked'
        Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit `
            -Verified $cv.Verified -Shortfalls $cv.Shortfalls -NotEstablished $cv.NotEstablished -AffectedObjects $cv.AffectedObjects `
            -CurrentValue "userRiskLevels = $($levels -join ', '); all-user coverage for high: $($perLevel['high'].Kind)" `
            -RequiredValue 'CA policy in force for all users on all applications: userRiskLevels = high + require password change or risk remediation'
    } elseif ($riskPolicies.Count -eq 0 -and @($ro15.Qualifying).Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "A user risk policy meets every requirement (high user risk, all users and applications, a responding control) but is in report-only mode, which collects evaluation data and enforces nothing: $(@($ro15.Qualifying) -join ', '). Until it is turned on, an account Identity Protection rates high risk is not forced to change its password or blocked; Partial is still a failed baseline requirement.$(Get-TPRiskReportOnlyNote -ReportOnly $ro15)" `
            -CurrentValue "Report-only: $(@($ro15.Qualifying) -join ', ')" -RequiredValue 'CA policy in force: userRiskLevels = high + require password change or risk remediation' -Remediation $ctrl.Remediation
    } elseif ($riskPolicies.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "The enabled user risk policies ($names) apply to $($levels -join ', ') risk only, so an account Identity Protection rates high risk (likely compromised) is not forced to change its password or blocked." `
            -CurrentValue "userRiskLevels = $($levels -join ', ')" -RequiredValue 'CA policy: userRiskLevels = high + require password change or risk remediation' -Remediation $ctrl.Remediation
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail ('No enabled Conditional Access policy uses the user risk condition, so an account Identity Protection rates as likely compromised is not forced to change its password or blocked. (User risk policies need Entra ID P2; on a tenant without it this control is not scored.)' + (Get-TPRiskReportOnlyNote -ReportOnly $ro15)) -Remediation $ctrl.Remediation
    }
}

# ── AAD-2.2 Named Locations Defined ──────────────────────────────────────────
function Test-TPControlAADNamedLocations {
    [CmdletBinding()] param()
    $cid = 'AAD-2.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $ca  = Get-TPRawData -Key 'AAD-CAPolicies'
    # Named locations are a Conditional Access condition, and beside Security
    # Defaults no policy in force can use them. Licensed but not configured
    # is still a Gap: none defined is the same Gap as with Security Defaults
    # off (an unlicensed tenant is moved out of the score by license gating,
    # not here). Locations that exist earn no credit, because nothing can use
    # them until Security Defaults is off. Not read is not assessed.
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        $sdLoc = @{ ControlId = $cid; Category = $ctrl.Category; Title = $ctrl.Title; FrameworkIds = $cit; RequiredValue = 'At least one trusted IP range defined' }
        if ((Get-TPObjectField -Item $ca -Key 'Success' -Default $null) -ne $true -or -not (Test-TPSectionCollected $ca 'NamedLocations')) {
            Add-TPSecurityDefaultsFinding @sdLoc -State 'NotApplicable' `
                -Detail 'Named locations were not collected, so whether any are defined was not assessed.' `
                -CurrentValue 'Security Defaults enabled; named locations: not read'
            return
        }
        $locs = @(@(Get-TPNestedProperty -Object $ca -Path 'Data.NamedLocations' -Default @()) | Where-Object { $null -ne $_ })
        if ($locs.Count -eq 0) {
            Add-TPSecurityDefaultsFinding @sdLoc -State 'Gap' -Severity $ctrl.Severity `
                -Detail 'No named locations are defined. Named locations are a Conditional Access condition, and Security Defaults has no location conditions an administrator can configure.' `
                -CurrentValue 'Security Defaults enabled; named locations: 0 defined' `
                -Remediation $ctrl.Remediation -NeedsConditionalAccess
            return
        }
        $trusted = @($locs | Where-Object { (Get-TPObjectField -Item $_ -Key 'IsTrusted' -Default $false) -eq $true }).Count
        Add-TPSecurityDefaultsFinding @sdLoc -State 'NotApplicable' `
            -Detail "$($locs.Count) named location(s) are defined ($trusted marked trusted), but named locations are a Conditional Access condition and Security Defaults has no location conditions an administrator can configure, so no policy in force can use them and they earn no credit. The absence of Conditional Access is reported under AAD-2.1." `
            -CurrentValue "Security Defaults enabled; named locations: $($locs.Count) defined ($trusted trusted)"
        return
    }
    if (-not $ca -or -not $ca.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    # Empty is not clean. NamedLocations is an independent sub-query from the
    # primary CA-policies fetch (which is all $ca.Success reflects) — a
    # throttled or failed namedLocations call leaves the list empty while
    # Success stays $true, and reading that as "no named locations defined"
    # is a false Gap on a tenant that has them.
    if (-not (Test-TPSectionCollected $ca 'NamedLocations')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'NamedLocations was not collected; not assessed.'
        return
    }
    $namedLocations   = @(Get-TPNestedProperty -Object $ca -Path 'Data.NamedLocations' -Default @())
    $trustedLocations = @($namedLocations | Where-Object { $_.IsTrusted })
    if ($trustedLocations.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($trustedLocations.Count) trusted named location(s) defined."
    } elseif ($namedLocations.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail "$($namedLocations.Count) named location(s) defined but none marked as trusted." -CurrentValue 'Named locations defined, none trusted' -RequiredValue 'At least one trusted IP range defined'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No named locations defined. Cannot enforce location-based CA conditions or exclude trusted office IPs.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-2.3 Device Compliance Enforced via CA ─────────────────────────────────
function Test-TPControlAADDeviceComplianceCA {
    [CmdletBinding()] param()
    $cid = 'AAD-2.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        Add-TPSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No policy in force requires a compliant or hybrid-joined device. Security Defaults has no device requirement: its MFA prompts do not require the device to be compliant, managed or hybrid-joined, so unmanaged devices can reach corporate resources.' `
            -CurrentValue 'Security Defaults enabled; no compliant-device requirement in force' -RequiredValue 'Compliant or hybrid-joined device required by an enabled CA policy' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca  = Get-TPRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    # One judgment shared with INT-1.2 (Get-TPCADeviceComplianceCoverage): the
    # requirement counts only from enabled policies that require a device of all
    # users on all applications with no narrowing, reaching the browser and the
    # desktop and mobile clients, exclusions combined across policies. This used to
    # credit ANY enabled policy requiring a device, whatever its scope, so a policy
    # on one group passed the control for the tenant (2026-10-15 review).
    # "Compliant OR hybrid-joined OR MFA" (a Microsoft template) lets MFA alone
    # through on an unmanaged device, so it enforces nothing and is a named Gap.
    $pols = @(Get-TPObjectField -Item $ca.Data -Key 'Policies' -Default @() | Where-Object { $null -ne $_ })
    Add-TPCADeviceComplianceFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit `
        -Model (Get-TPCADeviceComplianceCoverage -Policies $pols) `
        -Consequence 'Unmanaged personal devices access corporate resources unchecked.' `
        -RequiredValue 'Compliant or hybrid-joined device required by an enabled CA policy for all users on all applications'
}

# ── AAD-3.2 No Permanent Admin Assignments ────────────────────────────────────
function Test-TPControlAADNoPermanentAdmins {
    [CmdletBinding()] param()
    $cid = 'AAD-3.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pim = Get-TPRawData -Key 'AAD-PIMSchedules'
    $roles = Get-TPRawData -Key 'AAD-DirectoryRoles'
    if (-not $pim -or -not $pim.Success) {
        if ($pim -and $pim.PIMAvailable -eq $false) {
            Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM not available (requires Entra P2 license)'; return
        }
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM data not collected'; return
    }
    # "No permanent privileged role assignments" is a claim about the ROLE data,
    # so it cannot be made without it. Previously $permanentPriv simply stayed
    # empty when AAD-DirectoryRoles was missing or its section had not landed,
    # and the Satisfied branch below fired anyway — producing a clean bill of
    # health on a privilege-escalation control, worded identically to a genuinely
    # clean tenant, from data that never arrived.
    if (-not $roles -or -not $roles.Success -or -not (Test-TPSectionCollected $roles 'RoleAssignments')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'Directory role assignments were not collected, so permanent privileged assignments could not be evaluated. Not assessed — re-run before treating this control as clean.'
        return
    }
    $permanentPriv = @($roles.Data['RoleAssignments'] | Where-Object {
        $_.IsPriv -and $_.PrincipalType -notmatch 'servicePrincipal'
    })
    # An ACTIVATED eligible assignment appears in roleAssignments for the
    # activation window; it is PIM working, not a standing assignment. The
    # schedule's assignmentType says which ('Activated' vs 'Assigned').
    $activated = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($sch in @(Get-TPNestedProperty -Object $pim -Path 'Data.ActiveSchedules' -Default @())) {
        if ([string](Get-TPObjectField -Item $sch -Key 'AssignmentType' -Default '') -eq 'Activated') {
            $null = $activated.Add("$(Get-TPObjectField -Item $sch -Key 'PrincipalId' -Default '')|$(Get-TPObjectField -Item $sch -Key 'RoleDefinitionId' -Default '')")
        }
    }
    # Break-glass accounts are permanent BY DESIGN (Microsoft: emergency access
    # accounts must not depend on PIM activation). Cloud-only Global Admins
    # excluded from Conditional Access are set aside and named in the detail.
    # Not while Security Defaults is enabled: an administrator cannot exclude
    # any account from it and no CA policy can be on beside it, so a CA
    # exclusion (even a stale CAExcluded = $true) is never credited, and every
    # verdict that depends on that goes through Add-TPSecurityDefaultsFinding,
    # which reports a CA read contradicting Security Defaults as not assessed.
    $sdOn = (Get-TPSecurityDefaultsState) -eq $true
    $bgIds = [System.Collections.Generic.HashSet[string]]::new()
    if (-not $sdOn) {
        $govBg = Get-TPRawData -Key 'AAD-IdentityGovernance'
        foreach ($b in @(Get-TPNestedProperty -Object $govBg -Path 'Data.BreakGlassIndicators' -Default @())) {
            if ((Get-TPObjectField -Item $b -Key 'CAExcluded' -Default $false) -eq $true -and -not (Get-TPObjectField -Item $b -Key 'Synced' -Default $false)) {
                $null = $bgIds.Add([string](Get-TPObjectField -Item $b -Key 'PrincipalId' -Default ''))
            }
        }
    }
    $pidOf = { param($a) [string](Get-TPObjectField -Item $a -Key 'PrincipalId' -Default '') }
    $ridOf = { param($a) [string](Get-TPObjectField -Item $a -Key 'RoleDefinitionId' -Default '') }
    $setAside = @($permanentPriv | Where-Object { (& $pidOf $_) -and $bgIds.Contains((& $pidOf $_)) -and $_.RoleDefinitionName -eq 'Global Administrator' })
    $permanentPriv = @($permanentPriv | Where-Object {
        -not $activated.Contains("$(& $pidOf $_)|$(& $ridOf $_)") -and
        -not ((& $pidOf $_) -and $bgIds.Contains((& $pidOf $_)) -and $_.RoleDefinitionName -eq 'Global Administrator')
    })
    $bgNote = if ($setAside.Count -gt 0) { " $($setAside.Count) break-glass Global Administrator account(s) set aside (permanent by design): $(($setAside | ForEach-Object { $_.PrincipalDisplayName }) -join ', ')." } else { '' }

    # Same rule for the PIM half. The collector pre-initialises every section to
    # @(), so an empty EligibleSchedules is ambiguous between "no PIM adoption"
    # and "the query failed" — and only the section status can tell them apart.
    $eligibleCollected = Test-TPSectionCollected $pim 'EligibleSchedules'
    $eligibleCount = @($pim.Data['EligibleSchedules']).Count

    # Under Security Defaults the two cloud-only emergency access accounts
    # Microsoft recommends keeping permanently assigned Global Administrator
    # cannot be told apart from standing access (no exclusion exists to mark
    # them). Only when what remains is exactly that shape — at most two
    # cloud-only principals holding nothing but Global Administrator, beside
    # real PIM adoption — does the verdict turn on that unknown. Every other
    # shape is a Gap whatever those accounts are.
    if ($sdOn -and $permanentPriv.Count -gt 0 -and $eligibleCollected -and $eligibleCount -gt 0) {
        $keyOf = {
            param($a)
            foreach ($k in 'PrincipalId', 'PrincipalUPN', 'PrincipalDisplayName') {
                $v = [string](Get-TPObjectField -Item $a -Key $k -Default '')
                if ($v) { return $v }
            }
            return ''
        }
        # OnPremisesSyncEnabled is $null for an account never synchronized
        # (Graph's documented cloud-only value) and for one whose value was
        # not read, so the prose says "not marked as synchronized" — what was
        # read — never "cloud-only".
        $nonGa  = @($permanentPriv | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'RoleDefinitionName' -Default '') -ne 'Global Administrator' })
        $synced = @($permanentPriv | Where-Object { (Get-TPObjectField -Item $_ -Key 'OnPremisesSyncEnabled' -Default $null) -eq $true })
        $people = @($permanentPriv | ForEach-Object { & $keyOf $_ } | Sort-Object -Unique)
        if ($nonGa.Count -eq 0 -and $synced.Count -eq 0 -and $people.Count -le 2) {
            $gaNames = @($permanentPriv | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'PrincipalDisplayName' -Default '') } | Where-Object { $_ } | Sort-Object -Unique) -join ', '
            # One account or two: the prose follows what was read.
            $which = if ($people.Count -eq 1) { 'whether this account is one of' } else { 'whether these accounts are' }
            $conv  = if ($people.Count -eq 1) { 'if it is, no standing privileged access exists outside it; if it is not, convert it to a PIM-eligible assignment' } else { 'if they are, no standing privileged access exists outside them; if they are not, convert them to PIM-eligible assignments' }
            Add-TPSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'NotApplicable' `
                -Detail "$($permanentPriv.Count) permanent privileged assignment(s) remain on $($people.Count) account(s), all of them Global Administrator on accounts not marked as synchronized from on-premises, and $eligibleCount PIM-eligible assignment(s) are configured. An administrator cannot exclude any account from Security Defaults (its only exclusion is Microsoft's automatic one for directory synchronization accounts), so this control cannot tell $which the two cloud-only emergency access accounts Microsoft recommends keeping permanently assigned Global Administrator. That requires manual verification: $conv." `
                -CurrentValue "Permanent Global Administrator (not marked as synchronized from on-premises): $gaNames" `
                -RequiredValue 'All privileged roles via PIM eligible assignments only'
            return
        }
    }
    if ($permanentPriv.Count -gt 0) {
        $g = @{ ControlId = $cid; Category = $ctrl.Category; Title = $ctrl.Title; FrameworkIds = $cit; Severity = $ctrl.Severity; Remediation = $ctrl.Remediation
                CurrentValue = "Permanent: $($permanentPriv.PrincipalDisplayName -join ', ')"; RequiredValue = 'All privileged roles via PIM eligible assignments only' }
        $gapText = "$($permanentPriv.Count) permanent privileged role assignment(s) found. Admins should be eligible in PIM and activate only when needed."
        if ($sdOn) {
            # Nothing was set aside because of Security Defaults, so the Gap
            # says so through the one emitter (prefix, and a CA read that
            # contradicts Security Defaults makes it not assessed).
            Add-TPSecurityDefaultsFinding @g -State 'Gap' -Detail ($gapText + $script:TPSecurityDefaultsNoExclusionNote)
        } else {
            Add-TPFinding @g -State 'Gap' -Detail "$gapText$bgNote"
        }
    } elseif (-not $eligibleCollected) {
        # Roles are clean, but we cannot say whether PIM is in use.
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'No permanent privileged assignments were found, but the PIM eligible-schedule query did not complete, so PIM adoption could not be confirmed. Not assessed.'
    } elseif ($eligibleCount -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "No permanent privileged role assignments. $eligibleCount eligible (PIM) assignment(s) configured.$bgNote"
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'PIM is available but no eligible (just-in-time) role assignments are configured. Privileged roles are not managed through PIM.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-3.3 PIM Requires MFA on Activation ───────────────────────────────────
# PIM offers two routes: "Azure MFA" ('MultiFactorAuthentication' in the
# enablement rule) and a Conditional Access authentication context. A context
# is only a label; what it requires is whatever the Conditional Access policy
# targeting its claim value grants, which may be terms of use or a compliant
# device. So the context route counts as MFA only when an enabled policy that
# targets the claim value requires MFA (every grant alternative MFA or an
# authentication strength) and reaches everyone (Get-TPCAEffectiveCoverage; an
# authentication-context policy names no application, so that reason is
# expected). A policy with neither route is a Gap; a context whose backing
# policy could not be judged, or a results file from before the two routes
# were recorded apart, is not assessed.
function Get-TPPIMAuthContextMfa {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ClaimValue)
    $ca = Get-TPRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or (Get-TPObjectField -Item $ca -Key 'Success' -Default $false) -ne $true) {
        return [pscustomobject]@{ State = 'Unknown'; Why = "Conditional Access policies were not read, so what authentication context '$ClaimValue' requires is not known" }
    }
    $pols = @(Get-TPNestedProperty -Object $ca -Path 'Data.Policies' -Default @() | Where-Object { $null -ne $_ })
    $ctxRead = @($pols | Where-Object { Test-TPFieldPresent -Item (Get-TPNestedProperty -Object $_ -Path 'Conditions.Applications' -Default $null) -Key 'AuthenticationContext' }).Count -eq $pols.Count
    if ($pols.Count -gt 0 -and -not $ctxRead) {
        return [pscustomobject]@{ State = 'Unknown'; Why = "the Conditional Access read predates the authentication-context field, so the policy behind '$ClaimValue' could not be identified" }
    }
    $targeting = @($pols | Where-Object {
        [string](Get-TPObjectField -Item $_ -Key 'State' -Default '') -eq 'enabled' -and
        @(Get-TPNestedProperty -Object $_ -Path 'Conditions.Applications.AuthenticationContext' -Default @()) -contains $ClaimValue })
    $mfa = @($targeting | Where-Object { Test-TPCAGrantRequires -Policy $_ -Any @('mfa', 'authStrength') })
    $cov = Get-TPCAEffectiveCoverage -Policies $mfa -RequiredClientAppTypes (Get-TPCAInteractiveClientAppTypes) -Ignore @('applies to no application')
    switch ($cov.Kind) {
        'Full' { return [pscustomobject]@{ State = 'Mfa'; Why = "authentication context '$ClaimValue' requires MFA for all users through $(@($cov.FullNames) -join ', ')" } }
        'Exceptions' { return [pscustomobject]@{ State = 'Unknown'; Why = "the policy requiring MFA for authentication context '$ClaimValue' excludes $(@($cov.Exceptions).Count) principal(s) ($(@($cov.Exceptions) -join ', ')); whether any of them is eligible for the role was not read" } }
        'Unproven' { return [pscustomobject]@{ State = 'Unknown'; Why = "the policies requiring MFA for authentication context '$ClaimValue' exclude different users or groups and group membership was not resolved" } }
    }
    $complete = Test-TPSectionCollected $ca 'PolicyCompleteness'
    $narrow = @($cov.Narrowed | ForEach-Object { "'$($_.Name)' $($_.Why)" })
    if (-not $complete) {
        return [pscustomobject]@{ State = 'Unknown'; Why = "no enabled policy read requires MFA for every user on authentication context '$ClaimValue', but the Conditional Access list could not be proven complete" }
    }
    $why = if ($narrow.Count) { "authentication context '$ClaimValue' requires MFA only through a narrower policy ($($narrow -join '; '))" }
           elseif ($targeting.Count) { "the enabled policy targeting authentication context '$ClaimValue' ($(@($targeting | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'DisplayName' -Default '?') }) -join ', ')) does not require MFA" }
           else { "no enabled Conditional Access policy targets authentication context '$ClaimValue', so it requires nothing" }
    return [pscustomobject]@{ State = 'NoMfa'; Why = $why }
}

function Test-TPControlAADPIMMFA {
    [CmdletBinding()] param()
    $cid = 'AAD-3.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $gov = Get-TPRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success -or @($gov.Data['PIMRolePolicies']).Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'PIM policy data not collected or PIM not licensed'; return
    }
    $sc = Get-TPPIMScopedPolicies -Policies $gov.Data['PIMRolePolicies']
    $scope = if ($sc.Scoped) { 'privileged-role' } else { 'PIM role' }
    $note  = if ($sc.Scoped) { '' } else { ' (Policy-to-role mapping was unavailable, so every role was scored, not only privileged ones.)' }
    $label = { param($p) if ($sc.Scoped) { [string](Get-TPObjectField -Item $p -Key 'RoleName' -Default '?') } else { [string](Get-TPObjectField -Item $p -Key 'PolicyId' -Default '?') } }
    $ctxCache = @{}
    $viaMfa = @(); $viaCtx = @(); $noMfa = @(); $unknown = @()
    foreach ($p in @($sc.Policies)) {
        $req = Get-TPObjectField -Item $p -Key 'RequiresMFA' -Default $null
        $enab = Get-TPObjectField -Item $p -Key 'MfaViaEnablement' -Default $null
        $ctxOn = Get-TPObjectField -Item $p -Key 'AuthContextEnabled' -Default $null
        $claim = [string](Get-TPObjectField -Item $p -Key 'AuthContextClaimValue' -Default '')
        if ($enab -eq $true) { $viaMfa += $p; continue }
        if ($req -eq $false) { $noMfa += [pscustomobject]@{ P = $p; Why = 'neither MFA nor an authentication context is required on activation' }; continue }
        if ($null -eq $req) { $unknown += [pscustomobject]@{ P = $p; Why = 'the activation rules could not be read' }; continue }
        # RequiresMFA is true but not through the enablement rule: the context route.
        if ($null -eq $enab -and $null -eq $ctxOn) { $unknown += [pscustomobject]@{ P = $p; Why = 'the results file predates recording the MFA and authentication-context routes apart' }; continue }
        if ($ctxOn -ne $true) { $noMfa += [pscustomobject]@{ P = $p; Why = 'neither MFA nor an authentication context is required on activation' }; continue }
        if (-not $claim) { $unknown += [pscustomobject]@{ P = $p; Why = 'an authentication context is required but its claim value was not recorded' }; continue }
        if (-not $ctxCache.ContainsKey($claim)) { $ctxCache[$claim] = Get-TPPIMAuthContextMfa -ClaimValue $claim }
        $r = $ctxCache[$claim]
        switch ($r.State) {
            'Mfa'   { $viaCtx += $p }
            'NoMfa' { $noMfa += [pscustomobject]@{ P = $p; Why = $r.Why } }
            default { $unknown += [pscustomobject]@{ P = $p; Why = $r.Why } }
        }
    }
    $total = @($sc.Policies).Count
    $ctxNote = if ($viaCtx.Count) { " $($viaCtx.Count) through an authentication context backed by an MFA policy ($((@($ctxCache.Values | Where-Object { $_.State -eq 'Mfa' } | ForEach-Object { $_.Why }) | Sort-Object -Unique) -join '; '))." } else { '' }
    $why = { param($list) ((@($list | Group-Object Why | ForEach-Object {
        $names = if ($sc.Scoped) { ' (' + ((@($_.Group | ForEach-Object { & $label $_.P }) | Sort-Object -Unique) -join ', ') + ')' } else { '' }
        "$($_.Count): $($_.Name)$names" })) -join '; ') }
    if ($noMfa.Count -gt 0) {
        $extra = if ($unknown.Count) { " Not assessed for $($unknown.Count) other policy(ies): $(& $why $unknown)." } else { '' }
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$($noMfa.Count) of $total $scope policy(ies) do not require MFA on activation. $(& $why $noMfa).$extra$note" -CurrentValue "$($noMfa.Count) without MFA on activation" -RequiredValue 'MFA required on activation (Azure MFA, or an authentication context whose Conditional Access policy requires MFA)' -Remediation $ctrl.Remediation
    } elseif ($total -eq 0 -or $unknown.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "Activation MFA could not be established for $($unknown.Count) $scope policy(ies): $(& $why $unknown). Not assessed.$note"
    } else {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "All $total $scope policies require MFA on activation: $($viaMfa.Count) through Azure MFA in the activation rules.$ctxNote$note"
    }
}

# ── AAD-3.4 PIM Requires Justification ───────────────────────────────────────
function Test-TPControlAADPIMJustification {
    [CmdletBinding()] param()
    $cid = 'AAD-3.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $gov = Get-TPRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success -or @($gov.Data['PIMRolePolicies']).Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM policy data not collected'; return
    }
    $sc = Get-TPPIMScopedPolicies -Policies $gov.Data['PIMRolePolicies']
    $scope = if ($sc.Scoped) { 'privileged-role' } else { 'PIM role' }
    $note  = if ($sc.Scoped) { '' } else { ' (Policy-to-role mapping was unavailable, so every role was scored, not only privileged ones.)' }
    $noJust = @($sc.Policies | Where-Object { $_.RequiresJustification -eq $false })
    $unknown = @($sc.Policies | Where-Object { $null -eq $_.RequiresJustification })
    if ($noJust.Count -gt 0) {
        $names = if ($sc.Scoped) { ' Roles: ' + (($noJust | ForEach-Object { $_.RoleName } | Sort-Object) -join ', ') + '.' } else { '' }
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$($noJust.Count) of $(@($sc.Policies).Count) $scope policy(ies) do not require justification — no audit trail for why privilege was elevated.$names$note" -Remediation $ctrl.Remediation
    } elseif (@($sc.Policies).Count -eq 0 -or $unknown.Count -gt 0) {
        # A $null RequiresJustification means the rule could not be read — never a pass.
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "Activation justification setting could not be read for $($unknown.Count) $scope policy(ies); not assessed."
    } else {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "All $(@($sc.Policies).Count) $scope policies require justification on activation.$note"
    }
}

# ── AAD-3.5 PIM GA Activation Requires Approval ──────────────────────────────
function Test-TPControlAADPIMApproval {
    [CmdletBinding()] param()
    $cid = 'AAD-3.5'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $gov = Get-TPRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success -or @($gov.Data['PIMRolePolicies']).Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM policy data not collected'; return
    }
    # Graph names every directory-role policy "DirectoryRole", so the GA policy
    # is found by its role, via the collector's policy->role map. The Global
    # Administrator built-in role template ID is a Microsoft constant, identical
    # in every tenant.
    $gaTemplateId = '62e90394-69f5-4237-9190-012177145e10'
    $gaPolicy = @($gov.Data['PIMRolePolicies'] | Where-Object {
        [string](Get-TPObjectField -Item $_ -Key 'RoleDefinitionId' -Default '') -eq $gaTemplateId
    }) | Select-Object -First 1
    if (-not $gaPolicy) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Global Administrator PIM policy could not be identified (policy-to-role assignment data not collected); not assessed.'; return
    }
    if ($null -eq (Get-TPObjectField -Item $gaPolicy -Key 'RequiresApproval')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Global Administrator PIM approval setting could not be read; not assessed.'; return
    }
    if ($gaPolicy.RequiresApproval -eq $true) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Global Administrator PIM activation requires approval.'
    } else {
        # Approval off is the setting not configured: a Gap, not half credit.
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Global Administrator PIM activation does not require approval, so any user eligible for Global Administrator can activate it alone.' -CurrentValue 'Approval not required' -RequiredValue 'Approval required to activate Global Administrator' -Remediation $ctrl.Remediation
    }
}

# ── AAD-3.6 PIM Max Activation Duration ──────────────────────────────────────
function Test-TPControlAADPIMDuration {
    [CmdletBinding()] param()
    $cid = 'AAD-3.6'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $gov = Get-TPRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success -or @($gov.Data['PIMRolePolicies']).Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM policy data not collected'; return
    }
    $sc = Get-TPPIMScopedPolicies -Policies $gov.Data['PIMRolePolicies']
    $scope = if ($sc.Scoped) { 'privileged-role' } else { 'PIM role' }
    $note  = if ($sc.Scoped) { '' } else { ' (Policy-to-role mapping was unavailable, so every role was scored, not only privileged ones.)' }
    $longDuration = @($sc.Policies | Where-Object { $null -ne $_.MaxDurationHours -and $_.MaxDurationHours -gt 8 })
    $unknownDuration = @($sc.Policies | Where-Object { $null -eq $_.MaxDurationHours })
    if ($longDuration.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail "$($longDuration.Count) $scope policy(ies) allow activation >8 hours. Shorter windows reduce blast radius.$note" -CurrentValue ">8h max duration" -RequiredValue '≤8 hours max duration'
    } elseif (@($sc.Policies).Count -eq 0 -or $unknownDuration.Count -gt 0) {
        # Previously scored Partial on an unreadable duration — a verdict the tool never computed.
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "Maximum activation duration could not be read for $($unknownDuration.Count) $scope policy(ies); not assessed."
    } else {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "All $(@($sc.Policies).Count) $scope policies have max activation ≤8 hours.$note"
    }
}

# ── AAD-4.1 Guest Invite Permissions Restricted ───────────────────────────────
function Test-TPControlAADGuestInvite {
    [CmdletBinding()] param()
    $cid = 'AAD-4.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $gov = Get-TPRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    # A failed authorizationPolicy read defaulted to 'everyone' and scored a
    # Gap ("Anyone can invite guests") on tenants that restrict invitations.
    if (-not (Test-TPSectionCollected $gov 'ExternalCollab')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'ExternalCollab was not collected; not assessed.'
        return
    }
    $inviteFrom = [string](Get-TPNestedProperty -Object $gov -Path 'Data.ExternalCollab.AllowInvitesFrom' -Default '')
    if (-not $inviteFrom) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The guest-invitation setting (allowInvitesFrom) was not returned; not assessed.'
        return
    }
    $secure     = @('adminsAndGuestInviters','admins','none')
    if ($inviteFrom -in $secure) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Guest invitations restricted to: $inviteFrom"
    } elseif ($inviteFrom -eq 'adminsGuestInvitersAndAllMembers') {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'All members can invite guests — restrict to admins only.' -CurrentValue $inviteFrom -RequiredValue 'adminsAndGuestInviters or admins'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "Anyone can invite guest users ($inviteFrom). This allows uncontrolled external access provisioning." -CurrentValue $inviteFrom -RequiredValue 'adminsAndGuestInviters' -Remediation $ctrl.Remediation
    }
}

# ── AAD-4.2 External Collaboration Settings ───────────────────────────────────
function Test-TPControlAADExternalCollab {
    [CmdletBinding()] param()
    $cid = 'AAD-4.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $gov = Get-TPRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $gov 'ExternalCollab')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'ExternalCollab was not collected; not assessed.'
        return
    }
    $collab = Get-TPNestedProperty -Object $gov -Path 'Data.ExternalCollab'
    $gaps = @()
    if (Get-TPNestedProperty -Object $collab -Path 'DefaultUserRolePermissions.AllowedToCreateTenants') { $gaps += 'Users can create new tenants' }
    # blockMsolPowerShell is no longer scored: Microsoft retired the MSOnline
    # module (April-May 2025), so the setting no longer gates any access.
    if ($gaps.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'External collaboration settings properly restricted.'
    } else {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "External collab gaps: $($gaps -join '; ')" -Remediation $ctrl.Remediation
    }
}

# ── AAD-4.3 B2B Guest Default Permissions Restricted ─────────────────────────
function Test-TPControlAADGuestPermissions {
    [CmdletBinding()] param()
    $cid = 'AAD-4.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $gov = Get-TPRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    # GuestUserRoleId: 10dae51f-b6af-4016-8d66-8c2a99b929b3 = Guest User (restricted)
    # 2af84b1e-32c8-42b7-82bc-daa82404023b = Guest User (very restricted, recommended)
    # bf6b3c49-c849-4f4c-b32d-... = Member user role (too permissive)
    # The control asks for the RESTRICTED Guest User role (2af84b1e). The
    # default Guest User role (10dae51f) is limited but still lets guests
    # enumerate groups and members. It is Microsoft's default — nothing was
    # configured — so it is a Gap (the not-configured rule), not half credit.
    $guestRoleId = [string]((Get-SafeProp (Get-SafeProp $gov.Data 'ExternalCollab') 'GuestUserRoleId') ?? '')
    if ($guestRoleId -eq '2af84b1e-32c8-42b7-82bc-daa82404023b') {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Guests have the Restricted Guest User role: they can read only their own directory objects.'
    } elseif ($guestRoleId -eq '10dae51f-b6af-4016-8d66-8c2a99b929b3') {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Guests have the same access as members (guestUserRoleId 10dae51f-b6af-4016-8d66-8c2a99b929b3), the most permissive setting: a guest can enumerate every user, group and membership in the directory. Set guest user access to Restricted (2af84b1e-32c8-42b7-82bc-daa82404023b).' -CurrentValue "RoleId: $guestRoleId (same as members)" -RequiredValue 'Restricted Guest User role' -Remediation $ctrl.Remediation
    } elseif ($guestRoleId -eq 'a0b1b346-4d3e-4e8b-98f8-753987be4970') {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Guests have the default Guest User role (guestUserRoleId a0b1b346-4d3e-4e8b-98f8-753987be4970, limited access): a guest can read the properties and memberships of the users and groups it can see. Microsoft documents this as the default; the baseline wants Restricted (2af84b1e-32c8-42b7-82bc-daa82404023b), which limits a guest to its own objects.' -CurrentValue "RoleId: $guestRoleId (limited access, the default)" -RequiredValue 'Restricted Guest User role' -Remediation $ctrl.Remediation
    } elseif ([string]::IsNullOrEmpty($guestRoleId)) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Guest role ID not available in collected data'
    } else {
        # Only the three ids Microsoft documents are judged; a fourth is not read as
        # permissive or restrictive.
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "Guest user access is set to role id $guestRoleId, which is not one of the three roles Microsoft documents (restricted, limited, same as members); not assessed." -CurrentValue "RoleId: $guestRoleId"
    }
}

# ── AAD-5.1 SSPR Enabled ──────────────────────────────────────────────────────
function Test-TPControlAADSSPR {
    [CmdletBinding()] param()
    $cid = 'AAD-5.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $auth = Get-TPRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    # Empty is not clean. AuthorizationPolicy is an independent sub-query from
    # the collector's overall Success flag — a failed read leaves it $null
    # while Success stays $true, and defaulting AllowedToUseSSPR to $false in
    # that case reported "SSPR is disabled" on tenants where it is enabled.
    if (-not (Test-TPSectionCollected $auth 'AuthorizationPolicy')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AuthorizationPolicy was not collected; not assessed.'
        return
    }
    # authorizationPolicy.allowedToUseSSPR is documented as whether
    # ADMINISTRATORS can use SSPR, not users. The user SSPR setting
    # (None / Selected / All) is not exposed by a supported Graph read, so the
    # old verdict answered a different question.
    Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title "$($ctrl.Title) (Manual review required)" -FrameworkIds $cit `
        -Detail 'This control requires manual verification — the user self-service password reset setting is not exposed by a supported read API. Check Entra ID > Protection > Password reset > Properties (Selected or All).'
}

# ── AAD-5.2 SSPR Requires Multiple Auth Methods ───────────────────────────────
function Test-TPControlAADSSPRMethods {
    [CmdletBinding()] param()
    $cid = 'AAD-5.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    # The number of methods required to reset (1 or 2) lives in the legacy
    # SSPR policy, which has no supported read API; counting the methods
    # ENABLED in the authentication methods policy ("6 methods enabled")
    # answered a different question and passed tenants requiring one method.
    Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title "$($ctrl.Title) (Manual review required)" -FrameworkIds $cit `
        -Detail 'This control requires manual verification — the number of methods required to reset a password is not exposed by a supported read API. Check Entra ID > Protection > Password reset > Authentication methods (Number of methods required to reset = 2).'
}

# ── AAD-6.1 User App Registration Disabled ────────────────────────────────────
function Test-TPControlAADUserAppReg {
    [CmdletBinding()] param()
    $cid = 'AAD-6.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $gov = Get-TPRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    # The setting is collected in two places (identity governance and the
    # AAD-AuthPolicies authorization policy). A missing value used to default
    # to "users CAN register apps" and score a High Gap — on a live tenant
    # whose raw data showed AllowedToCreateApps = false. Read either source;
    # with neither, say so instead of guessing.
    $canCreateRaw = Get-TPNestedProperty -Object $gov -Path 'Data.ExternalCollab.DefaultUserRolePermissions.AllowedToCreateApps' -Default $null
    if ($null -eq $canCreateRaw) {
        $authPol = Get-TPRawData -Key 'AAD-AuthPolicies'
        $canCreateRaw = Get-TPNestedProperty -Object $authPol -Path 'Data.AuthorizationPolicy.DefaultUserRolePermissions.AllowedToCreateApps' -Default $null
    }
    if ($null -eq $canCreateRaw) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The user app-registration setting (defaultUserRolePermissions.allowedToCreateApps) was not collected; not assessed.'; return
    }
    $canCreate = [bool]$canCreateRaw
    if (-not $canCreate) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Users cannot register applications. Only admins can create app registrations.'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Any user can register applications. Malicious OAuth apps or accidental exposure of sensitive API permissions is possible.' -CurrentValue 'AllowedToCreateApps = $true' -RequiredValue 'AllowedToCreateApps = $false' -Remediation $ctrl.Remediation
    }
}

# ── AAD-6.2 User Consent to Apps Restricted ───────────────────────────────────
function Test-TPControlAADUserConsent {
    [CmdletBinding()] param()
    $cid = 'AAD-6.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $gov = Get-TPRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    # Empty is not clean. A failed ExternalCollab sub-query leaves no consent
    # policies to inspect, and "no unrestricted consent policy found" then reads
    # as "user consent is restricted" — a false pass on the control that stops
    # consent phishing.
    if (-not (Test-TPSectionCollected $gov 'ExternalCollab')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'ExternalCollab was not collected; not assessed.'
        return
    }
    # Key presence, not the property helper: an empty list (no user consent
    # at all) would come back as $null and read as "not returned".
    $ec  = Get-TPNestedProperty -Object $gov -Path 'Data.ExternalCollab' -Default $null
    $raw = $null; $has = $false
    if ($ec -is [System.Collections.IDictionary]) { if ($ec.Contains('PermissionGrantPolicies')) { $has = $true; $raw = $ec['PermissionGrantPolicies'] } }
    elseif ($null -ne $ec -and $ec.PSObject.Properties['PermissionGrantPolicies']) { $has = $true; $raw = $ec.PermissionGrantPolicies }
    if (-not $has -or ($null -eq $raw -and $has)) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The user-consent setting (permissionGrantPoliciesAssigned) was not returned, so it was not assessed.'
        return
    }
    $consentPolicies = @(@($raw) | ForEach-Object { [string]$_ } | Where-Object { $_ -like 'ManagePermissionGrantsForSelf.*' })
    # Microsoft's built-in user consent policies (Manage app consent policies, Learn):
    #   microsoft-user-default-legacy        users can consent to ANY app permission.
    #   microsoft-user-default-low           verified publishers, low-impact permissions only.
    #   microsoft-user-default-recommended   the Microsoft-managed policy ("Let Microsoft manage your
    #                                        consent settings"), the default for new tenants: users can
    #                                        consent to any user-consentable delegated permission EXCEPT
    #                                        the file, site, mail, calendar, chat, online-meeting,
    #                                        contacts, tasks and people scopes Microsoft lists and the
    #                                        legacy mail-protocol scopes; Microsoft updates the list.
    #   microsoft-user-default-allow-consent-apps  companion policy, on by default: named mail clients
    #                                        (Apple Mail, Thunderbird, ...) may be consented for mail scopes.
    # Reading the managed policy as "custom" filed every new tenant as not assessed; it is a documented,
    # partial restriction and is judged as one. A policy that is none of these allows whatever it defines,
    # which this tool cannot evaluate, so it is not called restricted.
    $unrestrictedConsent = $consentPolicies | Where-Object { $_ -match 'legacy|ByDefault' }
    $managed  = @($consentPolicies | Where-Object { $_ -match 'microsoft-user-default-recommended$' })
    $mailApps = @($consentPolicies | Where-Object { $_ -match 'microsoft-user-(default-allow|allow-default)-consent-apps$' })
    $custom   = @($consentPolicies | Where-Object { $_ -notmatch 'microsoft-user-default-(legacy|low|recommended)$' -and $_ -notmatch 'microsoft-user-(default-allow|allow-default)-consent-apps$' })
    $mailNote = if ($mailApps.Count -gt 0) { " The companion mail-client policy ($($mailApps -join ', ')) also lets users consent to the mail clients Microsoft names (Apple Mail, Thunderbird and others) for mail scopes." } else { '' }
    # Expected state: users cannot consent freely (disabled, or limited to low-impact permissions from
    # verified publishers). The admin consent workflow is a different safeguard that AAD-6.3 owns; it is
    # shown here as related context and never decides this verdict, so one disabled workflow costs one
    # baseline failure (AAD-6.3), not two.
    $verified = @(); $short = @(); $unknown = @()
    if ($consentPolicies.Count -eq 0) {
        $verified += 'Users cannot consent to applications (no user consent policy assigned).'
    } elseif ($unrestrictedConsent) {
        $short += 'Users can consent to any app permissions. Consent phishing attacks grant attacker apps access to mailbox, files, and contacts without admin awareness.'
    } elseif ($custom.Count -gt 0) {
        $unknown += "what user consent allows, because it is governed by a custom permission grant policy ($($custom -join ', ')) that requires manual verification."
    } elseif ($managed.Count -gt 0) {
        # Partial on purpose: the managed policy is a real, Microsoft-maintained restriction (verified),
        # and still lets users consent to every other delegated permission from any publisher (shortfall).
        $verified += "The Microsoft-managed consent policy ($($managed -join ', ')) blocks user consent to the file, site, mail, calendar, chat, online-meeting, contacts, tasks and people scopes and the legacy mail-protocol scopes Microsoft lists.$mailNote"
        $short += 'Users can still consent to every other user-consentable delegated permission, from any publisher; the baseline expects user consent disabled, or limited to low-impact permissions from verified publishers.'
    } else {
        $verified += "User consent is limited to low-impact permissions for apps from verified publishers ($($consentPolicies -join ', ')).$mailNote"
    }
    $context = ''
    if (Test-TPSectionCollected $gov 'ConsentPolicy') {
        $wf = Get-TPNestedProperty -Object $gov -Path 'Data.ConsentPolicy.IsEnabled' -Default $null
        if ($wf -is [bool] -and $wf) { $context = 'the admin consent workflow is enabled (AAD-6.3).' }
        elseif ($wf -is [bool]) { $context = 'the admin consent workflow is disabled, so users who need an app have no approval path (scored under AAD-6.3).' }
    }
    # Unrestricted consent is a Gap outright; the Microsoft-managed policy's shortfall sits beside a
    # verified restriction and takes the helper's Partial.
    $shortfallState = if ($managed.Count -gt 0 -and -not $unrestrictedConsent) { 'Auto' } else { 'Gap' }
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $unknown `
        -ShortfallState $shortfallState -Context $context `
        -CurrentValue $(if ($consentPolicies.Count) { $consentPolicies -join ', ' } else { 'No user consent policy assigned' }) `
        -RequiredValue 'User consent disabled, or limited to low-impact permissions from verified publishers'
}

# ── AAD-6.3 Admin Consent Workflow Enabled ────────────────────────────────────
function Test-TPControlAADAdminConsentWorkflow {
    [CmdletBinding()] param()
    $cid = 'AAD-6.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $gov = Get-TPRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    # A failed adminConsentRequestPolicy read (403) left IsEnabled at its
    # $false default and scored "admin consent workflow disabled".
    if (-not (Test-TPSectionCollected $gov 'ConsentPolicy')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'ConsentPolicy was not collected; not assessed.'
        return
    }
    $consentEnabled = [bool](Get-TPNestedProperty -Object $gov -Path 'Data.ConsentPolicy.IsEnabled' -Default $false)
    if ($consentEnabled) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Admin consent workflow enabled — users can request app access via approval process.'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Admin consent workflow disabled. Users who need app access have no path to request it — may bypass controls or use unmanaged alternatives.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-7.1 Password Protection Lockout Configured ───────────────────────────
function Test-TPControlAADPasswordProtection {
    [CmdletBinding()] param()
    $cid = 'AAD-7.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $auth = Get-TPRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success -or -not $auth.Data['PasswordProtection']) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Password protection data not collected (the Password Rule Settings read from /v1.0/groupSettings failed or did not run).'; return
    }
    # CIS 5.2.3.8: a lockout threshold of 10 or fewer failed attempts. The
    # lockout duration (5.2.3.9) is AAD-7.3's and shows here as context only, so
    # one setting never costs two baseline failures. The collector stores
    # Microsoft's template defaults (10 and 60) when the setting was never
    # customized, and $null for a value that was present but not a whole number.
    $pp = $auth.Data['PasswordProtection']
    $lockout  = ConvertTo-TPWholeNumber (Get-TPObjectField -Item $pp -Key 'LockoutThreshold' -Default $null)
    $duration = ConvertTo-TPWholeNumber (Get-TPObjectField -Item $pp -Key 'LockoutDurationSeconds' -Default $null)
    $v = @(); $sf = @(); $ne = @()
    if ($null -eq $lockout) { $ne += 'the lockout threshold was not read as a number.' }
    elseif ($lockout -le 10) { $v += "Lockout threshold: $lockout failed attempts (10 or fewer)." }
    else { $sf += "Lockout threshold is $lockout failed attempts; it must be 10 or fewer to limit the brute-force window." }
    $ctx = if ($null -ne $duration) { "lockout duration $duration seconds (AAD-7.3)." } else { 'lockout duration not read (AAD-7.3).' }
    $tTxt = if ($null -ne $lockout) { "$lockout" } else { 'not read' }
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $v -Shortfalls $sf -NotEstablished $ne -Context $ctx `
        -CurrentValue "LockoutThreshold = $tTxt" -RequiredValue 'Lockout threshold 10 or fewer failed attempts'
}

# Parses a Password Rule Settings number: an int from the collector, or a
# string of ASCII digits from an older results file; anything else is $null.
function ConvertTo-TPWholeNumber {
    [CmdletBinding()]
    param([AllowNull()] $Value)
    if ($Value -is [int] -or $Value -is [long]) { return [long]$Value }
    $n = [long]0
    if ($null -ne $Value -and ([string]$Value) -cmatch '\A[0-9]{1,10}\z' -and [long]::TryParse([string]$Value, [ref]$n)) { return $n }
    return $null
}

# ── AAD-7.3 Smart Lockout Duration at Least 60 Seconds ───────────────────────
function Test-TPControlAADLockoutDuration {
    [CmdletBinding()] param()
    $cid = 'AAD-7.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $auth = Get-TPRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success -or -not $auth.Data['PasswordProtection']) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Password protection data not collected (the Password Rule Settings read from /v1.0/groupSettings failed or did not run).'; return
    }
    # CIS 5.2.3.9: lockout duration of at least 60 seconds (Microsoft's
    # default). An absent value in an instantiated setting, or a setting never
    # created, is that default in effect.
    $duration = ConvertTo-TPWholeNumber (Get-TPObjectField -Item $auth.Data['PasswordProtection'] -Key 'LockoutDurationSeconds' -Default $null)
    if ($null -eq $duration) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The lockout duration was not read as a whole number of seconds; not assessed.'
    } elseif ($duration -ge 60) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Smart lockout holds an account for $duration seconds after the lockout threshold is reached (at least 60)." -CurrentValue "LockoutDurationInSeconds = $duration"
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "Smart lockout holds an account for only $duration seconds; at least 60 is required, so an attacker can resume guessing almost at once." `
            -CurrentValue "LockoutDurationInSeconds = $duration" -RequiredValue 'Lockout duration at least 60 seconds' -Remediation $ctrl.Remediation
    }
}

# ── AAD-7.4 Custom Banned Password List Enforced ─────────────────────────────
function Test-TPControlAADBannedPasswords {
    [CmdletBinding()] param()
    $cid = 'AAD-7.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $auth = Get-TPRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success -or -not $auth.Data['PasswordProtection']) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Password protection data not collected (the Password Rule Settings read from /v1.0/groupSettings failed or did not run).'; return
    }
    # CIS 5.2.3.2: enforcement of the custom list on, and the list holding
    # entries. The entries themselves are never collected, only their count
    # (BannedPasswordCount; an older results file carries only whether the list
    # was non-empty).
    $pp = $auth.Data['PasswordProtection']
    $enforced = Get-TPObjectField -Item $pp -Key 'EnableBannedPasswordCheck' -Default $null
    $count = ConvertTo-TPWholeNumber (Get-TPObjectField -Item $pp -Key 'BannedPasswordCount' -Default $null)
    $present = Get-TPObjectField -Item $pp -Key 'BannedPasswordListPresent' -Default $null
    $v = @(); $sf = @(); $ne = @()
    if ($enforced -eq $true) { $v += 'Enforce custom list is on.' }
    elseif ($enforced -eq $false) { $sf += 'Enforce custom list is off, so the custom banned passwords are not applied.' }
    else { $ne += 'whether the custom list is enforced was not read.' }
    if ($null -ne $count) {
        if ($count -gt 0) { $v += "The custom banned password list holds $count entries." } else { $sf += 'The custom banned password list is empty.' }
    } elseif ($present -eq $true) { $v += 'The custom banned password list holds entries.' }
    elseif ($present -eq $false) { $sf += 'The custom banned password list is empty.' }
    else { $ne += 'whether the custom list holds entries was not read.' }
    $cv = "EnableBannedPasswordCheck = $(if ($null -eq $enforced) { 'not read' } else { $enforced }); entries = $(if ($null -ne $count) { $count } elseif ($null -ne $present) { if ($present) { 'some' } else { 0 } } else { 'not read' })"
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $v -Shortfalls $sf -NotEstablished $ne `
        -CurrentValue $cv -RequiredValue 'Enforce custom list on, with the organization''s own terms in the list'
}

# ── AAD-7.5 Passwords Set to Never Expire ────────────────────────────────────
function Test-TPControlAADPasswordExpiry {
    [CmdletBinding()] param()
    $cid = 'AAD-7.5'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $auth = Get-TPRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AAD-AuthPolicies collector did not run; not assessed.'; return
    }
    # The Domains section is new: an older results file has no status for it and
    # no list, and must not read as "no domains, nothing expires".
    $status = Get-TPNestedProperty -Object $auth -Path 'Data.SectionStatus.Domains' -Default $null
    if ([string]$status -ne 'Collected') {
        $why = if ($null -eq $status) { 'were not read (a results file from before this check)' } else { "were not read (section $status)" }
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "Domain password validity periods $why; not assessed."; return
    }
    # CIS 1.3.1: every domain's passwordValidityPeriodInDays is 2147483647
    # ("never expire"). Microsoft: an unset value means the 90-day default.
    # Unverified domains cannot be used to sign in and are not judged.
    $never = 2147483647
    $doms = @(@(Get-TPNestedProperty -Object $auth -Path 'Data.Domains' -Default @()) | Where-Object { $null -ne $_ -and (Get-TPObjectField -Item $_ -Key 'IsVerified' -Default $null) -eq $true })
    if ($doms.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'No verified domain was returned; not assessed.'; return
    }
    $ok = @(); $bad = @(); $unk = @(); $fed = @()
    foreach ($d in $doms) {
        $id = [string](Get-TPObjectField -Item $d -Key 'Id' -Default '')
        if ([string](Get-TPObjectField -Item $d -Key 'AuthenticationType' -Default '') -eq 'Federated') { $fed += $id }
        $set = Get-TPObjectField -Item $d -Key 'PasswordValiditySet' -Default $null
        $days = ConvertTo-TPWholeNumber (Get-TPObjectField -Item $d -Key 'PasswordValidityPeriodInDays' -Default $null)
        if ($null -ne $days -and $days -eq $never) { $ok += $id }
        elseif ($null -ne $days) { $bad += "$id ($days days)" }
        elseif ($set -eq $false) { $bad += "$id (not set: Microsoft's 90-day default)" }
        else { $unk += $id }
    }
    $v = @(); $sf = @(); $ne = @()
    if ($ok.Count)  { $v  += "Passwords never expire on $($ok.Count) verified domain(s): $(@($ok | Select-Object -First 5) -join ', ')$(if ($ok.Count -gt 5) { ", and $($ok.Count - 5) more" })." }
    if ($bad.Count) { $sf += "Passwords expire on $($bad.Count) verified domain(s): $(@($bad | Select-Object -First 5) -join ', ')$(if ($bad.Count -gt 5) { ", and $($bad.Count - 5) more" }). Forced periodic changes push users to predictable patterns (NIST SP 800-63B)." }
    if ($unk.Count) { $ne += "the password validity period of $($unk -join ', ') was not read as a number." }
    $ctx = if ($fed.Count) { "federated domain(s) $($fed -join ', ') take their password policy from the federation provider, which this check does not read." } else { '' }
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $v -Shortfalls $sf -NotEstablished $ne -Context $ctx `
        -CurrentValue "$($ok.Count) of $($doms.Count) verified domain(s) set to never expire" -RequiredValue 'passwordValidityPeriodInDays = 2147483647 (never expire) on every verified domain'
}

# ── AAD-7.2 Break-Glass Accounts Configured ───────────────────────────────────
function Test-TPControlAADBreakGlass {
    [CmdletBinding()] param()
    $cid = 'AAD-7.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $gov = Get-TPRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    # Security Defaults cannot be scoped, so an administrator cannot exclude
    # any account from it, and this control recognizes break-glass accounts
    # only by CA exclusion — never credit for a stale CAExcluded, and never
    # the "if CA policies break" Gap. What the role data CAN prove still
    # decides: Microsoft recommends two cloud-only emergency access accounts
    # PERMANENTLY assigned Global Administrator, so with fewer than two
    # permanent Global Administrator assignments on accounts not marked as
    # synchronized, the recommendation is provably unmet (a Gap). Only with
    # two or more such candidates does the answer turn on which accounts they
    # are, and the finding says that requires manual verification
    # (Get-TPAssessmentScope files it for manual review). Runs before the
    # BreakGlassIndicators gate, which reads NotRun whenever the CA read
    # failed.
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        $sdBg = @{ ControlId = $cid; Category = $ctrl.Category; Title = $ctrl.Title; FrameworkIds = $cit }
        $noExclusion = "It cannot be scoped or customized (Microsoft: 'No customization (on or off)'), so an administrator cannot exclude any account from it (its only exclusion is Microsoft's automatic one for directory synchronization accounts), and this control recognizes emergency access (break-glass) accounts only by their exclusion from Conditional Access policies in force."
        $verify = "confirm they exist, that their credentials are held offline, and that each has an MFA method registered, because Security Defaults requires Global Administrators to complete MFA at every sign-in"
        if (-not (Test-TPSectionCollected $gov 'BreakGlassIndicators')) {
            Add-TPSecurityDefaultsFinding @sdBg -State 'NotApplicable' `
                -Detail "$noExclusion Microsoft recommends two cloud-only emergency access accounts permanently assigned Global Administrator; the Global Administrator list this check reads (BreakGlassIndicators) was not collected, so whether they exist was not assessed." `
                -RequiredValue 'Two cloud-only emergency access Global Administrator accounts, permanently assigned (confirm manually while Security Defaults is on)'
            return
        }
        $all = @(@(Get-TPNestedProperty -Object $gov -Path 'Data.BreakGlassIndicators' -Default @()) | Where-Object { $null -ne $_ })
        if ($all.Count -eq 0) {
            Add-TPSecurityDefaultsFinding @sdBg -State 'NotApplicable' -Detail 'No Global Administrator accounts were found to evaluate.'
            return
        }
        # Synced is OnPremisesSyncEnabled -eq $true, so $null (Graph's
        # never-synchronized value, or a value not read) is a candidate: the
        # prose says "not marked as synchronized", what was read. Source is
        # 'permanent' or 'eligible' (the collector defaults a missing one to
        # 'permanent'); a PIM-eligible Global Administrator is not the
        # permanently assigned account Microsoft recommends.
        $seen = [System.Collections.Generic.HashSet[string]]::new()
        $cand = @($all | Where-Object {
            (Get-TPObjectField -Item $_ -Key 'Synced' -Default $false) -ne $true -and
            [string](Get-TPObjectField -Item $_ -Key 'Source' -Default 'permanent') -eq 'permanent'
        } | Where-Object {
            $k = [string](Get-TPObjectField -Item $_ -Key 'PrincipalId' -Default '')
            if (-not $k) { $k = [string](Get-TPObjectField -Item $_ -Key 'UPN' -Default ([guid]::NewGuid().ToString())) }
            $seen.Add($k)
        })
        $syncedN   = @($all | Where-Object { (Get-TPObjectField -Item $_ -Key 'Synced' -Default $false) -eq $true }).Count
        $eligibleN = @($all | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'Source' -Default 'permanent') -ne 'permanent' }).Count
        $names = @($cand | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'DisplayName' -Default '') } | Where-Object { $_ }) -join ', '
        $read  = "$($all.Count) Global Administrator assignment(s) were read ($syncedN on accounts marked as synchronized from on-premises, $eligibleN PIM-eligible)"
        $current = "Permanent Global Administrator assignments on accounts not marked as synchronized from on-premises: $($cand.Count)$(if ($names) { " ($names)" })"
        $required = 'Two cloud-only emergency access Global Administrator accounts, permanently assigned'
        $bgFix = 'Keep two cloud-only emergency access accounts permanently assigned Global Administrator (create whichever are missing), with long random passwords held offline, and register an MFA method for each (Security Defaults requires Global Administrators to complete MFA at every sign-in). When Conditional Access replaces Security Defaults, exclude both from every policy that would otherwise reach them, and monitor their sign-ins.'
        if ($cand.Count -eq 0) {
            Add-TPSecurityDefaultsFinding @sdBg -State 'Gap' -Severity $ctrl.Severity `
                -Detail "$read, and none is a permanent assignment on an account not marked as synchronized from on-premises. Microsoft recommends two cloud-only emergency access accounts permanently assigned Global Administrator, so no emergency access account of the recommended kind exists." `
                -CurrentValue $current -RequiredValue $required -Remediation $bgFix
        } elseif ($cand.Count -eq 1) {
            Add-TPSecurityDefaultsFinding @sdBg -State 'Gap' -Severity $ctrl.Severity `
                -Detail "$read, and only one is a permanent assignment on an account not marked as synchronized from on-premises. Microsoft recommends two cloud-only emergency access accounts permanently assigned Global Administrator, so the two-account recommendation is not met. Whether this one account is kept as an emergency access account could not be determined, because Security Defaults offers no exclusion to recognize it by." `
                -CurrentValue $current -RequiredValue $required -Remediation $bgFix
        } else {
            Add-TPSecurityDefaultsFinding @sdBg -State 'NotApplicable' `
                -Detail "$noExclusion Microsoft recommends two cloud-only emergency access accounts permanently assigned Global Administrator. $($cand.Count) permanent Global Administrator assignment(s) are on accounts not marked as synchronized from on-premises; whether two of them are emergency access accounts requires manual verification: $verify." `
                -CurrentValue $current -RequiredValue "$required (confirm manually while Security Defaults is on)"
        }
        return
    }
    # Without the CA data the exclusion check never ran (NotRun): every
    # CAExcluded is a default $false, and reading that as "no break-glass
    # accounts" was a false Gap.
    if (-not (Test-TPSectionCollected $gov 'BreakGlassIndicators')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'BreakGlassIndicators was not collected (role or Conditional Access data missing); not assessed.'
        return
    }
    $bgAccounts = @($gov.Data['BreakGlassIndicators'] | Where-Object { $_.CAExcluded -eq $true -and -not $_.Synced })
    $unknownBg  = @($gov.Data['BreakGlassIndicators'] | Where-Object { $null -eq $_.CAExcluded -and -not $_.Synced })
    $allGAs     = @($gov.Data['BreakGlassIndicators'])
    # The requirement is unchanged: excluded from EVERY enabled Conditional
    # Access policy that reaches the account (Microsoft: policies that block or
    # restrict sign-in; report-only ones are not counted). What is new is
    # naming. A cloud-only GA excluded from every policy with a grant control
    # but still reached by session-only policies is a CANDIDATE: probably the
    # break-glass account, with named policies left to exclude. A GA still
    # reached by one or two grant policies is named the same way. Older
    # results carry neither list and add nothing.
    $nameOf = { param($a) "$([string](Get-TPObjectField -Item $a -Key 'DisplayName' -Default '')) ($([string](Get-TPObjectField -Item $a -Key 'UPN' -Default '')))" }
    $quote  = { param($list) (@($list | ForEach-Object { "'$_'" })) -join ', ' }
    $candidates = @($allGAs | Where-Object { $_.CAExcluded -eq $false -and -not $_.Synced -and (Get-TPObjectField -Item $_ -Key 'BlockingExcluded' -Default $false) -eq $true })
    $candidateNotes = @($candidates | ForEach-Object {
        $left = @(@(Get-TPObjectField -Item $_ -Key 'NotExcludedFrom' -Default @()) | Where-Object { $_ })
        "$(& $nameOf $_) is excluded from every policy with a grant control but is still reached by $(& $quote $left) (session controls only)"
    })
    $nearMiss = @($allGAs | Where-Object { $_.CAExcluded -eq $false -and -not $_.Synced -and (Get-TPObjectField -Item $_ -Key 'BlockingExcluded' -Default $false) -ne $true } | ForEach-Object {
        $left = @(@(Get-TPObjectField -Item $_ -Key 'NotExcludedFrom' -Default @()) | Where-Object { $_ })
        if ($left.Count -ge 1 -and $left.Count -le 2) { "$(& $nameOf $_) is still reached by $(& $quote $left)" }
    })
    $notes = @($candidateNotes) + @($nearMiss)
    $nearNote = if ($notes.Count -gt 0) { " Not excluded from every enabled policy: $($notes -join '; '). Microsoft recommends excluding emergency access accounts from policies that block or restrict sign-in; exclude these accounts from the named policies too." } else { '' }
    if ($bgAccounts.Count -lt 2 -and $unknownBg.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "$($unknownBg.Count) Global Administrator account(s) may be excluded through a group whose membership could not be read, so break-glass coverage was not assessed."
    } elseif ($bgAccounts.Count -ge 2) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($bgAccounts.Count) cloud-only GA account(s) are excluded from every enabled Conditional Access policy that reaches them, consistent with the break-glass pattern."
    } elseif ($bgAccounts.Count -eq 1) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "Only one cloud-only GA is excluded from every enabled Conditional Access policy that reaches it. Best practice is two break-glass accounts for redundancy.$nearNote" -CurrentValue '1 break-glass account' -RequiredValue '2 break-glass accounts'
    } elseif ($candidates.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "No cloud-only GA is excluded from every enabled Conditional Access policy, but $($candidates.Count) is excluded from every policy that can deny sign-in through a grant control.$nearNote" -CurrentValue "$($candidates.Count) candidate break-glass account(s), still reached by session-only policies" -RequiredValue '2 break-glass accounts excluded from every enabled policy' -Remediation $ctrl.Remediation
    } elseif ($allGAs.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "No cloud-only GA account is excluded from every enabled Conditional Access policy that reaches it, so a misconfigured policy could leave no emergency access path to the tenant.$nearNote" -Remediation $ctrl.Remediation
    } else {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'No GA accounts found to evaluate'
    }
}

# ── AAD-8.1 PIM Alerts Configured ────────────────────────────────────────────
function Test-TPControlAADPIMAlerts {
    [CmdletBinding()] param()
    $cid = 'AAD-8.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pim = Get-TPRawData -Key 'AAD-PIMSchedules'
    if (-not $pim -or -not $pim.PIMAvailable) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'PIM not available (requires Entra P2)'; return
    }
    # PIM alert configuration (Roles assigned outside PIM / Redundant roles /
    # Stale assignments) requires GET /beta/privilegedAccess/aadRoles/alerts,
    # which is not collected — this control has no programmatic check today.
    # It must emit NotApplicable, never Partial: Partial is worth 0.5 toward
    # the compliance score, so an unconditional Partial here handed every
    # Entra P2 tenant free credit for a verdict the tool never computed.
    Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Medium' -FrameworkIds $cit `
        -Detail 'This control requires manual verification — PIM alert configuration is not exposed to the APIs this assessment uses. Verify in PIM > Alerts: Roles assigned outside PIM, Redundant roles, Stale assignments.' `
        -Remediation $ctrl.Remediation
}

# ── AAD-8.2 Access Reviews for Privileged Roles ───────────────────────────────
function Test-TPControlAADAccessReviews {
    [CmdletBinding()] param()
    $cid = 'AAD-8.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pim = Get-TPRawData -Key 'AAD-PIMSchedules'
    if (-not $pim -or -not $pim.PIMAvailable) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'PIM not available — access reviews require Entra P2'; return
    }
    # Access review definitions need the AccessReview.Read.All scope, which is a
    # re-consent scope (like AAD-11.3 / DEF-4.6). Until the enterprise app is
    # re-consented the collector can't read them — report NotApplicable, never a
    # false "no reviews" gap.
    if (-not $pim.AccessReviewsCollected) {
        $why = if (Test-TPGraphScopeMissing -Scope 'AccessReview.Read.All') { Get-TPConsentMissingDetail -Scope 'AccessReview.Read.All' }
               else { 'Access review data not collected — requires the AccessReview.Read.All scope (re-consent the enterprise app in each tenant). Verify manually in PIM > Microsoft Entra roles > Access reviews.' }
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit -Detail $why
        return
    }
    $reviews = @($pim.Data['AccessReviews'] ?? @())
    $activeStatuses = @('InProgress', 'NotStarted', 'Applying', 'Applied')
    $roleReviews = @($reviews | Where-Object {
        (Get-TPObjectField -Item $_ -Key 'TargetsRoles') -eq $true -and
        ([string](Get-TPObjectField -Item $_ -Key 'Status')) -in $activeStatuses
    })
    # A role review that ran once and finished recertified access at one point
    # in time; nothing re-reviews it. Part-way, not "no role reviews".
    $pastRoleReviews = @($reviews | Where-Object {
        (Get-TPObjectField -Item $_ -Key 'TargetsRoles') -eq $true -and
        ([string](Get-TPObjectField -Item $_ -Key 'Status')) -notin $activeStatuses
    })
    if ($roleReviews.Count -eq 0 -and $pastRoleReviews.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "$($pastRoleReviews.Count) access review(s) of privileged roles exist but none is active or recurring ($(($pastRoleReviews | ForEach-Object { "$(Get-TPObjectField -Item $_ -Key 'DisplayName' -Default '?') [$(Get-TPObjectField -Item $_ -Key 'Status' -Default '?')]" }) -join ', ')). Role assignments are not re-attested going forward." `
            -CurrentValue 'Role review completed, not recurring' -RequiredValue 'A recurring access review scoped to privileged directory roles' -Remediation $ctrl.Remediation
    } elseif ($roleReviews.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($roleReviews.Count) active access review(s) recertify privileged directory-role assignments. Standing admin access is periodically re-attested instead of accumulating unchecked." `
            -CurrentValue "$($roleReviews.Count) role access review(s) active"
    } elseif ($reviews.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "$($reviews.Count) access review(s) exist but none target privileged directory roles. Groups/apps are reviewed, but Global Admin and other privileged role assignments are not recertified." `
            -CurrentValue 'Access reviews present, none for privileged roles' `
            -RequiredValue 'A recurring access review scoped to privileged directory roles' `
            -Remediation $ctrl.Remediation
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No access reviews are configured. Privileged role assignments are never recertified, so stale or over-provisioned admin access accumulates unnoticed.' `
            -CurrentValue 'No access reviews configured' `
            -RequiredValue 'A recurring access review scoped to privileged directory roles' `
            -Remediation $ctrl.Remediation
    }
}

# ── AAD-9.1 Authenticator Number Matching Enabled ────────────────────────────
function Test-TPControlAADAuthenticatorNumberMatch {
    [CmdletBinding()] param()
    $cid = 'AAD-9.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $auth = Get-TPRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $auth 'AuthMethodsPolicy')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AuthMethodsPolicy was not collected; not assessed.'
        return
    }
    # Enforced by the platform. Microsoft has required number matching for every
    # Microsoft Authenticator push notification since May 2023 and users cannot
    # opt out (Learn: How number matching works in MFA push notifications). The
    # property this control used to read, featureSettings.numberMatchingRequiredState,
    # no longer exists in Graph v1.0 (microsoftAuthenticatorFeatureSettings defines
    # only displayAppInformationRequiredState and displayLocationInformationRequiredState),
    # so the read always came back empty and the control scored Satisfied from
    # nothing on every tenant. There is no tenant setting to read or score; the
    # TMS-2.5 pattern applies: not applicable, never a pass.
    Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
        -Detail 'Enforced by the platform: Microsoft requires number matching for every Microsoft Authenticator push notification (since May 2023) and users cannot opt out, so there is no tenant setting to read or score. The Graph property this control once read (numberMatchingRequiredState) no longer exists. Not scored; MFA fatigue protection beyond number matching is the additional-context settings (application name and location), which this assessment does not score.'
}

# ── AAD-9.2 Passwordless Auth Methods Available ───────────────────────────────
function Test-TPControlAADPasswordless {
    [CmdletBinding()] param()
    $cid = 'AAD-9.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $auth = Get-TPRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $auth 'AuthMethodsPolicy')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AuthMethodsPolicy was not collected; not assessed.'
        return
    }
    $ampConfigs = @(Get-TPNestedProperty -Object $auth -Path 'Data.AuthMethodsPolicy.AuthenticationMethodConfigs' -Default @())
    # Passwordless methods in the authentication methods policy: FIDO2 /
    # passkeys, Microsoft Authenticator in passwordless-capable mode ('any' or
    # 'deviceBasedPush'), and certificate-based authentication. There is no
    # 'WindowsHello' method configuration (WHfB is device-side), so reading it
    # found nothing, and Authenticator phone sign-in was ignored.
    $on = { param($id) $ampConfigs | Where-Object { (Get-SafeProp $_ 'Id') -eq $id -and [string](Get-SafeProp $_ 'State') -eq 'enabled' } | Select-Object -First 1 }
    $methods = @()
    if (& $on 'Fido2') { $methods += 'FIDO2 / passkeys' }
    $ma = & $on 'MicrosoftAuthenticator'
    if ($ma -and @(@(Get-TPObjectField -Item $ma -Key 'AuthenticationModes' -Default @()) | Where-Object { $_ -in @('any','deviceBasedPush') }).Count -gt 0) { $methods += 'Microsoft Authenticator phone sign-in' }
    if (& $on 'X509Certificate') { $methods += 'certificate-based authentication' }
    if ($methods.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Passwordless methods enabled: $($methods -join ', ')."
    } else {
        # Nothing enabled is not configured: a Gap, not half credit.
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit `
            -Detail 'No passwordless authentication method is enabled (FIDO2/passkeys, Authenticator phone sign-in, or certificate-based authentication).' `
            -Remediation $ctrl.Remediation
    }
}

# ── AAD-10.1 Identity Protection Risky User Workflow ─────────────────────────
function Test-TPControlAADIdentityProtection {
    [CmdletBinding()] param()
    $cid = 'AAD-10.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        Add-TPSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No Conditional Access user risk policy can be turned on while Security Defaults is enabled, and Security Defaults has no configurable user risk policy of its own (Microsoft lists user and sign-in risk-based policies as what organizations with Microsoft Entra ID P2 add after moving to Conditional Access), so neither provides an automated response to user risk. The legacy Identity Protection user risk policy (retiring October 1, 2026) is not read by this tool.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access user risk policy in force' -RequiredValue 'Enabled CA policy with a user risk condition' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca = Get-TPRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    # Check for user risk policy as proxy for Identity Protection workflow
    $userRiskPolicies = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and @($_.Conditions.UserRiskLevels).Count -gt 0
    })
    if ($userRiskPolicies.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'User risk CA policy is active — Identity Protection risk signals are actioned automatically.'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No automated response to user risk: accounts Identity Protection detects as compromised are not remediated until someone acts on the alert. (Needs Entra ID P2; on a tenant without it this control is not scored.)' `
            -Remediation $ctrl.Remediation
    }
}

# ── AAD-10.2 Privileged Accounts Dedicated Cloud-Only ────────────────────────
function Test-TPControlAADPrivCloudOnly {
    [CmdletBinding()] param()
    $cid = 'AAD-10.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $roles = Get-TPRawData -Key 'AAD-DirectoryRoles'
    if (-not $roles -or -not $roles.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Directory role data not collected'; return
    }
    # AllPrivilegedAssignments includes PIM-eligible assignments: a synced
    # account eligible for Global Administrator escalates on-premises
    # compromise to the tenant exactly as a permanent one does.
    $privPool = @(Get-TPNestedProperty -Object $roles -Path 'Data.AllPrivilegedAssignments' -Default @())
    if ($privPool.Count -eq 0) { $privPool = @($roles.Data['PrivRoles']) }
    $seen10 = [System.Collections.Generic.HashSet[string]]::new()
    $syncedPriv = @($privPool | Where-Object {
        $_.OnPremisesSyncEnabled -eq $true -and $_.PrincipalType -notmatch 'servicePrincipal' -and
        $seen10.Add([string](Get-TPObjectField -Item $_ -Key 'PrincipalId' -Default (Get-TPObjectField -Item $_ -Key 'PrincipalUPN' -Default ([guid]::NewGuid().ToString()))))
    })
    if (@($roles.Data['PrivRoles']).Count -eq 0 -and -not (Test-TPRoleSectionCollected -Roles $roles -Section 'RoleAssignments')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title `
            -Detail 'Role assignment enumeration did not complete (see Exceptions) — on-premises synced privileged accounts could not be assessed.'
        return
    }
    # PrivRoles is derived from the same roleDefinitions lookup as AAD-11.2
    # (IsPriv = privRoleNames -contains RoleDefinitionName) and carries no
    # SectionStatus of its own — a failed lookup degrades every
    # RoleDefinitionName to the raw GUID, IsPriv never matches, and PrivRoles
    # empties silently regardless of what is actually assigned, so "no synced
    # privileged accounts" was reported from role data that was never
    # resolved. Check the raw RoleAssignments list, which still carries the
    # (possibly-degraded) names, for that signature directly.
    if (-not (Test-TPRoleNamesResolved -Assignments $roles.Data['RoleAssignments'])) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'Role definition names did not resolve (role-template lookup failed), so on-premises synced privileged accounts could not be reliably identified by role name. Not assessed.'
        return
    }
    if ($syncedPriv.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'No privileged role assignments are using on-premises synced accounts.'
    } else {
        # v4.6.4 PII FIX: prior code interpolated the full PrincipalUPN list into
        # Detail (renders in HTML client report → PII leak). Move UPNs to the
        # structured AffectedObjects field; keep Detail count-only.
        $affected = @($syncedPriv | ForEach-Object {
            [ordered]@{
                DisplayName    = [string]$_.PrincipalUPN
                AssignmentType = 'OnPremSyncedPrivilegedRole'
            }
        })
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($syncedPriv.Count) privileged account(s) are synced from on-premises AD. On-prem compromise directly escalates to cloud tenant. See AffectedObjects for the per-account list." `
            -CurrentValue "Synced privileged accounts: $($syncedPriv.Count)" `
            -RequiredValue 'Zero synced accounts in privileged roles' -Remediation $ctrl.Remediation `
            -AffectedObjects $affected
    }
}

# ── AAD-10.3 Emergency Access Account Monitoring ─────────────────────────────
function Test-TPControlAADBreakGlassMonitoring {
    [CmdletBinding()] param()
    $cid = 'AAD-10.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $gov = Get-TPRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    # Whether an alert fires on a break-glass sign-in is configured in
    # Sentinel / Defender XDR / a log-analytics rule, none of which this tool
    # reads. It used to PASS whenever two break-glass accounts existed —
    # "Verify sign-in alerts are configured" beside a Satisfied verdict.
    Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title "$($ctrl.Title) (Manual review required)" -FrameworkIds $cit `
        -Detail 'This control requires manual verification — sign-in alerting for break-glass accounts lives in Microsoft Sentinel, Defender XDR or Azure Monitor, which this assessment does not read. Confirm an alert rule fires on any sign-in by each break-glass account.'
}

# ── AAD-10.4 User Sign-in Frequency Session Control ─────────────────────────
function Test-TPControlAADSignInFrequency {
    [CmdletBinding()] param()
    $cid = 'AAD-10.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        Add-TPSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No sign-in frequency session control is in force: session controls are a Conditional Access feature Security Defaults does not provide, so sign-in sessions follow the default rolling window of up to 90 days and a stolen token stays usable within it.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access policy in force' -RequiredValue 'Enabled CA policy with a sign-in frequency session control' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca = Get-TPRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    Add-TPCAPolicyTierFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $ca.Data['Policies'] `
        -Match { (Get-TPNestedProperty -Object $_ -Path 'SessionControls.SignInFrequency.IsEnabled') -eq $true -and
                 # "Every time" on a risk-conditioned policy (Microsoft's
                 # risky-sign-in template) re-prompts only risky sign-ins; it
                 # is not a periodic re-authentication limit.
                 [string](Get-TPNestedProperty -Object $_ -Path 'SessionControls.SignInFrequency.FrequencyInterval' -Default '') -ne 'everyTime' -and
                 @(Get-TPNestedProperty -Object $_ -Path 'Conditions.SignInRiskLevels' -Default @()).Count -eq 0 -and
                 @(Get-TPNestedProperty -Object $_ -Path 'Conditions.UserRiskLevels' -Default @()).Count -eq 0 } `
        -What 'A sign-in frequency session control' `
        -EnabledDetail 'a sign-in frequency session control forces periodic re-authentication, limiting stolen token lifetime.' `
        -MissingDetail 'no Conditional Access policy sets a sign-in frequency. Stolen tokens remain valid for the default session lifetime (up to 90 days).' `
        -RequiredValue 'Enabled CA policy with a sign-in frequency session control'
}

# ── AAD-11.1 Device Code Authentication Flow Blocked ─────────────────────────
function Test-TPControlAADDeviceCode {
    [CmdletBinding()] param()
    $cid = 'AAD-11.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        Add-TPSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Satisfied' -Severity 'Informational' `
            -Detail 'Device code flow is blocked by Security Defaults. Microsoft documents: ''After security defaults are enabled in your tenant, authentication requests that use device code flow are blocked''; applications or devices that depend on it cannot complete sign-in while Security Defaults is enabled.' `
            -CurrentValue 'Device code flow blocked by Security Defaults' -RequiredValue 'Device code flow blocked for all users (Conditional Access policy or Security Defaults)'
        return
    }
    # The signal IS collected: Invoke-TPCollectAADCAPolicies stores each policy's
    # authentication-flow condition as Conditions.AuthFlows (the raw Graph
    # authenticationFlows object, which carries transferMethods). A CA policy that
    # blocks device code has transferMethods containing 'deviceCode'.
    $ca = Get-TPRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Conditional Access policy data not collected'; return
    }
    # Security Defaults not read and no CA policy On: it may be on (Satisfied)
    # or off (the Gap below). An unread state is never "disabled".
    if (Test-TPSecurityDefaultsUnresolved) {
        Add-TPSecurityDefaultsUnreadFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Question 'whether device code flow is blocked' `
            -IfOn 'it blocks authentication requests that use device code flow' `
            -IfOff 'no Conditional Access policy blocks it'
        return
    }
    $dcPolicies = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and
        ((@($_.Conditions.AuthFlows) | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'transferMethods') }) -join ',') -match 'deviceCode' -and
        # A policy that scopes device code but only requires MFA still lets
        # the flow run — the phishing kits relay the MFA prompt too.
        (Test-TPCAGrantRequires -Policy $_ -Any @('block'))
    })
    # Combined coverage: all users, all applications, no extra condition; exclusions are
    # judged across every qualifying policy (see Get-TPCAEffectiveCoverage).
    $cov = Get-TPCAEffectiveCoverage -Policies $dcPolicies
    if ($cov.Kind -ne 'None' -or @($cov.Narrowed).Count -gt 0) {
        $cv = Get-TPCACoverageVerdict -Coverage $cov -What 'The device code authentication flow is blocked'
        Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit `
            -Verified $cv.Verified -Shortfalls $cv.Shortfalls -NotEstablished $cv.NotEstablished -AffectedObjects $cv.AffectedObjects `
            -CurrentValue "Device code flow block: $($cov.Kind) coverage$(if ($cov.Names.Count) { ' by ' + ($cov.Names -join ', ') })" `
            -RequiredValue 'CA policy blocking the device code flow for all users on all applications (or Security Defaults)'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Device code authentication flow is not blocked. Attackers use this flow in phishing campaigns where victims visit a URL and enter a code — no password required to compromise the account.' -CurrentValue 'No CA policy blocks deviceCodeFlow' -RequiredValue 'CA policy blocking deviceCodeFlow for all users' -Remediation $ctrl.Remediation
    }
}

# ── AAD-11.2 No Guest Users in Highly Privileged Roles ───────────────────────
# A guest is a user whose userType is Guest (Microsoft's definition, the one the
# Zero Trust check reads) or whose UPN carries #EXT#; a privileged role is one in
# the tool's own lists or one Microsoft marks isPrivileged (beta role
# definitions, read by the roles collector as IsPrivileged / PrivilegedRoleIds).
# Permanent AND eligible assignments count: an eligible guest can activate.
# Satisfied needs every input that could hide a guest: both assignment reads,
# Microsoft's privileged flags, resolved role names, and a userType on every
# user principal. A results file from before userType or the flags were read is
# not assessed, never a pass.
function Test-TPControlAADNoGuestInPrivRoles {
    [CmdletBinding()] param()
    $cid = 'AAD-11.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $roles = Get-TPRawData -Key 'AAD-DirectoryRoles'
    if (-not $roles -or -not $roles.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Directory role data not collected'; return
    }
    $privRoleNames = @(
        'Global Administrator','Privileged Role Administrator','Security Administrator',
        'Exchange Administrator','SharePoint Administrator','Teams Administrator',
        'Application Administrator','Cloud Application Administrator','Conditional Access Administrator',
        'Intune Administrator','User Administrator','Authentication Policy Administrator'
    )
    if (@($roles.Data['RoleAssignments']).Count -eq 0 -and -not (Test-TPRoleSectionCollected -Roles $roles -Section 'RoleAssignments')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'Role assignment enumeration did not complete (see Exceptions) — guest privileged access could not be assessed.'
        return
    }
    # The collector's roleDefinitions sub-query is independent of the
    # assignments read; a failed lookup degrades every RoleDefinitionName to the
    # raw role-template GUID, so the name match finds nothing.
    if (-not (Test-TPRoleNamesResolved -Assignments $roles.Data['RoleAssignments'])) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'Role definition names did not resolve (role-template lookup failed), so guest privileged-role membership could not be reliably identified by role name. Not assessed.'
        return
    }
    $flagsRead = [string](Get-TPNestedProperty -Object $roles -Path 'Data.SectionStatus.PrivilegedRoleFlags' -Default '') -eq 'Collected'
    $msPriv = @{}
    foreach ($rid in @(Get-TPNestedProperty -Object $roles -Path 'Data.PrivilegedRoleIds' -Default @() | Where-Object { $_ })) { $msPriv[[string]$rid] = $true }
    $eligStatus = [string](Get-TPNestedProperty -Object $roles -Path 'Data.SectionStatus.RoleEligibilitySchedules' -Default '')
    $eligRead = $eligStatus -eq 'Collected'
    $pool = @(@(Get-TPNestedProperty -Object $roles -Path 'Data.RoleAssignments' -Default @()) +
              @(Get-TPNestedProperty -Object $roles -Path 'Data.RoleEligibilitySchedules' -Default @()) +
              @(Get-TPNestedProperty -Object $roles -Path 'Data.AllPrivilegedAssignments' -Default @())) | Where-Object { $null -ne $_ }
    $isPrivRole = { param($a)
        ([string](Get-TPObjectField -Item $a -Key 'RoleDefinitionName' -Default '')) -in $privRoleNames -or
        (Get-TPObjectField -Item $a -Key 'IsPriv' -Default $false) -eq $true -or
        $msPriv.ContainsKey([string](Get-TPObjectField -Item $a -Key 'RoleDefinitionId' -Default '')) }
    $isUser = { param($a) [string](Get-TPObjectField -Item $a -Key 'PrincipalType' -Default '') -match 'user$' }
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $guestPriv = [System.Collections.Generic.List[object]]::new()
    $typeUnknown = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($a in $pool) {
        if (-not (& $isPrivRole $a)) { continue }
        $upn  = [string](Get-TPObjectField -Item $a -Key 'PrincipalUPN' -Default '')
        $type = [string](Get-TPObjectField -Item $a -Key 'PrincipalUserType' -Default '')
        $guest = ($type -eq 'Guest') -or ($upn -like '*#EXT#*')
        if (-not $guest) {
            if ((& $isUser $a) -and -not $type) { $null = $typeUnknown.Add($(if ($upn) { $upn } else { [string](Get-TPObjectField -Item $a -Key 'PrincipalId' -Default '') })) }
            continue
        }
        $key = "$(Get-TPObjectField -Item $a -Key 'PrincipalId' -Default $upn)|$(Get-TPObjectField -Item $a -Key 'RoleDefinitionId' -Default (Get-TPObjectField -Item $a -Key 'RoleDefinitionName' -Default ''))"
        if ($seen.Add($key)) { $guestPriv.Add($a) }
    }
    if ($guestPriv.Count -gt 0) {
        $named = @($guestPriv | ForEach-Object {
            $how = if ([string](Get-TPObjectField -Item $_ -Key 'Source' -Default '') -eq 'eligible' -or (Get-TPObjectField -Item $_ -Key 'MemberType' -Default $null)) { 'eligible' } else { 'assigned' }
            "$([string](Get-TPObjectField -Item $_ -Key 'PrincipalDisplayName' -Default '?')) ($([string](Get-TPObjectField -Item $_ -Key 'RoleDefinitionName' -Default '?')), $how)" } | Sort-Object -Unique)
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$($guestPriv.Count) guest role assignment(s) to privileged roles: $($named -join ', '). Guest accounts are outside your identity governance — compromised guest accounts escalate to tenant admin." -CurrentValue "Guest admins: $($guestPriv.Count)" -RequiredValue 'Zero guest accounts in privileged roles, assigned or eligible' -Remediation $ctrl.Remediation
        return
    }
    $missing = @()
    if (-not $eligRead) { $missing += "PIM eligible assignments were not read (status: $(if ($eligStatus) { $eligStatus } else { 'not recorded' })), so a guest eligible for a privileged role would not be seen" }
    if (-not $flagsRead) { $missing += "Microsoft's privileged-role flags (isPrivileged) were not read, so only the tool's fixed role list was checked and a guest in another privileged role would not be seen" }
    if ($typeUnknown.Count -gt 0) { $missing += "the user type of $($typeUnknown.Count) privileged role holder(s) was not recorded, so a guest without #EXT# in the UPN would not be seen ($((@($typeUnknown) | Select-Object -First 5) -join ', '))" }
    if ($missing.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "No guest was found in a privileged role, but $($missing -join '; '). Not assessed."
        return
    }
    Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "No guest account (user type Guest, or #EXT# in the UPN) holds or is eligible for a privileged directory role ($($msPriv.Count) role(s) Microsoft marks privileged, plus the tool's own list). Role-assignable groups are not expanded."
}

# ── AAD-11.3 Risky Service Principals and Applications Reviewed ───────────────
function Test-TPControlAADRiskyServicePrincipals {
    [CmdletBinding()] param()
    $cid = 'AAD-11.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $auth = Get-TPRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    # $null = endpoint not reachable (scope not consented, or no Workload Identities
    # Premium so detections never run) — honest NotApplicable, not a false pass.
    $risky = Get-TPNestedProperty -Object $auth -Path 'Data.RiskyServicePrincipals' -Default $null
    if ($null -eq $risky) {
        $why = if (Test-TPGraphScopeMissing -Scope 'IdentityRiskyServicePrincipal.Read.All') { Get-TPConsentMissingDetail -Scope 'IdentityRiskyServicePrincipal.Read.All' }
               else { 'Risky workload-identity data unavailable (requires IdentityRiskyServicePrincipal.Read.All consent and Workload Identities Premium); not assessed.' }
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail $why; return
    }
    $risky = @($risky)
    # atRisk / confirmedCompromised are the states that demand action; remediated,
    # dismissed, confirmedSafe and none are resolved or benign.
    $active = @($risky | Where-Object { (Get-TPObjectField -Item $_ -Key 'RiskState') -in @('atRisk','confirmedCompromised') })
    if ($active.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "No service principals are currently flagged at-risk by Identity Protection ($($risky.Count) workload identities evaluated)."
    } else {
        $names = @($active | ForEach-Object { $n = [string](Get-TPObjectField -Item $_ -Key 'DisplayName'); if ($n) { $n } else { [string](Get-TPObjectField -Item $_ -Key 'AppId') } }) | Select-Object -First 10
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($active.Count) service principal(s) are flagged at-risk or confirmed compromised by Identity Protection. Compromised workload identities can hold OAuth grants that persist through user password resets and MFA. Investigate and remediate." `
            -CurrentValue "$($active.Count) risky SP(s): $($names -join ', ')" `
            -RequiredValue 'Zero at-risk / confirmed-compromised service principals' `
            -Remediation $ctrl.Remediation `
            -AffectedObjects $active
    }
}

# ── AAD-11.4 Token Protection (Binding) Conditional Access ───────────────────
function Test-TPControlAADTokenProtection {
    [CmdletBinding()] param()
    $cid = 'AAD-11.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        Add-TPSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No token protection (binding) is in force: it is a Conditional Access session control Security Defaults does not provide. AiTM phishing steals session tokens and replays them from attacker infrastructure; token binding ties tokens to the originating device.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access policy in force' -RequiredValue 'Enabled CA policy requiring token protection' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca = Get-TPRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    # Token protection is sessionControls.secureSignInSession, readable only in
    # the beta shape. Without that section it cannot be seen either way. (The
    # old match on signInFrequency.authenticationType read "re-authenticate
    # every time" as token binding.)
    if (-not (Test-TPSectionCollected $ca 'TokenProtection')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'TokenProtection was not collected (the beta Conditional Access read did not complete); not assessed.'
        return
    }
    # A token-protection policy counts only when it reaches what Microsoft's
    # deployment guide and Zero Trust check name: the Windows platform (listed,
    # or 'all' without Windows excluded), some users (not None), and All
    # resources or both Office 365 Exchange Online and Office 365 SharePoint
    # Online (neither excluded). Microsoft scopes this policy to those apps by
    # design, so it is not judged on all-application coverage. One scoped to an
    # unrelated app, or without Windows, used to pass.
    $exo = '00000002-0000-0ff1-ce00-000000000000'; $spo = '00000003-0000-0ff1-ce00-000000000000'
    $tpShort = { param($p)
        $why = @()
        $inc = @(Get-TPNestedProperty -Object $p -Path 'Conditions.Platforms' -Default @() | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
        $exc = @(Get-TPNestedProperty -Object $p -Path 'Conditions.ExcludePlatforms' -Default @() | Where-Object { $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
        if (-not (($inc -contains 'windows' -or $inc -contains 'all') -and $exc -notcontains 'windows')) { $why += 'does not include the Windows platform' }
        $u = @(@(Get-TPNestedProperty -Object $p -Path 'Conditions.Users.IncludeUsers' -Default @()) + @(Get-TPNestedProperty -Object $p -Path 'Conditions.Users.IncludeGroups' -Default @()) + @(Get-TPNestedProperty -Object $p -Path 'Conditions.Users.IncludeRoles' -Default @()) | Where-Object { $_ -and $_ -ne 'None' })
        if ($u.Count -eq 0) { $why += 'includes no users' }
        $apps = @(Get-TPNestedProperty -Object $p -Path 'Conditions.Applications.Include' -Default @() | Where-Object { $_ } | ForEach-Object { [string]$_ })
        $appX = @(Get-TPNestedProperty -Object $p -Path 'Conditions.Applications.Exclude' -Default @() | Where-Object { $_ } | ForEach-Object { [string]$_ })
        if (-not ($apps -contains 'All' -or ($apps -contains $exo -and $apps -contains $spo)) -or $appX -contains $exo -or $appX -contains $spo) { $why += 'does not target both Office 365 Exchange Online and Office 365 SharePoint Online (or All resources)' }
        $why }
    $tpPolicies = @(@($ca.Data['Policies']) | Where-Object { $null -ne $_ -and (Get-TPNestedProperty -Object $_ -Path 'SessionControls.SecureSignInSession' -Default $null) -eq $true })
    $narrow = @($tpPolicies | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'State' -Default '') -in @('enabled','enabledForReportingButNotEnforced') -and @(& $tpShort $_).Count -gt 0 } |
        ForEach-Object { "'$([string](Get-TPObjectField -Item $_ -Key 'DisplayName' -Default '?'))' requires token protection but $((& $tpShort $_) -join ' and ')" })
    $narrowNote = if ($narrow.Count) { " Not counted: $($narrow -join '; ')." } else { '' }
    Add-TPCAPolicyTierFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $tpPolicies `
        -Match { @(& $tpShort $_).Count -eq 0 } `
        -What 'Token protection (binding) for Exchange Online and SharePoint Online on Windows' `
        -EnabledDetail "token protection binds session tokens to the originating device for Office 365 Exchange Online and SharePoint Online on Windows, so a stolen token cannot be replayed from attacker infrastructure.$narrowNote" `
        -MissingDetail "no enabled token protection (binding) Conditional Access policy covers Office 365 Exchange Online and SharePoint Online on Windows. AiTM phishing steals session tokens and replays them from attacker infrastructure; token binding ties tokens to the originating device.$narrowNote" `
        -RequiredValue 'Enabled CA policy requiring token protection for users, on Windows, for Exchange Online and SharePoint Online (or All resources)'
}

# ── AAD-11.5 Continuous Access Evaluation Enabled ────────────────────────────
function Test-TPControlAADContinuousAccess {
    [CmdletBinding()] param()
    $cid = 'AAD-11.5'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        Add-TPSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'Continuous access evaluation strict enforcement is not in force: it is a Conditional Access session control Security Defaults does not provide.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access policy in force' -RequiredValue 'Enabled CA policy with continuous access evaluation strict enforcement' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca = Get-TPRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    # CAE is enabled by default in most tenants; CA policy can enforce strict mode
    # Graph values are strictEnforcement / strictLocation; 'strict' never
    # matched. Stored as the mode string; older data nested it under .Mode.
    $caePolicies = @($ca.Data['Policies'] | Where-Object {
        $cae = Get-TPNestedProperty -Object $_ -Path 'SessionControls.ContinuousAccessEvaluation' -Default ''
        if ($cae -is [System.Collections.IDictionary] -or $cae -is [pscustomobject]) { $cae = Get-TPObjectField -Item $cae -Key 'Mode' -Default '' }
        $_.State -eq 'enabled' -and [string]$cae -in @('strictEnforcement','strictLocation')
    })
    if ($caePolicies.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Continuous Access Evaluation strict mode enforced via CA policy. Session revocation propagates in near-real-time.'
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'CAE strict mode not enforced (the default; not configured). CAE is active by default but strict mode ensures immediate session revocation when IP or risk changes — consider enforcing for sensitive workloads.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-11.6 Cross-Tenant Access Inbound Trust Settings ──────────────────────
function Test-TPControlAADCrossTenantAccess {
    [CmdletBinding()] param()
    $cid = 'AAD-11.6'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $auth = Get-TPRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $auth 'CrossTenantAccess')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CrossTenantAccess was not collected; not assessed.'
        return
    }
    $xtap = Get-TPNestedProperty -Object $auth -Path 'Data.CrossTenantAccess'
    if (-not $xtap) {
        # No data is not half credit.
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The cross-tenant access default policy was not returned; not assessed. Verify in Entra ID > External Identities > Cross-tenant access settings that inbound defaults do not trust MFA or device compliance from other tenants.'
        return
    }
    $trustsMFA    = [bool](Get-TPNestedProperty -Object $xtap -Path 'InboundTrust.IsMfaAccepted' -Default $false)
    $trustsDevice = [bool](Get-TPNestedProperty -Object $xtap -Path 'InboundTrust.IsCompliantDeviceAccepted' -Default $false)
    if (-not $trustsMFA -and -not $trustsDevice) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Cross-tenant default inbound settings do not trust external MFA or device compliance claims.'
    } else {
        $trusted = @(); if ($trustsMFA) { $trusted += 'MFA' }; if ($trustsDevice) { $trusted += 'Device Compliance' }
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "Default inbound cross-tenant trust accepts: $($trusted -join ', ') from all external tenants. An attacker in any tenant could satisfy your MFA/compliance requirements using their own tenant's weaker controls." -CurrentValue "Trusts: $($trusted -join ', ')" -RequiredValue 'No trust of external MFA or device compliance by default' -Remediation $ctrl.Remediation
    }
}

# ── AAD-11.7 Privileged Access Workstation Indicator ─────────────────────────
function Test-TPControlAADPrivilegedWorkstation {
    [CmdletBinding()] param()
    $cid = 'AAD-11.7'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        Add-TPSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No device-scoped policy for privileged roles is in force: Security Defaults requires 16 administrator roles to complete MFA at every sign-in but does not restrict the devices they sign in from.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access policy in force' -RequiredValue 'Enabled CA policy restricting privileged roles to managed devices' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca = Get-TPRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    # Microsoft's privileged access workstation check needs BOTH halves: an
    # enabled policy for a privileged role that requires a compliant device, and
    # an enabled policy for a privileged role that blocks every device outside a
    # device filter (filter mode exclude, grant block), which is what keeps
    # administrators on the designated workstations. Either alone, a hybrid-join
    # requirement, a filter of any other mode, or a policy for a role that is not
    # privileged used to pass. Privileged = a role this tenant's catalog marks
    # (the tool's list, IsPriv, or Microsoft's isPrivileged flag). Each half is
    # judged on the policy's other scope with Get-TPCANarrowing (role scope, and
    # for the block half its device filter, are expected); a narrower policy is
    # named, not counted, and a report-only one is a shortfall naming it.
    $roleRaw = Get-TPRawData -Key 'AAD-DirectoryRoles'
    $privIds = @{}
    if ($roleRaw -and (Get-TPObjectField -Item $roleRaw -Key 'Success' -Default $false) -eq $true) {
        foreach ($d in @(Get-TPNestedProperty -Object $roleRaw -Path 'Data.RoleDefinitions' -Default @())) {
            if ((Get-TPObjectField -Item $d -Key 'IsPriv' -Default $false) -eq $true -or (Get-TPObjectField -Item $d -Key 'IsPrivileged' -Default $false) -eq $true) {
                $privIds[[string](Get-TPObjectField -Item $d -Key 'Id' -Default '')] = $true
            }
        }
        foreach ($rid in @(Get-TPNestedProperty -Object $roleRaw -Path 'Data.PrivilegedRoleIds' -Default @() | Where-Object { $_ })) { $privIds[[string]$rid] = $true }
    }
    $pols = @(@($ca.Data['Policies']) | Where-Object { $null -ne $_ })
    $nameOf = { param($p) [string](Get-TPObjectField -Item $p -Key 'DisplayName' -Default '?') }
    $stateOf = { param($p) [string](Get-TPObjectField -Item $p -Key 'State' -Default '') }
    $rolesOf = { param($p) @(Get-TPNestedProperty -Object $p -Path 'Conditions.Users.IncludeRoles' -Default @() | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
    $roleScoped = @($pols | Where-Object { @(& $rolesOf $_).Count -gt 0 })
    $privScoped = @($roleScoped | Where-Object { @(& $rolesOf $_ | Where-Object { $privIds.ContainsKey($_) }).Count -gt 0 })
    $usersIgnore = 'applies to only some users, groups or roles'
    $judge = { param([object[]] $Candidates, [string[]] $Ignore, [string[]] $Clients)
        $ok = @(); $narrow = @(); $staged = @()
        foreach ($p in $Candidates) {
            $nar = @(Get-TPCANarrowing -Policy $p -RequiredClientAppTypes $Clients -Ignore $Ignore)
            if ($nar.Count) { if ((& $stateOf $p) -in @('enabled','enabledForReportingButNotEnforced')) { $narrow += "'$(& $nameOf $p)' $($nar -join '; ')" }; continue }
            if ((& $stateOf $p) -eq 'enabled') { $ok += (& $nameOf $p) } elseif ((& $stateOf $p) -eq 'enabledForReportingButNotEnforced') { $staged += (& $nameOf $p) }
        }
        [pscustomobject]@{ Ok = $ok; Narrow = $narrow; Staged = $staged } }
    $compliant = & $judge @($privScoped | Where-Object { Test-TPCAGrantRequires -Policy $_ -Any @('compliantDevice') }) @($usersIgnore) (Get-TPCAInteractiveClientAppTypes)
    $pawBlock  = & $judge @($privScoped | Where-Object {
            [string](Get-TPNestedProperty -Object $_ -Path 'Conditions.Devices.FilterMode' -Default '') -eq 'exclude' -and
            [string](Get-TPNestedProperty -Object $_ -Path 'Conditions.Devices.FilterRule' -Default '') -and
            @(Get-TPNestedProperty -Object $_ -Path 'GrantControls.BuiltInControls' -Default @()) -contains 'block' }) @($usersIgnore, 'limited by a device filter') @()
    $v = @(); $sf = @(); $ne = @()
    foreach ($half in @(
            @{ R = $compliant; Ok = 'A privileged role must use a compliant device'; Miss = 'no enabled Conditional Access policy for a privileged role requires a compliant device' },
            @{ R = $pawBlock;  Ok = 'Privileged roles are blocked outside the designated devices (device filter, exclude mode, block)'; Miss = 'no enabled Conditional Access policy for a privileged role blocks every device outside a device filter (filter mode exclude, grant block), so administrators are not kept on designated workstations' })) {
        $r = $half.R
        if (@($r.Ok).Count) { $v += "$($half.Ok): $(@($r.Ok) -join ', ')." }
        else {
            $m = $half.Miss
            if (@($r.Staged).Count) { $m += "; report-only, which enforces nothing: $(@($r.Staged) -join ', ')" }
            if (@($r.Narrow).Count) { $m += "; narrower and not counted: $(@($r.Narrow) -join '; ')" }
            if ($privIds.Count -eq 0) { $ne += "whether a privileged role is targeted: the tenant's role catalog was not read." } else { $sf += "$m." }
        }
    }
    $other = @($roleScoped | Where-Object { $_ -notin $privScoped -and (& $stateOf $_) -eq 'enabled' -and ([string](Get-TPNestedProperty -Object $_ -Path 'Conditions.Devices.FilterRule' -Default '') -or (Test-TPCAGrantRequires -Policy $_ -Any @('compliantDevice','domainJoinedDevice'))) } | ForEach-Object { & $nameOf $_ })
    if ($other.Count -and $privIds.Count) { if ($sf.Count) { $sf += "Not counted (no privileged role included): $($other -join ', ')." } else { $v += "Not counted (no privileged role included): $($other -join ', ')." } }
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $v -Shortfalls $sf -NotEstablished $ne `
        -CurrentValue "Compliant-device policy: $(if (@($compliant.Ok).Count) { @($compliant.Ok) -join ', ' } else { 'none' }); PAW device-filter block: $(if (@($pawBlock.Ok).Count) { @($pawBlock.Ok) -join ', ' } else { 'none' })" `
        -RequiredValue 'Enabled CA policy for privileged roles requiring a compliant device, and an enabled CA policy for privileged roles blocking devices outside a device filter (exclude mode)'
}

# ── AAD-11.8 Terms of Use for External Access ─────────────────────────────────
function Test-TPControlAADTermsOfUse {
    [CmdletBinding()] param()
    $cid = 'AAD-11.8'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        Add-TPSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No Terms of Use acceptance is required: Terms of Use is a Conditional Access grant control Security Defaults does not provide.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access policy in force' -RequiredValue 'Enabled CA policy requiring Terms of Use acceptance' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca = Get-TPRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    Add-TPCAPolicyTierFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $ca.Data['Policies'] `
        -Match { @(Get-TPNestedProperty -Object $_ -Path 'GrantControls.TermsOfUse' -Default @()).Count -gt 0 } `
        -What 'Terms of Use' `
        -EnabledDetail 'users must acknowledge acceptable use before accessing resources.' `
        -MissingDetail 'no Terms of Use Conditional Access policy. For organizations with guests or external contractors, Terms of Use create a legal acknowledgment of acceptable use.' `
        -RequiredValue 'Enabled CA policy requiring Terms of Use acceptance'
}

# ── AAD-11.9 Workload Identity CA Policy ─────────────────────────────────────
function Test-TPControlAADWorkloadIdentityCA {
    [CmdletBinding()] param()
    $cid = 'AAD-11.9'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    if ((Get-TPSecurityDefaultsState) -eq $true) {
        Add-TPSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No Conditional Access policy applies to workload identities: Security Defaults has no policy for service principals, and Conditional Access for workload identities also needs the Workload Identities Premium license.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access policy in force' -RequiredValue 'Enabled CA policy scoped to workload identities' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca = Get-TPRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    # A workload identity policy earns the control only when it responds to
    # service principal RISK (Microsoft's recommendation: a risk-based
    # Conditional Access policy for workload identities), i.e. includes service
    # principals, selects at least one service principal risk level and blocks.
    # A location-only workload policy is named, not counted. A results file from
    # before ServicePrincipalRiskLevels was collected is not assessed.
    $isSp = { param($p) @(Get-TPNestedProperty -Object $p -Path 'Conditions.ClientApplications.IncludeServicePrincipals' -Default @() | Where-Object { $_ }).Count -gt 0 }
    $spPols = @(@($ca.Data['Policies']) | Where-Object { $null -ne $_ -and (& $isSp $_) })
    $unread = @($spPols | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'State' -Default '') -in @('enabled','enabledForReportingButNotEnforced') -and -not (Test-TPFieldPresent -Item (Get-TPObjectField -Item $_ -Key 'Conditions' -Default $null) -Key 'ServicePrincipalRiskLevels') })
    $qualifies = { param($p) @(Get-TPNestedProperty -Object $p -Path 'Conditions.ServicePrincipalRiskLevels' -Default @() | Where-Object { $_ -and $_ -ne 'none' }).Count -gt 0 -and
                             @(Get-TPNestedProperty -Object $p -Path 'GrantControls.BuiltInControls' -Default @()) -contains 'block' }
    $nameOf = { param($p) [string](Get-TPObjectField -Item $p -Key 'DisplayName' -Default '?') }
    if ($unread.Count -gt 0 -and @($spPols | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'State' -Default '') -eq 'enabled' -and (& $qualifies $_) }).Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "Workload identity Conditional Access policies were found ($(@($unread | ForEach-Object { & $nameOf $_ }) -join ', ')), but their service principal risk condition was not recorded (a results file from before it was collected), so whether any responds to workload identity risk is not known. Not assessed."
        return
    }
    $other = @($spPols | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'State' -Default '') -in @('enabled','enabledForReportingButNotEnforced') -and -not (& $qualifies $_) } | ForEach-Object { & $nameOf $_ })
    $otherNote = if ($other.Count) { " Not counted (applies to workload identities without blocking on service principal risk): $($other -join ', ')." } else { '' }
    Add-TPCAPolicyTierFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $spPols `
        -Match { & $qualifies $_ } `
        -What 'A risk-based workload identity policy' `
        -EnabledDetail "Conditional Access blocks service principals at the selected workload identity risk levels.$otherNote" `
        -MissingDetail "no Conditional Access policy blocks workload identities (service principals) on service principal risk.$otherNote" `
        -RequiredValue 'Enabled CA policy including service principals, with service principal risk levels selected, that blocks access'
}
