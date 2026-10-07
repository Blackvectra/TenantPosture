#Requires -Version 7.0

# Safe property accessor — prevents throw on null nested object access

# ── Collection Guard ────────────────────────────────────────────────────────
# Returns $true if AAD data was successfully collected
function Test-NRGAADDataAvailable {
    $ca   = Get-NRGRawData -Key 'AAD-CAPolicies'
    $auth = Get-NRGRawData -Key 'AAD-AuthPolicies'
    $usr  = Get-NRGRawData -Key 'AAD-Users'
    # 'AAD-DirectoryRoles' is the key Invoke-NRGCollectAADRoles actually writes.
    # This previously read 'AAD-Roles', which no collector sets, so the clause
    # below was always false — the helper could not see role data even when it
    # had been collected successfully.
    $rol  = Get-NRGRawData -Key 'AAD-DirectoryRoles'
    # At least one AAD collector must have succeeded
    return ($ca   -and $ca.Success)   -or
           ($auth -and $auth.Success) -or
           ($usr  -and $usr.Success)  -or
           ($rol  -and $rol.Success)
}


# Returns $true only when the named AAD-DirectoryRoles section was collected.
#
# Invoke-NRGCollectAADRoles sets Success = (assignments -OR- eligibility), so a
# tenant whose permanent-assignment read failed while eligibility succeeded
# still reports Success = $true with RoleAssignments and PrivRoles empty. Every
# real tenant has at least one privileged assignment, so an empty list there is
# a failed read — never a clean tenant — and reporting "no guest admins" or "no
# synced admins" from it is a false pass on the tenant-takeover controls.
#
# Absent SectionStatus (older captured data) is treated as collected so a
# replayed results JSON keeps its previous behavior.
function Test-NRGRoleSectionCollected {
    [CmdletBinding()]
    param(
        [AllowNull()] $Roles,
        [Parameter(Mandatory)] [string] $Section
    )
    $status = Get-NRGNestedProperty -Object $Roles -Path "Data.SectionStatus.$Section" -Default $null
    if ($null -eq $status) { return $true }
    return ($status -eq 'Collected')
}

# Returns $true when every RoleAssignment's RoleDefinitionName resolved to a
# human-readable name, $false if any degraded to the raw role-template GUID.
#
# Invoke-NRGCollectAADRoles builds $roleMap from a SEPARATE roleDefinitions
# sub-query; when that query fails, the catch only registers an exception (no
# SectionStatus flag for it), RoleDefinitionName falls back to the bare GUID
# for every assignment, and IsPriv is computed against that GUID so it never
# matches a role name — every name-based privileged-role filter then matches
# nothing while RoleAssignments itself still reports 'Collected', because the
# assignments read succeeded. The GUID-shaped name is the only evaluator-side
# signal of that failure without a collector change.
function Test-NRGRoleNamesResolved {
    [CmdletBinding()]
    param([AllowNull()] $Assignments)
    # Service-principal rows are excluded: Microsoft first-party apps (e.g.
    # "Microsoft Office 365 Portal") hold hidden internal roles that the
    # roleDefinitions endpoint never lists, so their names never resolve even
    # when the lookup worked. Both callers assess USER principals only, and a
    # genuinely failed lookup degrades the user rows too, so it is still caught.
    $list = @(@($Assignments) | Where-Object {
        [string](Get-NRGObjectField -Item $_ -Key 'PrincipalType' -Default '') -notmatch 'servicePrincipal'
    })
    if ($list.Count -eq 0) { return $true }
    $guidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
    $unresolved = @($list | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'RoleDefinitionName') -match $guidPattern })
    return ($unresolved.Count -eq 0)
}

# Three-tier verdict for "is there a Conditional Access policy doing X":
#   enabled                              -> Satisfied  ('Enabled')
#   only report-only (audit mode)        -> Partial    ('Audit mode (report-only)')
#   none, or only disabled policies      -> Gap        ('None')
# Report-only logs what the policy would do but blocks nothing, so it earns
# half credit — it is real progress toward enforcement. Nothing configured
# earns none: half credit for an absent control inflates the score.
function Add-NRGCAPolicyTierFinding {
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
    $enabled  = @($matched | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'State') -eq 'enabled' })
    $auditing = @($matched | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'State') -eq 'enabledForReportingButNotEnforced' })
    $names    = { param($list) (@($list) | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'DisplayName') } | Select-Object -First 5) -join ', ' }
    if ($enabled.Count -gt 0) {
        Add-NRGFinding -ControlId $ControlId -State 'Satisfied' -Category $Control.Category -Title $Control.Title `
            -Severity 'Informational' -FrameworkIds $FrameworkIds `
            -Detail "Enabled: $EnabledDetail Policies: $(& $names $enabled)." `
            -CurrentValue "Enabled ($($enabled.Count) policy(ies))" -RequiredValue $RequiredValue
    } elseif ($auditing.Count -gt 0) {
        Add-NRGFinding -ControlId $ControlId -State 'Partial' -Category $Control.Category -Title $Control.Title `
            -Severity $Control.Severity -FrameworkIds $FrameworkIds `
            -Detail "Audit mode: $What is configured only in report-only mode ($(& $names $auditing)). Sign-ins are logged against it but nothing is enforced. Review the report-only results, then switch the policy to On." `
            -CurrentValue "Audit mode (report-only, $($auditing.Count) policy(ies))" -RequiredValue $RequiredValue `
            -Remediation $Control.Remediation
    } else {
        Add-NRGFinding -ControlId $ControlId -State 'Gap' -Category $Control.Category -Title $Control.Title `
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
function Test-NRGAuthStrengthPhishResistant {
    [CmdletBinding()]
    param([AllowNull()] $GrantControls)
    $id = [string](Get-NRGObjectField -Item $GrantControls -Key 'AuthStrengthId' -Default '')
    if (-not $id) { return $null }
    switch ($id) {
        '00000000-0000-0000-0000-000000000004' { return $true }
        '00000000-0000-0000-0000-000000000002' { return $false }
        '00000000-0000-0000-0000-000000000003' { return $false }
    }
    $combos = @(Get-NRGObjectField -Item $GrantControls -Key 'AuthStrengthCombinations' -Default @() | Where-Object { $_ })
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
function Get-NRGPIMScopedPolicies {
    [CmdletBinding()]
    param([AllowNull()] $Policies)
    $all = @($Policies)
    $roles = Get-NRGRawData -Key 'AAD-DirectoryRoles'
    $defs = @{}
    foreach ($d in @(Get-NRGNestedProperty -Object $roles -Path 'Data.RoleDefinitions' -Default @())) {
        $id = [string](Get-NRGObjectField -Item $d -Key 'Id' -Default '')
        if ($id) { $defs[$id] = $d }
    }
    $mapped = @($all | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'RoleDefinitionId' -Default '') })
    if ($mapped.Count -eq 0 -or $defs.Count -eq 0) {
        return [pscustomobject]@{ Scoped = $false; Policies = $all }
    }
    $priv = foreach ($p in $mapped) {
        $d = $defs[[string]$p.RoleDefinitionId]
        if ($d -and (Get-NRGObjectField -Item $d -Key 'IsPriv' -Default $false) -eq $true) {
            @{
                PolicyId              = Get-NRGObjectField -Item $p -Key 'PolicyId'
                RoleDefinitionId      = [string]$p.RoleDefinitionId
                RoleName              = [string](Get-NRGObjectField -Item $d -Key 'DisplayName' -Default '')
                RequiresMFA           = Get-NRGObjectField -Item $p -Key 'RequiresMFA'
                RequiresJustification = Get-NRGObjectField -Item $p -Key 'RequiresJustification'
                RequiresApproval      = Get-NRGObjectField -Item $p -Key 'RequiresApproval'
                MaxDurationHours      = Get-NRGObjectField -Item $p -Key 'MaxDurationHours'
            }
        }
    }
    return [pscustomobject]@{ Scoped = $true; Policies = @($priv) }
}

# ── Conditional Access reading helpers ───────────────────────────────────────
# A grant with operator OR is satisfied by ANY of its controls, so "requires
# MFA" holds only when every alternative is MFA (or an authentication
# strength). "compliantDevice OR mfa" requires neither.
function Get-NRGCAGrantAlternatives {
    [CmdletBinding()]
    param([AllowNull()] $Policy)
    $builtIn = @(Get-NRGNestedProperty -Object $Policy -Path 'GrantControls.BuiltInControls' -Default @() | Where-Object { $_ } | ForEach-Object { [string]$_ })
    $alts = [System.Collections.Generic.List[string]]::new()
    foreach ($b in $builtIn) { $alts.Add($b) }
    if ([string](Get-NRGNestedProperty -Object $Policy -Path 'GrantControls.AuthStrengthId' -Default '')) { $alts.Add('authStrength') }
    foreach ($t in @(Get-NRGNestedProperty -Object $Policy -Path 'GrantControls.TermsOfUse' -Default @() | Where-Object { $_ })) { $alts.Add('termsOfUse') }
    $op = [string](Get-NRGNestedProperty -Object $Policy -Path 'GrantControls.Operator' -Default '')
    [pscustomobject]@{ Operator = $(if ($alts.Count -le 1) { 'AND' } else { $op.ToUpperInvariant() }); Controls = @($alts) }
}

function Test-NRGCAGrantRequires {
    <# True when satisfying the grant NECESSARILY involves one of $Any. #>
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] $Policy, [Parameter(Mandatory)] [string[]] $Any)
    $g = Get-NRGCAGrantAlternatives -Policy $Policy
    if ($g.Controls.Count -eq 0) { return $false }
    if ($g.Operator -eq 'OR') { return (@($g.Controls | Where-Object { $_ -notin $Any }).Count -eq 0) }
    return (@($g.Controls | Where-Object { $_ -in $Any }).Count -gt 0)
}

function Test-NRGCAAllUsers {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] $Policy)
    return (@(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Users.IncludeUsers' -Default @()) -contains 'All')
}

function Test-NRGCAAllApps {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] $Policy)
    return (@(Get-NRGNestedProperty -Object $Policy -Path 'Conditions.Applications.Include' -Default @()) -contains 'All')
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
# Test-NRGControl-AAD.ps1  (v4.5.5)
# Evaluates Entra ID (AAD) security controls.
# SCORING ONLY — no API calls, no data collection.
# Reads from module state via Get-NRGRawData; writes findings via Add-NRGFinding.
#
# NIST SP 800-53: IA-2, IA-5, AC-6, AC-2, AC-7
# MITRE ATT&CK:   T1078, T1110, T1621, T1528
#

# ── AAD-1.1 Legacy Authentication Block ──────────────────────────────────────
function Get-NRGLegacyAuthBlockState {
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
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        return [ordered]@{ Kind = 'Blocked'; Detail = 'Security Defaults is on and blocks legacy authentication tenant-wide' }
    }
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not (Get-NRGObjectField -Item $ca -Key 'Success' -Default $false)) {
        return [ordered]@{ Kind = 'Unknown'; Detail = 'Conditional Access data was not collected' }
    }
    if (Test-NRGSecurityDefaultsUnresolved) {
        return [ordered]@{ Kind = 'Unknown'; Detail = 'the Security Defaults state was not read and no Conditional Access policy is On' }
    }
    $legacy = @($ca.Data['Policies'] | Where-Object {
        @($_.Conditions.ClientAppTypes) -contains 'other' -and (Test-NRGCAGrantRequires -Policy $_ -Any @('block'))
    })
    $cov = Get-NRGCAEffectiveCoverage -Policies @($legacy | Where-Object { $_.State -eq 'enabled' })
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

function Test-NRGControlAADLegacyAuth {
    [CmdletBinding()] param()

    $controlId = 'AAD-1.1'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    # Security Defaults blocks legacy authentication tenant-wide and cannot be
    # scoped, which is exactly what this control requires. It runs before the
    # CA gate: no CA policy can be turned on beside it, so CA data cannot
    # change this verdict.
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        Add-NRGSecurityDefaultsFinding -ControlId $controlId -Category $control.Category -Title $control.Title -FrameworkIds $citations `
            -State 'Satisfied' -Severity 'Informational' `
            -Detail 'Legacy authentication is blocked by Security Defaults: Microsoft documents that it blocks every authentication request made by an older protocol tenant-wide, including clients that do not use modern authentication, IMAP, SMTP and POP3, and Exchange ActiveSync basic authentication, and that it cannot be scoped or customized.' `
            -CurrentValue 'Legacy authentication blocked for all users by Security Defaults' `
            -RequiredValue 'Legacy authentication blocked for all users (Conditional Access policy blocking Other clients, or Security Defaults)'
        return
    }

    $caData = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $caData -or -not $caData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'Conditional Access data not collected'
        return
    }
    # Security Defaults not read and no CA policy On: it may be on (Satisfied)
    # or off (the CA verdict below). An unread state is never "disabled".
    if (Test-NRGSecurityDefaultsUnresolved) {
        Add-NRGSecurityDefaultsUnreadFinding -ControlId $controlId -Category $control.Category -Title $control.Title -FrameworkIds $citations `
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
        @($_.Conditions.ClientAppTypes) -contains 'other' -and (Test-NRGCAGrantRequires -Policy $_ -Any @('block'))
    })
    # Combined coverage (Get-NRGCAEffectiveCoverage): a policy must cover all users on all
    # applications with no extra condition to count; user exclusions are judged across
    # every qualifying policy, so one policy excluding a break-glass account is not a gap
    # when another covers them, and is reported as an exception when none does.
    $cov     = Get-NRGCAEffectiveCoverage -Policies @($legacy | Where-Object { $_.State -eq 'enabled' })
    $scoped  = @($cov.Narrowed)
    $audit   = @($legacy | Where-Object { $_.State -eq 'enabledForReportingButNotEnforced' })
    $names   = { param($l) (@($l) | ForEach-Object { $_.DisplayName }) -join ', ' }

    if ($cov.Kind -ne 'None') {
        $cv = Get-NRGCACoverageVerdict -Coverage $cov -What 'Legacy authentication (Other clients) is blocked'
        Add-NRGExpectedStateFinding -ControlId $controlId -Control $control -FrameworkIds $citations `
            -Verified $cv.Verified -Shortfalls $cv.Shortfalls -NotEstablished $cv.NotEstablished `
            -CurrentValue "Legacy block: $($cov.Kind) coverage by $($cov.Names -join ', ')" `
            -RequiredValue 'CA policy blocking Other clients for all users on all applications, or Security Defaults'
    } elseif ($scoped.Count -gt 0 -or $audit.Count -gt 0) {
        $why = if ($scoped.Count -gt 0) { "blocked only for a subset of users, groups or applications, or under a narrowing condition ($(($scoped | ForEach-Object { "$($_.Name): $($_.Why)" }) -join '; ')); everyone else can still use legacy protocols" } else { "configured only in report-only mode ($(& $names $audit)); nothing is blocked" }
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail "Legacy authentication is $why." `
            -CurrentValue 'Legacy auth block not enforced for all users' -RequiredValue 'CA policy blocking Other clients for all users' `
            -Remediation $control.Remediation
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail 'No Conditional Access policy found that blocks legacy authentication (Other clients).' `
            -CurrentValue 'No blocking CA policy' -RequiredValue 'CA policy blocking Other clients for all users' `
            -Remediation $control.Remediation
    }
}

# ── AAD-1.3 Phishing-Resistant MFA for Admins ────────────────────────────────
function Test-NRGControlAADPhishResistantMFA {
    [CmdletBinding()] param()

    $controlId = 'AAD-1.3'
    $control   = Get-NRGControlById -ControlId $controlId
    if (-not $control) { return }
    $citations = Get-NRGFrameworkCitations -ControlId $controlId

    # Security Defaults requires MFA of 16 administrator roles at every
    # sign-in; it has them register Authenticator notifications (or use OATH
    # TOTP codes) and requires no phishing-resistant method. Standard admin
    # MFA scores Partial (Medium) on the CA path below, so it scores the same
    # here — never the Critical "no MFA for admins" Gap.
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        Add-NRGSecurityDefaultsFinding -ControlId $controlId -Category $control.Category -Title $control.Title -FrameworkIds $citations `
            -State 'Partial' -Severity 'Medium' `
            -Detail 'The 16 administrator roles Security Defaults names (among them Global Administrator, Privileged Role Administrator, Security Administrator, Exchange Administrator and SharePoint Administrator) must complete MFA at every sign-in. Security Defaults requires them to register for Microsoft Authenticator notifications (or use OATH TOTP codes) and does not require a phishing-resistant method: Microsoft''s phishing-resistant MFA strength allows only Windows Hello for Business or platform credential, FIDO2 security keys and certificate-based MFA. Requiring it for administrators is done with a Conditional Access authentication-strength policy.' `
            -CurrentValue 'Security Defaults: MFA at every sign-in for 16 administrator roles; no phishing-resistant method required' `
            -RequiredValue 'CA policy with Authentication Strength targeting admin roles' `
            -Remediation $control.Remediation -NeedsConditionalAccess
        return
    }

    $caData = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $caData -or -not $caData.Success) {
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -Detail 'Conditional Access data not collected'
        return
    }
    # Security Defaults not read and no CA policy On: it may be on (Partial,
    # admin MFA at every sign-in) or off (the Critical Gap below).
    if (Test-NRGSecurityDefaultsUnresolved) {
        Add-NRGSecurityDefaultsUnreadFinding -ControlId $controlId -Category $control.Category -Title $control.Title -FrameworkIds $citations `
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
    $coversAdmins = { param($p) @($p.Conditions.Users.IncludeRoles).Count -gt 0 -or (Test-NRGCAAllUsers $p) }
    $roleStrengthPolicies = @($caData.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and (& $coversAdmins $_) -and
        (-not [string]::IsNullOrEmpty($_.GrantControls.AuthStrengthId)) -and
        (Test-NRGCAGrantRequires -Policy $_ -Any @('authStrength'))
    })
    $phishResistantPolicies = @($roleStrengthPolicies | Where-Object { (Test-NRGAuthStrengthPhishResistant -GrantControls $_.GrantControls) -eq $true })
    $weakStrengthPolicies   = @($roleStrengthPolicies | Where-Object { (Test-NRGAuthStrengthPhishResistant -GrantControls $_.GrantControls) -eq $false })
    $unknownStrengthPolicies = @($roleStrengthPolicies | Where-Object { $null -eq (Test-NRGAuthStrengthPhishResistant -GrantControls $_.GrantControls) })

    # Also check for policies targeting roles with MFA (lower bar — Partial)
    $mfaForRolePolicies = @($caData.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and (& $coversAdmins $_) -and
        (Test-NRGCAGrantRequires -Policy $_ -Any @('mfa','authStrength'))
    })

    if ($phishResistantPolicies.Count -gt 0) {
        # Coverage of the administrator population, not just "a policy exists": an
        # all-users policy covers admins; a role-scoped one must include every privileged
        # role this tenant's own role catalog lists (never Microsoft's fixed list, which
        # the tool cannot verify here); exclusions are judged across every qualifying policy.
        $privIds = $null
        $roleRaw = Get-NRGRawData -Key 'AAD-DirectoryRoles'
        if ($roleRaw -and (Get-NRGObjectField -Item $roleRaw -Key 'Success' -Default $null) -eq $true) {
            $defs = @(Get-NRGNestedProperty -Object $roleRaw -Path 'Data.RoleDefinitions' -Default @())
            if ($defs.Count -gt 0) {
                $privIds = @{}
                foreach ($d in $defs) { if ((Get-NRGObjectField -Item $d -Key 'IsPriv' -Default $false) -eq $true) { $privIds[[string](Get-NRGObjectField -Item $d -Key 'Id' -Default '')] = $true } }
            }
        }
        $cands = @(); $narrowed = @(); $roleUnverified = @()
        foreach ($p in $phishResistantPolicies) {
            $nm = [string]$p.DisplayName
            $nar = @(Get-NRGCANarrowing -Policy $p | Where-Object { $_ -ne 'applies to only some users, groups or roles' })
            if (-not (Test-NRGCAAllUsers $p)) {
                $rc = Get-NRGCAAdminRoleCoverage -Policy $p -PrivRoleIds $privIds
                if ($null -eq $rc) { $roleUnverified += $nm }
                elseif ($rc.CoveredCount -lt $rc.TotalPriv) { $nar += "it covers $($rc.CoveredCount) of $($rc.TotalPriv) privileged roles" }
            }
            if ($nar.Count -gt 0) { $narrowed += [pscustomobject]@{ Name = $nm; Why = ($nar -join '; ') } }
            else { $cands += [pscustomobject]@{ Name = $nm; Exclusions = @(Get-NRGCAPrincipalExclusions -Policy $p) } }
        }
        $cov = Get-NRGExclusionCoverage -Candidates $cands
        $cov['Narrowed'] = @($narrowed)
        $cv = Get-NRGCACoverageVerdict -Coverage $cov -What 'Phishing-resistant MFA (Authentication Strength) is required for admin roles'
        if ($cov.Kind -ne 'None' -and $roleUnverified.Count -gt 0 -and @($cov.FullNames | Where-Object { $_ -notin $roleUnverified }).Count -eq 0) {
            $cv.NotEstablished = @($cv.NotEstablished) + "whether $($roleUnverified -join ', ') covers every privileged role, because this tenant's role catalog was not read."
        }
        Add-NRGExpectedStateFinding -ControlId $controlId -Control $control -FrameworkIds $citations `
            -Verified $cv.Verified -Shortfalls $cv.Shortfalls -NotEstablished $cv.NotEstablished `
            -CurrentValue "Phishing-resistant MFA for admins: $($cov.Kind) coverage" `
            -RequiredValue 'CA policy with a phishing-resistant authentication strength covering every privileged role'
    } elseif ($unknownStrengthPolicies.Count -gt 0) {
        # A strength is required, but which methods it allows could not be
        # read, so phishing resistance is unverified in either direction.
        Add-NRGFinding -ControlId $controlId -State 'NotApplicable' -Category $control.Category `
            -Title $control.Title -FrameworkIds $citations `
            -Detail "Admin roles require an authentication strength ($(($unknownStrengthPolicies | ForEach-Object { "$($_.DisplayName) [$(Get-NRGObjectField -Item $_.GrantControls -Key 'AuthStrengthName' -Default 'custom strength')]" }) -join ', ')), but its allowed methods could not be read, so whether it is phishing-resistant is not assessed. Verify in Entra > Protection > Authentication methods > Authentication strengths."
    } elseif ($weakStrengthPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail "Admin roles require an authentication strength that is NOT phishing-resistant — it allows methods such as SMS, voice, or app push that AiTM phishing can relay: $(($weakStrengthPolicies | ForEach-Object { "$($_.DisplayName) [$(Get-NRGObjectField -Item $_.GrantControls -Key 'AuthStrengthName' -Default 'custom strength')]" }) -join ', ')." `
            -CurrentValue 'Authentication strength for admins allows non-phishing-resistant methods' `
            -RequiredValue 'Phishing-resistant MFA strength (FIDO2/passkey, Windows Hello for Business, certificate-based MFA) for admin roles' `
            -Remediation $control.Remediation
    } elseif ($mfaForRolePolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $controlId -State 'Partial' -Category $control.Category `
            -Title $control.Title -Severity 'Medium' -FrameworkIds $citations `
            -Detail 'Admin roles have MFA required via CA, but not using Authentication Strength (phishing-resistant). AiTM attacks can bypass standard MFA.' `
            -CurrentValue 'CA requires standard MFA for admin roles' `
            -RequiredValue 'CA using Authentication Strength (phishing-resistant MFA) for admin roles' `
            -Remediation $control.Remediation
    } else {
        Add-NRGFinding -ControlId $controlId -State 'Gap' -Category $control.Category `
            -Title $control.Title -Severity $control.Severity -FrameworkIds $citations `
            -Detail 'No CA policy found that requires MFA for privileged directory roles.' `
            -CurrentValue 'No phishing-resistant MFA for admins' `
            -RequiredValue 'CA policy with Authentication Strength targeting admin roles' `
            -Remediation $control.Remediation
    }
}

# ── AAD-1.4 Sign-in Risk CA Policy ───────────────────────────────────────────
function Test-NRGControlAADSignInRisk {
    [CmdletBinding()] param()
    $cid = 'AAD-1.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        Add-NRGSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No Conditional Access sign-in risk policy can be in force while Security Defaults is enabled, and Security Defaults has no configurable sign-in risk policy of its own: it prompts registered users for MFA when Microsoft decides it is necessary. Conditional Access risk policies need Microsoft Entra ID P2. The legacy Identity Protection sign-in risk policy (retiring October 1, 2026) is not read by this tool.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access sign-in risk policy in force' -RequiredValue 'CA policy: signInRiskLevels = high/medium + require MFA' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca  = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    $riskPolicies = @($ca.Data['Policies'] | Where-Object {
        # Block is the strongest response to a risky sign-in, not a miss.
        $_.State -eq 'enabled' -and @($_.Conditions.SignInRiskLevels).Count -gt 0 -and
        (Test-NRGCAGrantRequires -Policy $_ -Any @('mfa','authStrength','block'))
    })
    # Risk levels are discrete: a policy applies only to the levels it
    # selects. Microsoft's template selects High and Medium; the levels are
    # combined across every enabled policy that responds.
    $levels = @($riskPolicies | ForEach-Object { @($_.Conditions.SignInRiskLevels) } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $high = $levels -contains 'high'; $medium = $levels -contains 'medium'
    $names = (@($riskPolicies | ForEach-Object { [string]$_.DisplayName }) -join ', ')
    $ro14 = Get-NRGRiskReportOnlyPolicies -Policies $ca.Data['Policies'] -Condition 'SignInRiskLevels' -RequiredLevels @('high','medium') -GrantAny @('mfa','authStrength','block')
    if (-not ($high -and $medium) -and (Get-NRGPolicyListIncomplete -CA $ca)) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "Not assessed: the Conditional Access policy list could not be read in full (the beta list failed and the v1.0 list withholds some policies), so whether a complete sign-in risk policy exists was not established.$(if ($names) { " Enabled sign-in risk policies read: $names." })"
        return
    }
    if ($high -and $medium) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Sign-in risk Conditional Access in force for high and medium risk: $names"
    } elseif ($high -or $medium) {
        $missing = if ($high) { 'medium' } else { 'high' }
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "The enabled sign-in risk policies ($names) apply to $(if ($high) { 'high' } else { 'medium' })-risk sign-ins only. A policy applies only to the risk levels it selects, so a $missing-risk sign-in is let through without a challenge; Microsoft's template selects High and Medium." `
            -CurrentValue "signInRiskLevels = $($levels -join ', ')" -RequiredValue 'CA policy: signInRiskLevels = high/medium + require MFA' -Remediation $ctrl.Remediation
    } elseif ($riskPolicies.Count -eq 0 -and @($ro14.Qualifying).Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "A sign-in risk policy meets every requirement (high and medium sign-in risk, all users and applications, a responding control) but is in report-only mode, which collects evaluation data and enforces nothing: $(@($ro14.Qualifying) -join ', '). Until it is turned on, a risky sign-in is let through without a challenge; Partial is still a failed baseline requirement.$(Get-NRGRiskReportOnlyNote -ReportOnly $ro14)" `
            -CurrentValue "Report-only: $(@($ro14.Qualifying) -join ', ')" -RequiredValue 'CA policy in force: signInRiskLevels = high/medium + require MFA' -Remediation $ctrl.Remediation
    } elseif ($riskPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "The enabled sign-in risk policies ($names) apply to $($levels -join ', ') risk only, so a medium- or high-risk sign-in (password spray, anonymous IP, token replay) is let through without a challenge." `
            -CurrentValue "signInRiskLevels = $($levels -join ', ')" -RequiredValue 'CA policy: signInRiskLevels = high/medium + require MFA' -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail ('No enabled Conditional Access policy uses the sign-in risk condition, so a sign-in Identity Protection rates risky (password spray, anonymous IP, token replay) is let through without a challenge. (Sign-in risk policies need Entra ID P2; on a tenant without it this control is not scored.)' + (Get-NRGRiskReportOnlyNote -ReportOnly $ro14)) -CurrentValue 'No sign-in risk policy' -RequiredValue 'CA policy: signInRiskLevels = high/medium + require MFA' -Remediation $ctrl.Remediation
    }
}

# Risk-based Conditional Access policies in report-only (audit) mode. Report-only collects evaluation
# telemetry and enforces nothing, so it is never a pass. One that would satisfy the requirement if it were
# enforced (every required risk level, a responding grant, and a scope of all users and all applications with no
# platform, location, device-filter or application-exclusion narrowing) is part-way (Partial); anything else
# is a Gap. Both remain failed baseline requirements.
# True only when the collector says the Conditional Access list could not be proven complete. A key that is
# absent (results collected before the beta merge existed) counts as complete, so older results replay unchanged.
function Get-NRGPolicyListIncomplete {
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] $CA)
    $st = [string](Get-NRGNestedProperty -Object $CA -Path 'Data.SectionStatus.PolicyCompleteness' -Default '')
    return ($st -in @('Failed', 'NotRun'))
}

function Get-NRGRiskReportOnlyPolicies {
    [CmdletBinding()]
    param([AllowNull()] [object[]] $Policies, [Parameter(Mandatory)] [ValidateSet('SignInRiskLevels', 'UserRiskLevels')] [string] $Condition,
          [Parameter(Mandatory)] [string[]] $RequiredLevels, [Parameter(Mandatory)] [string[]] $GrantAny)
    $qualifying = [System.Collections.Generic.List[string]]::new()
    $other = [System.Collections.Generic.List[string]]::new()
    foreach ($pol in @($Policies)) {
        if ($null -eq $pol) { continue }
        if ([string](Get-NRGObjectField -Item $pol -Key 'State' -Default '') -ne 'enabledForReportingButNotEnforced') { continue }
        $levels = @(Get-NRGNestedProperty -Object $pol -Path "Conditions.$Condition" -Default @() | ForEach-Object { [string]$_ } | Where-Object { $_ })
        if ($levels.Count -eq 0) { continue }
        $name = [string](Get-NRGObjectField -Item $pol -Key 'DisplayName' -Default '')
        $why = [System.Collections.Generic.List[string]]::new()
        $missing = @($RequiredLevels | Where-Object { $_ -notin $levels })
        if ($missing.Count -gt 0) { $why.Add("does not select $($missing -join '/') risk") }
        if (-not (Test-NRGCAGrantRequires -Policy $pol -Any $GrantAny)) { $why.Add('does not require a responding control') }
        foreach ($n in @(Get-NRGCANarrowing -Policy $pol | Where-Object { $_ -ne 'applies only at certain risk levels' })) { $why.Add($n) }
        if ($why.Count -eq 0) { $qualifying.Add($name) } else { $other.Add("$name ($($why -join '; '))") }
    }
    [pscustomobject]@{ Qualifying = @($qualifying); Other = @($other) }
}

function Get-NRGRiskReportOnlyNote {
    [CmdletBinding()]
    [OutputType([string])]
    param([AllowNull()] $ReportOnly)
    if ($null -eq $ReportOnly -or @($ReportOnly.Other).Count -eq 0) { return '' }
    return " Report-only (audit mode, not enforcing) and not meeting the full requirement: $(@($ReportOnly.Other) -join '; ')."
}

# ── AAD-1.5 User Risk CA Policy ───────────────────────────────────────────────
function Test-NRGControlAADUserRisk {
    [CmdletBinding()] param()
    $cid = 'AAD-1.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        Add-NRGSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No Conditional Access user risk policy can be in force while Security Defaults is enabled, and Security Defaults has no configurable user risk policy of its own, so neither forces an account Identity Protection rates as likely compromised to change its password or blocks it. Conditional Access risk policies need Microsoft Entra ID P2. The legacy Identity Protection user risk policy (retiring October 1, 2026) is not read by this tool.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access user risk policy in force' -RequiredValue 'CA policy: userRiskLevels = high + require password change or risk remediation' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca  = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    $riskPolicies = @($ca.Data['Policies'] | Where-Object {
        # riskRemediation ("require risk remediation", Microsoft's current
        # template) arrives as unknownFutureValue from data collected without
        # the Prefer header; block and auth strengths are responses too.
        $_.State -eq 'enabled' -and @($_.Conditions.UserRiskLevels).Count -gt 0 -and
        (Test-NRGCAGrantRequires -Policy $_ -Any @('mfa','authStrength','passwordChange','riskRemediation','unknownFutureValue','block'))
    })
    # Microsoft's template is "Require password change for high-risk users":
    # a policy without the High level never applies to those accounts.
    $levels = @($riskPolicies | ForEach-Object { @($_.Conditions.UserRiskLevels) } | ForEach-Object { [string]$_ } | Sort-Object -Unique)
    $names = (@($riskPolicies | ForEach-Object { [string]$_.DisplayName }) -join ', ')
    $ro15 = Get-NRGRiskReportOnlyPolicies -Policies $ca.Data['Policies'] -Condition 'UserRiskLevels' -RequiredLevels @('high') -GrantAny @('mfa','authStrength','passwordChange','riskRemediation','unknownFutureValue','block')
    # Microsoft's v1.0 list withholds some policies (the risk-remediation ones were withheld on the first full
    # run), so with the beta list unread, "no qualifying policy" is not a conclusion the evidence supports.
    if ($levels -notcontains 'high' -and (Get-NRGPolicyListIncomplete -CA $ca)) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "Not assessed: the Conditional Access policy list could not be read in full (the beta list failed and the v1.0 list withholds some policies), so whether a user risk policy exists was not established.$(if ($names) { " Enabled user risk policies read: $names." })"
        return
    }
    if ($levels -contains 'high') {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "User risk Conditional Access in force for high-risk users: $names"
    } elseif ($riskPolicies.Count -eq 0 -and @($ro15.Qualifying).Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "A user risk policy meets every requirement (high user risk, all users and applications, a responding control) but is in report-only mode, which collects evaluation data and enforces nothing: $(@($ro15.Qualifying) -join ', '). Until it is turned on, an account Identity Protection rates high risk is not forced to change its password or blocked; Partial is still a failed baseline requirement.$(Get-NRGRiskReportOnlyNote -ReportOnly $ro15)" `
            -CurrentValue "Report-only: $(@($ro15.Qualifying) -join ', ')" -RequiredValue 'CA policy in force: userRiskLevels = high + require password change or risk remediation' -Remediation $ctrl.Remediation
    } elseif ($riskPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "The enabled user risk policies ($names) apply to $($levels -join ', ') risk only, so an account Identity Protection rates high risk (likely compromised) is not forced to change its password or blocked." `
            -CurrentValue "userRiskLevels = $($levels -join ', ')" -RequiredValue 'CA policy: userRiskLevels = high + require password change or risk remediation' -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail ('No enabled Conditional Access policy uses the user risk condition, so an account Identity Protection rates as likely compromised is not forced to change its password or blocked. (User risk policies need Entra ID P2; on a tenant without it this control is not scored.)' + (Get-NRGRiskReportOnlyNote -ReportOnly $ro15)) -Remediation $ctrl.Remediation
    }
}

# ── AAD-2.2 Named Locations Defined ──────────────────────────────────────────
function Test-NRGControlAADNamedLocations {
    [CmdletBinding()] param()
    $cid = 'AAD-2.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $ca  = Get-NRGRawData -Key 'AAD-CAPolicies'
    # Named locations are a Conditional Access condition, and beside Security
    # Defaults no policy in force can use them. Licensed but not configured
    # is still a Gap: none defined is the same Gap as with Security Defaults
    # off (an unlicensed tenant is moved out of the score by license gating,
    # not here). Locations that exist earn no credit, because nothing can use
    # them until Security Defaults is off. Not read is not assessed.
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        $sdLoc = @{ ControlId = $cid; Category = $ctrl.Category; Title = $ctrl.Title; FrameworkIds = $cit; RequiredValue = 'At least one trusted IP range defined' }
        if ((Get-NRGObjectField -Item $ca -Key 'Success' -Default $null) -ne $true -or -not (Test-NRGSectionCollected $ca 'NamedLocations')) {
            Add-NRGSecurityDefaultsFinding @sdLoc -State 'NotApplicable' `
                -Detail 'Named locations were not collected, so whether any are defined was not assessed.' `
                -CurrentValue 'Security Defaults enabled; named locations: not read'
            return
        }
        $locs = @(@(Get-NRGNestedProperty -Object $ca -Path 'Data.NamedLocations' -Default @()) | Where-Object { $null -ne $_ })
        if ($locs.Count -eq 0) {
            Add-NRGSecurityDefaultsFinding @sdLoc -State 'Gap' -Severity $ctrl.Severity `
                -Detail 'No named locations are defined. Named locations are a Conditional Access condition, and Security Defaults has no location conditions an administrator can configure.' `
                -CurrentValue 'Security Defaults enabled; named locations: 0 defined' `
                -Remediation $ctrl.Remediation -NeedsConditionalAccess
            return
        }
        $trusted = @($locs | Where-Object { (Get-NRGObjectField -Item $_ -Key 'IsTrusted' -Default $false) -eq $true }).Count
        Add-NRGSecurityDefaultsFinding @sdLoc -State 'NotApplicable' `
            -Detail "$($locs.Count) named location(s) are defined ($trusted marked trusted), but named locations are a Conditional Access condition and Security Defaults has no location conditions an administrator can configure, so no policy in force can use them and they earn no credit. The absence of Conditional Access is reported under AAD-2.1." `
            -CurrentValue "Security Defaults enabled; named locations: $($locs.Count) defined ($trusted trusted)"
        return
    }
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    # Empty is not clean. NamedLocations is an independent sub-query from the
    # primary CA-policies fetch (which is all $ca.Success reflects) — a
    # throttled or failed namedLocations call leaves the list empty while
    # Success stays $true, and reading that as "no named locations defined"
    # is a false Gap on a tenant that has them.
    if (-not (Test-NRGSectionCollected $ca 'NamedLocations')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'NamedLocations was not collected; not assessed.'
        return
    }
    $namedLocations   = @(Get-NRGNestedProperty -Object $ca -Path 'Data.NamedLocations' -Default @())
    $trustedLocations = @($namedLocations | Where-Object { $_.IsTrusted })
    if ($trustedLocations.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($trustedLocations.Count) trusted named location(s) defined."
    } elseif ($namedLocations.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail "$($namedLocations.Count) named location(s) defined but none marked as trusted." -CurrentValue 'Named locations defined, none trusted' -RequiredValue 'At least one trusted IP range defined'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No named locations defined. Cannot enforce location-based CA conditions or exclude trusted office IPs.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-2.3 Device Compliance Enforced via CA ─────────────────────────────────
function Test-NRGControlAADDeviceComplianceCA {
    [CmdletBinding()] param()
    $cid = 'AAD-2.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        Add-NRGSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No policy in force requires a compliant or hybrid-joined device. Security Defaults has no device requirement: its MFA prompts do not require the device to be compliant, managed or hybrid-joined, so unmanaged devices can reach corporate resources.' `
            -CurrentValue 'Security Defaults enabled; no compliant-device requirement in force' -RequiredValue 'Compliant or hybrid-joined device required by an enabled CA policy' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca  = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    $devCtl = @('compliantDevice','domainJoinedDevice')
    $compliancePolicies = @($ca.Data['Policies'] | Where-Object { $_.State -eq 'enabled' -and (Test-NRGCAGrantRequires -Policy $_ -Any $devCtl) })
    # "Compliant OR hybrid-joined OR MFA" (a Microsoft template) lets MFA alone
    # through on an unmanaged device, so it does not enforce compliance.
    $optional = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and @($_.GrantControls.BuiltInControls | Where-Object { $_ -in $devCtl }).Count -gt 0 -and -not (Test-NRGCAGrantRequires -Policy $_ -Any $devCtl) })
    if ($compliancePolicies.Count -eq 0 -and $optional.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "A compliant or hybrid-joined device is only one alternative in $(($optional | ForEach-Object { $_.DisplayName }) -join ', ') (grant operator OR): MFA alone still grants access from an unmanaged device." -CurrentValue 'Device compliance optional (OR)' -RequiredValue 'Compliant or hybrid-joined device required' -Remediation $ctrl.Remediation
    } elseif ($compliancePolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Device compliance required by $($compliancePolicies.Count) CA policy(ies)."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No CA policy requires compliant or hybrid-joined device. Unmanaged personal devices access corporate resources unchecked.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-3.2 No Permanent Admin Assignments ────────────────────────────────────
function Test-NRGControlAADNoPermanentAdmins {
    [CmdletBinding()] param()
    $cid = 'AAD-3.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pim = Get-NRGRawData -Key 'AAD-PIMSchedules'
    $roles = Get-NRGRawData -Key 'AAD-DirectoryRoles'
    if (-not $pim -or -not $pim.Success) {
        if ($pim -and $pim.PIMAvailable -eq $false) {
            Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM not available (requires Entra P2 license)'; return
        }
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM data not collected'; return
    }
    # "No permanent privileged role assignments" is a claim about the ROLE data,
    # so it cannot be made without it. Previously $permanentPriv simply stayed
    # empty when AAD-DirectoryRoles was missing or its section had not landed,
    # and the Satisfied branch below fired anyway — producing a clean bill of
    # health on a privilege-escalation control, worded identically to a genuinely
    # clean tenant, from data that never arrived.
    if (-not $roles -or -not $roles.Success -or -not (Test-NRGSectionCollected $roles 'RoleAssignments')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
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
    foreach ($sch in @(Get-NRGNestedProperty -Object $pim -Path 'Data.ActiveSchedules' -Default @())) {
        if ([string](Get-NRGObjectField -Item $sch -Key 'AssignmentType' -Default '') -eq 'Activated') {
            $null = $activated.Add("$(Get-NRGObjectField -Item $sch -Key 'PrincipalId' -Default '')|$(Get-NRGObjectField -Item $sch -Key 'RoleDefinitionId' -Default '')")
        }
    }
    # Break-glass accounts are permanent BY DESIGN (Microsoft: emergency access
    # accounts must not depend on PIM activation). Cloud-only Global Admins
    # excluded from Conditional Access are set aside and named in the detail.
    # Not while Security Defaults is enabled: an administrator cannot exclude
    # any account from it and no CA policy can be on beside it, so a CA
    # exclusion (even a stale CAExcluded = $true) is never credited, and every
    # verdict that depends on that goes through Add-NRGSecurityDefaultsFinding,
    # which reports a CA read contradicting Security Defaults as not assessed.
    $sdOn = (Get-NRGSecurityDefaultsState) -eq $true
    $bgIds = [System.Collections.Generic.HashSet[string]]::new()
    if (-not $sdOn) {
        $govBg = Get-NRGRawData -Key 'AAD-IdentityGovernance'
        foreach ($b in @(Get-NRGNestedProperty -Object $govBg -Path 'Data.BreakGlassIndicators' -Default @())) {
            if ((Get-NRGObjectField -Item $b -Key 'CAExcluded' -Default $false) -eq $true -and -not (Get-NRGObjectField -Item $b -Key 'Synced' -Default $false)) {
                $null = $bgIds.Add([string](Get-NRGObjectField -Item $b -Key 'PrincipalId' -Default ''))
            }
        }
    }
    $pidOf = { param($a) [string](Get-NRGObjectField -Item $a -Key 'PrincipalId' -Default '') }
    $ridOf = { param($a) [string](Get-NRGObjectField -Item $a -Key 'RoleDefinitionId' -Default '') }
    $setAside = @($permanentPriv | Where-Object { (& $pidOf $_) -and $bgIds.Contains((& $pidOf $_)) -and $_.RoleDefinitionName -eq 'Global Administrator' })
    $permanentPriv = @($permanentPriv | Where-Object {
        -not $activated.Contains("$(& $pidOf $_)|$(& $ridOf $_)") -and
        -not ((& $pidOf $_) -and $bgIds.Contains((& $pidOf $_)) -and $_.RoleDefinitionName -eq 'Global Administrator')
    })
    $bgNote = if ($setAside.Count -gt 0) { " $($setAside.Count) break-glass Global Administrator account(s) set aside (permanent by design): $(($setAside | ForEach-Object { $_.PrincipalDisplayName }) -join ', ')." } else { '' }

    # Same rule for the PIM half. The collector pre-initialises every section to
    # @(), so an empty EligibleSchedules is ambiguous between "no PIM adoption"
    # and "the query failed" — and only the section status can tell them apart.
    $eligibleCollected = Test-NRGSectionCollected $pim 'EligibleSchedules'
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
                $v = [string](Get-NRGObjectField -Item $a -Key $k -Default '')
                if ($v) { return $v }
            }
            return ''
        }
        # OnPremisesSyncEnabled is $null for an account never synchronized
        # (Graph's documented cloud-only value) and for one whose value was
        # not read, so the prose says "not marked as synchronized" — what was
        # read — never "cloud-only".
        $nonGa  = @($permanentPriv | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'RoleDefinitionName' -Default '') -ne 'Global Administrator' })
        $synced = @($permanentPriv | Where-Object { (Get-NRGObjectField -Item $_ -Key 'OnPremisesSyncEnabled' -Default $null) -eq $true })
        $people = @($permanentPriv | ForEach-Object { & $keyOf $_ } | Sort-Object -Unique)
        if ($nonGa.Count -eq 0 -and $synced.Count -eq 0 -and $people.Count -le 2) {
            $gaNames = @($permanentPriv | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'PrincipalDisplayName' -Default '') } | Where-Object { $_ } | Sort-Object -Unique) -join ', '
            # One account or two: the prose follows what was read.
            $which = if ($people.Count -eq 1) { 'whether this account is one of' } else { 'whether these accounts are' }
            $conv  = if ($people.Count -eq 1) { 'if it is, no standing privileged access exists outside it; if it is not, convert it to a PIM-eligible assignment' } else { 'if they are, no standing privileged access exists outside them; if they are not, convert them to PIM-eligible assignments' }
            Add-NRGSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'NotApplicable' `
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
            Add-NRGSecurityDefaultsFinding @g -State 'Gap' -Detail ($gapText + $script:NRGSecurityDefaultsNoExclusionNote)
        } else {
            Add-NRGFinding @g -State 'Gap' -Detail "$gapText$bgNote"
        }
    } elseif (-not $eligibleCollected) {
        # Roles are clean, but we cannot say whether PIM is in use.
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'No permanent privileged assignments were found, but the PIM eligible-schedule query did not complete, so PIM adoption could not be confirmed. Not assessed.'
    } elseif ($eligibleCount -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "No permanent privileged role assignments. $eligibleCount eligible (PIM) assignment(s) configured.$bgNote"
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'PIM is available but no eligible (just-in-time) role assignments are configured. Privileged roles are not managed through PIM.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-3.3 PIM Requires MFA on Activation ───────────────────────────────────
function Test-NRGControlAADPIMMFA {
    [CmdletBinding()] param()
    $cid = 'AAD-3.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success -or @($gov.Data['PIMRolePolicies']).Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM policy data not collected or PIM not licensed'; return
    }
    $sc = Get-NRGPIMScopedPolicies -Policies $gov.Data['PIMRolePolicies']
    $scope = if ($sc.Scoped) { 'privileged-role' } else { 'PIM role' }
    $note  = if ($sc.Scoped) { '' } else { ' (Policy-to-role mapping was unavailable, so every role was scored, not only privileged ones.)' }
    $noMFA = @($sc.Policies | Where-Object { $_.RequiresMFA -eq $false })
    $unknown = @($sc.Policies | Where-Object { $null -eq $_.RequiresMFA })
    if ($noMFA.Count -gt 0) {
        $names = if ($sc.Scoped) { ' Roles: ' + (($noMFA | ForEach-Object { $_.RoleName } | Sort-Object) -join ', ') + '.' } else { '' }
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$($noMFA.Count) of $(@($sc.Policies).Count) $scope policy(ies) do not require MFA (or an authentication context) on activation.$names$note" -CurrentValue "$($noMFA.Count) without MFA on activation" -RequiredValue 'MFA or authentication context required on activation' -Remediation $ctrl.Remediation
    } elseif (@($sc.Policies).Count -eq 0 -or $unknown.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "Activation MFA setting could not be read for $($unknown.Count) $scope policy(ies); not assessed."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "All $(@($sc.Policies).Count) $scope policies require MFA (or an authentication context) on activation.$note"
    }
}

# ── AAD-3.4 PIM Requires Justification ───────────────────────────────────────
function Test-NRGControlAADPIMJustification {
    [CmdletBinding()] param()
    $cid = 'AAD-3.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success -or @($gov.Data['PIMRolePolicies']).Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM policy data not collected'; return
    }
    $sc = Get-NRGPIMScopedPolicies -Policies $gov.Data['PIMRolePolicies']
    $scope = if ($sc.Scoped) { 'privileged-role' } else { 'PIM role' }
    $note  = if ($sc.Scoped) { '' } else { ' (Policy-to-role mapping was unavailable, so every role was scored, not only privileged ones.)' }
    $noJust = @($sc.Policies | Where-Object { $_.RequiresJustification -eq $false })
    $unknown = @($sc.Policies | Where-Object { $null -eq $_.RequiresJustification })
    if ($noJust.Count -gt 0) {
        $names = if ($sc.Scoped) { ' Roles: ' + (($noJust | ForEach-Object { $_.RoleName } | Sort-Object) -join ', ') + '.' } else { '' }
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$($noJust.Count) of $(@($sc.Policies).Count) $scope policy(ies) do not require justification — no audit trail for why privilege was elevated.$names$note" -Remediation $ctrl.Remediation
    } elseif (@($sc.Policies).Count -eq 0 -or $unknown.Count -gt 0) {
        # A $null RequiresJustification means the rule could not be read — never a pass.
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "Activation justification setting could not be read for $($unknown.Count) $scope policy(ies); not assessed."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "All $(@($sc.Policies).Count) $scope policies require justification on activation.$note"
    }
}

# ── AAD-3.5 PIM GA Activation Requires Approval ──────────────────────────────
function Test-NRGControlAADPIMApproval {
    [CmdletBinding()] param()
    $cid = 'AAD-3.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success -or @($gov.Data['PIMRolePolicies']).Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM policy data not collected'; return
    }
    # Graph names every directory-role policy "DirectoryRole", so the GA policy
    # is found by its role, via the collector's policy->role map. The Global
    # Administrator built-in role template ID is a Microsoft constant, identical
    # in every tenant.
    $gaTemplateId = '62e90394-69f5-4237-9190-012177145e10'
    $gaPolicy = @($gov.Data['PIMRolePolicies'] | Where-Object {
        [string](Get-NRGObjectField -Item $_ -Key 'RoleDefinitionId' -Default '') -eq $gaTemplateId
    }) | Select-Object -First 1
    if (-not $gaPolicy) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Global Administrator PIM policy could not be identified (policy-to-role assignment data not collected); not assessed.'; return
    }
    if ($null -eq (Get-NRGObjectField -Item $gaPolicy -Key 'RequiresApproval')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Global Administrator PIM approval setting could not be read; not assessed.'; return
    }
    if ($gaPolicy.RequiresApproval -eq $true) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Global Administrator PIM activation requires approval.'
    } else {
        # Approval off is the setting not configured: a Gap, not half credit.
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Global Administrator PIM activation does not require approval, so any user eligible for Global Administrator can activate it alone.' -CurrentValue 'Approval not required' -RequiredValue 'Approval required to activate Global Administrator' -Remediation $ctrl.Remediation
    }
}

# ── AAD-3.6 PIM Max Activation Duration ──────────────────────────────────────
function Test-NRGControlAADPIMDuration {
    [CmdletBinding()] param()
    $cid = 'AAD-3.6'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success -or @($gov.Data['PIMRolePolicies']).Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'PIM policy data not collected'; return
    }
    $sc = Get-NRGPIMScopedPolicies -Policies $gov.Data['PIMRolePolicies']
    $scope = if ($sc.Scoped) { 'privileged-role' } else { 'PIM role' }
    $note  = if ($sc.Scoped) { '' } else { ' (Policy-to-role mapping was unavailable, so every role was scored, not only privileged ones.)' }
    $longDuration = @($sc.Policies | Where-Object { $null -ne $_.MaxDurationHours -and $_.MaxDurationHours -gt 8 })
    $unknownDuration = @($sc.Policies | Where-Object { $null -eq $_.MaxDurationHours })
    if ($longDuration.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail "$($longDuration.Count) $scope policy(ies) allow activation >8 hours. Shorter windows reduce blast radius.$note" -CurrentValue ">8h max duration" -RequiredValue '≤8 hours max duration'
    } elseif (@($sc.Policies).Count -eq 0 -or $unknownDuration.Count -gt 0) {
        # Previously scored Partial on an unreadable duration — a verdict the tool never computed.
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "Maximum activation duration could not be read for $($unknownDuration.Count) $scope policy(ies); not assessed."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "All $(@($sc.Policies).Count) $scope policies have max activation ≤8 hours.$note"
    }
}

# ── AAD-4.1 Guest Invite Permissions Restricted ───────────────────────────────
function Test-NRGControlAADGuestInvite {
    [CmdletBinding()] param()
    $cid = 'AAD-4.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    # A failed authorizationPolicy read defaulted to 'everyone' and scored a
    # Gap ("Anyone can invite guests") on tenants that restrict invitations.
    if (-not (Test-NRGSectionCollected $gov 'ExternalCollab')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'ExternalCollab was not collected; not assessed.'
        return
    }
    $inviteFrom = [string](Get-NRGNestedProperty -Object $gov -Path 'Data.ExternalCollab.AllowInvitesFrom' -Default '')
    if (-not $inviteFrom) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The guest-invitation setting (allowInvitesFrom) was not returned; not assessed.'
        return
    }
    $secure     = @('adminsAndGuestInviters','admins','none')
    if ($inviteFrom -in $secure) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Guest invitations restricted to: $inviteFrom"
    } elseif ($inviteFrom -eq 'adminsGuestInvitersAndAllMembers') {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail 'All members can invite guests — restrict to admins only.' -CurrentValue $inviteFrom -RequiredValue 'adminsAndGuestInviters or admins'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "Anyone can invite guest users ($inviteFrom). This allows uncontrolled external access provisioning." -CurrentValue $inviteFrom -RequiredValue 'adminsAndGuestInviters' -Remediation $ctrl.Remediation
    }
}

# ── AAD-4.2 External Collaboration Settings ───────────────────────────────────
function Test-NRGControlAADExternalCollab {
    [CmdletBinding()] param()
    $cid = 'AAD-4.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $gov 'ExternalCollab')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'ExternalCollab was not collected; not assessed.'
        return
    }
    $collab = Get-NRGNestedProperty -Object $gov -Path 'Data.ExternalCollab'
    $gaps = @()
    if (Get-NRGNestedProperty -Object $collab -Path 'DefaultUserRolePermissions.AllowedToCreateTenants') { $gaps += 'Users can create new tenants' }
    # blockMsolPowerShell is no longer scored: Microsoft retired the MSOnline
    # module (April-May 2025), so the setting no longer gates any access.
    if ($gaps.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'External collaboration settings properly restricted.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "External collab gaps: $($gaps -join '; ')" -Remediation $ctrl.Remediation
    }
}

# ── AAD-4.3 B2B Guest Default Permissions Restricted ─────────────────────────
function Test-NRGControlAADGuestPermissions {
    [CmdletBinding()] param()
    $cid = 'AAD-4.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
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
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Guests have the Restricted Guest User role: they can read only their own directory objects.'
    } elseif ($guestRoleId -eq '10dae51f-b6af-4016-8d66-8c2a99b929b3') {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Guests have the default Guest User role (limited access): they can still read the membership of groups they belong to. The Restricted Guest User role limits them to their own objects.' -CurrentValue 'Guest User (limited access, default)' -RequiredValue 'Restricted Guest User role' -Remediation $ctrl.Remediation
    } elseif ([string]::IsNullOrEmpty($guestRoleId)) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Guest role ID not available in collected data'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Guest users may have excessive default permissions. Set to Restricted Guest User.' -CurrentValue "RoleId: $guestRoleId" -RequiredValue 'Restricted Guest User role' -Remediation $ctrl.Remediation
    }
}

# ── AAD-5.1 SSPR Enabled ──────────────────────────────────────────────────────
function Test-NRGControlAADSSPR {
    [CmdletBinding()] param()
    $cid = 'AAD-5.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $auth = Get-NRGRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    # Empty is not clean. AuthorizationPolicy is an independent sub-query from
    # the collector's overall Success flag — a failed read leaves it $null
    # while Success stays $true, and defaulting AllowedToUseSSPR to $false in
    # that case reported "SSPR is disabled" on tenants where it is enabled.
    if (-not (Test-NRGSectionCollected $auth 'AuthorizationPolicy')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AuthorizationPolicy was not collected; not assessed.'
        return
    }
    # authorizationPolicy.allowedToUseSSPR is documented as whether
    # ADMINISTRATORS can use SSPR, not users. The user SSPR setting
    # (None / Selected / All) is not exposed by a supported Graph read, so the
    # old verdict answered a different question.
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title "$($ctrl.Title) (Manual review required)" -FrameworkIds $cit `
        -Detail 'This control requires manual verification — the user self-service password reset setting is not exposed by a supported read API. Check Entra ID > Protection > Password reset > Properties (Selected or All).'
}

# ── AAD-5.2 SSPR Requires Multiple Auth Methods ───────────────────────────────
function Test-NRGControlAADSSPRMethods {
    [CmdletBinding()] param()
    $cid = 'AAD-5.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    # The number of methods required to reset (1 or 2) lives in the legacy
    # SSPR policy, which has no supported read API; counting the methods
    # ENABLED in the authentication methods policy ("6 methods enabled")
    # answered a different question and passed tenants requiring one method.
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title "$($ctrl.Title) (Manual review required)" -FrameworkIds $cit `
        -Detail 'This control requires manual verification — the number of methods required to reset a password is not exposed by a supported read API. Check Entra ID > Protection > Password reset > Authentication methods (Number of methods required to reset = 2).'
}

# ── AAD-6.1 User App Registration Disabled ────────────────────────────────────
function Test-NRGControlAADUserAppReg {
    [CmdletBinding()] param()
    $cid = 'AAD-6.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    # The setting is collected in two places (identity governance and the
    # AAD-AuthPolicies authorization policy). A missing value used to default
    # to "users CAN register apps" and score a High Gap — on a live tenant
    # whose raw data showed AllowedToCreateApps = false. Read either source;
    # with neither, say so instead of guessing.
    $canCreateRaw = Get-NRGNestedProperty -Object $gov -Path 'Data.ExternalCollab.DefaultUserRolePermissions.AllowedToCreateApps' -Default $null
    if ($null -eq $canCreateRaw) {
        $authPol = Get-NRGRawData -Key 'AAD-AuthPolicies'
        $canCreateRaw = Get-NRGNestedProperty -Object $authPol -Path 'Data.AuthorizationPolicy.DefaultUserRolePermissions.AllowedToCreateApps' -Default $null
    }
    if ($null -eq $canCreateRaw) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The user app-registration setting (defaultUserRolePermissions.allowedToCreateApps) was not collected; not assessed.'; return
    }
    $canCreate = [bool]$canCreateRaw
    if (-not $canCreate) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Users cannot register applications. Only admins can create app registrations.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Any user can register applications. Malicious OAuth apps or accidental exposure of sensitive API permissions is possible.' -CurrentValue 'AllowedToCreateApps = $true' -RequiredValue 'AllowedToCreateApps = $false' -Remediation $ctrl.Remediation
    }
}

# ── AAD-6.2 User Consent to Apps Restricted ───────────────────────────────────
function Test-NRGControlAADUserConsent {
    [CmdletBinding()] param()
    $cid = 'AAD-6.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    # Empty is not clean. A failed ExternalCollab sub-query leaves no consent
    # policies to inspect, and "no unrestricted consent policy found" then reads
    # as "user consent is restricted" — a false pass on the control that stops
    # consent phishing.
    if (-not (Test-NRGSectionCollected $gov 'ExternalCollab')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'ExternalCollab was not collected; not assessed.'
        return
    }
    # Key presence, not the property helper: an empty list (no user consent
    # at all) would come back as $null and read as "not returned".
    $ec  = Get-NRGNestedProperty -Object $gov -Path 'Data.ExternalCollab' -Default $null
    $raw = $null; $has = $false
    if ($ec -is [System.Collections.IDictionary]) { if ($ec.Contains('PermissionGrantPolicies')) { $has = $true; $raw = $ec['PermissionGrantPolicies'] } }
    elseif ($null -ne $ec -and $ec.PSObject.Properties['PermissionGrantPolicies']) { $has = $true; $raw = $ec.PermissionGrantPolicies }
    if (-not $has -or ($null -eq $raw -and $has)) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The user-consent setting (permissionGrantPoliciesAssigned) was not returned, so it was not assessed.'
        return
    }
    $consentPolicies = @(@($raw) | ForEach-Object { [string]$_ } | Where-Object { $_ -like 'ManagePermissionGrantsForSelf.*' })
    # microsoft-user-default-legacy = users can consent to ANY app permission.
    # microsoft-user-default-low    = verified publishers, low-impact permissions only.
    # A custom ManagePermissionGrantsForSelf.* policy allows whatever it defines,
    # which this tool cannot evaluate, so it is not called restricted.
    $unrestrictedConsent = $consentPolicies | Where-Object { $_ -match 'legacy|ByDefault' }
    $custom = @($consentPolicies | Where-Object { $_ -notmatch 'microsoft-user-default-(legacy|low)$' })
    # Expected state: users cannot consent freely (disabled, or limited to low-impact permissions from
    # verified publishers). The admin consent workflow is a different safeguard that AAD-6.3 owns; it is
    # shown here as related context and never decides this verdict, so one disabled workflow costs one
    # baseline failure (AAD-6.3), not two.
    $verified = @(); $short = @(); $unknown = @()
    if ($consentPolicies.Count -eq 0) {
        $verified += 'Users cannot consent to applications (no user consent policy assigned).'
    } elseif (-not $unrestrictedConsent -and $custom.Count -eq 0) {
        $verified += "User consent is limited to low-impact permissions for apps from verified publishers ($($consentPolicies -join ', '))."
    } elseif (-not $unrestrictedConsent) {
        $unknown += "what user consent allows, because it is governed by a custom permission grant policy ($($custom -join ', ')) that requires manual verification."
    } else {
        $short += 'Users can consent to any app permissions. Consent phishing attacks grant attacker apps access to mailbox, files, and contacts without admin awareness.'
    }
    $context = ''
    if (Test-NRGSectionCollected $gov 'ConsentPolicy') {
        $wf = Get-NRGNestedProperty -Object $gov -Path 'Data.ConsentPolicy.IsEnabled' -Default $null
        if ($wf -is [bool] -and $wf) { $context = 'the admin consent workflow is enabled (AAD-6.3).' }
        elseif ($wf -is [bool]) { $context = 'the admin consent workflow is disabled, so users who need an app have no approval path (scored under AAD-6.3).' }
    }
    Add-NRGExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $unknown `
        -ShortfallState 'Gap' -Context $context `
        -CurrentValue $(if ($consentPolicies.Count) { $consentPolicies -join ', ' } else { 'No user consent policy assigned' }) `
        -RequiredValue 'User consent disabled, or limited to low-impact permissions from verified publishers'
}

# ── AAD-6.3 Admin Consent Workflow Enabled ────────────────────────────────────
function Test-NRGControlAADAdminConsentWorkflow {
    [CmdletBinding()] param()
    $cid = 'AAD-6.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    # A failed adminConsentRequestPolicy read (403) left IsEnabled at its
    # $false default and scored "admin consent workflow disabled".
    if (-not (Test-NRGSectionCollected $gov 'ConsentPolicy')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'ConsentPolicy was not collected; not assessed.'
        return
    }
    $consentEnabled = [bool](Get-NRGNestedProperty -Object $gov -Path 'Data.ConsentPolicy.IsEnabled' -Default $false)
    if ($consentEnabled) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Admin consent workflow enabled — users can request app access via approval process.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Admin consent workflow disabled. Users who need app access have no path to request it — may bypass controls or use unmanaged alternatives.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-7.1 Password Protection Lockout Configured ───────────────────────────
function Test-NRGControlAADPasswordProtection {
    [CmdletBinding()] param()
    $cid = 'AAD-7.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $auth = Get-NRGRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success -or -not $auth.Data['PasswordProtection']) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Password protection data not collected (the Password Rule Settings read from /v1.0/groupSettings failed or did not run).'; return
    }
    $pp = $auth.Data['PasswordProtection']
    $lockout = [int]($pp.LockoutThreshold ?? 10)
    if ($lockout -le 10) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Password lockout threshold: $lockout failed attempts."
    } else {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit -Detail "Lockout threshold is $lockout — consider reducing to ≤10 to limit brute force window." -CurrentValue "LockoutThreshold = $lockout" -RequiredValue '≤10 failed attempts'
    }
}

# ── AAD-7.2 Break-Glass Accounts Configured ───────────────────────────────────
function Test-NRGControlAADBreakGlass {
    [CmdletBinding()] param()
    $cid = 'AAD-7.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
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
    # (Get-NRGAssessmentScope files it for manual review). Runs before the
    # BreakGlassIndicators gate, which reads NotRun whenever the CA read
    # failed.
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        $sdBg = @{ ControlId = $cid; Category = $ctrl.Category; Title = $ctrl.Title; FrameworkIds = $cit }
        $noExclusion = "It cannot be scoped or customized (Microsoft: 'No customization (on or off)'), so an administrator cannot exclude any account from it (its only exclusion is Microsoft's automatic one for directory synchronization accounts), and this control recognizes emergency access (break-glass) accounts only by their exclusion from Conditional Access policies in force."
        $verify = "confirm they exist, that their credentials are held offline, and that each has an MFA method registered, because Security Defaults requires Global Administrators to complete MFA at every sign-in"
        if (-not (Test-NRGSectionCollected $gov 'BreakGlassIndicators')) {
            Add-NRGSecurityDefaultsFinding @sdBg -State 'NotApplicable' `
                -Detail "$noExclusion Microsoft recommends two cloud-only emergency access accounts permanently assigned Global Administrator; the Global Administrator list this check reads (BreakGlassIndicators) was not collected, so whether they exist was not assessed." `
                -RequiredValue 'Two cloud-only emergency access Global Administrator accounts, permanently assigned (confirm manually while Security Defaults is on)'
            return
        }
        $all = @(@(Get-NRGNestedProperty -Object $gov -Path 'Data.BreakGlassIndicators' -Default @()) | Where-Object { $null -ne $_ })
        if ($all.Count -eq 0) {
            Add-NRGSecurityDefaultsFinding @sdBg -State 'NotApplicable' -Detail 'No Global Administrator accounts were found to evaluate.'
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
            (Get-NRGObjectField -Item $_ -Key 'Synced' -Default $false) -ne $true -and
            [string](Get-NRGObjectField -Item $_ -Key 'Source' -Default 'permanent') -eq 'permanent'
        } | Where-Object {
            $k = [string](Get-NRGObjectField -Item $_ -Key 'PrincipalId' -Default '')
            if (-not $k) { $k = [string](Get-NRGObjectField -Item $_ -Key 'UPN' -Default ([guid]::NewGuid().ToString())) }
            $seen.Add($k)
        })
        $syncedN   = @($all | Where-Object { (Get-NRGObjectField -Item $_ -Key 'Synced' -Default $false) -eq $true }).Count
        $eligibleN = @($all | Where-Object { [string](Get-NRGObjectField -Item $_ -Key 'Source' -Default 'permanent') -ne 'permanent' }).Count
        $names = @($cand | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'DisplayName' -Default '') } | Where-Object { $_ }) -join ', '
        $read  = "$($all.Count) Global Administrator assignment(s) were read ($syncedN on accounts marked as synchronized from on-premises, $eligibleN PIM-eligible)"
        $current = "Permanent Global Administrator assignments on accounts not marked as synchronized from on-premises: $($cand.Count)$(if ($names) { " ($names)" })"
        $required = 'Two cloud-only emergency access Global Administrator accounts, permanently assigned'
        $bgFix = 'Keep two cloud-only emergency access accounts permanently assigned Global Administrator (create whichever are missing), with long random passwords held offline, and register an MFA method for each (Security Defaults requires Global Administrators to complete MFA at every sign-in). When Conditional Access replaces Security Defaults, exclude both from every policy that would otherwise reach them, and monitor their sign-ins.'
        if ($cand.Count -eq 0) {
            Add-NRGSecurityDefaultsFinding @sdBg -State 'Gap' -Severity $ctrl.Severity `
                -Detail "$read, and none is a permanent assignment on an account not marked as synchronized from on-premises. Microsoft recommends two cloud-only emergency access accounts permanently assigned Global Administrator, so no emergency access account of the recommended kind exists." `
                -CurrentValue $current -RequiredValue $required -Remediation $bgFix
        } elseif ($cand.Count -eq 1) {
            Add-NRGSecurityDefaultsFinding @sdBg -State 'Gap' -Severity $ctrl.Severity `
                -Detail "$read, and only one is a permanent assignment on an account not marked as synchronized from on-premises. Microsoft recommends two cloud-only emergency access accounts permanently assigned Global Administrator, so the two-account recommendation is not met. Whether this one account is kept as an emergency access account could not be determined, because Security Defaults offers no exclusion to recognize it by." `
                -CurrentValue $current -RequiredValue $required -Remediation $bgFix
        } else {
            Add-NRGSecurityDefaultsFinding @sdBg -State 'NotApplicable' `
                -Detail "$noExclusion Microsoft recommends two cloud-only emergency access accounts permanently assigned Global Administrator. $($cand.Count) permanent Global Administrator assignment(s) are on accounts not marked as synchronized from on-premises; whether two of them are emergency access accounts requires manual verification: $verify." `
                -CurrentValue $current -RequiredValue "$required (confirm manually while Security Defaults is on)"
        }
        return
    }
    # Without the CA data the exclusion check never ran (NotRun): every
    # CAExcluded is a default $false, and reading that as "no break-glass
    # accounts" was a false Gap.
    if (-not (Test-NRGSectionCollected $gov 'BreakGlassIndicators')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'BreakGlassIndicators was not collected (role or Conditional Access data missing); not assessed.'
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
    $nameOf = { param($a) "$([string](Get-NRGObjectField -Item $a -Key 'DisplayName' -Default '')) ($([string](Get-NRGObjectField -Item $a -Key 'UPN' -Default '')))" }
    $quote  = { param($list) (@($list | ForEach-Object { "'$_'" })) -join ', ' }
    $candidates = @($allGAs | Where-Object { $_.CAExcluded -eq $false -and -not $_.Synced -and (Get-NRGObjectField -Item $_ -Key 'BlockingExcluded' -Default $false) -eq $true })
    $candidateNotes = @($candidates | ForEach-Object {
        $left = @(@(Get-NRGObjectField -Item $_ -Key 'NotExcludedFrom' -Default @()) | Where-Object { $_ })
        "$(& $nameOf $_) is excluded from every policy with a grant control but is still reached by $(& $quote $left) (session controls only)"
    })
    $nearMiss = @($allGAs | Where-Object { $_.CAExcluded -eq $false -and -not $_.Synced -and (Get-NRGObjectField -Item $_ -Key 'BlockingExcluded' -Default $false) -ne $true } | ForEach-Object {
        $left = @(@(Get-NRGObjectField -Item $_ -Key 'NotExcludedFrom' -Default @()) | Where-Object { $_ })
        if ($left.Count -ge 1 -and $left.Count -le 2) { "$(& $nameOf $_) is still reached by $(& $quote $left)" }
    })
    $notes = @($candidateNotes) + @($nearMiss)
    $nearNote = if ($notes.Count -gt 0) { " Not excluded from every enabled policy: $($notes -join '; '). Microsoft recommends excluding emergency access accounts from policies that block or restrict sign-in; exclude these accounts from the named policies too." } else { '' }
    if ($bgAccounts.Count -lt 2 -and $unknownBg.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail "$($unknownBg.Count) Global Administrator account(s) may be excluded through a group whose membership could not be read, so break-glass coverage was not assessed."
    } elseif ($bgAccounts.Count -ge 2) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($bgAccounts.Count) cloud-only GA account(s) are excluded from every enabled Conditional Access policy that reaches them, consistent with the break-glass pattern."
    } elseif ($bgAccounts.Count -eq 1) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "Only one cloud-only GA is excluded from every enabled Conditional Access policy that reaches it. Best practice is two break-glass accounts for redundancy.$nearNote" -CurrentValue '1 break-glass account' -RequiredValue '2 break-glass accounts'
    } elseif ($candidates.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit -Detail "No cloud-only GA is excluded from every enabled Conditional Access policy, but $($candidates.Count) is excluded from every policy that can deny sign-in through a grant control.$nearNote" -CurrentValue "$($candidates.Count) candidate break-glass account(s), still reached by session-only policies" -RequiredValue '2 break-glass accounts excluded from every enabled policy' -Remediation $ctrl.Remediation
    } elseif ($allGAs.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "No cloud-only GA account is excluded from every enabled Conditional Access policy that reaches it, so a misconfigured policy could leave no emergency access path to the tenant.$nearNote" -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'No GA accounts found to evaluate'
    }
}

# ── AAD-8.1 PIM Alerts Configured ────────────────────────────────────────────
function Test-NRGControlAADPIMAlerts {
    [CmdletBinding()] param()
    $cid = 'AAD-8.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pim = Get-NRGRawData -Key 'AAD-PIMSchedules'
    if (-not $pim -or -not $pim.PIMAvailable) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'PIM not available (requires Entra P2)'; return
    }
    # PIM alert configuration (Roles assigned outside PIM / Redundant roles /
    # Stale assignments) requires GET /beta/privilegedAccess/aadRoles/alerts,
    # which is not collected — this control has no programmatic check today.
    # It must emit NotApplicable, never Partial: Partial is worth 0.5 toward
    # the compliance score, so an unconditional Partial here handed every
    # Entra P2 tenant free credit for a verdict the tool never computed.
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Medium' -FrameworkIds $cit `
        -Detail 'This control requires manual verification — PIM alert configuration is not exposed to the APIs this assessment uses. Verify in PIM > Alerts: Roles assigned outside PIM, Redundant roles, Stale assignments.' `
        -Remediation $ctrl.Remediation
}

# ── AAD-8.2 Access Reviews for Privileged Roles ───────────────────────────────
function Test-NRGControlAADAccessReviews {
    [CmdletBinding()] param()
    $cid = 'AAD-8.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $pim = Get-NRGRawData -Key 'AAD-PIMSchedules'
    if (-not $pim -or -not $pim.PIMAvailable) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'PIM not available — access reviews require Entra P2'; return
    }
    # Access review definitions need the AccessReview.Read.All scope, which is a
    # re-consent scope (like AAD-11.3 / DEF-4.6). Until the enterprise app is
    # re-consented the collector can't read them — report NotApplicable, never a
    # false "no reviews" gap.
    if (-not $pim.AccessReviewsCollected) {
        $why = if (Test-NRGGraphScopeMissing -Scope 'AccessReview.Read.All') { Get-NRGConsentMissingDetail -Scope 'AccessReview.Read.All' }
               else { 'Access review data not collected — requires the AccessReview.Read.All scope (re-consent the enterprise app in each tenant). Verify manually in PIM > Microsoft Entra roles > Access reviews.' }
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -FrameworkIds $cit -Detail $why
        return
    }
    $reviews = @($pim.Data['AccessReviews'] ?? @())
    $activeStatuses = @('InProgress', 'NotStarted', 'Applying', 'Applied')
    $roleReviews = @($reviews | Where-Object {
        (Get-NRGObjectField -Item $_ -Key 'TargetsRoles') -eq $true -and
        ([string](Get-NRGObjectField -Item $_ -Key 'Status')) -in $activeStatuses
    })
    # A role review that ran once and finished recertified access at one point
    # in time; nothing re-reviews it. Part-way, not "no role reviews".
    $pastRoleReviews = @($reviews | Where-Object {
        (Get-NRGObjectField -Item $_ -Key 'TargetsRoles') -eq $true -and
        ([string](Get-NRGObjectField -Item $_ -Key 'Status')) -notin $activeStatuses
    })
    if ($roleReviews.Count -eq 0 -and $pastRoleReviews.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "$($pastRoleReviews.Count) access review(s) of privileged roles exist but none is active or recurring ($(($pastRoleReviews | ForEach-Object { "$(Get-NRGObjectField -Item $_ -Key 'DisplayName' -Default '?') [$(Get-NRGObjectField -Item $_ -Key 'Status' -Default '?')]" }) -join ', ')). Role assignments are not re-attested going forward." `
            -CurrentValue 'Role review completed, not recurring' -RequiredValue 'A recurring access review scoped to privileged directory roles' -Remediation $ctrl.Remediation
    } elseif ($roleReviews.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($roleReviews.Count) active access review(s) recertify privileged directory-role assignments. Standing admin access is periodically re-attested instead of accumulating unchecked." `
            -CurrentValue "$($roleReviews.Count) role access review(s) active"
    } elseif ($reviews.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "$($reviews.Count) access review(s) exist but none target privileged directory roles. Groups/apps are reviewed, but Global Admin and other privileged role assignments are not recertified." `
            -CurrentValue 'Access reviews present, none for privileged roles' `
            -RequiredValue 'A recurring access review scoped to privileged directory roles' `
            -Remediation $ctrl.Remediation
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No access reviews are configured. Privileged role assignments are never recertified, so stale or over-provisioned admin access accumulates unnoticed.' `
            -CurrentValue 'No access reviews configured' `
            -RequiredValue 'A recurring access review scoped to privileged directory roles' `
            -Remediation $ctrl.Remediation
    }
}

# ── AAD-9.1 Authenticator Number Matching Enabled ────────────────────────────
function Test-NRGControlAADAuthenticatorNumberMatch {
    [CmdletBinding()] param()
    $cid = 'AAD-9.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $auth = Get-NRGRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $auth 'AuthMethodsPolicy')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AuthMethodsPolicy was not collected; not assessed.'
        return
    }
    $ampConfigs = @(Get-NRGNestedProperty -Object $auth -Path 'Data.AuthMethodsPolicy.AuthenticationMethodConfigs' -Default @())
    $mfaConfig  = $ampConfigs | Where-Object { $_.Id -eq 'MicrosoftAuthenticator' } | Select-Object -First 1
    # Microsoft enforced number matching as the platform default in May 2023.
    # When the property is null/empty the API is reporting "MS is enforcing it
    # at the platform level" — NOT "we don't know". Treating absence as unknown
    # produced "Number matching state is ''" Gap findings on every modern
    # tenant (mirrors the AAD-2.3 fix in Test-NRGControlAADCA.ps1).
    $nmStateRaw = Get-NRGNestedProperty -Object $mfaConfig -Path 'FeatureSettings.NumberMatchingRequiredState'
    $nmState    = if ($null -eq $nmStateRaw -or [string]::IsNullOrWhiteSpace([string]$nmStateRaw)) {
                      'default'
                  } else {
                      [string]$nmStateRaw
                  }
    if ($nmState -eq 'enabled' -or $nmState -eq 'default') {
        $msg = if ($nmState -eq 'enabled') {
            'Microsoft Authenticator number matching is explicitly enabled — MFA fatigue attacks blocked.'
        } else {
            'Number matching: enabled (Microsoft platform default since May 2023). Explicit configuration is optional but ensures it cannot be disabled.'
        }
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail $msg `
            -CurrentValue "NumberMatchingRequiredState = $nmState" `
            -RequiredValue 'enabled (or default)'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "Number matching state is '$nmState'. MFA push fatigue attacks are possible — attacker can spam approve requests." `
            -CurrentValue "NumberMatchingRequiredState = $nmState" `
            -RequiredValue 'enabled' -Remediation $ctrl.Remediation
    }
}

# ── AAD-9.2 Passwordless Auth Methods Available ───────────────────────────────
function Test-NRGControlAADPasswordless {
    [CmdletBinding()] param()
    $cid = 'AAD-9.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $auth = Get-NRGRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $auth 'AuthMethodsPolicy')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AuthMethodsPolicy was not collected; not assessed.'
        return
    }
    $ampConfigs = @(Get-NRGNestedProperty -Object $auth -Path 'Data.AuthMethodsPolicy.AuthenticationMethodConfigs' -Default @())
    # Passwordless methods in the authentication methods policy: FIDO2 /
    # passkeys, Microsoft Authenticator in passwordless-capable mode ('any' or
    # 'deviceBasedPush'), and certificate-based authentication. There is no
    # 'WindowsHello' method configuration (WHfB is device-side), so reading it
    # found nothing, and Authenticator phone sign-in was ignored.
    $on = { param($id) $ampConfigs | Where-Object { (Get-SafeProp $_ 'Id') -eq $id -and [string](Get-SafeProp $_ 'State') -eq 'enabled' } | Select-Object -First 1 }
    $methods = @()
    if (& $on 'Fido2') { $methods += 'FIDO2 / passkeys' }
    $ma = & $on 'MicrosoftAuthenticator'
    if ($ma -and @(@(Get-NRGObjectField -Item $ma -Key 'AuthenticationModes' -Default @()) | Where-Object { $_ -in @('any','deviceBasedPush') }).Count -gt 0) { $methods += 'Microsoft Authenticator phone sign-in' }
    if (& $on 'X509Certificate') { $methods += 'certificate-based authentication' }
    if ($methods.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "Passwordless methods enabled: $($methods -join ', ')."
    } else {
        # Nothing enabled is not configured: a Gap, not half credit.
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Low' -FrameworkIds $cit `
            -Detail 'No passwordless authentication method is enabled (FIDO2/passkeys, Authenticator phone sign-in, or certificate-based authentication).' `
            -Remediation $ctrl.Remediation
    }
}

# ── AAD-10.1 Identity Protection Risky User Workflow ─────────────────────────
function Test-NRGControlAADIdentityProtection {
    [CmdletBinding()] param()
    $cid = 'AAD-10.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        Add-NRGSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No Conditional Access user risk policy can be turned on while Security Defaults is enabled, and Security Defaults has no configurable user risk policy of its own (Microsoft lists user and sign-in risk-based policies as what organizations with Microsoft Entra ID P2 add after moving to Conditional Access), so neither provides an automated response to user risk. The legacy Identity Protection user risk policy (retiring October 1, 2026) is not read by this tool.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access user risk policy in force' -RequiredValue 'Enabled CA policy with a user risk condition' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    # Check for user risk policy as proxy for Identity Protection workflow
    $userRiskPolicies = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and @($_.Conditions.UserRiskLevels).Count -gt 0
    })
    if ($userRiskPolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail 'User risk CA policy is active — Identity Protection risk signals are actioned automatically.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No automated response to user risk: accounts Identity Protection detects as compromised are not remediated until someone acts on the alert. (Needs Entra ID P2; on a tenant without it this control is not scored.)' `
            -Remediation $ctrl.Remediation
    }
}

# ── AAD-10.2 Privileged Accounts Dedicated Cloud-Only ────────────────────────
function Test-NRGControlAADPrivCloudOnly {
    [CmdletBinding()] param()
    $cid = 'AAD-10.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $roles = Get-NRGRawData -Key 'AAD-DirectoryRoles'
    if (-not $roles -or -not $roles.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Directory role data not collected'; return
    }
    # AllPrivilegedAssignments includes PIM-eligible assignments: a synced
    # account eligible for Global Administrator escalates on-premises
    # compromise to the tenant exactly as a permanent one does.
    $privPool = @(Get-NRGNestedProperty -Object $roles -Path 'Data.AllPrivilegedAssignments' -Default @())
    if ($privPool.Count -eq 0) { $privPool = @($roles.Data['PrivRoles']) }
    $seen10 = [System.Collections.Generic.HashSet[string]]::new()
    $syncedPriv = @($privPool | Where-Object {
        $_.OnPremisesSyncEnabled -eq $true -and $_.PrincipalType -notmatch 'servicePrincipal' -and
        $seen10.Add([string](Get-NRGObjectField -Item $_ -Key 'PrincipalId' -Default (Get-NRGObjectField -Item $_ -Key 'PrincipalUPN' -Default ([guid]::NewGuid().ToString()))))
    })
    if (@($roles.Data['PrivRoles']).Count -eq 0 -and -not (Test-NRGRoleSectionCollected -Roles $roles -Section 'RoleAssignments')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
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
    if (-not (Test-NRGRoleNamesResolved -Assignments $roles.Data['RoleAssignments'])) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'Role definition names did not resolve (role-template lookup failed), so on-premises synced privileged accounts could not be reliably identified by role name. Not assessed.'
        return
    }
    if ($syncedPriv.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
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
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($syncedPriv.Count) privileged account(s) are synced from on-premises AD. On-prem compromise directly escalates to cloud tenant. See AffectedObjects for the per-account list." `
            -CurrentValue "Synced privileged accounts: $($syncedPriv.Count)" `
            -RequiredValue 'Zero synced accounts in privileged roles' -Remediation $ctrl.Remediation `
            -AffectedObjects $affected
    }
}

# ── AAD-10.3 Emergency Access Account Monitoring ─────────────────────────────
function Test-NRGControlAADBreakGlassMonitoring {
    [CmdletBinding()] param()
    $cid = 'AAD-10.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $gov = Get-NRGRawData -Key 'AAD-IdentityGovernance'
    if (-not $gov -or -not $gov.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Identity governance data not collected'; return
    }
    # Whether an alert fires on a break-glass sign-in is configured in
    # Sentinel / Defender XDR / a log-analytics rule, none of which this tool
    # reads. It used to PASS whenever two break-glass accounts existed —
    # "Verify sign-in alerts are configured" beside a Satisfied verdict.
    Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title "$($ctrl.Title) (Manual review required)" -FrameworkIds $cit `
        -Detail 'This control requires manual verification — sign-in alerting for break-glass accounts lives in Microsoft Sentinel, Defender XDR or Azure Monitor, which this assessment does not read. Confirm an alert rule fires on any sign-in by each break-glass account.'
}

# ── AAD-10.4 User Sign-in Frequency Session Control ─────────────────────────
function Test-NRGControlAADSignInFrequency {
    [CmdletBinding()] param()
    $cid = 'AAD-10.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        Add-NRGSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No sign-in frequency session control is in force: session controls are a Conditional Access feature Security Defaults does not provide, so sign-in sessions follow the default rolling window of up to 90 days and a stolen token stays usable within it.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access policy in force' -RequiredValue 'Enabled CA policy with a sign-in frequency session control' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    Add-NRGCAPolicyTierFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $ca.Data['Policies'] `
        -Match { (Get-NRGNestedProperty -Object $_ -Path 'SessionControls.SignInFrequency.IsEnabled') -eq $true -and
                 # "Every time" on a risk-conditioned policy (Microsoft's
                 # risky-sign-in template) re-prompts only risky sign-ins; it
                 # is not a periodic re-authentication limit.
                 [string](Get-NRGNestedProperty -Object $_ -Path 'SessionControls.SignInFrequency.FrequencyInterval' -Default '') -ne 'everyTime' -and
                 @(Get-NRGNestedProperty -Object $_ -Path 'Conditions.SignInRiskLevels' -Default @()).Count -eq 0 -and
                 @(Get-NRGNestedProperty -Object $_ -Path 'Conditions.UserRiskLevels' -Default @()).Count -eq 0 } `
        -What 'A sign-in frequency session control' `
        -EnabledDetail 'a sign-in frequency session control forces periodic re-authentication, limiting stolen token lifetime.' `
        -MissingDetail 'no Conditional Access policy sets a sign-in frequency. Stolen tokens remain valid for the default session lifetime (up to 90 days).' `
        -RequiredValue 'Enabled CA policy with a sign-in frequency session control'
}

# ── AAD-11.1 Device Code Authentication Flow Blocked ─────────────────────────
function Test-NRGControlAADDeviceCode {
    [CmdletBinding()] param()
    $cid = 'AAD-11.1'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        Add-NRGSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Satisfied' -Severity 'Informational' `
            -Detail 'Device code flow is blocked by Security Defaults. Microsoft documents: ''After security defaults are enabled in your tenant, authentication requests that use device code flow are blocked''; applications or devices that depend on it cannot complete sign-in while Security Defaults is enabled.' `
            -CurrentValue 'Device code flow blocked by Security Defaults' -RequiredValue 'Device code flow blocked for all users (Conditional Access policy or Security Defaults)'
        return
    }
    # The signal IS collected: Invoke-NRGCollectAADCAPolicies stores each policy's
    # authentication-flow condition as Conditions.AuthFlows (the raw Graph
    # authenticationFlows object, which carries transferMethods). A CA policy that
    # blocks device code has transferMethods containing 'deviceCode'.
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Conditional Access policy data not collected'; return
    }
    # Security Defaults not read and no CA policy On: it may be on (Satisfied)
    # or off (the Gap below). An unread state is never "disabled".
    if (Test-NRGSecurityDefaultsUnresolved) {
        Add-NRGSecurityDefaultsUnreadFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Question 'whether device code flow is blocked' `
            -IfOn 'it blocks authentication requests that use device code flow' `
            -IfOff 'no Conditional Access policy blocks it'
        return
    }
    $dcPolicies = @($ca.Data['Policies'] | Where-Object {
        $_.State -eq 'enabled' -and
        ((@($_.Conditions.AuthFlows) | ForEach-Object { [string](Get-NRGObjectField -Item $_ -Key 'transferMethods') }) -join ',') -match 'deviceCode' -and
        # A policy that scopes device code but only requires MFA still lets
        # the flow run — the phishing kits relay the MFA prompt too.
        (Test-NRGCAGrantRequires -Policy $_ -Any @('block'))
    })
    # Combined coverage: all users, all applications, no extra condition; exclusions are
    # judged across every qualifying policy (see Get-NRGCAEffectiveCoverage).
    $cov = Get-NRGCAEffectiveCoverage -Policies $dcPolicies
    if ($cov.Kind -ne 'None' -or @($cov.Narrowed).Count -gt 0) {
        $cv = Get-NRGCACoverageVerdict -Coverage $cov -What 'The device code authentication flow is blocked'
        Add-NRGExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit `
            -Verified $cv.Verified -Shortfalls $cv.Shortfalls -NotEstablished $cv.NotEstablished `
            -CurrentValue "Device code flow block: $($cov.Kind) coverage$(if ($cov.Names.Count) { ' by ' + ($cov.Names -join ', ') })" `
            -RequiredValue 'CA policy blocking the device code flow for all users on all applications (or Security Defaults)'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Device code authentication flow is not blocked. Attackers use this flow in phishing campaigns where victims visit a URL and enter a code — no password required to compromise the account.' -CurrentValue 'No CA policy blocks deviceCodeFlow' -RequiredValue 'CA policy blocking deviceCodeFlow for all users' -Remediation $ctrl.Remediation
    }
}

# ── AAD-11.2 No Guest Users in Highly Privileged Roles ───────────────────────
function Test-NRGControlAADNoGuestInPrivRoles {
    [CmdletBinding()] param()
    $cid = 'AAD-11.2'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $roles = Get-NRGRawData -Key 'AAD-DirectoryRoles'
    if (-not $roles -or -not $roles.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Directory role data not collected'; return
    }
    $privRoleNames = @(
        'Global Administrator','Privileged Role Administrator','Security Administrator',
        'Exchange Administrator','SharePoint Administrator','Teams Administrator',
        'Application Administrator','Cloud Application Administrator','Conditional Access Administrator',
        'Intune Administrator','User Administrator','Authentication Policy Administrator'
    )
    # Collector stores RoleDefinitionName (not RoleName) and no UserType — guests
    # are identifiable by the #EXT# marker in PrincipalUPN. Reading the old
    # RoleName/UserType keys made $guestPriv always empty -> a guest holding
    # Global Administrator was silently reported Satisfied (Critical false-negative).
    # Permanent AND eligible: a guest ELIGIBLE for Global Administrator can
    # activate it at will, and this list ignored eligibility entirely. The
    # collector's IsPriv flag also counts (Privileged Authentication
    # Administrator was missing from the local list).
    $pool = @(@($roles.Data['RoleAssignments']) + @(Get-NRGNestedProperty -Object $roles -Path 'Data.AllPrivilegedAssignments' -Default @()))
    $seen = [System.Collections.Generic.HashSet[string]]::new()
    $guestPriv = @($pool | Where-Object {
        ($_.RoleDefinitionName -in $privRoleNames -or (Get-NRGObjectField -Item $_ -Key 'IsPriv' -Default $false) -eq $true) -and $_.PrincipalUPN -like '*#EXT#*' -and
        $seen.Add("$(Get-NRGObjectField -Item $_ -Key 'PrincipalId' -Default (Get-NRGObjectField -Item $_ -Key 'PrincipalUPN' -Default ''))|$(Get-NRGObjectField -Item $_ -Key 'RoleDefinitionId' -Default (Get-NRGObjectField -Item $_ -Key 'RoleDefinitionName' -Default ''))")
    })
    if (@($roles.Data['RoleAssignments']).Count -eq 0 -and -not (Test-NRGRoleSectionCollected -Roles $roles -Section 'RoleAssignments')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title `
            -Detail 'Role assignment enumeration did not complete (see Exceptions) — guest privileged access could not be assessed.'
        return
    }
    # The collector's roleDefinitions sub-query is independent of the
    # assignments read above and has no SectionStatus of its own — a failed
    # lookup degrades every RoleDefinitionName to the raw role-template GUID,
    # so the name match above matches nothing and a guest Global Administrator
    # reads as "no guest accounts hold privileged roles" (Satisfied). Detect
    # that degradation directly rather than trust an empty $guestPriv.
    if (-not (Test-NRGRoleNamesResolved -Assignments $roles.Data['RoleAssignments'])) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'Role definition names did not resolve (role-template lookup failed), so guest privileged-role membership could not be reliably identified by role name. Not assessed.'
        return
    }
    if ($guestPriv.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'No guest accounts hold highly privileged directory roles.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$($guestPriv.Count) guest account(s) hold privileged roles: $($guestPriv.PrincipalDisplayName -join ', '). Guest accounts are outside your identity governance — compromised guest accounts escalate to tenant admin." -CurrentValue "Guest admins: $($guestPriv.Count)" -RequiredValue 'Zero guest accounts in privileged roles' -Remediation $ctrl.Remediation
    }
}

# ── AAD-11.3 Risky Service Principals and Applications Reviewed ───────────────
function Test-NRGControlAADRiskyServicePrincipals {
    [CmdletBinding()] param()
    $cid = 'AAD-11.3'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $auth = Get-NRGRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    # $null = endpoint not reachable (scope not consented, or no Workload Identities
    # Premium so detections never run) — honest NotApplicable, not a false pass.
    $risky = Get-NRGNestedProperty -Object $auth -Path 'Data.RiskyServicePrincipals' -Default $null
    if ($null -eq $risky) {
        $why = if (Test-NRGGraphScopeMissing -Scope 'IdentityRiskyServicePrincipal.Read.All') { Get-NRGConsentMissingDetail -Scope 'IdentityRiskyServicePrincipal.Read.All' }
               else { 'Risky workload-identity data unavailable (requires IdentityRiskyServicePrincipal.Read.All consent and Workload Identities Premium); not assessed.' }
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail $why; return
    }
    $risky = @($risky)
    # atRisk / confirmedCompromised are the states that demand action; remediated,
    # dismissed, confirmedSafe and none are resolved or benign.
    $active = @($risky | Where-Object { (Get-NRGObjectField -Item $_ -Key 'RiskState') -in @('atRisk','confirmedCompromised') })
    if ($active.Count -eq 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "No service principals are currently flagged at-risk by Identity Protection ($($risky.Count) workload identities evaluated)."
    } else {
        $names = @($active | ForEach-Object { $n = [string](Get-NRGObjectField -Item $_ -Key 'DisplayName'); if ($n) { $n } else { [string](Get-NRGObjectField -Item $_ -Key 'AppId') } }) | Select-Object -First 10
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($active.Count) service principal(s) are flagged at-risk or confirmed compromised by Identity Protection. Compromised workload identities can hold OAuth grants that persist through user password resets and MFA. Investigate and remediate." `
            -CurrentValue "$($active.Count) risky SP(s): $($names -join ', ')" `
            -RequiredValue 'Zero at-risk / confirmed-compromised service principals' `
            -Remediation $ctrl.Remediation `
            -AffectedObjects $active
    }
}

# ── AAD-11.4 Token Protection (Binding) Conditional Access ───────────────────
function Test-NRGControlAADTokenProtection {
    [CmdletBinding()] param()
    $cid = 'AAD-11.4'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        Add-NRGSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No token protection (binding) is in force: it is a Conditional Access session control Security Defaults does not provide. AiTM phishing steals session tokens and replays them from attacker infrastructure; token binding ties tokens to the originating device.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access policy in force' -RequiredValue 'Enabled CA policy requiring token protection' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    # Token protection is sessionControls.secureSignInSession, readable only in
    # the beta shape. Without that section it cannot be seen either way. (The
    # old match on signInFrequency.authenticationType read "re-authenticate
    # every time" as token binding.)
    if (-not (Test-NRGSectionCollected $ca 'TokenProtection')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'TokenProtection was not collected (the beta Conditional Access read did not complete); not assessed.'
        return
    }
    Add-NRGCAPolicyTierFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $ca.Data['Policies'] `
        -Match { (Get-NRGNestedProperty -Object $_ -Path 'SessionControls.SecureSignInSession' -Default $null) -eq $true } `
        -What 'Token protection (binding)' `
        -EnabledDetail 'token protection binds session tokens to the originating device, so a stolen token cannot be replayed from attacker infrastructure.' `
        -MissingDetail 'no token protection (binding) Conditional Access policy. AiTM phishing steals session tokens and replays them from attacker infrastructure; token binding ties tokens to the originating device.' `
        -RequiredValue 'Enabled CA policy requiring token protection'
}

# ── AAD-11.5 Continuous Access Evaluation Enabled ────────────────────────────
function Test-NRGControlAADContinuousAccess {
    [CmdletBinding()] param()
    $cid = 'AAD-11.5'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        Add-NRGSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'Continuous access evaluation strict enforcement is not in force: it is a Conditional Access session control Security Defaults does not provide.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access policy in force' -RequiredValue 'Enabled CA policy with continuous access evaluation strict enforcement' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    # CAE is enabled by default in most tenants; CA policy can enforce strict mode
    # Graph values are strictEnforcement / strictLocation; 'strict' never
    # matched. Stored as the mode string; older data nested it under .Mode.
    $caePolicies = @($ca.Data['Policies'] | Where-Object {
        $cae = Get-NRGNestedProperty -Object $_ -Path 'SessionControls.ContinuousAccessEvaluation' -Default ''
        if ($cae -is [System.Collections.IDictionary] -or $cae -is [pscustomobject]) { $cae = Get-NRGObjectField -Item $cae -Key 'Mode' -Default '' }
        $_.State -eq 'enabled' -and [string]$cae -in @('strictEnforcement','strictLocation')
    })
    if ($caePolicies.Count -gt 0) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Continuous Access Evaluation strict mode enforced via CA policy. Session revocation propagates in near-real-time.'
    } else {
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'CAE strict mode not enforced (the default; not configured). CAE is active by default but strict mode ensures immediate session revocation when IP or risk changes — consider enforcing for sensitive workloads.' -Remediation $ctrl.Remediation
    }
}

# ── AAD-11.6 Cross-Tenant Access Inbound Trust Settings ──────────────────────
function Test-NRGControlAADCrossTenantAccess {
    [CmdletBinding()] param()
    $cid = 'AAD-11.6'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    $auth = Get-NRGRawData -Key 'AAD-AuthPolicies'
    if (-not $auth -or -not $auth.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Auth policy data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-NRGSectionCollected $auth 'CrossTenantAccess')) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CrossTenantAccess was not collected; not assessed.'
        return
    }
    $xtap = Get-NRGNestedProperty -Object $auth -Path 'Data.CrossTenantAccess'
    if (-not $xtap) {
        # No data is not half credit.
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'The cross-tenant access default policy was not returned; not assessed. Verify in Entra ID > External Identities > Cross-tenant access settings that inbound defaults do not trust MFA or device compliance from other tenants.'
        return
    }
    $trustsMFA    = [bool](Get-NRGNestedProperty -Object $xtap -Path 'InboundTrust.IsMfaAccepted' -Default $false)
    $trustsDevice = [bool](Get-NRGNestedProperty -Object $xtap -Path 'InboundTrust.IsCompliantDeviceAccepted' -Default $false)
    if (-not $trustsMFA -and -not $trustsDevice) {
        Add-NRGFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail 'Cross-tenant default inbound settings do not trust external MFA or device compliance claims.'
    } else {
        $trusted = @(); if ($trustsMFA) { $trusted += 'MFA' }; if ($trustsDevice) { $trusted += 'Device Compliance' }
        Add-NRGFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "Default inbound cross-tenant trust accepts: $($trusted -join ', ') from all external tenants. An attacker in any tenant could satisfy your MFA/compliance requirements using their own tenant's weaker controls." -CurrentValue "Trusts: $($trusted -join ', ')" -RequiredValue 'No trust of external MFA or device compliance by default' -Remediation $ctrl.Remediation
    }
}

# ── AAD-11.7 Privileged Access Workstation Indicator ─────────────────────────
function Test-NRGControlAADPrivilegedWorkstation {
    [CmdletBinding()] param()
    $cid = 'AAD-11.7'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        Add-NRGSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No device-scoped policy for privileged roles is in force: Security Defaults requires 16 administrator roles to complete MFA at every sign-in but does not restrict the devices they sign in from.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access policy in force' -RequiredValue 'Enabled CA policy restricting privileged roles to managed devices' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    # PAW is indicated by configuration, not name: a policy called "...PAW
    # accounts excluded" passed. Admin-role policies that filter devices, or
    # that REQUIRE a compliant / hybrid-joined device (Microsoft's template).
    Add-NRGCAPolicyTierFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $ca.Data['Policies'] `
        -Match { @(Get-NRGNestedProperty -Object $_ -Path 'Conditions.Users.IncludeRoles' -Default @()).Count -gt 0 -and
                 ([string](Get-NRGNestedProperty -Object $_ -Path 'Conditions.Devices.FilterRule' -Default '') -or
                  (Test-NRGCAGrantRequires -Policy $_ -Any @('compliantDevice','domainJoinedDevice'))) } `
        -What 'A device-scoped policy for privileged roles' `
        -EnabledDetail 'privileged role access is restricted to specific managed devices by a device-scoped CA policy.' `
        -MissingDetail 'no device-scoped Conditional Access policy for privileged role access. Admins can authenticate from any device; a privileged access workstation or compliant-device requirement for admin roles reduces attack surface.' `
        -RequiredValue 'Enabled CA policy restricting privileged roles to managed devices'
}

# ── AAD-11.8 Terms of Use for External Access ─────────────────────────────────
function Test-NRGControlAADTermsOfUse {
    [CmdletBinding()] param()
    $cid = 'AAD-11.8'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        Add-NRGSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No Terms of Use acceptance is required: Terms of Use is a Conditional Access grant control Security Defaults does not provide.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access policy in force' -RequiredValue 'Enabled CA policy requiring Terms of Use acceptance' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    Add-NRGCAPolicyTierFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $ca.Data['Policies'] `
        -Match { @(Get-NRGNestedProperty -Object $_ -Path 'GrantControls.TermsOfUse' -Default @()).Count -gt 0 } `
        -What 'Terms of Use' `
        -EnabledDetail 'users must acknowledge acceptable use before accessing resources.' `
        -MissingDetail 'no Terms of Use Conditional Access policy. For organizations with guests or external contractors, Terms of Use create a legal acknowledgment of acceptable use.' `
        -RequiredValue 'Enabled CA policy requiring Terms of Use acceptance'
}

# ── AAD-11.9 Workload Identity CA Policy ─────────────────────────────────────
function Test-NRGControlAADWorkloadIdentityCA {
    [CmdletBinding()] param()
    $cid = 'AAD-11.9'; $ctrl = Get-NRGControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-NRGFrameworkCitations -ControlId $cid
    if ((Get-NRGSecurityDefaultsState) -eq $true) {
        Add-NRGSecurityDefaultsFinding -ControlId $cid -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -State 'Gap' -Severity $ctrl.Severity `
            -Detail 'No Conditional Access policy applies to workload identities: Security Defaults has no policy for service principals, and Conditional Access for workload identities also needs the Workload Identities Premium license.' `
            -CurrentValue 'Security Defaults enabled; no Conditional Access policy in force' -RequiredValue 'Enabled CA policy scoped to workload identities' `
            -Remediation $ctrl.Remediation -NeedsConditionalAccess
        return
    }
    $ca = Get-NRGRawData -Key 'AAD-CAPolicies'
    if (-not $ca -or -not $ca.Success) {
        Add-NRGFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'CA data not collected'; return
    }
    Add-NRGCAPolicyTierFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $ca.Data['Policies'] `
        -Match { (Get-NRGNestedProperty -Object $_ -Path 'Conditions.ClientApplications.IncludeServicePrincipals') -or
                 (Get-NRGNestedProperty -Object $_ -Path 'Conditions.ClientApplications.IncludeAllServicePrincipals') } `
        -What 'A workload identity policy' `
        -EnabledDetail 'Conditional Access applies to workload identities (service principals), so application access is subject to CA controls.' `
        -MissingDetail 'no Conditional Access policy applies to workload identities. Service principals and managed identities are not subject to any conditional access controls.' `
        -RequiredValue 'Enabled CA policy scoped to workload identities'
}