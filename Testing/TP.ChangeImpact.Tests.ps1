#Requires -Version 7.0
#
# TP.ChangeImpact.Tests.ps1
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Guards the change-impact view (Lib/Get-TPChangeImpact.ps1,
# Publishers/Publish-TPChangeImpact.ps1, Config/change-impact.json):
#   - the catalog: every control it lists exists, every evidence type is
#     documented and handled, and nothing documented as invisible to users is
#     filed as able to break accounts
#   - the three lists: Implement now only for a licensed, documented
#     low-friction change; an undocumented impact is "could break accounts";
#     an unconfirmed license is a license decision, never a list item
#   - the accounts: named from the raw shapes the collectors write, a disabled
#     account dropped, an MFA sign-in not counted as single-factor, an admin
#     with a FIDO2 key not flagged, the approved emergency-access accounts
#     listed to exclude
#   - honesty: not read is NotRead with the reason, an incomplete read with
#     nobody found is NotEstablished, NoneFound only after a complete read and
#     always with the caveat, a page-capped list is never whole
#   - it is a view: the findings are unchanged
#   - the report loads nothing, escapes everything, never says "compliant"
#   - the Intune collector records each non-compliant device's user
#   - the entry point never shadows a parameter with a same-named variable
# Data keys consumed: synthetic raw data only. Graph scopes / cmdlets: none.

BeforeAll {
    $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
    Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
    $script:Mod = Get-Module 'TenantPosture'
    $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('tp-ci-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
    $null = New-Item -ItemType Directory -Path $script:Tmp -Force
    $script:Catalog = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/change-impact.json') -Raw | ConvertFrom-Json -AsHashtable
    $script:Lic = Get-TPTenantLicenseProfile -SubscribedSkus @(@{ SkuPartNumber = 'SPB'; ServicePlans = @('AAD_PREMIUM', 'INTUNE_A', 'ATP_ENTERPRISE', 'EXCHANGE_S_ARCHIVE_ADDON') })
    $script:Meta = @{ TenantDomain = 'contoso.com'; AssessmentTime = '2026-10-28T01:00:00Z'; ToolVersion = '9.9.9' }
    $script:BreakGlassId = '99999999-9999-9999-9999-999999999999'
    $script:Ea = @{
        EmergencyAccess = @{ "user:$($script:BreakGlassId)" = 1 }
        EmergencyAccessEntries = @([pscustomobject]@{ ObjectId = $script:BreakGlassId; Kind = 'User'; UserPrincipalName = 'breakglass1@contoso.onmicrosoft.com'; DisplayName = 'Break Glass 1'; Approved = $true })
    }

    $f = { param($id, $state) @{ ControlId = $id; State = $state; Severity = 'High'; Title = $id; Detail = 'd'; Category = 'c'; FrameworkIds = ''; CurrentValue = ''; RequiredValue = ''; AffectedObjects = @() } }
    $script:NewFindings = {
        @(
            (& $f 'AAD-1.1' 'Gap'), (& $f 'AAD-1.2' 'Partial'), (& $f 'AAD-1.3' 'Gap'), (& $f 'AAD-17.3' 'Gap'),
            (& $f 'EXO-7.1' 'Gap'), (& $f 'EXO-7.2' 'Gap'), (& $f 'EXO-2.4' 'Gap'), (& $f 'AAD-3.2' 'Gap'), (& $f 'INT-1.2' 'Gap'),
            (& $f 'EXO-1.1' 'Gap'), (& $f 'DEF-1.1' 'Gap'), (& $f 'DNS-1.1' 'Gap'), (& $f 'AAD-11.1' 'Gap'), (& $f 'SPO-1.3' 'Satisfied'),
            (& $f 'EXO-1.2' 'Gap')
        )
    }
    $ex = '00000002-0000-0ff1-ce00-000000000000'
    $script:NewRaw = {
        @{
            'AAD-SignInEvidence' = @{ Success = $true; Data = @{ Available = $true; WindowDays = 30
                SectionStatus = @{ LegacyAuth = 'Collected'; SingleFactor = 'Collected' }
                Sections = @{
                    LegacyAuth = @{ Truncated = $false; Events = @(
                        @{ UserId = '11111111-1111-1111-1111-111111111111'; UserPrincipalName = 'scanner@contoso.com'; ClientAppUsed = 'Authenticated SMTP'; ResourceId = $ex; CreatedDateTime = '2026-10-20T08:00:00Z' },
                        @{ UserId = '22222222-2222-2222-2222-222222222222'; UserPrincipalName = 'bob@contoso.com'; ClientAppUsed = 'IMAP4'; ResourceId = $ex; CreatedDateTime = '2026-10-21T08:00:00Z' },
                        @{ UserId = '22222222-2222-2222-2222-222222222222'; UserPrincipalName = 'bob@contoso.com'; ClientAppUsed = 'IMAP4'; ResourceId = $ex; CreatedDateTime = '2026-10-25T08:00:00Z' }) }
                    SingleFactor = @{ Truncated = $false; Events = @(
                        @{ UserId = '33333333-3333-3333-3333-333333333333'; UserPrincipalName = 'carol@contoso.com'; AppDisplayName = 'Office 365'; CreatedDateTime = '2026-10-22T08:00:00Z'; AuthDetails = @(@{ Method = 'Password'; Step = 'Primary authentication'; Succeeded = $true; Result = 'Correct password' }) },
                        @{ UserId = '44444444-4444-4444-4444-444444444444'; UserPrincipalName = 'dave@contoso.com'; AppDisplayName = 'Office 365'; CreatedDateTime = '2026-10-22T08:00:00Z'; AuthDetails = @(@{ Method = 'Mobile app notification'; Step = 'Secondary authentication'; Succeeded = $true; Result = 'MFA successfully completed' }) }) } } } }
            'AAD-Users' = @{ Success = $true; Data = @{ SectionStatus = @{ MFARegistration = 'Collected' }
                Users = @(@{ Id = '55555555-5555-5555-5555-555555555555'; AccountEnabled = $false })
                MFARegistration = @{ RegistrationDetails = @(
                    @{ Id = '33333333-3333-3333-3333-333333333333'; UserPrincipalName = 'carol@contoso.com'; UserDisplayName = 'Carol'; IsAdmin = $false; IsMfaRegistered = $false; AuthMethodsRegistered = @() },
                    @{ Id = '55555555-5555-5555-5555-555555555555'; UserPrincipalName = 'gone@contoso.com'; UserDisplayName = 'Disabled'; IsAdmin = $false; IsMfaRegistered = $false; AuthMethodsRegistered = @() },
                    @{ Id = $script:BreakGlassId; UserPrincipalName = 'breakglass1@contoso.onmicrosoft.com'; UserDisplayName = 'Break Glass 1'; IsAdmin = $true; IsMfaRegistered = $false; AuthMethodsRegistered = @() },
                    @{ Id = '66666666-6666-6666-6666-666666666666'; UserPrincipalName = 'admin@contoso.com'; UserDisplayName = 'Admin'; IsAdmin = $true; IsMfaRegistered = $true; AuthMethodsRegistered = @('microsoftAuthenticatorPush', 'mobilePhone') },
                    @{ Id = '77777777-7777-7777-7777-777777777777'; UserPrincipalName = 'secadmin@contoso.com'; UserDisplayName = 'Sec Admin'; IsAdmin = $true; IsMfaRegistered = $true; AuthMethodsRegistered = @('fido2SecurityKey') },
                    @{ Id = '88888888-8888-8888-8888-888888888888'; UserPrincipalName = 'erin@contoso.com'; UserDisplayName = 'Erin'; IsAdmin = $false; IsMfaRegistered = $true; AuthMethodsRegistered = @('mobilePhone', 'email') },
                    @{ Id = '12121212-1212-1212-1212-121212121212'; UserPrincipalName = 'ivan@contoso.com'; UserDisplayName = 'Ivan'; IsAdmin = $false; IsMfaRegistered = $true; AuthMethodsRegistered = @('mobilePhone', 'softwareOneTimePasscode') }) } } }
            'AAD-DirectoryRoles' = @{ Success = $true; Data = @{ SectionStatus = @{ RoleAssignments = 'Collected'; RoleEligibilitySchedules = 'Collected' }
                RoleAssignments = @(@{ PrincipalId = '66666666-6666-6666-6666-666666666666'; PrincipalDisplayName = 'Admin'; PrincipalUPN = 'admin@contoso.com'; PrincipalType = '#microsoft.graph.user'; RoleDefinitionName = 'Global Administrator'; IsPriv = $true })
                AllPrivilegedAssignments = @(@{ PrincipalId = '66666666-6666-6666-6666-666666666666'; PrincipalDisplayName = 'Admin'; PrincipalUPN = 'admin@contoso.com'; PrincipalType = '#microsoft.graph.user'; RoleDefinitionName = 'Global Administrator'; IsPriv = $true; Source = 'permanent' }) } }
            'EXO-Inventory' = @{ Success = $true; Data = @{ SectionStatus = @{ ForwardingMailboxes = 'Collected'; InboxRulesForwarding = 'Collected'; SmtpAuthEnabledPerUser = 'Collected'; SharedMailboxes = 'Collected' }
                Stats = @{ MailboxesRuleScanFailed = 0 }
                ForwardingMailboxes = @(
                    @{ DisplayName = 'Frank'; UPN = 'frank@contoso.com'; ForwardingAddress = 'frank@gmail.com'; ForwardingMechanism = 'ForwardingSmtpAddress'; Classification = 'External'; IsExternal = $true; DeliverToMailboxAndForward = $true },
                    @{ DisplayName = 'Inside'; UPN = 'inside@contoso.com'; ForwardingAddress = 'boss@contoso.com'; ForwardingMechanism = 'ForwardingAddress'; Classification = 'Internal'; IsExternal = $false; DeliverToMailboxAndForward = $false })
                InboxRulesForwarding = @(@{ Mailbox = 'grace@contoso.com'; DisplayName = 'Grace'; RuleName = 'to home'; Enabled = $true; ExternalRecipients = @('grace@yahoo.com'); UnresolvedRecipients = @() })
                SmtpAuthEnabledPerUser = @(@{ DisplayName = 'Scanner'; UPN = 'scanner@contoso.com' }); SmtpAuthEnabledPerUserCount = 1
                SharedMailboxSignIn = @(); SharedMailboxUnconfirmed = @() } }
            'Intune-DeviceCompliance' = @{ Success = $true; Data = @{ SectionStatus = @{ OSComplianceSummary = 'Collected' }
                OSComplianceSummary = @{ NonCompliantTruncated = $false; NonCompliantDevices = @(
                    @{ DeviceName = 'LAPTOP-7'; OperatingSystem = 'Windows'; ComplianceState = 'noncompliant'; UserPrincipalName = 'heidi@contoso.com' },
                    @{ DeviceName = 'KIOSK-1'; OperatingSystem = 'Windows'; ComplianceState = 'noncompliant'; UserPrincipalName = '' }) } } }
        }
    }
    $script:Build = {
        param([object] $Raw = (& $script:NewRaw), [object] $Lic = $script:Lic, [object] $Ea = $script:Ea, [object[]] $Findings = (& $script:NewFindings), [string] $ImpactPath = '', [int] $Cap = 200)
        Get-TPChangeImpact -Findings $Findings -Metadata $script:Meta -RawData $Raw -LicenseProfile $Lic -EmergencyAccessRecord $Ea -ImpactPath $ImpactPath -AccountCap $Cap
    }
    $script:Item = { param($m, [string] $cid) foreach ($t in 'ImplementNow', 'NeedsPlanning', 'CouldBreakAccounts', 'LicenseDecision') { foreach ($it in @($m[$t])) { if ($it.ControlId -eq $cid) { return $it } } } }
    $script:Block = { param($it, [string] $type) @($it.Evidence | Where-Object { $_.Type -eq $type })[0] }
    $script:Upns = { param($b) @($b.Accounts | ForEach-Object { $_.UserPrincipalName }) }
}

AfterAll {
    if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
}

Describe 'Change impact: the catalog' {
    It 'every control it lists is a real control and none is documented as invisible to users' {
        $ids = @(& $script:Mod { Get-TPControlDefinitions } | ForEach-Object { $_.ControlId })
        $impact = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/operational-impact.json') -Raw | ConvertFrom-Json -AsHashtable
        $low = & $script:Mod { Get-TPLowFrictionArchetypes }
        foreach ($cid in $script:Catalog.accountRisk.Keys) {
            $ids | Should -Contain $cid
            $impact.controls[$cid] | Should -Not -BeIn $low -Because "$cid cannot be both invisible to users and able to break accounts"
            [string]$script:Catalog.accountRisk[$cid].Why | Should -Not -BeNullOrEmpty
        }
    }
    It 'every evidence type a control names is documented and handled, even with no data at all' {
        foreach ($cid in $script:Catalog.accountRisk.Keys) {
            foreach ($spec in @($script:Catalog.accountRisk[$cid].Evidence)) {
                $script:Catalog.evidenceTypes.Contains($spec.Type) | Should -BeTrue -Because "$cid names $($spec.Type)"
                $b = & $script:Mod { param($s) Get-TPChangeImpactEvidence -Spec $s -RawData $null -EmergencyAccessRecord $null } $spec
                $b.Status | Should -Be 'NotRead' -Because "$($spec.Type) with no raw data is not read, never none found"
                $b.Note | Should -Not -BeNullOrEmpty
            }
        }
    }
    It 'every account-breaking change to a sign-in policy names the emergency-access accounts to exclude' {
        foreach ($cid in 'AAD-1.1', 'AAD-1.2', 'AAD-1.3', 'AAD-2.1', 'AAD-2.3', 'INT-1.2', 'AAD-11.1', 'AAD-3.2') {
            @($script:Catalog.accountRisk[$cid].Evidence | ForEach-Object { $_.Type }) | Should -Contain 'EmergencyAccess'
        }
    }
}

Describe 'Change impact: the three lists' {
    BeforeAll { $script:M = & $script:Build }

    It 'sorts each open control into exactly one list and leaves a passed control out' {
        @($script:M.ImplementNow.ControlId) | Should -Be @('EXO-1.1')
        @($script:M.NeedsPlanning.ControlId) | Should -Contain 'DNS-1.1'
        @($script:M.NeedsPlanning.ControlId) | Should -Contain 'DEF-1.1'
        foreach ($c in 'AAD-1.1', 'AAD-1.2', 'AAD-1.3', 'AAD-17.3', 'EXO-7.1', 'EXO-7.2', 'EXO-2.4', 'INT-1.2', 'AAD-11.1', 'EXO-1.2') { @($script:M.CouldBreakAccounts.ControlId) | Should -Contain $c }
        $all = @($script:M.ImplementNow + $script:M.NeedsPlanning + $script:M.CouldBreakAccounts + $script:M.LicenseDecision | ForEach-Object { $_.ControlId })
        $all | Should -Not -Contain 'SPO-1.3'
        @($all | Group-Object | Where-Object Count -gt 1).Count | Should -Be 0
        $script:M.Summary.CouldBreakAccounts | Should -Be @($script:M.CouldBreakAccounts).Count
    }
    It 'a control the tenant is not licensed for is a license decision (PIM needs P2; Business Premium has P1)' {
        @($script:M.LicenseDecision.ControlId) | Should -Contain 'AAD-3.2'
    }
    It 'with licensing not read, a licensed-only control is a license decision that says licensing was not read' {
        $m = & $script:Build -Lic $null
        $it = & $script:Item $m 'AAD-1.2'
        @($m.LicenseDecision) | Should -Contain $it
        $it.Reason | Should -Match 'not read'
    }
    It 'an undocumented operational impact is "could break accounts", never "implement now"' {
        $impact = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/operational-impact.json') -Raw | ConvertFrom-Json -AsHashtable
        $impact.controls.Remove('EXO-1.1')
        $path = Join-Path $script:Tmp 'impact-missing.json'
        $impact | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $path -Encoding utf8
        $m = & $script:Build -ImpactPath $path
        $it = & $script:Item $m 'EXO-1.1'
        @($m.CouldBreakAccounts) | Should -Contain $it
        $it.ImpactDocumented | Should -BeFalse
        $it.Why | Should -Match 'not documented'
    }
    It 'is a view: the findings are unchanged' {
        $findings = & $script:NewFindings
        $before = $findings | ConvertTo-Json -Depth 8
        $null = & $script:Build -Findings $findings
        ($findings | ConvertTo-Json -Depth 8) | Should -Be $before
    }
}

Describe 'Change impact: the accounts named' {
    BeforeAll { $script:M = & $script:Build }

    It 'legacy sign-ins: everyone for the legacy block, only IMAP for the IMAP change, only SMTP for SMTP AUTH' {
        & $script:Upns (& $script:Block (& $script:Item $script:M 'AAD-1.1') 'LegacyAuthSignIns') | Should -Be @('bob@contoso.com', 'scanner@contoso.com')
        & $script:Upns (& $script:Block (& $script:Item $script:M 'EXO-2.4') 'LegacyAuthSignIns') | Should -Be @('bob@contoso.com')
        & $script:Upns (& $script:Block (& $script:Item $script:M 'EXO-1.2') 'LegacyAuthSignIns') | Should -Be @('scanner@contoso.com')
        (& $script:Block (& $script:Item $script:M 'EXO-2.4') 'LegacyAuthSignIns').Accounts[0].Detail | Should -Match '2 successful sign-in\(s\) through IMAP4 in the 30-day window; last 2026-10-25'
    }
    It 'MFA: the unregistered and the single-factor are named; a disabled account and an MFA sign-in are not' {
        $it = & $script:Item $script:M 'AAD-1.2'
        $unreg = & $script:Upns (& $script:Block $it 'MfaUnregistered')
        $unreg | Should -Contain 'carol@contoso.com'
        $unreg | Should -Not -Contain 'gone@contoso.com'
        & $script:Upns (& $script:Block $it 'SingleFactorSignIns') | Should -Be @('carol@contoso.com')
    }
    It 'the approved emergency-access account is marked to exclude, not to fix, and listed to exclude' {
        $it = & $script:Item $script:M 'AAD-1.2'
        $bg = @((& $script:Block $it 'MfaUnregistered').Accounts | Where-Object { $_.ObjectId -eq $script:BreakGlassId })[0]
        $bg.Detail | Should -Match 'exclude it from the change'
        $it.EmergencyAccess.Role | Should -Be 'MustExclude'
        $it.EmergencyAccess.Status | Should -Be 'Named'
        $script:M.EmergencyAccess.Accounts[0].UserPrincipalName | Should -Be 'breakglass1@contoso.onmicrosoft.com'
    }
    It 'phishing-resistant: an admin without a FIDO2 key or passkey is named, one with a key is not' {
        $u = & $script:Upns (& $script:Block (& $script:Item $script:M 'AAD-1.3') 'AdminsWithoutPhishResistant')
        $u | Should -Contain 'admin@contoso.com'
        $u | Should -Not -Contain 'secadmin@contoso.com'
    }
    It 'phone-only MFA names the account with only a phone, not one with an authenticator code too' {
        & $script:Upns (& $script:Block (& $script:Item $script:M 'AAD-17.3') 'PhoneOnlyMfa') | Should -Be @('erin@contoso.com')
    }
    It 'forwarding: the external forwarder and the external rule; internal forwarding is not named' {
        & $script:Upns (& $script:Block (& $script:Item $script:M 'EXO-7.1') 'ForwardingMailboxes') | Should -Be @('frank@contoso.com')
        & $script:Upns (& $script:Block (& $script:Item $script:M 'EXO-7.2') 'ForwardingRules') | Should -Be @('grace@contoso.com')
    }
    It 'device compliance names the device''s user and counts a device with no user' {
        $b = & $script:Block (& $script:Item $script:M 'INT-1.2') 'NonCompliantDevices'
        & $script:Upns $b | Should -Be @('heidi@contoso.com')
        $b.Note | Should -Match '1 non-compliant device\(s\) have no primary user'
        $b.Note | Should -Match 'not enrolled in Intune are not seen'
    }
    It 'a change whose accounts the tool cannot read says what it cannot see' {
        $it = & $script:Item $script:M 'AAD-11.1'
        @($it.Evidence).Count | Should -Be 0
        $it.Unseen | Should -Match 'Device-code sign-ins are not read'
    }
    It 'caps the accounts kept per block and counts the rest' {
        $m = & $script:Build -Cap 1
        $b = & $script:Block (& $script:Item $m 'AAD-1.1') 'LegacyAuthSignIns'
        @($b.Accounts).Count | Should -Be 1
        $b.Count | Should -Be 2
        $b.NotShown | Should -Be 1
    }
}

Describe 'Change impact: empty is not clean' {
    It 'a sign-in log not readable for licensing is NotRead with the reason' {
        $raw = & $script:NewRaw
        $raw['AAD-SignInEvidence'].Data.Available = $false
        $raw['AAD-SignInEvidence'].Data.UnavailableReason = 'PremiumLicenseRequired'
        $b = & $script:Block (& $script:Item (& $script:Build -Raw $raw) 'AAD-1.1') 'LegacyAuthSignIns'
        $b.Status | Should -Be 'NotRead'
        $b.Note | Should -Match 'Entra ID P1 or P2'
    }
    It 'a truncated read that found nobody is NotEstablished, never NoneFound' {
        $raw = & $script:NewRaw
        $raw['AAD-SignInEvidence'].Data.Sections.LegacyAuth = @{ Truncated = $true; Events = @() }
        $b = & $script:Block (& $script:Item (& $script:Build -Raw $raw) 'AAD-1.1') 'LegacyAuthSignIns'
        $b.Status | Should -Be 'NotEstablished'
        $b.Complete | Should -BeFalse
    }
    It 'a read that failed part-way keeps what it found and is not complete' {
        $raw = & $script:NewRaw
        $raw['AAD-SignInEvidence'].Data.SectionStatus.LegacyAuth = 'Failed'
        $b = & $script:Block (& $script:Item (& $script:Build -Raw $raw) 'AAD-1.1') 'LegacyAuthSignIns'
        $b.Status | Should -Be 'Named'
        $b.Complete | Should -BeFalse
        $b.Note | Should -Match 'failed part-way'
    }
    It 'a sign-in with no recorded steps is neither single-factor nor clean' {
        $raw = & $script:NewRaw
        $raw['AAD-SignInEvidence'].Data.Sections.SingleFactor.Events = @(@{ UserId = 'x'; UserPrincipalName = 'x@contoso.com'; CreatedDateTime = '2026-10-22T08:00:00Z'; AuthDetails = $null })
        $b = & $script:Block (& $script:Item (& $script:Build -Raw $raw) 'AAD-1.2') 'SingleFactorSignIns'
        $b.Status | Should -Be 'NotEstablished'
        $b.Note | Should -Match 'no authentication steps'
    }
    It 'NoneFound only after a complete read, with the window caveat' {
        $raw = & $script:NewRaw
        $raw['AAD-SignInEvidence'].Data.Sections.LegacyAuth = @{ Truncated = $false; Events = @() }
        $b = & $script:Block (& $script:Item (& $script:Build -Raw $raw) 'AAD-1.1') 'LegacyAuthSignIns'
        $b.Status | Should -Be 'NoneFound'
        $b.Complete | Should -BeTrue
        $b.Note | Should -Match 'used less often than that is not seen'
    }
    It 'a capped SMTP AUTH list is not whole' {
        $raw = & $script:NewRaw
        $raw['EXO-Inventory'].Data.SmtpAuthEnabledPerUserCount = 250
        $b = & $script:Block (& $script:Item (& $script:Build -Raw $raw) 'EXO-1.2') 'SmtpAuthMailboxes'
        $b.Complete | Should -BeFalse
        $b.Note | Should -Match '250 mailbox'
    }
    It 'an Exchange read that failed is NotRead' {
        $raw = & $script:NewRaw
        $raw['EXO-Inventory'].Data.SectionStatus.ForwardingMailboxes = 'Failed'
        (& $script:Block (& $script:Item (& $script:Build -Raw $raw) 'EXO-7.1') 'ForwardingMailboxes').Status | Should -Be 'NotRead'
    }
    It 'an older results file without device users says so and names nobody' {
        $raw = & $script:NewRaw
        $raw['Intune-DeviceCompliance'].Data.OSComplianceSummary = @{ TotalCount = 3 }
        $b = & $script:Block (& $script:Item (& $script:Build -Raw $raw) 'INT-1.2') 'NonCompliantDevices'
        $b.Status | Should -Be 'NotRead'
        $b.Note | Should -Match 'run the assessment again'
    }
    It 'no emergency-access record is a warning to confirm one exists, never silence' {
        $m = & $script:Build -Ea $null
        $m.EmergencyAccess.Status | Should -Be 'NotRead'
        $m.EmergencyAccess.Note | Should -Match 'lock every administrator out'
    }
}

Describe 'Change impact: the report' {
    BeforeAll {
        $raw = & $script:NewRaw
        $raw['EXO-Inventory'].Data.ForwardingMailboxes[0].DisplayName = '<script>alert(1)</script>[x](https://evil.example)'
        $raw['AAD-SignInEvidence'].Data.Sections.LegacyAuth.Events = @()
        $m = & $script:Build -Raw $raw
        $script:Files = Publish-TPChangeImpact -Model $m -OutputPath (Join-Path $script:Tmp 'contoso-change-impact.html') -ShowAccounts 1 -GeneratedAt ([datetime]::new(2041, 1, 2, 3, 4, 0, [DateTimeKind]::Utc))
        $script:Html = Get-Content -LiteralPath $script:Files.Html -Raw
        $script:Md = Get-Content -LiteralPath $script:Files.Markdown -Raw
    }
    It 'writes the three lists in order, then license decisions and emergency access' {
        $order = @('id="implement-now"', 'id="needs-planning"', 'id="could-break-accounts"', 'id="license-decisions"', 'id="emergency-access"') | ForEach-Object { $script:Html.IndexOf($_) }
        $order | Should -Not -Contain -1
        ($order | Sort-Object) | Should -Be $order
    }
    It 'loads nothing and runs nothing, and escapes tenant text' {
        $script:Html | Should -Not -Match '(?i)<script|<link|<img|<iframe|@import'
        $script:Html | Should -Match '&lt;script&gt;'
        $script:Md | Should -Not -Match '<script>'
        # Escaped brackets cannot form a link.
        $script:Md | Should -Match ([regex]::Escape('\[x\]'))
        $script:Md | Should -Not -Match '(?<!\\)\[x(?<!\\)\]\('
    }
    It 'a none-found block carries the caveat; the cap says how many more' {
        $script:Html | Should -Match 'does not mean nothing can break'
        $script:Md | Should -Match 'does not mean nothing can break'
        $script:Html | Should -Match 'And \d+ more; the results file lists them'
    }
    It 'never says compliant and quotes no time or price' {
        foreach ($t in $script:Html, $script:Md) {
            # 'devices that are not compliant' describes a device; a claim about the tenant is what is barred.
            $t | Should -Not -Match '(?i)\b(is|are|fully|now)\s+compliant\b|\bcompliant with\b'
            $t | Should -Not -Match '\$\d'
        }
    }
}

Describe 'Change impact: wiring' {
    It 'the Intune collector records each non-compliant device''s user from the same read' {
        & $script:Mod { Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value {
            param([string] $Uri, [string] $Method = 'GET', $Headers, $Body, [string] $OutputType = 'HashTable')
            if ($Uri -match 'managedDevices') {
                if ($Uri -notmatch 'userPrincipalName') { throw 'the device read must select userPrincipalName' }
                return @{ value = @(
                    @{ id = '1'; deviceName = 'LAPTOP-7'; operatingSystem = 'Windows'; complianceState = 'noncompliant'; userPrincipalName = 'heidi@contoso.com' },
                    @{ id = '2'; deviceName = 'LAPTOP-8'; operatingSystem = 'Windows'; complianceState = 'compliant'; userPrincipalName = 'ok@contoso.com' }) }
            }
            return @{ value = @() }
        } }
        try {
            Clear-TPState
            Invoke-TPCollectIntuneDeviceCompliance | Out-Null
            $sum = (Get-TPRawData -Key 'Intune-DeviceCompliance').Data.OSComplianceSummary
            @($sum.NonCompliantDevices).Count | Should -Be 1
            $sum.NonCompliantDevices[0].UserPrincipalName | Should -Be 'heidi@contoso.com'
            $sum.NonCompliantTruncated | Should -BeFalse
        } finally {
            & $script:Mod { Remove-Item -Path 'function:script:Invoke-TPGraphRequest' -ErrorAction SilentlyContinue }
            Clear-TPState
        }
    }
    It 'the entry point computes the view, writes it to the results JSON and publishes it under -ChangeImpact or -AllFiles' {
        $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
        $src | Should -Match '\[switch\] \$ChangeImpact'
        $src | Should -Match 'ChangeImpact\s+= \$changeImpactView'
        $src | Should -Match '\(\$ChangeImpact -or \$AllFiles\)'
    }
    It 'no variable in the entry point shadows a parameter under another casing' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1'), [ref]$null, [ref]$null)
        $params = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        $assigned = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.AssignmentStatementAst] -and $n.Left -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) |
            ForEach-Object { $_.Left.VariablePath.UserPath } | Sort-Object -Unique)
        foreach ($p in $params) {
            $clash = @($assigned | Where-Object { $_ -ieq $p -and $_ -cne $p })
            $clash | Should -BeNullOrEmpty -Because "`$$($clash -join ', ') is the -$p parameter: PowerShell variable names ignore case"
        }
    }
}
