#
# Test-NRGControlAADCA.ps1
# Evaluates Conditional Access policy coverage.
#
# Controls:
#   AAD-1.1  Legacy authentication blocked (CA enforcement)
#   AAD-2.3  Authenticator number matching enabled
#   AAD-3.1  CA: MFA required for all users on all cloud apps
#   AAD-3.2  CA: Legacy authentication blocked
#   AAD-3.3  CA: MFA required for Azure management
#   AAD-3.4  No CA policies stuck in report-only mode
#   AAD-3.5  CA: Sign-in risk policy (Entra ID P2)
#   AAD-3.6  CA: User risk policy (Entra ID P2)
#
# Reads from module state:
#   Get-NRGRawData -Key 'AAD-CAPolicies'
#   Get-NRGRawData -Key 'AAD-Users'
#
# NIST SP 800-53: IA-2, IA-2(1), IA-2(2), IA-2(8), AC-17, SI-4
# MITRE ATT&CK:   T1078, T1110, T1133, T1621 (MFA Fatigue)
#

function Test-NRGControlAADCA {
    [CmdletBinding()] param()

    $caRaw   = Get-NRGRawData -Key 'AAD-CAPolicies'
    $userRaw = Get-NRGRawData -Key 'AAD-Users'

    # CA collector failed — skip all CA controls
    if (-not $caRaw -or -not $caRaw.Success) {
        $detail = if ($caRaw) { "CA collector failed: $($caRaw.Exceptions -join '; ')" } else { 'AAD-CAPolicies collector did not run.' }
        foreach ($id in @('AAD-1.1','AAD-3.1','AAD-3.2','AAD-3.3','AAD-3.4','AAD-3.5','AAD-3.6')) {
            Add-NRGFinding -ControlId $id -State 'NotApplicable' `
                -Category 'Identity' -Title "CA Policy Assessment — $id" -Detail $detail
        }
        # AAD-2.3 uses user data — fall through to assess separately below
    }

    $policies = if ($caRaw -and $caRaw.Success) { @($caRaw.Data['Policies']) } else { @() }

    #--------------------------------------------------------------------------
    # AAD-3.2  CA: Legacy authentication blocked
    # IA-2, AC-17 | T1110 — legacy auth bypasses MFA and CA entirely
    #--------------------------------------------------------------------------
    if ($caRaw -and $caRaw.Success) {
        $legacyBlock = @($policies | Where-Object {
            $_.State -eq 'enabled' -and
            ($_.Conditions.ClientAppTypes -contains 'other' -or
             $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync') -and
            $_.GrantControls.BuiltInControls -contains 'block'
        })

        if ($legacyBlock.Count -gt 0) {
            Add-NRGFinding -ControlId 'AAD-3.2' -State 'Satisfied' `
                -Category 'Identity' -Title 'Conditional Access: Legacy authentication blocked' `
                -Severity 'Informational' `
                -CurrentValue "Enforced CA policy: '$($legacyBlock[0].DisplayName)'" `
                -RequiredValue 'Enabled CA policy blocking client app types: other, exchangeActiveSync'
        }
        else {
            $legacyReportOnly = @($policies | Where-Object {
                $_.State -eq 'enabledForReportingButNotEnforced' -and
                ($_.Conditions.ClientAppTypes -contains 'other' -or
                 $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync') -and
                $_.GrantControls.BuiltInControls -contains 'block'
            })

            if ($legacyReportOnly.Count -gt 0) {
                Add-NRGFinding -ControlId 'AAD-3.2' -State 'Partial' `
                    -Category 'Identity' -Title 'Conditional Access: Legacy authentication blocked' `
                    -Severity 'Critical' `
                    -Detail 'Policy exists but is in report-only mode — no enforcement active.' `
                    -CurrentValue "Report-only policy: '$($legacyReportOnly[0].DisplayName)'" `
                    -RequiredValue 'Enabled (enforced) CA policy blocking legacy auth client app types' `
                    -Remediation 'Review EXO sign-in logs for active legacy auth clients. Promote to enabled once confirmed clear. Verify EXO SMTP AUTH disabled independently (EXO-1.2).' `
                    -FrameworkIds @('IA-2','IA-2(1)','AC-17')
            }
            else {
                Add-NRGFinding -ControlId 'AAD-3.2' -State 'Gap' `
                    -Category 'Identity' -Title 'Conditional Access: Legacy authentication blocked' `
                    -Severity 'Critical' `
                    -Detail 'No enabled CA policy found blocking legacy authentication (client app types: Other/Exchange ActiveSync).' `
                    -CurrentValue 'No CA policy blocking legacy auth' `
                    -RequiredValue 'Enabled CA policy: All users, All apps, Client apps = Other + EAS, Grant = Block' `
                    -Remediation 'Create CA policy: All users, All cloud apps, Client apps = Other clients + Exchange ActiveSync, Grant = Block. Stage in report-only first. Verify EXO SMTP AUTH (EXO-1.2) independently.' `
                    -FrameworkIds @('IA-2','IA-2(1)','AC-17')
            }
        }

        #----------------------------------------------------------------------
        # AAD-3.1  MFA required for all users, all cloud apps
        # IA-2(1), IA-2(2) | T1078
        #----------------------------------------------------------------------
        $mfaAllUsers = @($policies | Where-Object {
            $_.State -eq 'enabled' -and
            $_.Conditions.Users.IncludeUsers -contains 'All' -and
            $_.Conditions.Applications.IncludeApplications -contains 'All' -and
            $_.GrantControls -ne $null -and
            $_.GrantControls.BuiltInControls -contains 'mfa'
        })

        if ($mfaAllUsers.Count -gt 0) {
            Add-NRGFinding -ControlId 'AAD-3.1' -State 'Satisfied' `
                -Category 'Identity' -Title 'Conditional Access: MFA required for all users on all cloud apps' `
                -Severity 'Informational' `
                -CurrentValue "Enforced CA policy: '$($mfaAllUsers[0].DisplayName)'" `
                -RequiredValue 'Enabled CA policy requiring MFA for All users on All cloud apps'
        }
        else {
            $mfaReportOnly = @($policies | Where-Object {
                $_.State -eq 'enabledForReportingButNotEnforced' -and
                $_.Conditions.Users.IncludeUsers -contains 'All' -and
                $_.GrantControls.BuiltInControls -contains 'mfa'
            })

            if ($mfaReportOnly.Count -gt 0) {
                Add-NRGFinding -ControlId 'AAD-3.1' -State 'Partial' `
                    -Category 'Identity' -Title 'Conditional Access: MFA required for all users on all cloud apps' `
                    -Severity 'Critical' `
                    -Detail 'MFA policy exists but is in report-only mode. Not enforced — MFA is not required.' `
                    -CurrentValue "Report-only policy: '$($mfaReportOnly[0].DisplayName)'" `
                    -RequiredValue 'Enabled (enforced) CA policy requiring MFA for all users' `
                    -Remediation 'Verify MFA registration completeness (AAD-2.1 >= 95%) then promote policy to enabled.' `
                    -FrameworkIds @('IA-2(1)','IA-2(2)')
            }
            else {
                Add-NRGFinding -ControlId 'AAD-3.1' -State 'Gap' `
                    -Category 'Identity' -Title 'Conditional Access: MFA required for all users on all cloud apps' `
                    -Severity 'Critical' `
                    -Detail 'No enabled CA policy requires MFA for All users on All cloud apps. Compromised credentials provide immediate account access.' `
                    -CurrentValue 'No MFA CA policy for all users' `
                    -RequiredValue 'Enabled CA policy: All users (exclude break-glass), All cloud apps, Grant = Require MFA' `
                    -Remediation 'Create CA policy: All users (exclude break-glass named location), All cloud apps, Grant = Require MFA. Deploy report-only first. Do not enforce until AAD-2.1 registration exceeds 95%.' `
                    -FrameworkIds @('IA-2(1)','IA-2(2)')
            }
        }

        #----------------------------------------------------------------------
        # AAD-3.3  MFA required for Azure management
        # AC-6(5), IA-2(1) | T1078.004
        #----------------------------------------------------------------------
        $azureMgmtAppId = '797f4846-ba00-4fd7-ba43-dac1f8f63013'
        $mfaAzure = @($policies | Where-Object {
            $_.State -eq 'enabled' -and
            ($_.Conditions.Applications.IncludeApplications -contains $azureMgmtAppId -or
             $_.Conditions.Applications.IncludeApplications -contains 'All') -and
            $_.GrantControls -ne $null -and
            $_.GrantControls.BuiltInControls -contains 'mfa'
        })

        if ($mfaAzure.Count -gt 0) {
            Add-NRGFinding -ControlId 'AAD-3.3' -State 'Satisfied' `
                -Category 'Identity' -Title 'Conditional Access: MFA required for Azure management' `
                -Severity 'Informational' `
                -CurrentValue "Covered by policy: '$($mfaAzure[0].DisplayName)'" `
                -RequiredValue 'Enabled CA policy requiring MFA for Microsoft Azure Management app'
        }
        else {
            Add-NRGFinding -ControlId 'AAD-3.3' -State 'Gap' `
                -Category 'Identity' -Title 'Conditional Access: MFA required for Azure management' `
                -Severity 'High' `
                -Detail 'No enabled CA policy enforces MFA for Azure management (Azure portal, CLI, PowerShell). App ID: 797f4846-ba00-4fd7-ba43-dac1f8f63013.' `
                -CurrentValue 'No MFA CA policy for Azure management' `
                -RequiredValue 'Enabled CA policy targeting Microsoft Azure Management app with MFA grant' `
                -Remediation 'Add Microsoft Azure Management to existing all-users MFA CA policy, or create a dedicated policy. Covers Azure portal, Azure CLI, and Azure PowerShell.' `
                -FrameworkIds @('IA-2(1)','AC-6(5)')
        }

        #----------------------------------------------------------------------
        # AAD-3.4  No CA policies stuck in report-only
        # CM-7 — unenforced policies create false coverage
        #----------------------------------------------------------------------
        $reportOnlyPolicies = @($policies | Where-Object {
            $_.State -eq 'enabledForReportingButNotEnforced'
        })

        if ($reportOnlyPolicies.Count -eq 0) {
            Add-NRGFinding -ControlId 'AAD-3.4' -State 'Satisfied' `
                -Category 'Identity' -Title 'No Conditional Access policies remaining in report-only mode' `
                -Severity 'Informational' `
                -CurrentValue 'No CA policies in report-only mode' `
                -RequiredValue 'All CA policies either enforced or disabled'
        }
        else {
            $names = ($reportOnlyPolicies | Select-Object -ExpandProperty DisplayName) -join '; '
            Add-NRGFinding -ControlId 'AAD-3.4' -State 'Partial' `
                -Category 'Identity' -Title 'No Conditional Access policies remaining in report-only mode' `
                -Severity 'Medium' `
                -Detail 'Report-only policies provide zero enforcement. They generate logs but do not block or require anything.' `
                -CurrentValue "$($reportOnlyPolicies.Count) report-only policy/policies: $names" `
                -RequiredValue 'All security CA policies in enabled (enforced) state' `
                -Remediation 'Review each. Enforce or document acceptance with rationale and target date. Report-only provides zero protection.'
        }

        #----------------------------------------------------------------------
        # AAD-3.5  Sign-in risk CA policy (Entra ID P2 required)
        # SI-4, IA-2 | T1078 — anomalous sign-in detection
        #----------------------------------------------------------------------
        $signInRiskPolicy = @($policies | Where-Object {
            $_.State -eq 'enabled' -and
            $_.Conditions.SignInRiskLevels -ne $null -and
            $_.Conditions.SignInRiskLevels.Count -gt 0
        })

        if ($signInRiskPolicy.Count -gt 0) {
            $levels = ($signInRiskPolicy[0].Conditions.SignInRiskLevels) -join ', '
            Add-NRGFinding -ControlId 'AAD-3.5' -State 'Satisfied' `
                -Category 'Identity' -Title 'Conditional Access: Sign-in risk policy configured (Entra ID P2)' `
                -Severity 'Informational' `
                -CurrentValue "Policy: '$($signInRiskPolicy[0].DisplayName)' [Risk levels: $levels]" `
                -RequiredValue 'Enabled CA policy targeting sign-in risk Medium/High with MFA or block response'
        }
        else {
            Add-NRGFinding -ControlId 'AAD-3.5' -State 'Gap' `
                -Category 'Identity' -Title 'Conditional Access: Sign-in risk policy configured (Entra ID P2)' `
                -Severity 'High' `
                -Detail 'No CA policy found targeting sign-in risk levels. Entra ID Protection signals (impossible travel, malicious IP, atypical behavior) are generated but not acted upon.' `
                -CurrentValue 'No sign-in risk CA policy' `
                -RequiredValue 'Enabled CA policy: All users, All cloud apps, Sign-in risk = Medium+High, Grant = Require MFA (High = block or compliant device)' `
                -Remediation 'Requires Entra ID P2 (included in M365 Business Premium). Create sign-in risk CA policy: Medium risk = MFA step-up; High risk = block or MFA + compliant device.' `
                -FrameworkIds @('IA-2','SI-4','AU-6')
        }

        #----------------------------------------------------------------------
        # AAD-3.6  User risk CA policy (Entra ID P2 required)
        # IR-4, SI-4 | T1078 — compromised account containment
        #----------------------------------------------------------------------
        $userRiskPolicy = @($policies | Where-Object {
            $_.State -eq 'enabled' -and
            $_.Conditions.UserRiskLevels -ne $null -and
            $_.Conditions.UserRiskLevels.Count -gt 0
        })

        if ($userRiskPolicy.Count -gt 0) {
            $levels = ($userRiskPolicy[0].Conditions.UserRiskLevels) -join ', '
            Add-NRGFinding -ControlId 'AAD-3.6' -State 'Satisfied' `
                -Category 'Identity' -Title 'Conditional Access: User risk policy configured (Entra ID P2)' `
                -Severity 'Informational' `
                -CurrentValue "Policy: '$($userRiskPolicy[0].DisplayName)' [Risk levels: $levels]" `
                -RequiredValue 'Enabled CA policy targeting user risk High with block or password change response'
        }
        else {
            Add-NRGFinding -ControlId 'AAD-3.6' -State 'Gap' `
                -Category 'Identity' -Title 'Conditional Access: User risk policy configured (Entra ID P2)' `
                -Severity 'High' `
                -Detail 'No CA policy targeting user risk. Leaked credential detection and persistent behavioral anomalies do not result in automated account action.' `
                -CurrentValue 'No user risk CA policy' `
                -RequiredValue 'Enabled CA policy: All users, All cloud apps, User risk = High, Grant = Block or require password change + MFA' `
                -Remediation 'Requires Entra ID P2. Create user risk CA policy: High user risk = block sign-in or require secure password change + MFA.' `
                -FrameworkIds @('IA-2','IR-4','SI-4')
        }
    }

    #--------------------------------------------------------------------------
    # AAD-2.3  Authenticator number matching enabled
    # IA-2(8) — replay-resistant authentication | T1621 (MFA Fatigue)
    #
    # FIX: Microsoft enforced number matching as platform default in May 2023.
    # Absent/null state = Microsoft enforcing it = Satisfied, not unknown/Gap.
    #--------------------------------------------------------------------------
    if ($userRaw -and $userRaw.Success -and $userRaw.Data['AuthMethodPolicy']) {
        $authPolicy          = $userRaw.Data['AuthMethodPolicy']
        $authenticatorConfig = $authPolicy.AuthenticationMethodConfigurations |
            Where-Object { $_.Id -eq 'MicrosoftAuthenticator' }

        if ($authenticatorConfig) {
            $features           = $authenticatorConfig.AdditionalProperties['featureSettings']
            $numberMatchState   = if ($features -and $features['numberMatchingRequiredState'])        { $features['numberMatchingRequiredState']['state'] }        else { $null }
            $additionalCtxState = if ($features -and $features['displayAppInformationRequiredState']) { $features['displayAppInformationRequiredState']['state'] }  else { $null }

            $numberMatchEffective = if (-not $numberMatchState -or $numberMatchState -in @('enabled','default')) {
                'enabled (Microsoft default or explicit)'
            } else {
                $numberMatchState
            }
            $additionalCtxDisplay = if (-not $additionalCtxState) { 'default' } else { $additionalCtxState }

            if ($numberMatchState -eq 'disabled') {
                Add-NRGFinding -ControlId 'AAD-2.3' -State 'Gap' `
                    -Category 'Identity' -Title 'Authenticator app number matching enabled' `
                    -Severity 'High' `
                    -Detail 'Number matching is explicitly disabled. Push notifications are vulnerable to MFA fatigue (T1621).' `
                    -CurrentValue "Number matching: disabled. Additional context: $additionalCtxDisplay" `
                    -RequiredValue 'Number matching: enabled' `
                    -Remediation 'Entra ID > Authentication methods > Microsoft Authenticator > Configure. Enable Number matching. This should not be disabled on any current tenant.' `
                    -FrameworkIds @('IA-2(8)')
            }
            else {
                Add-NRGFinding -ControlId 'AAD-2.3' -State 'Satisfied' `
                    -Category 'Identity' -Title 'Authenticator app number matching enabled' `
                    -Severity 'Informational' `
                    -CurrentValue "Number matching: $numberMatchEffective. Additional context: $additionalCtxDisplay" `
                    -RequiredValue 'Number matching: enabled'
            }
        }
        else {
            Add-NRGFinding -ControlId 'AAD-2.3' -State 'NotApplicable' `
                -Category 'Identity' -Title 'Authenticator app number matching enabled' `
                -Detail 'Microsoft Authenticator not found in authentication method policy configurations.'
        }
    }
    else {
        Add-NRGFinding -ControlId 'AAD-2.3' -State 'NotApplicable' `
            -Category 'Identity' -Title 'Authenticator app number matching enabled' `
            -Detail 'AAD-Users collector data unavailable — cannot assess auth method policy.'
    }
}
