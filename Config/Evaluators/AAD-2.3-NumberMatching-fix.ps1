#
# Test-NRGControlAADCA.ps1 — AAD-2.3 number matching fix
#
# PATCH: Replace the AAD-2.3 block in Test-NRGControlAADCA.ps1 with this version.
#
# Root cause of "Number matching: unknown":
#   Microsoft enforced number matching as a non-configurable tenant default in May 2023.
#   When 'numberMatchingRequiredState' is absent from featureSettings, it means Microsoft
#   is enforcing it at the platform level — NOT that it is disabled or unknown.
#   Treating absence as 'unknown' was producing false Gap findings.
#
# Fix logic:
#   - state = 'enabled'  → Satisfied (explicitly configured)
#   - state absent/null  → Satisfied (Microsoft platform default, enforced since May 2023)
#   - state = 'disabled' → Gap (explicitly disabled — should not be possible on current tenants)
#   - state = 'default'  → Satisfied (Microsoft default enforcement)
#

    #--------------------------------------------------------------------------
    # AAD-2.3  Authenticator number matching enabled
    # IA-2(8) — replay-resistant authentication | T1621 (MFA Fatigue)
    # Replace the existing AAD-2.3 block with this version
    #--------------------------------------------------------------------------
    if ($UserData.Success -and $UserData.AuthMethodPolicy) {
        $authPolicy = $userRaw.Data['AuthMethodPolicy']
        $authenticatorConfig = $authPolicy.AuthenticationMethodConfigurations |
            Where-Object { $_.Id -eq 'MicrosoftAuthenticator' }

        if ($authenticatorConfig) {
            $features           = $authenticatorConfig.AdditionalProperties['featureSettings']
            $numberMatchState   = if ($features -and $features['numberMatchingRequiredState'])        { $features['numberMatchingRequiredState']['state'] }        else { $null }
            $additionalCtxState = if ($features -and $features['displayAppInformationRequiredState']) { $features['displayAppInformationRequiredState']['state'] }  else { $null }

            # Microsoft enforced number matching as platform default in May 2023.
            # Absent or null = Microsoft default enforcement = Satisfied.
            # Only 'disabled' is a genuine gap (and Microsoft removed the ability to set this).
            $numberMatchEffective = if (-not $numberMatchState -or $numberMatchState -in @('enabled','default')) {
                'enabled (Microsoft default or explicit)'
            } else {
                $numberMatchState
            }

            $additionalCtxDisplay = if (-not $additionalCtxState) { 'default' } else { $additionalCtxState }

            if ($numberMatchState -eq 'disabled') {
                # Explicit disable — should not be possible on modern tenants
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
                # Enabled, default, absent — all mean Microsoft is enforcing it
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
