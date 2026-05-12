#
# Test-NRGControlPowerPlatform.ps1
# Evaluates Microsoft Power Platform governance controls.
#
# Controls:
#   PPL-1.1  Default environment DLP policy configured
#   PPL-1.2  Power Platform tenant isolation enabled
#   PPL-1.3  High-risk connectors blocked in DLP policies
#   PPL-2.1  Power Platform admin role count minimal
#   PPL-2.2  Non-default environments isolated with DLP policy
#
# Reads: Get-NRGRawData -Key 'PowerPlatform'
#        Get-NRGRawData -Key 'AAD-Roles' (PPL-2.1 only — uses PermanentAssignments)
#
# NOTE: Full DLP policy assessment requires the PowerApps.Administration.PowerShell
# module. Controls will show NotApplicable if that module is not available.
#
# NIST SP 800-53: AC-3, CM-7, AC-17
# MITRE ATT&CK:   T1567, T1530
#

function Test-NRGControlPowerPlatform {
    [CmdletBinding()] param()

    $raw = Get-NRGRawData -Key 'PowerPlatform'

    if (-not $raw -or -not $raw.Success) {
        $detail = if ($raw) { "Collector failed: $($raw.Exceptions -join '; ')" } else { 'Power Platform collector did not run.' }
        foreach ($id in @('PPL-1.1','PPL-1.2','PPL-1.3','PPL-2.1','PPL-2.2')) {
            $ctrl = Get-NRGControlById -ControlId $id
            Add-NRGFinding -ControlId $id -State 'NotApplicable' `
                -Category 'Power Platform' -Title ($ctrl.Title) -Detail $detail
        }
        return
    }

    $envs      = @($raw.Data['Environments'])
    $isolation = $raw.Data['TenantIsolation']
    $dlp       = @($raw.Data['DLPPolicies'])
    $dlpAvail  = $raw.Data['DLPAvailable'] -eq $true

    #--------------------------------------------------------------------------
    # PPL-1.1  Default environment DLP policy configured
    # CM-7, AC-3 | T1567
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'PPL-1.1'
    if (-not $dlpAvail) {
        Add-NRGFinding -ControlId 'PPL-1.1' -State 'NotApplicable' `
            -Category 'Power Platform' -Title $ctrl.Title `
            -Detail 'Power Platform DLP data not available. Install Microsoft.PowerApps.Administration.PowerShell for full DLP assessment: Install-Module Microsoft.PowerApps.Administration.PowerShell'
    } else {
        $defaultEnvId  = ($envs | Where-Object { $_.properties.environmentSku -eq 'Default' -or $_.name -match 'Default' } | Select-Object -First 1).name
        $defaultEnvDlp = @($dlp | Where-Object {
            $_.environments -contains $defaultEnvId -or
            ($_.filterType -eq 'include' -and $_.environments -contains $defaultEnvId) -or
            ($_.filterType -eq 'exclude' -and -not ($_.environments -contains $defaultEnvId)) -or
            $_.filterType -eq 'all'
        })
        if ($defaultEnvDlp.Count -gt 0) {
            Add-NRGFinding -ControlId 'PPL-1.1' -State 'Satisfied' `
                -Category 'Power Platform' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue "$($defaultEnvDlp.Count) DLP policy(ies) apply to the default environment" `
                -RequiredValue 'At least one DLP policy covering the default Power Platform environment'
        } else {
            Add-NRGFinding -ControlId 'PPL-1.1' -State 'Gap' `
                -Category 'Power Platform' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail 'No DLP policy covers the default Power Platform environment. All Power Apps and Power Automate flows created in the default environment can connect to any data source, including external services.' `
                -CurrentValue 'No DLP policy on default environment' `
                -RequiredValue 'DLP policy restricting connector groups in the default environment' `
                -Remediation 'Power Platform admin center > Policies > Data policies > New policy. Apply to Default environment. Move high-risk connectors (HTTP, custom) to Blocked group.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PPL-1.1')
        }
    }

    #--------------------------------------------------------------------------
    # PPL-1.2  Tenant isolation enabled
    # AC-17 | T1567
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'PPL-1.2'
    if ($isolation) {
        $isolationMode = $isolation.isolationMode -or $isolation.tenantIsolationMode
        if ($isolationMode -and $isolationMode -ne 'none' -and $isolationMode -ne 'disabled') {
            Add-NRGFinding -ControlId 'PPL-1.2' -State 'Satisfied' `
                -Category 'Power Platform' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue "Tenant isolation: $isolationMode" `
                -RequiredValue 'Tenant isolation enabled (inbound, outbound, or both)'
        } else {
            Add-NRGFinding -ControlId 'PPL-1.2' -State 'Gap' `
                -Category 'Power Platform' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail 'Tenant isolation is disabled. Power Platform flows and apps in this tenant can connect to data in other tenants, and flows from external tenants can connect to this tenant''s data.' `
                -CurrentValue "Tenant isolation: $isolationMode" `
                -RequiredValue 'Tenant isolation enabled for both inbound and outbound connections' `
                -Remediation 'Power Platform admin center > Policies > Tenant isolation > Enable. Configure allowed exceptions for trusted partner tenants as needed.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PPL-1.2')
        }
    } else {
        Add-NRGFinding -ControlId 'PPL-1.2' -State 'NotApplicable' `
            -Category 'Power Platform' -Title $ctrl.Title `
            -Detail 'Tenant isolation data not available via Graph beta API. Verify Power Platform is provisioned in this tenant.'
    }

    #--------------------------------------------------------------------------
    # PPL-1.3  High-risk connectors blocked in DLP policies
    # CM-7 | T1567
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'PPL-1.3'
    if (-not $dlpAvail) {
        Add-NRGFinding -ControlId 'PPL-1.3' -State 'NotApplicable' `
            -Category 'Power Platform' -Title $ctrl.Title `
            -Detail 'Power Platform DLP data not available. Install Microsoft.PowerApps.Administration.PowerShell for DLP connector assessment.'
    } elseif ($dlp.Count -gt 0) {
        $policiesWithBlocked = @($dlp | Where-Object {
            $_.connectorGroups -and ($_.connectorGroups | Where-Object { $_.classification -eq 'Blocked' -and $_.connectors.Count -gt 0 })
        })
        if ($policiesWithBlocked.Count -gt 0) {
            Add-NRGFinding -ControlId 'PPL-1.3' -State 'Satisfied' `
                -Category 'Power Platform' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue "$($policiesWithBlocked.Count) DLP policy(ies) with Blocked connector group configured" `
                -RequiredValue 'DLP policies with HTTP and custom connectors in Blocked group'
        } else {
            Add-NRGFinding -ControlId 'PPL-1.3' -State 'Gap' `
                -Category 'Power Platform' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail 'DLP policies exist but no Blocked connector group is configured. HTTP and custom connectors — which allow arbitrary external connections — may be unrestricted.' `
                -CurrentValue 'No Blocked connector group in any DLP policy' `
                -RequiredValue 'HTTP, HTTPWithAzureAD, and Custom connectors in Blocked group' `
                -Remediation 'Power Platform admin center > Policies > [DLP Policy] > Blocked group > Add HTTP, HTTPWithAzureAD, Custom connectors.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PPL-1.3')
        }
    } else {
        Add-NRGFinding -ControlId 'PPL-1.3' -State 'Gap' `
            -Category 'Power Platform' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail 'No Power Platform DLP policies found. All connectors are unrestricted — flows can connect to any external service.' `
            -CurrentValue 'No DLP policies' `
            -RequiredValue 'DLP policy with high-risk connectors in Blocked group' `
            -Remediation 'Power Platform admin center > Policies > Data policies > Create DLP policy. Block HTTP connectors and restrict others.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PPL-1.3')
    }

    #--------------------------------------------------------------------------
    # PPL-2.1  Power Platform admin role count minimal
    # AC-6(5) | T1078
    #
    # AAD-Roles collector stores PermanentAssignments (not RoleAssignments).
    # Each assignment has RoleDefinitionId. Filter by known Entra role GUIDs.
    #   Power Platform Administrator : 11648597-926c-4cf3-9c36-bcebb0ba8dcc
    #   Dynamics 365 Administrator   : 44367163-eba1-44c3-98af-f5787879f96a
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'PPL-2.1'
    $rolesRaw = Get-NRGRawData -Key 'AAD-Roles'
    if ($rolesRaw -and $rolesRaw.Success) {
        $allAssignments = @($rolesRaw.Data['PermanentAssignments'])

        # Known Entra role template GUIDs for Power Platform admin roles
        $pplRoleGuids = @(
            '11648597-926c-4cf3-9c36-bcebb0ba8dcc'   # Power Platform Administrator
            '44367163-eba1-44c3-98af-f5787879f96a'   # Dynamics 365 Administrator
        )

        $pplAdmins = @($allAssignments | Where-Object {
            $_.RoleDefinitionId -and $pplRoleGuids -contains $_.RoleDefinitionId
        })

        # Fallback: match by display name if the assignment object carries it
        if ($pplAdmins.Count -eq 0) {
            $pplAdminNames = @('Power Platform Administrator','Dynamics 365 Administrator')
            $pplAdmins = @($allAssignments | Where-Object {
                $_.RoleDisplayName -and $pplAdminNames -contains $_.RoleDisplayName
            })
        }

        if ($pplAdmins.Count -eq 0) {
            Add-NRGFinding -ControlId 'PPL-2.1' -State 'Satisfied' `
                -Category 'Power Platform' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue 'No dedicated Power Platform admin role assignments (Global Admins have access implicitly)' `
                -RequiredValue 'Minimal Power Platform Administrator role assignments'
        } elseif ($pplAdmins.Count -le 3) {
            Add-NRGFinding -ControlId 'PPL-2.1' -State 'Satisfied' `
                -Category 'Power Platform' -Title $ctrl.Title -Severity 'Informational' `
                -CurrentValue "$($pplAdmins.Count) Power Platform admin role assignment(s) — within acceptable range" `
                -RequiredValue '3 or fewer Power Platform admin role assignments'
        } else {
            Add-NRGFinding -ControlId 'PPL-2.1' -State 'Gap' `
                -Category 'Power Platform' -Title $ctrl.Title -Severity $ctrl.Severity `
                -Detail "$($pplAdmins.Count) Power Platform admin role assignments found. Excessive admin access expands attack surface for tenant-wide Power Platform control." `
                -CurrentValue "$($pplAdmins.Count) Power Platform Administrator/Dynamics 365 admin assignments" `
                -RequiredValue '3 or fewer Power Platform admin role assignments' `
                -Remediation 'Review Power Platform Administrator and Dynamics 365 Administrator role assignments. Remove any that are not actively required.' `
                -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PPL-2.1')
        }
    } else {
        Add-NRGFinding -ControlId 'PPL-2.1' -State 'NotApplicable' `
            -Category 'Power Platform' -Title $ctrl.Title `
            -Detail 'AAD role data not available to assess Power Platform admin count.'
    }

    #--------------------------------------------------------------------------
    # PPL-2.2  Non-default environments isolated with DLP policy
    # CM-7 | T1567
    #--------------------------------------------------------------------------
    $ctrl = Get-NRGControlById -ControlId 'PPL-2.2'
    if (-not $dlpAvail) {
        Add-NRGFinding -ControlId 'PPL-2.2' -State 'NotApplicable' `
            -Category 'Power Platform' -Title $ctrl.Title `
            -Detail 'Power Platform DLP data not available. Install Microsoft.PowerApps.Administration.PowerShell.'
    } elseif ($envs.Count -le 1) {
        Add-NRGFinding -ControlId 'PPL-2.2' -State 'Satisfied' `
            -Category 'Power Platform' -Title $ctrl.Title -Severity 'Informational' `
            -CurrentValue 'Only default environment found — no additional environments to isolate' `
            -RequiredValue 'All non-default environments covered by a DLP policy'
    } elseif ($dlp.Count -gt 0) {
        $nonDefaultCount = @($envs | Where-Object {
            $_.properties.environmentSku -ne 'Default' -and $_.name -notmatch 'Default'
        }).Count
        Add-NRGFinding -ControlId 'PPL-2.2' -State 'Partial' `
            -Category 'Power Platform' -Title $ctrl.Title -Severity 'Medium' `
            -Detail "Found $($envs.Count) environments ($nonDefaultCount non-default). DLP policies exist but manual verification required to confirm all non-default environments are covered." `
            -CurrentValue "$($envs.Count) environments, $($dlp.Count) DLP policies" `
            -RequiredValue 'Every non-default environment explicitly covered by a DLP policy' `
            -Remediation 'Power Platform admin center > Policies > Data policies > Verify each non-default environment appears in at least one DLP policy scope.'
    } else {
        Add-NRGFinding -ControlId 'PPL-2.2' -State 'Gap' `
            -Category 'Power Platform' -Title $ctrl.Title -Severity $ctrl.Severity `
            -Detail "$($envs.Count) environments found but no DLP policies exist. Non-default environments (production, sandbox, developer) have no connector restrictions." `
            -CurrentValue "$($envs.Count) environments, no DLP policies" `
            -RequiredValue 'DLP policy covering each non-default environment' `
            -Remediation 'Power Platform admin center > Policies > Data policies > Create policies for each environment or apply tenant-wide policies.' `
            -FrameworkIds (Get-NRGFrameworkCitations -ControlId 'PPL-2.2')
    }
}