#Requires -Version 7.0
#
# Test-TPControlAADPrivAccess.ps1
# Evaluates AAD-3.1 "Global Administrator Count 2-8, Cloud-Only" (canonical
# control per Config/controls.json).
#
# v4.6.4: scope-of-emission contracted to AAD-3.1 ONLY. Earlier revisions of
# this file emitted findings under AAD-4.1, AAD-4.2 and AAD-4.3 with the
# wrong Title strings, colliding with the older monolithic AAD evaluator
# (Test-TPControl-AAD.ps1) which is the canonical evaluator for those IDs.
# It also emitted findings under AAD-4.4 and AAD-4.5 which are not defined in
# controls.json. All cross-emit logic was removed; this file now matches the
# EvaluatorFunction field declared in controls.json for AAD-3.1.
#
# Reads from module state:
#   Get-TPRawData -Key 'AAD-DirectoryRoles'  (Invoke-TPCollectAADRoles)
#
# NIST SP 800-53: AC-6, AC-6(5)
# MITRE ATT&CK:   T1078.004, T1098
#

function Test-TPControlAADPrivAccess {
    [CmdletBinding()] param()

    $roleRaw = Get-TPRawData -Key 'AAD-DirectoryRoles'

    if (-not $roleRaw -or -not $roleRaw.Success) {
        $detail = if ($roleRaw) { "Collector failed: $(@(Get-TPObjectField -Item $roleRaw -Key 'Exceptions' -Default @()) -join '; ')" } else { 'AAD-DirectoryRoles collector did not run.' }
        Add-TPFinding -ControlId 'AAD-3.1' -State 'NotApplicable' `
            -Category 'Identity' -Title 'Global Administrator Count 2-8, Cloud-Only' -Detail $detail
        return
    }

    # Well-known Entra ID built-in role template GUID — stable across all tenants
    $GA_ROLE_ID = '62e90394-69f5-4237-9190-012177145e10'

    # Collector (Invoke-TPCollectAADRoles) writes Data.RoleAssignments as an array
    # of hashtables with keys RoleDefinitionId / OnPremisesSyncEnabled. Read via
    # Get-TPObjectField (IDictionary-aware) — Get-TPSafeProperty is property-only
    # and returns Default for hashtables, which made every GA read $null → a
    # permanent false "0 Global Administrators" finding independent of collection.
    $allAssignments = @(Get-TPNestedProperty -Object $roleRaw -Path 'Data.RoleAssignments' -Default @())

    # The collector's Success is (assignments -OR- eligibility), so an empty
    # assignment list can survive a failed read. Counting Global Admins from it
    # would then report "fewer than 2 Global Administrators" — a false alarm on
    # a tenant that may have plenty, which is just as damaging to the report's
    # credibility as a false pass.
    $roleSection = Get-TPNestedProperty -Object $roleRaw -Path 'Data.SectionStatus.RoleAssignments' -Default $null
    if ($allAssignments.Count -eq 0 -and $null -ne $roleSection -and $roleSection -ne 'Collected') {
        Add-TPFinding -ControlId 'AAD-3.1' -State 'NotApplicable' `
            -Category 'Identity' -Title 'Global Administrator Count 2-8, Cloud-Only' `
            -Detail 'Role assignment enumeration did not complete (see Exceptions) — Global Administrator count could not be determined.'
        return
    }
    # Everyone who can act as Global Administrator: permanent AND eligible
    # (PIM), one row per principal. Counting permanent assignments only let a
    # tenant with 20 eligible GAs pass "2-8 Global Administrators".
    $pool = @($allAssignments) + @(Get-TPNestedProperty -Object $roleRaw -Path 'Data.AllPrivilegedAssignments' -Default @())
    $seenGa = [System.Collections.Generic.HashSet[string]]::new()
    $globalAdmins   = @($pool | Where-Object {
        (Get-TPObjectField -Item $_ -Key 'RoleDefinitionId') -eq $GA_ROLE_ID -and
        $seenGa.Add([string](Get-TPObjectField -Item $_ -Key 'PrincipalId' -Default (Get-TPObjectField -Item $_ -Key 'PrincipalUPN' -Default ([guid]::NewGuid().ToString()))))
    })
    # A role-assignable GROUP holding Global Administrator stands for all its
    # members, whose number and sync state were never read — counting the group
    # as one cloud-only admin is not an answer.
    $gaGroups = @($globalAdmins | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'PrincipalType' -Default '') -match 'group' })
    if ($gaGroups.Count -gt 0) {
        Add-TPFinding -ControlId 'AAD-3.1' -State 'NotApplicable' `
            -Category 'Identity' -Title 'Global Administrator Count 2-8, Cloud-Only' `
            -FrameworkIds (Get-TPFrameworkCitations -ControlId 'AAD-3.1') `
            -Detail "Global Administrator is assigned to $($gaGroups.Count) group(s) ($(($gaGroups | ForEach-Object { Get-TPObjectField -Item $_ -Key 'PrincipalDisplayName' -Default '?' }) -join ', ')) whose members were not enumerated, so the number of Global Administrators and whether any is synced from on-premises could not be determined. Not assessed."
        return
    }
    $gaCount        = $globalAdmins.Count
    $syncedGAs      = @($globalAdmins | Where-Object { (Get-TPObjectField -Item $_ -Key 'OnPremisesSyncEnabled') -eq $true })

    # Satisfied  = count in [2..8] AND zero on-prem-synced GA
    # Partial    = count in [2..8] but at least one synced GA (correct count, wrong source)
    # Gap        = count outside [2..8]
    if ($gaCount -ge 2 -and $gaCount -le 8 -and $syncedGAs.Count -eq 0) {
        Add-TPFinding -ControlId 'AAD-3.1' -State 'Satisfied' `
            -Category 'Identity' -Title 'Global Administrator Count 2-8, Cloud-Only' `
            -Severity 'High' `
            -CurrentValue "$gaCount Global Administrator(s) (permanent and eligible), all cloud-only." `
            -RequiredValue 'Between 2 and 8 permanent Global Administrators, all cloud-only (no on-prem sync)' `
            -FrameworkIds (Get-TPFrameworkCitations -ControlId 'AAD-3.1')
    }
    elseif ($gaCount -ge 2 -and $gaCount -le 8 -and $syncedGAs.Count -gt 0) {
        $syncedList = ($syncedGAs | Select-Object -ExpandProperty PrincipalUPN) -join ', '
        Add-TPFinding -ControlId 'AAD-3.1' -State 'Partial' `
            -Category 'Identity' -Title 'Global Administrator Count 2-8, Cloud-Only' `
            -Severity 'High' `
            -Detail 'GA count is within range but at least one GA is synced from on-prem AD. On-prem AD compromise produces immediate Entra Global Admin access via Entra Connect (T1078.002).' `
            -CurrentValue "$gaCount GA(s); $($syncedGAs.Count) synced from on-prem: $syncedList" `
            -RequiredValue 'All Global Administrators cloud-only (no on-prem sync)' `
            -Remediation 'Remove GA role from each synced account. Replace with dedicated cloud-only admin accounts (separate from daily-use accounts).' `
            -FrameworkIds (Get-TPFrameworkCitations -ControlId 'AAD-3.1')
    }
    elseif ($gaCount -lt 2) {
        Add-TPFinding -ControlId 'AAD-3.1' -State 'Gap' `
            -Category 'Identity' -Title 'Global Administrator Count 2-8, Cloud-Only' `
            -Severity 'High' `
            -Detail 'Fewer than 2 Global Administrators creates recovery risk. MFA device loss, account lockout, or Entra outage can produce complete loss of admin access.' `
            -CurrentValue "Permanent Global Administrator count: $gaCount" `
            -RequiredValue 'Minimum 2 Global Administrator accounts for redundancy' `
            -Remediation 'Add a second GA account as dedicated break-glass: cloud-only, unlicensed, credentials sealed offline.' `
            -FrameworkIds (Get-TPFrameworkCitations -ControlId 'AAD-3.1')
    }
    else {
        $gaList = ($globalAdmins | Select-Object -ExpandProperty PrincipalUPN) -join ', '
        Add-TPFinding -ControlId 'AAD-3.1' -State 'Gap' `
            -Category 'Identity' -Title 'Global Administrator Count 2-8, Cloud-Only' `
            -Severity 'High' `
            -Detail 'More than 8 permanent Global Administrators expands the attack surface. Each additional GA is another account that can be compromised for full tenant takeover.' `
            -CurrentValue "Permanent Global Administrator count: $gaCount. Accounts: $gaList" `
            -RequiredValue 'Maximum 8 permanent Global Administrator assignments' `
            -Remediation 'Reduce to 8 or fewer. Reassign excess to scoped roles (Exchange Admin, User Admin, Security Admin, etc.). Migrate remaining to PIM eligible where Entra ID P2 is licensed.' `
            -FrameworkIds (Get-TPFrameworkCitations -ControlId 'AAD-3.1')
    }
}
