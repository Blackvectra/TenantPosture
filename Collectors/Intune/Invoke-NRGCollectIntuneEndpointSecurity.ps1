#Requires -Version 7.0
#
# Invoke-NRGCollectIntuneEndpointSecurity.ps1
# Collects Intune Endpoint Security policies (LAPS, ASR, Firewall, EDR, Antivirus).
#
# READ-ONLY: GET-only Graph calls. Does not create, modify, or remove configuration.
#
# Returns: structured hashtable under key 'Intune-EndpointSecurity' via Set-NRGRawData.
# Reads:   Graph deviceManagement/configurationPolicies and deviceManagement/intents.
#
# NIST SP 800-53: CM-7 (least functionality), SI-3 (malicious code protection),
#                 SI-4 (system monitoring), SC-7 (boundary protection),
#                 IA-5 (authenticator management — for LAPS local admin)
# MITRE ATT&CK:   T1078.003 (Local Accounts), T1059 (Command and Scripting Interpreter),
#                 T1190 (Exploit Public-Facing App), T1190
#

function Invoke-NRGCollectIntuneEndpointSecurity {
    [CmdletBinding()] param()
    $result = @{
        Success = $false
        Data    = @{
            LAPSPolicies              = @()
            ASRPolicies               = @()
            FirewallPolicies          = @()
            EndpointDetectionPolicies = @()
            AntivirusPolicies         = @()
            # Aggregate union with TemplateType field — used by legacy INT-1.5 evaluator
            EndpointSecurityPolicies  = @()
        }
    }

    # Template-family values from /deviceManagement/configurationPolicies.templateReference.
    # Source: Intune docs ref-graph-api-csp-windows; values are stable strings.
    $familyMap = @{
        'endpointSecurityAccountProtection'           = 'LAPS'   # account protection (LAPS + Cred Guard live here)
        'endpointSecurityAttackSurfaceReduction'      = 'ASR'
        'endpointSecurityFirewall'                    = 'Firewall'
        'endpointSecurityEndpointDetectionAndResponse'= 'EDR'
        'endpointSecurityAntivirus'                   = 'Antivirus'
    }

    # Empty is not clean: every section below initializes to @(), so an empty
    # list cannot be told apart from a query that failed. Both the settings-catalog and the legacy intents endpoint feed the same sections.
    # A section is only 'Failed' when EVERY query feeding it failed —
    # one surviving feeder still yields real data.
    $cfgFailed = $false
    $intentFailed = $false

    try {
        # ── Unified settings-catalog endpoint security policies ──────────────
        # configurationPolicies is the modern surface; templateReference.templateFamily
        # tags the policy type. Beta is used because templateReference is more reliable
        # there for endpoint-security families.
        try {
            $uri  = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$select=id,name,description,platforms,templateReference,createdDateTime,lastModifiedDateTime'
            $next = $uri
            $all  = @()
            # Pagination cap (v4.6.3 P2): see Intune-DeviceCompliance / AADRoles.
            $maxPages  = 200
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-NRGGraphRequest -Method GET -Uri $next -ErrorAction Stop
                if ($page.value) { $all += $page.value }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Intune-EndpointSecurity' `
                        -Message "Pagination cap reached ($maxPages pages); configuration policy list may be truncated."
                }
            }

            foreach ($p in $all) {
                $tplFamily = $null
                if ($p.templateReference) { $tplFamily = [string]$p.templateReference.templateFamily }
                $tplName = if ($p.templateReference) { [string]$p.templateReference.templateDisplayName } else { '' }
                $name    = [string]$p.name

                # Map template family → bucket, with displayName fallback for tenants
                # whose templateReference is unpopulated on legacy migrated policies.
                $bucket = $null
                if ($tplFamily -and $familyMap.ContainsKey($tplFamily)) {
                    $bucket = $familyMap[$tplFamily]
                } elseif ($tplName -match 'LAPS|Local admin password') {
                    $bucket = 'LAPS'
                } elseif ($tplName -match 'Attack Surface|ASR') {
                    $bucket = 'ASR'
                } elseif ($tplName -match 'Firewall') {
                    $bucket = 'Firewall'
                } elseif ($tplName -match 'Endpoint Detection|EDR') {
                    $bucket = 'EDR'
                } elseif ($tplName -match 'Antivirus|Microsoft Defender') {
                    $bucket = 'Antivirus'
                } elseif ($name -match 'LAPS') {
                    $bucket = 'LAPS'
                } elseif ($name -match 'ASR|Attack Surface') {
                    $bucket = 'ASR'
                } elseif ($name -match 'Firewall') {
                    $bucket = 'Firewall'
                } elseif ($name -match 'EDR|Endpoint Detection') {
                    $bucket = 'EDR'
                } elseif ($name -match 'Antivirus|AV\b|Defender Antivirus') {
                    $bucket = 'Antivirus'
                }

                $entry = @{
                    Id                  = $p.id
                    DisplayName         = $name
                    Description         = [string]$p.description
                    Platforms           = [string]$p.platforms
                    TemplateFamily      = $tplFamily
                    TemplateDisplayName = $tplName
                    TemplateType        = $bucket
                    Source              = 'configurationPolicies'
                    CreatedDateTime     = $p.createdDateTime
                    LastModifiedDateTime= $p.lastModifiedDateTime
                }

                $result.Data.EndpointSecurityPolicies += $entry

                switch ($bucket) {
                    'LAPS'      { $result.Data.LAPSPolicies              += $entry }
                    'ASR'       { $result.Data.ASRPolicies               += $entry }
                    'Firewall'  { $result.Data.FirewallPolicies          += $entry }
                    'EDR'       { $result.Data.EndpointDetectionPolicies += $entry }
                    'Antivirus' { $result.Data.AntivirusPolicies         += $entry }
                }
            }
        } catch {
            $cfgFailed = $true
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-EndpointSecurity-ConfigPolicies' -Message $_.Exception.Message
            }
        }

        # ── Legacy intents endpoint (older endpoint-security templates) ──────
        # Tenants created before unified settings catalog may have policies only here.
        # Same bucketing logic by templateDisplayName.
        # v4.6.4 EMERGENCY FIX (Critical #3): added @odata.nextLink pagination.
        try {
            $next = 'https://graph.microsoft.com/beta/deviceManagement/intents?$select=id,displayName,description,templateId,isAssigned'
            $intentAll = @()
            $maxPages  = 200
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-NRGGraphRequest -Method GET -Uri $next -ErrorAction Stop
                if ($page.value) { $intentAll += $page.value }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                    Register-NRGException -Source 'Intune-EndpointSecurity-Intents' `
                        -Message "Pagination cap reached ($maxPages pages); intents list may be truncated."
                }
            }
            foreach ($i in $intentAll) {
                $tplName = [string]$i.displayName
                $bucket = $null
                if     ($tplName -match 'LAPS|Local admin password') { $bucket = 'LAPS' }
                elseif ($tplName -match 'Attack Surface|ASR')         { $bucket = 'ASR' }
                elseif ($tplName -match 'Firewall')                   { $bucket = 'Firewall' }
                elseif ($tplName -match 'Endpoint Detection|EDR')     { $bucket = 'EDR' }
                elseif ($tplName -match 'Antivirus|Microsoft Defender'){$bucket = 'Antivirus' }

                if (-not $bucket) { continue }  # not an endpoint security intent we track

                $entry = @{
                    Id                  = $i.id
                    DisplayName         = $tplName
                    Description         = [string]$i.description
                    TemplateId          = [string]$i.templateId
                    IsAssigned          = [bool]$i.isAssigned
                    TemplateType        = $bucket
                    Source              = 'intents'
                }

                $result.Data.EndpointSecurityPolicies += $entry
                switch ($bucket) {
                    'LAPS'      { $result.Data.LAPSPolicies              += $entry }
                    'ASR'       { $result.Data.ASRPolicies               += $entry }
                    'Firewall'  { $result.Data.FirewallPolicies          += $entry }
                    'EDR'       { $result.Data.EndpointDetectionPolicies += $entry }
                    'Antivirus' { $result.Data.AntivirusPolicies         += $entry }
                }
            }
        } catch {
            $intentFailed = $true
            if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
                Register-NRGException -Source 'Intune-EndpointSecurity-Intents' -Message $_.Exception.Message
            }
        }

        $result.Data.SectionStatus = @{
            LAPSPolicies              = $(if ($cfgFailed -and $intentFailed) { 'Failed' } else { 'Collected' })
            ASRPolicies               = $(if ($cfgFailed -and $intentFailed) { 'Failed' } else { 'Collected' })
            FirewallPolicies          = $(if ($cfgFailed -and $intentFailed) { 'Failed' } else { 'Collected' })
            EndpointDetectionPolicies = $(if ($cfgFailed -and $intentFailed) { 'Failed' } else { 'Collected' })
            AntivirusPolicies         = $(if ($cfgFailed -and $intentFailed) { 'Failed' } else { 'Collected' })
            EndpointSecurityPolicies  = $(if ($cfgFailed -and $intentFailed) { 'Failed' } else { 'Collected' })
        }

        $result.Success = $true
    } catch {
        if (Get-Command Register-NRGException -ErrorAction SilentlyContinue) {
            Register-NRGException -Source 'Intune-EndpointSecurity-Collector' -Message $_.Exception.Message
        }
    }

    Set-NRGRawData -Key 'Intune-EndpointSecurity' -Data $result
    # v4.6.4 EMERGENCY FIX (Critical #3): added missing Register-NRGCoverage call
    # per CLAUDE.md collector contract.
    if (Get-Command Register-NRGCoverage -ErrorAction SilentlyContinue) {
        $status = if ($result.Success) { 'Collected' } else { 'Failed' }
        $note   = "LAPS=$($result.Data.LAPSPolicies.Count) ASR=$($result.Data.ASRPolicies.Count) FW=$($result.Data.FirewallPolicies.Count) EDR=$($result.Data.EndpointDetectionPolicies.Count) AV=$($result.Data.AntivirusPolicies.Count)"
        Register-NRGCoverage -Family 'Intune-EndpointSecurity' -Status $status -Note $note
    }
}
