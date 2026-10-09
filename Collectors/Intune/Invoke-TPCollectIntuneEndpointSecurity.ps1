#Requires -Version 7.0
#
# Invoke-TPCollectIntuneEndpointSecurity.ps1
# Collects Intune Endpoint Security policies (LAPS, ASR, Firewall, EDR, Antivirus).
#
# READ-ONLY: GET-only Graph calls. Does not create, modify, or remove configuration.
#
# Returns: structured hashtable under key 'Intune-EndpointSecurity' via Set-TPRawData.
# Reads:   Graph deviceManagement/configurationPolicies and deviceManagement/intents.
#
# NIST SP 800-53: CM-7 (least functionality), SI-3 (malicious code protection),
#                 SI-4 (system monitoring), SC-7 (boundary protection),
#                 IA-5 (authenticator management — for LAPS local admin)
# MITRE ATT&CK:   T1078.003 (Local Accounts), T1059 (Command and Scripting Interpreter),
#                 T1190 (Exploit Public-Facing App), T1190
#

# Bucket for an endpoint security policy, from its template name first
# (templateReference.templateDisplayName), then the policy name for policies
# with no template reference. $null for anything that is not one of the five
# policy kinds the controls score.
function Get-TPIntuneEndpointBucket {
    [CmdletBinding()]
    param([string] $TemplateName, [string] $Family, [string] $PolicyName)
    if ($TemplateName) {
        if ($TemplateName -match 'LAPS|Local admin password')                   { return 'LAPS' }
        if ($TemplateName -match '^Attack Surface Reduction Rules|ASR Rules')   { return 'ASR' }
        if ($TemplateName -match 'Firewall' -and $TemplateName -notmatch 'Rules') { return 'Firewall' }
        if ($TemplateName -match 'Endpoint Detection')                          { return 'EDR' }
        if ($TemplateName -match '^(Microsoft )?Defender Antivirus$|^Microsoft Defender Antivirus$|^Antivirus$') { return 'Antivirus' }
        return $null
    }
    if ($Family -eq 'endpointSecurityEndpointDetectionAndResponse') { return 'EDR' }
    if ($PolicyName -match 'LAPS|Local admin password')                         { return 'LAPS' }
    if ($PolicyName -match 'Attack Surface Reduction|\bASR\b')                { return 'ASR' }
    if ($PolicyName -match 'Firewall' -and $PolicyName -notmatch 'Rules')       { return 'Firewall' }
    if ($PolicyName -match 'Endpoint Detection|\bEDR\b')                      { return 'EDR' }
    if ($PolicyName -match 'Antivirus' -and $PolicyName -notmatch 'exclusion')  { return 'Antivirus' }
    return $null
}

function Invoke-TPCollectIntuneEndpointSecurity {
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
            $uri  = 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$select=id,name,description,platforms,templateReference,createdDateTime,lastModifiedDateTime&$expand=assignments'
            $next = $uri
            $all  = @()
            # Pagination cap (v4.6.3 P2): see Intune-DeviceCompliance / AADRoles.
            $maxPages  = 200
            $pageCount = 0
            while ($next -and $pageCount -lt $maxPages) {
                $page = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
                if ($page.value) { $all += $page.value }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'Intune-EndpointSecurity' `
                        -Message "Pagination cap reached ($maxPages pages); configuration policy list may be truncated."
                }
            }

            foreach ($p in $all) {
                # templateReference is a $select'd field that can still come
                # back entirely absent (legacy migrated policies) — a bare
                # $p.templateReference read (even just to test truthiness)
                # throws under StrictMode when the key itself is missing.
                $tplRef    = Get-TPNestedProperty -Object $p -Path 'templateReference' -Default $null
                $tplFamily = if ($tplRef) { [string](Get-TPNestedProperty -Object $tplRef -Path 'templateFamily' -Default '') } else { $null }
                $tplName   = if ($tplRef) { [string](Get-TPNestedProperty -Object $tplRef -Path 'templateDisplayName' -Default '') } else { '' }
                $name    = [string](Get-TPObjectField -Item $p -Key 'name' -Default '')

                # A template FAMILY holds several templates: account protection
                # is LAPS, Account protection (Credential Guard, WHfB) and more;
                # attack surface reduction is ASR Rules, Device Control, App
                # Control, Exploit Protection and Web Protection; antivirus
                # includes exclusions and the Security Experience. Bucketing by
                # family counted a USB-block policy as ASR rules and Credential
                # Guard as LAPS, so the specific template name decides.
                $bucket = Get-TPIntuneEndpointBucket -TemplateName $tplName -Family $tplFamily -PolicyName $name
                $asg = Get-TPObjectField -Item $p -Key 'assignments' -Default $null

                $entry = @{
                    Id                  = (Get-TPObjectField -Item $p -Key 'id' -Default $null)
                    DisplayName         = $name
                    Description         = [string](Get-TPObjectField -Item $p -Key 'description' -Default '')
                    Platforms           = [string](Get-TPObjectField -Item $p -Key 'platforms' -Default '')
                    TemplateFamily      = $tplFamily
                    TemplateDisplayName = $tplName
                    TemplateType        = $bucket
                    Source              = 'configurationPolicies'
                    IsAssigned          = $(if ($null -ne $asg) { @($asg | Where-Object { $_ }).Count -gt 0 } else { $null })
                    CreatedDateTime     = (Get-TPObjectField -Item $p -Key 'createdDateTime' -Default $null)
                    LastModifiedDateTime= (Get-TPObjectField -Item $p -Key 'lastModifiedDateTime' -Default $null)
                }

                # For an assigned ASR policy, read the rules it configures and each rule's
                # mode: a policy existing does not show Block mode. A failed read is recorded
                # on the entry, never guessed.
                if ($bucket -in @('ASR','Antivirus') -and $entry.IsAssigned -ne $false -and $entry.Id) {
                    try {
                        $sUri = "https://graph.microsoft.com/beta/deviceManagement/configurationPolicies/$($entry.Id)/settings"
                        $sAll = @(); $sPages = 0
                        while ($sUri -and $sPages -lt 20) {
                            $sPage = Invoke-TPGraphRequest -Method GET -Uri $sUri -ErrorAction Stop
                            if ($sPage.value) { $sAll += $sPage.value }
                            $sUri = $sPage['@odata.nextLink']
                            $sPages++
                        }
                        $sStatus = $(if ($sUri) { 'Partial' } else { 'Read' })
                        if ($bucket -eq 'ASR') {
                            $entry.AsrRuleModes = Get-TPAsrRuleModes -Settings $sAll
                            $entry.AsrSettingsStatus = $sStatus
                        } else {
                            $entry.AvSettings = Get-TPAvSettings -Settings $sAll
                            $entry.AvSettingsStatus = $sStatus
                        }
                    } catch {
                        if ($bucket -eq 'ASR') { $entry.AsrSettingsStatus = 'Failed' } else { $entry.AvSettingsStatus = 'Failed' }
                        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                            Register-TPException -Source "Intune-EndpointSecurity-${bucket}Settings" -Message $_.Exception.Message
                        }
                    }
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
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Intune-EndpointSecurity-ConfigPolicies' -Message $_.Exception.Message
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
                $page = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
                if ($page.value) { $intentAll += $page.value }
                $next = $page['@odata.nextLink']
                $pageCount++
            }
            if ($pageCount -ge $maxPages -and $next) {
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'Intune-EndpointSecurity-Intents' `
                        -Message "Pagination cap reached ($maxPages pages); intents list may be truncated."
                }
            }
            foreach ($i in $intentAll) {
                $tplName = [string](Get-TPObjectField -Item $i -Key 'displayName' -Default '')
                $bucket = Get-TPIntuneEndpointBucket -TemplateName '' -Family '' -PolicyName $tplName

                if (-not $bucket) { continue }  # not an endpoint security intent we track

                $entry = @{
                    Id                  = (Get-TPObjectField -Item $i -Key 'id' -Default $null)
                    DisplayName         = $tplName
                    Description         = [string](Get-TPObjectField -Item $i -Key 'description' -Default '')
                    TemplateId          = [string](Get-TPObjectField -Item $i -Key 'templateId' -Default '')
                    IsAssigned          = Get-TPObjectField -Item $i -Key 'isAssigned' -Default $null
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
            if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                Register-TPException -Source 'Intune-EndpointSecurity-Intents' -Message $_.Exception.Message
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
        if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
            Register-TPException -Source 'Intune-EndpointSecurity-Collector' -Message $_.Exception.Message
        }
    }

    Set-TPRawData -Key 'Intune-EndpointSecurity' -Data $result
    # v4.6.4 EMERGENCY FIX (Critical #3): added missing Register-TPCoverage call
    # per CLAUDE.md collector contract.
    if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
        $status = if ($result.Success) { 'Collected' } else { 'Failed' }
        $note   = "LAPS=$($result.Data.LAPSPolicies.Count) ASR=$($result.Data.ASRPolicies.Count) FW=$($result.Data.FirewallPolicies.Count) EDR=$($result.Data.EndpointDetectionPolicies.Count) AV=$($result.Data.AntivirusPolicies.Count)"
        Register-TPCoverage -Family 'Intune-EndpointSecurity' -Status $status -Note $note
    }
}
