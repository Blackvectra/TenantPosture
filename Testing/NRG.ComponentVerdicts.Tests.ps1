#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.ComponentVerdicts.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: The seven baseline controls that used to report Satisfied while part of
             their expected state was not proved (AAD-6.2, AAD-2.1, DEF-2.2, DEF-2.3,
             DNS-1.3, EXO-1.5, INT-1.5) now judge every component. Pinned per control:
             a genuine full pass is Satisfied; an established shortfall is Partial or
             Gap even when another component is unknown; an unread component or an
             unapproved NRG standard is not assessed with the verified parts kept in
             the Detail; empty collected lists are not clean; and the approved lists
             (Config/nrg-standards.json) ship empty, never invented.
    Data keys consumed: none. Graph scopes / cmdlets: none.
#>

Describe 'Baseline controls judge every component of the expected state' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Raw = { param([string] $Id, $Data) @{ CollectorId = $Id; CollectedAt = (Get-Date).ToString('o'); Success = $true; Data = $Data } }
        $script:Verdict = { param([string] $Fn, [string] $Cid) & $Fn | Out-Null; @(Get-NRGFindings | Where-Object { $_.ControlId -eq $Cid })[0] }
        # Approved NRG standards for one test: replaces the file read inside the module.
        $script:Approve = { param([hashtable] $Lists)
            $std = [ordered]@{ DmarcReportingAddresses = @(); CommonAttachmentFileTypes = @(); PriorityUsers = @(); RequiredConditionalAccessTemplates = @() }
            foreach ($k in $Lists.Keys) { $std[$k] = @($Lists[$k]) }
            $script:Std = $std
            Mock -ModuleName NRG-Assessment Get-NRGStandards { $script:Std }.GetNewClosure() }
    }
    AfterAll { Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }
    BeforeEach { Clear-NRGState }

    Context 'The approved standards ship empty' {
        It 'every list in Config/nrg-standards.json is empty, and the loader returns all four' {
            $s = Get-NRGStandards -Path (Join-Path $script:Root 'Config' 'nrg-standards.json')
            foreach ($k in 'DmarcReportingAddresses', 'CommonAttachmentFileTypes', 'PriorityUsers', 'RequiredConditionalAccessTemplates') {
                $s.Contains($k) | Should -BeTrue
                @($s[$k]).Count | Should -Be 0
            }
        }
        It 'a missing or unreadable file means not approved, never met' {
            $s = Get-NRGStandards -Path (Join-Path $TestDrive 'nope.json')
            @($s.DmarcReportingAddresses).Count | Should -Be 0
            Set-Content -LiteralPath (Join-Path $TestDrive 'bad.json') -Value '{ not json'
            @((Get-NRGStandards -Path (Join-Path $TestDrive 'bad.json')).PriorityUsers).Count | Should -Be 0
        }
        It 'reads approved values and trims them' {
            Set-Content -LiteralPath (Join-Path $TestDrive 's.json') -Value '{"PriorityUsers":{"Values":[" ceo@corp.example ",""]}}'
            @((Get-NRGStandards -Path (Join-Path $TestDrive 's.json')).PriorityUsers) | Should -Be @('ceo@corp.example')
        }
    }

    Context 'AAD-6.2 user consent and AAD-6.3 admin consent workflow are two independent verdicts' {
        BeforeAll {
            $script:Gov = { param($Policies, $Workflow, $Status = @{ ExternalCollab = 'Collected'; ConsentPolicy = 'Collected' })
                $cp = if ($null -eq $Workflow) { $null } else { @{ IsEnabled = $Workflow } }
                & $script:Raw 'AAD-IdentityGovernance' @{ SectionStatus = $Status; ExternalCollab = @{ PermissionGrantPolicies = $Policies }; ConsentPolicy = $cp } }
            $script:V62 = { & $script:Verdict 'Test-NRGControlAADUserConsent' 'AAD-6.2' }
            $script:V63 = { & $script:Verdict 'Test-NRGControlAADAdminConsentWorkflow' 'AAD-6.3' }
            $script:Legacy = 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'
        }
        # The matrix: one disabled workflow is ONE baseline failure (AAD-6.3), never two.
        It 'consent restricted, workflow disabled: AAD-6.2 Satisfied, AAD-6.3 Gap' {
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (& $script:Gov @() $false)
            $a = & $script:V62; $b = & $script:V63
            $a.State | Should -Be 'Satisfied'; $b.State | Should -Be 'Gap'
            $a.Detail | Should -Match 'Verified: Users cannot consent'
        }
        It 'consent unrestricted, workflow enabled: AAD-6.2 Gap, AAD-6.3 Satisfied' {
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (& $script:Gov @($script:Legacy) $true)
            (& $script:V62).State | Should -Be 'Gap'; (& $script:V63).State | Should -Be 'Satisfied'
        }
        It 'both configured: Satisfied and Satisfied' {
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (& $script:Gov @() $true)
            (& $script:V62).State | Should -Be 'Satisfied'; (& $script:V63).State | Should -Be 'Satisfied'
        }
        It 'neither configured: Gap and Gap (two different requirements)' {
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (& $script:Gov @($script:Legacy) $false)
            (& $script:V62).State | Should -Be 'Gap'; (& $script:V63).State | Should -Be 'Gap'
        }
        It 'consent setting not returned, workflow enabled: AAD-6.2 not assessed, AAD-6.3 Satisfied' {
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (& $script:Gov $null $true)
            (& $script:V62).State | Should -Be 'NotApplicable'; (& $script:V63).State | Should -Be 'Satisfied'
        }
        It 'the workflow shows in the AAD-6.2 Detail as related context, never as a Shortfall or a Verified component' {
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (& $script:Gov @() $false)
            $d = (& $script:V62).Detail
            $d | Should -Match 'Related \(judged under another control, not part of this verdict\): the admin consent workflow is disabled'
            $d | Should -Not -Match 'Shortfall:'
        }
        It 'the workflow read failing does not change AAD-6.2: restricted consent is still Satisfied, with no workflow claim' {
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (& $script:Gov @() $null @{ ExternalCollab = 'Collected'; ConsentPolicy = 'Failed' })
            $a = & $script:V62; $a.State | Should -Be 'Satisfied'; $a.Detail | Should -Not -Match 'workflow'
            (& $script:V63).State | Should -Be 'NotApplicable'
        }
        It 'a custom grant policy cannot be judged: AAD-6.2 not assessed whatever the workflow does' {
            Set-NRGRawData -Key 'AAD-IdentityGovernance' -Data (& $script:Gov @('ManagePermissionGrantsForSelf.nrg-custom') $false)
            $v = & $script:V62; $v.State | Should -Be 'NotApplicable'; $v.Detail | Should -Match 'custom permission grant policy'
        }
    }

    Context 'DEF-2.2 zero-hour auto purge for spam, phishing AND malware' {
        BeforeAll {
            $script:Exo22 = { param($Spam) & $script:Raw 'EXO-MailboxConfig' @{ SectionStatus = @{ AntiSpamPolicies = 'Collected' }; AntiSpamPolicies = @($Spam); AntiSpamRules = @() } }
            $script:Def22 = { param($Mf) & $script:Raw 'Defender-Policies' @{ MalwareFilter = $Mf } }
            $script:SpamOn  = @{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $true; PhishZapEnabled = $true }
            $script:MfOn    = @{ Available = $true; Rules = @(); Policies = @(@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $true }) }
            $script:V22 = { & $script:Verdict 'Test-NRGControlDefenderZAP' 'DEF-2.2' }
        }
        It 'all three on: Satisfied' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (& $script:Exo22 $script:SpamOn); Set-NRGRawData -Key 'Defender-Policies' -Data (& $script:Def22 $script:MfOn)
            (& $script:V22).State | Should -Be 'Satisfied'
        }
        It 'malware ZAP off is a Partial shortfall although spam and phishing are on' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (& $script:Exo22 $script:SpamOn)
            Set-NRGRawData -Key 'Defender-Policies' -Data (& $script:Def22 @{ Available = $true; Rules = @(); Policies = @(@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $false }) })
            $v = & $script:V22; $v.State | Should -Be 'Partial'; $v.Detail | Should -Match 'Malware ZAP is off'
        }
        It 'spam ZAP off is a shortfall even when malware ZAP could not be read' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (& $script:Exo22 @{ Name = 'Default'; IsDefault = $true; SpamZapEnabled = $false; PhishZapEnabled = $true })
            Set-NRGRawData -Key 'Defender-Policies' -Data (& $script:Def22 @{ Available = $false })
            $v = & $script:V22; $v.State | Should -Be 'Gap'; $v.Detail | Should -Match 'Not assessed: malware ZAP'
        }
        It 'malware policies not read: spam/phish kept, malware ZAP not assessed (never Satisfied)' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (& $script:Exo22 $script:SpamOn); Set-NRGRawData -Key 'Defender-Policies' -Data (& $script:Def22 @{ Available = $false })
            $v = & $script:V22; $v.State | Should -Be 'NotApplicable'; $v.Detail | Should -Match 'Verified: Spam and phishing ZAP'
        }
        It 'results from before ZapEnabled was collected: malware ZAP is not assessed, not assumed on' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (& $script:Exo22 $script:SpamOn)
            Set-NRGRawData -Key 'Defender-Policies' -Data (& $script:Def22 @{ Available = $true; Rules = @(); Policies = @(@{ Name = 'Default'; IsDefault = $true }) })
            (& $script:V22).State | Should -Be 'NotApplicable'
        }
        It 'a custom malware policy with ZAP off that applies to nobody does not count' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (& $script:Exo22 $script:SpamOn)
            Set-NRGRawData -Key 'Defender-Policies' -Data (& $script:Def22 @{ Available = $true; Rules = @(); Policies = @(@{ Name = 'Default'; IsDefault = $true; ZapEnabled = $true }, @{ Name = 'Orphan'; IsDefault = $false; ZapEnabled = $false }) })
            (& $script:V22).State | Should -Be 'Satisfied'
        }
    }

    Context 'DEF-2.3 common attachments filter and the approved blocked-type list' {
        BeforeAll {
            $script:Def23 = { param($Policies) & $script:Raw 'Defender-Policies' @{ MalwareFilter = @{ Available = $true; Rules = @(); Policies = @($Policies); FileFilterEnabledCount = @($Policies | Where-Object { $_.EnableFileFilter }).Count } } }
            $script:V23 = { & $script:Verdict 'Test-NRGControlDefenderCommonAttachments' 'DEF-2.3' }
        }
        It 'no approved list: filter on is verified, the list is not assessed (never Satisfied)' {
            & $script:Approve @{}
            Set-NRGRawData -Key 'Defender-Policies' -Data (& $script:Def23 @(@{ Name = 'Default'; IsDefault = $true; EnableFileFilter = $true; FileTypes = @('exe') }))
            $v = & $script:V23; $v.State | Should -Be 'NotApplicable'; $v.Detail | Should -Match 'Verified: The common attachments filter is on'; $v.Detail | Should -Match 'Not assessed: whether the filter blocks the NRG'
        }
        It 'approved list fully blocked: Satisfied' {
            & $script:Approve @{ CommonAttachmentFileTypes = @('exe', '.js') }
            Set-NRGRawData -Key 'Defender-Policies' -Data (& $script:Def23 @(@{ Name = 'Default'; IsDefault = $true; EnableFileFilter = $true; FileTypes = @('exe', 'js', 'vbs') }))
            (& $script:V23).State | Should -Be 'Satisfied'
        }
        It 'an approved type missing from the list is a Partial shortfall naming it' {
            & $script:Approve @{ CommonAttachmentFileTypes = @('exe', 'iso') }
            Set-NRGRawData -Key 'Defender-Policies' -Data (& $script:Def23 @(@{ Name = 'Default'; IsDefault = $true; EnableFileFilter = $true; FileTypes = @('exe') }))
            $v = & $script:V23; $v.State | Should -Be 'Partial'; $v.Detail | Should -Match 'iso'
        }
        It 'filter off is a Gap whether or not a list is approved' {
            & $script:Approve @{}
            Set-NRGRawData -Key 'Defender-Policies' -Data (& $script:Def23 @(@{ Name = 'Default'; IsDefault = $true; EnableFileFilter = $false; FileTypes = @() }))
            (& $script:V23).State | Should -Be 'Gap'
        }
        It 'an empty collected FileTypes list does not satisfy an approved list' {
            & $script:Approve @{ CommonAttachmentFileTypes = @('exe') }
            Set-NRGRawData -Key 'Defender-Policies' -Data (& $script:Def23 @(@{ Name = 'Default'; IsDefault = $true; EnableFileFilter = $true; FileTypes = @() }))
            (& $script:V23).State | Should -Be 'Partial'
        }
    }

    Context 'DNS-1.3 DMARC enforcement and the approved reporting address' {
        BeforeAll {
            $script:Dns = { param($Record) & $script:Raw 'DNS-EmailRecords' @{ DomainCount = 1; Domains = @{ 'corp.example' = @{ DMARC = $Record; DMARCPolicy = 'reject'; DMARCPct = 100; DMARCSubPolicy = ''; DMARCRecordCount = 1; LookupStatus = @{} } } } }
            $script:V13 = { & $script:Verdict 'Test-NRGControlDNSDMARC' 'DNS-1.3' }
        }
        It 'parses rua: mailto, several addresses, size suffix, no rua' {
            @(Get-NRGDmarcReportAddresses -Record 'v=DMARC1; p=reject; rua=mailto:A@X.example!10m, mailto:b@y.example; pct=100') | Should -Be @('a@x.example', 'b@y.example')
            @(Get-NRGDmarcReportAddresses -Record 'v=DMARC1; p=reject').Count | Should -Be 0
            @(Get-NRGDmarcReportAddresses -Record $null).Count | Should -Be 0
        }
        It 'an address or an @domain matches' {
            Test-NRGDmarcReportAddress -Wanted 'r@dmarcian.example' -Present @('r@dmarcian.example') | Should -BeTrue
            Test-NRGDmarcReportAddress -Wanted '@dmarcian.example' -Present @('x@dmarcian.example') | Should -BeTrue
        }
        It 'an @domain does not match a longer lookalike domain' {
            Test-NRGDmarcReportAddress -Wanted '@dmarcian.example' -Present @('x@notdmarcian.example') | Should -BeFalse
        }
        It 'no approved address: enforcement verified, reporting address not assessed' {
            & $script:Approve @{}
            Set-NRGRawData -Key 'DNS-EmailRecords' -Data (& $script:Dns 'v=DMARC1; p=reject; rua=mailto:r@dmarcian.example')
            $v = & $script:V13; $v.State | Should -Be 'NotApplicable'; $v.Detail | Should -Match 'Verified: corp.example DMARC p=reject'; $v.Detail | Should -Match 'Not assessed: whether rua names the NRG reporting address'
        }
        It 'approved address present: Satisfied' {
            & $script:Approve @{ DmarcReportingAddresses = @('r@dmarcian.example') }
            Set-NRGRawData -Key 'DNS-EmailRecords' -Data (& $script:Dns 'v=DMARC1; p=reject; rua=mailto:r@dmarcian.example')
            (& $script:V13).State | Should -Be 'Satisfied'
        }
        It 'approved address absent (or no rua at all): Partial shortfall' {
            & $script:Approve @{ DmarcReportingAddresses = @('r@dmarcian.example') }
            Set-NRGRawData -Key 'DNS-EmailRecords' -Data (& $script:Dns 'v=DMARC1; p=reject; rua=mailto:other@corp.example')
            (& $script:V13).State | Should -Be 'Partial'
            Clear-NRGState
            Set-NRGRawData -Key 'DNS-EmailRecords' -Data (& $script:Dns 'v=DMARC1; p=reject')
            $v = & $script:V13; $v.State | Should -Be 'Partial'; $v.Detail | Should -Match 'r@dmarcian.example'
        }
    }

    Context 'EXO-1.5 impersonation protection and the approved priority users' {
        BeforeAll {
            $script:Ap = { param($Users, $UserAction = 'Quarantine', $UserOn = $true) @{ Name = 'Default'; IsDefault = $true
                EnableOrganizationDomainsProtection = $true; TargetedDomainProtectionAction = 'Quarantine'
                EnableMailboxIntelligence = $true; EnableMailboxIntelligenceProtection = $true; MailboxIntelligenceProtectionAction = 'MoveToJmf'
                EnableTargetedUserProtection = $UserOn; TargetedUserProtectionAction = $UserAction; TargetedUsersToProtect = @($Users) } }
            $script:SetAp = { param($Policy) Set-NRGRawData -Key 'Defender-Policies' -Data (& $script:Raw 'Defender-Policies' @{ AntiPhishing = @{ Available = $true; Rules = @(); Policies = @($Policy) } }) }
            $script:V15 = { & $script:Verdict 'Test-NRGControlEXOAntiPhish' 'EXO-1.5' }
        }
        It 'no approved priority users: domain and intelligence protection verified, users not assessed' {
            & $script:Approve @{}
            & $script:SetAp (& $script:Ap @())
            $v = & $script:V15; $v.State | Should -Be 'NotApplicable'; $v.Detail | Should -Match 'Verified: Impersonation of your own'; $v.Detail | Should -Match 'Not assessed: whether the approved priority users'
        }
        It 'every approved user listed with an action: Satisfied' {
            & $script:Approve @{ PriorityUsers = @('ceo@corp.example') }
            & $script:SetAp (& $script:Ap @('Chief Exec;ceo@corp.example'))
            (& $script:V15).State | Should -Be 'Satisfied'
        }
        It 'an approved user missing from the list is a Partial shortfall naming the user' {
            & $script:Approve @{ PriorityUsers = @('ceo@corp.example', 'cfo@corp.example') }
            & $script:SetAp (& $script:Ap @('Chief Exec;ceo@corp.example'))
            $v = & $script:V15; $v.State | Should -Be 'Partial'; $v.Detail | Should -Match 'cfo@corp.example'
        }
        It 'user protection off, or an action of NoAction, is a shortfall even with the user listed' {
            & $script:Approve @{ PriorityUsers = @('ceo@corp.example') }
            & $script:SetAp (& $script:Ap @('Chief Exec;ceo@corp.example') 'Quarantine' $false)
            (& $script:V15).State | Should -Be 'Partial'
            Clear-NRGState
            & $script:SetAp (& $script:Ap @('Chief Exec;ceo@corp.example') 'NoAction' $true)
            (& $script:V15).State | Should -Be 'Partial'
        }
        It 'domain protection off is a shortfall whether or not priority users are approved' {
            & $script:Approve @{}
            $p = & $script:Ap @(); $p.EnableOrganizationDomainsProtection = $false
            & $script:SetAp $p
            (& $script:V15).State | Should -Be 'Gap'
        }
    }

    Context 'INT-1.5 antivirus policy configures Defender Antivirus' {
        BeforeAll {
            $script:AvPol = { param($Status, $Settings) [pscustomobject]@{ DisplayName = 'AV'; TemplateType = 'Antivirus'; IsAssigned = $true; AvSettingsStatus = $Status; AvSettings = $Settings } }
            $script:SetAv = { param($Pols) Set-NRGRawData -Key 'Intune-EndpointSecurity' -Data (& $script:Raw 'Intune-EndpointSecurity' @{ SectionStatus = @{ EndpointSecurityPolicies = 'Collected' }; EndpointSecurityPolicies = @($Pols) }) }
            $script:V15i = { & $script:Verdict 'Test-NRGControlIntune' 'INT-1.5' }
            $script:On = [ordered]@{ RealTimeProtection = 'On'; CloudProtection = 'On'; PuaProtection = 'On' }
        }
        It 'parses the Settings Catalog values and leaves absent settings NotConfigured' {
            $settings = @(
                @{ settingInstance = @{ settingDefinitionId = 'device_vendor_msft_policy_config_defender_allowrealtimemonitoring'; choiceSettingValue = @{ value = 'device_vendor_msft_policy_config_defender_allowrealtimemonitoring_1' } } },
                @{ settingInstance = @{ settingDefinitionId = 'device_vendor_msft_policy_config_defender_puaprotection'; choiceSettingValue = @{ value = 'device_vendor_msft_policy_config_defender_puaprotection_2' } } })
            $r = Get-NRGAvSettings -Settings $settings
            $r.RealTimeProtection | Should -Be 'On'; $r.PuaProtection | Should -Be 'Audit'; $r.CloudProtection | Should -Be 'NotConfigured'
        }
        It 'an unrecognized value is unknown, never On' {
            $r = Get-NRGAvSettings -Settings @(@{ settingDefinitionId = 'device_vendor_msft_policy_config_defender_allowcloudprotection'; choiceSettingValue = @{ value = 'device_vendor_msft_policy_config_defender_allowcloudprotection_9' } })
            $r.CloudProtection | Should -Be 'Unknown:9'
        }
        It 'all three on: Satisfied' {
            & $script:SetAv @((& $script:AvPol 'Read' $script:On))
            (& $script:V15i).State | Should -Be 'Satisfied'
        }
        It 'a policy that turns a setting off is a Partial shortfall' {
            $s = [ordered]@{ RealTimeProtection = 'On'; CloudProtection = 'Off'; PuaProtection = 'On' }
            & $script:SetAv @((& $script:AvPol 'Read' $s))
            $v = & $script:V15i; $v.State | Should -Be 'Partial'; $v.Detail | Should -Match 'Cloud-delivered protection is turned off'
        }
        It 'settings that could not be read: the policy is verified, the settings are not assessed' {
            & $script:SetAv @((& $script:AvPol 'Failed' $null))
            $v = & $script:V15i; $v.State | Should -Be 'NotApplicable'; $v.Detail | Should -Match 'could not be read'
        }
        It 'a setting no policy sets is not assessed, not assumed on' {
            $s = [ordered]@{ RealTimeProtection = 'On'; CloudProtection = 'NotConfigured'; PuaProtection = 'On' }
            & $script:SetAv @((& $script:AvPol 'Read' $s))
            $v = & $script:V15i; $v.State | Should -Be 'NotApplicable'; $v.Detail | Should -Match 'not set by any assigned policy'
        }
        It 'an unassigned policy is still no policy (Gap)' {
            $p = & $script:AvPol 'Read' $script:On; $p.IsAssigned = $false
            & $script:SetAv @($p)
            (& $script:V15i).State | Should -Be 'Gap'
        }
    }

    Context 'AAD-2.1 the approved NRG Conditional Access policy set' {
        BeforeAll {
            $script:Mk = { param($n, $state, $apps, $grant, $exUsers = @(), $appInclude = @('All')) @{ DisplayName = $n; State = $state
                Conditions = @{ ClientAppTypes = $apps; SignInRiskLevels = @(); UserRiskLevels = @(); AuthFlows = @()
                                Users = @{ IncludeUsers = @('All'); IncludeGroups = @(); IncludeRoles = @(); ExcludeUsers = $exUsers; ExcludeGroups = @() }
                                Applications = @{ Include = $appInclude; Exclude = @() }
                                Devices = @{ FilterMode = ''; FilterRule = '' }; ClientApplications = @{ IncludeServicePrincipals = @() } }
                GrantControls = @{ Operator = 'AND'; BuiltInControls = $grant; AuthStrengthId = ''; TermsOfUse = @() }; SessionControls = @{} } }
            $script:SetCa = { param($Pols) Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies' @{ Policies = @($Pols) }) }
            $script:V21 = { Test-NRGControlAADCA; @(Get-NRGFindings | Where-Object { $_.ControlId -eq 'AAD-2.1' })[0] }
            $script:Three = @((& $script:Mk 'legacy' 'enabled' @('other') @('block')), (& $script:Mk 'mfa' 'enabled' @('all') @('mfa')))
        }
        It 'with no approved set, three enforced tracks are verified and the set is not assessed (never Satisfied)' {
            & $script:Approve @{}
            & $script:SetCa $script:Three
            $v = & $script:V21
            $v.State | Should -Be 'NotApplicable'; $v.Detail | Should -Match 'Verified: 2 enabled CA policies cover'; $v.Detail | Should -Match 'Not assessed: whether the NRG baseline policy set'
        }
        It 'every approved template enforced: Satisfied' {
            & $script:Approve @{ RequiredConditionalAccessTemplates = @('block-legacy-auth', 'mfa-all-users') }
            & $script:SetCa $script:Three
            $v = & $script:V21
            $v.State | Should -Be 'Satisfied'; $v.Detail | Should -Match 'Required NRG policies enforced: block-legacy-auth, mfa-all-users'
        }
        It 'an approved template with no policy is a shortfall even though the three tracks pass' {
            & $script:Approve @{ RequiredConditionalAccessTemplates = @('block-legacy-auth', 'block-device-code') }
            & $script:SetCa $script:Three
            $v = & $script:V21
            $v.State | Should -Be 'Partial'; $v.Detail | Should -Match 'block-device-code'
        }
        It 'a report-only policy does not count as the approved template' {
            & $script:Approve @{ RequiredConditionalAccessTemplates = @('block-device-code') }
            $pols = @($script:Three) + @(& $script:Mk 'devcode' 'enabledForReportingButNotEnforced' @('all') @('block'))
            & $script:SetCa $pols
            (& $script:V21).State | Should -Be 'Partial'
        }
        It 'an unknown template id is not assessed, never satisfied' {
            & $script:Approve @{ RequiredConditionalAccessTemplates = @('no-such-template') }
            & $script:SetCa $script:Three
            (& $script:V21).State | Should -Be 'NotApplicable'
        }
        It 'a policy scoped to one application is not the approved all-apps template' {
            & $script:Approve @{ RequiredConditionalAccessTemplates = @('mfa-all-users') }
            $pols = @((& $script:Mk 'legacy' 'enabled' @('other') @('block')), (& $script:Mk 'mfa' 'enabled' @('all') @('mfa') @() @('one-app-id')))
            & $script:SetCa $pols
            (& $script:V21).State | Should -Not -Be 'Satisfied'
        }
    }

    Context 'A missing NRG standard is its own kind of unknown, not a collection fault' {
        BeforeAll {
            $script:MfUnapproved = { & $script:Approve @{}
                Set-NRGRawData -Key 'Defender-Policies' -Data (& $script:Raw 'Defender-Policies' @{ MalwareFilter = @{ Available = $true; Rules = @(); FileFilterEnabledCount = 1; Policies = @(@{ Name = 'Default'; IsDefault = $true; EnableFileFilter = $true; FileTypes = @('exe') }) } })
                Test-NRGControlDefenderCommonAttachments }
        }
        It 'the scope files it under StandardNotApproved, never "data did not collect"' {
            & $script:MfUnapproved
            $scope = Get-NRGAssessmentScope -Findings @(Get-NRGFindings) -Coverage @{} -RawData @{ 'Defender-Policies' = (& $script:Raw 'Defender-Policies' @{}) }
            @($scope.StandardNotApproved | ForEach-Object ControlId) | Should -Contain 'DEF-2.3'
            @($scope.CollectionIncomplete | ForEach-Object ControlId) | Should -Not -Contain 'DEF-2.3'
            ($scope.Limitations -join ' ') | Should -Match 'NRG standard'
        }
        It 'the buckets still sum to the unscored count with no control in two of them' {
            & $script:MfUnapproved
            $scope = Get-NRGAssessmentScope -Findings @(Get-NRGFindings) -Coverage @{} -RawData @{}
            $ids = @(foreach ($b in 'LicenceBlocked', 'CollectionIncomplete', 'StandardNotApproved', 'NoProgrammaticCheck', 'ThirdPartyAttested', 'NotApplicableToTenant', 'NotEvaluatedThisMode', 'SkippedByOperator', 'NoResult', 'Errors') { $scope.$b | ForEach-Object ControlId })
            @($ids | Select-Object -Unique).Count | Should -Be $ids.Count
        }
        It 'a collector that failed is still named as the cause, not the missing standard' {
            & $script:MfUnapproved
            $scope = Get-NRGAssessmentScope -Findings @(Get-NRGFindings) -Coverage @{} -RawData @{ 'Defender-Policies' = @{ CollectorId = 'Defender-Policies'; Success = $false; Data = @{} } }
            @($scope.CollectionIncomplete | ForEach-Object ControlId) | Should -Contain 'DEF-2.3'
        }
        It 'the baseline reason code says the standard is not approved' {
            & $script:MfUnapproved
            $c = Get-NRGBaselineCompliance -Findings @(Get-NRGFindings) -TargetTier Standard -RawData @{ 'Defender-Policies' = (& $script:Raw 'Defender-Policies' @{}) } -Coverage @{}
            $row = @($c.Controls | Where-Object { $_.ControlId -eq 'DEF-2.3' })[0]
            $row.ReasonCode | Should -Be 'StandardNotApproved'
            $row.Reason | Should -Match 'blocked-file-type list'
        }
    }

    Context 'EXO-1.6 never claims a password is accepted while authentication policies are unread' {
        BeforeAll {
            $script:Exo16 = { param($SmtpDisabled) & $script:Raw 'EXO-MailboxConfig' @{ OrganizationConfig = @{ OAuth2ClientProfileEnabled = $true }
                TransportConfig = @{ SmtpClientAuthenticationDisabled = $SmtpDisabled }
                SmtpAuthConfig = @{ PerMailboxEnabledCount = 0; SampleEnabled = @() }; SectionStatus = @{ SmtpAuthConfig = 'Collected' } } }
            $script:V16 = { & $script:Verdict 'Test-NRGControlEXOModernAuth' 'EXO-1.6' }
            $script:CaNone = { Set-NRGRawData -Key 'AAD-CAPolicies' -Data (& $script:Raw 'AAD-CAPolicies' @{ Policies = @() })
                Set-NRGRawData -Key 'AAD-AuthPolicies' -Data (& $script:Raw 'AAD-AuthPolicies' @{ SecurityDefaults = @{ IsEnabled = $false } }) }
        }
        It 'SMTP AUTH available and no legacy block found: Partial as an exposure, stating acceptance is not established' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (& $script:Exo16 $false); & $script:CaNone
            $v = & $script:V16
            $v.State | Should -Be 'Partial'
            $v.Detail | Should -Match 'Exchange authentication policies'
            $v.Detail | Should -Match 'not a confirmed acceptance'
            $v.Detail | Should -Not -Match 'can still be used|is accepted|are accepted'
            $v.CurrentValue | Should -Match 'authentication policies not read'
        }
        It 'SMTP AUTH closed org-wide with no mailbox override is Satisfied without needing the policies' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (& $script:Exo16 $true)
            (& $script:V16).State | Should -Be 'Satisfied'
        }
        It 'no legacy-auth evidence at all: not assessed, not Partial' {
            Set-NRGRawData -Key 'EXO-MailboxConfig' -Data (& $script:Exo16 $false)
            (& $script:V16).State | Should -Be 'NotApplicable'
        }
    }
}
