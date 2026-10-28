#Requires -Version 7.0
#
# Invoke-TPCollectAADCAWhatIf.ps1
# Dependencies: Invoke-TPCAWhatIfEvaluation, Get-TPRawData, Get-TPObjectField,
#               Set-TPRawData, Register-TPException, Register-TPCoverage
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: Simulate sign-ins with Microsoft's Conditional Access What If
#   evaluation, the way Maester does (MT.1033 "users should be blocked from
#   using legacy authentication", MT.1034 "emergency access users should not
#   be blocked"), and one addition of the tool's own: a browser sign-in that
#   should be asked for MFA.
#
# Sets:     AAD-CAWhatIf (Data.Users, Data.SectionStatus, Data.Available)
# Consumes: AAD-Users (the sample of regular users), AAD-CAPolicies (only to
#           know a policy list was read; the evaluation reads the tenant)
# Graph:    POST /identity/conditionalAccess/evaluate through
#           Invoke-TPCAWhatIfEvaluation (the tool's one POST; see that file),
#           Policy.Read.All, already requested.
#
# WHO IS SIMULATED
# ----------------
# - Regular users: up to -SampleSize enabled member accounts from AAD-Users,
#   sorted by user principal name so two runs pick the same accounts, never an
#   account on the emergency-access record. Maester samples five.
# - Emergency access: the user accounts on the tenant's approved
#   EmergencyAccess record (-EmergencyAccessUserIds). Maester infers them from
#   the policy exclusions when none is configured; the tool simulates only
#   approved accounts and says when there is no record, because an inferred
#   account is a guess.
#
# WHAT IS ASKED (the sign-in Microsoft evaluates)
# -----------------------------------------------
#   LegacyAuth   Exchange ActiveSync to Exchange Online (Maester's MT.1033 and
#                MT.1034 sign-in, unchanged)
#   Mfa          a browser sign-in to Exchange Online (the tool's addition)
# Device, location and risk are not supplied, so a policy that needs one of
# them does not apply in the simulation; the finding says so.

function Invoke-TPCollectAADCAWhatIf {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()] [string[]] $EmergencyAccessUserIds = @(),
        [ValidateRange(1, 25)] [int] $SampleSize = 5
    )

    $exchangeOnline = '00000002-0000-0ff1-ce00-000000000000'
    $scenarios = @(
        [ordered]@{ Name = 'LegacyAuth'; ClientAppType = 'exchangeActiveSync'; ApplicationId = $exchangeOnline }
        [ordered]@{ Name = 'Mfa';        ClientAppType = 'browser';            ApplicationId = $exchangeOnline }
    )
    $guid = '\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z'

    $result = @{
        CollectorId = 'AAD-CAWhatIf'
        CollectedAt = (Get-Date).ToUniversalTime().ToString('o')
        Success     = $false
        Data        = @{
            Available            = $false
            UnavailableReason    = ''
            Scenarios            = @($scenarios | ForEach-Object { [ordered]@{ Name = $_.Name; ClientAppType = $_.ClientAppType; ApplicationId = $_.ApplicationId } })
            SampleSize           = $SampleSize
            EmergencyRecordUsers = @($EmergencyAccessUserIds | Where-Object { [string]$_ -cmatch $guid }).Count
            Users                = @()
            SectionStatus        = @{ Regular = 'NotRun'; Emergency = 'NotRun' }
        }
    }

    $usersRaw = Get-TPRawData -Key 'AAD-Users'
    if ($null -eq $usersRaw -or -not [bool](Get-TPObjectField -Item $usersRaw -Key 'Success' -Default $false)) {
        $result.Data.UnavailableReason = 'UsersNotRead'
    }

    $emergency = @($EmergencyAccessUserIds | ForEach-Object { ([string]$_).ToLowerInvariant() } | Where-Object { $_ -cmatch $guid } | Select-Object -Unique)
    $directory = @{}
    $regular = @()
    if (-not $result.Data.UnavailableReason) {
        $all = @(Get-TPObjectField -Item (Get-TPObjectField -Item $usersRaw -Key 'Data' -Default $null) -Key 'Users' -Default @() | Where-Object { $null -ne $_ })
        foreach ($u in $all) { $directory[([string](Get-TPObjectField -Item $u -Key 'Id' -Default '')).ToLowerInvariant()] = $u }
        $regular = @($all | Where-Object {
                ([string](Get-TPObjectField -Item $_ -Key 'UserType' -Default '')) -eq 'Member' -and
                (Get-TPObjectField -Item $_ -Key 'AccountEnabled' -Default $false) -eq $true -and
                ([string](Get-TPObjectField -Item $_ -Key 'Id' -Default '')).ToLowerInvariant() -cmatch $guid -and
                ([string](Get-TPObjectField -Item $_ -Key 'Id' -Default '')).ToLowerInvariant() -notin $emergency
            } | Sort-Object { [string](Get-TPObjectField -Item $_ -Key 'UserPrincipalName' -Default '') } | Select-Object -First $SampleSize)
    }

    $users = [System.Collections.Generic.List[object]]::new()
    $failed = @{ Regular = 0; Emergency = 0 }
    $asked = @{ Regular = 0; Emergency = 0 }
    $simulate = {
        param([string] $Id, [string] $Upn, [string] $Kind)
        $row = [ordered]@{ UserId = $Id; UserPrincipalName = $Upn; Kind = $Kind; Results = [ordered]@{} }
        foreach ($s in $scenarios) {
            $asked[$Kind]++
            try {
                $applied = @(Invoke-TPCAWhatIfEvaluation -UserId $Id -ApplicationId $s.ApplicationId -ClientAppType $s.ClientAppType)
                $row.Results[$s.Name] = [ordered]@{ Read = $true; Error = ''; Applied = $applied }
            } catch {
                $failed[$Kind]++
                $row.Results[$s.Name] = [ordered]@{ Read = $false; Error = ($_.Exception.Message -split "`n")[0]; Applied = @() }
                if (Get-Command Register-TPException -ErrorAction SilentlyContinue) {
                    Register-TPException -Source 'AAD-CAWhatIf' -Message "$($s.Name): $($_.Exception.Message)"
                }
            }
        }
        $users.Add($row)
    }

    if (-not $result.Data.UnavailableReason) {
        foreach ($u in $regular) {
            & $simulate ([string](Get-TPObjectField -Item $u -Key 'Id' -Default '')).ToLowerInvariant() ([string](Get-TPObjectField -Item $u -Key 'UserPrincipalName' -Default '')) 'Regular'
        }
        $result.Data.SectionStatus.Regular = if ($regular.Count -eq 0) { 'Collected' } elseif ($failed.Regular -eq 0) { 'Collected' } elseif ($failed.Regular -lt $asked.Regular) { 'Partial' } else { 'Failed' }
    }
    if ($emergency.Count -gt 0) {
        foreach ($id in $emergency) {
            $upn = if ($directory.ContainsKey($id)) { [string](Get-TPObjectField -Item $directory[$id] -Key 'UserPrincipalName' -Default '') } else { '' }
            & $simulate $id $upn 'Emergency'
        }
        $result.Data.SectionStatus.Emergency = if ($failed.Emergency -eq 0) { 'Collected' } elseif ($failed.Emergency -lt $asked.Emergency) { 'Partial' } else { 'Failed' }
    }

    $result.Data.Users = $users.ToArray()
    $anyAsked = ($asked.Regular + $asked.Emergency) -gt 0
    $allFailed = $anyAsked -and (($failed.Regular + $failed.Emergency) -eq ($asked.Regular + $asked.Emergency))
    $result.Data.Available = $anyAsked -and -not $allFailed
    if ($allFailed) { $result.Data.UnavailableReason = 'EvaluationFailed' }
    elseif (-not $anyAsked -and -not $result.Data.UnavailableReason) { $result.Data.UnavailableReason = 'NoUsersToSimulate' }
    $result.Success = -not $allFailed -and $result.Data.UnavailableReason -ne 'UsersNotRead'

    if (Get-Command Set-TPRawData -ErrorAction SilentlyContinue) {
        Set-TPRawData -Key 'AAD-CAWhatIf' -Data $result
    }
    if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
        $n = $users.Count
        if ($allFailed) {
            Register-TPCoverage -Family 'AAD-CAWhatIf' -Status 'Failed' -Note 'What If evaluation failed (see Exceptions)'
        } elseif ($result.Data.UnavailableReason -eq 'UsersNotRead') {
            Register-TPCoverage -Family 'AAD-CAWhatIf' -Status 'NotCollected' -Note 'users not read; nothing simulated'
        } elseif (($failed.Regular + $failed.Emergency) -gt 0) {
            Register-TPCoverage -Family 'AAD-CAWhatIf' -Status 'Partial' -Note "$n account(s) simulated, some evaluations failed"
        } else {
            Register-TPCoverage -Family 'AAD-CAWhatIf' -Status 'Collected' -Note "$n account(s) simulated"
        }
    }
    return $result
}
