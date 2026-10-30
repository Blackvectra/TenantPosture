#Requires -Version 7.0
#
# Invoke-TPCollectAADSignInEvidence.ps1
# Dependencies: Invoke-TPGraphRequest, Get-TPNestedProperty, Get-TPObjectField,
#               Set-TPRawData, Register-TPException, Register-TPCoverage
# TenantPosture
# Author: Matthew Levorson
#
# Sets:     AAD-SignInEvidence (Data.SectionStatus, Data.Sections, Data.Available)
# Consumes: nothing
# Scopes:   AuditLog.Read.All (already requested; no re-consent). The signed-in
#           account needs a role that reads sign-in logs (Global Reader,
#           Reports Reader, Security Reader), and Microsoft requires Entra ID
#           P1 or P2 to read sign-in logs through Graph.
#
# WHY THIS EXISTS
# ---------------
# The configuration controls say a block or an MFA requirement is in place.
# They cannot say whether it held. The sign-in log can: a successful sign-in
# through a legacy client while legacy authentication is supposed to be
# blocked, or a successful interactive sign-in that needed only one factor
# while MFA is supposed to be required, is the protection not doing its job
# for that account. This collector reads those two sets of events so the
# baseline's effectiveness column can say Effective or Ineffective instead of
# Unknown. It changes no finding and moves no score.
#
# WHAT IT READS (beta, on purpose)
# --------------------------------
# - Legacy clients: successful sign-ins whose clientAppUsed is one of the
#   legacy authentication clients Microsoft lists for the sign-in log filter
#   (howto-customize-filter-logs, "Legacy authentication client details"),
#   interactive AND non-interactive, because Microsoft's own procedure for
#   finding legacy authentication checks both logs. v1.0 returns interactive
#   sign-ins only, so this read uses beta's signInEventTypes filter.
# - Single-factor: successful interactive sign-ins whose authenticationRequirement
#   is singleFactorAuthentication. v1.0 does not carry that property.
# Every filter runs on the server ($filter on createdDateTime, status/errorCode,
# clientAppUsed and authenticationRequirement, each documented as filterable),
# so a tenant with no bypasses answers with a few empty pages.
#
# EMPTY IS NOT CLEAN
# ------------------
# Each read publishes SectionStatus, and a read that stopped at its page cap
# is marked Truncated: events found in it still prove a bypass, but an empty
# or partial read never proves there was none. Without Entra ID P1 or P2 the
# log cannot be read at all, which is recorded as PremiumLicenseRequired.
# Only the fields the judgment needs are kept: no IP address, location or
# device detail reaches the results file.

$script:TPSignInEvidenceWindowDays = 30

# Microsoft's legacy authentication clients, as the sign-in log names them.
$script:TPLegacyClientApps = @(
    'Authenticated SMTP', 'Autodiscover', 'Exchange ActiveSync', 'Exchange Online PowerShell',
    'Exchange Web Services', 'IMAP4', 'MAPI over HTTP', 'Offline Address Book',
    'Outlook Anywhere (RPC over HTTP)', 'Outlook Service', 'POP3', 'Reporting Web Services',
    'Other clients'
)

function ConvertTo-TPSignInEvidenceEvent {
    # Keeps only what the judgment needs from one signIn object.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowNull()] [object] $SignIn)
    if ($null -eq $SignIn) { return $null }
    [ordered]@{
        Id                  = [string](Get-TPNestedProperty -Object $SignIn -Path 'id' -Default '')
        CreatedDateTime     = [string](Get-TPNestedProperty -Object $SignIn -Path 'createdDateTime' -Default '')
        UserId              = ([string](Get-TPNestedProperty -Object $SignIn -Path 'userId' -Default '')).ToLowerInvariant()
        UserPrincipalName   = [string](Get-TPNestedProperty -Object $SignIn -Path 'userPrincipalName' -Default '')
        UserType            = [string](Get-TPNestedProperty -Object $SignIn -Path 'userType' -Default '')
        AppDisplayName      = [string](Get-TPNestedProperty -Object $SignIn -Path 'appDisplayName' -Default '')
        ResourceId          = ([string](Get-TPNestedProperty -Object $SignIn -Path 'resourceId' -Default '')).ToLowerInvariant()
        ResourceDisplayName = [string](Get-TPNestedProperty -Object $SignIn -Path 'resourceDisplayName' -Default '')
        ClientAppUsed       = [string](Get-TPNestedProperty -Object $SignIn -Path 'clientAppUsed' -Default '')
        IsInteractive       = Get-TPNestedProperty -Object $SignIn -Path 'isInteractive' -Default $null
        ErrorCode           = Get-TPNestedProperty -Object $SignIn -Path 'status.errorCode' -Default $null
        # The authentication steps, so an earlier MFA claim can be told from a
        # single-factor sign-in: Microsoft documents that authenticationRequirement
        # alone reads single-factor when a previous MFA claim was accepted.
        # $null means the property was not returned; @() means none were listed.
        AuthDetails         = ConvertTo-TPSignInAuthDetails -SignIn $SignIn
    }
}

function ConvertTo-TPSignInAuthDetails {
    # Method, step, success and result detail of each authentication step.
    [CmdletBinding()]
    param([Parameter(Mandatory)] [AllowNull()] [object] $SignIn)
    $raw = Get-TPObjectField -Item $SignIn -Key 'authenticationDetails' -Default $null
    if ($null -eq $raw) {
        $present = ($SignIn -is [System.Collections.IDictionary] -and $SignIn.Contains('authenticationDetails')) -or
                   ($SignIn -isnot [System.Collections.IDictionary] -and $null -ne $SignIn.PSObject.Properties['authenticationDetails'])
        if ($present) { return ,@() }
        return $null
    }
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($d in @($raw)) {
        if ($null -eq $d) { continue }
        $rows.Add([ordered]@{
            Method    = [string](Get-TPObjectField -Item $d -Key 'authenticationMethod' -Default '')
            Step      = [string](Get-TPObjectField -Item $d -Key 'authenticationStepRequirement' -Default '')
            Succeeded = Get-TPObjectField -Item $d -Key 'succeeded' -Default $null
            Result    = [string](Get-TPObjectField -Item $d -Key 'authenticationStepResultDetail' -Default '')
        })
    }
    return ,$rows.ToArray()
}

function Read-TPSignInEvidencePages {
    # Pages one filtered read up to a cap. Returns the events kept, whether
    # pages remained, and the error of a request that failed: events read
    # before a failure are kept, because a bypass already found stays proven,
    # and the caller fails the section so the list is never reported whole.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $Uri,
        [ValidateRange(1, 100)] [int] $MaxPages = 5,
        # The collector's time budget: no page is requested after it. A page
        # already requested is not interrupted (Graph gives no way to).
        [datetime] $Deadline = [datetime]::MaxValue
    )
    $events = [System.Collections.Generic.List[object]]::new()
    $next = $Uri; $pages = 0
    $err = ''; $budget = $false
    try {
        while ($next -and $pages -lt $MaxPages) {
            if ([datetime]::UtcNow -ge $Deadline) {
                $budget = $true
                $err = 'The collector''s time budget was reached before this read finished.'
                break
            }
            $resp = Invoke-TPGraphRequest -Method GET -Uri $next -ErrorAction Stop
            $raw = $null
            if ($resp -is [System.Collections.IDictionary]) {
                if ($resp.Contains('value')) { $raw = $resp['value'] }
            } elseif ($null -ne $resp -and $null -ne $resp.PSObject.Properties['value']) {
                $raw = $resp.PSObject.Properties['value'].Value
            }
            if ($null -eq $raw) { throw "Graph returned no 'value' collection for the sign-in read." }
            foreach ($s in @($raw)) {
                $e = ConvertTo-TPSignInEvidenceEvent -SignIn $s
                if ($null -ne $e) { $events.Add($e) }
            }
            # Flat key lookup: Get-TPNestedProperty would split '@odata.nextLink'.
            $next = [string](Get-TPObjectField -Item $resp -Key '@odata.nextLink' -Default '')
            $pages++
        }
    } catch {
        $err = $_.Exception.Message
        if (-not $err) { $err = 'The sign-in read failed.' }
    }
    [ordered]@{ Events = $events.ToArray(); Truncated = [bool]$next; Pages = $pages; Error = $err; BudgetReached = $budget }
}

function Test-TPSignInPremiumError {
    # The refusal Graph gives a tenant without Entra ID P1 or P2.
    [CmdletBinding()]
    [OutputType([bool])]
    param([AllowNull()] [AllowEmptyString()] [string] $Message)
    return [bool]($Message -match 'RequestFromNonPremiumTenant|premium license|Authentication_RequestFromNonPremiumTenantOrB2CTenant')
}

function Invoke-TPCollectAADSignInEvidence {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 30)] [int] $WindowDays = $script:TPSignInEvidenceWindowDays,
        [ValidateRange(1, 100)] [int] $MaxPages = 5,
        [datetime] $Now = [datetime]::UtcNow,
        # The whole collector's time budget. Each of the 27 reads is a
        # server-side filter over 30 days of the beta sign-in log, and on a
        # busy tenant they can run for many minutes; when the budget runs out
        # the reads not yet made are skipped and their sections are Failed
        # with the reason, so effectiveness reads Unknown, never Effective.
        [ValidateRange(1, 7200)] [int] $TimeBudgetSeconds = 600,
        # Called with one short line after each read, so the console can show
        # the collector moving. Collectors never write to the host themselves.
        [AllowNull()] [scriptblock] $Progress
    )
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $deadline = [datetime]::UtcNow.AddSeconds($TimeBudgetSeconds)
    $say = { param([string] $m) if ($null -ne $Progress) { try { & $Progress $m } catch { Write-Verbose "Progress callback failed: $($_.Exception.Message)" } } }
    $totalReads = 1 + (2 * @($script:TPLegacyClientApps).Count)
    $readsDone = 0; $readsSkipped = 0; $budgetReached = $false

    $end   = $Now.ToUniversalTime()
    $start = $end.AddDays(-$WindowDays)
    $since = $start.ToString('yyyy-MM-ddTHH:mm:ssZ', [cultureinfo]::InvariantCulture)

    $result = [ordered]@{
        CollectorId = 'AAD-SignInEvidence'
        CollectedAt = $end.ToString('o')
        Success     = $false
        Data        = [ordered]@{
            Endpoint          = 'beta'
            WindowDays        = $WindowDays
            WindowStart       = $start.ToString('o')
            WindowEnd         = $end.ToString('o')
            MaxPagesPerRead   = $MaxPages
            # False when the log cannot be read at all (licensing, role).
            Available         = $true
            UnavailableReason = ''
            SectionStatus     = [ordered]@{ LegacyAuth = 'NotRun'; SingleFactor = 'NotRun' }
            Sections          = [ordered]@{
                LegacyAuth   = [ordered]@{ ClientApps = @($script:TPLegacyClientApps); Truncated = $false; Events = @() }
                SingleFactor = [ordered]@{ Truncated = $false; Events = @() }
            }
            Errors            = @()
            TimeBudget        = [ordered]@{ Seconds = $TimeBudgetSeconds; Reached = $false; ReadsTotal = $totalReads; ReadsSkipped = 0; ElapsedSeconds = 0 }
        }
    }
    $base = 'https://graph.microsoft.com/beta/auditLogs/signIns?$top=1000&$filter='
    $note = { param([string] $m) $result.Data.Errors += $m; if (Get-Command Register-TPException -ErrorAction SilentlyContinue) { Register-TPException -Source 'AAD-SignInEvidence' -Message $m } }

    try {
        # ── Single-factor interactive successes (read first: a licensing
        #    refusal here is the same answer for both reads) ──────────────
        $f = "createdDateTime ge $since and status/errorCode eq 0 and authenticationRequirement eq 'singleFactorAuthentication'"
        $r = Read-TPSignInEvidencePages -Uri ($base + [uri]::EscapeDataString($f)) -MaxPages $MaxPages -Deadline $deadline
        $readsDone++
        if ($r.BudgetReached) { $budgetReached = $true }
        & $say ("single-factor sign-ins: {0} event(s) ({1}/{2})" -f @($r.Events).Count, $readsDone, $totalReads)
        $result.Data.Sections.SingleFactor.Events    = @($r.Events)
        $result.Data.Sections.SingleFactor.Truncated = [bool]$r.Truncated
        if (-not $r.Error) {
            $result.Data.SectionStatus.SingleFactor = 'Collected'
        } else {
            $why = $r.Error
            $result.Data.SectionStatus.SingleFactor = 'Failed'
            if (Test-TPSignInPremiumError -Message $why) {
                $result.Data.Available = $false
                $result.Data.UnavailableReason = 'PremiumLicenseRequired'
            } elseif ($why -match 'Authorization_RequestDenied|Forbidden|\b403\b') {
                # The account holds no role that reads sign-in logs; the
                # legacy read would be refused the same way 26 more times.
                $result.Data.Available = $false
                $result.Data.UnavailableReason = 'AccessDenied'
            }
            & $note "SingleFactor: $why"
        }

        # ── Legacy-client successes, interactive and non-interactive ───────
        if ($result.Data.Available) {
            $legacy = [System.Collections.Generic.List[object]]::new()
            $truncated = $false; $failed = $false
            foreach ($app in $script:TPLegacyClientApps) {
                $q = $app.Replace("'", "''")
                foreach ($kind in @('', " and signInEventTypes/any(t: t eq 'nonInteractiveUser')")) {
                    if ($budgetReached -or [datetime]::UtcNow -ge $deadline) {
                        # Out of time: this read is not made. The section is
                        # Failed below, so nothing reads the gap as clean.
                        $budgetReached = $true; $readsSkipped++; $failed = $true
                        continue
                    }
                    $f = "createdDateTime ge $since and status/errorCode eq 0 and clientAppUsed eq '$q'$kind"
                    $r = Read-TPSignInEvidencePages -Uri ($base + [uri]::EscapeDataString($f)) -MaxPages $MaxPages -Deadline $deadline
                    $readsDone++
                    if ($r.BudgetReached) { $budgetReached = $true }
                    & $say ("legacy {0}{1}: {2} event(s) ({3}/{4})" -f $app, $(if ($kind) { ', non-interactive' } else { '' }), @($r.Events).Count, $readsDone, $totalReads)
                    foreach ($e in @($r.Events)) { $legacy.Add($e) }
                    if ($r.Truncated) { $truncated = $true }
                    if ($r.Error) {
                        $failed = $true
                        & $note "LegacyAuth ($app$(if ($kind) { ', non-interactive' })): $($r.Error)"
                    }
                }
            }
            if ($readsSkipped -gt 0) { & $note "LegacyAuth: $readsSkipped of $($totalReads - 1) read(s) not made: the collector's $([math]::Round($TimeBudgetSeconds / 60, 1))-minute time budget was reached." }
            $result.Data.Sections.LegacyAuth.Events    = $legacy.ToArray()
            $result.Data.Sections.LegacyAuth.Truncated = $truncated
            $result.Data.SectionStatus.LegacyAuth = if ($failed) { 'Failed' } else { 'Collected' }
        } else {
            $result.Data.SectionStatus.LegacyAuth = 'Failed'
        }
        $result.Success = $true
    } catch {
        & $note "Sign-in evidence collection failed: $($_.Exception.Message)"
    }
    $clock.Stop()
    $result.Data.TimeBudget.Reached        = $budgetReached
    $result.Data.TimeBudget.ReadsSkipped   = $readsSkipped
    $result.Data.TimeBudget.ElapsedSeconds = [math]::Round($clock.Elapsed.TotalSeconds, 1)

    if (Get-Command Set-TPRawData -ErrorAction SilentlyContinue) {
        Set-TPRawData -Key 'AAD-SignInEvidence' -Data $result
    }
    if (Get-Command Register-TPCoverage -ErrorAction SilentlyContinue) {
        $statuses = @($result.Data.SectionStatus.Values)
        $status = if (-not $result.Success) { 'Failed' }
                  elseif (-not $result.Data.Available) { 'NotCollected' }
                  elseif ($statuses -contains 'Failed') { if ($statuses -contains 'Collected') { 'Partial' } else { 'Failed' } }
                  else { 'Collected' }
        $covNote = if (-not $result.Data.Available) { 'Sign-in logs need Microsoft Entra ID P1 or P2 to read through Graph' }
                   elseif ($result.Data.TimeBudget.Reached) { "$($result.Data.WindowDays)-day window; stopped at the $([math]::Round($TimeBudgetSeconds / 60, 1))-minute time budget ($($result.Data.TimeBudget.ReadsSkipped) read(s) not made); legacy $($result.Data.SectionStatus.LegacyAuth), single-factor $($result.Data.SectionStatus.SingleFactor)" }
                   else { "$($result.Data.WindowDays)-day window; legacy $($result.Data.SectionStatus.LegacyAuth), single-factor $($result.Data.SectionStatus.SingleFactor)" }
        Register-TPCoverage -Family 'AAD-SignInEvidence' -Status $status -Note $covNote
    }
    return $result
}
