#Requires -Version 7.0
#
# Test-TPControlDefender.ps1  (v4.5.5)
# Evaluates Defender for Office 365 controls.
# SCORING ONLY — no API calls.
#
# NIST SP 800-53: SI-3, SI-4, SI-8
# MITRE ATT&CK:   T1566, T1204.002
#

# ── Policies in force ────────────────────────────────────────────────────────
# Exchange Online applies, per recipient: a custom policy whose RULE is
# enabled and matches them, else an enabled preset (Standard / Strict, turned
# on by its protection-policy RULE), else the default / Built-in protection
# policy. Evaluating the default policy alone reported its settings for
# recipients a preset or custom policy actually governs, and evaluating "any
# policy" counted a custom policy whose rule is off. This returns the set that
# can actually apply; the default drops out only when an enabled rule provably
# covers every accepted domain with no exceptions.
function Get-TPInForcePolicies {
    [CmdletBinding()]
    param(
        [AllowNull()] [object[]] $Policies,
        [AllowNull()] $Rules,
        [Parameter(Mandatory)] [string] $RulePolicyKey,
        [Parameter(Mandatory)] [ValidateSet('EOP','ATP')] [string] $PresetKind,
        # The tenant's accepted domains, when the caller holds them itself (the -DistributionListsOnly run has no
        # EXO-MailboxConfig). Omitted: read from EXO-MailboxConfig, as before.
        [AllowNull()] [string[]] $AcceptedDomains = $null
    )
    $def = Get-TPRawData -Key 'Defender-Policies'
    $pr  = Get-TPNestedProperty -Object $def -Path 'Data.PresetRules' -Default $null
    $prKnown = [bool](Get-TPObjectField -Item $pr -Key 'Available' -Default $false)
    $presetRules = @(if ($prKnown) { @(Get-TPObjectField -Item $pr -Key $PresetKind -Default @()) })
    $presetOn = @{ Standard = $false; Strict = $false }
    foreach ($r in $presetRules) {
        $n = [string](Get-TPObjectField -Item $r -Key 'Name' -Default '')
        $on = [string](Get-TPObjectField -Item $r -Key 'State' -Default '') -eq 'Enabled'
        if ($n -match 'Strict') { $presetOn.Strict = $presetOn.Strict -or $on } elseif ($n -match 'Standard') { $presetOn.Standard = $presetOn.Standard -or $on }
    }
    $exo = Get-TPRawData -Key 'EXO-MailboxConfig'
    $accepted = @()
    if ($null -ne $AcceptedDomains) {
        $accepted = @($AcceptedDomains | ForEach-Object { ([string]$_).ToLowerInvariant() } | Where-Object { $_ })
    } elseif ($exo -and (Test-TPSectionCollected $exo 'AcceptedDomains')) {
        $accepted = @(@(Get-TPNestedProperty -Object $exo -Path 'Data.AcceptedDomains' -Default @()) | ForEach-Object { ([string](Get-TPObjectField -Item $_ -Key 'DomainName' -Default '')).ToLowerInvariant() } | Where-Object { $_ })
    }
    $coversAll = {
        param($r)
        if ($accepted.Count -eq 0) { return $false }
        if ([string](Get-TPObjectField -Item $r -Key 'State' -Default '') -ne 'Enabled') { return $false }
        if (@(Get-TPObjectField -Item $r -Key 'SentTo' -Default @() | Where-Object { $_ }).Count -gt 0) { return $false }
        if (@(Get-TPObjectField -Item $r -Key 'SentToMemberOf' -Default @() | Where-Object { $_ }).Count -gt 0) { return $false }
        if ((Get-TPObjectField -Item $r -Key 'HasExceptions' -Default $true) -ne $false) { return $false }
        $doms = @(@(Get-TPObjectField -Item $r -Key 'RecipientDomainIs' -Default @()) | ForEach-Object { ([string]$_).ToLowerInvariant() })
        return (@($accepted | Where-Object { $_ -notin $doms }).Count -eq 0)
    }

    $inForce  = [System.Collections.Generic.List[object]]::new()
    $fallback = [System.Collections.Generic.List[object]]::new()
    $everyone = $false
    foreach ($p in @($Policies | Where-Object { $null -ne $_ })) {
        $name = [string](Get-TPObjectField -Item $p -Key 'Name' -Default '')
        $type = [string](Get-TPObjectField -Item $p -Key 'RecommendedPolicyType' -Default '')
        if ((Get-TPObjectField -Item $p -Key 'IsDefault' -Default $false) -eq $true -or
            (Get-TPObjectField -Item $p -Key 'IsBuiltInProtection' -Default $false) -eq $true -or $name -eq 'Built-In Protection Policy') {
            $fallback.Add($p); continue
        }
        $preset = if ($type -in @('Standard','Strict')) { $type } elseif ($name -match '^(Standard|Strict) Preset Security Policy') { $Matches[1] } else { '' }
        if ($preset) {
            if (-not $prKnown -or $presetOn[$preset]) {
                $inForce.Add($p)
                foreach ($r in $presetRules) { if ([string](Get-TPObjectField -Item $r -Key 'Name' -Default '') -match $preset -and (& $coversAll $r)) { $everyone = $true } }
            }
            continue
        }
        if ($null -eq $Rules) { $inForce.Add($p); continue }   # rules not collected: cannot tell, keep it
        $mine = @(@($Rules) | Where-Object { [string](Get-TPObjectField -Item $_ -Key $RulePolicyKey -Default '') -eq $name })
        if (@($mine | Where-Object { [string](Get-TPObjectField -Item $_ -Key 'State' -Default '') -eq 'Enabled' }).Count -gt 0) {
            $inForce.Add($p)
            foreach ($r in $mine) { if (& $coversAll $r) { $everyone = $true } }
        }
    }
    if (-not $everyone) { foreach ($f in $fallback) { $inForce.Add($f) } }
    return @($inForce)
}

# One verdict over the policies in force: Satisfied when every one passes,
# Gap when none does, Partial when some recipients are protected and some
# are not — naming the policies that fall short.
function Add-TPPolicySetFinding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $ControlId, [Parameter(Mandatory)] $Control, [AllowNull()] $FrameworkIds,
        [AllowNull()] [object[]] $Policies, [Parameter(Mandatory)] [scriptblock] $Pass, [Parameter(Mandatory)] [scriptblock] $Value,
        [Parameter(Mandatory)] [string] $PassDetail, [Parameter(Mandatory)] [string] $FailDetail, [Parameter(Mandatory)] [string] $RequiredValue,
        [string] $Empty = 'No policy applies to any recipient; not assessed.'
    )
    $all = @($Policies | Where-Object { $null -ne $_ })
    if ($all.Count -eq 0) {
        Add-TPFinding -ControlId $ControlId -State 'NotApplicable' -Category $Control.Category -Title $Control.Title -FrameworkIds $FrameworkIds -Detail $Empty
        return
    }
    $good = @($all | Where-Object { & $Pass $_ })
    $bad  = @($all | Where-Object { -not (& $Pass $_) })
    $desc = { param($l) (@($l) | ForEach-Object { "$([string](Get-TPObjectField -Item $_ -Key 'Name' -Default '?')) ($(& $Value $_))" }) -join '; ' }
    if ($bad.Count -eq 0) {
        Add-TPFinding -ControlId $ControlId -State 'Satisfied' -Category $Control.Category -Title $Control.Title -Severity 'Informational' -FrameworkIds $FrameworkIds `
            -Detail "$PassDetail Policies in force: $(& $desc $good)." -CurrentValue (& $desc $good) -RequiredValue $RequiredValue
    } elseif ($good.Count -eq 0) {
        Add-TPFinding -ControlId $ControlId -State 'Gap' -Category $Control.Category -Title $Control.Title -Severity $Control.Severity -FrameworkIds $FrameworkIds `
            -Detail "$FailDetail Policies in force: $(& $desc $bad)." -CurrentValue (& $desc $bad) -RequiredValue $RequiredValue -Remediation $Control.Remediation
    } else {
        Add-TPFinding -ControlId $ControlId -State 'Partial' -Category $Control.Category -Title $Control.Title -Severity $Control.Severity -FrameworkIds $FrameworkIds `
            -Detail "Recipients covered by $(& $desc $good) are protected; recipients covered by $(& $desc $bad) are not. $FailDetail" `
            -CurrentValue "Meets: $(& $desc $good) | Falls short: $(& $desc $bad)" -RequiredValue $RequiredValue -Remediation $Control.Remediation
    }
}

# Unavailable Safe Links / Safe Attachments data: an upgrade opportunity only
# when licensing positively says the plan is missing; otherwise the read did
# not complete (never an Error that scores as a failure, never "not licensed"
# when licensing was not read).
function Add-TPDefenderUnavailableFinding {
    [CmdletBinding()]
    param([Parameter(Mandatory)] [string] $ControlId, [Parameter(Mandatory)] $Control, [AllowNull()] $FrameworkIds, [AllowNull()] $Section, [Parameter(Mandatory)] [string] $Feature)
    if ((Get-TPControlLicenseStatus -ControlId $ControlId) -eq 'NotMet') {
        Add-TPFinding -ControlId $ControlId -State 'NotApplicable' -Category $Control.Category -Title $Control.Title -FrameworkIds $FrameworkIds `
            -Detail "$Feature requires Defender for Office 365 Plan 1, which this tenant does not hold. Not scored as a gap — surfaced as a licensing upgrade opportunity." `
            -CurrentValue 'Defender for Office 365 P1 not licensed' -RequiredValue 'Defender for Office 365 Plan 1' -Remediation $Control.Remediation
    } else {
        $why = [string](Get-TPObjectField -Item $Section -Key 'Error' -Default '')
        Add-TPFinding -ControlId $ControlId -State 'NotApplicable' -Category $Control.Category -Title $Control.Title -FrameworkIds $FrameworkIds `
            -Detail "$Feature policies were not collected$(if ($why) { " ($why)" }); not assessed. Re-run once Exchange Online / Defender connectivity is confirmed."
    }
}

function Test-TPControlDefender {
    [CmdletBinding()] param()

    $defData = Get-TPRawData -Key 'Defender-Policies'
    if (-not $defData -or -not $defData.Success) {
        # Register NotApplicable for all Defender controls
        foreach ($cid in @('DEF-1.1','DEF-1.2','DEF-1.3','DEF-1.4','DEF-1.5','DEF-1.6')) {
            $ctrl = Get-TPControlById -ControlId $cid
            if ($ctrl) {
                Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
                    -Title $ctrl.Title -Detail 'Defender policy data not collected'
            }
        }
        return
    }

    $sa = $defData.Data['SafeAttachments']
    $sl = $defData.Data['SafeLinks']
    $ap = $defData.Data['AntiPhishing']
    $saForce = if ($sa -and $sa.Available) { @(Get-TPInForcePolicies -Policies @(Get-TPObjectField -Item $sa -Key 'Policies' -Default @()) -Rules (Get-TPRuleList -Item $sa -Key 'Rules') -RulePolicyKey 'SafeAttachmentPolicy' -PresetKind 'ATP') } else { @() }
    $slForce = if ($sl -and $sl.Available) { @(Get-TPInForcePolicies -Policies @(Get-TPObjectField -Item $sl -Key 'Policies' -Default @()) -Rules (Get-TPRuleList -Item $sl -Key 'Rules') -RulePolicyKey 'SafeLinksPolicy' -PresetKind 'ATP') } else { @() }
    $apForce = if ($ap -and $ap.Available) { @(Get-TPInForcePolicies -Policies @(Get-TPObjectField -Item $ap -Key 'Policies' -Default @()) -Rules (Get-TPRuleList -Item $ap -Key 'Rules') -RulePolicyKey 'AntiPhishPolicy' -PresetKind 'EOP') } else { @() }
    $f = { param($p, $k, $d = $null) Get-TPObjectField -Item $p -Key $k -Default $d }

    # ── DEF-1.1 Safe Attachments with Block ──────────────────────────────
    $ctrl = Get-TPControlById -ControlId 'DEF-1.1'
    if ($ctrl) {
        $cit = Get-TPFrameworkCitations -ControlId 'DEF-1.1'
        if (-not $sa -or -not $sa.Available) { Add-TPDefenderUnavailableFinding -ControlId 'DEF-1.1' -Control $ctrl -FrameworkIds $cit -Section $sa -Feature 'Safe Attachments' }
        else {
            Add-TPPolicySetFinding -ControlId 'DEF-1.1' -Control $ctrl -FrameworkIds $cit -Policies $saForce `
                -Pass { (& $f $_ 'Enable' $false) -eq $true -and [string](& $f $_ 'Action' '') -eq 'Block' } `
                -Value { "Enable=$(& $f $_ 'Enable' '?'), Action=$(& $f $_ 'Action' '?')" } `
                -PassDetail 'Safe Attachments is on with the Block action for every recipient.' `
                -FailDetail 'Malicious attachments are not blocked for these recipients (Safe Attachments off, or an action other than Block).' `
                -RequiredValue "Safe Attachments enabled with Action = 'Block' in every policy in force"
        }
    }

    # ── DEF-1.2 Safe Links enabled and hardened ──────────────────────────
    $ctrl = Get-TPControlById -ControlId 'DEF-1.2'
    if ($ctrl) {
        $cit = Get-TPFrameworkCitations -ControlId 'DEF-1.2'
        if (-not $sl -or -not $sl.Available) { Add-TPDefenderUnavailableFinding -ControlId 'DEF-1.2' -Control $ctrl -FrameworkIds $cit -Section $sl -Feature 'Safe Links' }
        else {
            # Hardened = scans email, click-through blocked, clicks tracked,
            # internal senders covered, URLs rewritten. The Built-in protection
            # policy (AllowClickThrough on, internal senders off, rewrite off)
            # was called hardened because only an 'IsDefault' row was checked
            # and Safe Links policies have none.
            $weak = { param($p) @(
                if ((& $f $p 'EnableSafeLinksForEmail' $false) -ne $true) { 'email scanning off' }
                if ((& $f $p 'AllowClickThrough' $true) -ne $false)       { 'click-through allowed' }
                if ((& $f $p 'TrackClicks' $false) -ne $true)             { 'clicks not tracked' }
                if ((& $f $p 'EnableForInternalSenders' $false) -ne $true) { 'internal senders not covered' }
                if ((& $f $p 'DisableUrlRewrite' $false) -eq $true)       { 'URL rewrite disabled' }) }
            Add-TPPolicySetFinding -ControlId 'DEF-1.2' -Control $ctrl -FrameworkIds $cit -Policies $slForce `
                -Pass { @(& $weak $_).Count -eq 0 } `
                -Value { $w = @(& $weak $_); if ($w.Count) { $w -join ', ' } else { 'hardened' } } `
                -PassDetail 'Safe Links scans email with click-through blocked, clicks tracked, internal senders covered and URLs rewritten.' `
                -FailDetail 'Safe Links is missing or not hardened for these recipients.' `
                -RequiredValue 'EnableSafeLinksForEmail, AllowClickThrough=False, TrackClicks=True, EnableForInternalSenders=True, URL rewrite on'
        }
    }

    # ── DEF-1.3 .. 1.6 anti-phishing ─────────────────────────────────────
    # One explicit call per control (literal ControlIds keep the coverage
    # audit able to see each verdict).
    $apOk = $ap -and $ap.Available
    $apGate = { param($cid) $c = Get-TPControlById -ControlId $cid
        if ($c -and -not $apOk) { Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $c.Category -Title $c.Title -FrameworkIds (Get-TPFrameworkCitations -ControlId $cid) -Detail 'AntiPhishing policies were not collected; not assessed.' }
        return [bool]($c -and $apOk) }
    if (& $apGate 'DEF-1.3') {
        Add-TPPolicySetFinding -ControlId 'DEF-1.3' -Control (Get-TPControlById -ControlId 'DEF-1.3') -FrameworkIds (Get-TPFrameworkCitations -ControlId 'DEF-1.3') -Policies $apForce `
            -Pass { (& $f $_ 'EnableSpoofIntelligence' $false) -eq $true } -Value { "EnableSpoofIntelligence=$(& $f $_ 'EnableSpoofIntelligence' '?')" } `
            -PassDetail 'Spoof intelligence evaluates spoofed senders.' -FailDetail 'Spoof intelligence is off for these recipients; spoofed senders are not evaluated.' -RequiredValue 'EnableSpoofIntelligence = True'
    }
    if (& $apGate 'DEF-1.4') {
        Add-TPPolicySetFinding -ControlId 'DEF-1.4' -Control (Get-TPControlById -ControlId 'DEF-1.4') -FrameworkIds (Get-TPFrameworkCitations -ControlId 'DEF-1.4') -Policies $apForce `
            -Pass { (& $f $_ 'HonorDmarcPolicy' $false) -eq $true } -Value { "HonorDmarcPolicy=$(& $f $_ 'HonorDmarcPolicy' '?')" } `
            -PassDetail 'Sender DMARC p=reject / p=quarantine is honored.' -FailDetail 'Sender DMARC policies are not honored for these recipients.' -RequiredValue 'HonorDmarcPolicy = True'
    }
    if (& $apGate 'DEF-1.5') {
        Add-TPPolicySetFinding -ControlId 'DEF-1.5' -Control (Get-TPControlById -ControlId 'DEF-1.5') -FrameworkIds (Get-TPFrameworkCitations -ControlId 'DEF-1.5') -Policies $apForce `
            -Pass { [int](& $f $_ 'PhishThresholdLevel' 1) -ge 2 } -Value { "PhishThresholdLevel=$(& $f $_ 'PhishThresholdLevel' 1)" } `
            -PassDetail 'Phishing threshold is 2 (Aggressive) or higher.' -FailDetail 'Phishing threshold is 1 (the default) for these recipients; CIS and CISA SCuBA recommend 2 or higher.' -RequiredValue 'PhishThresholdLevel >= 2'
    }
    if (& $apGate 'DEF-1.6') {
        Add-TPPolicySetFinding -ControlId 'DEF-1.6' -Control (Get-TPControlById -ControlId 'DEF-1.6') -FrameworkIds (Get-TPFrameworkCitations -ControlId 'DEF-1.6') -Policies $apForce `
            -Pass { (& $f $_ 'EnableFirstContactSafetyTips' $false) -eq $true } -Value { "EnableFirstContactSafetyTips=$(& $f $_ 'EnableFirstContactSafetyTips' '?')" } `
            -PassDetail 'First contact safety tips warn users about new senders.' -FailDetail 'First contact safety tips are off for these recipients.' -RequiredValue 'EnableFirstContactSafetyTips = True'
    }
}

# ── DEF-2.1 Preset Security Policies Applied ─────────────────────────────────
function Test-TPControlDefenderPresetPolicies {
    [CmdletBinding()] param()
    $cid = 'DEF-2.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $def = Get-TPRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Defender data not collected'; return
    }
    # A preset is ON when its protection-policy rule is Enabled. Matching
    # policy NAMES against 'Standard|Strict' passed a custom policy called
    # "Standard users - anti-phish", and a preset policy object remains after
    # the preset is switched off.
    $pr = Get-TPNestedProperty -Object $def -Path 'Data.PresetRules' -Default $null
    if (-not $pr -or (Get-TPObjectField -Item $pr -Key 'Available' -Default $false) -ne $true) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'PresetRules (Get-EOPProtectionPolicyRule) was not collected; not assessed.'
        return
    }
    $on = @(@(Get-TPObjectField -Item $pr -Key 'EOP' -Default @()) + @(Get-TPObjectField -Item $pr -Key 'ATP' -Default @()) |
        Where-Object { [string](Get-TPObjectField -Item $_ -Key 'State' -Default '') -eq 'Enabled' })
    if ($on.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No Standard or Strict preset security policy is turned on. Protection depends on the default and any custom policies, which must each be kept at recommended values by hand.' -CurrentValue 'No preset turned on' -RequiredValue 'Standard or Strict preset applied' -Remediation $ctrl.Remediation
        return
    }
    # A preset turned on is not a preset that applies to everyone. Judge WHO it covers: a
    # rule that names every accepted domain, names no other recipient scope and has no
    # exclusions covers everyone; otherwise recipients in a scope gap or an exclusion fall
    # back to whatever else is in force (the Built-In protection policy, a custom or the
    # default policy, which DEF-1.x judge). Standard and Strict are combined: a recipient
    # excluded from one is still covered by the other unless excluded from both.
    $exo = Get-TPRawData -Key 'EXO-MailboxConfig'
    $accepted = @()
    if ($exo -and (Test-TPSectionCollected $exo 'AcceptedDomains')) {
        $accepted = @(@(Get-TPNestedProperty -Object $exo -Path 'Data.AcceptedDomains' -Default @()) | ForEach-Object { ([string](Get-TPObjectField -Item $_ -Key 'DomainName' -Default '')).ToLowerInvariant() } | Where-Object { $_ })
    }
    $names = ($on | ForEach-Object { [string](Get-TPObjectField -Item $_ -Key 'Name' -Default '?') } | Sort-Object -Unique) -join ', '
    $byName = @($on | Group-Object { [string](Get-TPObjectField -Item $_ -Key 'Name' -Default '?') })
    $cands = @(); $scopeNotes = @(); $scopeUnknown = @(); $scopeUnread = @()
    foreach ($g in $byName) {
        $rules = @($g.Group)
        # A preset's EOP and ATP rules carry the same scope; judge the most restrictive view.
        $scoped = @($rules | Where-Object {
            @(Get-TPObjectField -Item $_ -Key 'SentTo' -Default @() | Where-Object { $_ }).Count -gt 0 -or
            @(Get-TPObjectField -Item $_ -Key 'SentToMemberOf' -Default @() | Where-Object { $_ }).Count -gt 0 })
        $doms = @($rules | ForEach-Object { @(Get-TPObjectField -Item $_ -Key 'RecipientDomainIs' -Default @()) } | ForEach-Object { ([string]$_).ToLowerInvariant() } | Where-Object { $_ } | Sort-Object -Unique)
        $missingDoms = @($accepted | Where-Object { $_ -notin $doms })
        $ex = @($rules | ForEach-Object {
            foreach ($x in @(Get-TPObjectField -Item $_ -Key 'ExceptIfSentTo' -Default @())) { if ($x) { "recipient:$x" } }
            foreach ($x in @(Get-TPObjectField -Item $_ -Key 'ExceptIfSentToMemberOf' -Default @())) { if ($x) { "group:$x" } }
            foreach ($x in @(Get-TPObjectField -Item $_ -Key 'ExceptIfRecipientDomainIs' -Default @())) { if ($x) { "domain:$x" } }
            # An older result carries only the flag: the exclusion exists, its identity is unknown.
            if ((Get-TPObjectField -Item $_ -Key 'HasExceptions' -Default $false) -eq $true -and
                @(Get-TPObjectField -Item $_ -Key 'ExceptIfSentTo' -Default @()).Count -eq 0 -and @(Get-TPObjectField -Item $_ -Key 'ExceptIfSentToMemberOf' -Default @()).Count -eq 0 -and
                @(Get-TPObjectField -Item $_ -Key 'ExceptIfRecipientDomainIs' -Default @()).Count -eq 0) { "unnamed-exclusion:$($g.Name)" }
        } | Sort-Object -Unique)
        if ($scoped.Count -gt 0) { $scopeNotes += "$($g.Name) applies only to named recipients or groups" ; continue }
        # Microsoft documents that when a Standard or Strict preset rule's conditions and exceptions are
        # all empty there are no recipient restrictions: it applies to everyone. That reading is only safe
        # when the collector demonstrably read the exception fields (current results carry them); an older
        # result lacking them cannot tell "empty" from "not read", so scope stays not established.
        $shaped = @($rules | Where-Object {
            $r0 = $_
            if ($r0 -is [System.Collections.IDictionary]) { $r0.Contains('ExceptIfSentToMemberOf') } else { $null -ne $r0.PSObject.Properties['ExceptIfSentToMemberOf'] } }).Count -eq $rules.Count
        if ($doms.Count -eq 0 -and $shaped) { $cands += [pscustomobject]@{ Name = $g.Name; Exclusions = $ex }; continue }
        if ($doms.Count -eq 0) { $scopeUnknown += "$($g.Name): the rule returned no recipient scope and this result predates the exclusion fields, so who it applies to is not established"; continue }
        # Unread accepted domains establish nothing either way: not assessed, never a shortfall.
        if ($accepted.Count -eq 0) { $scopeUnread += "$($g.Name): the accepted domains were not read, so whether it covers every domain is not established"; continue }
        if ($missingDoms.Count -gt 0) { $scopeNotes += "$($g.Name) does not include accepted domain(s): $($missingDoms -join ', ')"; continue }
        $cands += [pscustomobject]@{ Name = $g.Name; Exclusions = $ex }
    }
    $cov = Get-TPExclusionCoverage -Candidates $cands
    $verified = @("Preset security policy turned on: $names."); $short = @(); $unknown = @()
    switch ($cov.Kind) {
        'Full'       { $verified += "$($cov.FullNames -join ', ') applies to every accepted domain with no recipient exclusions." }
        'Exceptions' { $short += "Every preset that covers all domains excludes the same recipients ($($cov.Exceptions -join ', ')), so they get no preset protection and fall back to the Built-In, custom or default policies (see DEF-1.1 to DEF-1.6 for what those provide)." }
        'Unproven'   { $unknown += "whether any recipient is excluded from every preset: $((@($cov.ExcludedBy.Keys) | ForEach-Object { "$_ excludes $(@($cov.ExcludedBy[$_]).Count) recipient scope(s)" }) -join '; '); group membership was not resolved, so overlap between the excluded groups is unproven." }
        'None'       { if ($scopeUnknown.Count -eq 0 -and $scopeUnread.Count -eq 0) { $short += 'No preset applies to all recipients.' } }
    }
    foreach ($n in $scopeUnknown) { $unknown += "$n." }
    # With another preset proven to cover everyone, the unread scope cannot change the verdict.
    foreach ($n in $scopeUnread) { if ($cov.Kind -eq 'Full') { $verified += "Also: $n." } else { $unknown += "$n." } }
    foreach ($n in $scopeNotes) { if ($cov.Kind -eq 'Full') { $verified += "Also: $n." } else { $short += "$n." } }
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $unknown `
        -CurrentValue $names -RequiredValue 'A Standard or Strict preset that applies to every recipient, with no exclusion unless another preset covers those recipients'
}

# ── DEF-2.2 Zero-hour auto purge (spam, phishing AND malware) ────────────────
function Test-TPControlDefenderZAP {
    [CmdletBinding()] param()
    $cid = 'DEF-2.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $exo = Get-TPRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'EXO data not collected'; return
    }
    if (-not (Test-TPSectionCollected $exo 'AntiSpamPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AntiSpamPolicies was not collected; not assessed.'; return
    }
    $f = { param($p, $k, $d = $null) Get-TPObjectField -Item $p -Key $k -Default $d }
    $verified = @(); $short = @(); $unknown = @()

    # Spam and phishing ZAP: anti-spam policies in force (SpamZapEnabled + PhishZapEnabled;
    # ZapEnabled is the deprecated umbrella, used only when neither is present).
    $policies = @(Get-TPInForcePolicies -Policies @(Get-TPNestedProperty -Object $exo -Path 'Data.AntiSpamPolicies' -Default @()) -Rules (Get-TPRuleList -Item $exo.Data -Key 'AntiSpamRules') -RulePolicyKey 'HostedContentFilterPolicy' -PresetKind 'EOP')
    $zap = { param($p) $s = & $f $p 'SpamZapEnabled'; $h = & $f $p 'PhishZapEnabled'
        if ($null -eq $s -and $null -eq $h) { (& $f $p 'ZapEnabled' $false) -eq $true } else { $s -eq $true -and $h -eq $true } }
    if ($policies.Count -eq 0) {
        $unknown += 'spam and phishing ZAP (no anti-spam policy in force could be identified).'
    } else {
        $bad = @($policies | Where-Object { -not (& $zap $_) })
        $names = { param($l) (@($l) | ForEach-Object { [string](& $f $_ 'Name' '?') }) -join ', ' }
        if ($bad.Count -eq 0) { $verified += "Spam and phishing ZAP is on in every anti-spam policy in force ($(& $names $policies))." }
        else {
            $goodSp = @($policies | Where-Object { & $zap $_ })
            if ($goodSp.Count) { $verified += "Spam and phishing ZAP is on in: $(& $names $goodSp)." }
            $short += "Spam or phishing ZAP is off in: $(& $names $bad)."
        }
    }

    # Malware ZAP is an anti-malware policy setting (ZapEnabled on Get-MalwareFilterPolicy).
    $def = Get-TPRawData -Key 'Defender-Policies'
    $mf  = if ($def -and $def.Success) { Get-TPObjectField -Item $def.Data -Key 'MalwareFilter' -Default $null } else { $null }
    if (-not $mf -or -not (Get-TPObjectField -Item $mf -Key 'Available' -Default $false)) {
        $unknown += 'malware ZAP (the anti-malware policies were not read).'
    } else {
        $mfForce = @(Get-TPInForcePolicies -Policies @(Get-TPObjectField -Item $mf -Key 'Policies' -Default @()) -Rules (Get-TPRuleList -Item $mf -Key 'Rules') -RulePolicyKey 'MalwareFilterPolicy' -PresetKind 'EOP')
        if ($mfForce.Count -eq 0) {
            $unknown += 'malware ZAP (no anti-malware policy in force could be identified).'
        } else {
            $read = @($mfForce | Where-Object { $null -ne (& $f $_ 'ZapEnabled') })
            if ($read.Count -lt $mfForce.Count) {
                $unknown += 'malware ZAP (ZapEnabled was not returned for every anti-malware policy in force).'
            } else {
                $badMf = @($mfForce | Where-Object { (& $f $_ 'ZapEnabled') -ne $true })
                if ($badMf.Count -eq 0) { $verified += 'Malware ZAP is on in every anti-malware policy in force.' }
                else {
                    $goodMf = @($mfForce | Where-Object { (& $f $_ 'ZapEnabled') -eq $true })
                    if ($goodMf.Count) { $verified += "Malware ZAP is on in: $((@($goodMf) | ForEach-Object { [string](& $f $_ 'Name' '?') }) -join ', ')." }
                    $short += "Malware ZAP is off in: $((@($badMf) | ForEach-Object { [string](& $f $_ 'Name' '?') }) -join ', ')."
                }
            }
        }
    }
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $unknown `
        -RequiredValue 'SpamZapEnabled, PhishZapEnabled and (anti-malware) ZapEnabled = True in every policy in force'
}

# ── DEF-2.3 Anti-Malware Common Attachments Blocked ─────────────────────────
function Test-TPControlDefenderCommonAttachments {
    [CmdletBinding()] param()
    $cid = 'DEF-2.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $def = Get-TPRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Defender data not collected'; return
    }
    $mf = $def.Data['MalwareFilter']
    if (-not $mf -or -not $mf.Available) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Malware filter data not available'; return
    }
    # Judged over the policies IN FORCE (an enabled rule, a preset, or the default when
    # nothing else applies), not "any policy has it on": a filter enabled in a policy
    # that applies to nobody protects nobody.
    $mfForce = @(Get-TPInForcePolicies -Policies @(Get-TPObjectField -Item $mf -Key 'Policies' -Default @()) -Rules (Get-TPRuleList -Item $mf -Key 'Rules') -RulePolicyKey 'MalwareFilterPolicy' -PresetKind 'EOP')
    if ($mfForce.Count -eq 0) {
        # Older results carry no rules: fall back to the policy-wide count, but the
        # blocked-type list still decides whether the expected state is met.
        if ($mf.FileFilterEnabledCount -gt 0) {
            Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit `
                -Verified @("The common attachments filter is on in $($mf.FileFilterEnabledCount) malware policy(ies); which policies are in force was not established.") `
                -NotEstablished @('the NRG blocked-file-type list was not compared (policies in force could not be determined).') `
                -RequiredValue 'Filter on with the approved blocked-type list in every policy in force'
        } else {
            Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'Common attachments filter is disabled. High-risk file types (.exe, .js, .vbs, etc.) are not blocked at the mail gateway.' -Remediation $ctrl.Remediation
        }
        return
    }
    $fv = { param($p, $k) Get-TPObjectField -Item $p -Key $k -Default $null }
    $pname = { param($p) [string](& $fv $p 'Name') }
    $off = @($mfForce | Where-Object { (& $fv $_ 'EnableFileFilter') -ne $true })
    $on  = @($mfForce | Where-Object { (& $fv $_ 'EnableFileFilter') -eq $true })
    $verified = @(); $short = @(); $unknown = @()
    if ($off.Count -eq 0) { $verified += "The common attachments filter is on in every malware policy in force ($((@($mfForce) | ForEach-Object { & $pname $_ }) -join ', '))." }
    else {
        if ($on.Count) { $verified += "The common attachments filter is on in: $((@($on) | ForEach-Object { & $pname $_ }) -join ', ')." }
        $short += "The common attachments filter is off in: $((@($off) | ForEach-Object { & $pname $_ }) -join ', '), so high-risk file types are not blocked by type for those recipients."
    }
    $approved = @((Get-TPStandards).CommonAttachmentFileTypes | ForEach-Object { $_.TrimStart('.').ToLowerInvariant() })
    if ($approved.Count -eq 0) {
        $unknown += 'whether the filter blocks the NRG blocked-file-type list, because no list is approved (Config/tp-standards.json CommonAttachmentFileTypes is empty).'
    } elseif ($on.Count -gt 0) {
        $missing = [ordered]@{}
        foreach ($pol in $on) {
            $types = @(@(& $fv $pol 'FileTypes') | ForEach-Object { ([string]$_).TrimStart('.').ToLowerInvariant() })
            $gone = @($approved | Where-Object { $_ -notin $types })
            if ($gone.Count) { $missing[(& $pname $pol)] = $gone }
        }
        if ($missing.Count -eq 0) { $verified += "Every policy with the filter on blocks all $($approved.Count) approved file type(s)." }
        else { $short += "Approved file types not blocked: $((@($missing.Keys) | ForEach-Object { "$_ ($($missing[$_] -join ', '))" }) -join '; ')." }
    }
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $unknown `
        -RequiredValue 'EnableFileFilter = True and the approved blocked-type list in every malware policy in force'
}

# ── DEF-2.4 Quarantine Policy Admin Managed ──────────────────────────────────
function Test-TPControlDefenderQuarantine {
    [CmdletBinding()] param()
    $cid = 'DEF-2.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $exo = Get-TPRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'EXO data not collected'; return
    }
    if (-not (Test-TPSectionCollected $exo 'AntiSpamPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AntiSpamPolicies was not collected; not assessed.'; return
    }
    $policies = @(Get-TPInForcePolicies -Policies @(Get-TPNestedProperty -Object $exo -Path 'Data.AntiSpamPolicies' -Default @()) -Rules (Get-TPRuleList -Item $exo.Data -Key 'AntiSpamRules') -RulePolicyKey 'HostedContentFilterPolicy' -PresetKind 'EOP')
    $f = { param($p, $k, $d = $null) Get-TPObjectField -Item $p -Key $k -Default $d }
    # The quarantine policy decides who may release: DefaultFullAccessPolicy
    # (Microsoft's default for phishing) lets users release their own. Stated,
    # not claimed away ("users cannot self-release" was false by default).
    Add-TPPolicySetFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $policies `
        -Pass { [string](& $f $_ 'PhishSpamAction' '') -eq 'Quarantine' } `
        -Value { "PhishSpamAction=$(& $f $_ 'PhishSpamAction' '?'), quarantine policy=$(& $f $_ 'PhishQuarantineTag' 'not read')" } `
        -PassDetail 'Phishing is quarantined rather than delivered to Junk. Whether users can release it depends on the quarantine policy shown.' `
        -FailDetail 'Phishing is delivered to the Junk folder for these recipients, where users can open it and click links.' `
        -RequiredValue 'PhishSpamAction = Quarantine'
}

# ── DEF-2.5 High Confidence Spam to Quarantine ──────────────────────────────
function Test-TPControlDefenderHCSpam {
    [CmdletBinding()] param()
    $cid = 'DEF-2.5'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $exo = Get-TPRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'EXO data not collected'; return
    }
    if (-not (Test-TPSectionCollected $exo 'AntiSpamPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AntiSpamPolicies was not collected; not assessed.'; return
    }
    $policies = @(Get-TPInForcePolicies -Policies @(Get-TPNestedProperty -Object $exo -Path 'Data.AntiSpamPolicies' -Default @()) -Rules (Get-TPRuleList -Item $exo.Data -Key 'AntiSpamRules') -RulePolicyKey 'HostedContentFilterPolicy' -PresetKind 'EOP')
    $f = { param($p, $k, $d = $null) Get-TPObjectField -Item $p -Key $k -Default $d }
    Add-TPPolicySetFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $policies `
        -Pass { [string](& $f $_ 'HighConfidenceSpamAction' '') -eq 'Quarantine' } `
        -Value { "HighConfidenceSpamAction=$(& $f $_ 'HighConfidenceSpamAction' '?')" } `
        -PassDetail 'High confidence spam is quarantined.' `
        -FailDetail 'High confidence spam reaches these recipients (Junk folder or inbox).' `
        -RequiredValue 'HighConfidenceSpamAction = Quarantine'
}

# ── DEF-2.6 Bulk Mail Threshold Configured ──────────────────────────────────
function Test-TPControlDefenderBulkThreshold {
    [CmdletBinding()] param()
    $cid = 'DEF-2.6'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $exo = Get-TPRawData -Key 'EXO-MailboxConfig'
    if (-not $exo -or -not $exo.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'EXO data not collected'; return
    }
    if (-not (Test-TPSectionCollected $exo 'AntiSpamPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AntiSpamPolicies was not collected; not assessed.'; return
    }
    $policies = @(Get-TPInForcePolicies -Policies @(Get-TPNestedProperty -Object $exo -Path 'Data.AntiSpamPolicies' -Default @()) -Rules (Get-TPRuleList -Item $exo.Data -Key 'AntiSpamRules') -RulePolicyKey 'HostedContentFilterPolicy' -PresetKind 'EOP')
    $f = { param($p, $k, $d = $null) Get-TPObjectField -Item $p -Key $k -Default $d }
    # 7 is the default: left at the default is not configured.
    Add-TPPolicySetFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $policies `
        -Pass { $t = & $f $_ 'BulkThreshold' $null; $null -ne $t -and [int]$t -le 6 } `
        -Value { "BulkThreshold=$(& $f $_ 'BulkThreshold' 'not read')" } `
        -PassDetail 'Bulk complaint level threshold is 6 or lower.' `
        -FailDetail 'Bulk mail threshold is above 6 (7 is the default) for these recipients, so more bulk mail reaches inboxes.' `
        -RequiredValue 'BulkThreshold <= 6'
}

# ── DEF-3.1 Unauthenticated Sender Indicator ─────────────────────────────────
function Test-TPControlDefenderUnauthSender {
    [CmdletBinding()] param()
    $cid = 'DEF-3.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $def = Get-TPRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Defender data not collected'; return
    }
    $ap = $def.Data['AntiPhishing']
    if (-not $ap -or -not $ap.Available) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AntiPhishing policies were not collected; not assessed.'; return
    }
    $policies = @(Get-TPInForcePolicies -Policies @(Get-TPObjectField -Item $ap -Key 'Policies' -Default @()) -Rules (Get-TPRuleList -Item $ap -Key 'Rules') -RulePolicyKey 'AntiPhishPolicy' -PresetKind 'EOP')
    $f = { param($p, $k, $d = $null) Get-TPObjectField -Item $p -Key $k -Default $d }
    Add-TPPolicySetFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $policies `
        -Pass { (& $f $_ 'EnableUnauthenticatedSender' $false) -eq $true } -Value { "EnableUnauthenticatedSender=$(& $f $_ 'EnableUnauthenticatedSender' '?')" } `
        -PassDetail 'Outlook marks senders that cannot be authenticated.' `
        -FailDetail 'Users get no indicator for senders that fail authentication.' `
        -RequiredValue 'EnableUnauthenticatedSender = True'
}

# ── DEF-3.2 Via Tag Enabled ──────────────────────────────────────────────────
function Test-TPControlDefenderViaTag {
    [CmdletBinding()] param()
    $cid = 'DEF-3.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $def = Get-TPRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'Defender data not collected'; return
    }
    $ap = $def.Data['AntiPhishing']
    if (-not $ap -or -not $ap.Available) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'AntiPhishing policies were not collected; not assessed.'; return
    }
    $policies = @(Get-TPInForcePolicies -Policies @(Get-TPObjectField -Item $ap -Key 'Policies' -Default @()) -Rules (Get-TPRuleList -Item $ap -Key 'Rules') -RulePolicyKey 'AntiPhishPolicy' -PresetKind 'EOP')
    $f = { param($p, $k, $d = $null) Get-TPObjectField -Item $p -Key $k -Default $d }
    Add-TPPolicySetFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $policies `
        -Pass { (& $f $_ 'EnableViaTag' $false) -eq $true } -Value { "EnableViaTag=$(& $f $_ 'EnableViaTag' '?')" } `
        -PassDetail 'Outlook shows the "via" tag when mail is sent through another domain.' `
        -FailDetail 'Users cannot see when mail was sent through a relay on behalf of a domain.' `
        -RequiredValue 'EnableViaTag = True'
}

# ── DEF-3.3 Defender for Cloud Apps Connected ────────────────────────────────
function Test-TPControlDefenderMDCA {
    [CmdletBinding()] param()
    $cid = 'DEF-3.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    # MDCA connection status requires a dedicated collector that doesn't exist
    # yet. v4.11.1: removed the unused $ca proxy read — the finding is
    # ADVISORY-ONLY (manual review) so no data dependency is needed.
    Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
        -Title "$($ctrl.Title) (Manual review required)" -Severity 'Medium' -FrameworkIds $cit `
        -Detail 'This control requires manual verification — Defender for Cloud Apps connection state is not exposed to the APIs this assessment uses. Confirm in Defender XDR > Settings > Cloud Apps > Connected apps that the Microsoft 365 connector is active.' `
        -Remediation $ctrl.Remediation
}

# ── DEF-3.4 Defender Alerts Email Notification ──────────────────────────────
function Test-TPControlDefenderAlertNotification {
    [CmdletBinding()] param()
    $cid = 'DEF-3.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid

    # v4.13.0: implemented. Reads alert POLICY configuration from
    # Get-ProtectionAlert (collected into Purview.ProtectionAlerts), which is a
    # different question from EXO-ConnectionFilter's /security/alerts_v2 feed:
    # that lists alerts which have fired, this asks whether anyone is configured
    # to be told when they do. An enabled policy with an empty NotifyUser raises
    # an alert into an empty room.
    $pvw = Get-TPRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Purview data not collected'
        return
    }

    $status = Get-TPNestedProperty -Object $pvw -Path 'Data.SectionStatus.ProtectionAlerts' -Default $null
    if ($status -ne 'Collected') {
        $why = if ($status -eq 'Failed') {
            'the Get-ProtectionAlert query failed (see Exceptions)'
        } else {
            'Get-ProtectionAlert was unavailable — this requires a Security & Compliance (IPPS) session'
        }
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title `
            -Detail "Alert policy configuration could not be read: $why. Alert notification state was not assessed."
        return
    }

    $policies = @($pvw.Data['ProtectionAlerts'] ?? @())
    if ($policies.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No alert policies are configured. Nothing in the tenant will raise a security alert, so a compromise produces no notification to anyone.' `
            -CurrentValue 'Zero alert policies' -RequiredValue 'High and Critical alert policies enabled with email recipients' `
            -Remediation $ctrl.Remediation
        return
    }

    $enabled = @($policies | Where-Object { -not $_.Disabled })
    $high    = @($enabled  | Where-Object { $_.Severity -in @('High','Critical') })
    $silent  = @($high     | Where-Object { @($_.NotifyUser).Count -eq 0 })

    if ($high.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "$($enabled.Count) alert policy(ies) are enabled but none are High or Critical severity, so the most serious events do not raise a prioritized alert." `
            -CurrentValue "$($enabled.Count) enabled policies, 0 at High/Critical" `
            -RequiredValue 'High and Critical alert policies enabled with email recipients' `
            -Remediation $ctrl.Remediation
        return
    }

    if ($silent.Count -eq 0) {
        # Recipients exist. Whether they are the NRG monitoring address is a separate
        # claim that needs an explicit configured list (Get-TPMonitoringAddresses).
        $routing = Get-TPAlertRouting -Policies $high -Addresses (Get-TPMonitoringAddresses)
        if (-not $routing.Configured) {
            Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
                -Title $ctrl.Title -FrameworkIds $cit `
                -Detail "Verified: all $($high.Count) enabled High/Critical alert policy(ies) have email recipients configured. Not assessed: whether any recipient is the NRG monitoring address, because no monitoring address is configured (-MonitoringAddress, MonitoringAddresses in clients.json, or MonitoringAddresses in branding.psd1)." `
                -CurrentValue "$($high.Count) of $($high.Count) High/Critical policies have recipients; routing to NRG not checked" `
                -RequiredValue 'Every enabled High/Critical alert policy notifies the NRG monitoring address'
        } elseif ($routing.Unrouted.Count -eq 0) {
            Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
                -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
                -Detail "All $($high.Count) enabled High/Critical alert policy(ies) notify a configured NRG monitoring address."
        } else {
            $affected = @($routing.Unrouted | ForEach-Object {
                [ordered]@{ DisplayName = [string]$_.Name; Severity = [string]$_.Severity; Recipients = (@($_.NotifyUser) -join ', ') }
            })
            $st = if ($routing.Routed.Count -gt 0) { 'Partial' } else { 'Gap' }
            Add-TPFinding -ControlId $cid -State $st -Category $ctrl.Category `
                -Title $ctrl.Title -Severity $(if ($st -eq 'Gap') { $ctrl.Severity } else { 'Medium' }) -FrameworkIds $cit `
                -Detail "Verified: all $($high.Count) enabled High/Critical alert policy(ies) have recipients. Shortfall: $($routing.Unrouted.Count) of $($high.Count) do not notify a configured NRG monitoring address, so those alerts go to people who may not be watching for them." `
                -CurrentValue "$($routing.Routed.Count) of $($high.Count) policies notify the NRG monitoring address" `
                -RequiredValue 'Every enabled High/Critical alert policy notifies the NRG monitoring address' `
                -Remediation $ctrl.Remediation -AffectedObjects $affected
        }
    } else {
        $affected = @($silent | ForEach-Object {
            [ordered]@{
                DisplayName = [string]$_.Name
                Severity    = [string]$_.Severity
                Recipients  = 'none configured'
            }
        })
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($silent.Count) of $($high.Count) enabled High/Critical alert policy(ies) have no email recipients. These alerts fire into the portal where nobody is watching — during an incident the tenant is generating exactly the signal that is needed and delivering it to no one." `
            -CurrentValue "$($silent.Count) High/Critical policies with no recipients" `
            -RequiredValue 'Every enabled High/Critical alert policy has at least one notification recipient' `
            -Remediation $ctrl.Remediation -AffectedObjects $affected
    }
}

function Test-TPControlDefenderDLPWorkloads {
    [CmdletBinding()] param()
    $cid = 'DEF-4.1'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pvw = Get-TPRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview DLP data not collected'; return
    }
    if (-not (Test-TPSectionCollected $pvw 'DLPPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail 'DLP policies were not collected; not assessed.'; return
    }
    $dlpPolicies = @($pvw.Data['DLPPolicies'] ?? @())
    if ($dlpPolicies.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No DLP policies configured. Sensitive data can be emailed, shared via Teams, or uploaded to SharePoint with no controls.' -Remediation $ctrl.Remediation; return
    }
    # COVERAGE only: which workloads an ENFORCING policy (Mode = Enable) is scoped to. A policy in test
    # mode or turned off protects nothing, so its workloads do not count (they are reported). Whether
    # rules detect sensitive data is DEF-4.2; whether they block is not claimed here.
    $required = @('Exchange','SharePoint','OneDriveForBusiness','Teams')
    # Mode values Microsoft documents for a DLP policy. Only Enable enforces; an empty, absent or
    # unrecognized Mode is unknown evidence, never "not enforcing": it can neither cover nor fail a workload.
    $knownOff  = @('TestWithNotifications', 'TestWithoutNotifications', 'Disable', 'PendingDeletion')
    $modeOf    = { param($p) [string](Get-TPObjectField -Item $p -Key 'Mode' -Default '') }
    $enforcing = @($dlpPolicies | Where-Object { (& $modeOf $_) -eq 'Enable' })
    $notEnforcing = @($dlpPolicies | Where-Object { (& $modeOf $_) -in $knownOff })
    $unknownMode  = @($dlpPolicies | Where-Object { (& $modeOf $_) -ne 'Enable' -and (& $modeOf $_) -notin $knownOff })
    $covered  = @($enforcing | ForEach-Object { @(Get-TPObjectField -Item $_ -Key 'Workloads' -Default @()) } | Sort-Object -Unique)
    # Workloads an unknown-mode policy names (all of them when it names none) and no enforcing policy covers.
    $maybe    = @($unknownMode | ForEach-Object { $wl = @(Get-TPObjectField -Item $_ -Key 'Workloads' -Default @() | Where-Object { $_ }); if ($wl.Count) { $wl } else { $required } } | Sort-Object -Unique)
    $modeUnknownWl = @($required | Where-Object { $_ -notin $covered -and $_ -in $maybe })
    $missing  = @($required | Where-Object { $_ -notin $covered -and $_ -notin $modeUnknownWl })
    # A workload named on a policy is not the workload covered: the policy may be scoped to a few
    # mailboxes, sites or teams. Judge the scope per workload across enforcing policies.
    $fullScope = @(); $partScope = [ordered]@{}; $scopeUnread = @()
    foreach ($w in @($required | Where-Object { $_ -in $covered })) {
        $isFull = $false; $named = @(); $unread = $false
        foreach ($pol in @($enforcing | Where-Object { $w -in @(Get-TPObjectField -Item $_ -Key 'Workloads' -Default @()) })) {
            $loc = Get-TPObjectField -Item (Get-TPObjectField -Item $pol -Key 'Locations' -Default $null) -Key $w -Default $null
            $inc = Get-TPObjectField -Item $loc -Key 'Include' -Default $null
            if ($null -eq $inc) { $unread = $true; continue }
            $exc = @(Get-TPObjectField -Item $loc -Key 'Exclude' -Default @())
            if (@($inc) -contains 'All' -and $exc.Count -eq 0) { $isFull = $true }
            else { $named += "$([string](Get-TPObjectField -Item $pol -Key 'Name' -Default '?')): $(if (@($inc) -contains 'All') { 'all, except ' + ($exc -join ', ') } else { @($inc).Count.ToString() + ' named location(s)' })" }
        }
        if ($isFull) { $fullScope += $w } elseif ($named.Count -gt 0) { $partScope[$w] = $named } elseif ($unread) { $scopeUnread += $w }
    }
    $verified = @(); $short = @(); $unknownScope = @()
    # Only a required workload that an enforcing policy covers is a verified component; an enforcing
    # policy covering none of them is reported with the shortfall, never as something met.
    if ($enforcing.Count -gt 0) {
        $line = "$($enforcing.Count) enforcing DLP polic$(if ($enforcing.Count -eq 1) { 'y' } else { 'ies' }) (Mode Enable) cover: $(($required | Where-Object { $_ -in $covered }) -join ', ')$(if (-not ($required | Where-Object { $_ -in $covered })) { 'none of the required workloads' })."
        if ($required | Where-Object { $_ -in $covered }) { $verified += $line } else { $short += $line }
    }
    if ($missing.Count -gt 0) { $short += "No enforcing policy covers: $($missing -join ', '). Data can leave those channels without policy enforcement." }
    if ($partScope.Count -gt 0) { $short += "Covered only for part of the workload: $((@($partScope.Keys) | ForEach-Object { "$_ ($($partScope[$_] -join '; '))" }) -join '; ')." }
    if ($fullScope.Count -gt 0) { $verified += "Whole-workload scope (All, no exclusions) confirmed for: $($fullScope -join ', ')." }
    if ($scopeUnread.Count -gt 0) { $unknownScope += "whether the policies cover the whole workload or only named locations for: $($scopeUnread -join ', '), because the policy location scope was not returned in this result." }
    if ($enforcing.Count -eq 0 -and $unknownMode.Count -eq 0) { $short += 'No DLP policy is in enforcing mode (Enable).' }
    if ($unknownMode.Count -gt 0) {
        $um = ($unknownMode | ForEach-Object { "$([string](Get-TPObjectField -Item $_ -Key 'Name' -Default '?')) [unknown mode]" }) -join '; '
        if ($modeUnknownWl.Count -gt 0) { $unknownScope += "whether $($modeUnknownWl -join ', ') $(if ($modeUnknownWl.Count -eq 1) { 'is' } else { 'are' }) covered, because the Mode of $um was empty or not recognized, so whether it enforces is unknown." }
        elseif ($verified.Count -gt 0) { $verified += "Not counted (mode not read): $um." }
        else { $short += "Not counted (mode not read): $um." }
    }
    # A policy in test mode or off is reported, never credited: the note is not a verified component, so
    # it rides with the verified list only when something real was verified, else with the shortfall.
    if ($notEnforcing.Count -gt 0) {
        $nm = ($notEnforcing | ForEach-Object { "$([string](Get-TPObjectField -Item $_ -Key 'Name' -Default '?')) [$([string](Get-TPObjectField -Item $_ -Key 'Mode' -Default 'unknown mode'))]" }) -join '; '
        if ($verified.Count -gt 0) { $verified += "Not counted (not enforcing): $nm." } else { $short += "Not counted (not enforcing): $nm." }
    }
    Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -Shortfalls $short -NotEstablished $unknownScope `
        -CurrentValue "Enforcing workloads: $(@($covered) -join ', ')" -RequiredValue 'Enforcing DLP policies covering Exchange, SharePoint, OneDrive and Teams'
}

# ── DEF-4.2 DLP Policy Uses Sensitive Information Types ──────────────────────
function Test-TPControlDefenderDLPSITs {
    [CmdletBinding()] param()
    $cid = 'DEF-4.2'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pvw = Get-TPRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview DLP data not collected'; return
    }
    # Sensitive information types live on the DLP RULE
    # (ContentContainsSensitiveInformation), not the parent policy —
    # Get-DlpCompliancePolicy exposes no SIT field. This previously read
    # $policy.SensitiveInfoTypes, a property that never exists, so under
    # StrictMode it threw and the control reported Error on every tenant.
    $dlpPolicies = @($pvw.Data['DLPPolicies'] ?? @())
    $ruleStatus  = Get-TPNestedProperty -Object $pvw -Path 'Data.SectionStatus.DLPRules' -Default $null
    $dlpRules    = @($pvw.Data['DLPRules'] ?? @())

    if ($ruleStatus -ne 'Collected') {
        $why = if ($ruleStatus -eq 'Failed') { 'the Get-DlpComplianceRule query failed (see Exceptions)' }
               else { 'Get-DlpComplianceRule was unavailable — this requires a Security & Compliance (IPPS) session' }
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title `
            -Detail "DLP rule configuration could not be read: $why. Sensitive information type coverage was not assessed."
        return
    }
    # A rule counts only inside an enforcing policy, so the policy Mode is half the evidence:
    # without the policy read, no rule can be shown enforcing or not.
    if (-not (Test-TPSectionCollected $pvw 'DLPPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail 'DLP policies were not collected, so whether any DLP rule is in an enforcing policy is unknown; sensitive information type coverage not assessed.'
        return
    }

    if ($dlpPolicies.Count -eq 0 -and $dlpRules.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail 'No DLP policies or rules exist, so no content is inspected for regulated data of any kind.' `
            -CurrentValue 'Zero DLP rules' -RequiredValue 'DLP rules referencing sensitive information types' `
            -Remediation $ctrl.Remediation
        return
    }

    # DETECTION: an enabled rule counts only inside a policy that is enforcing (Mode Enable). Rules in a
    # policy in test mode (or off) detect nothing that is enforced; their types are reported, not credited.
    $states      = @(Get-TPDlpRuleStates -Policies $dlpPolicies -Rules $dlpRules)
    $activeRules = @($states | Where-Object { $_.State -eq 'Enforcing' })
    $unknownRules = @($states | Where-Object { $_.State -eq 'Unknown' })
    $testRules   = @($states | Where-Object { $_.State -eq 'TestMode' })
    $unknownSit  = @($unknownRules | Where-Object { @($_.SITs).Count -gt 0 })
    $withSITs    = @($activeRules | Where-Object { @($_.SITs).Count -gt 0 })

    if ($withSITs.Count -gt 0) {
        $sitNames = @($withSITs | ForEach-Object { $_.SITs } | Sort-Object -Unique)
        $shown    = @($sitNames | Select-Object -First 8) -join ', '
        $more     = if ($sitNames.Count -gt 8) { " (+$($sitNames.Count - 8) more)" } else { '' }
        $blocking = @($withSITs | Where-Object { $_.Blocks -eq $true }).Count
        $unread   = @($withSITs | Where-Object { $null -eq $_.Blocks }).Count
        $enf = if ($unread -eq $withSITs.Count) { 'Whether they block or only notify was not read.' } else { "$blocking of $($withSITs.Count) block access; the rest notify or audit." }
        $verified = @("$($withSITs.Count) of $($activeRules.Count) enabled rule(s) in enforcing policies match on sensitive information types: $shown$more.", $enf)
        if ($testRules.Count -gt 0) {
            $tSits = @($testRules | ForEach-Object { $_.SITs } | Sort-Object -Unique)
            $verified += "Not counted (policy in test mode or off): $($testRules.Count) rule(s)$(if ($tSits.Count) { " that would detect $(@($tSits | Select-Object -First 6) -join ', ')" }) in $((@($testRules | ForEach-Object { $_.Policy } | Sort-Object -Unique)) -join ', ')."
        }
        $unk = @(if ($unknownRules.Count -gt 0) { "whether $($unknownRules.Count) rule(s) are in an enforcing policy, because their parent policy was not found among the collected policies or its Mode was empty or not recognized." })
        Add-TPExpectedStateFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Verified $verified -NotEstablished $unk `
            -CurrentValue "$($sitNames.Count) distinct sensitive information type(s) in enforcing rules"
    } elseif ($unknownSit.Count -gt 0) {
        # A rule matching a type whose parent policy was not found may be enforcing: not a Gap. A rule
        # matching no type cannot meet the requirement in any mode, so it does not hold the Gap back.
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit `
            -Detail "No rule in an enforcing policy matches a sensitive information type, but $($unknownSit.Count) enabled rule(s) that match one belong to a policy that was not found among the collected policies or whose Mode was empty or not recognized ($((@($unknownSit | ForEach-Object { $_.Policy } | Sort-Object -Unique)) -join ', ')), so whether they enforce is unknown; not assessed."
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "$($activeRules.Count) enabled DLP rule(s) exist but none match on a sensitive information type. Without SITs the rules cannot automatically detect credit card numbers, national identifiers, or health data — they only act on the other conditions configured." `
            -CurrentValue "0 of $($activeRules.Count) enabled rules use sensitive information types" `
            -RequiredValue 'At least one enabled DLP rule matching on sensitive information types' `
            -Remediation $ctrl.Remediation
    }
}

# ── DEF-4.3 Risky Application Alerts Configured ──────────────────────────────
function Test-TPControlDefenderRiskyAppAlerts {
    [CmdletBinding()] param()
    $cid = 'DEF-4.3'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid

    # v4.13.0: implemented against Get-ProtectionAlert policy configuration.
    #
    # Matching caveat, stated plainly because it affects how much weight the
    # finding deserves: there is no machine-readable "this policy covers OAuth
    # consent" flag, so a policy is matched by its Name / Operation / ThreatType
    # against consent and application-permission wording. A tenant using custom
    # or non-English policy names can therefore be under-detected. The Gap text
    # says so, and the check is deliberately broad rather than exact so that it
    # errs toward finding a policy rather than declaring one missing.
    $pvw = Get-TPRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title -Detail 'Purview data not collected'
        return
    }

    $status = Get-TPNestedProperty -Object $pvw -Path 'Data.SectionStatus.ProtectionAlerts' -Default $null
    if ($status -ne 'Collected') {
        $why = if ($status -eq 'Failed') {
            'the Get-ProtectionAlert query failed (see Exceptions)'
        } else {
            'Get-ProtectionAlert was unavailable — this requires a Security & Compliance (IPPS) session'
        }
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category `
            -Title $ctrl.Title `
            -Detail "Alert policy configuration could not be read: $why. OAuth consent alerting was not assessed."
        return
    }

    $policies = @($pvw.Data['ProtectionAlerts'] ?? @())
    $pattern  = 'consent|oauth|application permission|app permission|service principal|risky app'

    $matched = @($policies | Where-Object {
        $hay = @(
            [string]$_.Name
            [string]$_.ThreatType
            (@($_.Operation) -join ' ')
        ) -join ' '
        $hay -match $pattern
    })
    $active = @($matched | Where-Object { -not $_.Disabled })

    if ($active.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit `
            -Detail "No enabled alert policy was found covering OAuth consent or application permission grants. Consent phishing grants an attacker-controlled app standing access to mail and files without ever taking a password, and without an alert that grant is silent. (Detection matches policy name, operation and threat type against consent and application-permission wording, so a custom-named policy may exist and not be matched — verify in the portal before remediating.)" `
            -CurrentValue "0 of $($policies.Count) alert policies match OAuth/consent coverage" `
            -RequiredValue 'An enabled alert policy covering OAuth consent / application permission grants' `
            -Remediation $ctrl.Remediation
        return
    }

    $silent = @($active | Where-Object { @($_.NotifyUser).Count -eq 0 })
    if ($silent.Count -eq 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit `
            -Detail "$($active.Count) enabled alert policy(ies) cover OAuth consent / application permission activity, each with notification recipients configured."
    } else {
        $affected = @($silent | ForEach-Object {
            [ordered]@{ DisplayName = [string]$_.Name; Severity = [string]$_.Severity; Recipients = 'none configured' }
        })
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category `
            -Title $ctrl.Title -Severity 'Medium' -FrameworkIds $cit `
            -Detail "$($silent.Count) of $($active.Count) OAuth/consent alert policy(ies) are enabled but have no notification recipients, so a consent-phishing grant is recorded without anyone being told." `
            -CurrentValue "$($silent.Count) matching policies with no recipients" `
            -RequiredValue 'OAuth consent alert policy enabled with notification recipients' `
            -Remediation $ctrl.Remediation -AffectedObjects $affected
    }
}

function Test-TPControlDefenderPriorityAccounts {
    [CmdletBinding()] param()
    $cid = 'DEF-4.4'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $def = Get-TPRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Defender data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $def 'AntiPhishing')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'AntiPhishing was not collected; not assessed.'
        return
    }
    # The Defender "Priority account" user tag has no supported read surface (no Graph
    # endpoint, no EXO cmdlet). Rather than fabricate a result, surface the closest
    # machine-readable proxy — named-user impersonation protection in anti-phishing —
    # and direct the assessor to confirm the tag itself in the portal. Advisory
    # only: NotApplicable, never a false Satisfied/Gap/Partial.
    $ap = $def.Data['AntiPhishing']
    $proxyProtected = $false
    if ($ap -and $ap.Available) {
        $proxyProtected = @($ap.Policies | Where-Object {
            (Get-TPObjectField -Item $_ -Key 'EnableTargetedUserProtection') -and
            @(Get-TPObjectField -Item $_ -Key 'TargetedUsersToProtect' -Default @()).Count -gt 0
        }).Count -gt 0
    }
    $proxyNote = if ($proxyProtected) { 'Related signal: named-user impersonation protection IS configured in anti-phishing (see EXO-5.2).' } else { 'Related signal: no named-user impersonation protection is configured (see EXO-5.2).' }
    Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title "$($ctrl.Title) (Manual verification required)" -Severity 'Low' -FrameworkIds $cit `
        -Detail "This control requires manual verification — the Defender 'Priority account' user tag is not exposed by any supported Graph/EXO read API, so it cannot be assessed programmatically. Verify in Defender portal > Settings > Email & collaboration > User tags that executives and high-value mailboxes carry the Priority account tag. $proxyNote" `
        -Remediation $ctrl.Remediation
}

# ── DEF-4.5 Endpoint DLP Policy Active ───────────────────────────────────────
function Test-TPControlDefenderEndpointDLP {
    [CmdletBinding()] param()
    $cid = 'DEF-4.5'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $pvw = Get-TPRawData -Key 'Purview'
    if (-not $pvw -or -not $pvw.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Purview data not collected'; return
    }
    # Empty is not clean. The collector reported success, but this section
    # may not have landed — a failed sub-query leaves it absent or empty,
    # and reading that as compliance is a false pass on a control nobody
    # checked. Not assessed is the only honest verdict.
    if (-not (Test-TPSectionCollected $pvw 'DLPPolicies')) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'DLPPolicies was not collected; not assessed.'
        return
    }
    $endpointDLP = @($pvw.Data['DLPPolicies'] ?? @() | Where-Object { $_.Workloads -contains 'Devices' -or $_.Workloads -contains 'EndpointDevices' })
    if ($endpointDLP.Count -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "$($endpointDLP.Count) Endpoint DLP policy(ies) active. Sensitive data actions on endpoints (copy to USB, print, upload) are monitored or blocked."
    } else {
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail 'No Endpoint DLP policies detected. Users can copy sensitive files to USB drives, personal cloud storage, or print them without policy controls. Requires Defender for Endpoint + E5 Compliance or Microsoft 365 E5.' -Remediation $ctrl.Remediation
    }
}

# ── DEF-4.6 Attack Simulation Training Active ─────────────────────────────────
function Test-TPControlDefenderAttackSim {
    [CmdletBinding()] param()
    $cid = 'DEF-4.6'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $def = Get-TPRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Defender data not collected'; return
    }
    $sim = $def.Data['AttackSimulations']
    if (-not $sim -or -not (Get-TPObjectField -Item $sim -Key 'Available' -Default $false)) {
        $why = if (Test-TPGraphScopeMissing -Scope 'AttackSimulation.Read.All') { Get-TPConsentMissingDetail -Scope 'AttackSimulation.Read.All' }
               else { 'Attack Simulation Training data unavailable (requires AttackSimulation.Read.All consent + Defender for Office 365 P2; API is Global-cloud only); not assessed.' }
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -FrameworkIds $cit -Detail $why; return
    }
    $launched = [int](Get-TPObjectField -Item $sim -Key 'LaunchedCount' -Default 0)
    $total    = [int](Get-TPObjectField -Item $sim -Key 'Count' -Default 0)
    $scheduled = [int](Get-TPObjectField -Item $sim -Key 'ScheduledCount' -Default 0)
    if ($launched -gt 0) {
        Add-TPFinding -ControlId $cid -State 'Satisfied' -Category $ctrl.Category -Title $ctrl.Title -Severity 'Informational' -FrameworkIds $cit -Detail "Attack Simulation Training is in use — $launched launched/completed campaign(s) found. Users are being phishing-tested and trained."
    } elseif ($scheduled -gt 0) {
        # Scheduled but not yet run: nobody has been tested yet.
        Add-TPFinding -ControlId $cid -State 'Partial' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail "$scheduled simulation(s) are scheduled but none has run yet, so no user has been phishing-tested." -CurrentValue "0 launched, $scheduled scheduled" -RequiredValue 'At least one launched/recurring simulation campaign' -Remediation $ctrl.Remediation
    } else {
        $detail = if ($total -gt 0) { "Attack Simulation Training exists only as draft(s) ($total draft, 0 launched). No users have actually been phishing-tested." } else { 'No Attack Simulation Training campaigns exist. Users are never phishing-tested, so susceptibility to social-engineering attacks is unmeasured and untrained.' }
        Add-TPFinding -ControlId $cid -State 'Gap' -Category $ctrl.Category -Title $ctrl.Title -Severity $ctrl.Severity -FrameworkIds $cit -Detail $detail -CurrentValue "$launched launched, $total total campaign(s)" -RequiredValue 'At least one launched/recurring simulation campaign' -Remediation $ctrl.Remediation
    }
}

# ── DEF-4.7 Safe Links Policy Protects Office Applications ───────────────────
function Test-TPControlDefenderSafeLinksOffice {
    [CmdletBinding()] param()
    $cid = 'DEF-4.7'; $ctrl = Get-TPControlById -ControlId $cid; if (-not $ctrl) { return }
    $cit = Get-TPFrameworkCitations -ControlId $cid
    $def = Get-TPRawData -Key 'Defender-Policies'
    if (-not $def -or -not $def.Success) {
        Add-TPFinding -ControlId $cid -State 'NotApplicable' -Category $ctrl.Category -Title $ctrl.Title -Detail 'Defender data not collected'; return
    }
    $sl = $def.Data['SafeLinks']
    if (-not $sl -or -not $sl.Available) {
        Add-TPDefenderUnavailableFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Section $sl -Feature 'Safe Links'
        return
    }
    $policies = @(Get-TPInForcePolicies -Policies @(Get-TPObjectField -Item $sl -Key 'Policies' -Default @()) -Rules (Get-TPRuleList -Item $sl -Key 'Rules') -RulePolicyKey 'SafeLinksPolicy' -PresetKind 'ATP')
    # EnableSafeLinksForOffice (EnableSafeLinksForO365 is the old name; a bare
    # read of it threw under StrictMode and scored this control an Error).
    $office = { param($p) (Get-TPObjectField -Item $p -Key 'EnableSafeLinksForOffice' -Default $false) -eq $true -or (Get-TPObjectField -Item $p -Key 'EnableSafeLinksForO365' -Default $false) -eq $true }
    Add-TPPolicySetFinding -ControlId $cid -Control $ctrl -FrameworkIds $cit -Policies $policies `
        -Pass { & $office $_ } -Value { "EnableSafeLinksForOffice=$(& $office $_)" } `
        -PassDetail 'Safe Links checks links clicked in Office apps (Word, Excel, PowerPoint, Teams).' `
        -FailDetail 'Links in Office documents are not checked at click time for these recipients.' `
        -RequiredValue 'EnableSafeLinksForOffice = True'
}
