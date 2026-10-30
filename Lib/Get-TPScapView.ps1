#Requires -Version 7.0
#
# Get-TPScapView.ps1
# Dependencies: none beyond .NET (System.Xml)
# TenantPosture — NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Purpose: A separate, unscored view of SCAP scan results the operator brings
#   in: XCCDF results files from DISA SCC (SCAP Compliance Checker) or
#   OpenSCAP, plain XCCDF 1.1 / 1.2 or wrapped in an ARF asset report
#   collection, one file per host or several hosts per file. Per benchmark it
#   lists each rule with how many hosts passed or failed it and which hosts
#   failed, so the endpoint STIG / CIS baseline sits beside the tenant
#   assessment in one deliverable.
#
# A VIEW, LIKE THE BOD 25-01 SECTION: it creates no finding, changes no score,
# and judges nothing itself. TenantPosture did not scan these hosts and does
# not verify the results; it reports what the files say, and says so.
#
# HONESTY RULES (pinned by TP.ScapView.Tests.ps1)
#   - A rule is "Met on every host that checked it" only when every current
#     host that evaluated it reports pass and none reports fail, error,
#     unknown or notchecked. One failing host makes it Failing.
#   - error / unknown are "Not established" (the scanner could not tell);
#     notchecked is "Manual check" (SCC reports a manual STIG item this way);
#     notapplicable / notselected / informational never count as a pass.
#   - The hosts are the hosts in the files, not the fleet; every surface says so.
#   - A result older than -MaxAgeDays is listed as not current and left out of
#     the rule tallies: an old pass says nothing about the host today.
#   - Two results for one host and benchmark: the newest is used and the other
#     is listed as superseded, never merged.
#   - Nothing is called compliant.
#
# PARSING RULES (the files are untrusted input)
#   - DTDs are refused (XXE), no external resource is resolved, and a file is
#     read only below -MaxFileBytes. A file that fails these is listed with
#     the reason and skipped; the others still load.
#   - Elements are matched by local name, so XCCDF 1.1, 1.2 and ARF all read
#     the same way. Only the host name, scan time, benchmark, profile, score
#     and each rule's id, result, severity, title and identifiers are kept:
#     no IP address, MAC address or user name from the target facts.
#
# Data consumed: files under -Path (*.xml). Graph scopes / cmdlets: none. No network.

function Get-TPScapResultNames {
    # The result vocabulary XCCDF 1.2 defines (1.1 is a subset), each mapped
    # to the bucket this view counts it in.
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    return @{
        pass          = 'Pass'
        fixed         = 'Pass'
        fail          = 'Fail'
        error         = 'NotEstablished'
        unknown       = 'NotEstablished'
        notchecked    = 'Manual'
        notapplicable = 'NotApplicable'
        notselected   = 'NotApplicable'
        informational = 'NotApplicable'
    }
}

function Get-TPScapStatusNames {
    # The one copy of the per-rule status labels.
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param()
    return [ordered]@{
        Failing        = 'Failing on at least one host'
        NotEstablished = 'Not established on some hosts'
        Manual         = 'Manual check'
        Met            = 'Met on every host that checked it'
        NotApplicable  = 'Not applicable'
    }
}

function Read-TPScapResultFile {
    <#
    .SYNOPSIS
        Reads one XCCDF / ARF results file into TestResult records, refusing
        DTDs, external references and oversized files.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [ValidateRange(1024, 1073741824)] [long] $MaxFileBytes = 268435456,
        [ValidateRange(1, 200000)] [int] $MaxRuleResults = 50000
    )
    Set-StrictMode -Version Latest
    $out = [ordered]@{ File = [System.IO.Path]::GetFileName($Path); Ok = $false; Reason = ''; Results = @() }
    try {
        $item = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($item.PSIsContainer) { $out.Reason = 'Not a file.'; return $out }
        if ($item.Length -gt $MaxFileBytes) { $out.Reason = "Larger than the $([math]::Round($MaxFileBytes / 1MB)) MB limit."; return $out }
        if ($item.Length -eq 0) { $out.Reason = 'Empty file.'; return $out }

        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $settings.MaxCharactersFromEntities = 0
        $settings.MaxCharactersInDocument = $MaxFileBytes
        $settings.IgnoreComments = $true
        $settings.IgnoreProcessingInstructions = $true
        $doc = [System.Xml.XmlDocument]::new()
        $doc.XmlResolver = $null
        $reader = [System.Xml.XmlReader]::Create($item.FullName, $settings)
        try { $doc.Load($reader) } finally { $reader.Dispose() }

        # Rule titles, severities and identifiers from any benchmark in the
        # file, keyed by rule id (SCC and OpenSCAP both embed it).
        $rules = @{}
        foreach ($rule in @($doc.SelectNodes("//*[local-name()='Rule']"))) {
            $rid = $rule.GetAttribute('id')
            if (-not $rid -or $rules.ContainsKey($rid)) { continue }
            $title = @($rule.ChildNodes | Where-Object { $_.LocalName -eq 'title' } | Select-Object -First 1)
            $rules[$rid] = [ordered]@{
                Title    = $(if ($title.Count) { ($title[0].InnerText -replace '\s+', ' ').Trim() } else { '' })
                Severity = $rule.GetAttribute('severity')
                Idents   = @($rule.ChildNodes | Where-Object { $_.LocalName -eq 'ident' } | ForEach-Object { $_.InnerText.Trim() } | Where-Object { $_ })
            }
        }
        $benchTitle = ''; $benchVersion = ''; $benchId = ''
        $bench = @($doc.SelectNodes("//*[local-name()='Benchmark']") | Select-Object -First 1)
        if ($bench.Count) {
            $benchId = $bench[0].GetAttribute('id')
            $t = @($bench[0].ChildNodes | Where-Object { $_.LocalName -eq 'title' } | Select-Object -First 1)
            if ($t.Count) { $benchTitle = ($t[0].InnerText -replace '\s+', ' ').Trim() }
            $v = @($bench[0].ChildNodes | Where-Object { $_.LocalName -eq 'version' } | Select-Object -First 1)
            if ($v.Count) { $benchVersion = $v[0].InnerText.Trim() }
        }

        $records = [System.Collections.Generic.List[object]]::new()
        foreach ($tr in @($doc.SelectNodes("//*[local-name()='TestResult']"))) {
            $child = { param([string] $n) @($tr.ChildNodes | Where-Object { $_.LocalName -eq $n }) }
            $target = @(& $child 'target' | Select-Object -First 1)
            $host_ = if ($target.Count) { $target[0].InnerText.Trim() } else { '' }
            $fqdn = ''
            foreach ($facts in @(& $child 'target-facts')) {
                foreach ($f in @($facts.ChildNodes | Where-Object { $_.LocalName -eq 'fact' })) {
                    if ($f.GetAttribute('name') -match 'fqdn$') { $fqdn = $f.InnerText.Trim(); break }
                }
            }
            $bref = @(& $child 'benchmark' | Select-Object -First 1)
            $bid = if ($bref.Count -and $bref[0].GetAttribute('id')) { $bref[0].GetAttribute('id') } elseif ($bref.Count -and $bref[0].GetAttribute('href')) { $bref[0].GetAttribute('href') } else { $benchId }
            $prof = @(& $child 'profile' | Select-Object -First 1)
            $score = @(& $child 'score' | Select-Object -First 1)
            $end = $tr.GetAttribute('end-time'); if (-not $end) { $end = $tr.GetAttribute('start-time') }
            $endTime = $null
            $parsed = [datetime]::MinValue
            if ($end -and [datetime]::TryParse($end, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) { $endTime = $parsed }

            $rr = [System.Collections.Generic.List[object]]::new()
            foreach ($r in @(& $child 'rule-result')) {
                if ($rr.Count -ge $MaxRuleResults) { break }
                $res = @($r.ChildNodes | Where-Object { $_.LocalName -eq 'result' } | Select-Object -First 1)
                $rr.Add([ordered]@{
                    RuleId   = $r.GetAttribute('idref')
                    Result   = $(if ($res.Count) { $res[0].InnerText.Trim().ToLowerInvariant() } else { '' })
                    Severity = $r.GetAttribute('severity')
                    Idents   = @($r.ChildNodes | Where-Object { $_.LocalName -eq 'ident' } | ForEach-Object { $_.InnerText.Trim() } | Where-Object { $_ })
                })
            }
            $records.Add([ordered]@{
                Host             = $host_
                Fqdn             = $fqdn
                BenchmarkId      = [string]$bid
                BenchmarkTitle   = $benchTitle
                BenchmarkVersion = $benchVersion
                Profile          = $(if ($prof.Count) { $prof[0].GetAttribute('idref') } else { '' })
                Score            = $(if ($score.Count) { $score[0].InnerText.Trim() } else { '' })
                EndTime          = $endTime
                RuleResults      = $rr.ToArray()
                Rules            = $rules
                File             = $out.File
            })
        }
        if ($records.Count -eq 0) { $out.Reason = 'No XCCDF TestResult in the file.'; return $out }
        $out.Ok = $true
        $out.Results = $records.ToArray()
    } catch [System.Xml.XmlException] {
        $out.Reason = if ($_.Exception.Message -match 'DTD') { 'The file declares a DTD, which this reader refuses.' } else { 'Not well-formed XML.' }
    } catch {
        $out.Reason = 'The file could not be read.'
    }
    return $out
}

function Get-TPScapView {
    <#
    .SYNOPSIS
        Builds the SCAP results view from a folder (or one file) of XCCDF / ARF
        results. A view: no finding, no score.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory)] [string] $Path,
        [ValidateRange(1, 3650)] [int] $MaxAgeDays = 30,
        [ValidateRange(1, 20000)] [int] $MaxFiles = 5000,
        [ValidateRange(1, 10000)] [int] $HostListCap = 50,
        [datetime] $Now = [datetime]::UtcNow
    )
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    $item = Get-Item -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($null -eq $item) {
        return [ordered]@{ Available = $false; Note = 'The SCAP results path was not found.' }
    }
    # Two statements: an if-statement unrolls the array it yields, so a folder
    # holding one file would come back as that file, not a list of one.
    $files = @($item)
    if ($item.PSIsContainer) { $files = @(Get-ChildItem -LiteralPath $item.FullName -Filter '*.xml' -File -Recurse -ErrorAction SilentlyContinue | Sort-Object FullName) }
    $truncatedFiles = 0
    if ($files.Count -gt $MaxFiles) { $truncatedFiles = $files.Count - $MaxFiles; $files = @($files | Select-Object -First $MaxFiles) }

    $skipped = [System.Collections.Generic.List[object]]::new()
    $all = [System.Collections.Generic.List[object]]::new()
    foreach ($f in $files) {
        $read = Read-TPScapResultFile -Path $f.FullName
        if (-not $read.Ok) { $skipped.Add([ordered]@{ File = $read.File; Reason = $read.Reason }); continue }
        foreach ($r in @($read.Results)) {
            if (-not $r.Host) { $skipped.Add([ordered]@{ File = $read.File; Reason = 'A TestResult names no target host.' }); continue }
            $all.Add($r)
        }
    }
    if ($all.Count -eq 0) {
        return [ordered]@{
            Available = $false
            Note      = $(if ($files.Count -eq 0) { 'No .xml files were found at the SCAP results path.' } else { 'No readable XCCDF results were found at the SCAP results path.' })
            Skipped   = $skipped.ToArray()
        }
    }

    $map = Get-TPScapResultNames
    $names = Get-TPScapStatusNames
    $sevRank = @{ high = 0; medium = 1; low = 2 }
    $statusRank = @{ Failing = 0; NotEstablished = 1; Manual = 2; Met = 3; NotApplicable = 4 }
    $benchmarks = [System.Collections.Generic.List[object]]::new()

    foreach ($bg in @($all | Group-Object { $_.BenchmarkId } | Sort-Object Name)) {
        # Newest result per host; the rest are superseded, never merged.
        $hosts = [System.Collections.Generic.List[object]]::new()
        $use = [System.Collections.Generic.List[object]]::new()
        foreach ($hg in @($bg.Group | Group-Object { $_.Host.ToLowerInvariant() } | Sort-Object Name)) {
            $ordered = @($hg.Group | Sort-Object @{ Expression = { if ($null -ne $_.EndTime) { $_.EndTime } else { [datetime]::MinValue } }; Descending = $true })
            $newest = $ordered[0]
            $age = if ($null -ne $newest.EndTime) { [math]::Floor(($Now.ToUniversalTime() - $newest.EndTime).TotalDays) } else { $null }
            $current = ($null -ne $age -and $age -le $MaxAgeDays)
            $hosts.Add([ordered]@{
                Host       = $newest.Host
                Fqdn       = $newest.Fqdn
                Scanned    = $(if ($null -ne $newest.EndTime) { $newest.EndTime.ToString('yyyy-MM-dd', [cultureinfo]::InvariantCulture) } else { 'Not recorded' })
                AgeDays    = $age
                Current    = $current
                Profile    = $newest.Profile
                Score      = $newest.Score
                File       = $newest.File
                Superseded = @($ordered | Select-Object -Skip 1 | ForEach-Object { $_.File })
            })
            if ($current) { $use.Add($newest) }
        }

        $ruleIndex = @{}
        foreach ($r in $bg.Group) { foreach ($k in @($r.Rules.Keys)) { if (-not $ruleIndex.ContainsKey($k)) { $ruleIndex[$k] = $r.Rules[$k] } } }
        $tally = [ordered]@{}
        foreach ($res in $use) {
            foreach ($rr in @($res.RuleResults)) {
                if (-not $rr.RuleId) { continue }
                if (-not $tally.Contains($rr.RuleId)) {
                    $tally[$rr.RuleId] = [ordered]@{ Pass = 0; Fail = 0; NotEstablished = 0; Manual = 0; NotApplicable = 0; FailHosts = [System.Collections.Generic.List[string]]::new(); UnsureHosts = [System.Collections.Generic.List[string]]::new(); Severity = $rr.Severity; Idents = @($rr.Idents) }
                }
                $t = $tally[$rr.RuleId]
                $bucket = $map[$rr.Result]
                if (-not $bucket) { $bucket = 'NotEstablished' }   # a value XCCDF does not define is never a pass
                $t[$bucket]++
                if ($bucket -eq 'Fail') { $t.FailHosts.Add($res.Host) }
                elseif ($bucket -eq 'NotEstablished') { $t.UnsureHosts.Add($res.Host) }
                if (-not $t.Severity -and $rr.Severity) { $t.Severity = $rr.Severity }
            }
        }

        $rows = [System.Collections.Generic.List[object]]::new()
        foreach ($rid in @($tally.Keys)) {
            $t = $tally[$rid]
            $def = if ($ruleIndex.ContainsKey($rid)) { $ruleIndex[$rid] } else { $null }
            $sev = [string]$(if ($t.Severity) { $t.Severity } elseif ($def) { $def.Severity } else { '' })
            $idents = @(@($t.Idents) + @(if ($def) { $def.Idents }) | Where-Object { $_ } | Select-Object -Unique)
            $status = if ($t.Fail -gt 0) { 'Failing' }
                      elseif ($t.NotEstablished -gt 0) { 'NotEstablished' }
                      elseif ($t.Pass -gt 0 -and $t.Manual -eq 0) { 'Met' }
                      elseif ($t.Pass -gt 0) { 'NotEstablished' }
                      elseif ($t.Manual -gt 0) { 'Manual' }
                      else { 'NotApplicable' }
            $vid = @($idents | Where-Object { $_ -cmatch '\AV-\d+\z' } | Select-Object -First 1)
            $rows.Add([ordered]@{
                RuleId        = $rid
                Reference     = $(if ($vid.Count) { $vid[0] } else { $rid })
                Title         = $(if ($def -and $def.Title) { $def.Title } else { '' })
                Severity      = $sev.ToLowerInvariant()
                Category      = $(switch ($sev.ToLowerInvariant()) { 'high' { 'CAT I' } 'medium' { 'CAT II' } 'low' { 'CAT III' } default { '' } })
                Idents        = $idents
                Status        = $status
                StatusLabel   = $names[$status]
                Pass          = $t.Pass
                Fail          = $t.Fail
                NotEstablished = $t.NotEstablished
                Manual        = $t.Manual
                NotApplicable = $t.NotApplicable
                FailingHosts  = @($t.FailHosts | Sort-Object -Unique | Select-Object -First $HostListCap)
                FailingHostsNotShown = [math]::Max(0, @($t.FailHosts | Sort-Object -Unique).Count - $HostListCap)
                UnsureHosts   = @($t.UnsureHosts | Sort-Object -Unique | Select-Object -First $HostListCap)
            })
        }
        $sorted = @($rows | Sort-Object -Stable @{ Expression = { $statusRank[$_.Status] } }, @{ Expression = { $sevRank[$_.Severity] ?? 9 } }, @{ Expression = { -1 * $_.Fail } }, @{ Expression = { $_.Reference } })
        $counts = [ordered]@{}
        foreach ($k in $names.Keys) { $counts[$k] = @($sorted | Where-Object { $_.Status -eq $k }).Count }
        $failBySev = [ordered]@{ high = 0; medium = 0; low = 0 }
        foreach ($r in @($sorted | Where-Object { $_.Status -eq 'Failing' })) { if ($failBySev.Contains($r.Severity)) { $failBySev[$r.Severity]++ } }
        $first = $bg.Group[0]
        $benchmarks.Add([ordered]@{
            BenchmarkId     = $bg.Name
            Title           = $(if ($first.BenchmarkTitle) { $first.BenchmarkTitle } else { $bg.Name })
            Version         = $first.BenchmarkVersion
            Profiles        = @($bg.Group | ForEach-Object { $_.Profile } | Where-Object { $_ } | Sort-Object -Unique)
            HostsTotal      = $hosts.Count
            HostsCurrent    = $use.Count
            Hosts           = $hosts.ToArray()
            Counts          = $counts
            FailingBySeverity = $failBySev
            Rules           = $sorted
        })
    }

    return [ordered]@{
        Available    = $true
        Note         = ''
        GeneratedAt  = $Now.ToUniversalTime().ToString('o')
        MaxAgeDays   = $MaxAgeDays
        StatusNames  = $names
        FilesRead    = $files.Count - $skipped.Count
        FilesSkipped = $skipped.ToArray()
        FilesNotRead = $truncatedFiles
        Benchmarks   = $benchmarks.ToArray()
        Statements   = [ordered]@{
            Source   = 'Imported from SCAP scan results (XCCDF) produced by a SCAP tool such as DISA SCC or OpenSCAP. TenantPosture did not scan these hosts and did not verify the results; it reports what the files say.'
            Coverage = 'The hosts are the hosts in the imported files, not the whole fleet. A host with no file here was not reviewed.'
            NotThis  = 'This is not a compliance determination and carries no score. A rule met on every host that checked it was met when the scan ran.'
            Age      = "Results older than $MaxAgeDays days are listed as not current and left out of the rule counts."
        }
    }
}
