#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
.SYNOPSIS
    NRG.DistributionListWorksheet.Tests.ps1 — NRG Technology Services / NextLayerSec LLC
    Author: Matthew Levorson
    Purpose: Pins what the distribution-list scan WRITES and what it is allowed to DO.
               * the worksheet: one section per list in the .txt, one row per list per
                 recommendation in the .csv, each carrying members, current settings, the
                 recommended value, the finding, its Microsoft source and the NIST mapping;
               * parity: a verdict and the limitation that qualifies it read the same in the
                 text and the CSV (see NRG.OutputParity.Tests.ps1 for the assessment outputs);
               * the files hold tenant inventory, so they go through the restricted-file writer;
               * tenant text is hostile: a display name cannot forge a spreadsheet formula, a
                 line of the worksheet or a terminal escape;
               * the commands are TEXT: shown only beside a shortfall, never run, never written
                 to a .ps1 — proved by stubbed write cmdlets that throw, by static scans of every
                 new file, and by running the real entry script in a child process against
                 stand-in Microsoft modules that record any call outside Exchange reads;
               * the scan connects to Exchange Online and nothing else.
    Data keys consumed: EXO-DistributionLists.  Graph scopes / cmdlets: none (stubs only).
#>

Describe 'Distribution-list worksheet, safety and entry point' {

    BeforeAll {
        $script:Root = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:Root 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'NRG-Assessment'
        $script:Tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("nrg-dl-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force -Path $script:Tmp | Out-Null

        $script:L = { param([hashtable] $o = @{})
            $d = [ordered]@{ Name = 'x'; DisplayName = 'X'; PrimarySmtpAddress = 'x@contoso.com'; Guid = '11111111-1111-1111-1111-111111111111'; ListType = 'Distribution'
                RecipientTypeDetails = 'MailUniversalDistributionGroup'; IsDirSynced = $false; RecipientFilter = ''; Owners = @('Alice'); RequireSenderAuthenticationEnabled = $true
                AcceptMessagesOnlyFrom = @(); AcceptMessagesOnlyFromDLMembers = @(); AcceptMessagesOnlyFromSendersOrMembers = @(); ModerationEnabled = $false; ModeratedBy = @()
                MemberJoinRestriction = 'Closed'; MemberDepartRestriction = 'Open'; HiddenFromAddressListsEnabled = $false; PropertiesNotReturned = @()
                MemberStatus = 'Collected'; MemberCount = 2; MembersTruncated = $false; MemberError = ''
                Members = @(@{ UPN = 'alice@contoso.com'; DisplayName = 'Alice Smith' }, @{ UPN = 'dana@contoso.com'; DisplayName = 'Dana' })
                ExternalMembers = @(); NestedGroups = @(); UnclassifiedMemberCount = 0 }
            foreach ($k in $o.Keys) { $d[$k] = $o[$k] }
            [pscustomobject]$d }
        $script:Std = { param([hashtable] $o = @{})
            $raw = [ordered]@{ DistributionListMaxMembers = @(); DistributionListAllowedJoinRestrictions = @(); DistributionListAllowedDepartRestrictions = @(); DistributionListExternalMembers = @() }
            foreach ($k in $o.Keys) { $raw[$k] = $o[$k] }
            Get-NRGDistributionListStandards -Standards $raw }
        $script:Raw = { param($Lists, [hashtable] $Sections = @{})
            $s = @{ DistributionGroups = 'Collected'; DynamicDistributionGroups = 'Collected'; AcceptedDomains = 'Collected'; Members = 'Collected' }; foreach ($k in $Sections.Keys) { $s[$k] = $Sections[$k] }
            @{ CollectorId = 'EXO-DistributionLists'; CollectedAt = (Get-Date).ToString('o'); Success = $true; Data = @{ Lists = @($Lists); SectionStatus = $s; Stats = @{ MemberReadLimit = 5000 }; TenantDomain = 'contoso.com'; AcceptedDomains = @('contoso.com') } } }
        # Evaluate + publish; returns the publish result, the raw text of both files, and the parsed CSV.
        $script:Publish = { param($Lists, $Standards = $null, [string] $Base = 'contoso-20261002-120000', [hashtable] $Sections = @{})
            Clear-NRGState
            if ($null -eq $Standards) { $Standards = & $script:Std }
            $raw = & $script:Raw $Lists $Sections
            Set-NRGRawData -Key 'EXO-DistributionLists' -Data $raw
            Test-NRGControlDistributionLists -Standards $Standards
            $dir = Join-Path $script:Tmp ([guid]::NewGuid().ToString('N').Substring(0, 6))
            $out = Publish-NRGDistributionListWorksheet -OutputDirectory $dir -BaseName $Base -Metadata @{ TenantDomain = 'contoso.com'; ToolVersion = 'test' } -Raw $raw -Standards $Standards
            [pscustomobject]@{ Out = $out; Txt = (Get-Content -LiteralPath $out.TextPath -Raw -Encoding utf8); CsvText = (Get-Content -LiteralPath $out.CsvPath -Raw -Encoding utf8); Csv = @(Import-Csv -LiteralPath $out.CsvPath -Encoding utf8) } }

        $script:Mix = @(
            (& $script:L @{ Name = 'sales'; DisplayName = 'Sales'; PrimarySmtpAddress = 'sales@contoso.com'; Guid = '22222222-2222-2222-2222-222222222222'; RequireSenderAuthenticationEnabled = $false; Owners = @(); MemberJoinRestriction = 'Open'
                ExternalMembers = @(@{ UPN = 'v@fabrikam.com'; DisplayName = 'Vendor' }); NestedGroups = @(@{ UPN = 'eng@contoso.com'; DisplayName = 'Eng' }); MemberCount = 4 }),
            (& $script:L @{ Name = 'hr'; DisplayName = 'HR'; PrimarySmtpAddress = 'hr@contoso.com'; Guid = '33333333-3333-3333-3333-333333333333' }),
            (& $script:L @{ Name = 'sparse'; DisplayName = 'Sparse'; PrimarySmtpAddress = 'sparse@contoso.com'; Guid = '44444444-4444-4444-4444-444444444444'; Owners = $null; RequireSenderAuthenticationEnabled = $null
                ModerationEnabled = $null; MemberJoinRestriction = $null; MemberDepartRestriction = $null; HiddenFromAddressListsEnabled = $null; AcceptMessagesOnlyFrom = $null; AcceptMessagesOnlyFromDLMembers = $null; AcceptMessagesOnlyFromSendersOrMembers = $null; ModeratedBy = $null }),
            (& $script:L @{ Name = 'dyn'; DisplayName = 'Dynamic'; PrimarySmtpAddress = 'dyn@contoso.com'; Guid = '55555555-5555-5555-5555-555555555555'; ListType = 'Dynamic'; RecipientTypeDetails = 'DynamicDistributionGroup'; RecipientFilter = "(RecipientType -eq 'UserMailbox')"; MemberJoinRestriction = $null; MemberDepartRestriction = $null })
        )
        $script:AllApproved = & $script:Std @{ DistributionListMaxMembers = @('3'); DistributionListAllowedJoinRestrictions = @('Closed'); DistributionListAllowedDepartRestrictions = @('Closed'); DistributionListExternalMembers = @('Prohibited') }
        $script:R = & $script:Publish $script:Mix $script:AllApproved
        # The findings behind $script:R: later tests rebuild module state with other lists.
        $script:RFindings = @(Get-NRGFindings)
    }
    AfterAll { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue; Clear-NRGState; Remove-Module 'NRG-Assessment' -Force -ErrorAction SilentlyContinue }

    Context 'The files' {
        It 'writes <base>-distribution-lists.txt and .csv' {
            Split-Path -Leaf $script:R.Out.TextPath | Should -Be 'contoso-20261002-120000-distribution-lists.txt'
            Split-Path -Leaf $script:R.Out.CsvPath  | Should -Be 'contoso-20261002-120000-distribution-lists.csv'
            Test-Path -LiteralPath $script:R.Out.TextPath | Should -BeTrue
            Test-Path -LiteralPath $script:R.Out.CsvPath  | Should -BeTrue
        }
        It 'writes exactly two files, a text and a CSV: no script is produced' {
            @(Get-ChildItem -LiteralPath (Split-Path -Parent $script:R.Out.TextPath) -File | ForEach-Object Extension | Sort-Object) | Should -Be @('.csv', '.txt')
        }
        It 'the base name is reduced to letters, digits and hyphens and a traversal sequence is refused' {
            $r = & $script:Publish @((& $script:L)) $null '../../etc/pass wd'
            Split-Path -Leaf $r.Out.TextPath | Should -Be 'etcpasswd-distribution-lists.txt'
            { Publish-NRGDistributionListWorksheet -OutputDirectory (Join-Path $script:Tmp '..\x') -BaseName 'a' -Raw (& $script:Raw @()) -Findings @() } | Should -Throw '*traversal*'
        }
        It 'goes through the restricted-file writer for BOTH files (they hold tenant inventory)' {
            Mock -ModuleName NRG-Assessment Set-NRGSensitiveFileContent { }
            Clear-NRGState
            $raw = & $script:Raw @((& $script:L))
            Set-NRGRawData -Key 'EXO-DistributionLists' -Data $raw
            Test-NRGControlDistributionLists -Standards (& $script:Std)
            $null = Publish-NRGDistributionListWorksheet -OutputDirectory (Join-Path $script:Tmp 'mocked') -BaseName 'mocked' -Metadata @{ TenantDomain = 'contoso.com' } -Raw $raw
            Should -Invoke -ModuleName NRG-Assessment Set-NRGSensitiveFileContent -Times 2 -Exactly -ParameterFilter { $Path -like '*-distribution-lists.txt' -or $Path -like '*-distribution-lists.csv' }
        }
        It 'on Linux/macOS the files are owner-only (0600)' -Skip:($IsWindows) {
            foreach ($p in $script:R.Out.TextPath, $script:R.Out.CsvPath) { (& stat -c '%a' $p) | Should -Be '600' }
        }
        It 'the CSV opens with a byte-order mark so a spreadsheet reads non-ASCII names' {
            $b = [System.IO.File]::ReadAllBytes($script:R.Out.CsvPath)
            ($b[0..2] -join ',') | Should -Be '239,187,191'
        }
    }

    Context 'The text worksheet: one section per list, with everything an administrator needs' {
        It 'opens with the scope, the read-only statement, the frameworks and the NRG standards status' {
            $script:R.Txt | Should -Match 'distribution lists only'
            $script:R.Txt | Should -Match 'Every other area was NOT assessed'
            $script:R.Txt | Should -Match 'Read-only\. This tool read the lists and changed nothing'
            $script:R.Txt | Should -Match 'No CIS benchmark item'
            $script:R.Txt | Should -Match 'No SCuBA rule'
            $script:R.Txt | Should -Match 'DistributionListMaxMembers: approved, 3 direct members'
        }
        It 'has one LIST section per list, in a stable order' {
            ([regex]::Matches($script:R.Txt, '(?m)^LIST \d+ of 4: ')).Count | Should -Be 4
        }
        It 'each section shows the members, the current settings, and each recommendation''s current value, recommended value, finding, source and NIST mapping' {
            $t = $script:R.Txt
            $t | Should -Match 'alice@contoso.com \(Alice Smith\)'
            $t | Should -Match 'RequireSenderAuthenticationEnabled\s+False'
            $t | Should -Match 'Recommended: True \(Microsoft documented default\)'
            $t | Should -Match 'Source: https://learn\.microsoft\.com/exchange/'
            $t | Should -Match 'AC-3 Access Enforcement; SC-7 Boundary Protection; SI-8 Spam Protection'
            $t | Should -Match "this tool's mapping, not NIST text"
            $t | Should -Match 'External members \(outside the tenant''s accepted domains\):\s+v@fabrikam.com \(Vendor\)'
            $t | Should -Match 'Nested groups \(their members are NOT expanded here\):'
        }
        It 'says "no framework item verified" where none was, and never cites a SCuBA or CIS identifier' {
            $script:R.Txt | Should -Match 'no framework item verified'
            $script:R.Txt | Should -Not -Match 'MS\.[A-Z]+\.\d'
        }
        It 'a dynamic list shows its membership rule and "not applicable" for join and leave' {
            $script:R.Txt | Should -Match "Membership rule \(dynamic list\): \(RecipientType -eq 'UserMailbox'\)"
            $script:R.Txt | Should -Match 'MemberJoinRestriction\s+not applicable \(dynamic list\)'
        }
        It 'the summary adds up to the list count on every row (Met + shortfall + not assessed + ... = lists)' {
            foreach ($row in $script:R.Out.Model.Summary) {
                $sum = (@($script:R.Out.Model.StatusOrder | ForEach-Object { [int]$row.$_ }) | Measure-Object -Sum).Sum
                $sum | Should -Be $row.Total -Because $row.Id
                $row.Total | Should -Be 4 -Because "$($row.Id) has a row for every list"
            }
        }
        It 'NotApplicable is never blurred: reported only, not assessed, no approved standard and does not apply are four words' {
            $statuses = @($script:R.Csv | ForEach-Object Status | Sort-Object -Unique)
            $statuses | Should -Contain 'Reported only'
            $statuses | Should -Contain 'Not assessed'
            $statuses | Should -Contain 'Does not apply'
            $statuses | Should -Contain 'Shortfall'
            $statuses | Should -Contain 'Meets'
        }
    }

    Context 'Parity: the same verdict and limitation in the text and the CSV' {
        It 'the CSV has one row per list per recommendation plus the scan row' {
            $recs = @((Get-NRGDistributionListBaseline).Recommendations).Count
            $script:R.Csv.Count | Should -Be (1 + 4 * $recs)
            $script:R.Csv[0].Id | Should -Be 'DL-0.1'
        }
        It 'every CSV row''s Finding text appears verbatim in the text worksheet, under the same status word' {
            foreach ($row in $script:R.Csv) {
                $script:R.Txt.Contains($row.Finding) | Should -BeTrue -Because "$($row.List) $($row.Id)"
                $script:R.Txt.Contains("[$($row.Status.ToUpperInvariant())] $($row.Id)") -or $row.Id -eq 'DL-0.1' | Should -BeTrue -Because "$($row.List) $($row.Id) status $($row.Status)"
            }
        }
        It 'every row''s Finding is the evaluator''s own Detail for that list and control' {
            $findings = @($script:RFindings)
            foreach ($row in ($script:R.Csv | Where-Object Id -ne 'DL-0.1')) {
                $f = $findings | Where-Object { $_.ControlId -eq $row.Id -and $_.Instance -eq $row.ListAddress } | Select-Object -First 1
                $f | Should -Not -BeNullOrEmpty -Because "$($row.ListAddress) $($row.Id)"
                $row.Finding | Should -Be ([string]$f.Detail).Trim()
            }
        }
        It 'a not-assessed row carries its limitation ("Not read:") in BOTH outputs, and the scan row carries the scan limits' {
            $na = $script:R.Csv | Where-Object { $_.Status -like 'Not assessed*' }
            @($na).Count | Should -BeGreaterThan 0
            foreach ($row in $na) { $row.Finding | Should -Match 'Not read: ' }
            $scan = $script:R.Csv | Where-Object Id -eq 'DL-0.1'
            $scan.Finding | Should -Match 'Unified'
            $script:R.Txt | Should -Match 'Unified'
        }
        It 'a verdict never reads as passing in one output and failing in the other' {
            foreach ($row in ($script:R.Csv | Where-Object { $_.Status -in 'Shortfall', 'Partly meets' })) {
                $script:R.Txt | Should -Match ([regex]::Escape("[$($row.Status.ToUpperInvariant())] $($row.Id)"))
            }
            foreach ($row in ($script:R.Csv | Where-Object { $_.Status -eq 'Meets' })) { $row.Status | Should -Not -Be 'Shortfall' }
        }
    }

    Context 'Every outcome is visible: a list with no data is not a clean list' {
        It 'a failed section shows as Not assessed in the scan row and the header, not as an empty clean worksheet' {
            $r = & $script:Publish @() $null 'failed' @{ DistributionGroups = 'Failed' }
            $r.Out.ListCount | Should -Be 0
            $r.Txt | Should -Match 'Scan result \(Not assessed\)'
            $r.Txt | Should -Match 'were not read \(section Failed\)'
            ($r.Csv | Where-Object Id -eq 'DL-0.1').Status | Should -Be 'Not assessed'
        }
        It 'a list whose members could not be read says so on the list, and counts no members' {
            $r = & $script:Publish @((& $script:L @{ MemberStatus = 'Failed'; MemberCount = $null; Members = @(); MemberError = 'throttled (429)' })) $null 'mem' @{ Members = 'Failed' }
            $r.Txt | Should -Match 'Members read: not read \(Failed\)'
            $r.Txt | Should -Match 'Member read error: throttled \(429\)'
            $r.Txt | Should -Match '\(not read\)'
        }
    }

    Context 'Commands are text, shown only beside a shortfall' {
        It 'a command is printed for a Shortfall or Partly meets row and for no other status' {
            foreach ($row in $script:R.Csv) {
                if ($row.Status -in 'Shortfall', 'Partly meets') { $true | Should -BeTrue }
                else { $row.CommandTextOnly | Should -BeNullOrEmpty -Because "$($row.List) $($row.Id) is '$($row.Status)'" }
            }
            ($script:R.Csv | Where-Object { $_.CommandTextOnly }).Count | Should -BeGreaterThan 3
        }
        It 'the open, ownerless list gets the exact commands, each labeled TEXT ONLY' {
            $script:R.Txt | Should -Match "Set-DistributionGroup -Identity 'sales@contoso.com' -RequireSenderAuthenticationEnabled \`$true"
            $script:R.Txt | Should -Match "Set-DistributionGroup -Identity 'sales@contoso.com' -ManagedBy @\{Add='<owner-address>'\}"
            $script:R.Txt | Should -Match "Set-DistributionGroup -Identity 'sales@contoso.com' -MemberJoinRestriction Closed"
            $script:R.Txt | Should -Match 'TEXT ONLY, this tool never runs it'
            $script:R.Txt | Should -Match "Remove-DistributionGroupMember -Identity 'sales@contoso.com' -Member '<member-address>'"
        }
        It 'every printed command is one statement with a safely quoted identity' {
            foreach ($row in ($script:R.Csv | Where-Object CommandTextOnly)) {
                $row.CommandTextOnly | Should -Match '^(Set-(Dynamic)?DistributionGroup|Get-(Dynamic)?DistributionGroupMember|Remove-DistributionGroupMember) -Identity ''[^'']+'' '
                $row.CommandTextOnly | Should -Not -Match '[;|&`]'
            }
        }
        It 'a dynamic list is given the dynamic cmdlet only' {
            foreach ($row in ($script:R.Csv | Where-Object { $_.ListAddress -eq 'dyn@contoso.com' -and $_.CommandTextOnly })) { $row.CommandTextOnly | Should -Match '^(Set|Get)-Dynamic' }
        }
        It 'no module-loaded file defines or holds an executable command string for the worksheet: the catalog is JSON, the publisher only substitutes' {
            $pub = Get-Content -LiteralPath (Join-Path $script:Root 'Publishers/Publish-NRGDistributionListWorksheet.ps1') -Raw
            $pub | Should -Not -Match '(?m)^\s*Set-(Dynamic)?DistributionGroup\b'
            @(Get-ChildItem -LiteralPath (Join-Path $script:Root 'Publishers'), (Join-Path $script:Root 'Lib'), (Join-Path $script:Root 'Collectors'), (Join-Path $script:Root 'Evaluators') -Recurse -Filter '*.ps1' |
                Select-String -Pattern '(?m)^\s*(Set|Remove|Add|New)-(Dynamic)?DistributionGroup(Member)?\b' | Where-Object { $_.Line -notmatch '^\s*#' }).Count | Should -Be 0
        }
    }

    Context 'Tenant text is hostile' {
        BeforeAll {
            $esc = [string][char]27; $rlo = [string][char]0x202E
            $script:Hostile = @(
                (& $script:L @{ Name = 'h1'; DisplayName = '=HYPERLINK("http://evil.example","x")'; PrimarySmtpAddress = 'h1@contoso.com'; Guid = '66666666-6666-6666-6666-666666666666'
                    Owners = @('@SUM(1+1)'); Members = @(@{ UPN = '+cmd@evil.tld'; DisplayName = '-2+3' }, @{ UPN = 'ok@contoso.com'; DisplayName = "Line1`nFORGED [SHORTFALL] DL-9.9 injected" }) }),
                (& $script:L @{ Name = 'h2'; DisplayName = "Esc${esc}[31m red ${rlo}gnp.exe"; PrimarySmtpAddress = 'h2@contoso.com'; Guid = '77777777-7777-7777-7777-777777777777' }))
            $script:H = & $script:Publish $script:Hostile
        }
        It 'a leading = + - @ is defused in every CSV cell, so a spreadsheet does not read a name as a formula' {
            foreach ($row in $script:H.Csv) { foreach ($p in $row.PSObject.Properties) { [string]$p.Value | Should -Not -Match '^[=+\-@]' -Because "$($row.List) / $($p.Name)" } }
            ($script:H.Csv | Where-Object ListAddress -eq 'h1@contoso.com' | Select-Object -First 1).List | Should -Be '''=HYPERLINK("http://evil.example","x")'
        }
        It 'a newline in a name cannot forge a line of the worksheet, and a CSV row stays one line' {
            $script:H.Txt | Should -Not -Match '(?m)^FORGED'
            $script:H.Txt | Should -Match 'Line1 FORGED \[SHORTFALL\] DL-9\.9 injected'
            $script:H.CsvText.Split("`n").Count | Should -Be ($script:H.Csv.Count + 2) -Because 'header + rows + trailing newline: no row was split by a name'
        }
        It 'no escape character and no bidirectional override reaches either file' {
            foreach ($t in $script:H.Txt, $script:H.CsvText) {
                $t | Should -Not -Match '\x1b'
                $t | Should -Not -Match '[‪-‮⁦-⁩]'
            }
        }
        It 'a member list too long for a spreadsheet cell is cut with a marker, and the text worksheet keeps every member' {
            $many = 1..2500 | ForEach-Object { @{ UPN = "user$_@contoso.com"; DisplayName = "User Number $_ With A Long Name" } }
            $r = & $script:Publish @((& $script:L @{ Members = $many; MemberCount = 2500 })) $null 'many'
            $r.Csv[1].Members.Length | Should -BeLessThan 32767
            $r.Csv[1].Members | Should -Match 'cut at 30000 characters'
            ([regex]::Matches($r.Txt, '(?m)^    user\d+@contoso\.com')).Count | Should -Be 2500
        }
    }

    Context 'A full run never reaches a write cmdlet (stubs that throw)' {
        BeforeAll {
            foreach ($w in 'Set-DistributionGroup', 'Set-DynamicDistributionGroup', 'Add-DistributionGroupMember', 'Remove-DistributionGroupMember', 'New-DistributionGroup', 'Remove-DistributionGroup', 'Update-DistributionGroupMember', 'New-DynamicDistributionGroup', 'Set-Mailbox') {
                Set-Item -Path "function:global:$w" -Value { throw 'A WRITE CMDLET WAS CALLED' }
            }
        }
        AfterAll { foreach ($w in 'Set-DistributionGroup', 'Set-DynamicDistributionGroup', 'Add-DistributionGroupMember', 'Remove-DistributionGroupMember', 'New-DistributionGroup', 'Remove-DistributionGroup', 'Update-DistributionGroupMember', 'New-DynamicDistributionGroup', 'Set-Mailbox') { Remove-Item -Path "function:global:$w" -ErrorAction SilentlyContinue } }
        It 'evaluating and publishing shortfalls, with their commands in the output, throws nothing and registers no exception' {
            { $null = & $script:Publish $script:Mix $script:AllApproved } | Should -Not -Throw
            @(Get-NRGExceptions | Where-Object Message -Match 'WRITE CMDLET').Count | Should -Be 0
            @($script:R.Csv | Where-Object CommandTextOnly).Count | Should -BeGreaterThan 0 -Because 'the commands really are in the output, as text'
        }
    }

    Context 'Static: read-only, Exchange-only, no execution of text' {
        BeforeAll {
            $script:NewFiles = @('Collectors/EXO/Invoke-NRGCollectDistributionLists.ps1', 'Evaluators/Test-NRGControlDistributionLists.ps1', 'Publishers/Publish-NRGDistributionListWorksheet.ps1',
                'Lib/Get-NRGDistributionListBaseline.ps1', 'Lib/Connect-NRGExchangeOnly.ps1', 'Invoke-NRGDistributionListScan.ps1')
            $script:Ast = @{}
            foreach ($f in $script:NewFiles) { $script:Ast[$f] = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root $f), [ref]$null, [ref]$null) }
            $script:Calls = { param($Ast) @($Ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { "$($_.GetCommandName())" } | Where-Object { $_ }) }
        }
        It 'every new file parses and requires PowerShell 7' {
            foreach ($f in $script:NewFiles) {
                $e = $null; [void][System.Management.Automation.Language.Parser]::ParseFile((Join-Path $script:Root $f), [ref]$null, [ref]$e)
                @($e).Count | Should -Be 0 -Because $f
                (Get-Content -LiteralPath (Join-Path $script:Root $f) -TotalCount 2) -join "`n" | Should -Match '#Requires -Version 7\.0'
            }
        }
        It 'the collector and evaluator call no tenant write cmdlet: only Get-* reach Exchange, and every Exchange command is resolved by a literal Get-* name' {
            $write = '^(Set|New|Remove|Add|Update|Enable|Disable|Clear|Move|Rename|Restart|Grant|Revoke|Start|Stop|Import|Export|Invoke)-'
            $okInternal = '-NRG|^(Set-StrictMode|Start-Sleep|Import-Module)$'
            foreach ($f in 'Collectors/EXO/Invoke-NRGCollectDistributionLists.ps1', 'Evaluators/Test-NRGControlDistributionLists.ps1') {
                $bad = @(& $script:Calls $script:Ast[$f] | Where-Object { $_ -match $write -and $_ -notmatch $okInternal })
                $bad | Should -BeNullOrEmpty -Because "$f must not call a write cmdlet"
                @(& $script:Calls $script:Ast[$f] | Where-Object { $_ -match '^Invoke-(Expression|Command)$|^iex$' }) | Should -BeNullOrEmpty
            }
            $names = @($script:Ast['Collectors/EXO/Invoke-NRGCollectDistributionLists.ps1'].FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] -and "$($n.GetCommandName())" -eq 'Get-NRGExoCommand' }, $true))
            $text = Get-Content -LiteralPath (Join-Path $script:Root 'Collectors/EXO/Invoke-NRGCollectDistributionLists.ps1') -Raw
            foreach ($m in [regex]::Matches($text, "foreach \(\`$n in ((?:'[^']+',? ?)+)\)")) {
                foreach ($lit in [regex]::Matches($m.Groups[1].Value, "'([^']+)'")) { $lit.Groups[1].Value | Should -Match '^Get-' }
            }
            @($names).Count | Should -BeGreaterThan 0
        }
        It 'no new file evaluates text: no Invoke-Expression, Invoke-Command, Start-Process, Add-Type or script-block creation' {
            foreach ($f in $script:NewFiles) {
                @(& $script:Calls $script:Ast[$f] | Where-Object { $_ -match '^(Invoke-Expression|Invoke-Command|Start-Process|Add-Type|iex)$' }) | Should -BeNullOrEmpty -Because $f
                (Get-Content -LiteralPath (Join-Path $script:Root $f) -Raw) | Should -Not -Match '\[scriptblock\]::Create|ExecutionContext\.InvokeCommand'
            }
        }
        It 'the scan connects to Exchange Online and nothing else: no Graph, Purview, Teams, SharePoint or Connect-NRGServices in any new file' {
            foreach ($f in $script:NewFiles) {
                $calls = & $script:Calls $script:Ast[$f]
                @($calls | Where-Object { $_ -match '^(Connect-MgGraph|Connect-IPPSSession|Connect-MicrosoftTeams|Connect-SPOService|Connect-PnPOnline|Connect-NRGServices|Invoke-NRGGraphRequest|Invoke-MgGraphRequest|Get-Mg[A-Z]|Get-NRGGraphAllPages|Get-NRGPowerPlatformToken)' }) | Should -BeNullOrEmpty -Because $f
            }
            @(& $script:Calls $script:Ast['Lib/Connect-NRGExchangeOnly.ps1'] | Where-Object { $_ -match '^Connect-' } | Sort-Object -Unique) | Should -Be @('Connect-ExchangeOnline')
        }
        It 'the entry script states the scope and the read-only promise to the operator before it signs in' {
            $t = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-NRGDistributionListScan.ps1') -Raw
            $t | Should -Match 'Connects to Exchange Online ONLY'
            $t | Should -Match 'NOT assessed: Entra ID, Defender, Teams, SharePoint, Intune, Purview, Power Platform, DNS'
            $t | Should -Match 'Commands in the worksheet are text only'
            $t.IndexOf('Connects to Exchange Online ONLY') | Should -BeLessThan $t.IndexOf('Connect-NRGExchangeOnly @connectParams')
        }
        It 'the entry script validates its inputs and its output path' {
            $t = Get-Content -LiteralPath (Join-Path $script:Root 'Invoke-NRGDistributionListScan.ps1') -Raw
            $t | Should -Match 'Set-StrictMode -Version Latest'
            $t | Should -Match ([regex]::Escape('\.\.[/\\]'))
            $t | Should -Match "tenantTag -replace '\[\^a-zA-Z0-9-\]'"
            foreach ($p in 'UserPrincipalName', 'DelegatedOrganization', 'TenantId', 'OutputPath', 'MemberReadLimit', 'KeepSession') { $script:Ast['Invoke-NRGDistributionListScan.ps1'].ParamBlock.Parameters.Name.VariablePath.UserPath | Should -Contain $p }
        }
        It 'the DL series is documented where the other series are' {
            (Get-Content -LiteralPath (Join-Path $script:Root 'docs/NRG-DISTRIBUTION-LISTS.md') -Raw) | Should -Match 'DL-1\.1'
            (Get-Content -LiteralPath (Join-Path $script:Root 'README.md') -Raw) | Should -Match 'Invoke-NRGDistributionListScan\.ps1'
            (Get-Content -LiteralPath (Join-Path $script:Root 'CHANGELOG.md') -Raw) | Should -Match 'distribution-list'
            (Get-Content -LiteralPath (Join-Path $script:Root 'docs/KNOWN-ISSUES.md') -Raw) | Should -Match '(?i)distribution-list'
        }
    }

    Context 'Connect-NRGExchangeOnly (stubbed Exchange module, nothing else installed)' {
        BeforeAll {
            $script:ConnLog = @{ Calls = @(); Sessions = @() }
            function global:Connect-ExchangeOnline { param([switch] $ShowBanner, [switch] $DisableWAM, $UserPrincipalName, $DelegatedOrganization, $ErrorAction) $script:ConnLog.Calls += , @($PSBoundParameters.Keys | Sort-Object) ; if ($script:ConnLog.Fail) { throw $script:ConnLog.Fail } }
            function global:Get-ConnectionInformation { param($ErrorAction) @($script:ConnLog.Sessions) }
            foreach ($n in 'Connect-MgGraph', 'Connect-IPPSSession', 'Connect-MicrosoftTeams') { Set-Item -Path "function:global:$n" -Value { throw 'A NON-EXCHANGE SERVICE WAS CONNECTED' } }
        }
        AfterAll { foreach ($n in 'Connect-ExchangeOnline', 'Get-ConnectionInformation', 'Connect-MgGraph', 'Connect-IPPSSession', 'Connect-MicrosoftTeams') { Remove-Item -Path "function:global:$n" -ErrorAction SilentlyContinue } }
        BeforeEach { $script:ConnLog = @{ Calls = @(); Sessions = @() } }

        It 'connects with no banner, passes DisableWAM, the sign-in hint and the GDAP organization, and touches no other service' {
            $r = Connect-NRGExchangeOnly -UserPrincipalName 'tech@msp.example' -DelegatedOrganization 'client.onmicrosoft.com'
            $r.EXO | Should -BeTrue
            @($script:ConnLog.Calls).Count | Should -Be 1
            @($script:ConnLog.Calls[0]) | Should -Contain 'DelegatedOrganization'
            @($script:ConnLog.Calls[0]) | Should -Contain 'DisableWAM'
            @($script:ConnLog.Calls[0]) | Should -Contain 'ShowBanner'
            @($script:ConnLog.Calls[0]) | Should -Contain 'UserPrincipalName'
        }
        It 'a failed sign-in is a reported failure with the cause, not a throw' {
            $script:ConnLog.Fail = 'AADSTS50076: MFA required'
            $r = Connect-NRGExchangeOnly
            $r.EXO | Should -BeFalse
            $r.Error | Should -Match 'AADSTS50076'
        }
        It 'reuses an existing session only when it is provably the expected tenant' {
            $tid = '00000000-0000-0000-0000-00000000abcd'
            $script:ConnLog.Sessions = @([pscustomobject]@{ State = 'Connected'; IsEopSession = $false; TenantID = $tid; Name = 'ExchangeOnline_1' })
            $r = Connect-NRGExchangeOnly -ExpectedTenantId $tid
            $r.ReusedSession | Should -BeTrue; @($script:ConnLog.Calls).Count | Should -Be 0
            $null = Connect-NRGExchangeOnly -ExpectedTenantId '11111111-1111-1111-1111-111111111111'
            @($script:ConnLog.Calls).Count | Should -Be 1 -Because 'a session for another tenant is not reused'
        }
        It 'a Security & Compliance session is never mistaken for Exchange Online' {
            $script:ConnLog.Sessions = @([pscustomobject]@{ State = 'Connected'; IsEopSession = $true; TenantID = '00000000-0000-0000-0000-00000000abcd'; Name = 'ExchangeOnlineProtection_2' })
            $r = Connect-NRGExchangeOnly -ExpectedTenantId '00000000-0000-0000-0000-00000000abcd'
            $r.ReusedSession | Should -BeFalse
        }
        It 'a GDAP run with no tenant id never reuses a session that may be the operator''s own tenant' {
            $script:ConnLog.Sessions = @([pscustomobject]@{ State = 'Connected'; IsEopSession = $false; TenantID = '00000000-0000-0000-0000-00000000abcd'; Name = 'ExchangeOnline_1' })
            $null = Connect-NRGExchangeOnly -DelegatedOrganization 'client.onmicrosoft.com'
            @($script:ConnLog.Calls).Count | Should -Be 1
        }
    }

    Context 'The real entry script, in a child process, against stand-in Microsoft modules' {
        BeforeAll {
            $script:Mods = Join-Path $script:Tmp 'mods'
            $script:Marker = Join-Path $script:Tmp 'marker.txt'
            New-Item -ItemType Directory -Path $script:Mods -Force | Out-Null
            $exoFloor = & $script:Mod { Get-NRGExoModuleFloor }
            $exoVersion = [string]$exoFloor.Min
            $newStub = { param([string] $Name, [string] $Version, [string] $Guid, [string] $Body)
                $dir = Join-Path $script:Mods $Name $Version
                New-Item -ItemType Directory -Path $dir -Force | Out-Null
                Set-Content -LiteralPath (Join-Path $dir "$Name.psd1") -Encoding utf8 -Value "@{ RootModule = '$Name.psm1'; ModuleVersion = '$Version'; GUID = '$Guid'; FunctionsToExport = '*'; CmdletsToExport = @(); VariablesToExport = @(); AliasesToExport = @() }"
                Set-Content -LiteralPath (Join-Path $dir "$Name.psm1") -Encoding utf8 -Value $Body }
            # Any call outside Exchange reads appends to the marker file the test then checks.
            $mark = '$env:NRG_DL_MARKER'
            & $newStub 'Microsoft.Graph.Authentication' '2.40.0' 'b0b0b0b0-1111-4222-8333-444444444444' @"
function Connect-MgGraph { Add-Content -LiteralPath $mark -Value 'Connect-MgGraph' }
function Disconnect-MgGraph { }
function Get-MgContext { Add-Content -LiteralPath $mark -Value 'Get-MgContext'; `$null }
function Invoke-MgGraphRequest { Add-Content -LiteralPath $mark -Value 'Invoke-MgGraphRequest'; @{ value = @() } }
"@
            & $newStub 'ExchangeOnlineManagement' $exoVersion 'c0c0c0c0-1111-4222-8333-555555555555' @"
function Connect-ExchangeOnline { [CmdletBinding()] param([switch] `$ShowBanner, [switch] `$DisableWAM, `$UserPrincipalName, `$DelegatedOrganization) Add-Content -LiteralPath $mark -Value 'EXO-connect' }
function Disconnect-ExchangeOnline { [CmdletBinding()] param(`$Confirm) Add-Content -LiteralPath $mark -Value 'EXO-disconnect' }
function Get-ConnectionInformation { @() }
function Connect-IPPSSession { Add-Content -LiteralPath $mark -Value 'Connect-IPPSSession' }
function Get-AcceptedDomain { @([pscustomobject]@{ DomainName = 'smoke.example'; Default = `$true }) }
function Get-DistributionGroup { param(`$ResultSize)
    @([pscustomobject]@{ Name = 'open'; DisplayName = 'Open List'; PrimarySmtpAddress = 'open@smoke.example'; Guid = [guid]'aaaaaaaa-0000-0000-0000-000000000001'; RecipientTypeDetails = 'MailUniversalDistributionGroup'
        ManagedBy = @(); RequireSenderAuthenticationEnabled = `$false; AcceptMessagesOnlyFrom = @(); AcceptMessagesOnlyFromDLMembers = @(); AcceptMessagesOnlyFromSendersOrMembers = @()
        ModerationEnabled = `$false; ModeratedBy = @(); MemberJoinRestriction = 'Open'; MemberDepartRestriction = 'Open'; HiddenFromAddressListsEnabled = `$false }) }
function Get-DynamicDistributionGroup { param(`$ResultSize) @() }
function Get-DistributionGroupMember { param(`$Identity, `$ResultSize) @([pscustomobject]@{ DisplayName = 'Pat'; PrimarySmtpAddress = 'pat@smoke.example'; RecipientType = 'UserMailbox'; RecipientTypeDetails = 'UserMailbox' },
    [pscustomobject]@{ DisplayName = 'Vendor'; PrimarySmtpAddress = 'v@fabrikam.com'; ExternalEmailAddress = 'SMTP:v@fabrikam.com'; RecipientType = 'MailContact'; RecipientTypeDetails = 'MailContact' }) }
function Get-DynamicDistributionGroupMember { param(`$Identity, `$ResultSize) @() }
function Set-DistributionGroup { Add-Content -LiteralPath $mark -Value 'Set-DistributionGroup' }
function Set-DynamicDistributionGroup { Add-Content -LiteralPath $mark -Value 'Set-DynamicDistributionGroup' }
function Add-DistributionGroupMember { Add-Content -LiteralPath $mark -Value 'Add-DistributionGroupMember' }
function Remove-DistributionGroupMember { Add-Content -LiteralPath $mark -Value 'Remove-DistributionGroupMember' }
function New-DistributionGroup { Add-Content -LiteralPath $mark -Value 'New-DistributionGroup' }
"@
            & $newStub 'MicrosoftTeams' '5.9.0' 'd0d0d0d0-1111-4222-8333-666666666666' "function Connect-MicrosoftTeams { Add-Content -LiteralPath $mark -Value 'Connect-MicrosoftTeams' }"
            $script:ScanOut = Join-Path $script:Tmp 'scan-out'
            $old = $env:PSModulePath; $oldMark = $env:NRG_DL_MARKER
            try {
                $env:PSModulePath = $script:Mods + [System.IO.Path]::PathSeparator + $env:PSModulePath
                $env:NRG_DL_MARKER = $script:Marker
                $cmd = "& '$(Join-Path $script:Root 'Invoke-NRGDistributionListScan.ps1')' -OutputPath '$($script:ScanOut)' -UserPrincipalName 'tech@smoke.example'; exit `$LASTEXITCODE"
                $text = (& pwsh -NoProfile -NonInteractive -Command $cmd *>&1 | Out-String)
                $script:ScanCode = $LASTEXITCODE
            } finally { $env:PSModulePath = $old; $env:NRG_DL_MARKER = $oldMark }
            $script:ScanText = ($text -replace "\e\[[0-9;]*m", '')
            $script:ScanFiles = @(Get-ChildItem -LiteralPath $script:ScanOut -File -ErrorAction SilentlyContinue)
        }
        It 'exits 0 (every section read, nothing truncated) and prints the scope and the worksheet paths' {
            $script:ScanCode | Should -Be 0 -Because $script:ScanText
            $script:ScanText | Should -Match 'Connects to Exchange Online ONLY'
            $script:ScanText | Should -Match 'NOT assessed: Entra ID'
            $script:ScanText | Should -Match '1 shortfall\(s\)|shortfall\(s\) across 1 list'
        }
        It 'wrote the text worksheet and the CSV, named <tenant>-<timestamp>-distribution-lists' {
            @($script:ScanFiles.Name | Where-Object { $_ -match '^smoke-\d{8}-\d{6}-distribution-lists\.(txt|csv)$' }).Count | Should -Be 2
            $txt = Get-Content -LiteralPath ($script:ScanFiles | Where-Object Extension -eq '.txt').FullName -Raw
            $txt | Should -Match "Set-DistributionGroup -Identity 'open@smoke.example' -RequireSenderAuthenticationEnabled \`$true"
            $txt | Should -Match 'pat@smoke.example \(Pat\)'
        }
        It 'connected to Exchange Online, disconnected it, and called NOTHING else: no Graph, Purview or Teams, and no write cmdlet' {
            $calls = @(Get-Content -LiteralPath $script:Marker -ErrorAction SilentlyContinue)
            $calls | Should -Contain 'EXO-connect'
            $calls | Should -Contain 'EXO-disconnect'
            @($calls | Where-Object { $_ -notin 'EXO-connect', 'EXO-disconnect' }) | Should -BeNullOrEmpty
        }
    }
}
