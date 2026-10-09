#Requires -Version 7.0
#
# TP.DeviceCompliance.Tests.ps1
#
# Guards the endpoint compliance path end to end:
#   Device/Invoke-TPDeviceCompliance.ps1          runs ON the endpoint
#   Config/device-controls.json                    DEV-* definitions + NIST map
#   Collectors/Device/Invoke-TPCollectDeviceCompliance.ps1   ingests the JSON
#   Evaluators/Test-TPControlDevice.ps1           aggregates to findings
#
# Four properties this suite exists to protect.
#
#   1. The endpoint script runs on Windows PowerShell 5.1. Stock Windows ships
#      5.1, not 7. A `??`, a ternary, or a PS7-only cmdlet in that file fails on
#      the exact machines it is meant to run on — and it fails at a client site,
#      not here. Enforced statically because there is no 5.1 host in CI.
#
#   2. The endpoint script is standalone. It imports no module, reaches no
#      network, and holds no credential. The moment it needs TenantPosture.psm1
#      it stops being deployable by RMM to a bare machine.
#
#   3. Elevation is reported, never assumed. BitLocker, TPM, Secure Boot and the
#      audit policy return nothing without admin rights, which is
#      indistinguishable from "not configured". Those must land as NotAssessed
#      and must be excluded from the fleet denominator — counting them as passes
#      is the false-clean-bill-of-health bug, and counting them as failures
#      invents gaps that are not there.
#
#   4. Check IDs, control definitions and NIST citations stay in step. The
#      endpoint owns the check logic; the tool owns the judgement. That split is
#      only safe while the two agree on the identifiers.

Describe 'Endpoint device compliance' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) {
            Split-Path -Parent $PSScriptRoot
        } else { (Get-Location).Path }

        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop

        $script:AgentPath = Join-Path $script:RepoRoot 'Device/Invoke-TPDeviceCompliance.ps1'
        $script:AgentSrc  = Get-Content -LiteralPath $script:AgentPath -Raw

        $script:Defs = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/device-controls.json') -Raw -Encoding utf8 |
            ConvertFrom-Json).controls)

        $script:EmittedIds = @([regex]::Matches($script:AgentSrc, "Invoke-Check -Id '(DEV-[\d.]+)'") |
            ForEach-Object { $_.Groups[1].Value })

        # Code with comments removed, via the tokenizer. A line-based filter is
        # not enough: the file's own documentation block explains that it must
        # not use `??` and must not import TenantPosture.psm1, so a naive
        # search finds those strings in the prose and fails on a correct file.
        $tokens = $null; $perr = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($script:AgentPath, [ref]$tokens, [ref]$perr)
        $script:AgentCode = (@($tokens |
            Where-Object { $_.Kind -ne 'Comment' } |
            ForEach-Object { $_.Text }) -join ' ')

        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ("tp-dev-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        New-Item -ItemType Directory -Force -Path $script:Tmp | Out-Null

        # Builds a device result file the way the endpoint script would.
        function script:NewDeviceFile {
            param(
                [string] $Hostname,
                [bool]   $Elevated,
                [hashtable] $Results,   # checkId -> Result
                [string] $Folder,
                [switch] $WithBom,
                # Current by default: an endpoint result older than the freshness window
                # is (correctly) not counted, so a fixed old date would make every device stale.
                [string] $CollectedAt = ((Get-Date).ToUniversalTime().ToString('o'))
            )
            $checks = @()
            foreach ($k in $Results.Keys) {
                $checks += [ordered]@{ Id = $k; Result = $Results[$k]; Observed = 'obs'; Expected = 'exp'; Detail = '' }
            }
            $doc = [ordered]@{
                Schema        = 'tp-device-compliance/1.0'
                ScriptVersion = '1.0.0'
                CollectedAt   = $CollectedAt
                Elevated      = $Elevated
                Device        = [ordered]@{ Hostname = $Hostname; OSCaption = 'Windows 11 Pro'; OSBuild = '22631'; Serial = 'SN1'; JoinType = 'EntraJoined' }
                Checks        = $checks
            }
            $p = Join-Path $Folder "$Hostname.json"
            $json = $doc | ConvertTo-Json -Depth 6
            if ($WithBom) {
                # Windows PowerShell 5.1 -Encoding UTF8 emits a BOM. The
                # ingesting side must cope with it rather than requiring the
                # endpoint to do something 5.1 cannot do cleanly.
                [System.IO.File]::WriteAllText($p, $json, (New-Object System.Text.UTF8Encoding($true)))
            } else {
                [System.IO.File]::WriteAllText($p, $json, (New-Object System.Text.UTF8Encoding($false)))
            }
            return $p
        }
    }

    AfterAll {
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) {
            Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
        Clear-TPState
    }

    Context 'Endpoint script — runs on Windows PowerShell 5.1' {

        It 'declares #Requires -Version 5.1, not 7' {
            $script:AgentSrc | Should -Match '#Requires -Version 5\.1'
            $script:AgentSrc | Should -Not -Match '#Requires -Version 7'
        }

        It 'parses without error' {
            $errors = $null; $tokens = $null
            $null = [System.Management.Automation.Language.Parser]::ParseFile($script:AgentPath, [ref]$tokens, [ref]$errors)
            @($errors).Count | Should -Be 0
        }

        It 'uses no PowerShell 7-only syntax' {
            # There is no 5.1 host in CI, so this is the only thing standing
            # between a PS7-ism and a failure at a client site.
            $script:AgentCode | Should -Not -Match '\?\?'      -Because 'null-coalescing is PS7-only'
            $script:AgentCode | Should -Not -Match '\?\.'      -Because 'null-conditional access is PS7-only'
            $script:AgentCode | Should -Not -Match '-Parallel' -Because 'ForEach-Object -Parallel is PS7-only'
            $script:AgentCode | Should -Not -Match 'utf8NoBOM' -Because 'utf8NoBOM encoding is PS7-only'
            $script:AgentCode | Should -Not -Match 'Test-Json' -Because 'Test-Json is PS7-only'
        }

        It 'imports no module and calls nothing from the assessment tool' {
            $script:AgentCode | Should -Not -Match 'Import-Module'
            $script:AgentCode | Should -Not -Match 'TenantPosture\.psm1'
            # Its own helpers are unprefixed by design; a Get-NRG* call would
            # mean it had picked up a dependency on the module.
            $script:AgentCode | Should -Not -Match 'Get-TPObjectField'
            $script:AgentCode | Should -Not -Match 'Add-TPFinding'
        }

        It 'reaches no network and holds no credential' {
            foreach ($forbidden in 'Invoke-RestMethod', 'Invoke-WebRequest', 'Connect-MgGraph',
                                   'Connect-ExchangeOnline', 'System\.Net\.WebClient',
                                   'ConvertTo-SecureString', 'Net\.Sockets') {
                $script:AgentCode | Should -Not -Match $forbidden -Because "the endpoint collector must not $forbidden"
            }
        }

        It 'is read-only apart from the single result file it writes' {
            # A collector that changes the machine it is assessing is no longer
            # an assessment. Set-Content writing the result is the sole write.
            foreach ($forbidden in 'Set-ItemProperty', 'New-ItemProperty', 'Remove-Item',
                                   'Set-MpPreference', 'Enable-BitLocker', 'Set-NetFirewallProfile',
                                   'Set-LocalUser', 'Stop-Service', 'Set-Service') {
                $script:AgentCode | Should -Not -Match $forbidden -Because "the endpoint collector must not $forbidden"
            }
            @([regex]::Matches($script:AgentCode, 'Set-Content')).Count | Should -Be 1
        }

        It 'gates every elevation-dependent check behind the elevation switch' {
            # These four cannot be read without admin rights and silently return
            # nothing when they are not available.
            foreach ($id in 'DEV-1.1', 'DEV-1.4', 'DEV-1.5', 'DEV-8.2', 'DEV-8.3', 'DEV-8.4', 'DEV-8.6') {
                $script:AgentSrc | Should -Match ([regex]::Escape("Invoke-Check -Id '$id' -NeedsElevation")) `
                    -Because "$id reads state that requires administrative rights"
            }
        }

        It 'records whether it ran elevated' {
            $script:AgentSrc | Should -Match 'Elevated\s*=\s*\$script:IsElevated'
        }
    }

    Context 'Event log and audit-policy checks (DEV-8.3 to DEV-8.6)' {

        BeforeAll {
            # The verdicts are pure functions in the endpoint script, so they can
            # run here without a Windows event log. Taken from the parsed file,
            # not copied, so the test exercises the code that ships.
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:AgentPath, [ref]$null, [ref]$null)
            foreach ($name in 'Get-EventLogSizeVerdict', 'Get-EventLogModeVerdict') {
                $fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
                Set-Item -Path "function:script:$name" -Value $fn.Body.GetScriptBlock()
            }
            $script:Min = @{ Application = 32768; Security = 196608; Setup = 32768; System = 32768 }
            function script:L([string] $Name, $Bytes, $Mode = 'Circular') {
                [pscustomobject]@{ LogName = $Name; MaximumSizeInBytes = $Bytes; LogMode = $Mode }
            }
            $script:Good = @((L 'Application' 33554432), (L 'Security' 201326592), (L 'Setup' 33554432), (L 'System' 33554432))
        }

        It 'DEV-8.3 passes at the minimums and fails a Security log below 192 MB' {
            (Get-EventLogSizeVerdict -Logs $script:Good -MinimumKB $script:Min).Result | Should -Be 'Pass'
            $small = @($script:Good | Where-Object LogName -ne 'Security') + (L 'Security' 20971520)
            $v = Get-EventLogSizeVerdict -Logs $small -MinimumKB $script:Min
            $v.Result   | Should -Be 'Fail'
            $v.Detail   | Should -Match 'Security 20480 KB \(minimum 196608 KB\)'
            $v.Observed | Should -Match 'Security=20480 KB'
        }

        It 'DEV-8.3 never assumes an unread log is large enough' {
            $v = Get-EventLogSizeVerdict -Logs @($script:Good | Where-Object LogName -ne 'Setup') -MinimumKB $script:Min
            $v.Result | Should -Be 'NotAssessed' -Because 'a log that was not read is unknown, not compliant'
            $v.Detail | Should -Match 'Not read: Setup'
            (Get-EventLogSizeVerdict -Logs @() -MinimumKB $script:Min).Result | Should -Be 'NotAssessed'
            # A shortfall on a log that WAS read is still a failure, and the unread one is named.
            $mixed = @((L 'Security' 1048576), (L 'System' 33554432))
            $v = Get-EventLogSizeVerdict -Logs $mixed -MinimumKB $script:Min
            $v.Result | Should -Be 'Fail'
            $v.Detail | Should -Match 'Not read: Application, Setup'
        }

        It 'DEV-8.4 fails a log that stops recording when full, and passes Circular or AutoBackup' {
            $names = @('Application', 'Security', 'Setup', 'System')
            (Get-EventLogModeVerdict -Logs $script:Good -LogNames $names).Result | Should -Be 'Pass'
            $auto = @($script:Good | Where-Object LogName -ne 'Security') + (L 'Security' 201326592 'AutoBackup')
            (Get-EventLogModeVerdict -Logs $auto -LogNames $names).Result | Should -Be 'Pass'
            $retain = @($script:Good | Where-Object LogName -ne 'Security') + (L 'Security' 201326592 'Retain')
            $v = Get-EventLogModeVerdict -Logs $retain -LogNames $names
            $v.Result | Should -Be 'Fail'
            $v.Detail | Should -Match 'Stops recording new events when full: Security'
        }

        It 'DEV-8.4 reports an unread or unrecognized mode as not assessed, never a pass' {
            $names = @('Application', 'Security', 'Setup', 'System')
            (Get-EventLogModeVerdict -Logs @($script:Good | Where-Object LogName -ne 'System') -LogNames $names).Result | Should -Be 'NotAssessed'
            $odd = @($script:Good | Where-Object LogName -ne 'System') + (L 'System' 33554432 'Something')
            (Get-EventLogModeVerdict -Logs $odd -LogNames $names).Result | Should -Be 'NotAssessed'
        }

        It 'DEV-8.5 treats an absent value as the documented default (enabled) and fails only an explicit 0' {
            $body = [regex]::Match($script:AgentSrc, "(?s)Invoke-Check -Id 'DEV-8\.5'.*?\n    \}").Value
            $body | Should -Match ([regex]::Escape("'SCENoApplyLegacyAuditPolicy'"))
            $body | Should -Match ([regex]::Escape('$ok = $true')) -Because 'Microsoft documents the default as Enabled'
            $body | Should -Match ([regex]::Escape("([string]`$force -eq '1')"))
        }

        It 'DEV-8.6 is inventory: it records Info and is never a pass or a fail' {
            $def = @($script:Defs | Where-Object ControlId -eq 'DEV-8.6')[0]
            [bool]$def.Inventory | Should -BeTrue
            $body = [regex]::Match($script:AgentSrc, "(?s)Invoke-Check -Id 'DEV-8\.6'.*?\n    \}").Value
            $body | Should -Match "-Result 'Info'"
            $body | Should -Not -Match "'Pass'|'Fail'"
        }
    }

    Context 'Check IDs and control definitions agree' {

        It 'emits at least 30 checks' {
            $script:EmittedIds.Count | Should -BeGreaterOrEqual 30
        }

        It 'every emitted check has a control definition' {
            $defined = @($script:Defs | ForEach-Object { $_.ControlId })
            $orphans = @($script:EmittedIds | Where-Object { $_ -notin $defined })
            $orphans -join ', ' | Should -BeNullOrEmpty -Because 'a check with no definition has no title, severity or NIST citation'
        }

        It 'every control definition is emitted by the endpoint script' {
            $missing = @($script:Defs | ForEach-Object { $_.ControlId } | Where-Object { $_ -notin $script:EmittedIds })
            $missing -join ', ' | Should -BeNullOrEmpty -Because 'a defined control the endpoint never checks reports NotApplicable forever'
        }

        It 'every definition carries a title, severity, remediation and business risk' {
            $bad = @()
            foreach ($d in $script:Defs) {
                foreach ($f in 'Title', 'Severity', 'Remediation', 'BusinessRisk') {
                    if ([string]::IsNullOrWhiteSpace([string]$d.$f)) { $bad += "$($d.ControlId): $f" }
                }
            }
            $bad -join '; ' | Should -BeNullOrEmpty
        }

        It 'uses only severities the finding vocabulary accepts' {
            foreach ($d in $script:Defs) {
                $d.Severity | Should -BeIn @('Critical','High','Medium','Low','Informational')
            }
        }

        It 'every NIST citation resolves to a catalog title' {
            $bad = @()
            foreach ($d in $script:Defs) {
                @($d.Nist).Count | Should -BeGreaterThan 0 -Because "$($d.ControlId) must cite 800-53"
                foreach ($n in @($d.Nist)) {
                    if (-not (Get-TPNISTControlTitle -ControlId $n)) { $bad += "$($d.ControlId) => $n" }
                }
            }
            $bad -join '; ' | Should -BeNullOrEmpty
        }

        It 'does not collide with the tenant control set' {
            # DEV-* is deliberately outside controls.json: that file is the 202
            # tenant controls, a stated product number.
            $tenant = @((Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/controls.json') -Raw -Encoding utf8 |
                ConvertFrom-Json).controls | ForEach-Object { $_.ControlId })
            $collisions = @($script:Defs | Where-Object { $_.ControlId -in $tenant })
            $collisions.Count | Should -Be 0
            @($tenant | Where-Object { $_ -like 'DEV-*' }).Count | Should -Be 0
        }
    }

    Context 'Collector — ingesting result files' {

        BeforeEach { Clear-TPState }

        It 'ingests a folder of results' {
            $d = Join-Path $script:Tmp 'ok'; New-Item -ItemType Directory -Force -Path $d | Out-Null
            $null = NewDeviceFile -Hostname 'WKS-1' -Elevated $true -Folder $d -Results @{ 'DEV-2.1' = 'Pass' }
            $null = NewDeviceFile -Hostname 'WKS-2' -Elevated $true -Folder $d -Results @{ 'DEV-2.1' = 'Fail' }

            Invoke-TPCollectDeviceCompliance -ResultsPath $d
            $raw = Get-TPRawData -Key 'Device-Compliance'
            $raw.Success                              | Should -BeTrue
            $raw.Data.DeviceCount                     | Should -Be 2
            $raw.Data.SectionStatus.DeviceResults     | Should -Be 'Collected'
        }

        It 'handles the UTF-8 BOM Windows PowerShell 5.1 writes' {
            # -Encoding UTF8 on 5.1 emits a BOM and ConvertFrom-Json chokes on
            # it. If this regresses, every result file from every endpoint is
            # rejected and the whole device half silently vanishes.
            $d = Join-Path $script:Tmp 'bom'; New-Item -ItemType Directory -Force -Path $d | Out-Null
            $null = NewDeviceFile -Hostname 'WKS-BOM' -Elevated $true -Folder $d -Results @{ 'DEV-2.1' = 'Pass' } -WithBom

            Invoke-TPCollectDeviceCompliance -ResultsPath $d
            (Get-TPRawData -Key 'Device-Compliance').Data.DeviceCount | Should -Be 1
        }

        It 'rejects a file that is not a device-compliance result' {
            # A stray JSON in the collection folder must not become a device
            # with no checks — that would read as a device that passed nothing.
            $d = Join-Path $script:Tmp 'stray'; New-Item -ItemType Directory -Force -Path $d | Out-Null
            $null = NewDeviceFile -Hostname 'WKS-1' -Elevated $true -Folder $d -Results @{ 'DEV-2.1' = 'Pass' }
            '{"something":"else"}' | Out-File -LiteralPath (Join-Path $d 'unrelated.json') -Encoding utf8

            Invoke-TPCollectDeviceCompliance -ResultsPath $d
            $raw = Get-TPRawData -Key 'Device-Compliance'
            $raw.Data.DeviceCount   | Should -Be 1
            $raw.Data.RejectedFiles | Should -Be 1
        }

        It 'reports Failed, not empty, when files were present but none were usable' {
            # Empty is not clean. A folder of unreadable files is a broken
            # collection, and every DEV control must say so rather than
            # reporting a confident NotApplicable.
            $d = Join-Path $script:Tmp 'bad'; New-Item -ItemType Directory -Force -Path $d | Out-Null
            '{ not json' | Out-File -LiteralPath (Join-Path $d 'broken.json') -Encoding utf8

            Invoke-TPCollectDeviceCompliance -ResultsPath $d
            $raw = Get-TPRawData -Key 'Device-Compliance'
            $raw.Data.SectionStatus.DeviceResults | Should -Be 'Failed'
        }

        It 'reports NotRun for an empty folder' {
            $d = Join-Path $script:Tmp 'empty'; New-Item -ItemType Directory -Force -Path $d | Out-Null
            Invoke-TPCollectDeviceCompliance -ResultsPath $d
            (Get-TPRawData -Key 'Device-Compliance').Data.SectionStatus.DeviceResults | Should -Be 'NotRun'
        }

        It 'counts how many devices ran elevated' {
            $d = Join-Path $script:Tmp 'elev'; New-Item -ItemType Directory -Force -Path $d | Out-Null
            $null = NewDeviceFile -Hostname 'A' -Elevated $true  -Folder $d -Results @{ 'DEV-2.1' = 'Pass' }
            $null = NewDeviceFile -Hostname 'B' -Elevated $false -Folder $d -Results @{ 'DEV-2.1' = 'Pass' }

            Invoke-TPCollectDeviceCompliance -ResultsPath $d
            $raw = Get-TPRawData -Key 'Device-Compliance'
            $raw.Data.DeviceCount   | Should -Be 2
            $raw.Data.ElevatedCount | Should -Be 1
        }

        It 'rejects a path-traversal results path' {
            { Invoke-TPCollectDeviceCompliance -ResultsPath '../../evil' } | Should -Throw
        }
    }

    Context 'Evaluator — fleet aggregation' {

        BeforeEach { Clear-TPState }

        function script:RunFleet {
            param([hashtable[]] $Devices, [string] $Name)
            $d = Join-Path $script:Tmp $Name
            if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }
            New-Item -ItemType Directory -Force -Path $d | Out-Null
            foreach ($dev in $Devices) {
                $null = NewDeviceFile -Hostname $dev.Host -Elevated $dev.Elevated -Folder $d -Results $dev.Results
            }
            # Self-contained: clears state itself so an It block can call this
            # more than once without the second run's findings piling on top of
            # the first.
            Clear-TPState
            Invoke-TPCollectDeviceCompliance -ResultsPath $d
            Test-TPControlDevice
            return @(Get-TPFindings | Where-Object { $_.ControlId -like 'DEV-*' })
        }

        It 'emits exactly one finding per defined control, not one per device' {
            $f = RunFleet -Name 'agg1' -Devices @(
                @{ Host = 'A'; Elevated = $true; Results = @{ 'DEV-2.1' = 'Pass' } },
                @{ Host = 'B'; Elevated = $true; Results = @{ 'DEV-2.1' = 'Pass' } }
            )
            $f.Count | Should -Be $script:Defs.Count
            @($f | Where-Object { $_.ControlId -eq 'DEV-2.1' }).Count | Should -Be 1
        }

        It 'Satisfied only when every assessed device passes' {
            $f = RunFleet -Name 'agg2' -Devices @(
                @{ Host = 'A'; Elevated = $true; Results = @{ 'DEV-2.1' = 'Pass' } },
                @{ Host = 'B'; Elevated = $true; Results = @{ 'DEV-2.1' = 'Pass' } }
            )
            ($f | Where-Object { $_.ControlId -eq 'DEV-2.1' }).State | Should -Be 'Satisfied'
        }

        It 'Gap when no assessed device passes' {
            $f = RunFleet -Name 'agg3' -Devices @(
                @{ Host = 'A'; Elevated = $true; Results = @{ 'DEV-2.1' = 'Fail' } },
                @{ Host = 'B'; Elevated = $true; Results = @{ 'DEV-2.1' = 'Fail' } }
            )
            $x = $f | Where-Object { $_.ControlId -eq 'DEV-2.1' }
            $x.State | Should -Be 'Gap'
            @($x.AffectedObjects).Count | Should -Be 2
        }

        It 'Partial on a mixed fleet, and names the failing hosts' {
            $f = RunFleet -Name 'agg4' -Devices @(
                @{ Host = 'GOOD'; Elevated = $true; Results = @{ 'DEV-2.1' = 'Pass' } },
                @{ Host = 'BAD';  Elevated = $true; Results = @{ 'DEV-2.1' = 'Fail' } }
            )
            $x = $f | Where-Object { $_.ControlId -eq 'DEV-2.1' }
            $x.State | Should -Be 'Partial'
            @($x.AffectedObjects | ForEach-Object { $_.Hostname }) | Should -Be @('BAD')
        }

        It 'excludes NotAssessed from the denominator instead of counting it either way' {
            # THE load-bearing assertion. Two devices pass, one could not run the
            # check. The verdict must be Satisfied over a denominator of 2 — not
            # a Partial invented from a device that was never measured, and not
            # a Satisfied over 3 that claims knowledge of a machine nobody read.
            $f = RunFleet -Name 'agg5' -Devices @(
                @{ Host = 'A'; Elevated = $true;  Results = @{ 'DEV-1.1' = 'Pass' } },
                @{ Host = 'B'; Elevated = $true;  Results = @{ 'DEV-1.1' = 'Pass' } },
                @{ Host = 'C'; Elevated = $false; Results = @{ 'DEV-1.1' = 'NotAssessed' } }
            )
            $x = $f | Where-Object { $_.ControlId -eq 'DEV-1.1' }
            $x.State        | Should -Be 'Satisfied'
            $x.CurrentValue | Should -Match '2 of 2'
            $x.Detail       | Should -Match '1 device\(s\) could not run this check'
        }

        It 'says the collector was not elevated when that is why a check could not run' {
            $f = RunFleet -Name 'agg6' -Devices @(
                @{ Host = 'A'; Elevated = $false; Results = @{ 'DEV-1.1' = 'NotAssessed' } }
            )
            $x = $f | Where-Object { $_.ControlId -eq 'DEV-1.1' }
            $x.State  | Should -Be 'NotApplicable'
            $x.Detail | Should -Match 'without administrative rights'
        }

        It 'distinguishes "does not apply" from "could not be assessed"' {
            # Both report NotApplicable and neither may read as a pass, but the
            # operator has to tell them apart: RDP disabled everywhere is good
            # news, BitLocker unreadable everywhere is a blind spot.
            $f1 = RunFleet -Name 'agg9a' -Devices @(
                @{ Host = 'A'; Elevated = $true; Results = @{ 'DEV-3.5' = 'NotApplicable' } }
            )
            $x1 = $f1 | Where-Object { $_.ControlId -eq 'DEV-3.5' }
            $x1.State  | Should -Be 'NotApplicable'
            $x1.Detail | Should -Match 'does not apply'

            $f2 = RunFleet -Name 'agg9b' -Devices @(
                @{ Host = 'A'; Elevated = $false; Results = @{ 'DEV-1.1' = 'NotAssessed' } }
            )
            $x2 = $f2 | Where-Object { $_.ControlId -eq 'DEV-1.1' }
            $x2.State  | Should -Be 'NotApplicable'
            $x2.Detail | Should -Match 'could not run this check'
        }

        It 'NotApplicable, never Satisfied, when no device produced an assessable result' {
            $f = RunFleet -Name 'agg7' -Devices @(
                @{ Host = 'A'; Elevated = $true; Results = @{ 'DEV-2.1' = 'Error' } }
            )
            ($f | Where-Object { $_.ControlId -eq 'DEV-2.1' }).State | Should -Be 'NotApplicable'
        }

        It 'flags a device that reported no result for a check at all' {
            # Version skew across the fleet: an older endpoint script that does
            # not know about a newer check. Must be visible, not silently
            # shrinking the denominator.
            $f = RunFleet -Name 'agg8' -Devices @(
                @{ Host = 'NEW'; Elevated = $true; Results = @{ 'DEV-2.1' = 'Pass'; 'DEV-2.2' = 'Pass' } },
                @{ Host = 'OLD'; Elevated = $true; Results = @{ 'DEV-2.1' = 'Pass' } }
            )
            ($f | Where-Object { $_.ControlId -eq 'DEV-2.2' }).Detail |
                Should -Match 'reported no result for this check'
        }

        It 'reports NotApplicable with a prompt when no device results were supplied' {
            Clear-TPState
            Test-TPControlDevice
            $f = @(Get-TPFindings | Where-Object { $_.ControlId -like 'DEV-*' })
            $f.Count | Should -Be $script:Defs.Count
            @($f | Where-Object { $_.State -ne 'NotApplicable' }).Count | Should -Be 0
            $f[0].Detail | Should -Match 'Invoke-TPDeviceCompliance'
        }
    }

    Context 'Findings reach the NIST views' {

        It 'every DEV finding carries a parseable NIST citation' {
            # Without this a device finding is scored in the tenant total but
            # invisible in the family rollup and the standalone matrix — the one
            # place an 800-53 reader is actually looking.
            Clear-TPState
            Test-TPControlDevice
            $f = @(Get-TPFindings | Where-Object { $_.ControlId -like 'DEV-*' })
            foreach ($x in $f) {
                @(Get-TPNISTControlIdsFromFinding -Finding $x).Count |
                    Should -BeGreaterThan 0 -Because "$($x.ControlId) must cite 800-53"
            }
        }

        It 'device findings roll up into real NIST families' {
            Clear-TPState
            Test-TPControlDevice
            $f   = @(Get-TPFindings | Where-Object { $_.ControlId -like 'DEV-*' })
            $cov = Get-TPNISTFamilyCoverage -Findings $f -ErrorHandling 'Gap'
            $cov.FamilyCount | Should -BeGreaterThan 4
            $fams = @($cov.Families | ForEach-Object { $_.Family })
            foreach ($expect in 'SC', 'SI', 'AC', 'IA') {
                $fams | Should -Contain $expect
            }
        }
    }
}
