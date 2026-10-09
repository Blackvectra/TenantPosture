#Requires -Version 7.0
#
# TP.HipaaReadiness.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# Guards the HIPAA Security Rule readiness view: Config/hipaa-security-rule.json
# (from the eCFR text of 45 CFR 164 Subpart C), Lib/Get-TPHipaaReadiness.ps1
# and Publishers/Publish-TPHipaaReadiness.ps1.
#
# The rules are the SSP's, because a readiness report is read as a statement
# about the client: an item no control evidences never reads as met; an item
# whose requirement is a document or a process takes no evidence from tenant
# configuration even when a control cites it; a control with no finding counts
# in neither direction; and nothing says "compliant".

Describe 'HIPAA Security Rule readiness view' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Cat = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/hipaa-security-rule.json') -Raw -Encoding utf8 | ConvertFrom-Json
        $script:Items = @($script:Cat.items)
        $script:Controls = @(Get-TPControlDefinitions)

        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('tp-hipaa-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        $null = New-Item -ItemType Directory -Force -Path $script:Tmp

        function script:F([string] $Cid, [string] $State, [string] $Detail = '') {
            @{ ControlId = $Cid; State = $State; Detail = $Detail; Title = "$Cid title" }
        }
        function script:Row($Posture, [string] $Citation) { @($Posture['Items'] | Where-Object { $_['Citation'] -eq $Citation })[0] }
        $script:AllPass = @($script:Controls | ForEach-Object { F $_.ControlId 'Satisfied' })
    }

    AfterAll {
        if ($script:Tmp -and (Test-Path -LiteralPath $script:Tmp)) { Remove-Item -LiteralPath $script:Tmp -Recurse -Force -ErrorAction SilentlyContinue }
    }

    Context 'Catalog, as written in 45 CFR 164 Subpart C' {

        It 'holds all 63 standards and implementation specifications: 22 standards, 19 Required, 22 Addressable' {
            $script:Items.Count | Should -Be 63
            @($script:Items | Where-Object Kind -eq 'Standard').Count | Should -Be 22
            @($script:Items | Where-Object Requirement -eq 'Required').Count | Should -Be 19
            @($script:Items | Where-Object Requirement -eq 'Addressable').Count | Should -Be 22
        }

        It 'carries the Required / Addressable designation the regulation gives a few well-known specifications' {
            $by = @{}; foreach ($i in $script:Items) { $by[$i.Citation] = $i }
            $by['164.308(a)(1)(ii)(A)'].Name        | Should -Be 'Risk analysis'
            $by['164.308(a)(1)(ii)(A)'].Requirement | Should -Be 'Required'
            $by['164.312(a)(2)(iii)'].Name          | Should -Be 'Automatic logoff'
            $by['164.312(a)(2)(iii)'].Requirement   | Should -Be 'Addressable'
            $by['164.312(a)(2)(iv)'].Requirement    | Should -Be 'Addressable'
            $by['164.312(a)(2)(i)'].Requirement     | Should -Be 'Required'
            $by['164.308(a)(7)(ii)(A)'].Name        | Should -Be 'Data backup plan'
            $by['164.312(b)'].Kind                  | Should -Be 'Standard'
        }

        It 'has unique citations, and every specification names a standard that exists' {
            $cits = @($script:Items | ForEach-Object Citation)
            @($cits | Select-Object -Unique).Count | Should -Be $cits.Count
            foreach ($i in @($script:Items | Where-Object Kind -ne 'Standard')) {
                $cits | Should -Contain $i.Standard -Because "$($i.Citation) names standard $($i.Standard)"
            }
        }

        It 'records its source and the amendments it reflects' {
            $script:Cat.source     | Should -Match 'ecfr\.gov'
            $script:Cat.amendments | Should -Match '78 FR'
        }

        It 'every item whose requirement tenant configuration cannot show says why' {
            foreach ($i in @($script:Items | Where-Object TenantEvidence -eq 'None')) {
                $i.TenantEvidenceReason | Should -Not -BeNullOrEmpty -Because $i.Citation
            }
            @($script:Items | Where-Object TenantEvidence -eq 'None' | ForEach-Object Citation) | Should -Contain '164.308(a)(1)(ii)(A)'
        }

        It 'frameworks.json no longer labels the Security Rule "2024"' {
            $fw = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/frameworks.json') -Raw | ConvertFrom-Json
            $list = if ($fw -is [array]) { $fw } else { @($fw.PSObject.Properties | ForEach-Object Value | Where-Object { $_ -is [array] } | Select-Object -First 1) }
            $h = @(@($list) | Where-Object { $_.Id -eq 'HIPAA' })[0]
            $h.Version | Should -Not -Be '2024' -Because 'eCFR shows the Security Rule text last amended in 2013'
        }
    }

    Context 'Citation join' {

        It 'parses only full 45 CFR 164 paragraph citations' {
            Get-TPHipaaCitationsFromText -Citation '§164.312(d), §164.308(a)(4)(ii)(B)' | Should -Be @('164.312(d)', '164.308(a)(4)(ii)(B)')
            @(Get-TPHipaaCitationsFromText -Citation 'Req 8.3; 164.3; IA.L2-3.5.3') | Should -BeNullOrEmpty
            @(Get-TPHipaaCitationsFromText -Citation '') | Should -BeNullOrEmpty
        }

        It 'resolves every Security Rule citation in controls.json, and names the Privacy Rule ones instead of mapping them' {
            $p = Get-TPHipaaReadiness -Findings @()
            # Anything unmatched must be a bare section citation (164.316) that
            # names no standard: listed in the report, never silently dropped.
            # Every citation that names a standard or specification resolves.
            @($p['Summary']['UnmatchedCitations'] | Where-Object { $_ -notmatch '\(164\.3\d\d\)$' }) | Should -BeNullOrEmpty -Because 'a citation that matches no item would silently drop its evidence'
            @($p['Summary']['OutsideSecurityRule'] | Where-Object { $_ -notmatch '\(164\.[45]\d\d' }) | Should -BeNullOrEmpty
        }

        It 'a citation of a standard without its "(i)" means that standard' {
            $p = Get-TPHipaaReadiness -Findings @()
            (Row $p '164.308(a)(4)(i)')['MappedControls'] | Should -BeGreaterThan 0
        }
    }

    Context 'Honesty rules' {

        It 'with every control satisfied, the items no control can evidence still claim nothing' {
            $p = Get-TPHipaaReadiness -Findings $script:AllPass
            foreach ($r in @($p['Items'] | Where-Object { $_['MappedControls'] -eq 0 })) {
                $r['Status']     | Should -Be 'Attestation required' -Because $r['Citation']
                $r['Confidence'] | Should -Be 'Attestation only'
            }
            (Row $p '164.308(a)(1)(ii)(A)')['Status'] | Should -Be 'Attestation required' -Because 'no tenant setting is a risk analysis'
            # Every mapped item passed its checks; standards with an open
            # specification are held back, so satisfied + open = mapped.
            ($p['Summary']['ChecksSatisfied'] + $p['Summary']['SpecificationsOpen']) | Should -Be $p['Summary']['Mapped']
            $p['Summary']['AttestationRequired'] | Should -BeGreaterThan 30
        }

        It 'a control citing the clearinghouse specification is cited, not counted' {
            # controls.json no longer cites a document-only item
            # (docs/HIPAA-CITATION-CORRECTIONS.md), so the rule is exercised
            # with one definition rewritten to the citation it used to carry.
            $real = @(Get-TPControlDefinitions)
            Mock -ModuleName 'TenantPosture' Get-TPControlDefinitions {
                foreach ($d in $real) {
                    if ($d.ControlId -eq 'TMS-1.1') {
                        $c = $d | ConvertTo-Json -Depth 10 | ConvertFrom-Json
                        $c.References.HIPAA = '§164.308(a)(4)(ii)(A)'
                        $c
                    } else { $d }
                }
            }.GetNewClosure()
            $p = Get-TPHipaaReadiness -Findings $script:AllPass
            $r = Row $p '164.308(a)(4)(ii)(A)'
            $r['MappedControls'] | Should -Be 0
            $r['Status']         | Should -Be 'Attestation required'
            @($r['CitedNotCounted']) | Should -Contain 'TMS-1.1'
            @($r['Evidence'])        | Should -BeNullOrEmpty
        }

        It 'a cited control with no finding, or an Error, is never met' {
            $none = Get-TPHipaaReadiness -Findings @()
            (Row $none '164.312(d)')['Status'] | Should -Be 'Not assessed'
            $ids = @((Row $none '164.312(d)')['Evidence'] | ForEach-Object { $_['ControlId'] })
            $err = Get-TPHipaaReadiness -Findings @($ids | ForEach-Object { F $_ 'Error' })
            (Row $err '164.312(d)')['Status'] | Should -Be 'Not assessed'
        }

        It 'a known shortfall on one instance is not hidden by an Error on another (Codex review)' {
            # DNS-1.1 cites 164.312(e)(1) and reports once per domain.
            $base = @($script:AllPass | Where-Object { $_.ControlId -ne 'DNS-1.1' })
            $f = $base + @(
                @{ ControlId = 'DNS-1.1'; Instance = 'a.example'; State = 'Partial'; Detail = 'SPF soft fail on a.example.'; Title = 't' }
                @{ ControlId = 'DNS-1.1'; Instance = 'b.example'; State = 'Error';   Detail = 'evaluator threw on b.example'; Title = 't' }
            )
            (Row (Get-TPHipaaReadiness -Findings $f) '164.312(e)(1)')['Status'] | Should -Be 'Technical check shortfall'
            # An Error beside passes is still no verdict.
            $g = $base + @(
                @{ ControlId = 'DNS-1.1'; Instance = 'a.example'; State = 'Satisfied'; Detail = 'ok'; Title = 't' }
                @{ ControlId = 'DNS-1.1'; Instance = 'b.example'; State = 'Error';     Detail = 'threw'; Title = 't' }
            )
            (Row (Get-TPHipaaReadiness -Findings $g) '164.312(e)(1)')['Status'] | Should -Not -Be 'Mapped technical checks satisfied'
        }

        It 'keeps every instance finding of a control in the evidence (Codex review)' {
            $base = @($script:AllPass | Where-Object { $_.ControlId -ne 'DNS-1.1' })
            $f = $base + @(
                @{ ControlId = 'DNS-1.1'; Instance = 'a.example'; State = 'Gap';       Detail = 'No SPF on a.example.'; Title = 't' }
                @{ ControlId = 'DNS-1.1'; Instance = 'b.example'; State = 'Gap';       Detail = 'No SPF on b.example.'; Title = 't' }
                @{ ControlId = 'DNS-1.1'; Instance = 'c.example'; State = 'Satisfied'; Detail = 'SPF -all on c.example.'; Title = 't' }
            )
            $p = Get-TPHipaaReadiness -Findings $f
            $ev = @((Row $p '164.312(e)(1)')['Evidence'] | Where-Object { $_['ControlId'] -eq 'DNS-1.1' })
            $ev.Count | Should -Be 3
            @($ev | ForEach-Object { $_['Instance'] }) | Should -Be @('a.example', 'b.example', 'c.example')
            @($ev | ForEach-Object { $_['Detail'] }) | Should -Contain 'No SPF on b.example.'
            # The control counts once toward the item, not once per domain.
            (Row $p '164.312(e)(1)')['MappedControls'] | Should -Be (Row (Get-TPHipaaReadiness -Findings $script:AllPass) '164.312(e)(1)')['MappedControls']
            $md = Join-Path $script:Tmp 'instances.md'
            Publish-TPHipaaReadiness -Posture $p -OutputPath $md -Metadata @{ TenantDomain = 'example.com' } | Out-Null
            $txt = Get-Content -LiteralPath $md -Raw
            $txt | Should -Match 'DNS-1\.1 \(b\.example\)'
            (Get-Content -LiteralPath ([IO.Path]::ChangeExtension($md, '.html')) -Raw) | Should -Match 'DNS-1\.1 \(b\.example\)'
        }

        It 'reads a section-level citation instead of dropping it (Codex review)' {
            $ids = @(& (Get-Module TenantPosture) { Get-TPHipaaCitationsFromText -Citation '§164.402, §164.316, §164.312(a)(2)(iv), 164.3, 164.3081' })
            $ids | Should -Be @('164.402', '164.316', '164.312(a)(2)(iv)')
            $p = Get-TPHipaaReadiness -Findings $script:AllPass
            # controls.json cites 164.402 / 164.502 at section level today.
            $outside = @($p['Summary']['OutsideSecurityRule']) -join ' '
            $cited = @($script:Controls | Where-Object { [string]$_.References.HIPAA -match '164\.(402|502|524)(?![\d(])' } | ForEach-Object { $_.ControlId })
            foreach ($c in $cited) { $outside | Should -Match ([regex]::Escape($c)) }
        }

        It 'fails closed when the control definitions cannot be loaded (Codex review)' {
            Mock -ModuleName 'TenantPosture' Get-TPControlDefinitions { throw 'controls.json is malformed' }
            $p = Get-TPHipaaReadiness -Findings $script:AllPass
            $p['Available'] | Should -BeFalse
            $p['UnavailableReason'] | Should -Match 'controls.json could not be loaded'
            Mock -ModuleName 'TenantPosture' Get-TPControlDefinitions { @() }
            (Get-TPHipaaReadiness -Findings $script:AllPass)['Available'] | Should -BeFalse
        }

        It 'prints the full grouped regulation text, never a stem ending in a dash (Codex review)' {
            foreach ($it in $script:Items) {
                $it.Text.TrimEnd() | Should -Not -Match '(—|; and|:)$' -Because "$($it.Citation) must carry its whole text"
            }
            ($script:Items | Where-Object Citation -eq '164.314(a)(2)').Text | Should -Match '\(iii\) Business associate contracts with subcontractors'
            ($script:Items | Where-Object Citation -eq '164.314(b)(2)').Text | Should -Match '\(iv\) Report to the group health plan any security incident'
            ($script:Items | Where-Object Citation -eq '164.316(b)(1)').Text | Should -Match '\(ii\) If an action, activity or assessment is required'
        }

        It 'encodes markup from tenant data in the Markdown report (Codex review)' {
            $f = @($script:AllPass | Where-Object { $_.ControlId -ne 'DNS-1.1' }) + @(
                @{ ControlId = 'DNS-1.1'; State = 'Gap'; Detail = 'Policy <img src=x onerror=alert(1)> & co'; Title = 't' })
            $md = Join-Path $script:Tmp 'markup.md'
            Publish-TPHipaaReadiness -Posture (Get-TPHipaaReadiness -Findings $f) -OutputPath $md -Metadata @{ TenantDomain = 'example.com' } | Out-Null
            $txt = Get-Content -LiteralPath $md -Raw
            $txt | Should -Not -Match '<img'
            $txt | Should -Match '&lt;img src=x onerror=alert\(1\)&gt; &amp; co'
            # Unmatched citations are rendered, never only counted.
            $un = @((Get-TPHipaaReadiness -Findings $f)['Summary']['UnmatchedCitations'])
            if ($un.Count -gt 0) { $txt | Should -Match ([regex]::Escape(($un[0] -replace '[<>&|]', ''))) }
        }

        It 'renders the remediation for a shortfall, and counts every evidence-free item on page one (Codex review)' {
            $f = @($script:AllPass | Where-Object { $_.ControlId -ne 'DNS-1.1' }) + @(F 'DNS-1.1' 'Gap' 'No SPF.')
            $p = Get-TPHipaaReadiness -Findings $f
            $rem = [string](@($script:Controls | Where-Object ControlId -eq 'DNS-1.1')[0].Remediation)
            $md = Join-Path $script:Tmp 'remediation.md'
            Publish-TPHipaaReadiness -Posture $p -OutputPath $md -Metadata @{ TenantDomain = 'example.com' } | Out-Null
            $txt  = Get-Content -LiteralPath $md -Raw
            $html = Get-Content -LiteralPath ([IO.Path]::ChangeExtension($md, '.html')) -Raw
            $probe = ($rem -split '[<>&|]')[0].Substring(0, [Math]::Min(40, ($rem -split '[<>&|]')[0].Length))
            $txt  | Should -Match ([regex]::Escape($probe))
            $html | Should -Match 'Remediation:</b>'
            # A run where nothing produced evidence: every item is evidence-free,
            # not only the unmapped ones.
            $none = Get-TPHipaaReadiness -Findings @()
            $md2 = Join-Path $script:Tmp 'none.md'
            Publish-TPHipaaReadiness -Posture $none -OutputPath $md2 -Metadata @{ TenantDomain = 'example.com' } | Out-Null
            $s = $none['Summary']
            (Get-Content -LiteralPath $md2 -Raw) | Should -Match ("$($s['Total']) of $($s['Total']) items have no evidence from this run")
            (Get-Content -LiteralPath $md2 -Raw) | Should -Match ("$($s['Mapped']) have mapped checks that produced no evidence this run")
        }

        It 'a shortfall beside an errored instance keeps its status but is not tool-verified (Codex review of #122)' {
            $base = @($script:AllPass | Where-Object { $_.ControlId -ne 'DNS-1.1' })
            $f = $base + @(
                @{ ControlId = 'DNS-1.1'; Instance = 'a.example'; State = 'Gap';   Detail = 'No SPF.'; Title = 't' }
                @{ ControlId = 'DNS-1.1'; Instance = 'b.example'; State = 'Error'; Detail = 'threw';   Title = 't' }
            )
            $r = Row (Get-TPHipaaReadiness -Findings $f) '164.312(e)(1)'
            $r['Status']     | Should -Be 'Technical check shortfall'
            $r['Confidence'] | Should -Be 'Partial evidence'
            $g = $base + @(F 'DNS-1.1' 'Gap' 'No SPF.')
            (Row (Get-TPHipaaReadiness -Findings $g) '164.312(e)(1)')['Confidence'] | Should -Not -Be 'Partial evidence'
        }

        It 'escapes Markdown link and image syntax from tenant data (Codex review of #122)' {
            $f = @($script:AllPass | Where-Object { $_.ControlId -ne 'DNS-1.1' }) + @(
                @{ ControlId = 'DNS-1.1'; State = 'Gap'; Detail = 'see ![p](https://attacker.example/pixel) and [l](https://x.example) `code`'; Title = 't' })
            $md = Join-Path $script:Tmp 'mdlink.md'
            Publish-TPHipaaReadiness -Posture (Get-TPHipaaReadiness -Findings $f) -OutputPath $md -Metadata @{ TenantDomain = 'example.com' } | Out-Null
            $txt = Get-Content -LiteralPath $md -Raw
            $txt | Should -Not -Match '!\[p\]\('
            $txt | Should -Not -Match '(?<!\\)\[l\]\('
            $txt | Should -Match ([regex]::Escape('!\[p\](https://attacker.example/pixel)'))
        }

        It 'states the subcontractor assurance duty, 164.308(b)(2), in the business associate standard (Codex review of #122)' {
            ($script:Items | Where-Object Citation -eq '164.308(b)(1)').Text | Should -Match '\(2\) A business associate may permit a business associate that is a subcontractor'
        }

        It 'one pass beside a not-applicable control is not met' {
            $none = Get-TPHipaaReadiness -Findings @()
            $ids = @((Row $none '164.312(d)')['Evidence'] | ForEach-Object { $_['ControlId'] })
            $ids.Count | Should -BeGreaterThan 1
            $f = @(F $ids[0] 'Satisfied') + @($ids | Select-Object -Skip 1 | ForEach-Object { F $_ 'NotApplicable' 'not licensed' })
            $r = Row (Get-TPHipaaReadiness -Findings $f) '164.312(d)'
            $r['Status']     | Should -Be 'Not assessed'
            $r['Confidence'] | Should -Be 'Partial evidence'
        }

        It 'the worst instance of a control wins' {
            $none = Get-TPHipaaReadiness -Findings @()
            $cid = @((Row $none '164.312(b)')['Evidence'])[0]['ControlId']
            $f = @($script:AllPass | Where-Object { $_.ControlId -ne $cid }) + @((F $cid 'Satisfied'), (F $cid 'Gap'))
            (Row (Get-TPHipaaReadiness -Findings $f) '164.312(b)')['Status'] | Should -Be 'Technical check shortfall'
        }

        It 'no status states regulatory fulfillment; the strongest says the mapped checks were satisfied' {
            $names = @((& (Get-Module TenantPosture) { Get-TPHipaaStatusNames }).Values)
            $names | Should -Contain 'Mapped technical checks satisfied'
            foreach ($n in $names) { $n | Should -Not -Match '(?i)\bmet\b|complian' -Because $n }
            $p = Get-TPHipaaReadiness -Findings $script:AllPass
            foreach ($r in $p['Items']) { $names | Should -Contain $r['Status'] }
        }

        It 'keeps the detail of every finding, a passing one included' {
            $none = Get-TPHipaaReadiness -Findings @()
            $cid = @((Row $none '164.312(d)')['Evidence'])[0]['ControlId']
            $f = @(F $cid 'Satisfied' 'Verified: policy read. Not assessed: one exclusion group not resolved.')
            $e = @((Row (Get-TPHipaaReadiness -Findings $f) '164.312(d)')['Evidence'] | Where-Object { $_['ControlId'] -eq $cid })[0]
            $e['Detail'] | Should -Be 'Verified: policy read. Not assessed: one exclusion group not resolved.'
        }

        It 'distinguishes items mapped to checks from items with evidence collected' {
            $none = Get-TPHipaaReadiness -Findings @()
            $none['Summary']['Mapped']            | Should -BeGreaterThan 0
            $none['Summary']['EvidenceCollected'] | Should -Be 0 -Because 'no check ran, so a mapping is not evidence'
            $all = Get-TPHipaaReadiness -Findings $script:AllPass
            $all['Summary']['EvidenceCollected'] | Should -Be $all['Summary']['Mapped']
            $sg = @($none['Safeguards'] | Where-Object { $_['Name'] -eq 'Technical' })[0]
            $sg['Mapped'] | Should -BeGreaterThan $sg['EvidenceCollected']
        }

        It 'reviews a standard separately: its own checks passing does not cover an open specification' {
            $p = Get-TPHipaaReadiness -Findings $script:AllPass
            # 164.308(a)(4)(i) is cited directly, and its clearinghouse specification is attestation only.
            $std = Row $p '164.308(a)(4)(i)'
            $std['MappedControls'] | Should -BeGreaterThan 0
            $std['Status']         | Should -Be 'Mapped checks satisfied, specifications open'
            $std['Specifications']['Total'] | Should -Be 3
            $std['Specifications']['Attestation required'] | Should -Be 1
            # A standard whose specifications are all satisfied may read satisfied.
            (Row $p '164.312(a)(1)')['Status'] | Should -Be 'Mapped technical checks satisfied'
            # A specification is never rolled up from its parent's citation.
            (Row $p '164.308(a)(4)(ii)(A)')['Status'] | Should -Be 'Attestation required'
        }

        It 'records the catalog version and the source snapshot date, and one amendment history' {
            $p = Get-TPHipaaReadiness -Findings @()
            $p['CatalogVersion'] | Should -Match '^\d+\.\d+$'
            $p['SourceSnapshot'] | Should -Match '^\d{4}-\d{2}-\d{2}$'
            $p['SourceRetrieved'] | Should -Match '^\d{4}-\d{2}-\d{2}$'
            $p['Amendments'] | Should -Match '78 FR 34266'
            $p['Amendments'] | Should -Not -Match 'no later change' -Because 'eCFR lists later dated entries; the catalog must not claim there are none'
        }

        It 'is a view: it changes no finding' {
            $f = @(F 'AAD-1.1' 'Gap' 'detail')
            $before = $f | ConvertTo-Json -Depth 5
            $null = Get-TPHipaaReadiness -Findings $f
            ($f | ConvertTo-Json -Depth 5) | Should -Be $before
        }
    }

    Context 'Report' {

        BeforeAll {
            $f = @($script:AllPass | Where-Object { $_.ControlId -ne 'AAD-1.1' }) + @(F 'AAD-1.1' 'Gap' '<script>alert(1)</script> & "quoted"')
            $script:Md = Join-Path $script:Tmp 'contoso-hipaa-readiness.md'
            Publish-TPHipaaReadiness -Posture (Get-TPHipaaReadiness -Findings $f) -OutputPath $script:Md -Metadata @{ TenantDomain = 'contoso.com'; AssessmentDate = '2026-10-06' }
            $script:MdText   = Get-Content -LiteralPath $script:Md -Raw
            $script:HtmlText = Get-Content -LiteralPath ([IO.Path]::ChangeExtension($script:Md, '.html')) -Raw
        }

        It 'says on page one that it is not a risk analysis or a compliance determination, and that Addressable is not optional' {
            foreach ($t in @($script:MdText, $script:HtmlText)) {
                $t | Should -Match 'not a risk analysis'
                $t | Should -Match 'not a determination of HIPAA compliance'
                $t | Should -Match 'Addressable does not mean optional'
            }
        }

        It 'separates technical results from regulatory fulfillment, and explains documenting Addressable decisions' {
            foreach ($t in @($script:MdText, $script:HtmlText)) {
                $t | Should -Match 'Statuses report technical checks, not regulatory fulfillment'
                $t | Should -Match 'documenting why'
                # 164.306(d)(3) expressly requires documentation only when a
                # specification is not implemented; the rest is a recommendation.
                $t | Should -Match 'Recommended practice: record the assessment and decision for every Addressable specification'
                $t | Should -Match 'expressly requires documenting why when the specification is not implemented'
                $t | Should -Not -Match '(?<!practice: )\bRecord the assessment and the decision for every Addressable'
                $t | Should -Match 'currently in effect'
                $t | Should -Match 'does not implement the Security Rule changes HHS proposed'
                $t | Should -Match '164\.316\(b\)'
                $t | Should -Not -Match 'Met in Microsoft 365'
                $t | Should -Match 'catalog version|Catalog:\*\* version'
            }
        }

        It 'never calls the client compliant' {
            foreach ($t in @($script:MdText, $script:HtmlText)) {
                # "Non-Compliant" is a control title (INT-1.2), not a claim about the client.
                $t | Should -Not -Match '(?i)(?<!non-)\bcompliant\b|no issues found'
            }
        }

        It 'lists every item, and every item that needs attestation in the worklist' {
            foreach ($i in $script:Items) { $script:MdText | Should -Match ([regex]::Escape($i.Citation)) }
            $script:MdText | Should -Match 'Needs documents, interviews or a walkthrough'
        }

        It 'escapes finding text and runs no script' {
            $script:HtmlText | Should -Not -Match '<script'
            $script:HtmlText | Should -Match '&lt;script&gt;'
            $script:HtmlText | Should -Match "Content-Security-Policy"
            $script:HtmlText | Should -Match "default-src 'none'"
        }
    }

    Context 'Entry point' {

        It 'has a -HIPAA switch, and -AllFiles implies it' {
            $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-TPAssessment.ps1') -Raw
            $src | Should -Match '\[switch\] \$HIPAA'
            $src | Should -Match ([regex]::Escape('if (($HIPAA -or $AllFiles)'))
        }
    }
}
