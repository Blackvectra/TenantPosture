#Requires -Version 7.0
#
# NRG.HipaaReadiness.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Guards the HIPAA Security Rule readiness view: Config/hipaa-security-rule.json
# (from the eCFR text of 45 CFR 164 Subpart C), Lib/Get-NRGHipaaReadiness.ps1
# and Publishers/Publish-NRGHipaaReadiness.ps1.
#
# The rules are the SSP's, because a readiness report is read as a statement
# about the client: an item no control evidences never reads as met; an item
# whose requirement is a document or a process takes no evidence from tenant
# configuration even when a control cites it; a control with no finding counts
# in neither direction; and nothing says "compliant".

Describe 'HIPAA Security Rule readiness view' {

    BeforeAll {
        $script:RepoRoot = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        Import-Module (Join-Path $script:RepoRoot 'NRG-Assessment.psm1') -Force -ErrorAction Stop
        $script:Cat = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Config/hipaa-security-rule.json') -Raw -Encoding utf8 | ConvertFrom-Json
        $script:Items = @($script:Cat.items)
        $script:Controls = @(Get-NRGControlDefinitions)

        $script:Tmp = Join-Path ([IO.Path]::GetTempPath()) ('nrg-hipaa-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
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
            Get-NRGHipaaCitationsFromText -Citation '§164.312(d), §164.308(a)(4)(ii)(B)' | Should -Be @('164.312(d)', '164.308(a)(4)(ii)(B)')
            @(Get-NRGHipaaCitationsFromText -Citation 'Req 8.3; 164.3; IA.L2-3.5.3') | Should -BeNullOrEmpty
            @(Get-NRGHipaaCitationsFromText -Citation '') | Should -BeNullOrEmpty
        }

        It 'resolves every Security Rule citation in controls.json, and names the Privacy Rule ones instead of mapping them' {
            $p = Get-NRGHipaaReadiness -Findings @()
            @($p['Summary']['UnmatchedCitations']) | Should -BeNullOrEmpty -Because 'a citation that matches no item would silently drop its evidence'
            @($p['Summary']['OutsideSecurityRule'] | Where-Object { $_ -notmatch '\(164\.5\d\d' }) | Should -BeNullOrEmpty
        }

        It 'a citation of a standard without its "(i)" means that standard' {
            $p = Get-NRGHipaaReadiness -Findings @()
            (Row $p '164.308(a)(4)(i)')['MappedControls'] | Should -BeGreaterThan 0
        }
    }

    Context 'Honesty rules' {

        It 'with every control satisfied, the items no control can evidence still claim nothing' {
            $p = Get-NRGHipaaReadiness -Findings $script:AllPass
            foreach ($r in @($p['Items'] | Where-Object { $_['MappedControls'] -eq 0 })) {
                $r['Status']     | Should -Be 'Attestation required' -Because $r['Citation']
                $r['Confidence'] | Should -Be 'Attestation only'
            }
            (Row $p '164.308(a)(1)(ii)(A)')['Status'] | Should -Be 'Attestation required' -Because 'no tenant setting is a risk analysis'
            $p['Summary']['Met'] | Should -Be $p['Summary']['Evidenced']
            $p['Summary']['AttestationRequired'] | Should -BeGreaterThan 30
        }

        It 'a control citing the clearinghouse specification is cited, not counted' {
            $p = Get-NRGHipaaReadiness -Findings $script:AllPass
            $r = Row $p '164.308(a)(4)(ii)(A)'
            $r['MappedControls'] | Should -Be 0
            $r['Status']         | Should -Be 'Attestation required'
            @($r['CitedNotCounted']) | Should -Contain 'TMS-1.1'
            @($r['Evidence'])        | Should -BeNullOrEmpty
        }

        It 'a cited control with no finding, or an Error, is never met' {
            $none = Get-NRGHipaaReadiness -Findings @()
            (Row $none '164.312(d)')['Status'] | Should -Be 'Not assessed'
            $ids = @((Row $none '164.312(d)')['Evidence'] | ForEach-Object { $_['ControlId'] })
            $err = Get-NRGHipaaReadiness -Findings @($ids | ForEach-Object { F $_ 'Error' })
            (Row $err '164.312(d)')['Status'] | Should -Be 'Not assessed'
        }

        It 'one pass beside a not-applicable control is not met' {
            $none = Get-NRGHipaaReadiness -Findings @()
            $ids = @((Row $none '164.312(d)')['Evidence'] | ForEach-Object { $_['ControlId'] })
            $ids.Count | Should -BeGreaterThan 1
            $f = @(F $ids[0] 'Satisfied') + @($ids | Select-Object -Skip 1 | ForEach-Object { F $_ 'NotApplicable' 'not licensed' })
            $r = Row (Get-NRGHipaaReadiness -Findings $f) '164.312(d)'
            $r['Status']     | Should -Be 'Not assessed'
            $r['Confidence'] | Should -Be 'Partial evidence'
        }

        It 'the worst instance of a control wins' {
            $none = Get-NRGHipaaReadiness -Findings @()
            $cid = @((Row $none '164.312(b)')['Evidence'])[0]['ControlId']
            $f = @($script:AllPass | Where-Object { $_.ControlId -ne $cid }) + @((F $cid 'Satisfied'), (F $cid 'Gap'))
            (Row (Get-NRGHipaaReadiness -Findings $f) '164.312(b)')['Status'] | Should -Be 'Shortfall found'
        }

        It 'is a view: it changes no finding' {
            $f = @(F 'AAD-1.1' 'Gap' 'detail')
            $before = $f | ConvertTo-Json -Depth 5
            $null = Get-NRGHipaaReadiness -Findings $f
            ($f | ConvertTo-Json -Depth 5) | Should -Be $before
        }
    }

    Context 'Report' {

        BeforeAll {
            $f = @($script:AllPass | Where-Object { $_.ControlId -ne 'AAD-1.1' }) + @(F 'AAD-1.1' 'Gap' '<script>alert(1)</script> & "quoted"')
            $script:Md = Join-Path $script:Tmp 'contoso-hipaa-readiness.md'
            Publish-NRGHipaaReadiness -Posture (Get-NRGHipaaReadiness -Findings $f) -OutputPath $script:Md -Metadata @{ TenantDomain = 'contoso.com'; AssessmentDate = '2026-10-06' }
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
            $src = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'Invoke-NRGAssessment.ps1') -Raw
            $src | Should -Match '\[switch\] \$HIPAA'
            $src | Should -Match ([regex]::Escape('if (($HIPAA -or $AllFiles)'))
        }
    }
}
