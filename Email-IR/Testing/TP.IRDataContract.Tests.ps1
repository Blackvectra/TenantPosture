#Requires -Version 7.0
#
# TP.IRDataContract.Tests.ps1
# TenantPosture
# Author: Matthew Levorson
#
# The incident-response mode writes more than UPN and display name by design
# (sign-in addresses, geolocation, subjects, URLs: they are the indicators),
# and the audit of 2026-10-09 found two things in that JSON that are not
# indicators: the full phone number of every registered phone method, and the
# credential-bearing query string of a URL found in a message body (a
# SharePoint or Storage SAS `sig=`, an `access_token=`). These tests pin the
# helpers that remove them, drive the REAL collectors so the raw data never
# carries them (an evaluator fixture would never exercise the collector), and
# pin the documentation of the exception.

Describe 'IR data contract' {

    BeforeAll {
        $script:RepoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        Import-Module (Join-Path $script:RepoRoot 'TenantPosture.psm1') -Force -ErrorAction Stop
        $script:Mod = Get-Module 'TenantPosture'
    }

    Context 'ConvertTo-TPRedactedUrl' {

        It 'returns a URL with no query string as given' {
            ConvertTo-TPRedactedUrl 'https://badco.example/login' | Should -Be 'https://badco.example/login'
            ConvertTo-TPRedactedUrl 'https://badco.example/login?' | Should -Be 'https://badco.example/login?'
        }

        It 'returns an empty string for nothing' {
            ConvertTo-TPRedactedUrl $null | Should -Be ''
            ConvertTo-TPRedactedUrl ''    | Should -Be ''
        }

        It 'redacts the value of <Name> and keeps the host, path, the other parameters and the fragment' -ForEach @(
            @{ Name = 'sig' }, @{ Name = 'token' }, @{ Name = 'access_token' }, @{ Name = 'code' },
            @{ Name = 'key' }, @{ Name = 'apikey' }, @{ Name = 'password' }, @{ Name = 'client_secret' },
            @{ Name = 'SIG' }, @{ Name = 'X-Amz-Signature' }
        ) {
            $url = "https://corp.sharepoint.com/sites/f/doc.docx?sv=2024-01-01&$Name=SECRET123&se=2026-01-01#frag"
            $out = ConvertTo-TPRedactedUrl $url
            $out | Should -Be "https://corp.sharepoint.com/sites/f/doc.docx?sv=2024-01-01&$Name=[redacted]&se=2026-01-01#frag"
            $out | Should -Not -Match 'SECRET123'
        }

        It 'redacts a name that ends in a credential suffix (<Name>)' -ForEach @(
            @{ Name = 'oauth_token' }, @{ Name = 'my_secret' }, @{ Name = 'userPassword' }, @{ Name = 'X-Goog-Signature' }, @{ Name = 'X-Amz-Credential' }
        ) {
            ConvertTo-TPRedactedUrl "https://h.example/p?$Name=SECRET123" | Should -Be "https://h.example/p?$Name=[redacted]"
        }

        It 'leaves an ordinary parameter alone' {
            ConvertTo-TPRedactedUrl 'https://h.example/p?id=5&page=2&sp=r&se=2026&q=token' |
                Should -Be 'https://h.example/p?id=5&page=2&sp=r&se=2026&q=token'
        }

        It 'redacts a percent-encoded name' {
            ConvertTo-TPRedactedUrl 'https://h.example/p?%73ig=SECRET123' | Should -Be 'https://h.example/p?%73ig=[redacted]'
        }

        It 'redacts userinfo before the host' {
            # Assembled from parts: a literal user:password@host URL in a test file
            # is exactly what a secret scanner flags, and it would be right to.
            $withUserinfo = 'https://' + 'alice:Pa55' + 'word@h.example/p'
            ConvertTo-TPRedactedUrl $withUserinfo | Should -Be 'https://[redacted]@h.example/p'
            ConvertTo-TPRedactedUrl ($withUserinfo + '?token=x') | Should -Be 'https://[redacted]@h.example/p?token=[redacted]'
        }

        It 'redacts a credential in a query that sits inside the fragment' {
            ConvertTo-TPRedactedUrl 'https://app.example/#/reset?token=SECRET123&next=home' |
                Should -Be 'https://app.example/#/reset?token=[redacted]&next=home'
        }

        It 'keeps a parameter with no value' {
            ConvertTo-TPRedactedUrl 'https://h.example/p?flag&sig=S' | Should -Be 'https://h.example/p?flag&sig=[redacted]'
        }

        It 'redacts a one-time code by name or suffix (<Name>)' -ForEach @(
            @{ Name = 'oobCode' }, @{ Name = 'oob_code' }, @{ Name = 'verificationCode' }, @{ Name = 'authKey' },
            @{ Name = 'nonce' }, @{ Name = 'SAMLResponse' }, @{ Name = 'confirm' }, @{ Name = 'passcode' }, @{ Name = 'otp_code' }) {
            ConvertTo-TPRedactedUrl "https://app.example/action?mode=resetPassword&$Name=SECRET123&lang=en" |
                Should -Be "https://app.example/action?mode=resetPassword&$Name=[redacted]&lang=en"
        }

        It 'redacts a semicolon-delimited parameter and keeps the delimiters' {
            ConvertTo-TPRedactedUrl 'https://app.example/reset?lang=en;token=SECRET123;next=home' |
                Should -Be 'https://app.example/reset?lang=en;token=[redacted];next=home'
            ConvertTo-TPRedactedUrl 'https://app.example/reset?lang=en&sig=S1;code=S2' |
                Should -Be 'https://app.example/reset?lang=en&sig=[redacted];code=[redacted]'
        }

        It 'redacts a parameter inside the fragment whether or not an outer query precedes it (<Label>)' -ForEach @(
            @{ Label = 'outer query then hash route'; Url = 'https://app.example/?lang=en#/reset?token=SECRET123&next=home'; Expected = 'https://app.example/?lang=en#/reset?token=[redacted]&next=home' }
            @{ Label = 'implicit-flow fragment';      Url = 'https://app.example/cb#access_token=SECRET123&expires_in=3600&state=xyz'; Expected = 'https://app.example/cb#access_token=[redacted]&expires_in=3600&state=xyz' }
            @{ Label = 'outer secret and fragment secret'; Url = 'https://app.example/p?sig=S1#id_token=S2'; Expected = 'https://app.example/p?sig=[redacted]#id_token=[redacted]' }
            @{ Label = 'plain anchor';                Url = 'https://app.example/p?x=1#section-2'; Expected = 'https://app.example/p?x=1#section-2' }) {
            ConvertTo-TPRedactedUrl $Url | Should -Be $Expected
        }

        It 'redacts a credential inside a percent-encoded destination URL carried by a wrapper (<Label>)' -ForEach @(
            @{ Label = 'Safe Links style';  Url = 'https://safe.example/?url=https%3A%2F%2Fapp.example%2Freset%3Ftoken%3DSECRET123%26lang%3Den&data=05';
                                           Expected = 'https://safe.example/?url=https%3A%2F%2Fapp.example%2Freset%3Ftoken%3D%5Bredacted%5D%26lang%3Den&data=05' }
            @{ Label = 'raw nested URL';    Url = 'https://r.example/go?u=https://app.example/p?sig=SECRET123'; Expected = 'https://r.example/go?u=https://app.example/p?sig=[redacted]' }
            @{ Label = 'nested twice';      Url = 'https://a.example/?u=https%3A%2F%2Fb.example%2F%3Fu%3Dhttps%253A%252F%252Fc.example%252F%253Ftoken%253DSECRET123';
                                           Expected = 'https://a.example/?u=https%3A%2F%2Fb.example%2F%3Fu%3Dhttps%253A%252F%252Fc.example%252F%253Ftoken%253D%255Bredacted%255D' }
            @{ Label = 'a benign nested URL is kept as it came'; Url = 'https://safe.example/?url=https%3A%2F%2Fapp.example%2Fdocs%3Fpage%3D2'; Expected = 'https://safe.example/?url=https%3A%2F%2Fapp.example%2Fdocs%3Fpage%3D2' }) {
            $out = ConvertTo-TPRedactedUrl $Url
            $out | Should -Be $Expected
            $out | Should -Not -Match 'SECRET123'
        }

        It 'redacts the whole userinfo up to the last @ before the path' {
            $u = 'https://' + 'alice@example.com:SECRET123' + '@evil.example/p?x=1'
            ConvertTo-TPRedactedUrl $u | Should -Be 'https://[redacted]@evil.example/p?x=1'
            $u2 = 'https://' + 'a@b@c:SECRET123' + '@h.example/'
            ConvertTo-TPRedactedUrl $u2 | Should -Be 'https://[redacted]@h.example/'
            ConvertTo-TPRedactedUrl 'https://h.example/p?mail=alice@example.com' | Should -Be 'https://h.example/p?mail=alice@example.com' -Because 'an @ after the path is not userinfo'
        }

        It 'never leaves a secret value behind, whichever delimiter or position carries it' {
            foreach ($u in 'https://a.example/?a=1&token=SECRET', 'https://a.example/?a=1;token=SECRET', 'https://a.example/#token=SECRET',
                           'https://a.example/?a=1#x?token=SECRET', 'https://a.example/?oobCode=SECRET', 'https://a.example/?a=1#/r?lang=en;oobCode=SECRET',
                           'https://a.example/?u=https%3A%2F%2Fb.example%2F%3Fsig%3DSECRET', 'https://a.example/?u=https://b.example/#access_token=SECRET',
                           ('https://' + 'x:SECRET' + '@a.example/'), ('https://' + 'x@y:SECRET' + '@a.example/?u=https%3A%2F%2Fb.example%2F%3Fcode%3DSECRET')) {
                ConvertTo-TPRedactedUrl $u | Should -Not -Match 'SECRET' -Because $u
            }
        }
    }

    Context 'ConvertTo-TPMaskedPhone' {

        It 'keeps the country code and the last two digits (<In> -> <Out>)' -ForEach @(
            @{ In = '+1 2065550100';  Out = '+1 ********00' }
            @{ In = '+44 7700900123'; Out = '+44 ********23' }
            @{ In = '2065550100';     Out = '********00' }
            @{ In = '+12065550100';   Out = '+*********00' }
            @{ In = '+1 206-555-0100'; Out = '+1 ***-***-**00' }
            @{ In = '12';             Out = '**' }
            @{ In = '';               Out = '' }
        ) {
            ConvertTo-TPMaskedPhone $In | Should -Be $Out
        }

        It 'never keeps more than the last two digits of the number' {
            foreach ($n in '+1 2065550100', '+353 851234567', '0612345678', '+49 30 123456') {
                $masked = ConvertTo-TPMaskedPhone $n
                $digits = @([regex]::Matches(($masked -replace '^\+\d{1,3} ', ''), '\d')).Count
                $digits | Should -BeLessOrEqual 2 -Because "'$n' was stored as '$masked'"
            }
        }

        It 'does not treat a non-numeric prefix as a country code' {
            ConvertTo-TPMaskedPhone '+abc 2065550100' | Should -Be '+abc ********00'
        }
    }

    Context 'the real collectors store the minimized form' {

        BeforeAll {
            $script:RealGraph = & $script:Mod { ${function:Invoke-TPGraphRequest} }
            # Graph stand-in in MODULE scope, keyed on the URI, so the collectors
            # run unchanged. Every message carries a SAS link and a reset link.
            & $script:Mod {
                Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value {
                    param([string] $Method, [string] $Uri, $Body, $Headers, [string] $OutputType, $ErrorAction)
                    $when = (Get-Date).ToUniversalTime().AddDays(-1).ToString('o')
                    $preview = 'Open https://corp.sharepoint.com/sites/f/doc.docx?sv=2024-01-01&sig=SASSECRET123&se=2026 then https://evil.example/reset?token=RESETSECRET456&u=1 and https://plain.example/page'
                    $msg = @{
                        id = 'm1'; subject = 'Shared file'; receivedDateTime = $when; sentDateTime = $when; hasAttachments = $false
                        from = @{ emailAddress = @{ address = 'alerts@badco.example'; name = 'Account Team' } }
                        toRecipients = @(@{ emailAddress = @{ address = 'bob@corp.example' } })
                        ccRecipients = @(); bccRecipients = @()
                        bodyPreview = $preview
                    }
                    if ($Uri -match '/mailFolders/SentItems/')                { return @{ value = @($msg) } }
                    if ($Uri -match '/mailFolders/Inbox/messages')            { return @{ value = @($msg) } }
                    if ($Uri -match '/mailFolders/recoverableitemsdeletions') { return @{ value = @($msg) } }
                    if ($Uri -match '/messageRules')                          { return @{ value = @() } }
                    if ($Uri -match '/mailboxSettings') {
                        # The reply texts are message bodies: they must not reach the raw data.
                        return @{ automaticRepliesSetting = @{ status = 'alwaysEnabled'; externalAudience = 'all'; internalReplyMessage = '<p>OOO-INTERNAL-BODY-SECRET</p>'; externalReplyMessage = 'OOO-EXTERNAL-BODY-SECRET' }; delegateMeetingMessageDeliveryOptions = 'sendToDelegateOnly' }
                    }
                    if ($Uri -match '/authentication/methods') {
                        return @{ value = @(
                            @{ '@odata.type' = '#microsoft.graph.phoneAuthenticationMethod'; id = 'p1'; phoneNumber = '+1 2065550100'; phoneType = 'mobile'; createdDateTime = $when }
                            @{ '@odata.type' = '#microsoft.graph.microsoftAuthenticatorAuthenticationMethod'; id = 'a1'; displayName = 'Pixel 9'; createdDateTime = $when }
                            @{ '@odata.type' = '#microsoft.graph.emailAuthenticationMethod'; id = 'e1'; emailAddress = 'alice.alt@example.net'; createdDateTime = $when }
                        ) }
                    }
                    if ($Uri -match '/oauth2PermissionGrants')                { return @{ value = @() } }
                    return @{ id = 'u1'; displayName = 'Alice'; mail = 'alice@corp.example'; userPrincipalName = 'alice@corp.example' }
                }
            }
            & $script:Mod { Clear-TPState }
            Invoke-TPEmailCollectMailbox -WindowDays 7 -TargetUpn 'alice@corp.example' 3>$null | Out-Null
            Invoke-TPEmailCollectUserSecurity -TargetUpn 'alice@corp.example' 3>$null | Out-Null
            $script:Raw = Get-TPRawData
            $script:RawJson = $script:Raw | ConvertTo-Json -Depth 12
        }

        AfterAll {
            & $script:Mod { param($g) Set-Item -Path 'function:script:Invoke-TPGraphRequest' -Value $g } $script:RealGraph
            & $script:Mod { Clear-TPState }
        }

        It 'every mailbox section (<Key>) stores the links with their credentials redacted and the hosts kept' -ForEach @(
            @{ Key = 'IR-MailboxSentItems' }, @{ Key = 'IR-MailboxInbox' }, @{ Key = 'IR-MailboxRecoverable' }
        ) {
            $bag = Get-TPRawData -Key $Key
            $bag.Success | Should -BeTrue -Because "the stub answers $Key"
            @($bag.Data.Messages).Count | Should -Be 1
            $urls = @($bag.Data.Messages | ForEach-Object { $_.BodyURLs })
            $urls.Count | Should -Be 3
            $urls | Should -Contain 'https://corp.sharepoint.com/sites/f/doc.docx?sv=2024-01-01&sig=[redacted]&se=2026'
            $urls | Should -Contain 'https://evil.example/reset?token=[redacted]&u=1'
            $urls | Should -Contain 'https://plain.example/page'
        }

        It 'the user-security collector stores the phone method masked and the other display values whole' {
            $methods = @((Get-TPRawData -Key 'IR-UserAuthMethods').Data.Methods)
            $methods.Count | Should -Be 3
            ($methods | Where-Object { $_.MethodType -eq 'phoneAuthenticationMethod' }).Display | Should -Be '+1 ********00'
            ($methods | Where-Object { $_.MethodType -eq 'microsoftAuthenticatorAuthenticationMethod' }).Display | Should -Be 'Pixel 9'
            ($methods | Where-Object { $_.MethodType -eq 'emailAuthenticationMethod' }).Display | Should -Be 'alice.alt@example.net'
        }

        It 'nothing in the raw data carries the number, the SAS signature or the reset token' {
            $script:RawJson | Should -Not -Match '2065550100'
            $script:RawJson | Should -Not -Match 'SASSECRET123'
            $script:RawJson | Should -Not -Match 'RESETSECRET456'
        }

        It 'the automatic-reply texts are not stored; their state, audience and presence are' {
            $auto = (Get-TPRawData -Key 'IR-MailboxForwarding').Data.AutomaticRepliesSetting
            $auto.status | Should -Be 'alwaysEnabled'
            $auto.externalAudience | Should -Be 'all'
            $auto.hasInternalReplyMessage | Should -BeTrue
            $auto.hasExternalReplyMessage | Should -BeTrue
            $script:RawJson | Should -Not -Match 'OOO-INTERNAL-BODY-SECRET'
            $script:RawJson | Should -Not -Match 'OOO-EXTERNAL-BODY-SECRET'
        }
    }

    Context 'static: every stored URL and phone number passes through the helpers' {

        BeforeAll {
            $script:ParseCalls = {
                param([string] $Path)
                $t = $null; $e = $null
                $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$t, [ref]$e)
                $e.Count | Should -Be 0
                @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
                    ForEach-Object { $_.GetCommandName() })
            }
        }

        It 'the mailbox collector redacts at every site that extracts a URL from a body preview' {
            $path = Join-Path $script:RepoRoot 'Email-IR' 'Collectors' 'Invoke-TPEmailCollectMailbox.ps1'
            $text = Get-Content -LiteralPath $path -Raw
            $sites = [regex]::Matches($text, "\[regex\]::Matches\([^\n]*https\?://").Count
            $sites | Should -BeGreaterThan 0
            $calls = @(& $script:ParseCalls $path | Where-Object { $_ -eq 'ConvertTo-TPRedactedUrl' }).Count
            $calls | Should -Be $sites -Because 'a URL extraction site that stores the raw match writes a credential to the results JSON'
        }

        It 'the user-security collector masks the phone number' {
            $path = Join-Path $script:RepoRoot 'Email-IR' 'Collectors' 'Invoke-TPEmailCollectUserSecurity.ps1'
            @(& $script:ParseCalls $path | Where-Object { $_ -eq 'ConvertTo-TPMaskedPhone' }).Count | Should -BeGreaterThan 0
        }

        It 'the helpers make no network call and read no module state' {
            $path = Join-Path $script:RepoRoot 'Email-IR' 'Lib' 'ConvertTo-TPRedactedUrl.ps1'
            $names = @(& $script:ParseCalls $path)
            $names | Where-Object { $_ -match '^(Invoke-(RestMethod|WebRequest|TPGraphRequest|MgGraphRequest)|Get-TPRawData|Set-TPRawData|Add-TPFinding)$' } | Should -BeNullOrEmpty
        }
    }

    Context 'the exception is documented where the contract is stated' {

        It 'SECURITY.md states what the incident-response mode writes and the two lookups' {
            $text = Get-Content -LiteralPath (Join-Path $script:RepoRoot 'SECURITY.md') -Raw
            $text | Should -Match '## Data the Tool Writes'
            $text | Should -Match 'ConvertTo-TPMaskedPhone'
            $text | Should -Match 'ConvertTo-TPRedactedUrl'
            $text | Should -Match 'rdap\.org'
            $text | Should -Match '-EnableThreatIntel:\$false'
        }

        It 'the OSS-scanner threat model, CLAUDE.md and the Email-IR README state the same exception' {
            foreach ($rel in '.oss-scanner/threat_model.md', 'CLAUDE.md', 'Email-IR/README.md') {
                $text = Get-Content -LiteralPath (Join-Path $script:RepoRoot $rel) -Raw
                $text | Should -Match 'last two digits' -Because "$rel must state the phone rule"
                $text | Should -Match 'ConvertTo-TPRedactedUrl' -Because "$rel must name the URL rule"
            }
        }
    }
}
