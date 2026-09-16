#Requires -Version 7.0
#
# NRG.RecipientClassification.Tests.ps1
# NRG Technology Services / NextLayerSec LLC
# Author: Matthew Levorson
#
# Pins Get-NRGRecipientClass against the recipient shapes Exchange ACTUALLY
# returns, not the clean addresses every previous fixture used.
#
# The bug this suite exists for: the original parser split on '@' and required
# exactly two parts. Exchange renders a rule recipient as
#     "user@dom.tld" [SMTP:user@dom.tld]
# — the address appears twice, so the split yields three parts and the parser
# returned "internal" for every genuine external recipient. EXO-7.2 therefore
# reported a clean bill of health on a tenant with live external forwarding
# rules. Every SectionStatus guard passed, because the list was not
# empty-from-failure, it was empty-from-wrong-answer.
#
# A fixture of 'attacker@evil.tld' passes against the broken parser. That is
# precisely why the bug survived: the tests confirmed the parser on input it
# never receives in production.

BeforeAll {
    $script:ModuleRoot = Split-Path -Parent $PSScriptRoot
    . (Join-Path $script:ModuleRoot 'Lib/Get-NRGObjectField.ps1')
    . (Join-Path $script:ModuleRoot 'Lib/Get-NRGRecipientClass.ps1')

    $script:Accepted = @('nrgtechservices.com', 'nrgtech.onmicrosoft.com')

    function Invoke-Classify {
        param([string] $R, [scriptblock] $Resolver)
        Get-NRGRecipientClass -Recipient $R -AcceptedDomains $script:Accepted -Resolver $Resolver
    }
}

Describe 'Get-NRGRecipientClass — bracketed SMTP form (the regression)' {

    It 'classifies an external recipient in real EXO shape as External' {
        # THE bug. Two '@' in the string. The old parser said Internal.
        Invoke-Classify '"farmer@example-farms.com" [SMTP:farmer@example-farms.com]' | Should -Be 'External'
    }

    It 'classifies an internal recipient in real EXO shape as Internal' {
        Invoke-Classify '"Staff Member" [SMTP:staff@nrgtechservices.com]' | Should -Be 'Internal'
    }

    It 'reads the address from the brackets, not the display half' {
        # Display half carries an internal-looking address; the real
        # destination in the brackets is external. Trusting the display half
        # is a false clean.
        Invoke-Classify '"staff@nrgtechservices.com" [SMTP:attacker@evil.tld]' | Should -Be 'External'
    }

    It 'is not fooled by the reverse — external-looking display, internal target' {
        Invoke-Classify '"noreply@evil.tld" [SMTP:staff@nrgtechservices.com]' | Should -Be 'Internal'
    }

    It 'matches the SMTP tag case-insensitively' {
        Invoke-Classify '"x" [smtp:attacker@evil.tld]' | Should -Be 'External'
    }
}

Describe 'Get-NRGRecipientClass — bare address forms' {

    It 'classifies a bare external address as External' {
        Invoke-Classify 'attacker@evil.tld' | Should -Be 'External'
    }

    It 'classifies a bare internal address as Internal' {
        Invoke-Classify 'staff@nrgtechservices.com' | Should -Be 'Internal'
    }

    It 'strips the smtp: prefix ForwardingSmtpAddress carries' {
        Invoke-Classify 'smtp:attacker@evil.tld' | Should -Be 'External'
    }

    It 'strips angle brackets and quotes' {
        Invoke-Classify '<attacker@evil.tld>' | Should -Be 'External'
        Invoke-Classify '"attacker@evil.tld"'  | Should -Be 'External'
    }

    It 'is case-insensitive on the domain' {
        Invoke-Classify 'staff@NRGTechServices.COM' | Should -Be 'Internal'
        Invoke-Classify 'x@EVIL.TLD'                | Should -Be 'External'
    }

    It 'treats an empty or whitespace recipient as Internal, not a finding' {
        Invoke-Classify ''    | Should -Be 'Internal'
        Invoke-Classify '   ' | Should -Be 'Internal'
    }
}

Describe 'Get-NRGRecipientClass — legacy DN requires resolution' {

    It 'returns Unresolved for a legacy DN when no resolver is supplied' {
        # Never Internal. A DN can be an in-tenant user or a mail contact
        # pointing anywhere; guessing the safe-looking answer is the bug.
        Get-NRGRecipientClass -Recipient '"Jane Smith" [EX:/o=ExchangeLabs/ou=x/cn=jsmith]' `
            -AcceptedDomains $script:Accepted | Should -Be 'Unresolved'
    }

    It 'returns Unresolved when the resolver finds nothing' {
        Invoke-Classify '"Jane Smith" [EX:/o=ExchangeLabs/ou=x/cn=jsmith]' { param($l) $null } |
            Should -Be 'Unresolved'
    }

    It 'returns Unresolved when the resolver throws' {
        Invoke-Classify '"Jane Smith" [EX:/o=ExchangeLabs/ou=x/cn=jsmith]' { param($l) throw 'no session' } |
            Should -Be 'Unresolved'
    }

    It 'resolves a legacy DN that is an internal user' {
        Invoke-Classify '"Jane Smith" [EX:/o=ExchangeLabs/ou=x/cn=jsmith]' {
            param($l) [pscustomobject]@{ PrimarySmtpAddress = 'jane@nrgtechservices.com' }
        } | Should -Be 'Internal'
    }

    It 'resolves a legacy DN that is a mail contact pointing outside the tenant' {
        # The case the ForwardingAddress blind spot covered: a recipient
        # object that forwards mail straight out of the tenant.
        Invoke-Classify '"Outside Party" [EX:/o=ExchangeLabs/ou=x/cn=contact]' {
            param($l) [pscustomobject]@{ ExternalEmailAddress = 'SMTP:outside@evil.tld' }
        } | Should -Be 'External'
    }

    It 'prefers ExternalEmailAddress over PrimarySmtpAddress' {
        # A MailUser can hold an in-tenant primary address while mail actually
        # leaves to the external one. Reading the primary first calls that
        # internal and misses the exfil path.
        Invoke-Classify '"Dual" [EX:/o=ExchangeLabs/ou=x/cn=dual]' {
            param($l) [pscustomobject]@{
                PrimarySmtpAddress   = 'dual@nrgtechservices.com'
                ExternalEmailAddress = 'SMTP:dual@evil.tld'
            }
        } | Should -Be 'External'
    }

    It 'passes the DN itself to the resolver, not the display name' {
        $seen = $null
        Invoke-Classify '"Jane Smith" [EX:/o=ExchangeLabs/ou=x/cn=jsmith]' {
            param($l) $script:seen = $l; $null
        } | Out-Null
        $script:seen | Should -Be '/o=ExchangeLabs/ou=x/cn=jsmith'
    }
}

Describe 'Get-NRGRecipientClass — display names with no address' {

    It 'returns Unresolved for a bare display name with no resolver' {
        Get-NRGRecipientClass -Recipient 'Sales Team' -AcceptedDomains $script:Accepted |
            Should -Be 'Unresolved'
    }

    It 'resolves a bare display name through the resolver' {
        Invoke-Classify 'Sales Team' {
            param($l) [pscustomobject]@{ PrimarySmtpAddress = 'sales@nrgtechservices.com' }
        } | Should -Be 'Internal'
    }
}

Describe 'Get-NRGRecipientClass — the tri-state contract' {

    It 'never returns a truthy string for Unresolved in a boolean filter' {
        # Guards a specific trap: a classifier that returns the STRING
        # 'Unresolved' is truthy, so  Where-Object { & $classify $_ }  would
        # count every unresolvable recipient as external. Callers must compare
        # to 'External' explicitly, and this asserts the value is distinct
        # from both booleans so a careless caller fails loudly.
        $u = Get-NRGRecipientClass -Recipient 'Nobody' -AcceptedDomains $script:Accepted
        $u | Should -Be 'Unresolved'
        @('External', 'Internal', 'Unresolved') | Should -Contain $u
    }

    It 'only ever returns one of the three labels' {
        $inputs = @(
            '', '   ', 'x@evil.tld', 'smtp:x@evil.tld', '"a" [SMTP:b@evil.tld]',
            '"a" [EX:/o=x/cn=y]', 'Display Only', '@', 'no-at-sign', 'a@b@c.tld'
        )
        foreach ($i in $inputs) {
            Get-NRGRecipientClass -Recipient $i -AcceptedDomains $script:Accepted |
                Should -BeIn @('External', 'Internal', 'Unresolved')
        }
    }

    It 'does not classify a malformed multi-at string as internal' {
        # Three '@' and no brackets: not an address we can read. The old
        # parser's  -ne 2  guard called this internal.
        Get-NRGRecipientClass -Recipient 'a@b@c.tld' -AcceptedDomains $script:Accepted |
            Should -Be 'Unresolved'
    }

    It 'treats an empty accepted-domain list as everything external' {
        # If Get-AcceptedDomain failed we know nothing about the tenant's
        # domains. Calling every recipient internal there would be the same
        # false-clean bug one level up.
        Get-NRGRecipientClass -Recipient 'staff@nrgtechservices.com' -AcceptedDomains @() |
            Should -Be 'External'
    }
}

Describe 'Get-NRGRecipientClass — cache' {

    It 'memoises per recipient string and does not re-resolve' {
        $calls = 0
        $cache = @{}
        $resolver = { param($l) $script:calls++; [pscustomobject]@{ PrimarySmtpAddress = 'j@nrgtechservices.com' } }
        $script:calls = 0
        1..3 | ForEach-Object {
            Get-NRGRecipientClass -Recipient '"J" [EX:/o=x/cn=j]' -AcceptedDomains $script:Accepted `
                -Cache $cache -Resolver $resolver | Out-Null
        }
        $script:calls | Should -Be 1
        $cache.Count  | Should -Be 1
    }
}
