@{
    CompanyName    = 'TenantPosture'
    Phone          = ''
    Website        = ''
    Email          = ''
    Address        = ''
    CityStateZip   = ''

    PrimaryColor   = '#1a3a6b'
    SecondaryColor = '#e87722'
    AccentColor    = '#4a7ba6'

    LogoUrl        = ''

    # Which framework cards the HTML report shows when -Framework is not
    # given: NIST, CIS, SCuBA, CMMC or All. Presentation only: every framework
    # is still scored and the results JSON is unchanged.
    DefaultFramework = 'All'

    # The reporting address(es) or @domains that must appear in every managed
    # domain's DMARC rua (DNS-1.3), for example a DMARC analytics mailbox. This
    # is your own address, so it lives in the profile, not in the shared
    # Config/tp-standards.json. Empty means that component is not assessed.
    DmarcReportingAddresses = @()

    # Optional: the third-party EDR standardized across your clients (e.g.
    # 'Cortex XDR', 'CrowdStrike Falcon', 'SentinelOne'). It is the default
    # for every client that does not set ThirdPartyEDR in clients.json or pass
    # -ThirdPartyEDR. The Microsoft Defender endpoint checks (INT-1.5, INT-2.1,
    # INT-2.2, DEV-2.x) are then reported as covered by that product —
    # declared, not verified — and left out of the score. Leave '' if
    # Microsoft Defender for Endpoint is the EDR.
    EdrStack       = ''

    # Optional: the phishing simulation / security awareness training platform
    # standardized across your clients (e.g. 'KnowBe4'). It is the default for
    # every client that does not set ThirdPartyAwareness in clients.json or
    # pass -ThirdPartyAwareness. DEF-4.6 (Microsoft Attack Simulation
    # Training) is then reported as run on that platform — declared, not
    # verified — and left out of the score. Leave '' if Microsoft Attack
    # Simulation Training is the platform.
    AwarenessStack = ''

    # Optional: your monitoring address(es) security alert policies should
    # notify, for example @('alerts@your-domain.com') or a whole domain
    # '@your-domain.com'. DEF-3.4 and EXO-3.3 compare every enabled alert
    # policy's recipients with this list. Leave empty and those two controls
    # report that routing to you was not assessed (recipients existing still is).
    # Override per client with MonitoringAddresses in clients.json or per run
    # with -MonitoringAddress.
    MonitoringAddresses = @()

    HourlyRate     = 0
    AssessmentFee  = 0
    RegulatedFee   = 0
    GovernanceFee  = 0
}
