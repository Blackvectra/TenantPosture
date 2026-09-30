@{
    CompanyName    = 'NRG Technology Services'
    Phone          = '(701) 250-9400'
    Website        = 'https://www.nrgtechservices.com'
    Email          = 'security@nrgtechservices.com'
    Address        = ''
    CityStateZip   = ''

    PrimaryColor   = '#1a3a6b'
    SecondaryColor = '#e87722'
    AccentColor    = '#4a7ba6'

    LogoUrl        = ''

    # Optional: the third-party EDR standardized across your clients (e.g.
    # 'Cortex XDR', 'CrowdStrike Falcon', 'SentinelOne'). It is the default
    # for every client that does not set ThirdPartyEDR in clients.json or pass
    # -ThirdPartyEDR. The Microsoft Defender endpoint checks (INT-1.5, INT-2.1,
    # INT-2.2, DEV-2.x) are then reported as covered by that product —
    # declared, not verified — and left out of the score. Leave '' if
    # Microsoft Defender for Endpoint is the EDR.
    EdrStack       = ''

    # Optional: the NRG monitoring address(es) security alert policies should
    # notify, for example @('alerts@your-domain.com') or a whole domain
    # '@your-domain.com'. DEF-3.4 and EXO-3.3 compare every enabled alert
    # policy's recipients with this list. Leave empty and those two controls
    # report that routing to NRG was not assessed (recipients existing still is).
    # Override per client with MonitoringAddresses in clients.json or per run
    # with -MonitoringAddress.
    MonitoringAddresses = @()

    HourlyRate     = 185
    AssessmentFee  = 2500
    RegulatedFee   = 3500
    GovernanceFee  = 1500
}
