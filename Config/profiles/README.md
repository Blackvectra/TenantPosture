# Profiles

A profile is the practice-specific data the tool runs with: company name and contact for the
reports, colors, the default report framework, the DMARC reporting address, the EDR and awareness
platforms declared across every client, monitoring addresses, and rates. Nothing in a profile
changes what is assessed or how it is scored.

- `Config/branding.psd1` is the active profile by default. The shipped copy is neutral.
- `Config/profiles/<name>.psd1` is selected with `-Profile <name>` on `Invoke-TPAssessment.ps1`,
  or `TP_PROFILE=<name>` in the environment for every entry point. A name is lower-case letters,
  digits and hyphens.
- `nrg.psd1` and `nls.psd1` are the two practices this tool grew up in. Copy one to start your own.

A profile is data only (`Import-PowerShellDataFile`); it is never executed.
