# syntax=docker/dockerfile:1
#
# OSS Scanner build for TenantPosture (https://red.anthropic.com/oss-scanner/).
#
# Network access is available during this build and removed afterwards: the
# scan runs fully offline, so every module and package the tests need is
# installed here. The image carries the repository at /src, the module imported
# once to prove it loads, and the full Pester suite run the way CI runs it.
#
# Local check:  docker build -f .oss-scanner/Dockerfile -t tenantposture .
#               docker run --rm --network none tenantposture \
#                 pwsh -NoProfile -Command 'Invoke-Pester -Path ./Testing, ./Email-IR/Testing'

FROM mcr.microsoft.com/powershell:7.5-ubuntu-24.04

ENV DEBIAN_FRONTEND=noninteractive \
    POWERSHELL_TELEMETRY_OPTOUT=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1

# git: the Markdown check lists tracked files. python3 + openpyxl: the XLSX
# publishers (compliance matrix, NIST matrix, SSP); without openpyxl those
# tests skip. yamllint: the workflow and config lint.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates python3 python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && pip3 install --no-cache-dir --break-system-packages 'openpyxl>=3.1,<4' 'yamllint>=1.35,<2'

# Pester and PSScriptAnalyzer within the version ranges CI accepts.
RUN pwsh -NoProfile -Command ' \
      $ErrorActionPreference = "Stop"; \
      Set-PSRepository -Name PSGallery -InstallationPolicy Trusted; \
      Install-Module -Name Pester -MinimumVersion 5.5.0 -MaximumVersion 5.99.99 -Force -Scope AllUsers -SkipPublisherCheck; \
      Install-Module -Name PSScriptAnalyzer -MinimumVersion 1.21.0 -MaximumVersion 1.99.99 -Force -Scope AllUsers; \
      "Pester {0}" -f (Get-Module -ListAvailable Pester | Sort-Object Version -Descending | Select-Object -First 1).Version; \
      "PSScriptAnalyzer {0}" -f (Get-Module -ListAvailable PSScriptAnalyzer | Sort-Object Version -Descending | Select-Object -First 1).Version'

COPY . /src
WORKDIR /src

# Build. There is no compile step: the module is dot-sourced PowerShell. The
# build is therefore "the module imports, and the export lists agree with the
# manifest". Either failing fails the image.
RUN pwsh -NoProfile -File ./tools/Sync-ExportedFunctions.ps1 -Validate \
 && pwsh -NoProfile -Command ' \
      $ErrorActionPreference = "Stop"; \
      Import-Module ./TenantPosture.psm1 -Force; \
      "TenantPosture {0}: {1} functions exported" -f $TPAssessmentVersion, (Get-Command -Module TenantPosture).Count'

# Tests, as CI runs them: Testing/ and Email-IR/Testing together. The real web
# server context needs Pode and is skipped here, as on the Ubuntu CI job; it runs
# on the Windows CI job. A failing test is reported and the image is kept, so a
# regression in a test does not stop the scan.
RUN pwsh -NoProfile -Command ' \
      $c = New-PesterConfiguration; \
      $c.Run.Path = @("./Testing", "./Email-IR/Testing"); \
      $c.Run.PassThru = $true; \
      $c.Output.Verbosity = "Normal"; \
      $r = Invoke-Pester -Configuration $c; \
      "Pester: {0} passed, {1} failed, {2} skipped" -f $r.PassedCount, $r.FailedCount, $r.SkippedCount; \
      if ($r.FailedCount -gt 0) { Write-Warning "Tests failed; the image is kept so the scan can proceed." }' \
 || echo "WARNING: the test step errored; the image is kept so the scan can proceed."

CMD ["pwsh", "-NoProfile"]
