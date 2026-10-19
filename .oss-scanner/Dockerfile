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

# The base image by digest (7.5-ubuntu-24.04 as of 2026-10-19): a tag can be
# re-pointed at a different image; a digest cannot.
FROM mcr.microsoft.com/powershell:7.5-ubuntu-24.04@sha256:042240d57ec9e47e511033b92625a8d95875ee5860af3015992c248b58a8be81

ENV DEBIAN_FRONTEND=noninteractive \
    POWERSHELL_TELEMETRY_OPTOUT=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_NOLOGO=1

# git: the Markdown check lists tracked files. python3 + openpyxl: the XLSX
# publishers (compliance matrix, NIST matrix, SSP); without openpyxl those
# tests skip. yamllint: the workflow and config lint. Both by exact version and
# SHA-256 (.oss-scanner/requirements.txt), wheels only.
COPY .oss-scanner/requirements.txt /tmp/oss-requirements.txt
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates python3 python3-pip \
 && rm -rf /var/lib/apt/lists/* \
 && pip3 install --no-cache-dir --break-system-packages --require-hashes --only-binary=:all: -r /tmp/oss-requirements.txt

# Pester and PSScriptAnalyzer at the versions CI pins, each package checked
# against its SHA-256 in tools/pinned-modules.psd1 before it is extracted.
COPY tools/Install-TPPinnedModule.ps1 tools/pinned-modules.psd1 /tmp/tp-tools/
RUN pwsh -NoProfile -File /tmp/tp-tools/Install-TPPinnedModule.ps1 -Name Pester -Destination /usr/local/share/powershell/Modules \
 && pwsh -NoProfile -File /tmp/tp-tools/Install-TPPinnedModule.ps1 -Name PSScriptAnalyzer -Destination /usr/local/share/powershell/Modules

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
