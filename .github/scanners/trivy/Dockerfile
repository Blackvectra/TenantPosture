# Pin for the Trivy image the OSS Scanner image job scans with
# (.github/workflows/oss-scanner-image.yml). Nothing is built from this file:
# the job reads the FROM line and runs that reference. It is a Dockerfile so
# Dependabot's docker ecosystem (.github/dependabot.yml, this directory, 7-day
# cooldown) moves the tag and digest together when Aqua publishes a release;
# a digest in a workflow step would never be updated. Scan results are only as
# current as the scanner, so this pin is kept current like the others.
#
# The tag names the release; the digest is what runs. A tag can be re-pointed,
# a digest cannot. Bump both together.
FROM docker.io/aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222
