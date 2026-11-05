# Pin for the OSV-Scanner image the dependency scan runs
# (.github/workflows/osv-scanner.yml). Nothing is built from this file: the job
# reads the FROM line and runs that reference. It is a Dockerfile so
# Dependabot's docker ecosystem (.github/dependabot.yml, this directory, 7-day
# cooldown) moves the tag and digest together when Google publishes a release;
# a digest in a workflow step would never be updated.
#
# The tag names the release; the digest (the multi-platform index) is what
# runs. A tag can be re-pointed, a digest cannot. Bump both together.
FROM ghcr.io/google/osv-scanner:v2.7.0@sha256:4f3b7e2c64b9d38a5febc5a7e4a3dfef1d1362f726dea7a2ef4762b46469fcd0
