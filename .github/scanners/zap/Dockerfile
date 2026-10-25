# Pin for the OWASP ZAP image the dynamic scan runs (.github/workflows/dast.yml).
# Nothing is built from this file: the job reads the FROM line and runs that
# reference with --network host, which a container action cannot do. It is a
# Dockerfile so Dependabot's docker ecosystem (.github/dependabot.yml, this
# directory, 7-day cooldown) moves the tag and digest together when ZAP
# publishes a release; a digest in a workflow step would never be updated.
#
# The tag names the release; the digest is what runs. A tag can be re-pointed,
# a digest cannot. Bump both together.
FROM ghcr.io/zaproxy/zaproxy:2.17.0@sha256:5ccfff9a411743ab2615136a2edd7416bec9ce41572fa94e935df38c14adb2b6
