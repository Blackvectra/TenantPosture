# Sample Report

This directory contains an example HTML assessment report so you can see what NRG-Assessment produces without having to run it against a real tenant.

The sample demonstrates the output format including:
- Executive summary with score breakdown
- Findings table filterable by framework, severity, and status
- Per-control detail with remediation commands
- Framework crosswalk appendix

**File:** `example-assessment.html`

All tenant-identifying data has been sanitized to RFC 5737 documentation values:
- Tenant domain: `example.com`
- UPNs: `admin@example.com`, `user@example.com`
- Tenant GUIDs: all zeros (`00000000-0000-0000-0000-000000000000`)
- Real Microsoft well-known role / SKU GUIDs preserved so the report still parses
- IP addresses: `192.0.2.0/24` (RFC 5737 documentation range)

