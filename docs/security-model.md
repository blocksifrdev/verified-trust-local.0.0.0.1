# Security Model

## No Network Calls

VerifiedTrust Local makes zero outbound network connections. All scanning, analysis, and reporting happens on your machine.

## Read-Only

The tool only reads files. It does not modify, delete, or create any files in your repository.

## Secret Redaction

When credential patterns are detected, the values are redacted before appearing in any report:
- First 3 and last 3 characters are preserved for identification
- Middle characters are replaced with `***`
- Strings shorter than 8 characters are fully redacted to `[REDACTED]`

## No Telemetry

No usage data, analytics, error reports, or scan results are sent anywhere.

## Local Storage Only

License information is stored locally in `~/.verifiedtrust/license.json`. No license validation calls are made to external servers in Community Edition.

## Principle of Least Privilege

The tool runs as the current user and requires only read access to the directories being scanned.
