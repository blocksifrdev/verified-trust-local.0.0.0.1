# VerifiedTrust macOS Scanner (local build)

VerifiedTrust is a lightweight, high-fidelity macOS identity and endpoint hygiene scanner aligned with financial/compliance frameworks. This local build packages the primary scanner, a plugin framework, and export options for CSV/JSON/HTML (optional PDF). Each run stamps the scanner version in the banner and exports so you can confirm which build produced the evidence.

## Features

- UID-based scanning for daemon and user accounts
- Comprehensive effort profile (age decay, activity, privilege risk, sudo usage, linked apps, password age, failed logins)
- Service account effort decay surfaced separately (daemon UID ranges and underscore users)
- Framework mapping (NIST, ISO, PCI, HIPAA, SOX, GDPR, COBIT, CIS, Zero Trust) with compliant/review/non-compliant evidence
- MDM modes for Jamf (`<result>…</result>`) and Intune (single-line summary)
- Proof-of-scan hashes (SHA3-256/STARK-style) per account
- Export formats: CSV, JSON, HTML (PDF when `pandoc` is available)
- Plugin architecture (inherits environment, per-account execution)

## Project Layout

```
bin/verifiedtrust.sh      # Main scanner CLI
plugins/                  # Optional plugins executed per account
  ssh_keys.sh
  firewall_check.sh
output/                   # Placeholder output directory
LICENSE
README.md
```

## Usage

```bash
# Basic scan (daemon + user accounts)
bin/verifiedtrust.sh -v

# Minimal framework mapping, limit exports, enable Jamf EA mode
bin/verifiedtrust.sh -f minimal -e csv,json -m jamf

# Custom UID range and HTML export
bin/verifiedtrust.sh -u 0,1000 -e html

# Show scanner version and exit
bin/verifiedtrust.sh -V
```

### Options
- `-u <min,max>`: UID range to scan (default `0,500`)
- `-f <full|minimal>`: Framework set to include
- `-v`: Verbose logging to console (always logs to `~/VerifiedTrust-MacOS/MizanLogs`)
- `-e <csv,json,html,pdf>`: Export formats (comma separated)
- `-m <none|jamf|intune>`: MDM output modes
- `-h`: Help/usage
- `-V`: Print scanner version and exit

Environment variables:
- `KNOWN_GOOD_HASH`: SHA256 for integrity enforcement (skips check when unset)
- `PLUGIN_DIR`: Override plugin directory (default `./plugins`)
- `PARALLEL`: When set and GNU `parallel` is present, enables concurrent account processing

## Plugin Architecture

Plugins are sourced for each account and can emit structured strings that are appended to JSON results. Each plugin must expose a `plugin_main` function and can read the `PLUGIN_USER` environment variable. Example: `plugins/ssh_keys.sh` counts SSH keys and flags keys older than 180 days; `plugins/firewall_check.sh` reports macOS firewall status.

Identity-first plugins included in this build:

- `plugins/secure_token_filevault.sh`: surfaces SecureToken enablement and whether the account is listed for FileVault unlock
- `plugins/auth_policy.sh`: reports password hint presence plus notable AuthenticationAuthority flags (SecureToken, Kerberos, LocalCachedUser, NoPassword)
- `plugins/tcc_privacy.sh`: counts granted TCC entries for camera, microphone, screen recording, and automation access

Network-focused plugins included in this build:

- `plugins/remote_access.sh`: surfaces SSH, Apple Remote Events, Screen Sharing, and ARD enablement
- `plugins/vpn_clients.sh`: inventories configured VPN profiles and connected tunnels, plus common client processes
- `plugins/network_mounts.sh`: reports active SMB/AFP mounts and current `/Volumes` entries for the user

## Outputs

- **Logs**: `~/VerifiedTrust-MacOS/MizanLogs/scan_<id>.log` and `errors_<id>.log`
- **CSV**: `~/VerifiedTrust-MacOS/VerifiedTrust_macOS_ACCOUNTS_2025.csv` (first column includes scanner version)
- **JSON**: `~/VerifiedTrust-MacOS/VerifiedTrust_macOS_ACCOUNTS_2025.json` (includes `scanner_version` at the root)
- **HTML**: `~/VerifiedTrust-MacOS/VerifiedTrust_macOS_ACCOUNTS_2025.html` (includes version header; PDF if `pandoc` is installed and `pdf` export requested)
- Exports now include a `ServiceDecayNote` column/field to highlight dormant or inactive service principals
- If macOS account enumeration fails (e.g., `dscl` missing or access denied) the scanner falls back to `getent passwd` where available so you still see real account rows in the CSV/JSON/HTML outputs; if no directory tool is present it writes placeholder exports so evidence paths always exist for downstream automation.

## Notes

- The scanner relies on macOS utilities such as `dscl`, `pwpolicy`, `launchctl`, and `defaults`; running outside macOS will limit functionality.
- The integrity check is optional until you set `KNOWN_GOOD_HASH` to the script's SHA256.
- MDM-aware modes summarize results for Jamf/Intune while still writing evidence to log files.
