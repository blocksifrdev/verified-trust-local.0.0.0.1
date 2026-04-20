# 🛡️ VerifiedTrust Multi-OS Identity Scanner

<p align="left">
  <img alt="platforms" src="https://img.shields.io/badge/Platforms-macOS%20%7C%20Linux%20%7C%20Windows-2563eb">
  <img alt="cloud" src="https://img.shields.io/badge/Cloud-AWS%20%7C%20Azure%20%7C%20GCP-0ea5e9">
  <img alt="exports" src="https://img.shields.io/badge/Exports-CSV%20%7C%20JSON%20%7C%20HTML%20%7C%20PDF-16a34a">
  <img alt="mode" src="https://img.shields.io/badge/Release-Design%20Partner%20Beta-f59e0b">
</p>

VerifiedTrust is a lightweight identity hygiene scanner for local + cloud account posture. It helps security and IT teams detect weak identity hygiene signals quickly and generate exportable evidence aligned to major compliance frameworks.

![VerifiedTrust platform overview](docs/assets/verifiedtrust-platform-overview.svg)

---

## ✨ Why teams use this

- 🧭 **Unified visibility** across local identities and cloud identities.
- ⚡ **Fast posture evidence** with CSV/JSON/HTML outputs for audits and operations.
- 🧩 **Extensible plugin model** for environment-specific controls.
- 📜 **Framework mapping** to NIST, ISO, COBIT, CIS, Zero Trust, GDPR, SOX, PCI DSS, and HIPAA.

## 🔍 Core capabilities

### 🖥️ Local identity scanning
- UID-based daemon/user account scanning on macOS and Linux.
- Windows target mode support (PowerShell-based).
- Effort profile scoring with risk labels and service-account decay context.

### ☁️ Cloud identity scanning
- **AWS** IAM users with depth checks (e.g., MFA/key hygiene indicators).
- **Azure** user posture signals (e.g., auth methods / role-assignment pressure).
- **GCP** service-account posture signals (e.g., key/binding indicators).

### 🔐 Trust and governance controls
- Optional self-integrity enforcement with `KNOWN_GOOD_HASH`.
- Plugin trust mode (`PLUGIN_TRUST_MODE=strict|permissive`).
- Plugin execution allowlisting (`PLUGIN_ALLOWLIST`).

### 📦 Output and evidence
- Export formats: `csv`, `json`, `html`, optional `pdf`.
- Per-scan logs + scan IDs for traceability.
- Proof artifacts generated alongside account findings.

---

## 🗂️ Project layout

```text
bin/verifiedtrust.sh                         # Main scanner CLI
plugins/                                     # Optional per-account plugins
docs/assets/verifiedtrust-platform-overview.svg
GO_TO_MARKET_AND_GO_LIVE_ASSESSMENT.md      # GTM and readiness guidance
OPERATIONS_RUNBOOK.md                        # Packaging, release, support, rollback
REVIEW.md                                    # Repo findings and recommendations
README.md
```

---

## 🚀 Quick start

```bash
# 1) Basic local scan (auto platform detection)
bin/verifiedtrust.sh -v

# 2) Linux targeted scan + all cloud providers
bin/verifiedtrust.sh -o linux -c all -e csv,json

# 3) Minimal framework mapping + Jamf EA summary mode
bin/verifiedtrust.sh -f minimal -e csv,json -m jamf
```

## ⚙️ CLI options

- `-u <min,max>`: UID range (default `0,500`)
- `-f <full|minimal>`: framework mapping depth
- `-v`: verbose console logging
- `-e <csv,json,html,pdf>`: export formats
- `-m <none|jamf|intune>`: MDM output mode
- `-o <auto|macos|linux|windows>`: target OS mode
- `-c <none|aws|azure|gcp|all>`: cloud scan scope
- `-h`: help

## 🌍 Environment variables

- `KNOWN_GOOD_HASH`: optional SHA256 integrity enforcement
- `PLUGIN_DIR`: plugin directory override
- `PLUGIN_TRUST_MODE`: `strict` (default) or `permissive`
- `PLUGIN_ALLOWLIST`: comma-separated plugin basenames to allow
- `PARALLEL`: requests parallel mode (local build currently runs sequential for stability)

---

## 📁 Outputs

- Logs: `~/VerifiedTrust-<PLATFORM>/MizanLogs/scan_<id>.log`
- Errors: `~/VerifiedTrust-<PLATFORM>/MizanLogs/errors_<id>.log`
- CSV: `~/VerifiedTrust-<PLATFORM>/VerifiedTrust_<PLATFORM>_ACCOUNTS_2025.csv`
- JSON: `~/VerifiedTrust-<PLATFORM>/VerifiedTrust_<PLATFORM>_ACCOUNTS_2025.json`
- HTML: `~/VerifiedTrust-<PLATFORM>/VerifiedTrust_<PLATFORM>_ACCOUNTS_2025.html`

---

## 📘 Business and go-live docs

- `GO_TO_MARKET_AND_GO_LIVE_ASSESSMENT.md` — launch posture, risk model, 30/60/90 plan.
- `OPERATIONS_RUNBOOK.md` — packaging, release cadence, update/rollback, support SLAs.
- `REVIEW.md` — repository review findings and improvement priorities.

---

## 📝 Notes

- macOS mode uses native utilities (`dscl`, `pwpolicy`, `launchctl`, `defaults`).
- Linux mode expects tools like `getent`, `chage`, `passwd`.
- Windows mode expects PowerShell availability.
- Cloud modes require authenticated CLI access (`aws`, `az`, `gcloud`).
- Jamf/Intune summary modes are macOS-focused.
