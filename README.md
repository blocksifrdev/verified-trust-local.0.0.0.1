# VerifiedTrust Local

**VerifiedTrust Local is an open-source, local-first scanner for non-human identity authority, execution paths, and trust-boundary inflection points.**

Map where non-human identities gain authority, cross trust boundaries, and execute actions — without uploading source code or connecting production systems.

---

## Why It Exists

Modern software environments are filled with non-human identities (NHIs): service accounts, CI/CD runners, GitHub Apps, Kubernetes service accounts, cloud IAM roles, OAuth clients, API tokens, AI agents, and MCP servers. These identities often accumulate authority silently — granted broad permissions, never rotated, lacking owners, and executing across trust boundaries without review or evidence.

Traditional PAM tools focus on privileged human accounts. Secret scanners find exposed credentials. CNAPP tools require cloud connectivity. IGA platforms require enterprise rollout. None of them give you a coherent picture of **where machine identities gain authority and execute across trust boundaries in your own codebase and infrastructure-as-code** — offline, today, in minutes.

VerifiedTrust Local does exactly that.

---

## Quick Start

```bash
# Install
npm install -g @blocksifr/verifiedtrust-local

# Scan your repository
verifiedtrust scan . --out ./verifiedtrust-report

# View the reports
open ./verifiedtrust-report/executive-report.html
cat ./verifiedtrust-report/findings.json
```

---

## CLI Commands

### `scan <path>`
Scan a directory for non-human identities, execution paths, and trust-boundary inflection points.

```bash
verifiedtrust scan . --out ./report --edition community
verifiedtrust scan /path/to/repo --out /tmp/vt-report --edition pro
```

Options:
- `--out <dir>` — Output directory for reports (default: `./verifiedtrust-report`)
- `--edition <edition>` — Edition: community, pro, business, enterprise (default: community)

### `ingest <source> <fileOrDir>`
Ingest an offline export from an identity provider or PAM tool.

```bash
verifiedtrust ingest entra ./exports/entra-service-principals.json --out ./vt-data
verifiedtrust ingest aws ./exports/aws-iam.json --out ./vt-data
verifiedtrust ingest okta ./exports/okta-apps.csv --out ./vt-data
verifiedtrust ingest cyberark ./exports/cyberark-accounts.csv --out ./vt-data
verifiedtrust ingest csv ./exports/custom.csv --out ./vt-data
```

Supported sources: `entra`, `okta`, `aws`, `azure`, `gcp`, `cyberark`, `beyondtrust`, `delinea`, `vault`, `csv`, `log`

### `analyze <dataDir>`
Analyze previously ingested data.

```bash
verifiedtrust analyze ./vt-data --out ./report
```

### `report <findingsJson>`
Regenerate reports from an existing findings file.

```bash
verifiedtrust report ./report/findings.json --out ./report
```

### `doctor`
Check the environment and print diagnostic information.

```bash
verifiedtrust doctor
```

### `activate`
Activate a Pro/Business/Enterprise license key.

```bash
verifiedtrust activate --license VT-XXXX-XXXX-XXXX-XXXX
```

---

## GitHub Action Usage

Add to `.github/workflows/verifiedtrust.yml`:

```yaml
name: VerifiedTrust NHI Scan

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 8 * * 1'  # Weekly Monday morning

jobs:
  verifiedtrust-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: VerifiedTrust Local Scan
        uses: blocksifr/verifiedtrust-local@v1
        with:
          scan-path: '.'
          output-dir: 'verifiedtrust-report'
          edition: 'community'
      
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: verifiedtrust-report
          path: verifiedtrust-report/
```

---

## Offline Export Ingestion

VerifiedTrust Local is designed to work entirely offline. Export data from your identity systems and ingest locally:

| Source | Export Method | Format |
|--------|--------------|--------|
| Entra ID | Azure Portal > App Registrations > Export | JSON |
| Okta | Okta Admin > Reports > Applications | CSV |
| AWS IAM | `aws iam get-account-authorization-details` | JSON |
| Azure | `az role assignment list --all` | JSON |
| GCP | `gcloud projects get-iam-policy PROJECT_ID` | JSON |
| CyberArk | CyberArk Central Policy Manager > Export | CSV |
| BeyondTrust | BeyondTrust Password Safe > Export | CSV/JSON |
| Delinea | Secret Server > Reports > Export | CSV |
| HashiCorp Vault | Vault audit logs / entity export | JSON |

See [docs/offline-exports.md](docs/offline-exports.md) for detailed export instructions.

---

## Supported Sources

VerifiedTrust Local detects non-human identities from:

- **Filesystem**: `.env` files, config files, credential references
- **GitHub Actions**: Workflow files, GITHUB_TOKEN, secrets, OIDC
- **Azure DevOps**: `azure-pipelines.yml`, service connections
- **GitLab CI**: `.gitlab-ci.yml`, CI_JOB_TOKEN
- **Jenkins**: `Jenkinsfile`, credentials(), withCredentials
- **Terraform**: IAM roles, policies, service accounts, federated identities
- **Kubernetes**: ServiceAccounts, RoleBindings, ClusterRoleBindings
- **Entra ID** (offline export): App registrations, service principals, managed identities
- **Okta** (offline export): OAuth service apps
- **AWS IAM** (offline export): Roles, users, trust policies
- **Azure** (offline export): Role assignments, managed identities
- **GCP IAM** (offline export): Service accounts, IAM bindings
- **CyberArk** (offline export): Managed accounts, safes
- **BeyondTrust** (offline export): Managed accounts
- **Delinea/Thycotic** (offline export): Secrets, folders
- **HashiCorp Vault** (offline export): Entities, auth mounts
- **Generic CSV**: Any CSV with identity data
- **Generic Log**: CSV/JSON logs with actor/action data

---

## Security Model

- **No network calls**: VerifiedTrust Local makes zero outbound connections.
- **Read-only**: All scanning is read-only. No files are modified.
- **Local processing**: All data stays on your machine.
- **Secret redaction**: Detected secrets are redacted before appearing in any report. The tool shows patterns, not values.
- **No telemetry**: No usage data, analytics, or error reports are sent anywhere.
- **No agent required**: No sidecar, no daemon, no persistent process.

---

## Community vs Pro/Business/Enterprise

| Feature | Community | Pro | Business | Enterprise |
|---------|-----------|-----|----------|------------|
| NHI inventory (detailed) | First 25 | Unlimited | Unlimited | Unlimited |
| Identity graph | Yes | Yes | Yes | Yes |
| Execution path detection | Yes | Yes | Yes | Yes |
| Inflection point detection | Yes | Yes | Yes | Yes |
| JSON/HTML/Markdown reports | Yes | Yes | Yes | Yes |
| SARIF export | - | Yes | Yes | Yes |
| Executive PDF report | - | Yes | Yes | Yes |
| Signed evidence bundles | - | Yes | Yes | Yes |
| Policy packs | - | Yes | Yes | Yes |
| FrontDesk integration | - | - | Yes | Yes |
| Execution Exchange | - | - | - | Yes |
| SSO / SAML | - | - | Yes | Yes |
| Priority support | - | - | Yes | Yes |
| SLA | - | - | Yes | Yes |

Upgrade at [verifiedtrust.io](https://verifiedtrust.io).

---

## Competitive Positioning

VerifiedTrust Local is **not** a replacement for your existing security tools. It **complements** them:

| Tool Category | What They Do | What VerifiedTrust Local Adds |
|--------------|-------------|-------------------------------|
| PAM (CyberArk, BeyondTrust, Delinea) | Vault and rotate privileged credentials | Which NHIs exist outside the vault, execution paths, trust-boundary crossings |
| IGA (SailPoint, Saviynt) | Identity lifecycle for humans | Machine identity lifecycle, cross-system NHI authority mapping |
| CNAPP/CSPM (Wiz, Orca) | Cloud misconfiguration at runtime | Local, offline, code-level NHI authority graph without cloud connectivity |
| CIEM (Ermetic, Sonrai) | Cloud entitlement analysis | Multi-IDP, multi-pipeline, local-first, works on IaC before deploy |
| Secret Scanners (Gitleaks, TruffleHog) | Find exposed secrets in code | Also maps identity authority, execution paths, and inflection points |
| SAST (Semgrep, CodeQL) | Code vulnerabilities | Identity-specific patterns: ownership gaps, approval bypasses, stale credentials |

---

## Upgrade to VerifiedTrust Platform

VerifiedTrust Local is the foundation. The full VerifiedTrust platform includes:

- **VerifiedTrust** — Full multi-IDP identity authority graph, continuous monitoring, policy enforcement
- **FrontDesk** — Identity-aware access request, approval workflow, and audit trail
- **Execution Exchange** — Signed execution receipts for every machine identity action

Contact: [verifiedtrust.io](https://verifiedtrust.io) | [BlockSiFr](https://blocksifr.com)

---

## License

Apache 2.0. Copyright 2024 BlockSiFr.
