# 📦 VerifiedTrust Operational Readiness Runbook

Date: 2026-04-10

## 🎯 Objective
This runbook closes go-live operational gaps by defining packaging, update, and support workflows for production rollout.

## 1) 🧱 Packaging Strategy

### Release artifacts
- `verifiedtrust-<version>.tar.gz` containing:
  - `bin/verifiedtrust.sh`
  - `plugins/*.sh`
  - `README.md`
  - `RELEASE_NOTES.md`
- `SHA256SUMS` file for integrity verification.

### Distribution channels
- Internal artifact registry (primary).
- GitHub release assets (secondary) with immutable version tags.

### Install methods
- Manual install via tarball extraction.
- Managed deployment via MDM/endpoint tooling (Jamf/Intune/SCCM/Ansible).

## 2) 🔄 Update Strategy

### Versioning
- Semantic versioning: `MAJOR.MINOR.PATCH`.
- Patch: bug fixes/security hardening.
- Minor: backward-compatible features.
- Major: breaking changes.

### Release cadence
- Weekly patch train for beta.
- Biweekly or monthly for GA, with emergency hotfix path.

### Update process
1. Build artifact + checksums.
2. Run CI matrix checks (`-o` and `-c` permutations).
3. Publish release notes with known issues and rollback steps.
4. Promote to canary tenants first, then broad rollout.

### Rollback process
- Maintain previous two release artifacts.
- If regression rate exceeds threshold, roll back to previous stable tag.
- Open incident and publish postmortem within 48 hours.

## 3) 🆘 Support Workflow

### Support tiers
- **Tier 1:** Installation/authentication/configuration issues.
- **Tier 2:** Runtime scan errors, provider-specific troubleshooting.
- **Tier 3:** Engineering escalation for defects and hotfixes.

### SLAs (recommended)
- Sev1: response 1 hour, mitigation 4 hours.
- Sev2: response 4 hours, mitigation 1 business day.
- Sev3: response 1 business day, mitigation next release cycle.

### Required support artifacts
- Error logs (`errors_<scan_id>.log`).
- Scan logs (`scan_<scan_id>.log`).
- Invocation command and selected flags.
- Cloud provider auth context and permissions used.

## 4) 🔐 Security and Governance

### Plugin trust policy
- Default `PLUGIN_TRUST_MODE=strict`.
- Plugins must be owned by root/current user and not group/world writable.
- Optional `PLUGIN_ALLOWLIST` to restrict executable plugins by basename.

### Release integrity
- Publish SHA256 checksums for every release artifact.
- Recommend signature-based verification for production channels.

## 5) ✅ Go-Live Exit Criteria

- CI pass rate >= 99% across supported platform/provider matrix.
- Cloud scan failure rate < 5% for properly permissioned tenants.
- Documented support runbook and on-call rotation in place.
- Security review complete for plugin execution and release pipeline.
