# VerifiedTrust Platform Assessment for Go-to-Market (GTM) and Go-Live

Date: 2026-04-10

## Executive Summary

VerifiedTrust has a strong technical core for a **security-focused CLI scanner** with useful exports and a flexible plugin model, but it is currently at a **beta readiness level** for broad commercial go-live.

**Recommendation:**
- **Proceed with a controlled design-partner launch** (5–10 customers) rather than a broad GA release.
- Target a GA go-live after closing critical gaps in reliability, packaging, cloud depth, and support readiness.

## Readiness Scorecard (0–5)

| Domain | Score | Rationale |
|---|---:|---|
| Core product value | 4.0 | Clear identity hygiene value, practical outputs, and framework mapping. |
| Cross-platform reliability | 2.5 | Multi-OS paths exist, but behavior is uneven across macOS/Linux/Windows and depends on local tooling. |
| Cloud coverage depth | 2.5 | AWS/Azure/GCP are present but currently identity-listing centric; policy depth and privilege graphing are limited. |
| Security & trust posture | 3.0 | Script integrity check exists, but plugin trust model and hardened supply chain controls are still limited. |
| Operability (install, updates, logs) | 2.5 | No standardized packaging/release channel yet; operational docs are early-stage. |
| Enterprise go-live readiness | 2.0 | Missing SLAs, support runbooks, compatibility matrix, and formal onboarding artifacts. |

**Overall readiness:** **2.8 / 5.0 (Beta)**

## GTM Positioning Assessment

### Ideal customer profile (ICP)
- Security and IT operations teams with mixed endpoint estates.
- Compliance-sensitive organizations (SOC2/ISO/NIST-aligned controls) needing quick account posture evidence.
- Design partners comfortable with CLI-first tools and iterative rollout.

### Strong differentiators
- Unified local + cloud identity checks in one workflow.
- Fast evidence generation with CSV/JSON/HTML outputs.
- Built-in framework-oriented evidence mapping.

### Current GTM constraints
- Not yet turnkey for non-technical teams.
- Windows path is pragmatic but not deeply native.
- Cloud scans require preconfigured CLI auth and permissions, which increases onboarding friction.

## Go-Live Risk Assessment

### Critical risks before broad GA
1. **Platform consistency risk**
   - Different command dependencies across OS modes can produce uneven data quality.
2. **Cloud depth risk**
   - Current cloud checks are good for inventory baselines, but insufficient for full IAM risk posture claims.
3. **Operational readiness risk**
   - Packaging, update strategy, and support workflows are not yet mature enough for broad enterprise rollout.
4. **Trust and governance risk**
   - Plugin loading model is flexible but should be tightened for enterprise security expectations.

### Mitigations required
- Publish a formal compatibility matrix (OS versions, required binaries, auth models).
- Add deterministic test fixtures and CI validation for every platform/cloud mode.
- Introduce signed release artifacts and plugin trust controls (allowlist/signature checks).
- Expand cloud checks to include role bindings, inactive credentials, MFA posture, and excessive privilege signals.

## Go-Live Recommendation by Stage

### Stage 1: Design Partner Beta (Now)
**Go/No-Go:** **Go** (limited)

Conditions:
- 5–10 design partners.
- Weekly release cadence.
- Shared issue triage channel and rapid patch turnaround.

### Stage 2: Public Beta (After readiness gates)
**Go/No-Go:** **Conditional Go**

Required gates:
- CI matrix for macOS + Linux + Windows target modes.
- Cloud auth troubleshooting guide and least-privilege policy templates.
- Installer/distribution story (package manager or signed binaries/scripts).
- Minimum observability and support runbook.

### Stage 3: General Availability (GA)
**Go/No-Go:** **Not yet**

GA gates:
- SLO-backed reliability targets.
- Formal support and escalation model.
- Security review of plugin execution and supply-chain hardening.
- Clear pricing/packaging and buyer-facing collateral.

## 30/60/90 Day Plan

### 0–30 days (Stabilize)
- Freeze core interfaces and finalize compatibility matrix.
- Build automated smoke/integration tests for each `-o` and `-c` combination.
- Produce onboarding docs: install, auth, troubleshooting, expected outputs.

### 31–60 days (Harden)
- Add cloud policy-depth checks (high-risk IAM patterns).
- Implement plugin trust controls and signed release workflow.
- Establish release notes, versioning policy, and rollback guidance.

### 61–90 days (Scale)
- Pilot public beta with broader cohort.
- Add telemetry/diagnostics opt-in for supportability.
- Publish GA checklist and target date based on objective readiness metrics.

## Launch KPIs

- Scan success rate by platform mode.
- Cloud enumeration success rate by provider.
- Time-to-first-value (install to first usable report).
- False positive/false negative feedback rate from design partners.
- Mean time to resolve onboarding and runtime issues.

## Final Call

VerifiedTrust is **well-positioned for a focused beta GTM motion now** and can become GA-ready quickly with disciplined execution on reliability, cloud depth, and operational hardening.

## Implemented Mitigations in This Build

- Cloud identity scanning now includes provider-specific depth checks (MFA/auth methods, key hygiene, and role-assignment/binding pressure indicators) instead of inventory-only listing.
- Plugin governance now supports strict trust enforcement (owner/permission validation) and explicit allowlisting.
- Operational readiness documentation now includes packaging, release, update, rollback, and support SLA workflow guidance.
