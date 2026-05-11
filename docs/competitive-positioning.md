# Competitive Positioning

VerifiedTrust Local complements your existing security tooling rather than replacing it.

## How It Compares

| Tool Category | Examples | Their Focus | VerifiedTrust Local Adds |
|--------------|----------|-------------|--------------------------|
| PAM | CyberArk, BeyondTrust, Delinea | Vault and rotate privileged credentials | NHIs outside the vault, execution paths, trust-boundary crossings |
| IGA | SailPoint, Saviynt | Identity lifecycle for humans | Machine identity lifecycle, cross-system NHI authority mapping |
| CNAPP/CSPM | Wiz, Orca | Cloud misconfiguration at runtime | Local, offline, code-level NHI authority graph without cloud connectivity |
| CIEM | Ermetic, Sonrai | Cloud entitlement analysis | Multi-IDP, multi-pipeline, local-first, works on IaC before deploy |
| Secret Scanners | Gitleaks, TruffleHog | Find exposed secrets in code | Also maps identity authority, execution paths, and inflection points |
| SAST | Semgrep, CodeQL | Code vulnerabilities | Identity-specific patterns: ownership gaps, approval bypasses, stale credentials |

## The NHI Gap

Most security tools are optimized for either human identities or cloud runtime. VerifiedTrust Local focuses specifically on:

1. **Code-level NHI detection** — finding identities in workflows, IaC, and configs before they reach production
2. **Authority graph** — mapping who can do what across CI/CD, cloud, and PAM systems
3. **Execution path analysis** — tracing how machine identities reach production and whether those paths have approval gates
4. **Trust boundary visibility** — identifying where identities cross from dev to prod, internal to external
5. **AI/Agent identity** — detecting and assessing new agent and MCP identities

## Positioning

VerifiedTrust Local is the foundation layer for non-human identity governance. It gives you the inventory and risk picture that PAM, IGA, CNAPP, and CIEM tools need as inputs — without requiring cloud connectivity, agent deployment, or enterprise rollout.
