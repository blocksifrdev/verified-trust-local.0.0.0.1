import * as fs from 'fs';
import * as path from 'path';
import { RiskScore, Severity } from '../core/types';
import { IdentityGraph } from '../graph/identityGraph';

const SEVERITY_EMOJI: Record<Severity, string> = {
  CRITICAL: 'CRITICAL',
  HIGH: 'HIGH',
  MODERATE: 'MODERATE',
  LOW: 'LOW',
  INFO: 'INFO',
};

export async function writeMarkdownReport(
  graph: IdentityGraph,
  riskScore: RiskScore,
  outputDir: string
): Promise<void> {
  fs.mkdirSync(outputDir, { recursive: true });
  const md = generateMarkdownReport(graph, riskScore);
  fs.writeFileSync(path.join(outputDir, 'remediation-roadmap.md'), md, 'utf-8');
}

export function generateMarkdownReport(graph: IdentityGraph, riskScore: RiskScore): string {
  const graphData = graph.toJSON();
  const now = new Date().toISOString();

  const criticalFindings = graphData.findings.filter((f) => f.severity === 'CRITICAL');
  const highFindings = graphData.findings.filter((f) => f.severity === 'HIGH');
  const moderateFindings = graphData.findings.filter((f) => f.severity === 'MODERATE');

  const orphanedIdentities = graphData.identities.filter((i) => !i.owner);
  const prodPaths = graphData.executionPaths.filter((ep) => ep.isProduction);
  const unapprovedProdPaths = prodPaths.filter((ep) => !ep.approvalDetected);

  let md = `# VerifiedTrust Local — Remediation Roadmap

Generated: ${now}

**Risk Score: ${riskScore.total}/100 (${riskScore.band})**

---

## Executive Summary

| Metric | Count |
|--------|-------|
| Total NHIs Detected | ${graphData.identities.length} |
| Critical Findings | ${criticalFindings.length} |
| High Findings | ${highFindings.length} |
| Moderate Findings | ${moderateFindings.length} |
| Ownerless Identities | ${orphanedIdentities.length} |
| Production Execution Paths | ${prodPaths.length} |
| Unapproved Production Paths | ${unapprovedProdPaths.length} |

---

## 30-Day Remediation Plan

### Week 1: Critical and High Severity Items (Days 1–7)

**Priority: Immediate action required.**

`;

  if (criticalFindings.length > 0) {
    md += `#### Critical Findings\n\n`;
    for (const f of criticalFindings.slice(0, 5)) {
      md += `- **[${SEVERITY_EMOJI.CRITICAL}]** ${f.title}\n`;
      md += `  - _Description_: ${f.description}\n`;
      md += `  - _Recommendation_: ${f.recommendation}\n`;
      if (f.sourceFile) md += `  - _File_: \`${f.sourceFile}\`\n`;
      md += '\n';
    }
  }

  if (highFindings.length > 0) {
    md += `#### High Findings\n\n`;
    for (const f of highFindings.slice(0, 5)) {
      md += `- **[${SEVERITY_EMOJI.HIGH}]** ${f.title}\n`;
      md += `  - _Description_: ${f.description}\n`;
      md += `  - _Recommendation_: ${f.recommendation}\n`;
      if (f.sourceFile) md += `  - _File_: \`${f.sourceFile}\`\n`;
      md += '\n';
    }
  }

  if (criticalFindings.length === 0 && highFindings.length === 0) {
    md += `_No critical or high findings. Proceed to Week 2 items._\n\n`;
  }

  md += `---

### Week 2: Ownership and Approval Gaps (Days 8–14)

**Priority: Governance and accountability remediation.**

#### Actions

`;

  if (orphanedIdentities.length > 0) {
    md += `- Assign owners to **${orphanedIdentities.length}** ownerless non-human identities:\n`;
    for (const i of orphanedIdentities.slice(0, 5)) {
      md += `  - \`${i.name}\` (${i.identityType}, source: ${i.sourceSystem})\n`;
    }
    if (orphanedIdentities.length > 5) {
      md += `  - ... and ${orphanedIdentities.length - 5} more (see identity-map.json)\n`;
    }
    md += '\n';
  }

  if (unapprovedProdPaths.length > 0) {
    md += `- Add approval gates to **${unapprovedProdPaths.length}** production execution paths:\n`;
    for (const ep of unapprovedProdPaths.slice(0, 5)) {
      md += `  - \`${ep.identityName}\` → \`${ep.targetEnvironment}\` (${ep.sourceFile ?? ep.sourceSystem})\n`;
    }
    md += '\n';
  }

  md += `- Add a CODEOWNERS file to formally assign ownership of CI/CD workflows, IaC, and configuration files.
- Add pull request template with identity and security review checklist.
- Add SECURITY.md documenting vulnerability disclosure process.

---

### Week 3: Credential Hygiene and Rotation (Days 15–21)

**Priority: Reduce long-lived credential exposure.**

#### Actions

- Implement automated credential rotation for all long-lived NHI credentials using your secrets manager (Vault, AWS Secrets Manager, Azure Key Vault, etc.).
- Replace long-lived access keys with short-lived OIDC tokens using workload identity federation (GitHub Actions, AWS, GCP, Azure all support this).
- Audit and disable any NHI unused for 90+ days.
- Remove any credentials found hardcoded in source files immediately.
- Ensure all credentials follow the principle of least privilege — review wildcard (*) permissions.

---

### Week 4: Evidence, Policy, and Continuous Monitoring (Days 22–30)

**Priority: Establish ongoing governance.**

#### Actions

- Generate and publish an SBOM (Software Bill of Materials) for each release using Syft or CycloneDX.
- Implement policy-as-code using OPA/Rego to enforce identity and access policies programmatically.
- Configure environment protection rules in your CI/CD platform (GitHub, GitLab, Azure DevOps) requiring human review for production deployments.
- Add VerifiedTrust Local to your CI/CD pipeline for continuous scanning on every PR.
- Schedule weekly VerifiedTrust Local scans to catch new NHI introductions.
- Review AI agent identities and MCP server tool access — ensure all have minimum required permissions and human oversight.

---

## Identity Inventory (Top 20)

| Name | Type | Source | Owner | Risk Tags |
|------|------|--------|-------|-----------|
${graphData.identities.slice(0, 20).map((i) =>
  `| \`${i.name.replace(/\|/g, '\\|')}\` | ${i.identityType} | ${i.sourceSystem} | ${i.owner ?? '_None_'} | ${i.riskTags.join(', ') || '-'} |`
).join('\n')}

${graphData.identities.length > 20 ? `_... and ${graphData.identities.length - 20} more. See identity-map.json for full list._` : ''}

---

## Recommended VerifiedTrust Platform Next Steps

- **VerifiedTrust Pro**: Full inventory, SARIF, executive PDF, signed evidence, policy packs
- **FrontDesk**: Identity-aware access request, approval workflow, and audit trail
- **Execution Exchange**: Signed execution receipts for every machine identity action

Learn more: [verifiedtrust.io](https://verifiedtrust.io)

---

_VerifiedTrust Local v0.1.0 — Apache 2.0 — Copyright 2024 BlockSiFr — No telemetry._
`;

  return md;
}
