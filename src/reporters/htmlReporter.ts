import * as fs from 'fs';
import * as path from 'path';
import { RiskScore, Severity } from '../core/types';
import { IdentityGraph } from '../graph/identityGraph';
import { generateExecutiveSummary } from './executiveSummary';
import { UPGRADE_MESSAGE } from '../core/edition';

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function severityColor(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL': return '#c0392b';
    case 'HIGH': return '#e67e22';
    case 'MODERATE': return '#f39c12';
    case 'LOW': return '#27ae60';
    case 'INFO': return '#2980b9';
  }
}

function bandColor(band: string): string {
  switch (band) {
    case 'CRITICAL': return '#c0392b';
    case 'HIGH': return '#e67e22';
    case 'MODERATE': return '#f39c12';
    case 'LOW': return '#27ae60';
    default: return '#7f8c8d';
  }
}

export async function writeHtmlReport(
  graph: IdentityGraph,
  riskScore: RiskScore,
  edition: string,
  outputDir: string
): Promise<void> {
  fs.mkdirSync(outputDir, { recursive: true });
  const html = generateHtmlReport(graph, riskScore, edition);
  fs.writeFileSync(path.join(outputDir, 'executive-report.html'), html, 'utf-8');
}

export function generateHtmlReport(
  graph: IdentityGraph,
  riskScore: RiskScore,
  edition: string
): string {
  const graphData = graph.toJSON();
  const executiveSummary = generateExecutiveSummary(graph, riskScore, edition);
  const now = new Date().toISOString();

  const criticalFindings = graphData.findings.filter((f) => f.severity === 'CRITICAL');
  const highFindings = graphData.findings.filter((f) => f.severity === 'HIGH');
  const allFindingsSorted = [...graphData.findings].sort(
    (a, b) =>
      ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'INFO'].indexOf(a.severity) -
      ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'INFO'].indexOf(b.severity)
  );

  const privilegedIdentities = Array.from(graph.identities.values()).filter(
    (i) => i.riskTags.includes('admin') || i.riskTags.includes('wildcard') || i.permissions.some((p) => p.includes('*'))
  );

  const orphanedIdentities = Array.from(graph.identities.values()).filter((i) => !i.owner);
  const prodPaths = graphData.executionPaths.filter((ep) => ep.isProduction);
  const unapprovedProdPaths = prodPaths.filter((ep) => !ep.approvalDetected);
  const agentIdentities = Array.from(graph.identities.values()).filter(
    (i) => i.identityType === 'agent_identity' || i.identityType === 'mcp_server_identity'
  );

  const sourceSystemCounts: Record<string, number> = {};
  for (const identity of graph.identities.values()) {
    sourceSystemCounts[identity.sourceSystem] = (sourceSystemCounts[identity.sourceSystem] ?? 0) + 1;
  }

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VerifiedTrust Local Report</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #f4f6f9; color: #2c3e50; font-size: 14px; }
  .header { background: #1a2332; color: #fff; padding: 32px 48px; }
  .header h1 { font-size: 22px; font-weight: 600; letter-spacing: 0.5px; }
  .header .subtitle { color: #8fa8c8; font-size: 13px; margin-top: 6px; }
  .header .meta { color: #8fa8c8; font-size: 12px; margin-top: 4px; }
  .content { max-width: 1200px; margin: 0 auto; padding: 32px 24px; }
  .risk-banner { border-radius: 6px; padding: 24px 32px; margin-bottom: 32px; color: #fff; display: flex; align-items: center; gap: 32px; }
  .risk-score-circle { width: 80px; height: 80px; border-radius: 50%; background: rgba(255,255,255,0.2); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  .risk-score-number { font-size: 32px; font-weight: 700; }
  .risk-band-label { font-size: 20px; font-weight: 600; }
  .risk-summary-text { font-size: 14px; opacity: 0.9; margin-top: 4px; }
  .section { background: #fff; border-radius: 6px; padding: 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }
  .section-title { font-size: 16px; font-weight: 600; color: #1a2332; border-bottom: 2px solid #e8edf2; padding-bottom: 12px; margin-bottom: 16px; }
  .metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 16px; margin-bottom: 16px; }
  .metric-card { background: #f8fafc; border-radius: 4px; padding: 16px; text-align: center; border: 1px solid #e8edf2; }
  .metric-value { font-size: 28px; font-weight: 700; color: #1a2332; }
  .metric-label { font-size: 12px; color: #7f8c8d; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { background: #f4f6f9; text-align: left; padding: 10px 12px; font-weight: 600; color: #1a2332; border-bottom: 2px solid #e8edf2; }
  td { padding: 10px 12px; border-bottom: 1px solid #f0f2f5; vertical-align: top; }
  tr:hover td { background: #fafbfc; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; font-weight: 600; color: #fff; }
  .upgrade-box { background: #fef9e7; border: 1px solid #f39c12; border-radius: 6px; padding: 16px 20px; margin-top: 16px; color: #7d6608; font-size: 13px; }
  .remediation-week { background: #f8fafc; border-left: 4px solid #2980b9; padding: 12px 16px; margin-bottom: 12px; border-radius: 0 4px 4px 0; }
  .remediation-week h4 { color: #1a2332; font-size: 14px; margin-bottom: 8px; }
  .remediation-week ul { padding-left: 20px; }
  .remediation-week li { margin-bottom: 4px; font-size: 13px; }
  .footer { text-align: center; color: #7f8c8d; font-size: 12px; padding: 24px; border-top: 1px solid #e8edf2; margin-top: 32px; }
  .no-data { color: #7f8c8d; font-style: italic; font-size: 13px; }
  p { line-height: 1.6; }
</style>
</head>
<body>

<div class="header">
  <h1>VerifiedTrust Local Report — Multi-IDP Non-Human Identity + Execution Surface Assessment</h1>
  <div class="subtitle">Open-source, local-first non-human identity authority graph and execution inflection scanner</div>
  <div class="meta">Generated: ${escapeHtml(now)} &nbsp;|&nbsp; Edition: ${escapeHtml(edition.toUpperCase())} &nbsp;|&nbsp; VerifiedTrust Local v0.1.0 &nbsp;|&nbsp; No data left this machine.</div>
</div>

<div class="content">

<!-- Risk Banner -->
<div class="risk-banner" style="background: ${escapeHtml(bandColor(riskScore.band))};">
  <div class="risk-score-circle">
    <span class="risk-score-number">${riskScore.total}</span>
  </div>
  <div>
    <div class="risk-band-label">Risk Band: ${escapeHtml(riskScore.band)}</div>
    <div class="risk-summary-text">Composite risk score across ${graphData.identities.length} non-human identities, ${graphData.executionPaths.length} execution paths, ${graphData.findings.length} findings</div>
  </div>
</div>

<!-- Executive Verdict -->
<div class="section">
  <div class="section-title">Executive Verdict</div>
  <p>${escapeHtml(executiveSummary)}</p>
</div>

<!-- NHI Exposure Summary -->
<div class="section">
  <div class="section-title">NHI Exposure Summary</div>
  <div class="metric-grid">
    <div class="metric-card">
      <div class="metric-value">${graphData.identities.length}</div>
      <div class="metric-label">Total NHIs Detected</div>
    </div>
    <div class="metric-card">
      <div class="metric-value" style="color:${bandColor('CRITICAL')}">${criticalFindings.length}</div>
      <div class="metric-label">Critical Findings</div>
    </div>
    <div class="metric-card">
      <div class="metric-value" style="color:${bandColor('HIGH')}">${highFindings.length}</div>
      <div class="metric-label">High Findings</div>
    </div>
    <div class="metric-card">
      <div class="metric-value">${orphanedIdentities.length}</div>
      <div class="metric-label">Ownerless NHIs</div>
    </div>
    <div class="metric-card">
      <div class="metric-value">${unapprovedProdPaths.length}</div>
      <div class="metric-label">Unapproved Prod Paths</div>
    </div>
    <div class="metric-card">
      <div class="metric-value">${agentIdentities.length}</div>
      <div class="metric-label">AI/Agent Identities</div>
    </div>
  </div>
</div>

<!-- Identity Sources Analyzed -->
<div class="section">
  <div class="section-title">Identity Sources Analyzed</div>
  ${Object.keys(sourceSystemCounts).length > 0 ? `
  <table>
    <thead><tr><th>Source System</th><th>NHIs Detected</th></tr></thead>
    <tbody>
      ${Object.entries(sourceSystemCounts).map(([sys, count]) =>
        `<tr><td>${escapeHtml(sys)}</td><td>${count}</td></tr>`
      ).join('')}
    </tbody>
  </table>` : '<p class="no-data">No identity sources detected.</p>'}
</div>

<!-- Authority Graph Summary -->
<div class="section">
  <div class="section-title">Authority Graph Summary</div>
  <div class="metric-grid">
    <div class="metric-card"><div class="metric-value">${graphData.edges.length}</div><div class="metric-label">Authority Edges</div></div>
    <div class="metric-card"><div class="metric-value">${graphData.edges.filter((e) => e.isWildcard).length}</div><div class="metric-label">Wildcard Grants</div></div>
    <div class="metric-card"><div class="metric-value">${graphData.edges.filter((e) => e.isAdmin).length}</div><div class="metric-label">Admin Grants</div></div>
    <div class="metric-card"><div class="metric-value">${privilegedIdentities.length}</div><div class="metric-label">Privileged Identities</div></div>
  </div>
</div>

<!-- Top NHI Inflection Points -->
<div class="section">
  <div class="section-title">Top NHI Inflection Points</div>
  ${graphData.inflectionPoints.length > 0 ? `
  <table>
    <thead><tr><th>Severity</th><th>Type</th><th>Identity</th><th>Description</th></tr></thead>
    <tbody>
      ${graphData.inflectionPoints.slice(0, 15).map((ip) =>
        `<tr>
          <td><span class="badge" style="background:${severityColor(ip.severity)}">${escapeHtml(ip.severity)}</span></td>
          <td>${escapeHtml(ip.type)}</td>
          <td>${escapeHtml(ip.identityName ?? '-')}</td>
          <td>${escapeHtml(ip.description)}</td>
        </tr>`
      ).join('')}
    </tbody>
  </table>` : '<p class="no-data">No inflection points detected.</p>'}
</div>

<!-- Privileged Execution Paths -->
<div class="section">
  <div class="section-title">Privileged Execution Paths</div>
  ${prodPaths.length > 0 ? `
  <table>
    <thead><tr><th>Identity</th><th>Trigger</th><th>Environment</th><th>Approval</th><th>Trust Boundary</th></tr></thead>
    <tbody>
      ${prodPaths.slice(0, 10).map((ep) =>
        `<tr>
          <td>${escapeHtml(ep.identityName)}</td>
          <td>${escapeHtml(ep.trigger.slice(0, 60))}</td>
          <td>${escapeHtml(ep.targetEnvironment)}</td>
          <td><span class="badge" style="background:${ep.approvalDetected ? '#27ae60' : '#c0392b'}">${ep.approvalDetected ? 'YES' : 'NO'}</span></td>
          <td><span class="badge" style="background:${ep.trustBoundaryCrossed ? '#e67e22' : '#27ae60'}">${ep.trustBoundaryCrossed ? 'YES' : 'NO'}</span></td>
        </tr>`
      ).join('')}
    </tbody>
  </table>` : '<p class="no-data">No production execution paths detected.</p>'}
</div>

<!-- Dormant / Orphaned / Ownerless NHIs -->
<div class="section">
  <div class="section-title">Dormant, Orphaned, and Ownerless NHIs</div>
  ${orphanedIdentities.length > 0 ? `
  <table>
    <thead><tr><th>Identity</th><th>Type</th><th>Source</th><th>Last Used</th></tr></thead>
    <tbody>
      ${orphanedIdentities.slice(0, 10).map((i) =>
        `<tr>
          <td>${escapeHtml(i.name)}</td>
          <td>${escapeHtml(i.identityType)}</td>
          <td>${escapeHtml(i.sourceSystem)}</td>
          <td>${escapeHtml(i.lastUsedAt ?? 'Unknown')}</td>
        </tr>`
      ).join('')}
    </tbody>
  </table>` : '<p class="no-data">No ownerless identities detected.</p>'}
</div>

<!-- Credential and Secret Exposure -->
<div class="section">
  <div class="section-title">Credential and Secret Exposure</div>
  ${(() => {
    const credFindings = allFindingsSorted.filter((f) => f.inflectionType === 'SECRET_IN_CONFIG');
    return credFindings.length > 0 ? `
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>File</th></tr></thead>
    <tbody>
      ${credFindings.slice(0, 10).map((f) =>
        `<tr>
          <td><span class="badge" style="background:${severityColor(f.severity)}">${escapeHtml(f.severity)}</span></td>
          <td>${escapeHtml(f.title)}</td>
          <td>${escapeHtml(f.sourceFile ?? '-')}</td>
        </tr>`
      ).join('')}
    </tbody>
  </table>` : '<p class="no-data">No credential or secret exposures detected in scanned files.</p>';
  })()}
</div>

<!-- AI/Agent Tool Access -->
<div class="section">
  <div class="section-title">AI/Agent Tool Access</div>
  ${agentIdentities.length > 0 ? `
  <table>
    <thead><tr><th>Agent Name</th><th>Type</th><th>Source File</th><th>Risk Tags</th></tr></thead>
    <tbody>
      ${agentIdentities.map((i) =>
        `<tr>
          <td>${escapeHtml(i.name)}</td>
          <td>${escapeHtml(i.identityType)}</td>
          <td>${escapeHtml(i.sourceFile ?? '-')}</td>
          <td>${escapeHtml(i.riskTags.join(', '))}</td>
        </tr>`
      ).join('')}
    </tbody>
  </table>` : '<p class="no-data">No AI agent identities detected.</p>'}
</div>

<!-- Top 10 Findings -->
<div class="section">
  <div class="section-title">Top 10 Findings</div>
  ${allFindingsSorted.length > 0 ? `
  <table>
    <thead><tr><th>#</th><th>Severity</th><th>Title</th><th>Recommendation</th></tr></thead>
    <tbody>
      ${allFindingsSorted.slice(0, 10).map((f, idx) =>
        `<tr>
          <td>${idx + 1}</td>
          <td><span class="badge" style="background:${severityColor(f.severity)}">${escapeHtml(f.severity)}</span></td>
          <td>${escapeHtml(f.title)}</td>
          <td>${escapeHtml(f.recommendation)}</td>
        </tr>`
      ).join('')}
    </tbody>
  </table>` : '<p class="no-data">No findings recorded.</p>'}
</div>

<!-- 30-Day Remediation Plan -->
<div class="section">
  <div class="section-title">30-Day Remediation Plan</div>
  <div class="remediation-week">
    <h4>Week 1 — Critical and High Severity (Days 1–7)</h4>
    <ul>
      ${criticalFindings.length > 0
        ? criticalFindings.slice(0, 3).map((f) => `<li>${escapeHtml(f.title)}: ${escapeHtml(f.recommendation)}</li>`).join('')
        : '<li>No critical findings. Address any high-severity items below.</li>'}
      ${highFindings.length > 0
        ? highFindings.slice(0, 3).map((f) => `<li>${escapeHtml(f.title)}: ${escapeHtml(f.recommendation)}</li>`).join('')
        : ''}
    </ul>
  </div>
  <div class="remediation-week">
    <h4>Week 2 — Ownership and Approval Gaps (Days 8–14)</h4>
    <ul>
      <li>Assign owners to all ${orphanedIdentities.length} ownerless non-human identities.</li>
      <li>Add approval gates to ${unapprovedProdPaths.length} production execution paths lacking review.</li>
      <li>Implement CODEOWNERS to formalize ownership of CI/CD and IaC files.</li>
    </ul>
  </div>
  <div class="remediation-week">
    <h4>Week 3 — Credential Hygiene and Rotation (Days 15–21)</h4>
    <ul>
      <li>Implement automated credential rotation for all long-lived NHI credentials.</li>
      <li>Replace long-lived access keys with OIDC-based workload identity where possible.</li>
      <li>Audit and disable any stale or dormant identities not used in 90+ days.</li>
    </ul>
  </div>
  <div class="remediation-week">
    <h4>Week 4 — Evidence, Policy, and Monitoring (Days 22–30)</h4>
    <ul>
      <li>Add pull request templates with identity and security review checklists.</li>
      <li>Generate and publish an SBOM for each release.</li>
      <li>Implement policy-as-code (OPA/Rego) for identity and access controls.</li>
      <li>Schedule a recurring VerifiedTrust Local scan (weekly or per PR).</li>
    </ul>
  </div>
</div>

<!-- Recommended Next Step -->
<div class="section">
  <div class="section-title">Recommended Next Step</div>
  <p>VerifiedTrust Local provides a local, offline baseline of your non-human identity risk. To move from inventory to enforcement:</p>
  <ul style="margin-top:12px; padding-left:20px;">
    <li style="margin-bottom:8px;"><strong>VerifiedTrust Pro</strong> — Unlock full identity inventory (unlimited NHIs), SARIF export, executive PDF reports, signed evidence bundles, and policy packs.</li>
    <li style="margin-bottom:8px;"><strong>FrontDesk</strong> — Add identity-aware access request, approval workflow, and audit trail for non-human identities.</li>
    <li style="margin-bottom:8px;"><strong>Execution Exchange</strong> — Cryptographically signed execution receipts for every machine identity action, enabling compliance and forensic evidence chains.</li>
  </ul>
  <p style="margin-top:12px;">Contact: verifiedtrust.io</p>
  ${edition === 'community' && graphData.identities.length > 25 ? `
  <div class="upgrade-box">${escapeHtml(UPGRADE_MESSAGE)}</div>` : ''}
</div>

</div>

<div class="footer">
  VerifiedTrust Local v0.1.0 &nbsp;|&nbsp; Apache 2.0 &nbsp;|&nbsp; Copyright 2024 BlockSiFr &nbsp;|&nbsp; No telemetry. No network calls. All data remained local.
</div>

</body>
</html>`;

  return html;
}
