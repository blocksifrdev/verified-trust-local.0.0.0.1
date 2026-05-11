import * as fs from 'fs';
import * as path from 'path';
import { Finding, RiskScore, NHIGraph } from '../../core/types';
import { IdentityGraph } from '../../graph/identityGraph';
import { scoreGraph } from '../../scoring/trustRiskScoring';
import { writeJsonReports } from '../../reporters/jsonReporter';
import { writeHtmlReport } from '../../reporters/htmlReporter';
import { writeMarkdownReport } from '../../reporters/markdownReporter';

export async function reportCommand(
  findingsJson: string,
  opts: { out: string }
): Promise<void> {
  const edition = process.env['VT_EDITION'] ?? 'community';
  console.log(`Regenerating reports from: ${findingsJson}`);

  let findings: Finding[] = [];
  try {
    const content = fs.readFileSync(findingsJson, 'utf-8');
    const parsed = JSON.parse(content);
    // Support both array of findings and full NHIGraph format
    if (Array.isArray(parsed)) {
      findings = parsed;
    } else if (parsed.findings && Array.isArray(parsed.findings)) {
      findings = parsed.findings;
    }
  } catch (err) {
    console.error(`Cannot read findings file: ${findingsJson}`);
    process.exit(1);
  }

  // Try to read accompanying files from same directory
  const findingsDir = path.dirname(findingsJson);
  const graph = new IdentityGraph();

  // Load identity map if present
  const identityMapPath = path.join(findingsDir, 'identity-map.json');
  if (fs.existsSync(identityMapPath)) {
    try {
      const identities = JSON.parse(fs.readFileSync(identityMapPath, 'utf-8'));
      if (Array.isArray(identities)) {
        for (const i of identities) graph.addIdentity(i);
      }
    } catch { /* ignore */ }
  }

  // Load authority graph if present
  const authorityGraphPath = path.join(findingsDir, 'authority-graph.json');
  if (fs.existsSync(authorityGraphPath)) {
    try {
      const agData = JSON.parse(fs.readFileSync(authorityGraphPath, 'utf-8'));
      if (agData.edges && Array.isArray(agData.edges)) {
        for (const e of agData.edges) graph.addEdge(e);
      }
    } catch { /* ignore */ }
  }

  for (const f of findings) {
    graph.addFinding(f);
  }

  const riskScore = scoreGraph(graph);

  fs.mkdirSync(opts.out, { recursive: true });
  await writeJsonReports(graph, riskScore, opts.out);
  await writeHtmlReport(graph, riskScore, edition, opts.out);
  await writeMarkdownReport(graph, riskScore, opts.out);

  console.log(`Reports regenerated. Risk: ${riskScore.total}/100 (${riskScore.band})`);
  console.log(`Output: ${opts.out}`);
}
