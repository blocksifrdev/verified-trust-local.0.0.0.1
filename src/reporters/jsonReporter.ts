import * as fs from 'fs';
import * as path from 'path';
import { RiskScore, Severity } from '../core/types';
import { IdentityGraph } from '../graph/identityGraph';
import { UPGRADE_MESSAGE } from '../core/edition';

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'INFO'];

export async function writeJsonReports(
  graph: IdentityGraph,
  riskScore: RiskScore,
  outputDir: string
): Promise<void> {
  fs.mkdirSync(outputDir, { recursive: true });

  const graphData = graph.toJSON();

  // findings.json — sorted by severity
  const sortedFindings = [...graphData.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );
  fs.writeFileSync(
    path.join(outputDir, 'findings.json'),
    JSON.stringify(sortedFindings, null, 2),
    'utf-8'
  );

  // identity-map.json
  fs.writeFileSync(
    path.join(outputDir, 'identity-map.json'),
    JSON.stringify(graphData.identities, null, 2),
    'utf-8'
  );

  // authority-graph.json
  fs.writeFileSync(
    path.join(outputDir, 'authority-graph.json'),
    JSON.stringify({ identities: graphData.identities, edges: graphData.edges }, null, 2),
    'utf-8'
  );

  // evidence-map.json
  fs.writeFileSync(
    path.join(outputDir, 'evidence-map.json'),
    JSON.stringify(graphData.evidenceRefs, null, 2),
    'utf-8'
  );

  // risk-summary.json
  const criticalCount = sortedFindings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = sortedFindings.filter((f) => f.severity === 'HIGH').length;
  const moderateCount = sortedFindings.filter((f) => f.severity === 'MODERATE').length;
  const lowCount = sortedFindings.filter((f) => f.severity === 'LOW').length;
  const totalNHIs = graphData.identities.length;
  const isLimited = totalNHIs >= 25;

  const riskSummary = {
    riskScore,
    totalNHIs,
    criticalCount,
    highCount,
    moderateCount,
    lowCount,
    topFindings: sortedFindings.slice(0, 10).map((f) => ({
      id: f.id,
      severity: f.severity,
      title: f.title,
    })),
    ...(isLimited ? { upgradeMessage: UPGRADE_MESSAGE } : {}),
    generatedAt: new Date().toISOString(),
  };

  fs.writeFileSync(
    path.join(outputDir, 'risk-summary.json'),
    JSON.stringify(riskSummary, null, 2),
    'utf-8'
  );
}
