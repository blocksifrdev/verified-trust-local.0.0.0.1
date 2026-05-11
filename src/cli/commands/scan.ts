import * as fs from 'fs';
import * as path from 'path';
import { discoverFiles } from '../../core/fileDiscovery';
import { applyEditionLimit } from '../../core/limits';
import { normalizeIdentities } from '../../core/normalization';
import { fileSystemConnector } from '../../connectors/fileSystemConnector';
import { githubActionsConnector } from '../../connectors/githubActionsConnector';
import { azureDevOpsConnector } from '../../connectors/azureDevOpsConnector';
import { gitlabCiConnector } from '../../connectors/gitlabCiConnector';
import { jenkinsConnector } from '../../connectors/jenkinsConnector';
import { terraformConnector } from '../../connectors/terraformConnector';
import { kubernetesConnector } from '../../connectors/kubernetesConnector';
import { detectNHIs } from '../../detectors/nhiDetector';
import { detectInflectionPoints } from '../../detectors/inflectionPointDetector';
import { detectCredentialRisks } from '../../detectors/credentialRiskDetector';
import { detectExecutionPaths } from '../../detectors/executionPathDetector';
import { detectNetworkInflections } from '../../detectors/networkInflectionDetector';
import { detectEvidenceGaps } from '../../detectors/evidenceGapDetector';
import { detectEffortDecay } from '../../detectors/effortDecayDetector';
import { detectAIAgents } from '../../detectors/aiAgentDetector';
import { buildGraph } from '../../graph/graphBuilder';
import { scoreGraph } from '../../scoring/trustRiskScoring';
import { writeJsonReports } from '../../reporters/jsonReporter';
import { writeHtmlReport } from '../../reporters/htmlReporter';
import { writeMarkdownReport } from '../../reporters/markdownReporter';
import { ScanResult } from '../../core/types';

export async function scanCommand(
  scanPath: string,
  opts: { out: string; edition?: string }
): Promise<void> {
  const edition = opts.edition ?? process.env['VT_EDITION'] ?? 'community';
  const outputDir = opts.out;

  console.log('');
  console.log('VerifiedTrust Local — Non-Human Identity + Execution Surface Assessment');
  console.log('=========================================================================');
  console.log(`Scanning: ${path.resolve(scanPath)}`);
  console.log(`Output:   ${path.resolve(outputDir)}`);
  console.log(`Edition:  ${edition.toUpperCase()}`);
  console.log('');

  // 1. Discover files
  process.stdout.write('Discovering files...');
  const files = await discoverFiles(path.resolve(scanPath));
  console.log(` ${files.length} files found`);

  // Pre-load file contents for efficiency
  const fileContents = new Map<string, string>();

  // 2. Run all connectors
  process.stdout.write('Running connectors...');
  const scanResults: ScanResult[] = [];

  scanResults.push(fileSystemConnector(files, fileContents));
  scanResults.push(githubActionsConnector(files, fileContents));
  scanResults.push(azureDevOpsConnector(files, fileContents));
  scanResults.push(gitlabCiConnector(files, fileContents));
  scanResults.push(jenkinsConnector(files, fileContents));
  scanResults.push(terraformConnector(files, fileContents));
  scanResults.push(kubernetesConnector(files, fileContents));
  console.log(' done');

  // 3. Run detectors
  process.stdout.write('Running detectors...');
  const allIdentities = scanResults.flatMap((r) => r.identities);

  // NHI detector
  const nhiIdentities = detectNHIs(files, fileContents);
  const credentialFindings = detectCredentialRisks(files, fileContents);
  const { identities: agentIdentities, inflectionPoints: agentInflections } = detectAIAgents(files, fileContents);

  // Create a synthetic scan result for detected NHIs
  scanResults.push({
    identities: [...nhiIdentities, ...agentIdentities],
    edges: [],
    executionPaths: [],
    inflectionPoints: agentInflections,
    findings: credentialFindings,
    evidenceRefs: [],
    sourceSystem: 'filesystem',
  });
  console.log(' done');

  // 4. Build graph
  process.stdout.write('Building identity graph...');
  const graph = buildGraph(scanResults);
  console.log(` ${graph.identities.size} identities`);

  // 5. Normalize and apply edition limits
  const allIdentitiesNormalized = normalizeIdentities(Array.from(graph.identities.values()));
  const { items: limitedIdentities, limited, total } = applyEditionLimit(allIdentitiesNormalized, edition);

  // Rebuild identities map with limited set
  graph.identities.clear();
  for (const identity of limitedIdentities) {
    graph.identities.set(identity.id, identity);
  }

  // 6. Run post-graph detectors
  process.stdout.write('Detecting execution paths...');
  const execPaths = detectExecutionPaths(limitedIdentities, files, fileContents);
  for (const ep of execPaths) {
    graph.addExecutionPath(ep);
  }

  const networkInflections = detectNetworkInflections(limitedIdentities, graph.executionPaths);
  const inflectionPoints = detectInflectionPoints(graph);
  const evidenceGapFindings = detectEvidenceGaps(files, graph);
  const effortDecayInflections = detectEffortDecay(limitedIdentities);

  for (const ip of [...inflectionPoints, ...networkInflections, ...effortDecayInflections]) {
    graph.addInflectionPoint(ip);
  }
  for (const finding of evidenceGapFindings) {
    graph.addFinding(finding);
  }
  console.log(' done');

  // 7. Score risk
  const riskScore = scoreGraph(graph);

  // 8. Generate reports
  process.stdout.write('Generating reports...');
  fs.mkdirSync(outputDir, { recursive: true });
  await writeJsonReports(graph, riskScore, outputDir);
  await writeHtmlReport(graph, riskScore, edition, outputDir);
  await writeMarkdownReport(graph, riskScore, outputDir);
  console.log(' done');

  // 9. Print summary
  console.log('');
  console.log('=== Scan Complete ===');
  console.log(`Risk Score:  ${riskScore.total}/100 (${riskScore.band})`);
  console.log(`NHIs Found:  ${total} total${limited ? `, ${limitedIdentities.length} analyzed (Community Edition limit)` : ''}`);
  console.log(`Findings:    ${graph.findings.length}`);
  console.log(`Reports:     ${path.resolve(outputDir)}`);
  console.log('');
  console.log(`  executive-report.html   — Executive HTML report`);
  console.log(`  findings.json           — All findings sorted by severity`);
  console.log(`  identity-map.json       — NHI inventory`);
  console.log(`  authority-graph.json    — Identity authority graph`);
  console.log(`  evidence-map.json       — Evidence artifacts detected`);
  console.log(`  risk-summary.json       — Risk score summary`);
  console.log(`  remediation-roadmap.md  — 30-day remediation plan`);
  console.log('');

  if (limited) {
    console.log('NOTE: Community Edition limit reached. Run with --edition pro for full analysis.');
    console.log('      Upgrade at https://verifiedtrust.io');
    console.log('');
  }
}
