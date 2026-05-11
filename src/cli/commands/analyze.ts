import * as fs from 'fs';
import * as path from 'path';
import { ScanResult } from '../../core/types';
import { buildGraph } from '../../graph/graphBuilder';
import { detectInflectionPoints } from '../../detectors/inflectionPointDetector';
import { detectEvidenceGaps } from '../../detectors/evidenceGapDetector';
import { detectEffortDecay } from '../../detectors/effortDecayDetector';
import { scoreGraph } from '../../scoring/trustRiskScoring';
import { writeJsonReports } from '../../reporters/jsonReporter';
import { writeHtmlReport } from '../../reporters/htmlReporter';
import { writeMarkdownReport } from '../../reporters/markdownReporter';

export async function analyzeCommand(
  dataDir: string,
  opts: { out: string }
): Promise<void> {
  const edition = process.env['VT_EDITION'] ?? 'community';
  console.log(`Analyzing ingested data from: ${dataDir}`);

  // Read all JSON files from dataDir
  let jsonFiles: string[] = [];
  try {
    jsonFiles = fs.readdirSync(dataDir)
      .filter((f) => f.endsWith('.json'))
      .map((f) => path.join(dataDir, f));
  } catch (err) {
    console.error(`Cannot read data directory: ${dataDir}`);
    process.exit(1);
  }

  if (jsonFiles.length === 0) {
    console.error('No .json files found in data directory. Run "verifiedtrust ingest" first.');
    process.exit(1);
  }

  const scanResults: ScanResult[] = [];
  for (const jsonFile of jsonFiles) {
    try {
      const content = fs.readFileSync(jsonFile, 'utf-8');
      const result = JSON.parse(content) as ScanResult;
      scanResults.push(result);
    } catch {
      console.warn(`Skipping malformed file: ${jsonFile}`);
    }
  }

  console.log(`Loaded ${scanResults.length} data files with ${scanResults.flatMap((r) => r.identities).length} total identities.`);

  const graph = buildGraph(scanResults);

  // Run post-graph detectors
  const identities = Array.from(graph.identities.values());
  const inflectionPoints = detectInflectionPoints(graph);
  const effortDecay = detectEffortDecay(identities);
  const evidenceGaps = detectEvidenceGaps([], graph);

  for (const ip of [...inflectionPoints, ...effortDecay]) {
    graph.addInflectionPoint(ip);
  }
  for (const f of evidenceGaps) {
    graph.addFinding(f);
  }

  const riskScore = scoreGraph(graph);

  fs.mkdirSync(opts.out, { recursive: true });
  await writeJsonReports(graph, riskScore, opts.out);
  await writeHtmlReport(graph, riskScore, edition, opts.out);
  await writeMarkdownReport(graph, riskScore, opts.out);

  console.log(`Analysis complete. Risk: ${riskScore.total}/100 (${riskScore.band})`);
  console.log(`Reports written to: ${opts.out}`);
}
