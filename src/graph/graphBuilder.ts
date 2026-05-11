import { ScanResult } from '../core/types';
import { normalizeIdentities } from '../core/normalization';
import { IdentityGraph } from './identityGraph';

export function buildGraph(scanResults: ScanResult[]): IdentityGraph {
  const graph = new IdentityGraph();

  // Collect all identities first, then normalize (deduplicate)
  const allIdentities = scanResults.flatMap((r) => r.identities);
  const normalized = normalizeIdentities(allIdentities);

  for (const identity of normalized) {
    graph.addIdentity(identity);
  }

  for (const result of scanResults) {
    for (const edge of result.edges) {
      graph.addEdge(edge);
    }
    for (const ep of result.executionPaths) {
      graph.addExecutionPath(ep);
    }
    for (const ip of result.inflectionPoints) {
      graph.addInflectionPoint(ip);
    }
    for (const finding of result.findings) {
      graph.addFinding(finding);
    }
    for (const ref of result.evidenceRefs) {
      graph.addEvidenceRef(ref);
    }
  }

  return graph;
}
