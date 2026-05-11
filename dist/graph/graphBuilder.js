"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.buildGraph = buildGraph;
const normalization_1 = require("../core/normalization");
const identityGraph_1 = require("./identityGraph");
function buildGraph(scanResults) {
    const graph = new identityGraph_1.IdentityGraph();
    // Collect all identities first, then normalize (deduplicate)
    const allIdentities = scanResults.flatMap((r) => r.identities);
    const normalized = (0, normalization_1.normalizeIdentities)(allIdentities);
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
//# sourceMappingURL=graphBuilder.js.map