"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IdentityGraph = void 0;
class IdentityGraph {
    identities = new Map();
    edges = [];
    executionPaths = [];
    inflectionPoints = [];
    findings = [];
    evidenceRefs = [];
    addIdentity(identity) {
        this.identities.set(identity.id, identity);
    }
    addEdge(edge) {
        this.edges.push(edge);
    }
    addExecutionPath(ep) {
        this.executionPaths.push(ep);
    }
    addInflectionPoint(point) {
        this.inflectionPoints.push(point);
    }
    addFinding(finding) {
        this.findings.push(finding);
    }
    addEvidenceRef(ref) {
        this.evidenceRefs.push(ref);
    }
    toJSON() {
        return {
            identities: Array.from(this.identities.values()),
            edges: this.edges,
            executionPaths: this.executionPaths,
            inflectionPoints: this.inflectionPoints,
            findings: this.findings,
            evidenceRefs: this.evidenceRefs,
        };
    }
}
exports.IdentityGraph = IdentityGraph;
//# sourceMappingURL=identityGraph.js.map