import { Identity, AuthorityEdge, ExecutionPath, InflectionPoint, Finding, NHIGraph, EvidenceRef } from '../core/types';
export declare class IdentityGraph {
    identities: Map<string, Identity>;
    edges: AuthorityEdge[];
    executionPaths: ExecutionPath[];
    inflectionPoints: InflectionPoint[];
    findings: Finding[];
    evidenceRefs: EvidenceRef[];
    addIdentity(identity: Identity): void;
    addEdge(edge: AuthorityEdge): void;
    addExecutionPath(ep: ExecutionPath): void;
    addInflectionPoint(point: InflectionPoint): void;
    addFinding(finding: Finding): void;
    addEvidenceRef(ref: EvidenceRef): void;
    toJSON(): NHIGraph;
}
//# sourceMappingURL=identityGraph.d.ts.map