import {
  Identity,
  AuthorityEdge,
  ExecutionPath,
  InflectionPoint,
  Finding,
  NHIGraph,
  EvidenceRef,
} from '../core/types';

export class IdentityGraph {
  identities: Map<string, Identity> = new Map();
  edges: AuthorityEdge[] = [];
  executionPaths: ExecutionPath[] = [];
  inflectionPoints: InflectionPoint[] = [];
  findings: Finding[] = [];
  evidenceRefs: EvidenceRef[] = [];

  addIdentity(identity: Identity): void {
    this.identities.set(identity.id, identity);
  }

  addEdge(edge: AuthorityEdge): void {
    this.edges.push(edge);
  }

  addExecutionPath(ep: ExecutionPath): void {
    this.executionPaths.push(ep);
  }

  addInflectionPoint(point: InflectionPoint): void {
    this.inflectionPoints.push(point);
  }

  addFinding(finding: Finding): void {
    this.findings.push(finding);
  }

  addEvidenceRef(ref: EvidenceRef): void {
    this.evidenceRefs.push(ref);
  }

  toJSON(): NHIGraph {
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
