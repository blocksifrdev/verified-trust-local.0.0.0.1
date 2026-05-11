import { InflectionPoint } from '../core/types';
import { createInflectionPoint } from '../core/inflectionPoint';
import { IdentityGraph } from '../graph/identityGraph';

const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;

export function detectInflectionPoints(graph: IdentityGraph): InflectionPoint[] {
  const points: InflectionPoint[] = [];
  const now = Date.now();

  for (const identity of graph.identities.values()) {
    // CREDENTIAL_STALE
    if (identity.lastUsedAt) {
      const lastUsed = new Date(identity.lastUsedAt).getTime();
      if (now - lastUsed > NINETY_DAYS_MS) {
        points.push(createInflectionPoint({
          type: 'CREDENTIAL_STALE',
          severity: 'MODERATE',
          identityId: identity.id,
          identityName: identity.name,
          description: `Identity "${identity.name}" has not been used in over 90 days (last use: ${identity.lastUsedAt})`,
          recommendation: 'Review whether this identity is still required. Rotate or disable if unused.',
          metadata: { lastUsedAt: identity.lastUsedAt },
        }));
      }
    }

    // ROTATION_MISSING
    if (identity.credentialTypes.length > 0 && !identity.lastRotatedAt) {
      points.push(createInflectionPoint({
        type: 'ROTATION_MISSING',
        severity: 'MODERATE',
        identityId: identity.id,
        identityName: identity.name,
        description: `Identity "${identity.name}" has credentials (${identity.credentialTypes.join(', ')}) but no rotation evidence detected`,
        recommendation: 'Implement automated credential rotation for all non-human identity credentials.',
        metadata: { credentialTypes: identity.credentialTypes },
      }));
    }

    // OWNER_MISSING
    if (!identity.owner) {
      points.push(createInflectionPoint({
        type: 'OWNER_MISSING',
        severity: 'MODERATE',
        identityId: identity.id,
        identityName: identity.name,
        description: `Identity "${identity.name}" has no assigned owner`,
        recommendation: 'Assign a responsible owner (individual or team) to every non-human identity.',
        metadata: {},
      }));
    }
  }

  // APPROVAL_BYPASS
  for (const ep of graph.executionPaths) {
    if (ep.isProduction && !ep.approvalDetected) {
      points.push(createInflectionPoint({
        type: 'APPROVAL_BYPASS',
        severity: 'HIGH',
        identityId: ep.identityId,
        identityName: ep.identityName,
        executionPathId: ep.id,
        description: `Execution path for "${ep.identityName}" deploys to "${ep.targetEnvironment}" without detected approval gate`,
        recommendation: 'Require manual approval or automated policy gate before production deployments.',
        sourceFile: ep.sourceFile,
        metadata: { trigger: ep.trigger, environment: ep.targetEnvironment },
      }));
    }

    // EVIDENCE_MISSING
    if (!ep.evidenceDetected) {
      points.push(createInflectionPoint({
        type: 'EVIDENCE_MISSING',
        severity: 'LOW',
        identityId: ep.identityId,
        identityName: ep.identityName,
        executionPathId: ep.id,
        description: `No execution receipt or evidence detected for "${ep.identityName}" path to "${ep.targetEnvironment}"`,
        recommendation: 'Implement deployment receipts, audit logging, and signed evidence for all execution paths.',
        sourceFile: ep.sourceFile,
        metadata: { trigger: ep.trigger },
      }));
    }

    // TRUST_BOUNDARY_CROSSING
    if (ep.trustBoundaryCrossed) {
      points.push(createInflectionPoint({
        type: 'TRUST_BOUNDARY_CROSSING',
        severity: 'HIGH',
        identityId: ep.identityId,
        identityName: ep.identityName,
        executionPathId: ep.id,
        description: `Identity "${ep.identityName}" crosses a trust boundary deploying to "${ep.targetEnvironment}"`,
        recommendation: 'Ensure trust boundary crossings have explicit authorization, network segmentation, and audit logging.',
        sourceFile: ep.sourceFile,
        metadata: { environment: ep.targetEnvironment },
      }));
    }
  }

  // PRIVILEGE_ESCALATION_PATH
  for (const edge of graph.edges) {
    if (edge.isWildcard || edge.isAdmin) {
      const fromIdentity = graph.identities.get(edge.fromIdentityId);
      points.push(createInflectionPoint({
        type: 'PRIVILEGE_ESCALATION_PATH',
        severity: edge.isAdmin ? 'CRITICAL' : 'HIGH',
        identityId: edge.fromIdentityId,
        identityName: fromIdentity?.name ?? edge.fromIdentityId,
        edgeId: edge.id,
        description: `Identity has ${edge.isAdmin ? 'admin/cluster-admin' : 'wildcard'} authority via ${edge.relation}`,
        recommendation: 'Replace wildcard and admin authority grants with least-privilege specific permissions.',
        sourceFile: edge.sourceFile,
        metadata: { relation: edge.relation, permissions: edge.permissions, scope: edge.scope },
      }));
    }
  }

  // AI_CODE_CHANGE_PATH
  for (const identity of graph.identities.values()) {
    if (identity.identityType === 'agent_identity' || identity.identityType === 'mcp_server_identity') {
      const hasProdPath = graph.executionPaths.some(
        (ep) => ep.identityId === identity.id && ep.isProduction
      );
      if (hasProdPath) {
        points.push(createInflectionPoint({
          type: 'AI_CODE_CHANGE_PATH',
          severity: 'HIGH',
          identityId: identity.id,
          identityName: identity.name,
          description: `AI agent identity "${identity.name}" has detected production execution path`,
          recommendation: 'Ensure AI agent code changes require human review and approval before reaching production.',
          metadata: {},
        }));
      }
    }
  }

  return points;
}
