import { Identity, RiskScore, RiskBand } from '../core/types';
import { IdentityGraph } from '../graph/identityGraph';

function bandFromTotal(total: number): RiskBand {
  if (total >= 75) return 'CRITICAL';
  if (total >= 50) return 'HIGH';
  if (total >= 25) return 'MODERATE';
  return 'LOW';
}

export function scoreIdentity(identity: Identity, graph: IdentityGraph): RiskScore {
  const breakdown: Record<string, number> = {};
  let total = 0;

  // Privileged authority (edges with wildcard/admin)
  const hasPrivilegedEdge = graph.edges.some(
    (e) => (e.fromIdentityId === identity.id || e.toIdentityId === identity.id) && (e.isAdmin || e.isWildcard)
  );
  if (hasPrivilegedEdge || identity.permissions.some((p) => p.includes('*'))) {
    breakdown['privileged_authority'] = 20;
    total += 20;
  }

  // Production execution path detected
  const hasProdPath = graph.executionPaths.some(
    (ep) => ep.identityId === identity.id && ep.isProduction
  );
  if (hasProdPath) {
    breakdown['production_execution'] = 20;
    total += 20;
  }

  // Missing owner
  if (!identity.owner) {
    breakdown['missing_owner'] = 10;
    total += 10;
  }

  // Missing approval on execution path
  const hasUnapprovedProdPath = graph.executionPaths.some(
    (ep) => ep.identityId === identity.id && ep.isProduction && !ep.approvalDetected
  );
  if (hasUnapprovedProdPath) {
    breakdown['missing_approval'] = 15;
    total += 15;
  }

  // Missing evidence/receipt
  const hasNoEvidence = graph.executionPaths.some(
    (ep) => ep.identityId === identity.id && !ep.evidenceDetected
  );
  if (hasNoEvidence) {
    breakdown['missing_evidence'] = 15;
    total += 15;
  }

  // Stale credential or missing rotation
  const now = Date.now();
  const ninetyDays = 90 * 24 * 60 * 60 * 1000;
  if (identity.lastUsedAt) {
    const lastUsed = new Date(identity.lastUsedAt).getTime();
    if (now - lastUsed > ninetyDays) {
      breakdown['stale_credential'] = 10;
      total += 10;
    }
  } else if (identity.credentialTypes.length > 0) {
    // Has credentials but no usage info — flag as risk
    breakdown['stale_credential'] = 5;
    total += 5;
  }

  // Network trust boundary crossing
  const hasBoundaryCrossing = graph.executionPaths.some(
    (ep) => ep.identityId === identity.id && ep.trustBoundaryCrossed
  );
  if (hasBoundaryCrossing) {
    breakdown['trust_boundary_crossing'] = 10;
    total += 10;
  }

  // AI/agent tool access
  if (identity.identityType === 'agent_identity' || identity.identityType === 'mcp_server_identity') {
    breakdown['ai_agent_access'] = 5;
    total += 5;
  }

  // Secrets/token pattern in evidence
  if (identity.riskTags.includes('secret_exposure') || identity.riskTags.includes('credential_in_config')) {
    breakdown['secret_exposure'] = 10;
    total += 10;
  }

  const capped = Math.min(total, 100);

  return {
    total: capped,
    band: bandFromTotal(capped),
    breakdown,
  };
}

export function scoreGraph(graph: IdentityGraph): RiskScore {
  const identities = Array.from(graph.identities.values());
  if (identities.length === 0) {
    return { total: 0, band: 'LOW', breakdown: {} };
  }

  const scores = identities.map((i) => scoreIdentity(i, graph));
  const totalScore = Math.round(scores.reduce((sum, s) => sum + s.total, 0) / scores.length);

  const mergedBreakdown: Record<string, number> = {};
  for (const score of scores) {
    for (const [key, value] of Object.entries(score.breakdown)) {
      mergedBreakdown[key] = (mergedBreakdown[key] ?? 0) + value;
    }
  }

  // Average the breakdown values
  for (const key of Object.keys(mergedBreakdown)) {
    mergedBreakdown[key] = Math.round(mergedBreakdown[key] / scores.length);
  }

  return {
    total: Math.min(totalScore, 100),
    band: bandFromTotal(totalScore),
    breakdown: mergedBreakdown,
  };
}
