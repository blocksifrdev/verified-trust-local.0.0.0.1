import { Identity, ExecutionPath, Finding, IdentityType } from '../core/types';
import { IdentityGraph } from './identityGraph';

export function getPrivilegedIdentities(graph: IdentityGraph): Identity[] {
  const privilegedIds = new Set<string>();

  // Identities connected by admin/wildcard edges
  for (const edge of graph.edges) {
    if (edge.isAdmin || edge.isWildcard) {
      privilegedIds.add(edge.fromIdentityId);
      privilegedIds.add(edge.toIdentityId);
    }
  }

  // Identities with admin permission tags
  const result: Identity[] = [];
  for (const identity of graph.identities.values()) {
    if (
      privilegedIds.has(identity.id) ||
      identity.permissions.some((p) => p.includes('*') || p.toLowerCase().includes('admin') || p.toLowerCase().includes('owner')) ||
      identity.riskTags.includes('admin') ||
      identity.riskTags.includes('wildcard')
    ) {
      result.push(identity);
    }
  }
  return result;
}

export function getOrphanedIdentities(graph: IdentityGraph): Identity[] {
  return Array.from(graph.identities.values()).filter((i) => !i.owner);
}

export function getHighRiskPaths(graph: IdentityGraph): ExecutionPath[] {
  return graph.executionPaths.filter(
    (ep) => ep.isProduction && (!ep.approvalDetected || ep.trustBoundaryCrossed)
  );
}

export function getIdentitiesByType(graph: IdentityGraph, type: IdentityType): Identity[] {
  return Array.from(graph.identities.values()).filter((i) => i.identityType === type);
}

export function getCriticalFindings(graph: IdentityGraph): Finding[] {
  return graph.findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
}
