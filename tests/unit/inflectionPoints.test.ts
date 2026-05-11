import { describe, it, expect } from 'vitest';
import { detectInflectionPoints } from '../../src/detectors/inflectionPointDetector';
import { createIdentity } from '../../src/core/identity';
import { createExecutionPath } from '../../src/core/executionPath';
import { createAuthorityEdge } from '../../src/core/authorityEdge';
import { IdentityGraph } from '../../src/graph/identityGraph';

describe('detectInflectionPoints', () => {
  it('detects OWNER_MISSING for identities without owner', () => {
    const graph = new IdentityGraph();
    const identity = createIdentity({
      name: 'svc-database',
      identityType: 'service_account',
      sourceSystem: 'filesystem',
      credentialTypes: [],
      riskTags: [],
      // No owner
    });
    graph.addIdentity(identity);

    const inflections = detectInflectionPoints(graph);
    expect(inflections.some((ip) => ip.type === 'OWNER_MISSING' && ip.identityId === identity.id)).toBe(true);
  });

  it('detects APPROVAL_BYPASS for production path without approval', () => {
    const graph = new IdentityGraph();
    const identity = createIdentity({
      name: 'ci-runner',
      identityType: 'ci_cd_runner',
      sourceSystem: 'github_actions',
      credentialTypes: [],
      riskTags: [],
    });
    graph.addIdentity(identity);
    graph.addExecutionPath(createExecutionPath({
      identityId: identity.id,
      identityName: identity.name,
      trigger: 'push',
      targetEnvironment: 'production',
      isProduction: true,
      approvalDetected: false,
      evidenceDetected: false,
      trustBoundaryCrossed: false,
      sourceSystem: 'github_actions',
    }));

    const inflections = detectInflectionPoints(graph);
    expect(inflections.some((ip) => ip.type === 'APPROVAL_BYPASS')).toBe(true);
  });

  it('does NOT detect APPROVAL_BYPASS when approval is detected', () => {
    const graph = new IdentityGraph();
    const identity = createIdentity({
      name: 'ci-runner',
      identityType: 'ci_cd_runner',
      sourceSystem: 'github_actions',
      credentialTypes: [],
      riskTags: [],
    });
    graph.addIdentity(identity);
    graph.addExecutionPath(createExecutionPath({
      identityId: identity.id,
      identityName: identity.name,
      trigger: 'push',
      targetEnvironment: 'production',
      isProduction: true,
      approvalDetected: true,
      evidenceDetected: true,
      trustBoundaryCrossed: false,
      sourceSystem: 'github_actions',
    }));

    const inflections = detectInflectionPoints(graph);
    expect(inflections.some((ip) => ip.type === 'APPROVAL_BYPASS')).toBe(false);
  });

  it('detects TRUST_BOUNDARY_CROSSING', () => {
    const graph = new IdentityGraph();
    const identity = createIdentity({
      name: 'deploy-sa',
      identityType: 'service_account',
      sourceSystem: 'github_actions',
      credentialTypes: [],
      riskTags: [],
    });
    graph.addIdentity(identity);
    graph.addExecutionPath(createExecutionPath({
      identityId: identity.id,
      identityName: identity.name,
      trigger: 'push',
      targetEnvironment: 'production',
      isProduction: true,
      approvalDetected: true,
      evidenceDetected: false,
      trustBoundaryCrossed: true,
      sourceSystem: 'github_actions',
    }));

    const inflections = detectInflectionPoints(graph);
    expect(inflections.some((ip) => ip.type === 'TRUST_BOUNDARY_CROSSING')).toBe(true);
  });

  it('detects PRIVILEGE_ESCALATION_PATH for admin edges', () => {
    const graph = new IdentityGraph();
    const from = createIdentity({
      name: 'sa-from',
      identityType: 'service_account',
      sourceSystem: 'kubernetes',
      credentialTypes: [],
      riskTags: [],
    });
    const to = createIdentity({
      name: 'cluster-admin-role',
      identityType: 'unknown_nhi',
      sourceSystem: 'kubernetes',
      credentialTypes: [],
      riskTags: [],
    });
    graph.addIdentity(from);
    graph.addIdentity(to);
    graph.addEdge(createAuthorityEdge({
      fromIdentityId: from.id,
      toIdentityId: to.id,
      relation: 'ClusterRoleBinding',
      permissions: ['*'],
      isWildcard: true,
      isAdmin: true,
      sourceSystem: 'kubernetes',
    }));

    const inflections = detectInflectionPoints(graph);
    expect(inflections.some((ip) => ip.type === 'PRIVILEGE_ESCALATION_PATH')).toBe(true);
  });
});
