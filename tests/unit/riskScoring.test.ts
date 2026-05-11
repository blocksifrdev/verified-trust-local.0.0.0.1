import { describe, it, expect } from 'vitest';
import { scoreIdentity, scoreGraph } from '../../src/scoring/trustRiskScoring';
import { createIdentity } from '../../src/core/identity';
import { createExecutionPath } from '../../src/core/executionPath';
import { createAuthorityEdge } from '../../src/core/authorityEdge';
import { IdentityGraph } from '../../src/graph/identityGraph';

describe('scoreIdentity', () => {
  it('gives high/critical score to identity with no owner, admin permission, and no approval', () => {
    const graph = new IdentityGraph();
    const identity = createIdentity({
      name: 'admin-sa',
      identityType: 'service_account',
      sourceSystem: 'filesystem',
      credentialTypes: ['access_key'],
      riskTags: [],
      // No owner
    });
    graph.addIdentity(identity);

    // Add admin edge
    const targetIdentity = createIdentity({
      name: 'target-role',
      identityType: 'aws_iam_role',
      sourceSystem: 'aws_iam',
      credentialTypes: [],
      riskTags: [],
    });
    graph.addIdentity(targetIdentity);
    graph.addEdge(createAuthorityEdge({
      fromIdentityId: identity.id,
      toIdentityId: targetIdentity.id,
      relation: 'assumes',
      permissions: ['*'],
      isWildcard: true,
      isAdmin: true,
      sourceSystem: 'aws_iam',
    }));

    // Add unapproved production execution path
    graph.addExecutionPath(createExecutionPath({
      identityId: identity.id,
      identityName: identity.name,
      trigger: 'push',
      targetEnvironment: 'production',
      isProduction: true,
      approvalDetected: false,
      evidenceDetected: false,
      trustBoundaryCrossed: true,
      sourceSystem: 'github_actions',
    }));

    const score = scoreIdentity(identity, graph);
    expect(score.band).toMatch(/HIGH|CRITICAL/);
    expect(score.total).toBeGreaterThanOrEqual(50);
  });

  it('gives low score to identity with owner and limited permission', () => {
    const graph = new IdentityGraph();
    const identity = createIdentity({
      name: 'read-only-sa',
      identityType: 'service_account',
      sourceSystem: 'aws_iam',
      credentialTypes: ['access_key'],
      riskTags: [],
      owner: 'platform-team',
      permissions: ['s3:GetObject'],
    });
    graph.addIdentity(identity);

    const score = scoreIdentity(identity, graph);
    expect(score.band).toMatch(/LOW|MODERATE/);
    expect(score.total).toBeLessThan(50);
  });
});

describe('scoreGraph', () => {
  it('returns low score for empty graph', () => {
    const graph = new IdentityGraph();
    const score = scoreGraph(graph);
    expect(score.total).toBe(0);
    expect(score.band).toBe('LOW');
  });

  it('returns a score with breakdown for non-empty graph', () => {
    const graph = new IdentityGraph();
    const identity = createIdentity({
      name: 'test-sa',
      identityType: 'service_account',
      sourceSystem: 'filesystem',
      credentialTypes: ['access_key'],
      riskTags: [],
    });
    graph.addIdentity(identity);

    const score = scoreGraph(graph);
    expect(score.total).toBeGreaterThanOrEqual(0);
    expect(score.total).toBeLessThanOrEqual(100);
    expect(typeof score.breakdown).toBe('object');
  });
});
