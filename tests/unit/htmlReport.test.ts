import { describe, it, expect } from 'vitest';
import { generateHtmlReport } from '../../src/reporters/htmlReporter';
import { IdentityGraph } from '../../src/graph/identityGraph';
import { createIdentity } from '../../src/core/identity';
import { createFinding } from '../../src/core/finding';
import { RiskScore } from '../../src/core/types';

function makeGraph(): IdentityGraph {
  const graph = new IdentityGraph();

  const identity = createIdentity({
    name: 'svc-test',
    identityType: 'service_account',
    sourceSystem: 'filesystem',
    credentialTypes: ['access_key'],
    riskTags: [],
    owner: 'test-team',
  });
  graph.addIdentity(identity);

  graph.addFinding(createFinding({
    severity: 'HIGH',
    title: 'Test High Finding',
    description: 'A test finding',
    recommendation: 'Fix it',
    evidenceRefs: [],
    metadata: {},
  }));

  return graph;
}

const mockRiskScore: RiskScore = {
  total: 65,
  band: 'HIGH',
  breakdown: { privileged_authority: 20, missing_owner: 10 },
};

describe('generateHtmlReport', () => {
  it('returns a string', () => {
    const graph = makeGraph();
    const html = generateHtmlReport(graph, mockRiskScore, 'community');
    expect(typeof html).toBe('string');
  });

  it('contains executive report title', () => {
    const graph = makeGraph();
    const html = generateHtmlReport(graph, mockRiskScore, 'community');
    expect(html).toContain('VerifiedTrust Local Report');
  });

  it('contains Executive Verdict section', () => {
    const graph = makeGraph();
    const html = generateHtmlReport(graph, mockRiskScore, 'community');
    expect(html).toContain('Executive Verdict');
  });

  it('contains NHI Exposure Summary section', () => {
    const graph = makeGraph();
    const html = generateHtmlReport(graph, mockRiskScore, 'community');
    expect(html).toContain('NHI Exposure Summary');
  });

  it('contains Top 10 Findings section', () => {
    const graph = makeGraph();
    const html = generateHtmlReport(graph, mockRiskScore, 'community');
    expect(html).toContain('Top 10 Findings');
  });

  it('contains risk score', () => {
    const graph = makeGraph();
    const html = generateHtmlReport(graph, mockRiskScore, 'community');
    expect(html).toContain('65');
    expect(html).toContain('HIGH');
  });

  it('contains remediation plan section', () => {
    const graph = makeGraph();
    const html = generateHtmlReport(graph, mockRiskScore, 'community');
    expect(html).toContain('30-Day Remediation Plan');
  });

  it('is self-contained (no external CSS/JS links)', () => {
    const graph = makeGraph();
    const html = generateHtmlReport(graph, mockRiskScore, 'community');
    // Should not have external stylesheet links
    expect(html).not.toMatch(/href="https?:\/\//);
    expect(html).not.toMatch(/src="https?:\/\//);
  });

  it('contains VerifiedTrust branding', () => {
    const graph = makeGraph();
    const html = generateHtmlReport(graph, mockRiskScore, 'community');
    expect(html).toContain('BlockSiFr');
  });
});
