import { describe, it, expect } from 'vitest';
import { detectEvidenceGaps } from '../../src/detectors/evidenceGapDetector';
import { IdentityGraph } from '../../src/graph/identityGraph';
import { DiscoveredFile } from '../../src/core/fileDiscovery';

describe('detectEvidenceGaps', () => {
  it('generates finding for missing CODEOWNERS', () => {
    const graph = new IdentityGraph();
    const files: DiscoveredFile[] = [
      { path: '/repo/src/index.ts', size: 100, extension: '.ts' },
      { path: '/repo/package.json', size: 200, extension: '.json' },
    ]; // No CODEOWNERS

    const findings = detectEvidenceGaps(files, graph);
    expect(findings.some((f) => f.title.includes('CODEOWNERS'))).toBe(true);
  });

  it('does not generate CODEOWNERS finding when CODEOWNERS is present', () => {
    const graph = new IdentityGraph();
    const files: DiscoveredFile[] = [
      { path: '/repo/CODEOWNERS', size: 100, extension: '' },
      { path: '/repo/src/index.ts', size: 100, extension: '.ts' },
    ];

    const findings = detectEvidenceGaps(files, graph);
    expect(findings.some((f) => f.title.includes('CODEOWNERS'))).toBe(false);
  });

  it('generates finding for missing SECURITY.md', () => {
    const graph = new IdentityGraph();
    const files: DiscoveredFile[] = [];

    const findings = detectEvidenceGaps(files, graph);
    expect(findings.some((f) => f.title.toLowerCase().includes('security'))).toBe(true);
  });

  it('generates finding for missing PR template', () => {
    const graph = new IdentityGraph();
    const files: DiscoveredFile[] = [];

    const findings = detectEvidenceGaps(files, graph);
    expect(findings.some((f) => f.title.toLowerCase().includes('pr_template') || f.title.toLowerCase().includes('pull request'))).toBe(true);
  });

  it('returns array of findings', () => {
    const graph = new IdentityGraph();
    const findings = detectEvidenceGaps([], graph);
    expect(Array.isArray(findings)).toBe(true);
    expect(findings.length).toBeGreaterThan(0);
  });
});
