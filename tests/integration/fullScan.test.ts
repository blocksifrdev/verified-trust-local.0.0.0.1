import { describe, it, expect, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { scanCommand } from '../../src/cli/commands/scan';

const SAMPLE_REPO = path.join(__dirname, '../../examples/sample-repo');
let outputDir: string;

describe('Full scan integration test', () => {
  outputDir = path.join(os.tmpdir(), `vt-integration-test-${Date.now()}`);

  afterAll(() => {
    try {
      if (fs.existsSync(outputDir)) {
        fs.rmSync(outputDir, { recursive: true });
      }
    } catch { /* ignore cleanup errors */ }
  });

  it('runs scanCommand on examples/sample-repo without throwing', async () => {
    // Suppress console output
    const origLog = console.log;
    const origWrite = process.stdout.write.bind(process.stdout);
    console.log = () => {};
    process.stdout.write = (...args: Parameters<typeof process.stdout.write>) => {
      if (typeof args[0] === 'string' && !args[0].includes('\n')) return true;
      return origWrite(...args);
    };

    try {
      await expect(
        scanCommand(SAMPLE_REPO, { out: outputDir, edition: 'community' })
      ).resolves.not.toThrow();
    } finally {
      console.log = origLog;
      process.stdout.write = origWrite;
    }
  }, 30000);

  it('generates findings.json output file', () => {
    const findingsPath = path.join(outputDir, 'findings.json');
    expect(fs.existsSync(findingsPath)).toBe(true);
  });

  it('generates identity-map.json output file', () => {
    const identityMapPath = path.join(outputDir, 'identity-map.json');
    expect(fs.existsSync(identityMapPath)).toBe(true);
  });

  it('generates authority-graph.json output file', () => {
    const graphPath = path.join(outputDir, 'authority-graph.json');
    expect(fs.existsSync(graphPath)).toBe(true);
  });

  it('generates evidence-map.json output file', () => {
    const evidencePath = path.join(outputDir, 'evidence-map.json');
    expect(fs.existsSync(evidencePath)).toBe(true);
  });

  it('generates risk-summary.json output file', () => {
    const riskPath = path.join(outputDir, 'risk-summary.json');
    expect(fs.existsSync(riskPath)).toBe(true);
  });

  it('generates remediation-roadmap.md output file', () => {
    const roadmapPath = path.join(outputDir, 'remediation-roadmap.md');
    expect(fs.existsSync(roadmapPath)).toBe(true);
  });

  it('generates executive-report.html output file', () => {
    const htmlPath = path.join(outputDir, 'executive-report.html');
    expect(fs.existsSync(htmlPath)).toBe(true);
  });

  it('findings.json is valid JSON', () => {
    const findingsPath = path.join(outputDir, 'findings.json');
    const content = fs.readFileSync(findingsPath, 'utf-8');
    expect(() => JSON.parse(content)).not.toThrow();
  });

  it('identity-map.json contains at least 1 identity', () => {
    const identityMapPath = path.join(outputDir, 'identity-map.json');
    const content = fs.readFileSync(identityMapPath, 'utf-8');
    const identities = JSON.parse(content);
    expect(Array.isArray(identities)).toBe(true);
    expect(identities.length).toBeGreaterThanOrEqual(1);
  });

  it('risk-summary.json contains valid risk score', () => {
    const riskPath = path.join(outputDir, 'risk-summary.json');
    const content = fs.readFileSync(riskPath, 'utf-8');
    const summary = JSON.parse(content);
    expect(summary.riskScore).toBeDefined();
    expect(summary.riskScore.total).toBeGreaterThanOrEqual(0);
    expect(summary.riskScore.total).toBeLessThanOrEqual(100);
    expect(['LOW', 'MODERATE', 'HIGH', 'CRITICAL']).toContain(summary.riskScore.band);
  });

  it('executive-report.html is non-empty', () => {
    const htmlPath = path.join(outputDir, 'executive-report.html');
    const content = fs.readFileSync(htmlPath, 'utf-8');
    expect(content.length).toBeGreaterThan(1000);
    expect(content).toContain('VerifiedTrust');
  });
});
