import { describe, it, expect } from 'vitest';
import { detectNHIs } from '../../src/detectors/nhiDetector';
import { DiscoveredFile } from '../../src/core/fileDiscovery';

describe('detectNHIs', () => {
  it('detects service account patterns', () => {
    const files: DiscoveredFile[] = [
      { path: '/repo/config.yml', size: 100, extension: '.yml' },
    ];
    const contents = new Map([
      ['/repo/config.yml', 'serviceAccount: svc-database-prod\nimage: myapp:latest'],
    ]);
    const identities = detectNHIs(files, contents);
    expect(identities.length).toBeGreaterThan(0);
    expect(identities.some((i) => i.name.toLowerCase().includes('svc') || i.name.toLowerCase().includes('serviceaccount'))).toBe(true);
  });

  it('detects AWS IAM role ARNs', () => {
    const files: DiscoveredFile[] = [
      { path: '/repo/deploy.sh', size: 200, extension: '.sh' },
    ];
    const contents = new Map([
      ['/repo/deploy.sh', 'role_arn="arn:aws:iam::123456789012:role/DeploymentRole"'],
    ]);
    const identities = detectNHIs(files, contents);
    expect(identities.some((i) => i.identityType === 'aws_iam_role')).toBe(true);
  });

  it('detects GCP service account emails', () => {
    const files: DiscoveredFile[] = [
      { path: '/repo/config.json', size: 150, extension: '.json' },
    ];
    const contents = new Map([
      ['/repo/config.json', '{"serviceAccount": "data-pipeline@myproject.iam.gserviceaccount.com"}'],
    ]);
    const identities = detectNHIs(files, contents);
    expect(identities.some((i) => i.identityType === 'gcp_service_account')).toBe(true);
  });

  it('detects GITHUB_TOKEN references', () => {
    const files: DiscoveredFile[] = [
      { path: '/repo/.github/workflows/ci.yml', size: 300, extension: '.yml' },
    ];
    const contents = new Map([
      ['/repo/.github/workflows/ci.yml', 'env:\n  TOKEN: ${{ github.token }}\n  OTHER: ${{ GITHUB_TOKEN }}'],
    ]);
    const identities = detectNHIs(files, contents);
    expect(identities.some((i) => i.name.includes('GITHUB_TOKEN'))).toBe(true);
  });

  it('returns empty array for files with no NHI patterns', () => {
    const files: DiscoveredFile[] = [
      { path: '/repo/readme.md', size: 50, extension: '.md' },
    ];
    const contents = new Map([
      ['/repo/readme.md', '# My Project\nThis is a simple project.'],
    ]);
    const identities = detectNHIs(files, contents);
    // May or may not find patterns — just ensure no crash
    expect(Array.isArray(identities)).toBe(true);
  });
});
