import { describe, it, expect } from 'vitest';
import * as path from 'path';
import * as fs from 'fs';
import { githubActionsConnector } from '../../src/connectors/githubActionsConnector';
import { DiscoveredFile } from '../../src/core/fileDiscovery';

const FIXTURE_PATH = path.join(__dirname, '../fixtures/sample-workflow.yml');

describe('githubActionsConnector', () => {
  it('detects GITHUB_TOKEN from workflow file', () => {
    const files: DiscoveredFile[] = [
      { path: FIXTURE_PATH.replace('tests/fixtures', '.github/workflows').replace('tests\\fixtures', '.github\\workflows'), size: 500, extension: '.yml' },
    ];

    // Use a path that looks like a GitHub Actions workflow
    const fakeWorkflowPath = '/repo/.github/workflows/sample-workflow.yml';
    const content = fs.readFileSync(FIXTURE_PATH, 'utf-8');
    const fileContents = new Map([[fakeWorkflowPath, content]]);
    const filesWithCorrectPath: DiscoveredFile[] = [
      { path: fakeWorkflowPath, size: content.length, extension: '.yml' },
    ];

    const result = githubActionsConnector(filesWithCorrectPath, fileContents);
    expect(result.identities.some((i) => i.name === 'GITHUB_TOKEN' || i.credentialTypes.includes('github_token'))).toBe(true);
  });

  it('detects secrets usage', () => {
    const fakeWorkflowPath = '/repo/.github/workflows/deploy.yml';
    const content = `
name: Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Deploy
        env:
          TOKEN: \${{ github.token }}
          KEY: \${{ secrets.DEPLOY_KEY }}
          DB: \${{ secrets.DATABASE_URL }}
        run: ./deploy.sh
`;
    const fileContents = new Map([[fakeWorkflowPath, content]]);
    const files: DiscoveredFile[] = [
      { path: fakeWorkflowPath, size: content.length, extension: '.yml' },
    ];

    const result = githubActionsConnector(files, fileContents);
    // Should detect some identities
    expect(result.identities.length).toBeGreaterThan(0);
  });

  it('detects production environment', () => {
    const fakeWorkflowPath = '/repo/.github/workflows/prod.yml';
    const content = `
name: Prod Deploy
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - name: Deploy
        env:
          TOKEN: \${{ github.token }}
        run: ./deploy.sh
`;
    const fileContents = new Map([[fakeWorkflowPath, content]]);
    const files: DiscoveredFile[] = [
      { path: fakeWorkflowPath, size: content.length, extension: '.yml' },
    ];

    const result = githubActionsConnector(files, fileContents);
    const prodPaths = result.executionPaths.filter((ep) => ep.isProduction);
    expect(prodPaths.length).toBeGreaterThan(0);
  });

  it('returns empty result for non-workflow files', () => {
    const files: DiscoveredFile[] = [
      { path: '/repo/src/index.ts', size: 100, extension: '.ts' },
    ];
    const fileContents = new Map([['/repo/src/index.ts', 'export {}']]);

    const result = githubActionsConnector(files, fileContents);
    expect(result.identities).toHaveLength(0);
    expect(result.executionPaths).toHaveLength(0);
  });
});
