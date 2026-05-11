import { describe, it, expect } from 'vitest';
import * as path from 'path';
import * as fs from 'fs';
import { terraformConnector } from '../../src/connectors/terraformConnector';
import { DiscoveredFile } from '../../src/core/fileDiscovery';

const FIXTURE_PATH = path.join(__dirname, '../fixtures/sample-terraform.tf');

describe('terraformConnector', () => {
  it('detects AWS IAM roles from terraform files', () => {
    const content = fs.readFileSync(FIXTURE_PATH, 'utf-8');
    const fileContents = new Map([[FIXTURE_PATH, content]]);
    const files: DiscoveredFile[] = [
      { path: FIXTURE_PATH, size: content.length, extension: '.tf' },
    ];

    const result = terraformConnector(files, fileContents);
    expect(result.identities.some((i) => i.identityType === 'aws_iam_role')).toBe(true);
  });

  it('flags wildcard permissions as inflection points', () => {
    const content = fs.readFileSync(FIXTURE_PATH, 'utf-8');
    const fileContents = new Map([[FIXTURE_PATH, content]]);
    const files: DiscoveredFile[] = [
      { path: FIXTURE_PATH, size: content.length, extension: '.tf' },
    ];

    const result = terraformConnector(files, fileContents);
    expect(result.inflectionPoints.some((ip) => ip.type === 'WILDCARD_PERMISSION')).toBe(true);
  });

  it('flags public principal (*) as PUBLIC_EXPOSURE', () => {
    const content = fs.readFileSync(FIXTURE_PATH, 'utf-8');
    const fileContents = new Map([[FIXTURE_PATH, content]]);
    const files: DiscoveredFile[] = [
      { path: FIXTURE_PATH, size: content.length, extension: '.tf' },
    ];

    const result = terraformConnector(files, fileContents);
    // The fixture has Principal: "*" in admin_role
    expect(result.inflectionPoints.some((ip) => ip.type === 'PUBLIC_EXPOSURE')).toBe(true);
  });

  it('returns empty result for non-terraform files', () => {
    const files: DiscoveredFile[] = [
      { path: '/repo/readme.md', size: 50, extension: '.md' },
    ];
    const fileContents = new Map([['/repo/readme.md', '# Readme']]);

    const result = terraformConnector(files, fileContents);
    expect(result.identities).toHaveLength(0);
  });
});
