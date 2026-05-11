import { describe, it, expect } from 'vitest';
import * as path from 'path';
import * as fs from 'fs';
import { kubernetesConnector } from '../../src/connectors/kubernetesConnector';
import { DiscoveredFile } from '../../src/core/fileDiscovery';

const FIXTURE_PATH = path.join(__dirname, '../fixtures/sample-k8s.yaml');

describe('kubernetesConnector', () => {
  it('detects ServiceAccount from kubernetes YAML', () => {
    const content = fs.readFileSync(FIXTURE_PATH, 'utf-8');
    const fileContents = new Map([[FIXTURE_PATH, content]]);
    const files: DiscoveredFile[] = [
      { path: FIXTURE_PATH, size: content.length, extension: '.yaml' },
    ];

    const result = kubernetesConnector(files, fileContents);
    expect(result.identities.some((i) => i.identityType === 'kubernetes_service_account')).toBe(true);
  });

  it('detects ClusterRoleBinding and creates edge', () => {
    const content = fs.readFileSync(FIXTURE_PATH, 'utf-8');
    const fileContents = new Map([[FIXTURE_PATH, content]]);
    const files: DiscoveredFile[] = [
      { path: FIXTURE_PATH, size: content.length, extension: '.yaml' },
    ];

    const result = kubernetesConnector(files, fileContents);
    expect(result.edges.length).toBeGreaterThan(0);
  });

  it('flags cluster-admin binding as PRIVILEGE_ESCALATION_PATH', () => {
    const content = fs.readFileSync(FIXTURE_PATH, 'utf-8');
    const fileContents = new Map([[FIXTURE_PATH, content]]);
    const files: DiscoveredFile[] = [
      { path: FIXTURE_PATH, size: content.length, extension: '.yaml' },
    ];

    const result = kubernetesConnector(files, fileContents);
    expect(result.inflectionPoints.some((ip) => ip.type === 'PRIVILEGE_ESCALATION_PATH')).toBe(true);
  });

  it('handles malformed YAML without throwing', () => {
    const files: DiscoveredFile[] = [
      { path: '/repo/bad.yaml', size: 50, extension: '.yaml' },
    ];
    const fileContents = new Map([['/repo/bad.yaml', 'this: is: not: valid: yaml: {{{']]);

    expect(() => kubernetesConnector(files, fileContents)).not.toThrow();
  });
});
