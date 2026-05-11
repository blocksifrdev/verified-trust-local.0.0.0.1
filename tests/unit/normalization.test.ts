import { describe, it, expect } from 'vitest';
import { normalizeIdentities } from '../../src/core/normalization';
import { createIdentity } from '../../src/core/identity';

describe('normalizeIdentities', () => {
  it('deduplicates identities with the same normalized name and sourceSystem', () => {
    const identities = [
      createIdentity({
        name: 'svc-database',
        identityType: 'service_account',
        sourceSystem: 'filesystem',
        credentialTypes: ['access_key'],
        riskTags: ['stale'],
      }),
      createIdentity({
        name: 'SVC-DATABASE', // Different case — should be deduplicated
        identityType: 'service_account',
        sourceSystem: 'filesystem',
        credentialTypes: ['client_secret'],
        riskTags: ['no_owner'],
      }),
    ];

    const normalized = normalizeIdentities(identities);
    expect(normalized.length).toBe(1);
  });

  it('merges credentialTypes from duplicate identities', () => {
    const identities = [
      createIdentity({
        name: 'svc-database',
        identityType: 'service_account',
        sourceSystem: 'filesystem',
        credentialTypes: ['access_key'],
        riskTags: [],
      }),
      createIdentity({
        name: 'svc-database',
        identityType: 'service_account',
        sourceSystem: 'filesystem',
        credentialTypes: ['client_secret'],
        riskTags: [],
      }),
    ];

    const normalized = normalizeIdentities(identities);
    expect(normalized[0].credentialTypes).toContain('access_key');
    expect(normalized[0].credentialTypes).toContain('client_secret');
  });

  it('merges riskTags from duplicate identities', () => {
    const identities = [
      createIdentity({
        name: 'svc-app',
        identityType: 'service_account',
        sourceSystem: 'filesystem',
        credentialTypes: [],
        riskTags: ['stale'],
      }),
      createIdentity({
        name: 'svc-app',
        identityType: 'service_account',
        sourceSystem: 'filesystem',
        credentialTypes: [],
        riskTags: ['no_owner'],
      }),
    ];

    const normalized = normalizeIdentities(identities);
    expect(normalized[0].riskTags).toContain('stale');
    expect(normalized[0].riskTags).toContain('no_owner');
  });

  it('keeps identities with different sourceSystem separate', () => {
    const identities = [
      createIdentity({
        name: 'svc-database',
        identityType: 'service_account',
        sourceSystem: 'filesystem',
        credentialTypes: [],
        riskTags: [],
      }),
      createIdentity({
        name: 'svc-database',
        identityType: 'service_account',
        sourceSystem: 'aws_iam',
        credentialTypes: [],
        riskTags: [],
      }),
    ];

    const normalized = normalizeIdentities(identities);
    expect(normalized.length).toBe(2);
  });

  it('handles empty array', () => {
    expect(normalizeIdentities([])).toHaveLength(0);
  });
});
