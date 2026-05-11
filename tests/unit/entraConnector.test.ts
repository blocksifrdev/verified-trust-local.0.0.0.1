import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { entraExportConnector } from '../../src/connectors/entraExportConnector';

const FIXTURE_PATH = path.join(__dirname, '../fixtures/sample-entra.json');

describe('entraExportConnector', () => {
  it('creates identities from Entra export', () => {
    const result = entraExportConnector(FIXTURE_PATH);
    expect(result.identities.length).toBeGreaterThan(0);
  });

  it('assigns correct identity type for service principals', () => {
    const result = entraExportConnector(FIXTURE_PATH);
    expect(result.identities.some((i) =>
      i.identityType === 'service_principal' || i.identityType === 'azure_app_registration'
    )).toBe(true);
  });

  it('assigns correct identity type for managed identities', () => {
    const result = entraExportConnector(FIXTURE_PATH);
    expect(result.identities.some((i) => i.identityType === 'managed_identity')).toBe(true);
  });

  it('flags identities without owners as OWNER_MISSING', () => {
    const result = entraExportConnector(FIXTURE_PATH);
    expect(result.inflectionPoints.some((ip) => ip.type === 'OWNER_MISSING')).toBe(true);
  });

  it('sets sourceSystem to entra', () => {
    const result = entraExportConnector(FIXTURE_PATH);
    expect(result.identities.every((i) => i.sourceSystem === 'entra')).toBe(true);
  });

  it('returns empty result for non-existent file', () => {
    const result = entraExportConnector('/nonexistent/path.json');
    expect(result.identities).toHaveLength(0);
  });
});
