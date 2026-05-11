import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { genericCsvConnector } from '../../src/connectors/genericCsvConnector';

const FIXTURE_PATH = path.join(__dirname, '../fixtures/sample.csv');

describe('genericCsvConnector', () => {
  it('creates identities from CSV', () => {
    const result = genericCsvConnector(FIXTURE_PATH);
    expect(result.identities.length).toBeGreaterThan(0);
  });

  it('reads identity names from identity_name column', () => {
    const result = genericCsvConnector(FIXTURE_PATH);
    expect(result.identities.some((i) => i.name === 'svc-database')).toBe(true);
  });

  it('reads owner from owner column', () => {
    const result = genericCsvConnector(FIXTURE_PATH);
    const svcDb = result.identities.find((i) => i.name === 'svc-database');
    expect(svcDb?.owner).toBe('platform-team');
  });

  it('flags identities without owners', () => {
    const result = genericCsvConnector(FIXTURE_PATH);
    const botDeploy = result.identities.find((i) => i.name === 'bot-deploy');
    expect(botDeploy?.riskTags).toContain('no_owner');
  });

  it('sets sourceSystem to generic_csv', () => {
    const result = genericCsvConnector(FIXTURE_PATH);
    expect(result.identities.every((i) => i.sourceSystem === 'generic_csv')).toBe(true);
  });

  it('returns empty result for non-existent file', () => {
    const result = genericCsvConnector('/nonexistent/file.csv');
    expect(result.identities).toHaveLength(0);
  });
});
