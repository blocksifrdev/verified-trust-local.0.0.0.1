import { describe, it, expect } from 'vitest';
import { redactSecret, containsSecret } from '../../src/core/redaction';

describe('redactSecret', () => {
  it('keeps first 3 and last 3 chars, replaces middle with ***', () => {
    const result = redactSecret('ghp_abc123xyz789');
    expect(result).toBe('ghp***789');
  });

  it('fully redacts strings shorter than 8 chars', () => {
    expect(redactSecret('abc123')).toBe('[REDACTED]');
    expect(redactSecret('short')).toBe('[REDACTED]');
    expect(redactSecret('')).toBe('[REDACTED]');
  });

  it('handles exactly 8 char strings (keep 3+3)', () => {
    const result = redactSecret('abcdefgh');
    expect(result).toBe('abc***fgh');
  });

  it('handles long strings', () => {
    const result = redactSecret('AKIAIOSFODNN7EXAMPLE');
    expect(result.startsWith('AKI')).toBe(true);
    expect(result.endsWith('PLE')).toBe(true);
    expect(result).toContain('***');
  });
});

describe('containsSecret', () => {
  it('detects AWS Access Key patterns', () => {
    expect(containsSecret('AKIA1234567890ABCDEF')).toBe(true);
  });

  it('detects GitHub token patterns', () => {
    expect(containsSecret('ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')).toBe(true);
  });

  it('detects private key markers', () => {
    expect(containsSecret('-----BEGIN RSA PRIVATE KEY-----')).toBe(true);
  });

  it('returns false for normal strings', () => {
    expect(containsSecret('hello world')).toBe(false);
    expect(containsSecret('foo=bar')).toBe(false);
    expect(containsSecret('username=admin')).toBe(false);
  });

  it('detects database connection strings', () => {
    expect(containsSecret('postgresql://user:password@localhost:5432/db')).toBe(true);
  });
});
