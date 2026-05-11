import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { awsIamExportConnector } from '../../src/connectors/awsIamExportConnector';

const FIXTURE_PATH = path.join(__dirname, '../fixtures/sample-aws-iam.json');

describe('awsIamExportConnector', () => {
  it('detects IAM roles from AWS IAM export', () => {
    const result = awsIamExportConnector(FIXTURE_PATH);
    expect(result.identities.some((i) => i.identityType === 'aws_iam_role')).toBe(true);
  });

  it('detects multiple IAM roles', () => {
    const result = awsIamExportConnector(FIXTURE_PATH);
    const roles = result.identities.filter((i) => i.identityType === 'aws_iam_role');
    expect(roles.length).toBeGreaterThanOrEqual(2);
  });

  it('flags AdministratorAccess as ADMIN_ROLE_ASSIGNED', () => {
    const result = awsIamExportConnector(FIXTURE_PATH);
    expect(result.inflectionPoints.some((ip) => ip.type === 'ADMIN_ROLE_ASSIGNED')).toBe(true);
  });

  it('flags public trust policy (*) as PUBLIC_EXPOSURE', () => {
    const result = awsIamExportConnector(FIXTURE_PATH);
    expect(result.inflectionPoints.some((ip) => ip.type === 'PUBLIC_EXPOSURE')).toBe(true);
  });

  it('sets sourceSystem to aws_iam', () => {
    const result = awsIamExportConnector(FIXTURE_PATH);
    expect(result.identities.every((i) => i.sourceSystem === 'aws_iam')).toBe(true);
  });

  it('returns empty result for non-existent file', () => {
    const result = awsIamExportConnector('/nonexistent/file.json');
    expect(result.identities).toHaveLength(0);
  });
});
