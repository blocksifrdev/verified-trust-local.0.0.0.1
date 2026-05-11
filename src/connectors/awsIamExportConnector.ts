import * as fs from 'fs';
import { ScanResult, Identity, AuthorityEdge, InflectionPoint } from '../core/types';
import { createIdentity } from '../core/identity';
import { createInflectionPoint } from '../core/inflectionPoint';

function readFileSafe(filePath: string): string {
  try { return fs.readFileSync(filePath, 'utf-8'); } catch { return ''; }
}

export function awsIamExportConnector(fileOrDir: string): ScanResult {
  const identities: Identity[] = [];
  const edges: AuthorityEdge[] = [];
  const inflectionPoints: InflectionPoint[] = [];

  const content = readFileSafe(fileOrDir);
  if (!content) return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'aws_iam' };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let data: any = {};
  try { data = JSON.parse(content); } catch { return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'aws_iam' }; }

  // Parse IAM roles
  const roles = data?.RoleDetailList ?? data?.roles ?? [];
  for (const role of roles) {
    const roleName = role?.RoleName ?? role?.name ?? 'unknown-role';
    const arn = role?.Arn ?? role?.arn ?? '';
    const createdAt = role?.CreateDate ?? role?.created_at;
    const trustPolicy = role?.AssumeRolePolicyDocument ?? role?.trust_policy ?? {};
    const trustStr = JSON.stringify(trustPolicy);

    const isWildcard = trustStr.includes('"*"') || trustStr.includes("'*'");
    const isAdmin = (role?.AttachedManagedPolicies ?? []).some(
      (p: { PolicyName?: string }) => p?.PolicyName === 'AdministratorAccess' || p?.PolicyName === 'PowerUserAccess'
    );

    const identity = createIdentity({
      name: roleName,
      identityType: 'aws_iam_role',
      sourceSystem: 'aws_iam',
      credentialTypes: ['iam_role'],
      riskTags: [...(isWildcard ? ['public_trust'] : []), ...(isAdmin ? ['admin'] : [])],
      permissions: (role?.AttachedManagedPolicies ?? []).map((p: { PolicyName?: string }) => p?.PolicyName ?? ''),
      createdAt,
      metadata: { arn, trustPolicy },
    });
    identities.push(identity);

    if (isWildcard) {
      inflectionPoints.push(createInflectionPoint({
        type: 'PUBLIC_EXPOSURE',
        severity: 'CRITICAL',
        identityId: identity.id,
        identityName: roleName,
        description: `AWS IAM role "${roleName}" trust policy allows any principal (*)`,
        recommendation: 'Restrict trust policy to specific AWS accounts, services, and conditions.',
        metadata: { arn },
      }));
    }

    if (isAdmin) {
      inflectionPoints.push(createInflectionPoint({
        type: 'ADMIN_ROLE_ASSIGNED',
        severity: 'CRITICAL',
        identityId: identity.id,
        identityName: roleName,
        description: `AWS IAM role "${roleName}" has AdministratorAccess or PowerUserAccess`,
        recommendation: 'Replace with least-privilege policies.',
        metadata: { arn, policies: (role?.AttachedManagedPolicies ?? []).map((p: { PolicyName?: string }) => p?.PolicyName) },
      }));
    }

    // Lambda/ECS execution roles
    const isLambdaRole = trustStr.includes('lambda.amazonaws.com');
    const isEcsRole = trustStr.includes('ecs-tasks.amazonaws.com');
    if (isLambdaRole || isEcsRole) {
      identity.riskTags.push('execution_role');
      identity.metadata['executionRoleType'] = isLambdaRole ? 'lambda' : 'ecs';
    }
  }

  // Parse IAM users (service accounts — no console access, have access keys)
  const users = data?.UserDetailList ?? data?.users ?? [];
  for (const user of users) {
    const userName = user?.UserName ?? user?.name ?? 'unknown-user';
    const arn = user?.Arn ?? '';
    const accessKeys = user?.AccessKeyMetadata ?? user?.access_keys ?? [];
    const hasConsoleAccess = !!user?.LoginProfile;
    const createdAt = user?.CreateDate ?? user?.created_at;

    if (accessKeys.length > 0 && !hasConsoleAccess) {
      const identity = createIdentity({
        name: userName,
        identityType: 'service_account',
        sourceSystem: 'aws_iam',
        credentialTypes: ['access_key'],
        riskTags: [],
        createdAt,
        metadata: {
          arn,
          accessKeyCount: accessKeys.length,
          accessKeys: accessKeys.map((k: { AccessKeyId?: string; Status?: string; CreateDate?: string }) => ({
            id: k?.AccessKeyId,
            status: k?.Status,
            created: k?.CreateDate,
          })),
        },
      });
      identities.push(identity);

      // Check stale access keys
      for (const key of accessKeys) {
        const keyCreated = key?.CreateDate;
        if (keyCreated) {
          const daysSince = (Date.now() - new Date(keyCreated).getTime()) / (1000 * 60 * 60 * 24);
          if (daysSince > 365) {
            inflectionPoints.push(createInflectionPoint({
              type: 'CREDENTIAL_STALE',
              severity: 'HIGH',
              identityId: identity.id,
              identityName: userName,
              description: `IAM user "${userName}" has access key created ${Math.round(daysSince)} days ago`,
              recommendation: 'Rotate access keys at minimum annually. Prefer IAM roles over long-lived access keys.',
              metadata: { keyId: key?.AccessKeyId, daysSince: Math.round(daysSince) },
            }));
          }
        }
      }
    }
  }

  return {
    identities,
    edges,
    executionPaths: [],
    inflectionPoints,
    findings: [],
    evidenceRefs: [],
    sourceSystem: 'aws_iam',
  };
}
