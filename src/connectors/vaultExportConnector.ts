import * as fs from 'fs';
import { ScanResult } from '../core/types';
import { createIdentity } from '../core/identity';
import { createInflectionPoint } from '../core/inflectionPoint';

function readFileSafe(filePath: string): string {
  try { return fs.readFileSync(filePath, 'utf-8'); } catch { return ''; }
}

export function vaultExportConnector(fileOrDir: string): ScanResult {
  const identities = [];
  const inflectionPoints = [];

  const content = readFileSafe(fileOrDir);
  if (!content) return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'vault' };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let data: any = {};
  try { data = JSON.parse(content); } catch { return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'vault' }; }

  // Entities / aliases
  const entities = data?.entities ?? data?.data?.entity ?? [];
  for (const entity of Array.isArray(entities) ? entities : []) {
    const name = entity?.name ?? entity?.id ?? 'unknown-vault-entity';
    const aliases = entity?.aliases ?? [];
    const policies = entity?.policies ?? [];

    const authMounts = aliases.map((a: { mount_type?: string }) => a?.mount_type ?? 'unknown');
    const credTypes = Array.from(new Set(authMounts)) as string[];

    const identity = createIdentity({
      name,
      identityType: 'service_account',
      sourceSystem: 'vault',
      credentialTypes: credTypes,
      riskTags: [],
      permissions: policies,
      metadata: { aliases, policies },
    });
    identities.push(identity);

    if (policies.includes('root') || policies.includes('sudo')) {
      inflectionPoints.push(createInflectionPoint({
        type: 'ADMIN_ROLE_ASSIGNED',
        severity: 'CRITICAL',
        identityId: identity.id,
        identityName: name,
        description: `Vault entity "${name}" has root or sudo policy`,
        recommendation: 'Remove root/sudo policy assignments. Apply least-privilege Vault policies.',
        metadata: { policies },
      }));
    }
  }

  // Auth mounts from audit logs
  const auditLogs = data?.audit_logs ?? data?.logs ?? [];
  const authTypes = new Set<string>();
  for (const log of Array.isArray(auditLogs) ? auditLogs : []) {
    const authMount = log?.auth?.mount_type ?? log?.mount_type ?? '';
    if (authMount) authTypes.add(authMount);
  }

  if (authTypes.size > 0) {
    identities.push(createIdentity({
      name: 'vault-auth-mounts',
      identityType: 'service_account',
      sourceSystem: 'vault',
      credentialTypes: Array.from(authTypes),
      riskTags: [],
      metadata: { authMounts: Array.from(authTypes) },
    }));
  }

  return {
    identities,
    edges: [],
    executionPaths: [],
    inflectionPoints,
    findings: [],
    evidenceRefs: [],
    sourceSystem: 'vault',
  };
}
