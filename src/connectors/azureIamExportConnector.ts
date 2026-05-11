import * as fs from 'fs';
import { ScanResult } from '../core/types';
import { createIdentity } from '../core/identity';
import { createInflectionPoint } from '../core/inflectionPoint';

function readFileSafe(filePath: string): string {
  try { return fs.readFileSync(filePath, 'utf-8'); } catch { return ''; }
}

function parseCsv(content: string): Record<string, string>[] {
  const lines = content.split('\n').filter((l) => l.trim());
  if (lines.length === 0) return [];
  const headers = lines[0].split(',').map((h) => h.trim().replace(/^"|"$/g, ''));
  return lines.slice(1).map((line) => {
    const values = line.split(',').map((v) => v.trim().replace(/^"|"$/g, ''));
    const record: Record<string, string> = {};
    headers.forEach((h, i) => { record[h] = values[i] ?? ''; });
    return record;
  });
}

export function azureIamExportConnector(fileOrDir: string): ScanResult {
  const identities = [];
  const inflectionPoints = [];

  const content = readFileSafe(fileOrDir);
  if (!content) return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'azure_iam' };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let records: any[] = [];
  try {
    const parsed = JSON.parse(content);
    records = Array.isArray(parsed) ? parsed : (parsed?.value ?? [parsed]);
  } catch {
    records = parseCsv(content);
  }

  for (const record of records) {
    const principalType = record?.principalType ?? record?.PrincipalType ?? '';
    if (!['ServicePrincipal', 'ManagedIdentity'].includes(principalType)) continue;

    const principalName = record?.principalName ?? record?.PrincipalName ?? record?.displayName ?? 'unknown';
    const roleName = record?.roleDefinitionName ?? record?.RoleDefinitionName ?? 'unknown';
    const scope = record?.scope ?? record?.Scope ?? 'unknown';
    const isAdmin = ['Owner', 'Contributor', 'User Access Administrator'].includes(roleName);

    const identity = createIdentity({
      name: principalName,
      identityType: principalType === 'ManagedIdentity' ? 'managed_identity' : 'service_principal',
      sourceSystem: 'azure_iam',
      credentialTypes: [],
      riskTags: isAdmin ? ['admin'] : [],
      permissions: [roleName],
      metadata: {
        roleAssignmentId: record?.roleAssignmentId ?? record?.id,
        principalId: record?.principalId ?? record?.PrincipalId,
        scope,
        roleDefinitionId: record?.roleDefinitionId,
      },
    });
    identities.push(identity);

    if (isAdmin) {
      inflectionPoints.push(createInflectionPoint({
        type: 'ADMIN_ROLE_ASSIGNED',
        severity: 'HIGH',
        identityId: identity.id,
        identityName: principalName,
        description: `Azure ${principalType} "${principalName}" has ${roleName} at scope: ${scope}`,
        recommendation: 'Replace Owner/Contributor with least-privilege custom roles scoped to required resources.',
        metadata: { roleName, scope },
      }));
    }
  }

  return {
    identities,
    edges: [],
    executionPaths: [],
    inflectionPoints,
    findings: [],
    evidenceRefs: [],
    sourceSystem: 'azure_iam',
  };
}
