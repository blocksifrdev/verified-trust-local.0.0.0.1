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

export function delineaExportConnector(fileOrDir: string): ScanResult {
  const identities = [];
  const inflectionPoints = [];

  const content = readFileSafe(fileOrDir);
  if (!content) return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'delinea' };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let records: any[] = [];
  try {
    const parsed = JSON.parse(content);
    records = Array.isArray(parsed) ? parsed : (parsed?.secrets ?? [parsed]);
  } catch {
    records = parseCsv(content);
  }

  for (const record of records) {
    const secretName = record?.SecretName ?? record?.secret_name ?? record?.name ?? 'unknown';
    const folder = record?.Folder ?? record?.folder ?? '';
    const owner = record?.Owner ?? record?.owner ?? '';
    const lastAccessed = record?.LastAccessed ?? record?.last_accessed ?? '';

    const isStale = lastAccessed
      ? (Date.now() - new Date(lastAccessed).getTime()) / (1000 * 60 * 60 * 24) > 90
      : false;

    const identity = createIdentity({
      name: secretName,
      identityType: 'service_account',
      sourceSystem: 'delinea',
      credentialTypes: ['managed_secret'],
      riskTags: [...(isStale ? ['stale'] : []), ...(owner ? [] : ['no_owner'])],
      owner: owner || undefined,
      lastUsedAt: lastAccessed || undefined,
      metadata: { folder, lastAccessed },
    });
    identities.push(identity);

    if (!owner) {
      inflectionPoints.push(createInflectionPoint({
        type: 'OWNER_MISSING',
        severity: 'MODERATE',
        identityId: identity.id,
        identityName: secretName,
        description: `Delinea secret "${secretName}" in folder "${folder}" has no owner`,
        recommendation: 'Assign an owner to all secrets in Delinea Secret Server.',
        metadata: { folder },
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
    sourceSystem: 'delinea',
  };
}
