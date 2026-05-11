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

export function oktaExportConnector(fileOrDir: string): ScanResult {
  const identities = [];
  const inflectionPoints = [];

  let content = readFileSafe(fileOrDir);
  if (!content) return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'okta' };

  // Try JSON first, then CSV
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let records: any[] = [];
  try {
    const parsed = JSON.parse(content);
    records = Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    records = parseCsv(content);
  }

  for (const record of records) {
    const label = record?.label ?? record?.name ?? record?.displayName ?? 'unknown-okta-app';
    const status = record?.status ?? 'ACTIVE';
    const clientId = record?.credentials_client_id ?? record?.credentials?.oauthClient?.client_id ?? record?.client_id ?? '';
    const signOnMode = record?.signOnMode ?? record?.sign_on_mode ?? '';
    const createdAt = record?.created ?? record?.createdAt;
    const lastUpdated = record?.lastUpdated ?? record?.updated_at;

    const identity = createIdentity({
      name: label,
      identityType: 'oauth_client',
      sourceSystem: 'okta',
      credentialTypes: clientId ? ['client_secret'] : [],
      riskTags: status !== 'ACTIVE' ? ['inactive'] : [],
      metadata: {
        clientId,
        signOnMode,
        status,
        lastUpdated,
      },
      createdAt,
    });
    identities.push(identity);

    if (status !== 'ACTIVE') {
      inflectionPoints.push(createInflectionPoint({
        type: 'CREDENTIAL_STALE',
        severity: 'LOW',
        identityId: identity.id,
        identityName: identity.name,
        description: `Okta app "${label}" has status: ${status}`,
        recommendation: 'Review inactive Okta app integrations. Remove if no longer needed.',
        metadata: { status },
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
    sourceSystem: 'okta',
  };
}
