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

export function beyondTrustExportConnector(fileOrDir: string): ScanResult {
  const identities = [];
  const inflectionPoints = [];

  const content = readFileSafe(fileOrDir);
  if (!content) return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'beyondtrust' };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let records: any[] = [];
  try {
    const parsed = JSON.parse(content);
    records = Array.isArray(parsed) ? parsed : (parsed?.accounts ?? parsed?.managed_accounts ?? [parsed]);
  } catch {
    records = parseCsv(content);
  }

  for (const record of records) {
    const name = record?.AccountName ?? record?.account_name ?? record?.username ?? record?.name ?? 'unknown';
    const system = record?.SystemName ?? record?.system_name ?? record?.asset ?? '';
    const policyGroup = record?.PolicyGroup ?? record?.policy_group ?? '';
    const owner = record?.Owner ?? record?.owner ?? '';

    const identity = createIdentity({
      name,
      identityType: 'service_account',
      sourceSystem: 'beyondtrust',
      credentialTypes: ['managed_password'],
      riskTags: owner ? [] : ['no_owner'],
      owner: owner || undefined,
      metadata: { system, policyGroup },
    });
    identities.push(identity);

    if (!owner) {
      inflectionPoints.push(createInflectionPoint({
        type: 'OWNER_MISSING',
        severity: 'MODERATE',
        identityId: identity.id,
        identityName: name,
        description: `BeyondTrust managed account "${name}" has no assigned owner`,
        recommendation: 'Assign accountability for all managed accounts in BeyondTrust.',
        metadata: { system },
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
    sourceSystem: 'beyondtrust',
  };
}
