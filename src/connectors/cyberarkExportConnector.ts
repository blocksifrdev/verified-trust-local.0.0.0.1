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

export function cyberarkExportConnector(fileOrDir: string): ScanResult {
  const identities = [];
  const inflectionPoints = [];

  const content = readFileSafe(fileOrDir);
  if (!content) return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'cyberark' };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let records: any[] = [];
  try {
    const parsed = JSON.parse(content);
    records = Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    records = parseCsv(content);
  }

  for (const record of records) {
    const name = record?.AccountName ?? record?.account_name ?? record?.name ?? 'unknown';
    const safe = record?.Safe ?? record?.safe ?? '';
    const platform = record?.Platform ?? record?.platform ?? '';
    const owner = record?.Owner ?? record?.owner ?? '';
    const target = record?.TargetMachine ?? record?.target_machine ?? '';
    const lastChanged = record?.LastPasswordChangeDate ?? record?.last_password_change ?? '';
    const status = record?.PasswordStatus ?? record?.status ?? '';

    const isStale = lastChanged ? (Date.now() - new Date(lastChanged).getTime()) / (1000 * 60 * 60 * 24) > 90 : false;

    const identity = createIdentity({
      name,
      identityType: 'service_account',
      sourceSystem: 'cyberark',
      credentialTypes: ['managed_password'],
      riskTags: [...(isStale ? ['stale_password'] : []), ...(owner ? [] : ['no_owner'])],
      owner: owner || undefined,
      lastRotatedAt: lastChanged || undefined,
      metadata: { safe, platform, target, status, lastChanged },
    });
    identities.push(identity);

    if (isStale) {
      inflectionPoints.push(createInflectionPoint({
        type: 'CREDENTIAL_STALE',
        severity: 'MODERATE',
        identityId: identity.id,
        identityName: name,
        description: `CyberArk account "${name}" password last changed: ${lastChanged}`,
        recommendation: 'Verify rotation policy is active for this account in CyberArk.',
        metadata: { lastChanged, safe },
      }));
    }

    if (!owner) {
      inflectionPoints.push(createInflectionPoint({
        type: 'OWNER_MISSING',
        severity: 'MODERATE',
        identityId: identity.id,
        identityName: name,
        description: `CyberArk account "${name}" has no assigned owner`,
        recommendation: 'Assign an owner to all managed accounts in CyberArk.',
        metadata: { safe },
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
    sourceSystem: 'cyberark',
  };
}
