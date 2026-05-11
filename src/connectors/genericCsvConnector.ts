import * as fs from 'fs';
import { ScanResult, IdentityType, SourceSystem } from '../core/types';
import { createIdentity } from '../core/identity';

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

const VALID_IDENTITY_TYPES: IdentityType[] = [
  'service_account', 'service_principal', 'managed_identity', 'workload_identity',
  'bot_user', 'deploy_key', 'api_token', 'oauth_client', 'github_app', 'ci_cd_runner',
  'kubernetes_service_account', 'aws_iam_role', 'gcp_service_account', 'azure_app_registration',
  'agent_identity', 'mcp_server_identity', 'unknown_nhi',
];

function normalizeType(raw: string): IdentityType {
  const lower = raw.toLowerCase().replace(/[- ]/g, '_');
  if (VALID_IDENTITY_TYPES.includes(lower as IdentityType)) return lower as IdentityType;
  return 'unknown_nhi';
}

export function genericCsvConnector(fileOrDir: string): ScanResult {
  const identities = [];

  const content = readFileSafe(fileOrDir);
  if (!content) return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'generic_csv' };

  const records = parseCsv(content);

  for (const record of records) {
    const name = record?.identity_name ?? record?.name ?? record?.account ?? record?.username ?? '';
    if (!name) continue;

    const rawType = record?.identity_type ?? record?.type ?? '';
    const rawSource = record?.source ?? record?.source_system ?? 'generic_csv';
    const owner = record?.owner ?? '';
    const environment = record?.environment ?? '';
    const permission = record?.permission ?? '';
    const resource = record?.resource ?? '';
    const lastUsed = record?.last_used ?? record?.last_used_at ?? '';
    const createdAt = record?.created_at ?? record?.created ?? '';

    const identityType = normalizeType(rawType);
    const source: SourceSystem = 'generic_csv';

    identities.push(createIdentity({
      name,
      identityType,
      sourceSystem: source,
      credentialTypes: [],
      riskTags: owner ? [] : ['no_owner'],
      owner: owner || undefined,
      environment: environment || undefined,
      permissions: permission ? [permission] : [],
      lastUsedAt: lastUsed || undefined,
      createdAt: createdAt || undefined,
      metadata: { source: rawSource, resource },
    }));
  }

  return {
    identities,
    edges: [],
    executionPaths: [],
    inflectionPoints: [],
    findings: [],
    evidenceRefs: [],
    sourceSystem: 'generic_csv',
  };
}
