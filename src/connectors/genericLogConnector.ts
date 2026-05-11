import * as fs from 'fs';
import { ScanResult } from '../core/types';
import { createIdentity } from '../core/identity';
import { createExecutionPath } from '../core/executionPath';

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

export function genericLogConnector(fileOrDir: string): ScanResult {
  const identities = [];
  const executionPaths = [];

  const content = readFileSafe(fileOrDir);
  if (!content) return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'generic_log' };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let records: any[] = [];
  try {
    const parsed = JSON.parse(content);
    records = Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    records = parseCsv(content);
  }

  const actorMap = new Map<string, ReturnType<typeof createIdentity>>();

  for (const record of records) {
    const actor = record?.actor ?? record?.user ?? record?.identity ?? record?.source ?? '';
    const destination = record?.destination ?? record?.target ?? record?.resource ?? '';
    const action = record?.action ?? record?.event_type ?? record?.event ?? '';
    const timestamp = record?.timestamp ?? record?.time ?? record?.datetime ?? '';
    const result = record?.result ?? record?.outcome ?? '';

    if (!actor) continue;

    if (!actorMap.has(actor)) {
      const identity = createIdentity({
        name: actor,
        identityType: 'unknown_nhi',
        sourceSystem: 'generic_log',
        credentialTypes: [],
        riskTags: [],
        lastUsedAt: timestamp || undefined,
      });
      identities.push(identity);
      actorMap.set(actor, identity);
    }

    const identity = actorMap.get(actor)!;

    if (action && destination) {
      executionPaths.push(createExecutionPath({
        identityId: identity.id,
        identityName: identity.name,
        trigger: action,
        targetEnvironment: destination,
        isProduction: /prod/i.test(destination),
        approvalDetected: false,
        evidenceDetected: !!result,
        trustBoundaryCrossed: false,
        steps: [action],
        sourceSystem: 'generic_log',
        metadata: { timestamp, result, sourceIp: record?.source_ip ?? '' },
      }));
    }
  }

  return {
    identities,
    edges: [],
    executionPaths,
    inflectionPoints: [],
    findings: [],
    evidenceRefs: [],
    sourceSystem: 'generic_log',
  };
}
