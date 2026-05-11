import * as fs from 'fs';
import { ScanResult } from '../core/types';
import { createIdentity } from '../core/identity';
import { createInflectionPoint } from '../core/inflectionPoint';

function readFileSafe(filePath: string): string {
  try { return fs.readFileSync(filePath, 'utf-8'); } catch { return ''; }
}

export function gcpIamExportConnector(fileOrDir: string): ScanResult {
  const identities = [];
  const inflectionPoints = [];

  const content = readFileSafe(fileOrDir);
  if (!content) return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'gcp_iam' };

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let data: any = {};
  try { data = JSON.parse(content); } catch { return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'gcp_iam' }; }

  // Parse IAM policy bindings format (gcloud projects get-iam-policy)
  const bindings = data?.bindings ?? [];
  const saIdentities = new Map<string, ReturnType<typeof createIdentity>>();

  for (const binding of bindings) {
    const role = binding?.role ?? 'unknown';
    const members: string[] = binding?.members ?? [];
    const isAdmin = role.includes('roles/owner') || role.includes('roles/editor');

    for (const member of members) {
      if (!member.includes('@') || !member.includes('iam.gserviceaccount.com')) continue;
      const email = member.replace(/^serviceAccount:/, '');

      if (!saIdentities.has(email)) {
        const identity = createIdentity({
          name: email,
          identityType: 'gcp_service_account',
          sourceSystem: 'gcp_iam',
          credentialTypes: ['service_account_key'],
          riskTags: isAdmin ? ['admin'] : [],
          permissions: [role],
          metadata: { email, projectId: data?.name ?? data?.projectId },
        });
        identities.push(identity);
        saIdentities.set(email, identity);
      } else {
        const existing = saIdentities.get(email)!;
        if (!existing.permissions.includes(role)) existing.permissions.push(role);
        if (isAdmin && !existing.riskTags.includes('admin')) existing.riskTags.push('admin');
      }

      const identity = saIdentities.get(email)!;
      if (isAdmin) {
        inflectionPoints.push(createInflectionPoint({
          type: 'ADMIN_ROLE_ASSIGNED',
          severity: 'HIGH',
          identityId: identity.id,
          identityName: email,
          description: `GCP service account "${email}" has ${role}`,
          recommendation: 'Replace owner/editor roles with least-privilege custom roles.',
          metadata: { role },
        }));
      }
    }
  }

  return {
    identities,
    edges: [],
    executionPaths: [],
    inflectionPoints,
    findings: [],
    evidenceRefs: [],
    sourceSystem: 'gcp_iam',
  };
}
