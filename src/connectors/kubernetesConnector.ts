import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { ScanResult, Identity, AuthorityEdge, Finding, InflectionPoint } from '../core/types';
import { createIdentity } from '../core/identity';
import { createAuthorityEdge } from '../core/authorityEdge';
import { createInflectionPoint } from '../core/inflectionPoint';
import { createFinding } from '../core/finding';
import { DiscoveredFile } from '../core/fileDiscovery';

function readFileSafe(filePath: string): string {
  try { return fs.readFileSync(filePath, 'utf-8'); } catch { return ''; }
}

function isKubernetesFile(filePath: string): boolean {
  const ext = path.extname(filePath).toLowerCase();
  return ext === '.yaml' || ext === '.yml';
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function loadAllYamlDocs(content: string): any[] {
  const docs: unknown[] = [];
  try {
    yaml.loadAll(content, (doc) => { if (doc) docs.push(doc); });
  } catch {
    try {
      const doc = yaml.load(content);
      if (doc) docs.push(doc);
    } catch { /* ignore */ }
  }
  return docs;
}

export function kubernetesConnector(files: DiscoveredFile[], fileContents: Map<string, string>): ScanResult {
  const identities: Identity[] = [];
  const edges: AuthorityEdge[] = [];
  const inflectionPoints: InflectionPoint[] = [];
  const findings: Finding[] = [];

  const serviceAccounts = new Map<string, Identity>();

  const k8sFiles = files.filter((f) => isKubernetesFile(f.path));

  for (const file of k8sFiles) {
    let content = fileContents.get(file.path);
    if (content === undefined) {
      content = readFileSafe(file.path);
      fileContents.set(file.path, content);
    }
    if (!content) continue;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const docs = loadAllYamlDocs(content) as any[];

    for (const doc of docs) {
      if (!doc || typeof doc !== 'object') continue;
      const kind = doc?.kind ?? '';
      const metadata = doc?.metadata ?? {};
      const name = metadata?.name ?? 'unknown';
      const namespace = metadata?.namespace ?? 'default';

      if (kind === 'ServiceAccount') {
        const autoMount = doc?.automountServiceAccountToken;
        const identity = createIdentity({
          name: `k8s-sa:${namespace}/${name}`,
          identityType: 'kubernetes_service_account',
          sourceSystem: 'kubernetes',
          sourceFile: file.path,
          credentialTypes: ['kubernetes_service_account_token'],
          riskTags: autoMount === true ? ['auto_mount'] : [],
          metadata: { kind, name, namespace, automountServiceAccountToken: autoMount },
        });
        identities.push(identity);
        serviceAccounts.set(`${namespace}/${name}`, identity);

        if (autoMount === true) {
          inflectionPoints.push(createInflectionPoint({
            type: 'TRUST_BOUNDARY_CROSSING',
            severity: 'MODERATE',
            identityId: identity.id,
            identityName: identity.name,
            description: `ServiceAccount "${name}" in namespace "${namespace}" has automountServiceAccountToken=true`,
            recommendation: 'Set automountServiceAccountToken: false unless explicitly required.',
            sourceFile: file.path,
            metadata: { name, namespace },
          }));
        }
      }

      if (kind === 'Secret') {
        findings.push(createFinding({
          severity: 'MODERATE',
          title: `Kubernetes Secret manifest detected: ${name}`,
          description: `Kubernetes Secret "${name}" in namespace "${namespace}" is defined in source code.`,
          recommendation: 'Do not store Kubernetes Secrets in source control. Use sealed secrets or external secret operators.',
          sourceFile: file.path,
          sourceSystem: 'kubernetes',
          evidenceRefs: [],
          metadata: { name, namespace },
        }));
      }

      if (kind === 'ClusterRole' || kind === 'Role') {
        const rules = doc?.rules ?? [];
        const hasBroadVerbs = rules.some((rule: { verbs?: string[]; resources?: string[] }) =>
          rule?.verbs?.includes('*') ||
          (rule?.verbs?.some((v: string) => ['get', 'list', 'watch'].includes(v)) && rule?.resources?.includes('*'))
        );
        const hasWildcardResources = rules.some((rule: { resources?: string[] }) => rule?.resources?.includes('*'));

        if (hasBroadVerbs || hasWildcardResources) {
          findings.push(createFinding({
            severity: 'HIGH',
            title: `Kubernetes ${kind} "${name}" has broad permissions`,
            description: `${kind} "${name}" grants wildcard verbs or wildcard resources.`,
            recommendation: 'Apply least-privilege RBAC. Specify exact verbs and resources required.',
            sourceFile: file.path,
            sourceSystem: 'kubernetes',
            inflectionType: 'WILDCARD_PERMISSION',
            evidenceRefs: [],
            metadata: { kind, name, rules },
          }));
        }
      }

      if (kind === 'ClusterRoleBinding' || kind === 'RoleBinding') {
        const roleRef = doc?.roleRef ?? {};
        const roleName = roleRef?.name ?? 'unknown';
        const subjects = doc?.subjects ?? [];
        const isClusterAdmin = roleName === 'cluster-admin';
        const isNamespaceCrossing = kind === 'ClusterRoleBinding';

        for (const subject of subjects) {
          const subjectName = subject?.name ?? 'unknown';
          const subjectNamespace = subject?.namespace ?? namespace;
          const subjectKind = subject?.kind ?? '';

          const subjectKey = `${subjectNamespace}/${subjectName}`;
          const subjectIdentity = serviceAccounts.get(subjectKey) ?? createIdentity({
            name: `k8s-sa:${subjectNamespace}/${subjectName}`,
            identityType: 'kubernetes_service_account',
            sourceSystem: 'kubernetes',
            sourceFile: file.path,
            credentialTypes: ['kubernetes_service_account_token'],
            riskTags: isClusterAdmin ? ['admin', 'cluster_admin'] : [],
            metadata: { kind: subjectKind, namespace: subjectNamespace },
          });

          if (!serviceAccounts.has(subjectKey)) {
            identities.push(subjectIdentity);
            serviceAccounts.set(subjectKey, subjectIdentity);
          }

          // Create a placeholder target identity for the ClusterRole
          const roleIdentity = createIdentity({
            name: `k8s-role:${roleName}`,
            identityType: 'unknown_nhi',
            sourceSystem: 'kubernetes',
            sourceFile: file.path,
            credentialTypes: [],
            riskTags: isClusterAdmin ? ['admin'] : [],
            permissions: isClusterAdmin ? ['*'] : [],
          });
          identities.push(roleIdentity);

          edges.push(createAuthorityEdge({
            fromIdentityId: subjectIdentity.id,
            toIdentityId: roleIdentity.id,
            relation: kind,
            permissions: isClusterAdmin ? ['*'] : [roleName],
            isWildcard: isClusterAdmin,
            isAdmin: isClusterAdmin,
            scope: isNamespaceCrossing ? 'cluster' : namespace,
            sourceSystem: 'kubernetes',
            sourceFile: file.path,
            metadata: { roleName, kind },
          }));

          if (isClusterAdmin) {
            inflectionPoints.push(createInflectionPoint({
              type: 'PRIVILEGE_ESCALATION_PATH',
              severity: 'CRITICAL',
              identityId: subjectIdentity.id,
              identityName: subjectIdentity.name,
              description: `ServiceAccount "${subjectName}" is bound to cluster-admin via ${kind}`,
              recommendation: 'Remove cluster-admin binding. Apply least-privilege RBAC roles scoped to required namespaces.',
              sourceFile: file.path,
              metadata: { binding: name, roleName },
            }));
          }

          if (isNamespaceCrossing && !isClusterAdmin) {
            inflectionPoints.push(createInflectionPoint({
              type: 'TRUST_BOUNDARY_CROSSING',
              severity: 'MODERATE',
              identityId: subjectIdentity.id,
              identityName: subjectIdentity.name,
              description: `ClusterRoleBinding "${name}" grants cluster-wide access to "${subjectName}"`,
              recommendation: 'Use namespace-scoped RoleBindings unless cluster-wide access is strictly required.',
              sourceFile: file.path,
              metadata: { binding: name, roleName },
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
    findings,
    evidenceRefs: [],
    sourceSystem: 'kubernetes',
  };
}
