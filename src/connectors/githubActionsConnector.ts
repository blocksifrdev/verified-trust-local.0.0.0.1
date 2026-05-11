import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { Identity, ExecutionPath, InflectionPoint, ScanResult } from '../core/types';
import { createIdentity } from '../core/identity';
import { createExecutionPath } from '../core/executionPath';
import { createInflectionPoint } from '../core/inflectionPoint';
import { createFinding } from '../core/finding';
import { DiscoveredFile } from '../core/fileDiscovery';

function readFileSafe(filePath: string): string {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return '';
  }
}

function isWorkflowFile(filePath: string): boolean {
  const normalized = filePath.replace(/\\/g, '/');
  return (
    normalized.includes('/.github/workflows/') &&
    (normalized.endsWith('.yml') || normalized.endsWith('.yaml'))
  );
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parseWorkflow(content: string): any {
  try {
    return yaml.load(content) ?? {};
  } catch {
    return {};
  }
}

function detectSecrets(content: string): string[] {
  const secrets: string[] = [];
  const secretRegex = /secrets\.([A-Za-z0-9_]+)/g;
  let match;
  while ((match = secretRegex.exec(content)) !== null) {
    if (!secrets.includes(match[1])) {
      secrets.push(match[1]);
    }
  }
  return secrets;
}

export function githubActionsConnector(files: DiscoveredFile[], fileContents: Map<string, string>): ScanResult {
  const identities: Identity[] = [];
  const executionPaths: ExecutionPath[] = [];
  const inflectionPoints: InflectionPoint[] = [];
  const findings = [];

  const workflowFiles = files.filter((f) => isWorkflowFile(f.path));

  for (const file of workflowFiles) {
    let content = fileContents.get(file.path);
    if (content === undefined) {
      content = readFileSafe(file.path);
      fileContents.set(file.path, content);
    }
    if (!content) continue;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const workflow = parseWorkflow(content) as any;

    const hasGithubToken = content.includes('GITHUB_TOKEN') || content.includes('github.token');
    const secrets = detectSecrets(content);
    const hasOidc = content.includes('id-token') && content.includes('write');
    const hasDependabot = content.includes('dependabot');
    const hasRenovate = content.includes('renovate');
    const hasDeployKey = content.includes('DEPLOY_KEY') || content.includes('deploy_key') || content.includes('SSH_KEY');

    // Detect bot/NHI identities
    if (hasGithubToken) {
      identities.push(createIdentity({
        name: 'GITHUB_TOKEN',
        identityType: 'github_app',
        sourceSystem: 'github_actions',
        sourceFile: file.path,
        credentialTypes: ['github_token'],
        riskTags: [],
        description: 'Automatic GITHUB_TOKEN for workflow authentication',
      }));
    }

    if (hasDeployKey) {
      identities.push(createIdentity({
        name: 'deploy-key',
        identityType: 'deploy_key',
        sourceSystem: 'github_actions',
        sourceFile: file.path,
        credentialTypes: ['ssh_key'],
        riskTags: ['deploy_key'],
      }));
    }

    if (hasDependabot) {
      identities.push(createIdentity({
        name: 'dependabot',
        identityType: 'bot_user',
        sourceSystem: 'github_actions',
        sourceFile: file.path,
        credentialTypes: [],
        riskTags: ['bot'],
      }));
    }

    if (hasRenovate) {
      identities.push(createIdentity({
        name: 'renovate',
        identityType: 'bot_user',
        sourceSystem: 'github_actions',
        sourceFile: file.path,
        credentialTypes: [],
        riskTags: ['bot'],
      }));
    }

    if (hasOidc) {
      identities.push(createIdentity({
        name: 'oidc-workload-identity',
        identityType: 'workload_identity',
        sourceSystem: 'github_actions',
        sourceFile: file.path,
        credentialTypes: ['oidc_token'],
        riskTags: ['oidc'],
      }));
    }

    // Detect execution paths by inspecting jobs
    const jobs = (workflow && typeof workflow === 'object' && workflow['jobs']) ? workflow['jobs'] : {};
    for (const [jobName, jobDef] of Object.entries(jobs)) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const job = jobDef as any;
      const environment = job?.environment;
      const envName = typeof environment === 'string' ? environment : (environment?.name ?? '');
      const isProduction = /prod/i.test(envName) || /production/i.test(envName);
      const hasApproval = environment && typeof environment === 'object' && environment['url'];

      const epIdentity = identities[0] ?? createIdentity({
        name: path.basename(file.path),
        identityType: 'ci_cd_runner',
        sourceSystem: 'github_actions',
        sourceFile: file.path,
        credentialTypes: [],
        riskTags: [],
      });

      executionPaths.push(createExecutionPath({
        identityId: epIdentity.id,
        identityName: epIdentity.name,
        trigger: JSON.stringify(workflow['on'] ?? 'unknown'),
        targetEnvironment: envName || 'unspecified',
        isProduction,
        approvalDetected: !!hasApproval,
        evidenceDetected: false,
        trustBoundaryCrossed: isProduction,
        steps: Array.isArray(job?.steps) ? job.steps.map((s: { name?: string }) => s?.name ?? 'step') : [],
        sourceFile: file.path,
        sourceSystem: 'github_actions',
        metadata: { jobName },
      }));

      if (isProduction && !hasApproval) {
        inflectionPoints.push(createInflectionPoint({
          type: 'APPROVAL_BYPASS',
          severity: 'HIGH',
          identityName: epIdentity.name,
          description: `Job "${jobName}" deploys to production environment "${envName}" without detected approval gate in ${path.basename(file.path)}`,
          recommendation: 'Add environment protection rules with required reviewers for production deployments.',
          sourceFile: file.path,
          metadata: { jobName, environment: envName },
        }));
      }
    }

    // Check permissions
    const permissions = workflow?.permissions;
    if (permissions && typeof permissions === 'object') {
      const permStr = JSON.stringify(permissions);
      if (permStr.includes('write-all') || permStr.includes('"write"')) {
        findings.push(createFinding({
          severity: 'MODERATE',
          title: 'Broad workflow permissions detected',
          description: `Workflow ${path.basename(file.path)} has write permissions configured.`,
          recommendation: 'Apply least-privilege permissions per job. Avoid write-all at workflow level.',
          sourceFile: file.path,
          sourceSystem: 'github_actions',
          inflectionType: 'PRIVILEGE_ESCALATION_PATH',
          evidenceRefs: [],
          metadata: {},
        }));
      }
    }
  }

  return {
    identities,
    edges: [],
    executionPaths,
    inflectionPoints,
    findings,
    evidenceRefs: [],
    sourceSystem: 'github_actions',
  };
}
