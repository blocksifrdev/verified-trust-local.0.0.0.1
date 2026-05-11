import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { ExecutionPath, Finding, Identity, InflectionPoint, ScanResult } from '../core/types';
import { createIdentity } from '../core/identity';
import { createExecutionPath } from '../core/executionPath';
import { createInflectionPoint } from '../core/inflectionPoint';
import { DiscoveredFile } from '../core/fileDiscovery';

function readFileSafe(filePath: string): string {
  try { return fs.readFileSync(filePath, 'utf-8'); } catch { return ''; }
}

function isGitlabCi(filePath: string): boolean {
  return path.basename(filePath) === '.gitlab-ci.yml' || path.basename(filePath) === '.gitlab-ci.yaml';
}

export function gitlabCiConnector(files: DiscoveredFile[], fileContents: Map<string, string>): ScanResult {
  const identities: Identity[] = [];
  const executionPaths: ExecutionPath[] = [];
  const inflectionPoints: InflectionPoint[] = [];
  const findings: Finding[] = [];

  const ciFiles = files.filter((f) => isGitlabCi(f.path));

  for (const file of ciFiles) {
    let content = fileContents.get(file.path);
    if (content === undefined) {
      content = readFileSafe(file.path);
      fileContents.set(file.path, content);
    }
    if (!content) continue;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let pipeline: any = {};
    try { pipeline = yaml.load(content) ?? {}; } catch { continue; }

    // CI_JOB_TOKEN usage
    if (content.includes('CI_JOB_TOKEN')) {
      identities.push(createIdentity({
        name: 'CI_JOB_TOKEN',
        identityType: 'api_token',
        sourceSystem: 'gitlab_ci',
        sourceFile: file.path,
        credentialTypes: ['ci_job_token'],
        riskTags: [],
      }));
    }

    // Service accounts in variables
    const variables = (pipeline as any)?.variables ?? {};
    for (const [key, val] of Object.entries(variables)) {
      if (/service|account|token|secret/i.test(key)) {
        identities.push(createIdentity({
          name: `gitlab-var:${key}`,
          identityType: 'api_token',
          sourceSystem: 'gitlab_ci',
          sourceFile: file.path,
          credentialTypes: ['pipeline_variable'],
          riskTags: [],
          metadata: { value: String(val).slice(0, 20) },
        }));
      }
    }

    // Detect deploy stages
    for (const [jobName, jobDef] of Object.entries(pipeline as Record<string, unknown>)) {
      if (jobName.startsWith('.') || jobName === 'variables' || jobName === 'stages' || jobName === 'image') continue;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const job = jobDef as any;
      const stage = job?.stage ?? '';
      const envName = job?.environment?.name ?? job?.environment ?? '';
      const isProduction = /prod/i.test(stage) || /prod/i.test(String(envName));
      const hasApproval = !!job?.when && job?.when === 'manual';

      const identity = identities[0] ?? createIdentity({
        name: 'gitlab-runner',
        identityType: 'ci_cd_runner',
        sourceSystem: 'gitlab_ci',
        sourceFile: file.path,
        credentialTypes: [],
        riskTags: [],
      });

      if (stage && (stage === 'deploy' || /deploy|release/i.test(stage))) {
        executionPaths.push(createExecutionPath({
          identityId: identity.id,
          identityName: identity.name,
          trigger: 'gitlab-ci',
          targetEnvironment: String(envName) || stage,
          isProduction,
          approvalDetected: hasApproval,
          evidenceDetected: false,
          trustBoundaryCrossed: isProduction,
          steps: [],
          sourceFile: file.path,
          sourceSystem: 'gitlab_ci',
          metadata: { jobName, stage },
        }));

        if (isProduction && !hasApproval) {
          inflectionPoints.push(createInflectionPoint({
            type: 'APPROVAL_BYPASS',
            severity: 'HIGH',
            description: `GitLab CI job "${jobName}" deploys to production without manual approval`,
            recommendation: 'Add when: manual and protected environment approvals for production deployments.',
            sourceFile: file.path,
            metadata: { jobName },
          }));
        }
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
    sourceSystem: 'gitlab_ci',
  };
}
