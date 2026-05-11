import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { Identity, ExecutionPath } from '../core/types';
import { createExecutionPath } from '../core/executionPath';
import { DiscoveredFile } from '../core/fileDiscovery';

function readFileSafe(filePath: string): string {
  try { return fs.readFileSync(filePath, 'utf-8'); } catch { return ''; }
}

const PROD_PATTERNS = [/\bprod(?:uction)?\b/i, /\blive\b/i, /\brelease\b/i, /\bstaging\b/i];

function isProductionTarget(target: string): boolean {
  return PROD_PATTERNS.some((p) => p.test(target));
}

function detectTrustBoundaryCrossing(sourceFile: string, targetEnv: string): boolean {
  // Simple heuristic: if source is a CI file and target mentions cloud or prod
  const isCI = /workflow|pipeline|jenkins|gitlab-ci/i.test(sourceFile);
  return isCI && isProductionTarget(targetEnv);
}

export function detectExecutionPaths(
  identities: Identity[],
  files: DiscoveredFile[],
  fileContents: Map<string, string>
): ExecutionPath[] {
  const paths: ExecutionPath[] = [];

  // Look at CI/CD files and IaC for execution paths
  for (const file of files) {
    let content = fileContents.get(file.path);
    if (content === undefined) {
      content = readFileSafe(file.path);
      fileContents.set(file.path, content);
    }
    if (!content) continue;

    const ext = path.extname(file.path).toLowerCase();
    const name = path.basename(file.path).toLowerCase();

    // GitHub Actions
    if (name.endsWith('.yml') || name.endsWith('.yaml')) {
      let workflow: Record<string, unknown> = {};
      try { workflow = (yaml.load(content) as Record<string, unknown>) ?? {}; } catch { continue; }

      const on = workflow['on'];
      const trigger = on ? JSON.stringify(on) : 'unknown';
      const jobs = (workflow['jobs'] as Record<string, unknown>) ?? {};

      for (const [jobName, jobDef] of Object.entries(jobs)) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const job = jobDef as any;
        const environment = job?.environment;
        const envName = typeof environment === 'string' ? environment : (environment?.name ?? '');
        const isProduction = envName ? isProductionTarget(envName) : false;
        const hasApproval = environment && typeof environment === 'object';

        // Find matching identity (prefer CI runner identity)
        const identity = identities.find((i) =>
          i.sourceSystem === 'github_actions' || i.identityType === 'ci_cd_runner' || i.identityType === 'github_app'
        ) ?? identities[0];

        if (!identity) continue;

        paths.push(createExecutionPath({
          identityId: identity.id,
          identityName: identity.name,
          trigger,
          targetEnvironment: envName || 'unspecified',
          isProduction,
          approvalDetected: !!hasApproval,
          evidenceDetected: false,
          trustBoundaryCrossed: detectTrustBoundaryCrossing(file.path, envName),
          steps: Array.isArray(job?.steps) ? job.steps.map((s: { name?: string }) => s?.name ?? 'step') : [],
          sourceFile: file.path,
          sourceSystem: 'github_actions',
          metadata: { jobName },
        }));
      }
    }

    // Terraform files — detect deployment targets
    if (ext === '.tf') {
      const regionMatches = content.match(/region\s*=\s*"([^"]+)"/g) ?? [];
      for (const regionMatch of regionMatches) {
        const region = regionMatch.match(/"([^"]+)"/)?.[1] ?? 'unknown';
        const identity = identities.find((i) => i.sourceSystem === 'terraform') ?? identities[0];
        if (!identity) continue;

        paths.push(createExecutionPath({
          identityId: identity.id,
          identityName: identity.name,
          trigger: 'terraform apply',
          targetEnvironment: region,
          isProduction: isProductionTarget(region) || content.includes('prod'),
          approvalDetected: content.includes('prevent_destroy') || content.includes('lifecycle'),
          evidenceDetected: false,
          trustBoundaryCrossed: true, // Terraform always crosses trust boundaries
          steps: ['terraform plan', 'terraform apply'],
          sourceFile: file.path,
          sourceSystem: 'terraform',
          metadata: { region },
        }));
      }
    }
  }

  return paths;
}
