import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { Finding, Identity, InflectionPoint, ExecutionPath, ScanResult } from '../core/types';
import { createIdentity } from '../core/identity';
import { createExecutionPath } from '../core/executionPath';
import { createInflectionPoint } from '../core/inflectionPoint';
import { DiscoveredFile } from '../core/fileDiscovery';

function readFileSafe(filePath: string): string {
  try { return fs.readFileSync(filePath, 'utf-8'); } catch { return ''; }
}

function isAzurePipeline(filePath: string): boolean {
  const name = path.basename(filePath).toLowerCase();
  return name === 'azure-pipelines.yml' || name === 'azure-pipelines.yaml';
}

export function azureDevOpsConnector(files: DiscoveredFile[], fileContents: Map<string, string>): ScanResult {
  const identities: Identity[] = [];
  const executionPaths: ExecutionPath[] = [];
  const inflectionPoints: InflectionPoint[] = [];
  const findings: Finding[] = [];

  const pipelineFiles = files.filter((f) => isAzurePipeline(f.path));

  for (const file of pipelineFiles) {
    let content = fileContents.get(file.path);
    if (content === undefined) {
      content = readFileSafe(file.path);
      fileContents.set(file.path, content);
    }
    if (!content) continue;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let pipeline: any = {};
    try { pipeline = yaml.load(content) ?? {}; } catch { continue; }

    // Detect service connections
    const serviceConnectionMatches = content.match(/serviceConnection:\s*['"]?([^'"\n]+)/g) ?? [];
    for (const match of serviceConnectionMatches) {
      const name = match.replace(/serviceConnection:\s*['"]?/, '').replace(/['"]/, '').trim();
      identities.push(createIdentity({
        name: `azure-service-connection:${name}`,
        identityType: 'service_principal',
        sourceSystem: 'azure_devops',
        sourceFile: file.path,
        credentialTypes: ['service_connection'],
        riskTags: [],
      }));
    }

    // Detect secret variables
    if (content.includes('$(') && (content.toLowerCase().includes('secret') || content.toLowerCase().includes('password'))) {
      identities.push(createIdentity({
        name: 'azure-devops-pipeline-secrets',
        identityType: 'api_token',
        sourceSystem: 'azure_devops',
        sourceFile: file.path,
        credentialTypes: ['pipeline_secret'],
        riskTags: ['secret_in_pipeline'],
      }));
    }

    // Detect deployment stages/environments
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const stages = (pipeline as any)?.stages ?? [];
    for (const stage of stages) {
      const envName = stage?.environment ?? stage?.displayName ?? 'unknown';
      const isProduction = /prod/i.test(String(envName));
      const hasApproval = !!stage?.approval;

      const stageIdentity = identities[0] ?? createIdentity({
        name: 'azure-devops-runner',
        identityType: 'ci_cd_runner',
        sourceSystem: 'azure_devops',
        sourceFile: file.path,
        credentialTypes: [],
        riskTags: [],
      });

      executionPaths.push(createExecutionPath({
        identityId: stageIdentity.id,
        identityName: stageIdentity.name,
        trigger: 'azure-pipeline',
        targetEnvironment: String(envName),
        isProduction,
        approvalDetected: hasApproval,
        evidenceDetected: false,
        trustBoundaryCrossed: isProduction,
        steps: [],
        sourceFile: file.path,
        sourceSystem: 'azure_devops',
        metadata: { stage: stage?.stage ?? stage?.displayName },
      }));

      if (isProduction && !hasApproval) {
        inflectionPoints.push(createInflectionPoint({
          type: 'APPROVAL_BYPASS',
          severity: 'HIGH',
          description: `Azure DevOps stage deploys to production without approval gate`,
          recommendation: 'Add environment approval checks for production stages.',
          sourceFile: file.path,
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
    sourceSystem: 'azure_devops',
  };
}
