import * as fs from 'fs';
import * as path from 'path';
import { ExecutionPath, Finding, Identity, InflectionPoint, ScanResult } from '../core/types';
import { createIdentity } from '../core/identity';
import { createExecutionPath } from '../core/executionPath';
import { createInflectionPoint } from '../core/inflectionPoint';
import { DiscoveredFile } from '../core/fileDiscovery';

function readFileSafe(filePath: string): string {
  try { return fs.readFileSync(filePath, 'utf-8'); } catch { return ''; }
}

function isJenkinsFile(filePath: string): boolean {
  const name = path.basename(filePath);
  return name === 'Jenkinsfile' || name.endsWith('.jenkinsfile') || name.endsWith('.Jenkinsfile');
}

export function jenkinsConnector(files: DiscoveredFile[], fileContents: Map<string, string>): ScanResult {
  const identities: Identity[] = [];
  const executionPaths: ExecutionPath[] = [];
  const inflectionPoints: InflectionPoint[] = [];
  const findings: Finding[] = [];

  const jenkinsFiles = files.filter((f) => isJenkinsFile(f.path));

  for (const file of jenkinsFiles) {
    let content = fileContents.get(file.path);
    if (content === undefined) {
      content = readFileSafe(file.path);
      fileContents.set(file.path, content);
    }
    if (!content) continue;

    // Detect credentials() usage
    const credMatches = content.match(/credentials\(['"]([^'"]+)['"]\)/g) ?? [];
    for (const match of credMatches) {
      const credId = match.match(/credentials\(['"]([^'"]+)['"]\)/)?.[1] ?? 'unknown';
      identities.push(createIdentity({
        name: `jenkins-credential:${credId}`,
        identityType: 'api_token',
        sourceSystem: 'jenkins',
        sourceFile: file.path,
        credentialTypes: ['jenkins_credential'],
        riskTags: [],
        metadata: { credentialId: credId },
      }));
    }

    // withCredentials blocks
    if (content.includes('withCredentials')) {
      identities.push(createIdentity({
        name: 'jenkins-withCredentials',
        identityType: 'api_token',
        sourceSystem: 'jenkins',
        sourceFile: file.path,
        credentialTypes: ['jenkins_credential'],
        riskTags: [],
      }));
    }

    // Deployment stages
    const stageMatches = content.match(/stage\(['"]([^'"]+)['"]\)/g) ?? [];
    for (const stageMatch of stageMatches) {
      const stageName = stageMatch.match(/stage\(['"]([^'"]+)['"]\)/)?.[1] ?? '';
      const isProduction = /prod|production|deploy/i.test(stageName);

      if (isProduction) {
        const identity = identities[0] ?? createIdentity({
          name: 'jenkins-runner',
          identityType: 'ci_cd_runner',
          sourceSystem: 'jenkins',
          sourceFile: file.path,
          credentialTypes: [],
          riskTags: [],
        });

        executionPaths.push(createExecutionPath({
          identityId: identity.id,
          identityName: identity.name,
          trigger: 'jenkinsfile',
          targetEnvironment: stageName,
          isProduction: true,
          approvalDetected: content.includes('input') && content.indexOf('input') < content.indexOf(stageName),
          evidenceDetected: false,
          trustBoundaryCrossed: true,
          steps: [stageName],
          sourceFile: file.path,
          sourceSystem: 'jenkins',
          metadata: { stageName },
        }));

        if (!content.includes('input')) {
          inflectionPoints.push(createInflectionPoint({
            type: 'APPROVAL_BYPASS',
            severity: 'HIGH',
            description: `Jenkins stage "${stageName}" deploys without manual approval (input step)`,
            recommendation: 'Add an input step before production deployment stages.',
            sourceFile: file.path,
            metadata: { stageName },
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
    sourceSystem: 'jenkins',
  };
}
