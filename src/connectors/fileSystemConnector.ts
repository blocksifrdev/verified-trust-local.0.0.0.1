import * as fs from 'fs';
import * as path from 'path';
import { Identity, EvidenceRef, ScanResult } from '../core/types';
import { createIdentity } from '../core/identity';
import { createEvidenceRef } from '../core/evidenceRef';
import { containsSecret, redactSecret } from '../core/redaction';
import { createFinding } from '../core/finding';
import { DiscoveredFile } from '../core/fileDiscovery';

const SERVICE_ACCOUNT_PATTERNS = [
  /svc[-_]?\w+/i,
  /service[-_]account/i,
  /bot[-_]?\w+/i,
  /deploy[-_]?\w+/i,
  /runner[-_]?\w+/i,
  /automation[-_]?\w+/i,
  /ci[-_]?\w+/i,
  /m2m[-_]?\w+/i,
  /machine[-_]?\w+/i,
  /workload[-_]?\w+/i,
];

function readFileSafe(filePath: string): string {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return '';
  }
}

function isConfigFile(filePath: string): boolean {
  const name = path.basename(filePath).toLowerCase();
  const ext = path.extname(filePath).toLowerCase();
  return (
    name === '.env' ||
    name === 'docker-compose.yml' ||
    name === 'docker-compose.yaml' ||
    name.endsWith('.env') ||
    ext === '.json' ||
    ext === '.yaml' ||
    ext === '.yml' ||
    ext === '.toml' ||
    ext === '.ini'
  );
}

export function fileSystemConnector(files: DiscoveredFile[], fileContents: Map<string, string>): ScanResult {
  const identities: Identity[] = [];
  const evidenceRefs: EvidenceRef[] = [];
  const rawFindings: ReturnType<typeof createFinding>[] = [];

  const evidenceFiles = [
    'CODEOWNERS',
    'SECURITY.md',
    'CHANGELOG.md',
    'RELEASE.md',
  ];

  for (const file of files) {
    const name = path.basename(file.path);

    // Check for evidence files
    if (evidenceFiles.includes(name)) {
      evidenceRefs.push(createEvidenceRef({
        type: name.replace('.md', '').toLowerCase(),
        path: file.path,
        present: true,
        description: `Evidence file present: ${name}`,
      }));
    }

    // PR template
    if (name === 'pull_request_template.md') {
      evidenceRefs.push(createEvidenceRef({
        type: 'pr_template',
        path: file.path,
        present: true,
        description: 'Pull request template present',
      }));
    }

    if (!isConfigFile(file.path)) continue;

    let content = fileContents.get(file.path);
    if (content === undefined) {
      content = readFileSafe(file.path);
      fileContents.set(file.path, content);
    }
    if (!content) continue;

    // Look for service account name patterns
    for (const pattern of SERVICE_ACCOUNT_PATTERNS) {
      const match = content.match(pattern);
      if (match) {
        const foundName = match[0];
        identities.push(createIdentity({
          name: foundName,
          identityType: 'service_account',
          sourceSystem: 'filesystem',
          sourceFile: file.path,
          credentialTypes: [],
          riskTags: [],
        }));
        break; // One identity per file for now
      }
    }

    // Check for secrets
    if (containsSecret(content)) {
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (containsSecret(line)) {
          const redacted = redactSecret(line.trim().slice(0, 60));
          rawFindings.push(createFinding({
            severity: 'HIGH',
            title: 'Potential secret or credential detected in file',
            description: `Credential pattern detected in ${file.path}:${i + 1} — ${redacted}`,
            recommendation: 'Remove credentials from source files. Use environment variables or a secrets manager.',
            sourceFile: file.path,
            sourceSystem: 'filesystem',
            inflectionType: 'SECRET_IN_CONFIG',
            evidenceRefs: [],
            metadata: { line: i + 1 },
          }));
        }
      }
    }
  }

  return {
    identities,
    edges: [],
    executionPaths: [],
    inflectionPoints: [],
    findings: rawFindings,
    evidenceRefs,
    sourceSystem: 'filesystem',
  };
}
