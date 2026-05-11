import * as fs from 'fs';
import { Finding } from '../core/types';
import { createFinding } from '../core/finding';
import { SECRET_PATTERNS, containsSecret, redactSecret } from '../core/redaction';
import { DiscoveredFile } from '../core/fileDiscovery';

function readFileSafe(filePath: string): string {
  try { return fs.readFileSync(filePath, 'utf-8'); } catch { return ''; }
}

interface PatternMatch {
  pattern: RegExp;
  name: string;
  severity: 'CRITICAL' | 'HIGH' | 'MODERATE';
}

const LABELED_PATTERNS: PatternMatch[] = [
  { pattern: /AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}/, name: 'AWS Access Key', severity: 'CRITICAL' },
  { pattern: /ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}/, name: 'GitHub Token', severity: 'CRITICAL' },
  { pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, name: 'Private Key', severity: 'CRITICAL' },
  { pattern: /"private_key":\s*"-----BEGIN/, name: 'GCP Service Account Key', severity: 'CRITICAL' },
  { pattern: /DefaultEndpointsProtocol=https;AccountName=/, name: 'Azure Storage Connection String', severity: 'HIGH' },
  { pattern: /(?:mysql|postgres|postgresql|mongodb|mssql|redis):\/\/[^:]+:[^@]+@/i, name: 'Database Connection String', severity: 'HIGH' },
  { pattern: /(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY)=["']?[A-Za-z0-9+/=!@#$%^&*()-_]{16,}/i, name: 'Credential in Config', severity: 'HIGH' },
];

export function detectCredentialRisks(files: DiscoveredFile[], fileContents: Map<string, string>): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    let content = fileContents.get(file.path);
    if (content === undefined) {
      content = readFileSafe(file.path);
      fileContents.set(file.path, content);
    }
    if (!content || !containsSecret(content)) continue;

    const lines = content.split('\n');
    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];

      for (const { pattern, name, severity } of LABELED_PATTERNS) {
        if (pattern.test(line)) {
          const match = line.match(pattern)?.[0] ?? '';
          const redacted = match ? redactSecret(match) : '[REDACTED]';

          findings.push(createFinding({
            severity,
            title: `${name} detected in source file`,
            description: `${name} pattern found in ${file.path}:${lineIdx + 1} — value: ${redacted}`,
            recommendation: `Remove the ${name} from source code. Use environment variables or a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager).`,
            sourceFile: file.path,
            sourceSystem: 'filesystem',
            inflectionType: 'SECRET_IN_CONFIG',
            evidenceRefs: [],
            metadata: {
              line: lineIdx + 1,
              patternName: name,
              redactedValue: redacted,
            },
          }));
          break; // One finding per line
        }
      }
    }
  }

  return findings;
}
