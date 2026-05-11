import * as fs from 'fs';
import * as path from 'path';
import { Identity } from '../core/types';
import { createIdentity } from '../core/identity';
import { DiscoveredFile } from '../core/fileDiscovery';

const NHI_NAME_PATTERNS: Array<{ pattern: RegExp; type: string }> = [
  { pattern: /\bsvc[-_]?\w+/gi, type: 'service_account' },
  { pattern: /\bservice[-_]account\b/gi, type: 'service_account' },
  { pattern: /\bbot[-_]?\w+/gi, type: 'bot_user' },
  { pattern: /\bdeploy[-_]?\w+/gi, type: 'deploy_key' },
  { pattern: /\brunner[-_]?\w+/gi, type: 'ci_cd_runner' },
  { pattern: /\bautomation[-_]?\w+/gi, type: 'service_account' },
  { pattern: /\bapp[-_]?\w+/gi, type: 'service_account' },
  { pattern: /\bworkload[-_]?\w+/gi, type: 'workload_identity' },
  { pattern: /\bm2m[-_]?\w+/gi, type: 'service_account' },
  { pattern: /\bmachine[-_]?\w+/gi, type: 'service_account' },
  { pattern: /\bagent[-_]?\w+/gi, type: 'agent_identity' },
  { pattern: /\bdependabot\b/gi, type: 'bot_user' },
  { pattern: /\brenovate\b/gi, type: 'bot_user' },
  { pattern: /\bGITHUB_TOKEN\b/g, type: 'github_app' },
  { pattern: /arn:aws:iam::\d+:role\/[\w-]+/g, type: 'aws_iam_role' },
  { pattern: /[\w.-]+@[\w-]+\.iam\.gserviceaccount\.com/g, type: 'gcp_service_account' },
  { pattern: /serviceAccount(?:Name)?:\s*["']?[\w-]+/gi, type: 'kubernetes_service_account' },
  { pattern: /client_id["']?\s*[:=]\s*["'][\w-]{8,}["']/gi, type: 'oauth_client' },
  { pattern: /Bearer\s+[A-Za-z0-9._-]{20,}/gi, type: 'api_token' },
  { pattern: /mcp[-_.]server/gi, type: 'mcp_server_identity' },
  { pattern: /\.cursor\//gi, type: 'agent_identity' },
  { pattern: /\.claude\//gi, type: 'agent_identity' },
];

function readFileSafe(filePath: string): string {
  try { return fs.readFileSync(filePath, 'utf-8'); } catch { return ''; }
}

export function detectNHIs(files: DiscoveredFile[], fileContents: Map<string, string>): Identity[] {
  const identities: Identity[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    let content = fileContents.get(file.path);
    if (content === undefined) {
      content = readFileSafe(file.path);
      fileContents.set(file.path, content);
    }
    if (!content) continue;

    for (const { pattern, type } of NHI_NAME_PATTERNS) {
      pattern.lastIndex = 0; // Reset regex
      const matches = content.matchAll(new RegExp(pattern.source, pattern.flags));
      for (const match of matches) {
        const name = match[0].trim();
        const dedupeKey = `${name}::${type}`;
        if (seen.has(dedupeKey)) continue;
        seen.add(dedupeKey);

        identities.push(createIdentity({
          name,
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          identityType: type as any,
          sourceSystem: 'filesystem',
          sourceFile: file.path,
          credentialTypes: [],
          riskTags: [],
          metadata: { detectedBy: 'nhiDetector' },
        }));
      }
    }

    // Azure service principal patterns
    const spPattern = /servicePrincipal(?:Id)?["']?\s*[:=]\s*["'][\w-]{8,}["']/gi;
    const spMatches = content.matchAll(spPattern);
    for (const match of spMatches) {
      const name = match[0].trim();
      const dedupeKey = `${name}::service_principal`;
      if (!seen.has(dedupeKey)) {
        seen.add(dedupeKey);
        identities.push(createIdentity({
          name,
          identityType: 'service_principal',
          sourceSystem: 'filesystem',
          sourceFile: file.path,
          credentialTypes: [],
          riskTags: [],
          metadata: { detectedBy: 'nhiDetector' },
        }));
      }
    }

    // Deploy keys (SSH key refs)
    if (content.includes('-----BEGIN') && (file.path.endsWith('.pem') || file.path.endsWith('.key'))) {
      const dedupeKey = `${file.path}::deploy_key`;
      if (!seen.has(dedupeKey)) {
        seen.add(dedupeKey);
        identities.push(createIdentity({
          name: path.basename(file.path),
          identityType: 'deploy_key',
          sourceSystem: 'filesystem',
          sourceFile: file.path,
          credentialTypes: ['ssh_key'],
          riskTags: ['private_key_in_repo'],
          metadata: { detectedBy: 'nhiDetector' },
        }));
      }
    }
  }

  return identities;
}
