import * as fs from 'fs';
import * as path from 'path';
import { ScanResult, Identity, AuthorityEdge } from '../core/types';
import { createIdentity } from '../core/identity';
import { createAuthorityEdge } from '../core/authorityEdge';
import { createInflectionPoint } from '../core/inflectionPoint';
import { createFinding } from '../core/finding';
import { DiscoveredFile } from '../core/fileDiscovery';

function readFileSafe(filePath: string): string {
  try { return fs.readFileSync(filePath, 'utf-8'); } catch { return ''; }
}

function isTerraformFile(filePath: string): boolean {
  return filePath.endsWith('.tf');
}

// Simple regex-based HCL resource extraction
function extractResources(content: string): Array<{ type: string; name: string; block: string }> {
  const resources: Array<{ type: string; name: string; block: string }> = [];
  const resourceRegex = /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/g;
  let match;
  while ((match = resourceRegex.exec(content)) !== null) {
    const type = match[1];
    const name = match[2];
    // Extract a rough block (next 50 lines or so)
    const start = match.index;
    const rest = content.slice(start, start + 2000);
    resources.push({ type, name, block: rest });
  }
  return resources;
}

export function terraformConnector(files: DiscoveredFile[], fileContents: Map<string, string>): ScanResult {
  const identities: Identity[] = [];
  const edges: AuthorityEdge[] = [];
  const inflectionPoints = [];
  const findings = [];

  const tfFiles = files.filter((f) => isTerraformFile(f.path));

  for (const file of tfFiles) {
    let content = fileContents.get(file.path);
    if (content === undefined) {
      content = readFileSafe(file.path);
      fileContents.set(file.path, content);
    }
    if (!content) continue;

    const resources = extractResources(content);

    for (const resource of resources) {
      const { type, name, block } = resource;

      // AWS IAM roles
      if (type === 'aws_iam_role') {
        const identity = createIdentity({
          name: `aws-iam-role:${name}`,
          identityType: 'aws_iam_role',
          sourceSystem: 'terraform',
          sourceFile: file.path,
          credentialTypes: ['iam_role'],
          riskTags: [],
          metadata: { terraformResource: `${type}.${name}` },
        });
        identities.push(identity);

        // Check for wildcard permissions
        if (block.includes('"*"') && (block.includes('Action') || block.includes('actions'))) {
          identity.riskTags.push('wildcard');
          identity.permissions.push('*');
          inflectionPoints.push(createInflectionPoint({
            type: 'WILDCARD_PERMISSION',
            severity: 'HIGH',
            identityId: identity.id,
            identityName: identity.name,
            description: `AWS IAM role "${name}" has wildcard (*) actions in policy`,
            recommendation: 'Replace wildcard actions with least-privilege specific permissions.',
            sourceFile: file.path,
            metadata: { resource: `${type}.${name}` },
          }));
        }

        // Check for admin roles
        if (block.includes('AdministratorAccess') || block.includes('PowerUserAccess')) {
          identity.riskTags.push('admin');
          inflectionPoints.push(createInflectionPoint({
            type: 'ADMIN_ROLE_ASSIGNED',
            severity: 'CRITICAL',
            identityId: identity.id,
            identityName: identity.name,
            description: `AWS IAM role "${name}" has AdministratorAccess or PowerUserAccess`,
            recommendation: 'Replace with least-privilege policies scoped to required resources.',
            sourceFile: file.path,
            metadata: { resource: `${type}.${name}` },
          }));
        }

        // Public access (Principal: "*")
        if (block.includes('Principal') && block.includes('"*"')) {
          identity.riskTags.push('public_access');
          inflectionPoints.push(createInflectionPoint({
            type: 'PUBLIC_EXPOSURE',
            severity: 'CRITICAL',
            identityId: identity.id,
            identityName: identity.name,
            description: `AWS IAM role "${name}" trust policy allows any principal (*)`,
            recommendation: 'Restrict trust policy to specific AWS accounts and services.',
            sourceFile: file.path,
            metadata: { resource: `${type}.${name}` },
          }));
        }
      }

      // AWS IAM policies
      if (type === 'aws_iam_policy' || type === 'aws_iam_role_policy') {
        if (block.includes('"*"') && block.includes('Action')) {
          findings.push(createFinding({
            severity: 'HIGH',
            title: `Terraform IAM policy "${name}" contains wildcard actions`,
            description: `Resource ${type}.${name} grants wildcard (*) actions.`,
            recommendation: 'Restrict to specific required actions.',
            sourceFile: file.path,
            sourceSystem: 'terraform',
            inflectionType: 'WILDCARD_PERMISSION',
            evidenceRefs: [],
            metadata: { resource: `${type}.${name}` },
          }));
        }
      }

      // Azure role assignments
      if (type === 'azurerm_role_assignment') {
        const scopeMatch = block.match(/scope\s*=\s*"([^"]+)"/);
        const roleMatch = block.match(/role_definition_name\s*=\s*"([^"]+)"/);
        const principalMatch = block.match(/principal_id\s*=\s*([^\n]+)/);
        const roleName = roleMatch?.[1] ?? 'unknown';
        const scope = scopeMatch?.[1] ?? 'unknown';
        const principalRef = principalMatch?.[1]?.trim() ?? 'unknown';

        const identity = createIdentity({
          name: `azure-role-assignment:${name}`,
          identityType: 'service_principal',
          sourceSystem: 'terraform',
          sourceFile: file.path,
          credentialTypes: [],
          riskTags: roleName === 'Owner' || roleName === 'Contributor' ? ['admin'] : [],
          permissions: [roleName],
          metadata: { scope, roleName, principalRef, terraformResource: `${type}.${name}` },
        });
        identities.push(identity);

        if (roleName === 'Owner' || roleName === 'Contributor') {
          inflectionPoints.push(createInflectionPoint({
            type: 'ADMIN_ROLE_ASSIGNED',
            severity: 'HIGH',
            identityId: identity.id,
            identityName: identity.name,
            description: `Azure role assignment "${name}" grants ${roleName} at scope: ${scope}`,
            recommendation: 'Use least-privilege custom roles instead of built-in Owner/Contributor.',
            sourceFile: file.path,
            metadata: { roleName, scope },
          }));
        }
      }

      // GCP IAM bindings
      if (type === 'google_project_iam_binding' || type === 'google_project_iam_member') {
        const roleMatch = block.match(/role\s*=\s*"([^"]+)"/);
        const roleName = roleMatch?.[1] ?? 'unknown';
        const membersMatch = block.match(/members\s*=\s*\[([^\]]+)\]/);
        const members = membersMatch?.[1] ?? '';

        const isAdmin = roleName.includes('roles/owner') || roleName.includes('roles/editor');
        const identity = createIdentity({
          name: `gcp-iam-binding:${name}`,
          identityType: 'gcp_service_account',
          sourceSystem: 'terraform',
          sourceFile: file.path,
          credentialTypes: [],
          riskTags: isAdmin ? ['admin'] : [],
          permissions: [roleName],
          metadata: { roleName, members, terraformResource: `${type}.${name}` },
        });
        identities.push(identity);

        if (isAdmin) {
          inflectionPoints.push(createInflectionPoint({
            type: 'ADMIN_ROLE_ASSIGNED',
            severity: 'HIGH',
            identityId: identity.id,
            identityName: identity.name,
            description: `GCP IAM binding "${name}" grants ${roleName}`,
            recommendation: 'Use least-privilege custom roles instead of owner/editor.',
            sourceFile: file.path,
            metadata: { roleName },
          }));
        }
      }

      // GCP service accounts
      if (type === 'google_service_account') {
        const emailMatch = block.match(/account_id\s*=\s*"([^"]+)"/);
        const accountId = emailMatch?.[1] ?? name;
        identities.push(createIdentity({
          name: `gcp-service-account:${accountId}`,
          identityType: 'gcp_service_account',
          sourceSystem: 'terraform',
          sourceFile: file.path,
          credentialTypes: ['service_account_key'],
          riskTags: [],
          metadata: { accountId, terraformResource: `${type}.${name}` },
        }));
      }

      // AWS IAM users (service accounts)
      if (type === 'aws_iam_user') {
        identities.push(createIdentity({
          name: `aws-iam-user:${name}`,
          identityType: 'service_account',
          sourceSystem: 'terraform',
          sourceFile: file.path,
          credentialTypes: ['access_key'],
          riskTags: [],
          metadata: { terraformResource: `${type}.${name}` },
        }));
      }

      // Secrets resources
      if (type === 'aws_secretsmanager_secret' || type === 'azurerm_key_vault_secret') {
        findings.push(createFinding({
          severity: 'INFO',
          title: `Secret resource managed in Terraform: ${name}`,
          description: `Terraform resource ${type}.${name} manages a secret. Ensure state file is secured.`,
          recommendation: 'Ensure Terraform state is stored in an encrypted, access-controlled backend.',
          sourceFile: file.path,
          sourceSystem: 'terraform',
          evidenceRefs: [],
          metadata: { resource: `${type}.${name}` },
        }));
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
    sourceSystem: 'terraform',
  };
}
