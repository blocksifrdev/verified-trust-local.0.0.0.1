import * as fs from 'fs';
import * as path from 'path';
import { Finding } from '../core/types';
import { createFinding } from '../core/finding';
import { IdentityGraph } from '../graph/identityGraph';
import { DiscoveredFile } from '../core/fileDiscovery';

interface EvidenceCheck {
  name: string;
  patterns: string[];
  severity: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'INFO';
  description: string;
  recommendation: string;
}

const EVIDENCE_CHECKS: EvidenceCheck[] = [
  {
    name: 'CODEOWNERS',
    patterns: ['CODEOWNERS', '.github/CODEOWNERS', 'docs/CODEOWNERS'],
    severity: 'HIGH',
    description: 'No CODEOWNERS file detected. Code ownership is not formally defined.',
    recommendation: 'Add a CODEOWNERS file to assign accountability for sensitive code paths.',
  },
  {
    name: 'PR_TEMPLATE',
    patterns: ['.github/pull_request_template.md', '.github/PULL_REQUEST_TEMPLATE.md', 'pull_request_template.md'],
    severity: 'MODERATE',
    description: 'No pull request template detected. Review checklists are not enforced.',
    recommendation: 'Add a pull request template with security and identity review checklist items.',
  },
  {
    name: 'SECURITY_POLICY',
    patterns: ['SECURITY.md', '.github/SECURITY.md', 'docs/SECURITY.md'],
    severity: 'MODERATE',
    description: 'No SECURITY.md detected. Security disclosure policy is not documented.',
    recommendation: 'Add a SECURITY.md file documenting your vulnerability disclosure and response process.',
  },
  {
    name: 'CHANGELOG',
    patterns: ['CHANGELOG.md', 'CHANGELOG', 'RELEASE.md', 'RELEASE_NOTES.md'],
    severity: 'LOW',
    description: 'No CHANGELOG or RELEASE documentation detected.',
    recommendation: 'Maintain a CHANGELOG.md to track releases and changes.',
  },
  {
    name: 'SBOM',
    patterns: ['sbom.json', 'sbom.spdx', 'sbom.cyclonedx.json', '.sbom'],
    severity: 'MODERATE',
    description: 'No Software Bill of Materials (SBOM) detected.',
    recommendation: 'Generate and publish an SBOM for every release using tools like Syft or CycloneDX.',
  },
];

export function detectEvidenceGaps(files: DiscoveredFile[], graph: IdentityGraph): Finding[] {
  const findings: Finding[] = [];
  const filePaths = new Set(files.map((f) => f.path));
  const fileNames = new Set(files.map((f) => path.basename(f.path)));

  for (const check of EVIDENCE_CHECKS) {
    const found = check.patterns.some((pattern) => {
      const basename = path.basename(pattern);
      // Check by basename or full path match
      return fileNames.has(basename) || Array.from(filePaths).some((p) => p.endsWith(pattern));
    });

    if (!found) {
      findings.push(createFinding({
        severity: check.severity,
        title: `Missing evidence artifact: ${check.name}`,
        description: check.description,
        recommendation: check.recommendation,
        inflectionType: 'EVIDENCE_MISSING',
        evidenceRefs: [],
        metadata: { evidenceType: check.name, searchedPatterns: check.patterns },
      }));
    }
  }

  // Check for policy-as-code files
  const hasPolicyFiles = Array.from(filePaths).some((p) =>
    p.endsWith('.rego') || p.includes('policy/') || p.endsWith('.policy.yaml')
  );
  if (!hasPolicyFiles) {
    findings.push(createFinding({
      severity: 'MODERATE',
      title: 'No policy-as-code files detected',
      description: 'No OPA/Rego or policy-as-code files found. Identity and access policies are not enforced programmatically.',
      recommendation: 'Implement policy-as-code using OPA/Rego or similar to enforce identity and access policies.',
      inflectionType: 'EVIDENCE_MISSING',
      evidenceRefs: [],
      metadata: { evidenceType: 'POLICY_AS_CODE' },
    }));
  }

  // Check for environment protection config
  const hasEnvProtection = Array.from(filePaths).some((p) =>
    p.includes('environment') && (p.endsWith('.json') || p.endsWith('.yml'))
  );
  if (!hasEnvProtection) {
    findings.push(createFinding({
      severity: 'LOW',
      title: 'No environment protection configuration detected',
      description: 'No environment protection configuration files found in repository.',
      recommendation: 'Configure environment protection rules with required reviewers for production environments.',
      inflectionType: 'EVIDENCE_MISSING',
      evidenceRefs: [],
      metadata: { evidenceType: 'ENV_PROTECTION' },
    }));
  }

  return findings;
}
