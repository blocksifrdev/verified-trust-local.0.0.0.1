"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.detectEvidenceGaps = detectEvidenceGaps;
const path = __importStar(require("path"));
const finding_1 = require("../core/finding");
const EVIDENCE_CHECKS = [
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
function detectEvidenceGaps(files, graph) {
    const findings = [];
    const filePaths = new Set(files.map((f) => f.path));
    const fileNames = new Set(files.map((f) => path.basename(f.path)));
    for (const check of EVIDENCE_CHECKS) {
        const found = check.patterns.some((pattern) => {
            const basename = path.basename(pattern);
            // Check by basename or full path match
            return fileNames.has(basename) || Array.from(filePaths).some((p) => p.endsWith(pattern));
        });
        if (!found) {
            findings.push((0, finding_1.createFinding)({
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
    const hasPolicyFiles = Array.from(filePaths).some((p) => p.endsWith('.rego') || p.includes('policy/') || p.endsWith('.policy.yaml'));
    if (!hasPolicyFiles) {
        findings.push((0, finding_1.createFinding)({
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
    const hasEnvProtection = Array.from(filePaths).some((p) => p.includes('environment') && (p.endsWith('.json') || p.endsWith('.yml')));
    if (!hasEnvProtection) {
        findings.push((0, finding_1.createFinding)({
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
//# sourceMappingURL=evidenceGapDetector.js.map