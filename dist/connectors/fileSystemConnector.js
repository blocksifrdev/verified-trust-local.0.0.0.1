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
exports.fileSystemConnector = fileSystemConnector;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const identity_1 = require("../core/identity");
const evidenceRef_1 = require("../core/evidenceRef");
const redaction_1 = require("../core/redaction");
const finding_1 = require("../core/finding");
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
function readFileSafe(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf-8');
    }
    catch {
        return '';
    }
}
function isConfigFile(filePath) {
    const name = path.basename(filePath).toLowerCase();
    const ext = path.extname(filePath).toLowerCase();
    return (name === '.env' ||
        name === 'docker-compose.yml' ||
        name === 'docker-compose.yaml' ||
        name.endsWith('.env') ||
        ext === '.json' ||
        ext === '.yaml' ||
        ext === '.yml' ||
        ext === '.toml' ||
        ext === '.ini');
}
function fileSystemConnector(files, fileContents) {
    const identities = [];
    const evidenceRefs = [];
    const rawFindings = [];
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
            evidenceRefs.push((0, evidenceRef_1.createEvidenceRef)({
                type: name.replace('.md', '').toLowerCase(),
                path: file.path,
                present: true,
                description: `Evidence file present: ${name}`,
            }));
        }
        // PR template
        if (name === 'pull_request_template.md') {
            evidenceRefs.push((0, evidenceRef_1.createEvidenceRef)({
                type: 'pr_template',
                path: file.path,
                present: true,
                description: 'Pull request template present',
            }));
        }
        if (!isConfigFile(file.path))
            continue;
        let content = fileContents.get(file.path);
        if (content === undefined) {
            content = readFileSafe(file.path);
            fileContents.set(file.path, content);
        }
        if (!content)
            continue;
        // Look for service account name patterns
        for (const pattern of SERVICE_ACCOUNT_PATTERNS) {
            const match = content.match(pattern);
            if (match) {
                const foundName = match[0];
                identities.push((0, identity_1.createIdentity)({
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
        if ((0, redaction_1.containsSecret)(content)) {
            const lines = content.split('\n');
            for (let i = 0; i < lines.length; i++) {
                const line = lines[i];
                if ((0, redaction_1.containsSecret)(line)) {
                    const redacted = (0, redaction_1.redactSecret)(line.trim().slice(0, 60));
                    rawFindings.push((0, finding_1.createFinding)({
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
//# sourceMappingURL=fileSystemConnector.js.map