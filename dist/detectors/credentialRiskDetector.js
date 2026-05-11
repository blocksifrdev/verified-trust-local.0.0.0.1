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
exports.detectCredentialRisks = detectCredentialRisks;
const fs = __importStar(require("fs"));
const finding_1 = require("../core/finding");
const redaction_1 = require("../core/redaction");
function readFileSafe(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf-8');
    }
    catch {
        return '';
    }
}
const LABELED_PATTERNS = [
    { pattern: /AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}/, name: 'AWS Access Key', severity: 'CRITICAL' },
    { pattern: /ghp_[A-Za-z0-9]{36}|ghs_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}/, name: 'GitHub Token', severity: 'CRITICAL' },
    { pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/, name: 'Private Key', severity: 'CRITICAL' },
    { pattern: /"private_key":\s*"-----BEGIN/, name: 'GCP Service Account Key', severity: 'CRITICAL' },
    { pattern: /DefaultEndpointsProtocol=https;AccountName=/, name: 'Azure Storage Connection String', severity: 'HIGH' },
    { pattern: /(?:mysql|postgres|postgresql|mongodb|mssql|redis):\/\/[^:]+:[^@]+@/i, name: 'Database Connection String', severity: 'HIGH' },
    { pattern: /(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|APIKEY)=["']?[A-Za-z0-9+/=!@#$%^&*()-_]{16,}/i, name: 'Credential in Config', severity: 'HIGH' },
];
function detectCredentialRisks(files, fileContents) {
    const findings = [];
    for (const file of files) {
        let content = fileContents.get(file.path);
        if (content === undefined) {
            content = readFileSafe(file.path);
            fileContents.set(file.path, content);
        }
        if (!content || !(0, redaction_1.containsSecret)(content))
            continue;
        const lines = content.split('\n');
        for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
            const line = lines[lineIdx];
            for (const { pattern, name, severity } of LABELED_PATTERNS) {
                if (pattern.test(line)) {
                    const match = line.match(pattern)?.[0] ?? '';
                    const redacted = match ? (0, redaction_1.redactSecret)(match) : '[REDACTED]';
                    findings.push((0, finding_1.createFinding)({
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
//# sourceMappingURL=credentialRiskDetector.js.map