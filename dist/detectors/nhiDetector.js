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
exports.detectNHIs = detectNHIs;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const identity_1 = require("../core/identity");
const NHI_NAME_PATTERNS = [
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
function readFileSafe(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf-8');
    }
    catch {
        return '';
    }
}
function detectNHIs(files, fileContents) {
    const identities = [];
    const seen = new Set();
    for (const file of files) {
        let content = fileContents.get(file.path);
        if (content === undefined) {
            content = readFileSafe(file.path);
            fileContents.set(file.path, content);
        }
        if (!content)
            continue;
        for (const { pattern, type } of NHI_NAME_PATTERNS) {
            pattern.lastIndex = 0; // Reset regex
            const matches = content.matchAll(new RegExp(pattern.source, pattern.flags));
            for (const match of matches) {
                const name = match[0].trim();
                const dedupeKey = `${name}::${type}`;
                if (seen.has(dedupeKey))
                    continue;
                seen.add(dedupeKey);
                identities.push((0, identity_1.createIdentity)({
                    name,
                    // eslint-disable-next-line @typescript-eslint/no-explicit-any
                    identityType: type,
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
                identities.push((0, identity_1.createIdentity)({
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
                identities.push((0, identity_1.createIdentity)({
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
//# sourceMappingURL=nhiDetector.js.map