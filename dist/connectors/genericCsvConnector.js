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
exports.genericCsvConnector = genericCsvConnector;
const fs = __importStar(require("fs"));
const identity_1 = require("../core/identity");
function readFileSafe(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf-8');
    }
    catch {
        return '';
    }
}
function parseCsv(content) {
    const lines = content.split('\n').filter((l) => l.trim());
    if (lines.length === 0)
        return [];
    const headers = lines[0].split(',').map((h) => h.trim().replace(/^"|"$/g, ''));
    return lines.slice(1).map((line) => {
        const values = line.split(',').map((v) => v.trim().replace(/^"|"$/g, ''));
        const record = {};
        headers.forEach((h, i) => { record[h] = values[i] ?? ''; });
        return record;
    });
}
const VALID_IDENTITY_TYPES = [
    'service_account', 'service_principal', 'managed_identity', 'workload_identity',
    'bot_user', 'deploy_key', 'api_token', 'oauth_client', 'github_app', 'ci_cd_runner',
    'kubernetes_service_account', 'aws_iam_role', 'gcp_service_account', 'azure_app_registration',
    'agent_identity', 'mcp_server_identity', 'unknown_nhi',
];
function normalizeType(raw) {
    const lower = raw.toLowerCase().replace(/[- ]/g, '_');
    if (VALID_IDENTITY_TYPES.includes(lower))
        return lower;
    return 'unknown_nhi';
}
function genericCsvConnector(fileOrDir) {
    const identities = [];
    const content = readFileSafe(fileOrDir);
    if (!content)
        return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'generic_csv' };
    const records = parseCsv(content);
    for (const record of records) {
        const name = record?.identity_name ?? record?.name ?? record?.account ?? record?.username ?? '';
        if (!name)
            continue;
        const rawType = record?.identity_type ?? record?.type ?? '';
        const rawSource = record?.source ?? record?.source_system ?? 'generic_csv';
        const owner = record?.owner ?? '';
        const environment = record?.environment ?? '';
        const permission = record?.permission ?? '';
        const resource = record?.resource ?? '';
        const lastUsed = record?.last_used ?? record?.last_used_at ?? '';
        const createdAt = record?.created_at ?? record?.created ?? '';
        const identityType = normalizeType(rawType);
        const source = 'generic_csv';
        identities.push((0, identity_1.createIdentity)({
            name,
            identityType,
            sourceSystem: source,
            credentialTypes: [],
            riskTags: owner ? [] : ['no_owner'],
            owner: owner || undefined,
            environment: environment || undefined,
            permissions: permission ? [permission] : [],
            lastUsedAt: lastUsed || undefined,
            createdAt: createdAt || undefined,
            metadata: { source: rawSource, resource },
        }));
    }
    return {
        identities,
        edges: [],
        executionPaths: [],
        inflectionPoints: [],
        findings: [],
        evidenceRefs: [],
        sourceSystem: 'generic_csv',
    };
}
//# sourceMappingURL=genericCsvConnector.js.map