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
exports.vaultExportConnector = vaultExportConnector;
const fs = __importStar(require("fs"));
const identity_1 = require("../core/identity");
const inflectionPoint_1 = require("../core/inflectionPoint");
function readFileSafe(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf-8');
    }
    catch {
        return '';
    }
}
function vaultExportConnector(fileOrDir) {
    const identities = [];
    const inflectionPoints = [];
    const content = readFileSafe(fileOrDir);
    if (!content)
        return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'vault' };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let data = {};
    try {
        data = JSON.parse(content);
    }
    catch {
        return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'vault' };
    }
    // Entities / aliases
    const entities = data?.entities ?? data?.data?.entity ?? [];
    for (const entity of Array.isArray(entities) ? entities : []) {
        const name = entity?.name ?? entity?.id ?? 'unknown-vault-entity';
        const aliases = entity?.aliases ?? [];
        const policies = entity?.policies ?? [];
        const authMounts = aliases.map((a) => a?.mount_type ?? 'unknown');
        const credTypes = Array.from(new Set(authMounts));
        const identity = (0, identity_1.createIdentity)({
            name,
            identityType: 'service_account',
            sourceSystem: 'vault',
            credentialTypes: credTypes,
            riskTags: [],
            permissions: policies,
            metadata: { aliases, policies },
        });
        identities.push(identity);
        if (policies.includes('root') || policies.includes('sudo')) {
            inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                type: 'ADMIN_ROLE_ASSIGNED',
                severity: 'CRITICAL',
                identityId: identity.id,
                identityName: name,
                description: `Vault entity "${name}" has root or sudo policy`,
                recommendation: 'Remove root/sudo policy assignments. Apply least-privilege Vault policies.',
                metadata: { policies },
            }));
        }
    }
    // Auth mounts from audit logs
    const auditLogs = data?.audit_logs ?? data?.logs ?? [];
    const authTypes = new Set();
    for (const log of Array.isArray(auditLogs) ? auditLogs : []) {
        const authMount = log?.auth?.mount_type ?? log?.mount_type ?? '';
        if (authMount)
            authTypes.add(authMount);
    }
    if (authTypes.size > 0) {
        identities.push((0, identity_1.createIdentity)({
            name: 'vault-auth-mounts',
            identityType: 'service_account',
            sourceSystem: 'vault',
            credentialTypes: Array.from(authTypes),
            riskTags: [],
            metadata: { authMounts: Array.from(authTypes) },
        }));
    }
    return {
        identities,
        edges: [],
        executionPaths: [],
        inflectionPoints,
        findings: [],
        evidenceRefs: [],
        sourceSystem: 'vault',
    };
}
//# sourceMappingURL=vaultExportConnector.js.map