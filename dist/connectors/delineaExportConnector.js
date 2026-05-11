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
exports.delineaExportConnector = delineaExportConnector;
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
function delineaExportConnector(fileOrDir) {
    const identities = [];
    const inflectionPoints = [];
    const content = readFileSafe(fileOrDir);
    if (!content)
        return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'delinea' };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let records = [];
    try {
        const parsed = JSON.parse(content);
        records = Array.isArray(parsed) ? parsed : (parsed?.secrets ?? [parsed]);
    }
    catch {
        records = parseCsv(content);
    }
    for (const record of records) {
        const secretName = record?.SecretName ?? record?.secret_name ?? record?.name ?? 'unknown';
        const folder = record?.Folder ?? record?.folder ?? '';
        const owner = record?.Owner ?? record?.owner ?? '';
        const lastAccessed = record?.LastAccessed ?? record?.last_accessed ?? '';
        const isStale = lastAccessed
            ? (Date.now() - new Date(lastAccessed).getTime()) / (1000 * 60 * 60 * 24) > 90
            : false;
        const identity = (0, identity_1.createIdentity)({
            name: secretName,
            identityType: 'service_account',
            sourceSystem: 'delinea',
            credentialTypes: ['managed_secret'],
            riskTags: [...(isStale ? ['stale'] : []), ...(owner ? [] : ['no_owner'])],
            owner: owner || undefined,
            lastUsedAt: lastAccessed || undefined,
            metadata: { folder, lastAccessed },
        });
        identities.push(identity);
        if (!owner) {
            inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                type: 'OWNER_MISSING',
                severity: 'MODERATE',
                identityId: identity.id,
                identityName: secretName,
                description: `Delinea secret "${secretName}" in folder "${folder}" has no owner`,
                recommendation: 'Assign an owner to all secrets in Delinea Secret Server.',
                metadata: { folder },
            }));
        }
    }
    return {
        identities,
        edges: [],
        executionPaths: [],
        inflectionPoints,
        findings: [],
        evidenceRefs: [],
        sourceSystem: 'delinea',
    };
}
//# sourceMappingURL=delineaExportConnector.js.map