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
exports.beyondTrustExportConnector = beyondTrustExportConnector;
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
function beyondTrustExportConnector(fileOrDir) {
    const identities = [];
    const inflectionPoints = [];
    const content = readFileSafe(fileOrDir);
    if (!content)
        return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'beyondtrust' };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let records = [];
    try {
        const parsed = JSON.parse(content);
        records = Array.isArray(parsed) ? parsed : (parsed?.accounts ?? parsed?.managed_accounts ?? [parsed]);
    }
    catch {
        records = parseCsv(content);
    }
    for (const record of records) {
        const name = record?.AccountName ?? record?.account_name ?? record?.username ?? record?.name ?? 'unknown';
        const system = record?.SystemName ?? record?.system_name ?? record?.asset ?? '';
        const policyGroup = record?.PolicyGroup ?? record?.policy_group ?? '';
        const owner = record?.Owner ?? record?.owner ?? '';
        const identity = (0, identity_1.createIdentity)({
            name,
            identityType: 'service_account',
            sourceSystem: 'beyondtrust',
            credentialTypes: ['managed_password'],
            riskTags: owner ? [] : ['no_owner'],
            owner: owner || undefined,
            metadata: { system, policyGroup },
        });
        identities.push(identity);
        if (!owner) {
            inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                type: 'OWNER_MISSING',
                severity: 'MODERATE',
                identityId: identity.id,
                identityName: name,
                description: `BeyondTrust managed account "${name}" has no assigned owner`,
                recommendation: 'Assign accountability for all managed accounts in BeyondTrust.',
                metadata: { system },
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
        sourceSystem: 'beyondtrust',
    };
}
//# sourceMappingURL=beyondTrustExportConnector.js.map