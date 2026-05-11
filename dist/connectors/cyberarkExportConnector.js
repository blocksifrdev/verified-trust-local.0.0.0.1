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
exports.cyberarkExportConnector = cyberarkExportConnector;
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
function cyberarkExportConnector(fileOrDir) {
    const identities = [];
    const inflectionPoints = [];
    const content = readFileSafe(fileOrDir);
    if (!content)
        return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'cyberark' };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let records = [];
    try {
        const parsed = JSON.parse(content);
        records = Array.isArray(parsed) ? parsed : [parsed];
    }
    catch {
        records = parseCsv(content);
    }
    for (const record of records) {
        const name = record?.AccountName ?? record?.account_name ?? record?.name ?? 'unknown';
        const safe = record?.Safe ?? record?.safe ?? '';
        const platform = record?.Platform ?? record?.platform ?? '';
        const owner = record?.Owner ?? record?.owner ?? '';
        const target = record?.TargetMachine ?? record?.target_machine ?? '';
        const lastChanged = record?.LastPasswordChangeDate ?? record?.last_password_change ?? '';
        const status = record?.PasswordStatus ?? record?.status ?? '';
        const isStale = lastChanged ? (Date.now() - new Date(lastChanged).getTime()) / (1000 * 60 * 60 * 24) > 90 : false;
        const identity = (0, identity_1.createIdentity)({
            name,
            identityType: 'service_account',
            sourceSystem: 'cyberark',
            credentialTypes: ['managed_password'],
            riskTags: [...(isStale ? ['stale_password'] : []), ...(owner ? [] : ['no_owner'])],
            owner: owner || undefined,
            lastRotatedAt: lastChanged || undefined,
            metadata: { safe, platform, target, status, lastChanged },
        });
        identities.push(identity);
        if (isStale) {
            inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                type: 'CREDENTIAL_STALE',
                severity: 'MODERATE',
                identityId: identity.id,
                identityName: name,
                description: `CyberArk account "${name}" password last changed: ${lastChanged}`,
                recommendation: 'Verify rotation policy is active for this account in CyberArk.',
                metadata: { lastChanged, safe },
            }));
        }
        if (!owner) {
            inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                type: 'OWNER_MISSING',
                severity: 'MODERATE',
                identityId: identity.id,
                identityName: name,
                description: `CyberArk account "${name}" has no assigned owner`,
                recommendation: 'Assign an owner to all managed accounts in CyberArk.',
                metadata: { safe },
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
        sourceSystem: 'cyberark',
    };
}
//# sourceMappingURL=cyberarkExportConnector.js.map