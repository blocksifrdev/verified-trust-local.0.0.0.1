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
exports.entraExportConnector = entraExportConnector;
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
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function inferType(sp) {
    const spType = (sp?.servicePrincipalType ?? sp?.type ?? '').toLowerCase();
    if (spType === 'managedidentity')
        return 'managed_identity';
    if (sp?.appId && sp?.servicePrincipalType)
        return 'service_principal';
    if (sp?.appId)
        return 'azure_app_registration';
    return 'service_principal';
}
function entraExportConnector(fileOrDir) {
    const identities = [];
    const inflectionPoints = [];
    let content = '';
    try {
        const stat = fs.statSync(fileOrDir);
        if (stat.isDirectory()) {
            const files = fs.readdirSync(fileOrDir).filter((f) => f.endsWith('.json'));
            for (const f of files) {
                content += readFileSafe(`${fileOrDir}/${f}`) + '\n';
            }
        }
        else {
            content = readFileSafe(fileOrDir);
        }
    }
    catch {
        return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'entra' };
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let data = [];
    try {
        const parsed = JSON.parse(content);
        data = Array.isArray(parsed) ? parsed : (parsed?.value ?? [parsed]);
    }
    catch {
        return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'entra' };
    }
    for (const sp of data) {
        if (!sp || typeof sp !== 'object')
            continue;
        const displayName = sp?.displayName ?? sp?.display_name ?? 'unknown-entra-identity';
        const identityType = inferType(sp);
        const owners = sp?.owners ?? [];
        const hasOwner = Array.isArray(owners) ? owners.length > 0 : !!owners;
        const lastSignIn = sp?.signInActivity?.lastSignInDateTime ?? sp?.lastSignInDateTime;
        const createdAt = sp?.createdDateTime ?? sp?.created_at;
        const identity = (0, identity_1.createIdentity)({
            name: displayName,
            identityType,
            sourceSystem: 'entra',
            credentialTypes: sp?.passwordCredentials?.length > 0 ? ['client_secret'] :
                sp?.keyCredentials?.length > 0 ? ['certificate'] : [],
            riskTags: hasOwner ? [] : ['no_owner'],
            permissions: (sp?.appRoles ?? []).map((r) => r?.value ?? ''),
            owner: hasOwner ? (Array.isArray(owners) ? owners[0]?.displayName : owners) : undefined,
            lastUsedAt: lastSignIn,
            createdAt,
            metadata: {
                appId: sp?.appId,
                objectId: sp?.id ?? sp?.objectId,
                servicePrincipalType: sp?.servicePrincipalType,
                federatedCredentials: sp?.federatedIdentityCredentials ?? [],
            },
        });
        identities.push(identity);
        if (!hasOwner) {
            inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                type: 'OWNER_MISSING',
                severity: 'MODERATE',
                identityId: identity.id,
                identityName: identity.name,
                description: `Entra identity "${displayName}" has no assigned owner`,
                recommendation: 'Assign an owner to all service principals and app registrations.',
                metadata: {},
            }));
        }
        if (lastSignIn) {
            const daysSinceUse = (Date.now() - new Date(lastSignIn).getTime()) / (1000 * 60 * 60 * 24);
            if (daysSinceUse > 90) {
                inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                    type: 'LAST_USED_STALE',
                    severity: 'LOW',
                    identityId: identity.id,
                    identityName: identity.name,
                    description: `Entra identity "${displayName}" last signed in ${Math.round(daysSinceUse)} days ago`,
                    recommendation: 'Review whether this identity is still needed. Disable or delete if unused.',
                    metadata: { lastSignIn, daysSinceUse: Math.round(daysSinceUse) },
                }));
            }
        }
    }
    return {
        identities,
        edges: [],
        executionPaths: [],
        inflectionPoints,
        findings: [],
        evidenceRefs: [],
        sourceSystem: 'entra',
    };
}
//# sourceMappingURL=entraExportConnector.js.map