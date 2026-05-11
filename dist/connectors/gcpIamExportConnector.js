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
exports.gcpIamExportConnector = gcpIamExportConnector;
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
function gcpIamExportConnector(fileOrDir) {
    const identities = [];
    const inflectionPoints = [];
    const content = readFileSafe(fileOrDir);
    if (!content)
        return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'gcp_iam' };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let data = {};
    try {
        data = JSON.parse(content);
    }
    catch {
        return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'gcp_iam' };
    }
    // Parse IAM policy bindings format (gcloud projects get-iam-policy)
    const bindings = data?.bindings ?? [];
    const saIdentities = new Map();
    for (const binding of bindings) {
        const role = binding?.role ?? 'unknown';
        const members = binding?.members ?? [];
        const isAdmin = role.includes('roles/owner') || role.includes('roles/editor');
        for (const member of members) {
            if (!member.includes('@') || !member.includes('iam.gserviceaccount.com'))
                continue;
            const email = member.replace(/^serviceAccount:/, '');
            if (!saIdentities.has(email)) {
                const identity = (0, identity_1.createIdentity)({
                    name: email,
                    identityType: 'gcp_service_account',
                    sourceSystem: 'gcp_iam',
                    credentialTypes: ['service_account_key'],
                    riskTags: isAdmin ? ['admin'] : [],
                    permissions: [role],
                    metadata: { email, projectId: data?.name ?? data?.projectId },
                });
                identities.push(identity);
                saIdentities.set(email, identity);
            }
            else {
                const existing = saIdentities.get(email);
                if (!existing.permissions.includes(role))
                    existing.permissions.push(role);
                if (isAdmin && !existing.riskTags.includes('admin'))
                    existing.riskTags.push('admin');
            }
            const identity = saIdentities.get(email);
            if (isAdmin) {
                inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                    type: 'ADMIN_ROLE_ASSIGNED',
                    severity: 'HIGH',
                    identityId: identity.id,
                    identityName: email,
                    description: `GCP service account "${email}" has ${role}`,
                    recommendation: 'Replace owner/editor roles with least-privilege custom roles.',
                    metadata: { role },
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
        sourceSystem: 'gcp_iam',
    };
}
//# sourceMappingURL=gcpIamExportConnector.js.map