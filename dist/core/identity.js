"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeIdentityName = normalizeIdentityName;
exports.createIdentity = createIdentity;
const id_1 = require("./id");
function normalizeIdentityName(name) {
    return name.toLowerCase().trim().replace(/\s+/g, ' ');
}
function createIdentity(partial) {
    const normalized = normalizeIdentityName(partial.name);
    return {
        ...partial,
        id: partial.id ?? (0, id_1.createId)(),
        name: partial.name,
        normalizedName: normalized,
        identityType: partial.identityType,
        sourceSystem: partial.sourceSystem,
        environment: partial.environment,
        owner: partial.owner,
        team: partial.team,
        createdAt: partial.createdAt,
        lastUsedAt: partial.lastUsedAt,
        lastRotatedAt: partial.lastRotatedAt,
        credentialTypes: partial.credentialTypes ?? [],
        permissions: partial.permissions ?? [],
        riskTags: partial.riskTags ?? [],
        evidenceRefs: partial.evidenceRefs ?? [],
        metadata: partial.metadata ?? {},
        sourceFile: partial.sourceFile,
        description: partial.description,
    };
}
//# sourceMappingURL=identity.js.map