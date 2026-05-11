"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeIdentities = normalizeIdentities;
const identity_1 = require("./identity");
function normalizeIdentities(identities) {
    const map = new Map();
    for (const identity of identities) {
        const key = `${(0, identity_1.normalizeIdentityName)(identity.name)}::${identity.sourceSystem}`;
        const existing = map.get(key);
        if (!existing) {
            map.set(key, { ...identity });
        }
        else {
            // Merge credentialTypes
            const mergedCreds = Array.from(new Set([...existing.credentialTypes, ...identity.credentialTypes]));
            // Merge riskTags
            const mergedTags = Array.from(new Set([...existing.riskTags, ...identity.riskTags]));
            // Merge evidenceRefs
            const mergedEvidenceRefs = Array.from(new Set([...existing.evidenceRefs, ...identity.evidenceRefs]));
            // Merge permissions
            const mergedPermissions = Array.from(new Set([...existing.permissions, ...identity.permissions]));
            map.set(key, {
                ...existing,
                credentialTypes: mergedCreds,
                riskTags: mergedTags,
                evidenceRefs: mergedEvidenceRefs,
                permissions: mergedPermissions,
                // Prefer non-null values for optional fields
                owner: existing.owner ?? identity.owner,
                team: existing.team ?? identity.team,
                environment: existing.environment ?? identity.environment,
                lastUsedAt: existing.lastUsedAt ?? identity.lastUsedAt,
                createdAt: existing.createdAt ?? identity.createdAt,
                metadata: { ...existing.metadata, ...identity.metadata },
            });
        }
    }
    return Array.from(map.values());
}
//# sourceMappingURL=normalization.js.map