"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getPrivilegedIdentities = getPrivilegedIdentities;
exports.getOrphanedIdentities = getOrphanedIdentities;
exports.getHighRiskPaths = getHighRiskPaths;
exports.getIdentitiesByType = getIdentitiesByType;
exports.getCriticalFindings = getCriticalFindings;
function getPrivilegedIdentities(graph) {
    const privilegedIds = new Set();
    // Identities connected by admin/wildcard edges
    for (const edge of graph.edges) {
        if (edge.isAdmin || edge.isWildcard) {
            privilegedIds.add(edge.fromIdentityId);
            privilegedIds.add(edge.toIdentityId);
        }
    }
    // Identities with admin permission tags
    const result = [];
    for (const identity of graph.identities.values()) {
        if (privilegedIds.has(identity.id) ||
            identity.permissions.some((p) => p.includes('*') || p.toLowerCase().includes('admin') || p.toLowerCase().includes('owner')) ||
            identity.riskTags.includes('admin') ||
            identity.riskTags.includes('wildcard')) {
            result.push(identity);
        }
    }
    return result;
}
function getOrphanedIdentities(graph) {
    return Array.from(graph.identities.values()).filter((i) => !i.owner);
}
function getHighRiskPaths(graph) {
    return graph.executionPaths.filter((ep) => ep.isProduction && (!ep.approvalDetected || ep.trustBoundaryCrossed));
}
function getIdentitiesByType(graph, type) {
    return Array.from(graph.identities.values()).filter((i) => i.identityType === type);
}
function getCriticalFindings(graph) {
    return graph.findings.filter((f) => f.severity === 'CRITICAL' || f.severity === 'HIGH');
}
//# sourceMappingURL=graphQueries.js.map