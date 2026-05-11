"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createAuthorityEdge = createAuthorityEdge;
const id_1 = require("./id");
function createAuthorityEdge(partial) {
    return {
        ...partial,
        id: partial.id ?? (0, id_1.createId)(),
        fromIdentityId: partial.fromIdentityId,
        toIdentityId: partial.toIdentityId,
        relation: partial.relation,
        permissions: partial.permissions ?? [],
        isWildcard: partial.isWildcard ?? false,
        isAdmin: partial.isAdmin ?? false,
        scope: partial.scope,
        sourceSystem: partial.sourceSystem,
        sourceFile: partial.sourceFile,
        metadata: partial.metadata ?? {},
    };
}
//# sourceMappingURL=authorityEdge.js.map