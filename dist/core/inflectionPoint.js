"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createInflectionPoint = createInflectionPoint;
const id_1 = require("./id");
function createInflectionPoint(partial) {
    return {
        ...partial,
        id: partial.id ?? (0, id_1.createId)(),
        type: partial.type,
        severity: partial.severity,
        identityId: partial.identityId,
        identityName: partial.identityName,
        executionPathId: partial.executionPathId,
        edgeId: partial.edgeId,
        description: partial.description,
        recommendation: partial.recommendation,
        sourceFile: partial.sourceFile,
        detectedAt: partial.detectedAt ?? new Date().toISOString(),
        metadata: partial.metadata ?? {},
    };
}
//# sourceMappingURL=inflectionPoint.js.map