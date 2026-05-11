"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createFinding = createFinding;
const id_1 = require("./id");
function createFinding(partial) {
    return {
        ...partial,
        id: partial.id ?? (0, id_1.createId)(),
        severity: partial.severity ?? 'MODERATE',
        title: partial.title,
        description: partial.description,
        recommendation: partial.recommendation,
        identityId: partial.identityId,
        identityName: partial.identityName,
        sourceFile: partial.sourceFile,
        sourceSystem: partial.sourceSystem,
        inflectionType: partial.inflectionType,
        evidenceRefs: partial.evidenceRefs ?? [],
        detectedAt: partial.detectedAt ?? new Date().toISOString(),
        metadata: partial.metadata ?? {},
    };
}
//# sourceMappingURL=finding.js.map