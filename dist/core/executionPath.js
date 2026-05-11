"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createExecutionPath = createExecutionPath;
const id_1 = require("./id");
function createExecutionPath(partial) {
    return {
        ...partial,
        id: partial.id ?? (0, id_1.createId)(),
        identityId: partial.identityId,
        identityName: partial.identityName,
        trigger: partial.trigger,
        targetEnvironment: partial.targetEnvironment,
        isProduction: partial.isProduction ?? false,
        approvalDetected: partial.approvalDetected ?? false,
        evidenceDetected: partial.evidenceDetected ?? false,
        trustBoundaryCrossed: partial.trustBoundaryCrossed ?? false,
        steps: partial.steps ?? [],
        sourceFile: partial.sourceFile,
        sourceSystem: partial.sourceSystem,
        metadata: partial.metadata ?? {},
    };
}
//# sourceMappingURL=executionPath.js.map