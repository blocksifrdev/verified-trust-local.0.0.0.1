"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createEvidenceRef = createEvidenceRef;
const id_1 = require("./id");
function createEvidenceRef(partial) {
    return {
        ...partial,
        id: partial.id ?? (0, id_1.createId)(),
        type: partial.type,
        path: partial.path,
        url: partial.url,
        content: partial.content,
        detectedAt: partial.detectedAt ?? new Date().toISOString(),
        present: partial.present,
        description: partial.description,
    };
}
//# sourceMappingURL=evidenceRef.js.map