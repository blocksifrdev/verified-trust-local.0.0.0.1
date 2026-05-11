"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.createId = createId;
const node_crypto_1 = require("node:crypto");
function createId() {
    return (0, node_crypto_1.randomUUID)();
}
//# sourceMappingURL=id.js.map