"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.COMMUNITY_NHI_LIMIT = void 0;
exports.applyEditionLimit = applyEditionLimit;
exports.COMMUNITY_NHI_LIMIT = 25;
function applyEditionLimit(items, edition) {
    const total = items.length;
    if (edition === 'community' && total > exports.COMMUNITY_NHI_LIMIT) {
        return {
            items: items.slice(0, exports.COMMUNITY_NHI_LIMIT),
            limited: true,
            total,
        };
    }
    return {
        items,
        limited: false,
        total,
    };
}
//# sourceMappingURL=limits.js.map