"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UPGRADE_MESSAGE = void 0;
exports.getEdition = getEdition;
const localLicense_1 = require("./localLicense");
exports.UPGRADE_MESSAGE = 'VerifiedTrust Local detected more non-human identity exposure than Community Edition includes. ' +
    'Community Edition includes detailed analysis for the first 25 NHIs. ' +
    'Upgrade to VerifiedTrust Pro to unlock full identity inventory, executive PDF reports, SARIF export, ' +
    'signed evidence, policy packs, and FrontDesk integration.';
function getEdition() {
    const envEdition = process.env['VT_EDITION'];
    if (envEdition && isValidEdition(envEdition)) {
        return envEdition;
    }
    try {
        const license = (0, localLicense_1.loadLicense)();
        return license.edition;
    }
    catch {
        return 'community';
    }
}
function isValidEdition(value) {
    return ['community', 'pro', 'business', 'enterprise'].includes(value);
}
//# sourceMappingURL=edition.js.map