"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.activateCommand = activateCommand;
const localLicense_1 = require("../../core/localLicense");
async function activateCommand(opts) {
    console.log('Activating VerifiedTrust license...');
    const result = (0, localLicense_1.activateLicense)(opts.license);
    console.log(`Edition: ${result.edition.toUpperCase()}`);
    console.log(`Activated: ${result.activatedAt ?? 'N/A'}`);
    if (result.edition === 'community') {
        console.log('');
        console.log('Note: This license key was accepted but server-side validation is not yet implemented.');
        console.log('Your edition remains Community until Pro activation is available.');
        console.log('Visit https://verifiedtrust.io to manage your license.');
    }
}
//# sourceMappingURL=activate.js.map