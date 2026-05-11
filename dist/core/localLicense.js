"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.loadLicense = loadLicense;
exports.activateLicense = activateLicense;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const os = __importStar(require("os"));
function getLicensePath() {
    return path.join(os.homedir(), '.verifiedtrust', 'license.json');
}
function loadLicense() {
    const licensePath = getLicensePath();
    try {
        if (fs.existsSync(licensePath)) {
            const raw = fs.readFileSync(licensePath, 'utf-8');
            const parsed = JSON.parse(raw);
            return parsed;
        }
    }
    catch {
        // Fall through to community
    }
    return { edition: 'community' };
}
function activateLicense(key) {
    // Stub: always returns community for now with a note
    const info = {
        edition: 'community',
        licenseKey: key,
        activatedAt: new Date().toISOString(),
    };
    const licenseDir = path.join(os.homedir(), '.verifiedtrust');
    try {
        fs.mkdirSync(licenseDir, { recursive: true });
        fs.writeFileSync(getLicensePath(), JSON.stringify(info, null, 2), 'utf-8');
    }
    catch {
        // Ignore write errors
    }
    console.log('Note: License validation requires VerifiedTrust Pro server. ' +
        'This is a stub — edition remains community until server-side activation is implemented.');
    return info;
}
//# sourceMappingURL=localLicense.js.map