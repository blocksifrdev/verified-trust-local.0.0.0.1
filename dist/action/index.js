"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const scan_1 = require("../cli/commands/scan");
function getInput(name, fallback) {
    const envName = `INPUT_${name.toUpperCase().replace(/-/g, '_')}`;
    const legacyEnvName = `INPUT_${name.toUpperCase()}`;
    return (process.env[envName] ?? process.env[legacyEnvName] ?? fallback).trim();
}
async function main() {
    const scanPath = getInput('scan-path', '.');
    const out = getInput('output-dir', 'verifiedtrust-report');
    const edition = getInput('edition', 'community');
    await (0, scan_1.scanCommand)(scanPath, { out, edition });
}
main().catch((err) => {
    console.error('VerifiedTrust Action failed:', err instanceof Error ? err.message : String(err));
    process.exit(1);
});
//# sourceMappingURL=index.js.map