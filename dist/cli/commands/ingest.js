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
exports.ingestCommand = ingestCommand;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const entraExportConnector_1 = require("../../connectors/entraExportConnector");
const oktaExportConnector_1 = require("../../connectors/oktaExportConnector");
const awsIamExportConnector_1 = require("../../connectors/awsIamExportConnector");
const azureIamExportConnector_1 = require("../../connectors/azureIamExportConnector");
const gcpIamExportConnector_1 = require("../../connectors/gcpIamExportConnector");
const cyberarkExportConnector_1 = require("../../connectors/cyberarkExportConnector");
const beyondTrustExportConnector_1 = require("../../connectors/beyondTrustExportConnector");
const delineaExportConnector_1 = require("../../connectors/delineaExportConnector");
const vaultExportConnector_1 = require("../../connectors/vaultExportConnector");
const genericCsvConnector_1 = require("../../connectors/genericCsvConnector");
const genericLogConnector_1 = require("../../connectors/genericLogConnector");
const CONNECTORS = {
    entra: entraExportConnector_1.entraExportConnector,
    okta: oktaExportConnector_1.oktaExportConnector,
    aws: awsIamExportConnector_1.awsIamExportConnector,
    azure: azureIamExportConnector_1.azureIamExportConnector,
    gcp: gcpIamExportConnector_1.gcpIamExportConnector,
    cyberark: cyberarkExportConnector_1.cyberarkExportConnector,
    beyondtrust: beyondTrustExportConnector_1.beyondTrustExportConnector,
    delinea: delineaExportConnector_1.delineaExportConnector,
    vault: vaultExportConnector_1.vaultExportConnector,
    csv: genericCsvConnector_1.genericCsvConnector,
    log: genericLogConnector_1.genericLogConnector,
};
async function ingestCommand(source, fileOrDir, opts) {
    const connector = CONNECTORS[source.toLowerCase()];
    if (!connector) {
        console.error(`Unknown source: "${source}". Supported: ${Object.keys(CONNECTORS).join(', ')}`);
        process.exit(1);
    }
    console.log(`Ingesting ${source} data from ${fileOrDir}...`);
    const result = connector(fileOrDir);
    console.log(`Found ${result.identities.length} identities, ${result.findings.length} findings.`);
    fs.mkdirSync(opts.out, { recursive: true });
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const outFile = path.join(opts.out, `${source}-${timestamp}.json`);
    fs.writeFileSync(outFile, JSON.stringify(result, null, 2), 'utf-8');
    console.log(`Saved to: ${outFile}`);
}
//# sourceMappingURL=ingest.js.map