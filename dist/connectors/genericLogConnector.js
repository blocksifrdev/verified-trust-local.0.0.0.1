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
exports.genericLogConnector = genericLogConnector;
const fs = __importStar(require("fs"));
const identity_1 = require("../core/identity");
const executionPath_1 = require("../core/executionPath");
function readFileSafe(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf-8');
    }
    catch {
        return '';
    }
}
function parseCsv(content) {
    const lines = content.split('\n').filter((l) => l.trim());
    if (lines.length === 0)
        return [];
    const headers = lines[0].split(',').map((h) => h.trim().replace(/^"|"$/g, ''));
    return lines.slice(1).map((line) => {
        const values = line.split(',').map((v) => v.trim().replace(/^"|"$/g, ''));
        const record = {};
        headers.forEach((h, i) => { record[h] = values[i] ?? ''; });
        return record;
    });
}
function genericLogConnector(fileOrDir) {
    const identities = [];
    const executionPaths = [];
    const content = readFileSafe(fileOrDir);
    if (!content)
        return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'generic_log' };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let records = [];
    try {
        const parsed = JSON.parse(content);
        records = Array.isArray(parsed) ? parsed : [parsed];
    }
    catch {
        records = parseCsv(content);
    }
    const actorMap = new Map();
    for (const record of records) {
        const actor = record?.actor ?? record?.user ?? record?.identity ?? record?.source ?? '';
        const destination = record?.destination ?? record?.target ?? record?.resource ?? '';
        const action = record?.action ?? record?.event_type ?? record?.event ?? '';
        const timestamp = record?.timestamp ?? record?.time ?? record?.datetime ?? '';
        const result = record?.result ?? record?.outcome ?? '';
        if (!actor)
            continue;
        if (!actorMap.has(actor)) {
            const identity = (0, identity_1.createIdentity)({
                name: actor,
                identityType: 'unknown_nhi',
                sourceSystem: 'generic_log',
                credentialTypes: [],
                riskTags: [],
                lastUsedAt: timestamp || undefined,
            });
            identities.push(identity);
            actorMap.set(actor, identity);
        }
        const identity = actorMap.get(actor);
        if (action && destination) {
            executionPaths.push((0, executionPath_1.createExecutionPath)({
                identityId: identity.id,
                identityName: identity.name,
                trigger: action,
                targetEnvironment: destination,
                isProduction: /prod/i.test(destination),
                approvalDetected: false,
                evidenceDetected: !!result,
                trustBoundaryCrossed: false,
                steps: [action],
                sourceSystem: 'generic_log',
                metadata: { timestamp, result, sourceIp: record?.source_ip ?? '' },
            }));
        }
    }
    return {
        identities,
        edges: [],
        executionPaths,
        inflectionPoints: [],
        findings: [],
        evidenceRefs: [],
        sourceSystem: 'generic_log',
    };
}
//# sourceMappingURL=genericLogConnector.js.map