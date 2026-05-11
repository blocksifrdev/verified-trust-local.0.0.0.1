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
exports.azureDevOpsConnector = azureDevOpsConnector;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const yaml = __importStar(require("js-yaml"));
const identity_1 = require("../core/identity");
const executionPath_1 = require("../core/executionPath");
const inflectionPoint_1 = require("../core/inflectionPoint");
function readFileSafe(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf-8');
    }
    catch {
        return '';
    }
}
function isAzurePipeline(filePath) {
    const name = path.basename(filePath).toLowerCase();
    return name === 'azure-pipelines.yml' || name === 'azure-pipelines.yaml';
}
function azureDevOpsConnector(files, fileContents) {
    const identities = [];
    const executionPaths = [];
    const inflectionPoints = [];
    const findings = [];
    const pipelineFiles = files.filter((f) => isAzurePipeline(f.path));
    for (const file of pipelineFiles) {
        let content = fileContents.get(file.path);
        if (content === undefined) {
            content = readFileSafe(file.path);
            fileContents.set(file.path, content);
        }
        if (!content)
            continue;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        let pipeline = {};
        try {
            pipeline = yaml.load(content) ?? {};
        }
        catch {
            continue;
        }
        // Detect service connections
        const serviceConnectionMatches = content.match(/serviceConnection:\s*['"]?([^'"\n]+)/g) ?? [];
        for (const match of serviceConnectionMatches) {
            const name = match.replace(/serviceConnection:\s*['"]?/, '').replace(/['"]/, '').trim();
            identities.push((0, identity_1.createIdentity)({
                name: `azure-service-connection:${name}`,
                identityType: 'service_principal',
                sourceSystem: 'azure_devops',
                sourceFile: file.path,
                credentialTypes: ['service_connection'],
                riskTags: [],
            }));
        }
        // Detect secret variables
        if (content.includes('$(') && (content.toLowerCase().includes('secret') || content.toLowerCase().includes('password'))) {
            identities.push((0, identity_1.createIdentity)({
                name: 'azure-devops-pipeline-secrets',
                identityType: 'api_token',
                sourceSystem: 'azure_devops',
                sourceFile: file.path,
                credentialTypes: ['pipeline_secret'],
                riskTags: ['secret_in_pipeline'],
            }));
        }
        // Detect deployment stages/environments
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const stages = pipeline?.stages ?? [];
        for (const stage of stages) {
            const envName = stage?.environment ?? stage?.displayName ?? 'unknown';
            const isProduction = /prod/i.test(String(envName));
            const hasApproval = !!stage?.approval;
            const stageIdentity = identities[0] ?? (0, identity_1.createIdentity)({
                name: 'azure-devops-runner',
                identityType: 'ci_cd_runner',
                sourceSystem: 'azure_devops',
                sourceFile: file.path,
                credentialTypes: [],
                riskTags: [],
            });
            executionPaths.push((0, executionPath_1.createExecutionPath)({
                identityId: stageIdentity.id,
                identityName: stageIdentity.name,
                trigger: 'azure-pipeline',
                targetEnvironment: String(envName),
                isProduction,
                approvalDetected: hasApproval,
                evidenceDetected: false,
                trustBoundaryCrossed: isProduction,
                steps: [],
                sourceFile: file.path,
                sourceSystem: 'azure_devops',
                metadata: { stage: stage?.stage ?? stage?.displayName },
            }));
            if (isProduction && !hasApproval) {
                inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                    type: 'APPROVAL_BYPASS',
                    severity: 'HIGH',
                    description: `Azure DevOps stage deploys to production without approval gate`,
                    recommendation: 'Add environment approval checks for production stages.',
                    sourceFile: file.path,
                    metadata: {},
                }));
            }
        }
    }
    return {
        identities,
        edges: [],
        executionPaths,
        inflectionPoints,
        findings,
        evidenceRefs: [],
        sourceSystem: 'azure_devops',
    };
}
//# sourceMappingURL=azureDevOpsConnector.js.map