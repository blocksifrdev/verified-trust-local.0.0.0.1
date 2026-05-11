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
exports.jenkinsConnector = jenkinsConnector;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
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
function isJenkinsFile(filePath) {
    const name = path.basename(filePath);
    return name === 'Jenkinsfile' || name.endsWith('.jenkinsfile') || name.endsWith('.Jenkinsfile');
}
function jenkinsConnector(files, fileContents) {
    const identities = [];
    const executionPaths = [];
    const inflectionPoints = [];
    const findings = [];
    const jenkinsFiles = files.filter((f) => isJenkinsFile(f.path));
    for (const file of jenkinsFiles) {
        let content = fileContents.get(file.path);
        if (content === undefined) {
            content = readFileSafe(file.path);
            fileContents.set(file.path, content);
        }
        if (!content)
            continue;
        // Detect credentials() usage
        const credMatches = content.match(/credentials\(['"]([^'"]+)['"]\)/g) ?? [];
        for (const match of credMatches) {
            const credId = match.match(/credentials\(['"]([^'"]+)['"]\)/)?.[1] ?? 'unknown';
            identities.push((0, identity_1.createIdentity)({
                name: `jenkins-credential:${credId}`,
                identityType: 'api_token',
                sourceSystem: 'jenkins',
                sourceFile: file.path,
                credentialTypes: ['jenkins_credential'],
                riskTags: [],
                metadata: { credentialId: credId },
            }));
        }
        // withCredentials blocks
        if (content.includes('withCredentials')) {
            identities.push((0, identity_1.createIdentity)({
                name: 'jenkins-withCredentials',
                identityType: 'api_token',
                sourceSystem: 'jenkins',
                sourceFile: file.path,
                credentialTypes: ['jenkins_credential'],
                riskTags: [],
            }));
        }
        // Deployment stages
        const stageMatches = content.match(/stage\(['"]([^'"]+)['"]\)/g) ?? [];
        for (const stageMatch of stageMatches) {
            const stageName = stageMatch.match(/stage\(['"]([^'"]+)['"]\)/)?.[1] ?? '';
            const isProduction = /prod|production|deploy/i.test(stageName);
            if (isProduction) {
                const identity = identities[0] ?? (0, identity_1.createIdentity)({
                    name: 'jenkins-runner',
                    identityType: 'ci_cd_runner',
                    sourceSystem: 'jenkins',
                    sourceFile: file.path,
                    credentialTypes: [],
                    riskTags: [],
                });
                executionPaths.push((0, executionPath_1.createExecutionPath)({
                    identityId: identity.id,
                    identityName: identity.name,
                    trigger: 'jenkinsfile',
                    targetEnvironment: stageName,
                    isProduction: true,
                    approvalDetected: content.includes('input') && content.indexOf('input') < content.indexOf(stageName),
                    evidenceDetected: false,
                    trustBoundaryCrossed: true,
                    steps: [stageName],
                    sourceFile: file.path,
                    sourceSystem: 'jenkins',
                    metadata: { stageName },
                }));
                if (!content.includes('input')) {
                    inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                        type: 'APPROVAL_BYPASS',
                        severity: 'HIGH',
                        description: `Jenkins stage "${stageName}" deploys without manual approval (input step)`,
                        recommendation: 'Add an input step before production deployment stages.',
                        sourceFile: file.path,
                        metadata: { stageName },
                    }));
                }
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
        sourceSystem: 'jenkins',
    };
}
//# sourceMappingURL=jenkinsConnector.js.map