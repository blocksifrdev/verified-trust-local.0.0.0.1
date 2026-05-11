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
exports.gitlabCiConnector = gitlabCiConnector;
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
function isGitlabCi(filePath) {
    return path.basename(filePath) === '.gitlab-ci.yml' || path.basename(filePath) === '.gitlab-ci.yaml';
}
function gitlabCiConnector(files, fileContents) {
    const identities = [];
    const executionPaths = [];
    const inflectionPoints = [];
    const findings = [];
    const ciFiles = files.filter((f) => isGitlabCi(f.path));
    for (const file of ciFiles) {
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
        // CI_JOB_TOKEN usage
        if (content.includes('CI_JOB_TOKEN')) {
            identities.push((0, identity_1.createIdentity)({
                name: 'CI_JOB_TOKEN',
                identityType: 'api_token',
                sourceSystem: 'gitlab_ci',
                sourceFile: file.path,
                credentialTypes: ['ci_job_token'],
                riskTags: [],
            }));
        }
        // Service accounts in variables
        const variables = pipeline?.variables ?? {};
        for (const [key, val] of Object.entries(variables)) {
            if (/service|account|token|secret/i.test(key)) {
                identities.push((0, identity_1.createIdentity)({
                    name: `gitlab-var:${key}`,
                    identityType: 'api_token',
                    sourceSystem: 'gitlab_ci',
                    sourceFile: file.path,
                    credentialTypes: ['pipeline_variable'],
                    riskTags: [],
                    metadata: { value: String(val).slice(0, 20) },
                }));
            }
        }
        // Detect deploy stages
        for (const [jobName, jobDef] of Object.entries(pipeline)) {
            if (jobName.startsWith('.') || jobName === 'variables' || jobName === 'stages' || jobName === 'image')
                continue;
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const job = jobDef;
            const stage = job?.stage ?? '';
            const envName = job?.environment?.name ?? job?.environment ?? '';
            const isProduction = /prod/i.test(stage) || /prod/i.test(String(envName));
            const hasApproval = !!job?.when && job?.when === 'manual';
            const identity = identities[0] ?? (0, identity_1.createIdentity)({
                name: 'gitlab-runner',
                identityType: 'ci_cd_runner',
                sourceSystem: 'gitlab_ci',
                sourceFile: file.path,
                credentialTypes: [],
                riskTags: [],
            });
            if (stage && (stage === 'deploy' || /deploy|release/i.test(stage))) {
                executionPaths.push((0, executionPath_1.createExecutionPath)({
                    identityId: identity.id,
                    identityName: identity.name,
                    trigger: 'gitlab-ci',
                    targetEnvironment: String(envName) || stage,
                    isProduction,
                    approvalDetected: hasApproval,
                    evidenceDetected: false,
                    trustBoundaryCrossed: isProduction,
                    steps: [],
                    sourceFile: file.path,
                    sourceSystem: 'gitlab_ci',
                    metadata: { jobName, stage },
                }));
                if (isProduction && !hasApproval) {
                    inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                        type: 'APPROVAL_BYPASS',
                        severity: 'HIGH',
                        description: `GitLab CI job "${jobName}" deploys to production without manual approval`,
                        recommendation: 'Add when: manual and protected environment approvals for production deployments.',
                        sourceFile: file.path,
                        metadata: { jobName },
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
        sourceSystem: 'gitlab_ci',
    };
}
//# sourceMappingURL=gitlabCiConnector.js.map