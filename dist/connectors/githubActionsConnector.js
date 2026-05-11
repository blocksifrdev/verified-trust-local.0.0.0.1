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
exports.githubActionsConnector = githubActionsConnector;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const yaml = __importStar(require("js-yaml"));
const identity_1 = require("../core/identity");
const executionPath_1 = require("../core/executionPath");
const inflectionPoint_1 = require("../core/inflectionPoint");
const finding_1 = require("../core/finding");
function readFileSafe(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf-8');
    }
    catch {
        return '';
    }
}
function isWorkflowFile(filePath) {
    const normalized = filePath.replace(/\\/g, '/');
    return (normalized.includes('/.github/workflows/') &&
        (normalized.endsWith('.yml') || normalized.endsWith('.yaml')));
}
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parseWorkflow(content) {
    try {
        return yaml.load(content) ?? {};
    }
    catch {
        return {};
    }
}
function detectSecrets(content) {
    const secrets = [];
    const secretRegex = /secrets\.([A-Za-z0-9_]+)/g;
    let match;
    while ((match = secretRegex.exec(content)) !== null) {
        if (!secrets.includes(match[1])) {
            secrets.push(match[1]);
        }
    }
    return secrets;
}
function githubActionsConnector(files, fileContents) {
    const identities = [];
    const executionPaths = [];
    const inflectionPoints = [];
    const findings = [];
    const workflowFiles = files.filter((f) => isWorkflowFile(f.path));
    for (const file of workflowFiles) {
        let content = fileContents.get(file.path);
        if (content === undefined) {
            content = readFileSafe(file.path);
            fileContents.set(file.path, content);
        }
        if (!content)
            continue;
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const workflow = parseWorkflow(content);
        const hasGithubToken = content.includes('GITHUB_TOKEN') || content.includes('github.token');
        const secrets = detectSecrets(content);
        const hasOidc = content.includes('id-token') && content.includes('write');
        const hasDependabot = content.includes('dependabot');
        const hasRenovate = content.includes('renovate');
        const hasDeployKey = content.includes('DEPLOY_KEY') || content.includes('deploy_key') || content.includes('SSH_KEY');
        // Detect bot/NHI identities
        if (hasGithubToken) {
            identities.push((0, identity_1.createIdentity)({
                name: 'GITHUB_TOKEN',
                identityType: 'github_app',
                sourceSystem: 'github_actions',
                sourceFile: file.path,
                credentialTypes: ['github_token'],
                riskTags: [],
                description: 'Automatic GITHUB_TOKEN for workflow authentication',
            }));
        }
        if (hasDeployKey) {
            identities.push((0, identity_1.createIdentity)({
                name: 'deploy-key',
                identityType: 'deploy_key',
                sourceSystem: 'github_actions',
                sourceFile: file.path,
                credentialTypes: ['ssh_key'],
                riskTags: ['deploy_key'],
            }));
        }
        if (hasDependabot) {
            identities.push((0, identity_1.createIdentity)({
                name: 'dependabot',
                identityType: 'bot_user',
                sourceSystem: 'github_actions',
                sourceFile: file.path,
                credentialTypes: [],
                riskTags: ['bot'],
            }));
        }
        if (hasRenovate) {
            identities.push((0, identity_1.createIdentity)({
                name: 'renovate',
                identityType: 'bot_user',
                sourceSystem: 'github_actions',
                sourceFile: file.path,
                credentialTypes: [],
                riskTags: ['bot'],
            }));
        }
        if (hasOidc) {
            identities.push((0, identity_1.createIdentity)({
                name: 'oidc-workload-identity',
                identityType: 'workload_identity',
                sourceSystem: 'github_actions',
                sourceFile: file.path,
                credentialTypes: ['oidc_token'],
                riskTags: ['oidc'],
            }));
        }
        // Detect execution paths by inspecting jobs
        const jobs = (workflow && typeof workflow === 'object' && workflow['jobs']) ? workflow['jobs'] : {};
        for (const [jobName, jobDef] of Object.entries(jobs)) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            const job = jobDef;
            const environment = job?.environment;
            const envName = typeof environment === 'string' ? environment : (environment?.name ?? '');
            const isProduction = /prod/i.test(envName) || /production/i.test(envName);
            const hasApproval = environment && typeof environment === 'object' && environment['url'];
            const epIdentity = identities[0] ?? (0, identity_1.createIdentity)({
                name: path.basename(file.path),
                identityType: 'ci_cd_runner',
                sourceSystem: 'github_actions',
                sourceFile: file.path,
                credentialTypes: [],
                riskTags: [],
            });
            executionPaths.push((0, executionPath_1.createExecutionPath)({
                identityId: epIdentity.id,
                identityName: epIdentity.name,
                trigger: JSON.stringify(workflow['on'] ?? 'unknown'),
                targetEnvironment: envName || 'unspecified',
                isProduction,
                approvalDetected: !!hasApproval,
                evidenceDetected: false,
                trustBoundaryCrossed: isProduction,
                steps: Array.isArray(job?.steps) ? job.steps.map((s) => s?.name ?? 'step') : [],
                sourceFile: file.path,
                sourceSystem: 'github_actions',
                metadata: { jobName },
            }));
            if (isProduction && !hasApproval) {
                inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                    type: 'APPROVAL_BYPASS',
                    severity: 'HIGH',
                    identityName: epIdentity.name,
                    description: `Job "${jobName}" deploys to production environment "${envName}" without detected approval gate in ${path.basename(file.path)}`,
                    recommendation: 'Add environment protection rules with required reviewers for production deployments.',
                    sourceFile: file.path,
                    metadata: { jobName, environment: envName },
                }));
            }
        }
        // Check permissions
        const permissions = workflow?.permissions;
        if (permissions && typeof permissions === 'object') {
            const permStr = JSON.stringify(permissions);
            if (permStr.includes('write-all') || permStr.includes('"write"')) {
                findings.push((0, finding_1.createFinding)({
                    severity: 'MODERATE',
                    title: 'Broad workflow permissions detected',
                    description: `Workflow ${path.basename(file.path)} has write permissions configured.`,
                    recommendation: 'Apply least-privilege permissions per job. Avoid write-all at workflow level.',
                    sourceFile: file.path,
                    sourceSystem: 'github_actions',
                    inflectionType: 'PRIVILEGE_ESCALATION_PATH',
                    evidenceRefs: [],
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
        sourceSystem: 'github_actions',
    };
}
//# sourceMappingURL=githubActionsConnector.js.map