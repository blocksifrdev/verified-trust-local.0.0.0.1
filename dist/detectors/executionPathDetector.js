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
exports.detectExecutionPaths = detectExecutionPaths;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const yaml = __importStar(require("js-yaml"));
const executionPath_1 = require("../core/executionPath");
function readFileSafe(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf-8');
    }
    catch {
        return '';
    }
}
const PROD_PATTERNS = [/\bprod(?:uction)?\b/i, /\blive\b/i, /\brelease\b/i, /\bstaging\b/i];
function isProductionTarget(target) {
    return PROD_PATTERNS.some((p) => p.test(target));
}
function detectTrustBoundaryCrossing(sourceFile, targetEnv) {
    // Simple heuristic: if source is a CI file and target mentions cloud or prod
    const isCI = /workflow|pipeline|jenkins|gitlab-ci/i.test(sourceFile);
    return isCI && isProductionTarget(targetEnv);
}
function detectExecutionPaths(identities, files, fileContents) {
    const paths = [];
    // Look at CI/CD files and IaC for execution paths
    for (const file of files) {
        let content = fileContents.get(file.path);
        if (content === undefined) {
            content = readFileSafe(file.path);
            fileContents.set(file.path, content);
        }
        if (!content)
            continue;
        const ext = path.extname(file.path).toLowerCase();
        const name = path.basename(file.path).toLowerCase();
        // GitHub Actions
        if (name.endsWith('.yml') || name.endsWith('.yaml')) {
            let workflow = {};
            try {
                workflow = yaml.load(content) ?? {};
            }
            catch {
                continue;
            }
            const on = workflow['on'];
            const trigger = on ? JSON.stringify(on) : 'unknown';
            const jobs = workflow['jobs'] ?? {};
            for (const [jobName, jobDef] of Object.entries(jobs)) {
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                const job = jobDef;
                const environment = job?.environment;
                const envName = typeof environment === 'string' ? environment : (environment?.name ?? '');
                const isProduction = envName ? isProductionTarget(envName) : false;
                const hasApproval = environment && typeof environment === 'object';
                // Find matching identity (prefer CI runner identity)
                const identity = identities.find((i) => i.sourceSystem === 'github_actions' || i.identityType === 'ci_cd_runner' || i.identityType === 'github_app') ?? identities[0];
                if (!identity)
                    continue;
                paths.push((0, executionPath_1.createExecutionPath)({
                    identityId: identity.id,
                    identityName: identity.name,
                    trigger,
                    targetEnvironment: envName || 'unspecified',
                    isProduction,
                    approvalDetected: !!hasApproval,
                    evidenceDetected: false,
                    trustBoundaryCrossed: detectTrustBoundaryCrossing(file.path, envName),
                    steps: Array.isArray(job?.steps) ? job.steps.map((s) => s?.name ?? 'step') : [],
                    sourceFile: file.path,
                    sourceSystem: 'github_actions',
                    metadata: { jobName },
                }));
            }
        }
        // Terraform files — detect deployment targets
        if (ext === '.tf') {
            const regionMatches = content.match(/region\s*=\s*"([^"]+)"/g) ?? [];
            for (const regionMatch of regionMatches) {
                const region = regionMatch.match(/"([^"]+)"/)?.[1] ?? 'unknown';
                const identity = identities.find((i) => i.sourceSystem === 'terraform') ?? identities[0];
                if (!identity)
                    continue;
                paths.push((0, executionPath_1.createExecutionPath)({
                    identityId: identity.id,
                    identityName: identity.name,
                    trigger: 'terraform apply',
                    targetEnvironment: region,
                    isProduction: isProductionTarget(region) || content.includes('prod'),
                    approvalDetected: content.includes('prevent_destroy') || content.includes('lifecycle'),
                    evidenceDetected: false,
                    trustBoundaryCrossed: true, // Terraform always crosses trust boundaries
                    steps: ['terraform plan', 'terraform apply'],
                    sourceFile: file.path,
                    sourceSystem: 'terraform',
                    metadata: { region },
                }));
            }
        }
    }
    return paths;
}
//# sourceMappingURL=executionPathDetector.js.map