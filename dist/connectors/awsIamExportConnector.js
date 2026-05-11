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
exports.awsIamExportConnector = awsIamExportConnector;
const fs = __importStar(require("fs"));
const identity_1 = require("../core/identity");
const inflectionPoint_1 = require("../core/inflectionPoint");
function readFileSafe(filePath) {
    try {
        return fs.readFileSync(filePath, 'utf-8');
    }
    catch {
        return '';
    }
}
function awsIamExportConnector(fileOrDir) {
    const identities = [];
    const edges = [];
    const inflectionPoints = [];
    const content = readFileSafe(fileOrDir);
    if (!content)
        return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'aws_iam' };
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let data = {};
    try {
        data = JSON.parse(content);
    }
    catch {
        return { identities: [], edges: [], executionPaths: [], inflectionPoints: [], findings: [], evidenceRefs: [], sourceSystem: 'aws_iam' };
    }
    // Parse IAM roles
    const roles = data?.RoleDetailList ?? data?.roles ?? [];
    for (const role of roles) {
        const roleName = role?.RoleName ?? role?.name ?? 'unknown-role';
        const arn = role?.Arn ?? role?.arn ?? '';
        const createdAt = role?.CreateDate ?? role?.created_at;
        const trustPolicy = role?.AssumeRolePolicyDocument ?? role?.trust_policy ?? {};
        const trustStr = JSON.stringify(trustPolicy);
        const isWildcard = trustStr.includes('"*"') || trustStr.includes("'*'");
        const isAdmin = (role?.AttachedManagedPolicies ?? []).some((p) => p?.PolicyName === 'AdministratorAccess' || p?.PolicyName === 'PowerUserAccess');
        const identity = (0, identity_1.createIdentity)({
            name: roleName,
            identityType: 'aws_iam_role',
            sourceSystem: 'aws_iam',
            credentialTypes: ['iam_role'],
            riskTags: [...(isWildcard ? ['public_trust'] : []), ...(isAdmin ? ['admin'] : [])],
            permissions: (role?.AttachedManagedPolicies ?? []).map((p) => p?.PolicyName ?? ''),
            createdAt,
            metadata: { arn, trustPolicy },
        });
        identities.push(identity);
        if (isWildcard) {
            inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                type: 'PUBLIC_EXPOSURE',
                severity: 'CRITICAL',
                identityId: identity.id,
                identityName: roleName,
                description: `AWS IAM role "${roleName}" trust policy allows any principal (*)`,
                recommendation: 'Restrict trust policy to specific AWS accounts, services, and conditions.',
                metadata: { arn },
            }));
        }
        if (isAdmin) {
            inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                type: 'ADMIN_ROLE_ASSIGNED',
                severity: 'CRITICAL',
                identityId: identity.id,
                identityName: roleName,
                description: `AWS IAM role "${roleName}" has AdministratorAccess or PowerUserAccess`,
                recommendation: 'Replace with least-privilege policies.',
                metadata: { arn, policies: (role?.AttachedManagedPolicies ?? []).map((p) => p?.PolicyName) },
            }));
        }
        // Lambda/ECS execution roles
        const isLambdaRole = trustStr.includes('lambda.amazonaws.com');
        const isEcsRole = trustStr.includes('ecs-tasks.amazonaws.com');
        if (isLambdaRole || isEcsRole) {
            identity.riskTags.push('execution_role');
            identity.metadata['executionRoleType'] = isLambdaRole ? 'lambda' : 'ecs';
        }
    }
    // Parse IAM users (service accounts — no console access, have access keys)
    const users = data?.UserDetailList ?? data?.users ?? [];
    for (const user of users) {
        const userName = user?.UserName ?? user?.name ?? 'unknown-user';
        const arn = user?.Arn ?? '';
        const accessKeys = user?.AccessKeyMetadata ?? user?.access_keys ?? [];
        const hasConsoleAccess = !!user?.LoginProfile;
        const createdAt = user?.CreateDate ?? user?.created_at;
        if (accessKeys.length > 0 && !hasConsoleAccess) {
            const identity = (0, identity_1.createIdentity)({
                name: userName,
                identityType: 'service_account',
                sourceSystem: 'aws_iam',
                credentialTypes: ['access_key'],
                riskTags: [],
                createdAt,
                metadata: {
                    arn,
                    accessKeyCount: accessKeys.length,
                    accessKeys: accessKeys.map((k) => ({
                        id: k?.AccessKeyId,
                        status: k?.Status,
                        created: k?.CreateDate,
                    })),
                },
            });
            identities.push(identity);
            // Check stale access keys
            for (const key of accessKeys) {
                const keyCreated = key?.CreateDate;
                if (keyCreated) {
                    const daysSince = (Date.now() - new Date(keyCreated).getTime()) / (1000 * 60 * 60 * 24);
                    if (daysSince > 365) {
                        inflectionPoints.push((0, inflectionPoint_1.createInflectionPoint)({
                            type: 'CREDENTIAL_STALE',
                            severity: 'HIGH',
                            identityId: identity.id,
                            identityName: userName,
                            description: `IAM user "${userName}" has access key created ${Math.round(daysSince)} days ago`,
                            recommendation: 'Rotate access keys at minimum annually. Prefer IAM roles over long-lived access keys.',
                            metadata: { keyId: key?.AccessKeyId, daysSince: Math.round(daysSince) },
                        }));
                    }
                }
            }
        }
    }
    return {
        identities,
        edges,
        executionPaths: [],
        inflectionPoints,
        findings: [],
        evidenceRefs: [],
        sourceSystem: 'aws_iam',
    };
}
//# sourceMappingURL=awsIamExportConnector.js.map