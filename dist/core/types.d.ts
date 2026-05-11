export type IdentityType = 'service_account' | 'service_principal' | 'managed_identity' | 'workload_identity' | 'bot_user' | 'deploy_key' | 'api_token' | 'oauth_client' | 'github_app' | 'ci_cd_runner' | 'kubernetes_service_account' | 'aws_iam_role' | 'gcp_service_account' | 'azure_app_registration' | 'agent_identity' | 'mcp_server_identity' | 'unknown_nhi';
export type SourceSystem = 'filesystem' | 'github_actions' | 'azure_devops' | 'gitlab_ci' | 'jenkins' | 'terraform' | 'kubernetes' | 'entra' | 'okta' | 'aws_iam' | 'azure_iam' | 'gcp_iam' | 'cyberark' | 'beyondtrust' | 'delinea' | 'vault' | 'generic_csv' | 'generic_log';
export type Severity = 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'INFO';
export type RiskBand = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
export type InflectionPointType = 'CREDENTIAL_STALE' | 'ROTATION_MISSING' | 'OWNER_MISSING' | 'APPROVAL_BYPASS' | 'EVIDENCE_MISSING' | 'TRUST_BOUNDARY_CROSSING' | 'PRIVILEGE_ESCALATION_PATH' | 'AI_CODE_CHANGE_PATH' | 'AGENT_IDENTITY_CREATED' | 'MCP_SERVER_CONFIGURED' | 'TOOL_ACCESS_GRANTED' | 'LAST_USED_STALE' | 'SERVICE_TO_SERVICE_PATH' | 'PUBLIC_EXPOSURE' | 'WILDCARD_PERMISSION' | 'ADMIN_ROLE_ASSIGNED' | 'FEDERATED_IDENTITY_RISK' | 'SECRET_IN_CONFIG' | 'MISSING_ROTATION_POLICY';
export interface Identity {
    id: string;
    name: string;
    normalizedName: string;
    identityType: IdentityType;
    sourceSystem: SourceSystem;
    environment?: string;
    owner?: string;
    team?: string;
    createdAt?: string;
    lastUsedAt?: string;
    lastRotatedAt?: string;
    credentialTypes: string[];
    permissions: string[];
    riskTags: string[];
    evidenceRefs: string[];
    metadata: Record<string, unknown>;
    sourceFile?: string;
    description?: string;
}
export interface AuthorityEdge {
    id: string;
    fromIdentityId: string;
    toIdentityId: string;
    relation: string;
    permissions: string[];
    isWildcard: boolean;
    isAdmin: boolean;
    scope?: string;
    sourceSystem: SourceSystem;
    sourceFile?: string;
    metadata: Record<string, unknown>;
}
export interface ExecutionPath {
    id: string;
    identityId: string;
    identityName: string;
    trigger: string;
    targetEnvironment: string;
    isProduction: boolean;
    approvalDetected: boolean;
    evidenceDetected: boolean;
    trustBoundaryCrossed: boolean;
    steps: string[];
    sourceFile?: string;
    sourceSystem: SourceSystem;
    metadata: Record<string, unknown>;
}
export interface InflectionPoint {
    id: string;
    type: InflectionPointType;
    severity: Severity;
    identityId?: string;
    identityName?: string;
    executionPathId?: string;
    edgeId?: string;
    description: string;
    recommendation: string;
    sourceFile?: string;
    detectedAt: string;
    metadata: Record<string, unknown>;
}
export interface EvidenceRef {
    id: string;
    type: string;
    path?: string;
    url?: string;
    content?: string;
    detectedAt: string;
    present: boolean;
    description: string;
}
export interface Finding {
    id: string;
    severity: Severity;
    title: string;
    description: string;
    recommendation: string;
    identityId?: string;
    identityName?: string;
    sourceFile?: string;
    sourceSystem?: SourceSystem;
    inflectionType?: InflectionPointType;
    evidenceRefs: string[];
    detectedAt: string;
    metadata: Record<string, unknown>;
}
export interface NHIGraph {
    identities: Identity[];
    edges: AuthorityEdge[];
    executionPaths: ExecutionPath[];
    inflectionPoints: InflectionPoint[];
    findings: Finding[];
    evidenceRefs: EvidenceRef[];
}
export interface RiskScore {
    total: number;
    band: RiskBand;
    breakdown: Record<string, number>;
}
export interface ScanResult {
    identities: Identity[];
    edges: AuthorityEdge[];
    executionPaths: ExecutionPath[];
    inflectionPoints: InflectionPoint[];
    findings: Finding[];
    evidenceRefs: EvidenceRef[];
    sourceSystem: SourceSystem;
    sourceFile?: string;
}
//# sourceMappingURL=types.d.ts.map