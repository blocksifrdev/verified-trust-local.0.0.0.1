# Understanding Findings

## Severity Levels

| Level | Score Range | Meaning |
|-------|-------------|---------|
| CRITICAL | 75-100 | Immediate action required |
| HIGH | 50-74 | Prioritized remediation within 30 days |
| MODERATE | 25-49 | Scheduled remediation |
| LOW | 5-24 | Best practice improvement |
| INFO | 0-4 | Informational only |

## Inflection Point Types

### OWNER_MISSING
An NHI has no assigned owner.

**Remediation**: Assign an owner in your identity inventory or directory.

### APPROVAL_BYPASS
A production execution path lacks an approval gate.

**Remediation**: Add environment protection rules with required reviewers.

### TRUST_BOUNDARY_CROSSING
An identity executes across a trust boundary without explicit authorization.

**Remediation**: Enforce network segmentation and require explicit authorization.

### CREDENTIAL_STALE
A credential has not been used or rotated in more than 90 days.

**Remediation**: Rotate or disable unused credentials.

### PRIVILEGE_ESCALATION_PATH
An identity has a path to elevated privileges via admin roles or wildcard permissions.

**Remediation**: Replace with least-privilege specific permissions.

### SECRET_IN_CONFIG
A credential pattern was detected in a source file.

**Remediation**: Remove from source. Use environment variables or a secrets manager.

### AGENT_IDENTITY_CREATED
An AI agent identity was detected.

**Remediation**: Document access and require human review of agent-generated changes.

### MCP_SERVER_CONFIGURED
An MCP server was detected. MCP servers are machine identities with tool access.

**Remediation**: Audit MCP server tool access and apply least privilege.
