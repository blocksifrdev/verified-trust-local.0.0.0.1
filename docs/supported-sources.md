# Supported Sources

| Source | Type | Auto-scan | Ingest | Format |
|--------|------|-----------|--------|--------|
| Filesystem | Code/config files | Yes | - | Any |
| GitHub Actions | CI/CD | Yes | - | YAML |
| Azure DevOps | CI/CD | Yes | - | YAML |
| GitLab CI | CI/CD | Yes | - | YAML |
| Jenkins | CI/CD | Yes | - | Groovy/Jenkinsfile |
| Terraform | IaC | Yes | - | HCL (.tf) |
| Kubernetes | Workloads | Yes | - | YAML |
| Microsoft Entra ID | IDP | - | Yes | JSON |
| Okta | IDP | - | Yes | CSV/JSON |
| AWS IAM | Cloud IAM | - | Yes | JSON |
| Azure IAM | Cloud IAM | - | Yes | JSON/CSV |
| GCP IAM | Cloud IAM | - | Yes | JSON |
| CyberArk | PAM | - | Yes | CSV/JSON |
| BeyondTrust | PAM | - | Yes | CSV/JSON |
| Delinea/Thycotic | PAM | - | Yes | CSV/JSON |
| HashiCorp Vault | Secrets | - | Yes | JSON |
| Generic CSV | Custom | - | Yes | CSV |
| Generic Log | Audit logs | - | Yes | CSV/JSON |
