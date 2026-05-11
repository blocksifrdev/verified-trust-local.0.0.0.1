# Offline Export Guide

VerifiedTrust Local is designed for offline operation. Export data from your identity systems and ingest locally.

## Microsoft Entra ID

```bash
# Export service principals
az ad sp list --all --output json > entra-service-principals.json

# Export app registrations
az ad app list --all --output json > entra-app-registrations.json

# Ingest
verifiedtrust ingest entra ./entra-service-principals.json --out ./vt-data
```

## Okta

Export from Okta Admin Console:
- Go to Reports > Applications > Application Inventory
- Export as CSV
- Ingest: `verifiedtrust ingest okta ./okta-apps.csv --out ./vt-data`

## AWS IAM

```bash
aws iam get-account-authorization-details \
  --filter RoleDetailList UserDetailList \
  --output json > aws-iam.json

verifiedtrust ingest aws ./aws-iam.json --out ./vt-data
```

## Azure Role Assignments

```bash
az role assignment list --all --output json > azure-role-assignments.json
verifiedtrust ingest azure ./azure-role-assignments.json --out ./vt-data
```

## GCP IAM

```bash
gcloud projects get-iam-policy YOUR_PROJECT_ID \
  --format=json > gcp-iam-policy.json

verifiedtrust ingest gcp ./gcp-iam-policy.json --out ./vt-data
```

## CyberArk

Export from CyberArk Central Policy Manager:
- Go to Accounts > Export
- Select CSV format
- Ingest: `verifiedtrust ingest cyberark ./cyberark-accounts.csv --out ./vt-data`

## BeyondTrust

Export from BeyondTrust Password Safe:
- Go to Reports > Managed Accounts
- Export as CSV or JSON
- Ingest: `verifiedtrust ingest beyondtrust ./bt-accounts.csv --out ./vt-data`

## Delinea/Thycotic Secret Server

Export from Secret Server:
- Go to Reports > Custom Reports
- Export secrets list
- Ingest: `verifiedtrust ingest delinea ./delinea-secrets.csv --out ./vt-data`

## HashiCorp Vault

```bash
vault audit list -detailed > vault-audit.json
verifiedtrust ingest vault ./vault-audit.json --out ./vt-data
```

## Combining Multiple Sources

```bash
# Ingest all sources
verifiedtrust ingest entra ./entra.json --out ./vt-data
verifiedtrust ingest aws ./aws-iam.json --out ./vt-data
verifiedtrust ingest cyberark ./cyberark.csv --out ./vt-data

# Analyze all ingested data together
verifiedtrust analyze ./vt-data --out ./report
```
