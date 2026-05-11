# Upgrading VerifiedTrust Local

## From Community to Pro

1. Purchase a Pro license at [verifiedtrust.io](https://verifiedtrust.io)
2. Activate your license:
   ```bash
   verifiedtrust activate --license VT-XXXX-XXXX-XXXX-XXXX
   ```
3. Verify your edition:
   ```bash
   verifiedtrust doctor
   ```

## What Pro Unlocks

- Unlimited NHI inventory (remove the 25-NHI Community limit)
- SARIF export for GitHub Code Scanning
- Executive PDF reports
- Signed evidence bundles
- Policy packs

## Environment Variable Override

For CI/CD use, set the edition via environment variable:

```bash
VT_EDITION=pro verifiedtrust scan . --out ./report
```

Note: This requires a valid Pro license key to be activated.
