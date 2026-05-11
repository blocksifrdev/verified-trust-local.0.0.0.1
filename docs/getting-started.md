# Getting Started with VerifiedTrust Local

## Installation

```bash
# Global install via npm
npm install -g @blocksifr/verifiedtrust-local

# Or via npx (no install)
npx @blocksifr/verifiedtrust-local scan .
```

## Your First Scan

```bash
# Scan the current directory
verifiedtrust scan . --out ./verifiedtrust-report

# Scan a specific repository
verifiedtrust scan /path/to/your/repo --out /tmp/vt-report
```

## Understanding the Output

After a scan, you'll find these files in your output directory:

| File | Description |
|------|-------------|
| `executive-report.html` | Self-contained HTML report — open in any browser |
| `findings.json` | All findings sorted by severity |
| `identity-map.json` | Full NHI inventory |
| `authority-graph.json` | Identity authority edges |
| `evidence-map.json` | Evidence artifacts detected |
| `risk-summary.json` | Risk score summary |
| `remediation-roadmap.md` | 30-day remediation plan |

## Interpreting the Risk Score

- **0–24 (LOW)**: Minor issues. Good hygiene improvements recommended.
- **25–49 (MODERATE)**: Several issues requiring attention in the next sprint.
- **50–74 (HIGH)**: Significant exposure. Prioritize remediation within 30 days.
- **75–100 (CRITICAL)**: Critical exposure. Immediate action required.

## Running a Check

```bash
# Verify your environment
verifiedtrust doctor
```

## Next Steps

- See [offline-exports.md](offline-exports.md) to add data from identity providers
- See [findings.md](findings.md) to understand each finding type
- See [github-action.md](github-action.md) to add scanning to CI/CD
