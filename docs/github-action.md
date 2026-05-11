# GitHub Action Usage

VerifiedTrust Local can be used as a GitHub Action for continuous NHI scanning on every push and pull request.

## Basic Setup

Create `.github/workflows/verifiedtrust.yml`:

```yaml
name: VerifiedTrust NHI Scan

on:
  push:
    branches: [main]
  pull_request:
  schedule:
    - cron: '0 8 * * 1'  # Weekly Monday morning

jobs:
  verifiedtrust-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: VerifiedTrust Local Scan
        uses: blocksifr/verifiedtrust-local@v1
        with:
          scan-path: '.'
          output-dir: 'verifiedtrust-report'
          edition: 'community'
      
      - name: Upload Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: verifiedtrust-report
          path: verifiedtrust-report/
```

## Configuration Options

| Input | Description | Default |
|-------|-------------|---------|
| `scan-path` | Directory to scan | `.` |
| `output-dir` | Where to write reports | `verifiedtrust-report` |
| `edition` | Edition (community, pro, business, enterprise) | `community` |

## Fail on High Risk

```yaml
- name: VerifiedTrust Scan
  uses: blocksifr/verifiedtrust-local@v1
  
- name: Check Risk Score
  run: |
    BAND=$(cat verifiedtrust-report/risk-summary.json | jq -r '.riskScore.band')
    if [ "$BAND" = "CRITICAL" ]; then
      echo "CRITICAL risk detected. Review verifiedtrust-report/executive-report.html"
      exit 1
    fi
```

## Upload to GitHub Pages

```yaml
- name: Deploy Report to Pages
  uses: peaceiris/actions-gh-pages@v3
  if: github.ref == 'refs/heads/main'
  with:
    github_token: ${{ secrets.GITHUB_TOKEN }}
    publish_dir: verifiedtrust-report
```
