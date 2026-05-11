import { RiskScore } from '../core/types';
import { IdentityGraph } from '../graph/identityGraph';
import { UPGRADE_MESSAGE } from '../core/edition';

export function generateExecutiveSummary(
  graph: IdentityGraph,
  riskScore: RiskScore,
  edition: string
): string {
  const totalNHIs = graph.identities.size;
  const criticalCount = graph.findings.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = graph.findings.filter((f) => f.severity === 'HIGH').length;
  const ownerlessCount = Array.from(graph.identities.values()).filter((i) => !i.owner).length;
  const prodPaths = graph.executionPaths.filter((ep) => ep.isProduction).length;
  const unapprovedProdPaths = graph.executionPaths.filter((ep) => ep.isProduction && !ep.approvalDetected).length;

  const bandDescriptions: Record<string, string> = {
    CRITICAL: 'This repository presents a critical non-human identity risk posture requiring immediate remediation.',
    HIGH: 'This repository presents a high non-human identity risk posture requiring prioritized remediation within 30 days.',
    MODERATE: 'This repository presents a moderate non-human identity risk posture with several areas requiring attention.',
    LOW: 'This repository presents a low non-human identity risk posture with minor improvements recommended.',
  };

  const verdict = bandDescriptions[riskScore.band] ?? 'Non-human identity risk assessment completed.';

  let summary = `${verdict} `;
  summary += `VerifiedTrust Local identified ${totalNHIs} non-human identit${totalNHIs === 1 ? 'y' : 'ies'} across scanned sources`;

  if (criticalCount > 0 || highCount > 0) {
    summary += `, including ${criticalCount} critical and ${highCount} high-severity finding${highCount === 1 ? '' : 's'}`;
  }

  if (ownerlessCount > 0) {
    summary += `. ${ownerlessCount} identit${ownerlessCount === 1 ? 'y has' : 'ies have'} no assigned owner`;
  }

  if (unapprovedProdPaths > 0) {
    summary += `. ${unapprovedProdPaths} of ${prodPaths} production execution path${prodPaths === 1 ? '' : 's'} lack an approval gate`;
  }

  summary += `.`;

  if (edition === 'community' && totalNHIs > 25) {
    summary += ` Note: Community Edition analysis is limited to the first 25 NHIs. ${UPGRADE_MESSAGE}`;
  }

  return summary;
}
