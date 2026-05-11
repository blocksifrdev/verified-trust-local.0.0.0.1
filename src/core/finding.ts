import { Finding, Severity, SourceSystem, InflectionPointType } from './types';
import { createId } from './id';

export function createFinding(partial: Partial<Finding> & { title: string; description: string; recommendation: string }): Finding {
  return {
    ...partial,
    id: partial.id ?? createId(),
    severity: partial.severity ?? ('MODERATE' as Severity),
    title: partial.title,
    description: partial.description,
    recommendation: partial.recommendation,
    identityId: partial.identityId,
    identityName: partial.identityName,
    sourceFile: partial.sourceFile,
    sourceSystem: partial.sourceSystem as SourceSystem | undefined,
    inflectionType: partial.inflectionType as InflectionPointType | undefined,
    evidenceRefs: partial.evidenceRefs ?? [],
    detectedAt: partial.detectedAt ?? new Date().toISOString(),
    metadata: partial.metadata ?? {},
  };
}
