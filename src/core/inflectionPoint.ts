import { InflectionPoint, InflectionPointType, Severity } from './types';
import { createId } from './id';

export function createInflectionPoint(partial: Partial<InflectionPoint> & { type: InflectionPointType; severity: Severity; description: string; recommendation: string }): InflectionPoint {
  return {
    ...partial,
    id: partial.id ?? createId(),
    type: partial.type,
    severity: partial.severity,
    identityId: partial.identityId,
    identityName: partial.identityName,
    executionPathId: partial.executionPathId,
    edgeId: partial.edgeId,
    description: partial.description,
    recommendation: partial.recommendation,
    sourceFile: partial.sourceFile,
    detectedAt: partial.detectedAt ?? new Date().toISOString(),
    metadata: partial.metadata ?? {},
  };
}
