import { ExecutionPath, SourceSystem } from './types';
import { createId } from './id';

export function createExecutionPath(partial: Partial<ExecutionPath> & { identityId: string; identityName: string; trigger: string; targetEnvironment: string; sourceSystem: SourceSystem }): ExecutionPath {
  return {
    ...partial,
    id: partial.id ?? createId(),
    identityId: partial.identityId,
    identityName: partial.identityName,
    trigger: partial.trigger,
    targetEnvironment: partial.targetEnvironment,
    isProduction: partial.isProduction ?? false,
    approvalDetected: partial.approvalDetected ?? false,
    evidenceDetected: partial.evidenceDetected ?? false,
    trustBoundaryCrossed: partial.trustBoundaryCrossed ?? false,
    steps: partial.steps ?? [],
    sourceFile: partial.sourceFile,
    sourceSystem: partial.sourceSystem,
    metadata: partial.metadata ?? {},
  };
}
