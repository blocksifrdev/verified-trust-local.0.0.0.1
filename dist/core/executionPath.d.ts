import { ExecutionPath, SourceSystem } from './types';
export declare function createExecutionPath(partial: Partial<ExecutionPath> & {
    identityId: string;
    identityName: string;
    trigger: string;
    targetEnvironment: string;
    sourceSystem: SourceSystem;
}): ExecutionPath;
//# sourceMappingURL=executionPath.d.ts.map