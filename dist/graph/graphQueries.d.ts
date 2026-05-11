import { Identity, ExecutionPath, Finding, IdentityType } from '../core/types';
import { IdentityGraph } from './identityGraph';
export declare function getPrivilegedIdentities(graph: IdentityGraph): Identity[];
export declare function getOrphanedIdentities(graph: IdentityGraph): Identity[];
export declare function getHighRiskPaths(graph: IdentityGraph): ExecutionPath[];
export declare function getIdentitiesByType(graph: IdentityGraph, type: IdentityType): Identity[];
export declare function getCriticalFindings(graph: IdentityGraph): Finding[];
//# sourceMappingURL=graphQueries.d.ts.map