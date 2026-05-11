import { AuthorityEdge, SourceSystem } from './types';
export declare function createAuthorityEdge(partial: Partial<AuthorityEdge> & {
    fromIdentityId: string;
    toIdentityId: string;
    relation: string;
    sourceSystem: SourceSystem;
}): AuthorityEdge;
//# sourceMappingURL=authorityEdge.d.ts.map