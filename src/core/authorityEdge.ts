import { AuthorityEdge, SourceSystem } from './types';
import { createId } from './id';

export function createAuthorityEdge(partial: Partial<AuthorityEdge> & { fromIdentityId: string; toIdentityId: string; relation: string; sourceSystem: SourceSystem }): AuthorityEdge {
  return {
    ...partial,
    id: partial.id ?? createId(),
    fromIdentityId: partial.fromIdentityId,
    toIdentityId: partial.toIdentityId,
    relation: partial.relation,
    permissions: partial.permissions ?? [],
    isWildcard: partial.isWildcard ?? false,
    isAdmin: partial.isAdmin ?? false,
    scope: partial.scope,
    sourceSystem: partial.sourceSystem,
    sourceFile: partial.sourceFile,
    metadata: partial.metadata ?? {},
  };
}
