import { Identity, IdentityType, SourceSystem } from './types';
import { createId } from './id';

export function normalizeIdentityName(name: string): string {
  return name.toLowerCase().trim().replace(/\s+/g, ' ');
}

export function createIdentity(partial: Partial<Identity> & { name: string; identityType: IdentityType; sourceSystem: SourceSystem }): Identity {
  const normalized = normalizeIdentityName(partial.name);
  return {
    ...partial,
    id: partial.id ?? createId(),
    name: partial.name,
    normalizedName: normalized,
    identityType: partial.identityType,
    sourceSystem: partial.sourceSystem,
    environment: partial.environment,
    owner: partial.owner,
    team: partial.team,
    createdAt: partial.createdAt,
    lastUsedAt: partial.lastUsedAt,
    lastRotatedAt: partial.lastRotatedAt,
    credentialTypes: partial.credentialTypes ?? [],
    permissions: partial.permissions ?? [],
    riskTags: partial.riskTags ?? [],
    evidenceRefs: partial.evidenceRefs ?? [],
    metadata: partial.metadata ?? {},
    sourceFile: partial.sourceFile,
    description: partial.description,
  };
}
