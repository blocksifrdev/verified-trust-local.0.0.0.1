import { Identity, IdentityType, SourceSystem } from './types';
export declare function normalizeIdentityName(name: string): string;
export declare function createIdentity(partial: Partial<Identity> & {
    name: string;
    identityType: IdentityType;
    sourceSystem: SourceSystem;
}): Identity;
//# sourceMappingURL=identity.d.ts.map