import type { Edition } from './edition';
export interface LicenseInfo {
    edition: Edition;
    licenseKey?: string;
    activatedAt?: string;
    expiresAt?: string;
}
export declare function loadLicense(): LicenseInfo;
export declare function activateLicense(key: string): LicenseInfo;
//# sourceMappingURL=localLicense.d.ts.map