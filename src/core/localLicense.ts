import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { Edition } from './edition';

export interface LicenseInfo {
  edition: Edition;
  licenseKey?: string;
  activatedAt?: string;
  expiresAt?: string;
}

function getLicensePath(): string {
  return path.join(os.homedir(), '.verifiedtrust', 'license.json');
}

export function loadLicense(): LicenseInfo {
  const licensePath = getLicensePath();
  try {
    if (fs.existsSync(licensePath)) {
      const raw = fs.readFileSync(licensePath, 'utf-8');
      const parsed = JSON.parse(raw) as LicenseInfo;
      return parsed;
    }
  } catch {
    // Fall through to community
  }
  return { edition: 'community' };
}

export function activateLicense(key: string): LicenseInfo {
  // Stub: always returns community for now with a note
  const info: LicenseInfo = {
    edition: 'community',
    licenseKey: key,
    activatedAt: new Date().toISOString(),
  };

  const licenseDir = path.join(os.homedir(), '.verifiedtrust');
  try {
    fs.mkdirSync(licenseDir, { recursive: true });
    fs.writeFileSync(getLicensePath(), JSON.stringify(info, null, 2), 'utf-8');
  } catch {
    // Ignore write errors
  }

  console.log('Note: License validation requires VerifiedTrust Pro server. ' +
    'This is a stub — edition remains community until server-side activation is implemented.');

  return info;
}
