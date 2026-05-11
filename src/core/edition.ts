import { loadLicense } from './localLicense';

export type Edition = 'community' | 'pro' | 'business' | 'enterprise';

export const UPGRADE_MESSAGE =
  'VerifiedTrust Local detected more non-human identity exposure than Community Edition includes. ' +
  'Community Edition includes detailed analysis for the first 25 NHIs. ' +
  'Upgrade to VerifiedTrust Pro to unlock full identity inventory, executive PDF reports, SARIF export, ' +
  'signed evidence, policy packs, and FrontDesk integration.';

export function getEdition(): Edition {
  const envEdition = process.env['VT_EDITION'];
  if (envEdition && isValidEdition(envEdition)) {
    return envEdition as Edition;
  }

  try {
    const license = loadLicense();
    return license.edition;
  } catch {
    return 'community';
  }
}

function isValidEdition(value: string): boolean {
  return ['community', 'pro', 'business', 'enterprise'].includes(value);
}
