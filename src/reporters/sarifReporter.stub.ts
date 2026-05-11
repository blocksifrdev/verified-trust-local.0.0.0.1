import { UPGRADE_MESSAGE } from '../core/edition';

export function writeSarifReport(): never {
  throw new Error('SARIF export requires VerifiedTrust Pro or higher. ' + UPGRADE_MESSAGE);
}
