import { UPGRADE_MESSAGE } from '../core/edition';

export function writePdfReport(): never {
  throw new Error('PDF export requires VerifiedTrust Pro or higher. ' + UPGRADE_MESSAGE);
}
