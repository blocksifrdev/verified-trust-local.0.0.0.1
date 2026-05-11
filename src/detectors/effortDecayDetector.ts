import { Identity, InflectionPoint } from '../core/types';
import { createInflectionPoint } from '../core/inflectionPoint';

const NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1000;
const THREE_SIXTY_FIVE_DAYS_MS = 365 * 24 * 60 * 60 * 1000;

export function detectEffortDecay(identities: Identity[]): InflectionPoint[] {
  const inflectionPoints: InflectionPoint[] = [];
  const now = Date.now();

  for (const identity of identities) {
    // LAST_USED_STALE: > 90 days since last use
    if (identity.lastUsedAt) {
      const lastUsed = new Date(identity.lastUsedAt).getTime();
      const daysSince = Math.round((now - lastUsed) / (1000 * 60 * 60 * 24));

      if (now - lastUsed > NINETY_DAYS_MS) {
        inflectionPoints.push(createInflectionPoint({
          type: 'LAST_USED_STALE',
          severity: daysSince > 365 ? 'HIGH' : 'MODERATE',
          identityId: identity.id,
          identityName: identity.name,
          description: `Identity "${identity.name}" has not been used in ${daysSince} days (last used: ${identity.lastUsedAt})`,
          recommendation: 'Disable or remove identities unused for more than 90 days. Review whether the identity is still required.',
          metadata: { lastUsedAt: identity.lastUsedAt, daysSinceUse: daysSince },
        }));
      }
    }

    // CREDENTIAL_STALE: credential not rotated in > 365 days
    if (identity.lastRotatedAt) {
      const lastRotated = new Date(identity.lastRotatedAt).getTime();
      const daysSinceRotation = Math.round((now - lastRotated) / (1000 * 60 * 60 * 24));

      if (now - lastRotated > THREE_SIXTY_FIVE_DAYS_MS) {
        inflectionPoints.push(createInflectionPoint({
          type: 'CREDENTIAL_STALE',
          severity: 'HIGH',
          identityId: identity.id,
          identityName: identity.name,
          description: `Identity "${identity.name}" credentials last rotated ${daysSinceRotation} days ago (last rotation: ${identity.lastRotatedAt})`,
          recommendation: 'Rotate credentials at minimum annually. Implement automated rotation where possible.',
          metadata: { lastRotatedAt: identity.lastRotatedAt, daysSinceRotation },
        }));
      }
    } else if (identity.createdAt && identity.credentialTypes.length > 0) {
      // Has credentials but no rotation record — flag based on creation date
      const created = new Date(identity.createdAt).getTime();
      const daysSinceCreation = Math.round((now - created) / (1000 * 60 * 60 * 24));

      if (now - created > THREE_SIXTY_FIVE_DAYS_MS) {
        inflectionPoints.push(createInflectionPoint({
          type: 'ROTATION_MISSING',
          severity: 'MODERATE',
          identityId: identity.id,
          identityName: identity.name,
          description: `Identity "${identity.name}" was created ${daysSinceCreation} days ago with credentials but no rotation has been recorded`,
          recommendation: 'Establish a credential rotation policy. Rotate credentials that have not been rotated in over 1 year.',
          metadata: { createdAt: identity.createdAt, daysSinceCreation },
        }));
      }
    }
  }

  return inflectionPoints;
}
