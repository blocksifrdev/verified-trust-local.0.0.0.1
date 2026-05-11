import { EvidenceRef } from './types';
import { createId } from './id';

export function createEvidenceRef(partial: Partial<EvidenceRef> & { type: string; description: string; present: boolean }): EvidenceRef {
  return {
    ...partial,
    id: partial.id ?? createId(),
    type: partial.type,
    path: partial.path,
    url: partial.url,
    content: partial.content,
    detectedAt: partial.detectedAt ?? new Date().toISOString(),
    present: partial.present,
    description: partial.description,
  };
}
