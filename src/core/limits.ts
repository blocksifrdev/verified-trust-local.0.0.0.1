export const COMMUNITY_NHI_LIMIT = 25;

export function applyEditionLimit<T>(
  items: T[],
  edition: string
): { items: T[]; limited: boolean; total: number } {
  const total = items.length;

  if (edition === 'community' && total > COMMUNITY_NHI_LIMIT) {
    return {
      items: items.slice(0, COMMUNITY_NHI_LIMIT),
      limited: true,
      total,
    };
  }

  return {
    items,
    limited: false,
    total,
  };
}
