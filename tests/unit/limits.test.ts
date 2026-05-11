import { describe, it, expect } from 'vitest';
import { COMMUNITY_NHI_LIMIT, applyEditionLimit } from '../../src/core/limits';

describe('limits', () => {
  it('COMMUNITY_NHI_LIMIT is 25', () => {
    expect(COMMUNITY_NHI_LIMIT).toBe(25);
  });

  it('applyEditionLimit returns limited=true and 25 items when community edition and 30 items', () => {
    const items = Array.from({ length: 30 }, (_, i) => ({ id: i }));
    const result = applyEditionLimit(items, 'community');

    expect(result.limited).toBe(true);
    expect(result.items.length).toBe(25);
    expect(result.total).toBe(30);
  });

  it('applyEditionLimit returns all items for pro edition', () => {
    const items = Array.from({ length: 30 }, (_, i) => ({ id: i }));
    const result = applyEditionLimit(items, 'pro');

    expect(result.limited).toBe(false);
    expect(result.items.length).toBe(30);
    expect(result.total).toBe(30);
  });

  it('applyEditionLimit returns all items for business edition', () => {
    const items = Array.from({ length: 100 }, (_, i) => ({ id: i }));
    const result = applyEditionLimit(items, 'business');

    expect(result.limited).toBe(false);
    expect(result.items.length).toBe(100);
  });

  it('applyEditionLimit returns all items when community and under limit', () => {
    const items = Array.from({ length: 10 }, (_, i) => ({ id: i }));
    const result = applyEditionLimit(items, 'community');

    expect(result.limited).toBe(false);
    expect(result.items.length).toBe(10);
    expect(result.total).toBe(10);
  });

  it('applyEditionLimit returns empty array for empty input', () => {
    const result = applyEditionLimit([], 'community');
    expect(result.items).toHaveLength(0);
    expect(result.limited).toBe(false);
    expect(result.total).toBe(0);
  });
});
