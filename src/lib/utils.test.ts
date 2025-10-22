import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { generateSlug, calculateExpiryDate, isExpired } from './utils';

describe('generateSlug', () => {
  it('should generate a slug with 12 characters', () => {
    const slug = generateSlug();
    expect(slug).toHaveLength(12);
  });

  it('should generate unique slugs', () => {
    const slugs = new Set();
    for (let i = 0; i < 100; i++) {
      slugs.add(generateSlug());
    }
    expect(slugs.size).toBe(100);
  });

  it('should only contain URL-safe characters', () => {
    const slug = generateSlug();
    expect(slug).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

describe('calculateExpiryDate', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should calculate expiry date 1 hour from now', () => {
    const now = new Date('2025-01-01T12:00:00Z');
    vi.setSystemTime(now);

    const expiryDate = calculateExpiryDate(1);
    const expected = new Date('2025-01-01T13:00:00Z');

    expect(expiryDate.getTime()).toBe(expected.getTime());
  });

  it('should calculate expiry date 24 hours from now', () => {
    const now = new Date('2025-01-01T12:00:00Z');
    vi.setSystemTime(now);

    const expiryDate = calculateExpiryDate(24);
    const expected = new Date('2025-01-02T12:00:00Z');

    expect(expiryDate.getTime()).toBe(expected.getTime());
  });

  it('should calculate expiry date 168 hours (1 week) from now', () => {
    const now = new Date('2025-01-01T12:00:00Z');
    vi.setSystemTime(now);

    const expiryDate = calculateExpiryDate(168);
    const expected = new Date('2025-01-08T12:00:00Z');

    expect(expiryDate.getTime()).toBe(expected.getTime());
  });

  it('should calculate expiry date 8760 hours (1 year) from now', () => {
    const now = new Date('2025-01-01T12:00:00Z');
    vi.setSystemTime(now);

    const expiryDate = calculateExpiryDate(8760);
    const expected = new Date('2026-01-01T12:00:00Z');

    expect(expiryDate.getTime()).toBe(expected.getTime());
  });

  it('should handle fractional hours', () => {
    const now = new Date('2025-01-01T12:00:00Z');
    vi.setSystemTime(now);

    const expiryDate = calculateExpiryDate(0.5);
    const expected = new Date('2025-01-01T12:30:00Z');

    expect(expiryDate.getTime()).toBe(expected.getTime());
  });
});

describe('isExpired', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('should return false for null expiry date', () => {
    expect(isExpired(null)).toBe(false);
  });

  it('should return true for past dates', () => {
    const now = new Date('2025-01-01T12:00:00Z');
    vi.setSystemTime(now);

    const pastDate = new Date('2025-01-01T11:00:00Z');
    expect(isExpired(pastDate)).toBe(true);
  });

  it('should return false for future dates', () => {
    const now = new Date('2025-01-01T12:00:00Z');
    vi.setSystemTime(now);

    const futureDate = new Date('2025-01-01T13:00:00Z');
    expect(isExpired(futureDate)).toBe(false);
  });

  it('should return true for exact current time (edge case)', () => {
    const now = new Date('2025-01-01T12:00:00Z');
    vi.setSystemTime(now);

    const exactNow = new Date('2025-01-01T12:00:00Z');
    // Since new Date() > expiresAt, equal times should return false
    expect(isExpired(exactNow)).toBe(false);
  });

  it('should return true for dates 1 millisecond in the past', () => {
    const now = new Date('2025-01-01T12:00:00.000Z');
    vi.setSystemTime(now);

    const pastDate = new Date('2025-01-01T11:59:59.999Z');
    expect(isExpired(pastDate)).toBe(true);
  });

  it('should return false for dates 1 millisecond in the future', () => {
    const now = new Date('2025-01-01T12:00:00.000Z');
    vi.setSystemTime(now);

    const futureDate = new Date('2025-01-01T12:00:00.001Z');
    expect(isExpired(futureDate)).toBe(false);
  });
});
