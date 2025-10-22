import { describe, it, expect, vi, beforeEach } from 'vitest';
import { cleanupExpiredPastes } from './cleanup';

// Mock the prisma module
vi.mock('./db', () => ({
  prisma: {
    paste: {
      deleteMany: vi.fn(),
    },
  },
}));

import { prisma } from './db';

describe('cleanupExpiredPastes', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should delete expired and burned pastes', async () => {
    const mockDeleteMany = vi.mocked(prisma.paste.deleteMany);
    mockDeleteMany.mockResolvedValue({ count: 5 });

    const result = await cleanupExpiredPastes();

    expect(result).toBe(5);
    expect(mockDeleteMany).toHaveBeenCalledTimes(1);
  });

  it('should call deleteMany with correct where clause', async () => {
    const mockDeleteMany = vi.mocked(prisma.paste.deleteMany);
    mockDeleteMany.mockResolvedValue({ count: 0 });

    await cleanupExpiredPastes();

    expect(mockDeleteMany).toHaveBeenCalledWith({
      where: {
        OR: [
          {
            expires_at: {
              lte: expect.any(Date),
            },
          },
          {
            is_burned: true,
          },
        ],
      },
    });
  });

  it('should return 0 when no pastes are deleted', async () => {
    const mockDeleteMany = vi.mocked(prisma.paste.deleteMany);
    mockDeleteMany.mockResolvedValue({ count: 0 });

    const result = await cleanupExpiredPastes();

    expect(result).toBe(0);
  });

  it('should handle large number of deletions', async () => {
    const mockDeleteMany = vi.mocked(prisma.paste.deleteMany);
    mockDeleteMany.mockResolvedValue({ count: 1000 });

    const result = await cleanupExpiredPastes();

    expect(result).toBe(1000);
  });

  it('should propagate database errors', async () => {
    const mockDeleteMany = vi.mocked(prisma.paste.deleteMany);
    const dbError = new Error('Database connection failed');
    mockDeleteMany.mockRejectedValue(dbError);

    await expect(cleanupExpiredPastes()).rejects.toThrow('Database connection failed');
  });

  it('should use current date for expiry check', async () => {
    const mockDeleteMany = vi.mocked(prisma.paste.deleteMany);
    mockDeleteMany.mockResolvedValue({ count: 3 });

    const beforeCall = new Date();
    await cleanupExpiredPastes();
    const afterCall = new Date();

    const callArgs = mockDeleteMany.mock.calls[0][0];
    const expiresAtCondition = callArgs.where.OR[0].expires_at.lte;

    expect(expiresAtCondition.getTime()).toBeGreaterThanOrEqual(beforeCall.getTime());
    expect(expiresAtCondition.getTime()).toBeLessThanOrEqual(afterCall.getTime());
  });
});
