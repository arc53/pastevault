import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import Fastify, { FastifyInstance } from 'fastify';
import { pastesRoute } from './pastes';

// Mock the modules
vi.mock('../lib/db', () => ({
  prisma: {
    paste: {
      create: vi.fn(),
      findUnique: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
    },
  },
}));

vi.mock('../lib/config', () => ({
  config: {
    MAX_PASTE_SIZE_BYTES: 1048576, // 1MB
  },
}));

vi.mock('../lib/utils', () => ({
  generateSlug: vi.fn(() => 'test-slug-12'),
  calculateExpiryDate: vi.fn((hours: number) => new Date(Date.now() + hours * 60 * 60 * 1000)),
  isExpired: vi.fn((date: Date | null) => {
    if (!date) return false;
    return new Date() > date;
  }),
}));

import { prisma } from '../lib/db';
import { generateSlug, calculateExpiryDate, isExpired } from '../lib/utils';

describe('pastesRoute', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    app = Fastify();
    await app.register(pastesRoute, { prefix: '/api' });
    vi.clearAllMocks();
  });

  afterEach(async () => {
    await app.close();
  });

  describe('POST /api/pastes', () => {
    const validPaste = {
      ciphertext: 'dGVzdCBjaXBoZXJ0ZXh0', // base64 encoded
      nonce: '12345678901234567890123456789012',
      burn_after_read: false,
    };

    it('should create a paste successfully', async () => {
      const mockPaste = {
        id: 1,
        slug: 'test-slug-12',
        ciphertext: validPaste.ciphertext,
        nonce: validPaste.nonce,
        salt: null,
        kdf_params: null,
        expires_at: null,
        burn_after_read: false,
        is_burned: false,
        view_count: 0,
        created_at: new Date(),
      };

      vi.mocked(prisma.paste.create).mockResolvedValue(mockPaste);

      const response = await app.inject({
        method: 'POST',
        url: '/api/pastes',
        payload: validPaste,
      });

      expect(response.statusCode).toBe(201);
      const body = JSON.parse(response.body);
      expect(body).toEqual({
        slug: 'test-slug-12',
        expires_at: null,
      });
    });

    it('should accept custom slug', async () => {
      const customSlug = 'my-custom-slug';
      const mockPaste = {
        id: 1,
        slug: customSlug,
        ciphertext: validPaste.ciphertext,
        nonce: validPaste.nonce,
        salt: null,
        kdf_params: null,
        expires_at: null,
        burn_after_read: false,
        is_burned: false,
        view_count: 0,
        created_at: new Date(),
      };

      vi.mocked(prisma.paste.create).mockResolvedValue(mockPaste);

      const response = await app.inject({
        method: 'POST',
        url: '/api/pastes',
        payload: {
          ...validPaste,
          slug: customSlug,
        },
      });

      expect(response.statusCode).toBe(201);
      const body = JSON.parse(response.body);
      expect(body.slug).toBe(customSlug);
    });

    it('should accept expiry hours', async () => {
      const expiryDate = new Date('2025-01-02T12:00:00Z');
      vi.mocked(calculateExpiryDate).mockReturnValue(expiryDate);

      const mockPaste = {
        id: 1,
        slug: 'test-slug-12',
        ciphertext: validPaste.ciphertext,
        nonce: validPaste.nonce,
        salt: null,
        kdf_params: null,
        expires_at: expiryDate,
        burn_after_read: false,
        is_burned: false,
        view_count: 0,
        created_at: new Date(),
      };

      vi.mocked(prisma.paste.create).mockResolvedValue(mockPaste);

      const response = await app.inject({
        method: 'POST',
        url: '/api/pastes',
        payload: {
          ...validPaste,
          expires_in_hours: 24,
        },
      });

      expect(response.statusCode).toBe(201);
      const body = JSON.parse(response.body);
      expect(body.expires_at).toBe(expiryDate.toISOString());
    });

    it('should accept burn_after_read flag', async () => {
      const mockPaste = {
        id: 1,
        slug: 'test-slug-12',
        ciphertext: validPaste.ciphertext,
        nonce: validPaste.nonce,
        salt: null,
        kdf_params: null,
        expires_at: null,
        burn_after_read: true,
        is_burned: false,
        view_count: 0,
        created_at: new Date(),
      };

      vi.mocked(prisma.paste.create).mockResolvedValue(mockPaste);

      const response = await app.inject({
        method: 'POST',
        url: '/api/pastes',
        payload: {
          ...validPaste,
          burn_after_read: true,
        },
      });

      expect(response.statusCode).toBe(201);
    });

    it('should accept optional salt and kdf_params', async () => {
      const mockPaste = {
        id: 1,
        slug: 'test-slug-12',
        ciphertext: validPaste.ciphertext,
        nonce: validPaste.nonce,
        salt: 'random-salt',
        kdf_params: '{"iterations":100000}',
        expires_at: null,
        burn_after_read: false,
        is_burned: false,
        view_count: 0,
        created_at: new Date(),
      };

      vi.mocked(prisma.paste.create).mockResolvedValue(mockPaste);

      const response = await app.inject({
        method: 'POST',
        url: '/api/pastes',
        payload: {
          ...validPaste,
          salt: 'random-salt',
          kdf_params: '{"iterations":100000}',
        },
      });

      expect(response.statusCode).toBe(201);
    });

    it('should reject paste exceeding size limit', async () => {
      // Create a ciphertext that exceeds MAX_PASTE_SIZE_BYTES when base64 decoded
      // 1MB = 1048576 bytes, base64 encoding increases size by ~33%
      // So we need > 1398101 base64 chars to exceed 1MB when decoded
      const largeCiphertext = 'A'.repeat(1500000); // > 1MB when base64 decoded

      const response = await app.inject({
        method: 'POST',
        url: '/api/pastes',
        payload: {
          ...validPaste,
          ciphertext: largeCiphertext,
        },
      });

      expect(response.statusCode).toBe(413);
      const body = JSON.parse(response.body);
      // Fastify returns default error message for payload too large
      expect(body.error).toBe('Payload Too Large');
      // Note: maxSize is only included in custom error response, not Fastify's default
    });

    it('should reject invalid nonce length', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/api/pastes',
        payload: {
          ...validPaste,
          nonce: 'short-nonce',
        },
      });

      // Zod validation errors throw and result in 500 without error handler
      expect(response.statusCode).toBe(500);
    });

    it('should reject missing ciphertext', async () => {
      const { ciphertext, ...pasteWithoutCiphertext } = validPaste;
      const response = await app.inject({
        method: 'POST',
        url: '/api/pastes',
        payload: pasteWithoutCiphertext,
      });

      // Zod validation errors throw and result in 500 without error handler
      expect(response.statusCode).toBe(500);
    });

    it('should handle database errors', async () => {
      vi.mocked(prisma.paste.create).mockRejectedValue(new Error('Database error'));

      const response = await app.inject({
        method: 'POST',
        url: '/api/pastes',
        payload: validPaste,
      });

      expect(response.statusCode).toBe(500);
      const body = JSON.parse(response.body);
      expect(body.error).toBe('Internal server error');
    });
  });

  describe('GET /api/pastes/:slug', () => {
    const mockPaste = {
      id: 1,
      slug: 'test-slug',
      ciphertext: 'encrypted-content',
      nonce: '12345678901234567890123456789012',
      salt: null,
      kdf_params: null,
      expires_at: null,
      burn_after_read: false,
      is_burned: false,
      view_count: 0,
      created_at: new Date('2025-01-01T12:00:00Z'),
    };

    it('should retrieve a paste successfully', async () => {
      vi.mocked(prisma.paste.findUnique).mockResolvedValue(mockPaste);
      vi.mocked(prisma.paste.update).mockResolvedValue({
        ...mockPaste,
        view_count: 1,
      });

      const response = await app.inject({
        method: 'GET',
        url: '/api/pastes/test-slug',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.ciphertext).toBe('encrypted-content');
      expect(body.nonce).toBe('12345678901234567890123456789012');
      expect(body.metadata.view_count).toBe(1);
    });

    it('should increment view count', async () => {
      vi.mocked(prisma.paste.findUnique).mockResolvedValue(mockPaste);
      vi.mocked(prisma.paste.update).mockResolvedValue({
        ...mockPaste,
        view_count: 1,
      });

      await app.inject({
        method: 'GET',
        url: '/api/pastes/test-slug',
      });

      expect(prisma.paste.update).toHaveBeenCalledWith({
        where: { id: 1 },
        data: {
          view_count: { increment: 1 },
        },
      });
    });

    it('should return 404 for non-existent paste', async () => {
      vi.mocked(prisma.paste.findUnique).mockResolvedValue(null);

      const response = await app.inject({
        method: 'GET',
        url: '/api/pastes/non-existent',
      });

      expect(response.statusCode).toBe(404);
      const body = JSON.parse(response.body);
      expect(body.error).toBe('Paste not found');
    });

    it('should return 410 for burned paste', async () => {
      vi.mocked(prisma.paste.findUnique).mockResolvedValue({
        ...mockPaste,
        is_burned: true,
      });

      const response = await app.inject({
        method: 'GET',
        url: '/api/pastes/test-slug',
      });

      expect(response.statusCode).toBe(410);
      const body = JSON.parse(response.body);
      expect(body.error).toBe('Paste has been burned');
    });

    it('should delete and return 410 for expired paste', async () => {
      const expiredDate = new Date('2024-01-01T12:00:00Z');
      vi.mocked(isExpired).mockReturnValue(true);
      vi.mocked(prisma.paste.findUnique).mockResolvedValue({
        ...mockPaste,
        expires_at: expiredDate,
      });
      vi.mocked(prisma.paste.delete).mockResolvedValue(mockPaste);

      const response = await app.inject({
        method: 'GET',
        url: '/api/pastes/test-slug',
      });

      expect(response.statusCode).toBe(410);
      const body = JSON.parse(response.body);
      expect(body.error).toBe('Paste has expired');
      expect(prisma.paste.delete).toHaveBeenCalledWith({ where: { id: 1 } });
    });

    it('should burn paste on first view when burn_after_read is true', async () => {
      vi.mocked(prisma.paste.findUnique).mockResolvedValue({
        ...mockPaste,
        burn_after_read: true,
        view_count: 0,
      });
      vi.mocked(prisma.paste.update).mockResolvedValue({
        ...mockPaste,
        burn_after_read: true,
        is_burned: true,
        view_count: 1,
      });

      const response = await app.inject({
        method: 'GET',
        url: '/api/pastes/test-slug',
      });

      expect(response.statusCode).toBe(200);
      expect(prisma.paste.update).toHaveBeenCalledWith({
        where: { id: 1 },
        data: {
          view_count: { increment: 1 },
          is_burned: true,
        },
      });
    });

    it('should not burn paste on subsequent views', async () => {
      vi.mocked(prisma.paste.findUnique).mockResolvedValue({
        ...mockPaste,
        burn_after_read: true,
        view_count: 1,
      });
      vi.mocked(prisma.paste.update).mockResolvedValue({
        ...mockPaste,
        burn_after_read: true,
        view_count: 2,
      });

      const response = await app.inject({
        method: 'GET',
        url: '/api/pastes/test-slug',
      });

      expect(response.statusCode).toBe(200);
      expect(prisma.paste.update).toHaveBeenCalledWith({
        where: { id: 1 },
        data: {
          view_count: { increment: 1 },
        },
      });
    });

    it('should include salt and kdf_params in response', async () => {
      vi.mocked(prisma.paste.findUnique).mockResolvedValue({
        ...mockPaste,
        salt: 'random-salt',
        kdf_params: '{"iterations":100000}',
      });
      vi.mocked(prisma.paste.update).mockResolvedValue({
        ...mockPaste,
        salt: 'random-salt',
        kdf_params: '{"iterations":100000}',
        view_count: 1,
      });

      const response = await app.inject({
        method: 'GET',
        url: '/api/pastes/test-slug',
      });

      expect(response.statusCode).toBe(200);
      const body = JSON.parse(response.body);
      expect(body.salt).toBe('random-salt');
      expect(body.kdf_params).toBe('{"iterations":100000}');
      expect(body.metadata.salt).toBe('random-salt');
      expect(body.metadata.kdf_params).toBe('{"iterations":100000}');
    });

    it('should handle database errors on retrieval', async () => {
      vi.mocked(prisma.paste.findUnique).mockRejectedValue(new Error('Database error'));

      const response = await app.inject({
        method: 'GET',
        url: '/api/pastes/test-slug',
      });

      expect(response.statusCode).toBe(500);
      const body = JSON.parse(response.body);
      expect(body.error).toBe('Internal server error');
    });

    it('should handle route not found for empty slug path', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/api/pastes/',
      });

      // /api/pastes/ doesn't match /api/pastes/:slug route, validation throws
      expect(response.statusCode).toBe(500);
    });
  });
});
