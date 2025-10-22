import { describe, it, expect } from 'vitest';
import { createPasteSchema, getPasteParamsSchema } from './validation';

describe('createPasteSchema', () => {
  const validData = {
    ciphertext: 'encrypted_content',
    nonce: '12345678901234567890123456789012', // 32 chars
    burn_after_read: false,
  };

  describe('ciphertext validation', () => {
    it('should accept valid ciphertext', () => {
      const result = createPasteSchema.safeParse(validData);
      expect(result.success).toBe(true);
    });

    it('should reject empty ciphertext', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        ciphertext: '',
      });
      expect(result.success).toBe(false);
    });

    it('should reject missing ciphertext', () => {
      const { ciphertext, ...dataWithoutCiphertext } = validData;
      const result = createPasteSchema.safeParse(dataWithoutCiphertext);
      expect(result.success).toBe(false);
    });
  });

  describe('nonce validation', () => {
    it('should accept 32-character nonce', () => {
      const result = createPasteSchema.safeParse(validData);
      expect(result.success).toBe(true);
    });

    it('should reject nonce shorter than 32 characters', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        nonce: '1234567890123456789012345678901', // 31 chars
      });
      expect(result.success).toBe(false);
    });

    it('should reject nonce longer than 32 characters', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        nonce: '123456789012345678901234567890123', // 33 chars
      });
      expect(result.success).toBe(false);
    });

    it('should reject missing nonce', () => {
      const { nonce, ...dataWithoutNonce } = validData;
      const result = createPasteSchema.safeParse(dataWithoutNonce);
      expect(result.success).toBe(false);
    });
  });

  describe('slug validation', () => {
    it('should accept optional slug', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        slug: 'custom-slug',
      });
      expect(result.success).toBe(true);
    });

    it('should accept missing slug', () => {
      const result = createPasteSchema.safeParse(validData);
      expect(result.success).toBe(true);
    });

    it('should accept empty slug (will be validated elsewhere)', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        slug: '',
      });
      expect(result.success).toBe(true);
    });
  });

  describe('salt validation', () => {
    it('should accept optional salt', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        salt: 'random_salt',
      });
      expect(result.success).toBe(true);
    });

    it('should accept missing salt', () => {
      const result = createPasteSchema.safeParse(validData);
      expect(result.success).toBe(true);
    });
  });

  describe('kdf_params validation', () => {
    it('should accept optional kdf_params', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        kdf_params: '{"iterations":100000}',
      });
      expect(result.success).toBe(true);
    });

    it('should accept missing kdf_params', () => {
      const result = createPasteSchema.safeParse(validData);
      expect(result.success).toBe(true);
    });
  });

  describe('expires_in_hours validation', () => {
    it('should accept 1 hour (minimum)', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        expires_in_hours: 1,
      });
      expect(result.success).toBe(true);
    });

    it('should accept 8760 hours (maximum - 1 year)', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        expires_in_hours: 8760,
      });
      expect(result.success).toBe(true);
    });

    it('should accept hours in valid range', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        expires_in_hours: 24,
      });
      expect(result.success).toBe(true);
    });

    it('should reject 0 hours', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        expires_in_hours: 0,
      });
      expect(result.success).toBe(false);
    });

    it('should reject negative hours', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        expires_in_hours: -1,
      });
      expect(result.success).toBe(false);
    });

    it('should reject hours exceeding maximum (8761)', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        expires_in_hours: 8761,
      });
      expect(result.success).toBe(false);
    });

    it('should accept missing expires_in_hours (optional)', () => {
      const result = createPasteSchema.safeParse(validData);
      expect(result.success).toBe(true);
    });
  });

  describe('burn_after_read validation', () => {
    it('should accept true', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        burn_after_read: true,
      });
      expect(result.success).toBe(true);
    });

    it('should accept false', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        burn_after_read: false,
      });
      expect(result.success).toBe(true);
    });

    it('should default to false when missing', () => {
      const { burn_after_read, ...dataWithoutBurn } = validData;
      const result = createPasteSchema.safeParse(dataWithoutBurn);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.burn_after_read).toBe(false);
      }
    });

    it('should reject non-boolean values', () => {
      const result = createPasteSchema.safeParse({
        ...validData,
        burn_after_read: 'true',
      });
      expect(result.success).toBe(false);
    });
  });

  describe('complete valid paste', () => {
    it('should accept all fields populated', () => {
      const completeData = {
        ciphertext: 'encrypted_content',
        nonce: '12345678901234567890123456789012',
        slug: 'my-custom-slug',
        salt: 'random_salt_value',
        kdf_params: '{"iterations":100000}',
        expires_in_hours: 24,
        burn_after_read: true,
      };
      const result = createPasteSchema.safeParse(completeData);
      expect(result.success).toBe(true);
    });
  });
});

describe('getPasteParamsSchema', () => {
  it('should accept valid slug', () => {
    const result = getPasteParamsSchema.safeParse({ slug: 'valid-slug' });
    expect(result.success).toBe(true);
  });

  it('should reject empty slug', () => {
    const result = getPasteParamsSchema.safeParse({ slug: '' });
    expect(result.success).toBe(false);
  });

  it('should reject missing slug', () => {
    const result = getPasteParamsSchema.safeParse({});
    expect(result.success).toBe(false);
  });

  it('should accept slug with special characters', () => {
    const result = getPasteParamsSchema.safeParse({ slug: 'slug-with_chars123' });
    expect(result.success).toBe(true);
  });

  it('should accept long slug', () => {
    const result = getPasteParamsSchema.safeParse({
      slug: 'a'.repeat(100),
    });
    expect(result.success).toBe(true);
  });
});
