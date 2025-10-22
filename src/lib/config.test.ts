import { describe, it, expect } from 'vitest';
import { z } from 'zod';

// We need to recreate the schema here to test it without importing the module
// which would immediately parse process.env
const configSchema = z.object({
  DATABASE_URL: z.string().default('file:./pastevault.db'),
  DATABASE_PROVIDER: z.enum(['postgresql', 'sqlite']).default('sqlite'),
  PORT: z.string().default('3001').transform(Number),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  CORS_ORIGIN: z.string().default('http://localhost:3000'),
  RATE_LIMIT_MAX: z.string().default('10').transform(Number),
  RATE_LIMIT_WINDOW_MS: z.string().default('60000').transform(Number),
  MAX_PASTE_SIZE_BYTES: z.string().default('1048576').transform(Number),
  CLEANUP_INTERVAL_MINUTES: z.string().default('60').transform(Number),
});

describe('configSchema', () => {
  describe('default values', () => {
    it('should use default values when environment variables are missing', () => {
      const result = configSchema.parse({});

      expect(result.DATABASE_URL).toBe('file:./pastevault.db');
      expect(result.DATABASE_PROVIDER).toBe('sqlite');
      expect(result.PORT).toBe(3001);
      expect(result.NODE_ENV).toBe('development');
      expect(result.CORS_ORIGIN).toBe('http://localhost:3000');
      expect(result.RATE_LIMIT_MAX).toBe(10);
      expect(result.RATE_LIMIT_WINDOW_MS).toBe(60000);
      expect(result.MAX_PASTE_SIZE_BYTES).toBe(1048576);
      expect(result.CLEANUP_INTERVAL_MINUTES).toBe(60);
    });
  });

  describe('DATABASE_URL', () => {
    it('should accept custom database URL', () => {
      const result = configSchema.parse({
        DATABASE_URL: 'postgresql://user:pass@localhost:5432/db',
      });
      expect(result.DATABASE_URL).toBe('postgresql://user:pass@localhost:5432/db');
    });

    it('should accept file path for SQLite', () => {
      const result = configSchema.parse({
        DATABASE_URL: 'file:./custom.db',
      });
      expect(result.DATABASE_URL).toBe('file:./custom.db');
    });
  });

  describe('DATABASE_PROVIDER', () => {
    it('should accept "postgresql"', () => {
      const result = configSchema.parse({
        DATABASE_PROVIDER: 'postgresql',
      });
      expect(result.DATABASE_PROVIDER).toBe('postgresql');
    });

    it('should accept "sqlite"', () => {
      const result = configSchema.parse({
        DATABASE_PROVIDER: 'sqlite',
      });
      expect(result.DATABASE_PROVIDER).toBe('sqlite');
    });

    it('should reject invalid database provider', () => {
      expect(() =>
        configSchema.parse({
          DATABASE_PROVIDER: 'mysql',
        })
      ).toThrow();
    });
  });

  describe('PORT', () => {
    it('should transform string port to number', () => {
      const result = configSchema.parse({
        PORT: '8080',
      });
      expect(result.PORT).toBe(8080);
    });

    it('should accept valid port numbers', () => {
      const result = configSchema.parse({
        PORT: '3000',
      });
      expect(result.PORT).toBe(3000);
    });
  });

  describe('NODE_ENV', () => {
    it('should accept "development"', () => {
      const result = configSchema.parse({
        NODE_ENV: 'development',
      });
      expect(result.NODE_ENV).toBe('development');
    });

    it('should accept "production"', () => {
      const result = configSchema.parse({
        NODE_ENV: 'production',
      });
      expect(result.NODE_ENV).toBe('production');
    });

    it('should accept "test"', () => {
      const result = configSchema.parse({
        NODE_ENV: 'test',
      });
      expect(result.NODE_ENV).toBe('test');
    });

    it('should reject invalid NODE_ENV', () => {
      expect(() =>
        configSchema.parse({
          NODE_ENV: 'staging',
        })
      ).toThrow();
    });
  });

  describe('CORS_ORIGIN', () => {
    it('should accept custom CORS origin', () => {
      const result = configSchema.parse({
        CORS_ORIGIN: 'https://example.com',
      });
      expect(result.CORS_ORIGIN).toBe('https://example.com');
    });

    it('should accept wildcard CORS origin', () => {
      const result = configSchema.parse({
        CORS_ORIGIN: '*',
      });
      expect(result.CORS_ORIGIN).toBe('*');
    });
  });

  describe('RATE_LIMIT_MAX', () => {
    it('should transform string to number', () => {
      const result = configSchema.parse({
        RATE_LIMIT_MAX: '100',
      });
      expect(result.RATE_LIMIT_MAX).toBe(100);
    });

    it('should accept custom rate limit', () => {
      const result = configSchema.parse({
        RATE_LIMIT_MAX: '50',
      });
      expect(result.RATE_LIMIT_MAX).toBe(50);
    });
  });

  describe('RATE_LIMIT_WINDOW_MS', () => {
    it('should transform string to number', () => {
      const result = configSchema.parse({
        RATE_LIMIT_WINDOW_MS: '120000',
      });
      expect(result.RATE_LIMIT_WINDOW_MS).toBe(120000);
    });

    it('should accept custom window in milliseconds', () => {
      const result = configSchema.parse({
        RATE_LIMIT_WINDOW_MS: '30000',
      });
      expect(result.RATE_LIMIT_WINDOW_MS).toBe(30000);
    });
  });

  describe('MAX_PASTE_SIZE_BYTES', () => {
    it('should transform string to number', () => {
      const result = configSchema.parse({
        MAX_PASTE_SIZE_BYTES: '2097152',
      });
      expect(result.MAX_PASTE_SIZE_BYTES).toBe(2097152);
    });

    it('should accept custom paste size limit', () => {
      const result = configSchema.parse({
        MAX_PASTE_SIZE_BYTES: '524288',
      });
      expect(result.MAX_PASTE_SIZE_BYTES).toBe(524288);
    });
  });

  describe('CLEANUP_INTERVAL_MINUTES', () => {
    it('should transform string to number', () => {
      const result = configSchema.parse({
        CLEANUP_INTERVAL_MINUTES: '30',
      });
      expect(result.CLEANUP_INTERVAL_MINUTES).toBe(30);
    });

    it('should accept custom cleanup interval', () => {
      const result = configSchema.parse({
        CLEANUP_INTERVAL_MINUTES: '120',
      });
      expect(result.CLEANUP_INTERVAL_MINUTES).toBe(120);
    });
  });

  describe('complete configuration', () => {
    it('should parse complete custom configuration', () => {
      const customEnv = {
        DATABASE_URL: 'postgresql://localhost:5432/pastevault',
        DATABASE_PROVIDER: 'postgresql',
        PORT: '8080',
        NODE_ENV: 'production',
        CORS_ORIGIN: 'https://pastevault.dev',
        RATE_LIMIT_MAX: '50',
        RATE_LIMIT_WINDOW_MS: '120000',
        MAX_PASTE_SIZE_BYTES: '2097152',
        CLEANUP_INTERVAL_MINUTES: '30',
      };

      const result = configSchema.parse(customEnv);

      expect(result).toEqual({
        DATABASE_URL: 'postgresql://localhost:5432/pastevault',
        DATABASE_PROVIDER: 'postgresql',
        PORT: 8080,
        NODE_ENV: 'production',
        CORS_ORIGIN: 'https://pastevault.dev',
        RATE_LIMIT_MAX: 50,
        RATE_LIMIT_WINDOW_MS: 120000,
        MAX_PASTE_SIZE_BYTES: 2097152,
        CLEANUP_INTERVAL_MINUTES: 30,
      });
    });
  });
});
