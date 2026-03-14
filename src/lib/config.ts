import path from 'node:path'
import { z } from 'zod'
import dotenv from 'dotenv'

dotenv.config()

const defaultNodeEnv =
  process.env.NODE_ENV === 'production' || process.env.NODE_ENV === 'test'
    ? process.env.NODE_ENV
    : 'development'

const configSchema = z.object({
  DATABASE_URL: z.string().default('file:./pastevault.db'),
  DATABASE_PROVIDER: z.enum(['postgresql', 'sqlite']).default('sqlite'),
  DATA_DIR: z
    .string()
    .default(path.resolve(process.cwd(), 'data'))
    .transform((value) => path.resolve(value)),
  PORT: z.string().default('3001').transform(Number),
  NODE_ENV: z.enum(['development', 'production', 'test']).default(defaultNodeEnv),
  CORS_ORIGIN: z
    .string()
    .default(defaultNodeEnv === 'production' ? 'http://localhost:3000' : 'http://localhost:3002'),
  RATE_LIMIT_MAX: z.string().default('10').transform(Number),
  RATE_LIMIT_WINDOW_MS: z.string().default('60000').transform(Number),
  MAX_PASTE_SIZE_BYTES: z.string().default('1048576').transform(Number),
  MAX_FILE_SHARE_SIZE_BYTES: z.string().default('10737418240').transform(Number),
  MAX_FILE_SHARE_FILES: z.string().default('25').transform(Number),
  FILE_CHUNK_SIZE_BYTES: z.string().default('8388608').transform(Number),
  CLEANUP_INTERVAL_MINUTES: z.string().default('60').transform(Number),
  S3_ENDPOINT: z.string().optional(),
  S3_REGION: z.string().default('us-east-1'),
  S3_BUCKET: z.string().optional(),
  S3_ACCESS_KEY_ID: z.string().optional(),
  S3_SECRET_ACCESS_KEY: z.string().optional(),
  BETTER_AUTH_URL: z.string().optional(),
  BETTER_AUTH_TRUSTED_ORIGINS: z.string().optional(),
  S3_FORCE_PATH_STYLE: z
    .string()
    .default('true')
    .transform((value) => value === 'true'),
})

export const config = configSchema.parse(process.env)
