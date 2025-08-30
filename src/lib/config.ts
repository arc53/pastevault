import { z } from 'zod'
import dotenv from 'dotenv'

dotenv.config()

const configSchema = z.object({
  DATABASE_URL: z.string(),
  DATABASE_PROVIDER: z.enum(['postgresql', 'sqlite']).default('postgresql'),
  PORT: z.string().default('3001').transform(Number),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  CORS_ORIGIN: z.string().default('http://localhost:3000'),
  RATE_LIMIT_MAX: z.string().default('10').transform(Number),
  RATE_LIMIT_WINDOW_MS: z.string().default('60000').transform(Number),
  MAX_PASTE_SIZE_BYTES: z.string().default('1048576').transform(Number),
  CLEANUP_INTERVAL_MINUTES: z.string().default('60').transform(Number),
})

export const config = configSchema.parse(process.env)
