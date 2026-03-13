import 'dotenv/config'
import { join } from 'node:path'
import { defineConfig } from 'prisma/config'

const packageRoot = process.env.PASTEVAULT_PACKAGE_ROOT || process.cwd()
const provider = process.env.DATABASE_PROVIDER === 'postgresql' ? 'postgresql' : 'sqlite'

export default defineConfig({
  schema:
    provider === 'postgresql'
      ? join(packageRoot, 'prisma/schema.postgres.prisma')
      : join(packageRoot, 'prisma/schema.sqlite.prisma'),
  migrations: {
    path: join(packageRoot, 'prisma/migrations'),
  },
  datasource: {
    url: process.env.DATABASE_URL || 'file:./pastevault.db',
  },
})
