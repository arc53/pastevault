import { getPrisma, resolveDatabaseProvider } from './db.js'

// Runtime DDL helpers. SQLite deployments have no migrations, and Postgres
// servers can boot before `migrate deploy`, so every column or table the code
// reads is also created here. Definitions must match the Prisma schema and the
// Postgres migrations exactly, otherwise `prisma migrate diff` reports drift.

export function isPostgres() {
  return resolveDatabaseProvider() === 'postgresql'
}

// Prisma maps DateTime to TIMESTAMP(3) on Postgres.
export function timestampType() {
  return isPostgres() ? 'TIMESTAMP(3)' : 'TIMESTAMP'
}

async function listColumns(table: string) {
  const prisma = getPrisma()

  if (isPostgres()) {
    const rows = await prisma.$queryRaw<Array<{ column_name: string }>>`
      SELECT "column_name"
      FROM information_schema.columns
      WHERE "table_schema" = current_schema() AND "table_name" = ${table}
    `
    return new Set(rows.map((row) => row.column_name))
  }

  const rows = await prisma.$queryRawUnsafe<Array<{ name: string }>>(
    `PRAGMA table_info("${table}")`
  )
  return new Set(rows.map((row) => row.name))
}

// Adds any missing columns. Only ALTERs when a column is actually missing, so
// routine boots don't take an ACCESS EXCLUSIVE lock on Postgres. Table and
// column names come from code, never from requests.
export async function ensureColumns(
  table: string,
  columns: Array<[name: string, definition: string]>
) {
  const prisma = getPrisma()
  const existing = await listColumns(table)
  const ifNotExists = isPostgres() ? 'IF NOT EXISTS ' : ''

  for (const [name, definition] of columns) {
    if (existing.has(name)) {
      continue
    }

    try {
      await prisma.$executeRawUnsafe(
        `ALTER TABLE "${table}" ADD COLUMN ${ifNotExists}"${name}" ${definition}`
      )
    } catch (error: unknown) {
      // Another instance booting at the same time may have added it first.
      if (!(error instanceof Error && /duplicate column/i.test(error.message))) {
        throw error
      }
    }
  }
}

export async function ensureColumn(table: string, column: string, definition: string) {
  await ensureColumns(table, [[column, definition]])
}

// Both engines support partial indexes. Postgres stores the predicate
// normalised, so `where` should be written the way Prisma renders it.
export async function ensurePartialUniqueIndex(
  name: string,
  table: string,
  columns: string[],
  where: string
) {
  await getPrisma().$executeRawUnsafe(
    `CREATE UNIQUE INDEX IF NOT EXISTS "${name}" ON "${table}"(${columns
      .map((column) => `"${column}"`)
      .join(', ')}) WHERE ${where}`
  )
}
