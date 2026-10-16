// Runs every tests/e2e-*.mjs suite in turn (they share the generated Prisma
// client, so they must not run in parallel). Pass names to run a subset:
//   node tests/run-e2e.mjs tokens smoke
import { spawnSync } from 'node:child_process'
import { readdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const testsDirectory = fileURLToPath(new URL('.', import.meta.url))
const filters = process.argv.slice(2)
const suites = readdirSync(testsDirectory)
  .filter((name) => /^e2e-.+\.mjs$/.test(name))
  .filter((name) => filters.length === 0 || filters.some((filter) => name.includes(filter)))
  .sort()

if (suites.length === 0) {
  console.error('No e2e suites matched')
  process.exit(1)
}

for (const suite of suites) {
  console.log(`\n▶ ${suite}`)
  const result = spawnSync(process.execPath, [fileURLToPath(new URL(suite, import.meta.url))], {
    stdio: 'inherit',
  })
  if (result.status !== 0) {
    console.error(`✖ ${suite} failed`)
    process.exit(result.status ?? 1)
  }
}

console.log(`\nAll ${suites.length} e2e suites passed`)
