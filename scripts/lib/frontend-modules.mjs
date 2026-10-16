// Loads the web app's TypeScript modules (frontend/src) in plain Node, so
// scripts and tests can exercise the exact code the browser runs. Resolves
// the frontend's "@/..." path alias and compiles TypeScript with tsx.
import { existsSync } from 'node:fs'
import { registerHooks } from 'node:module'
import path from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

export const frontendSource = fileURLToPath(new URL('../../frontend/src', import.meta.url))

let registered = false

async function ensureRegistered() {
  if (registered) {
    return
  }
  registered = true

  registerHooks({
    resolve(specifier, context, nextResolve) {
      if (specifier.startsWith('@/')) {
        const base = path.join(frontendSource, specifier.slice(2))
        for (const candidate of [`${base}.ts`, `${base}.tsx`, path.join(base, 'index.ts')]) {
          if (existsSync(candidate)) {
            // CommonJS resolution takes paths, ESM takes URLs.
            const isRequire = context.conditions?.includes('require')
            return nextResolve(isRequire ? candidate : pathToFileURL(candidate).href, context)
          }
        }
      }
      return nextResolve(specifier, context)
    },
  })

  const { register } = await import('tsx/esm/api')
  register({ tsconfig: false })
}

// importFrontend('lib/crypto.ts') imports frontend/src/lib/crypto.ts.
export async function importFrontend(relativePath) {
  await ensureRegistered()
  return import(pathToFileURL(path.join(frontendSource, relativePath)).href)
}
