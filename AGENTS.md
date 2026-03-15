# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project Overview

PasteVault is a secure end-to-end encrypted paste sharing application built with TypeScript. It's structured as a monorepo with two main components:

- **Backend**: Fastify server (`src/`) providing REST API with encryption support
- **Frontend**: Next.js application (`frontend/`) with Monaco editor and crypto functionality  
- **CLI**: Single command deployment (`npx pastevault up`)

## Development Commands

### Backend Development
- `npm run dev` - Start backend in watch mode (port 3001)
- `npm run build` - Compile TypeScript to `dist/`
- `npm run typecheck` - Run TypeScript type checking
- `npm run lint` - Run ESLint on backend code

### Frontend Development  
- `cd frontend && npm run dev` - Start frontend dev server (port 3002)
- `cd frontend && npm run build` - Build Next.js production bundle
- `cd frontend && npm run typecheck` - Type check frontend code
- `cd frontend && npm run lint` - Run ESLint on frontend code

### Full Stack Build
- `npm run build:cli` - Build both backend and frontend for distribution
- `npm run build:frontend` - Build only frontend from root

### Database Operations
- `npm run db:push` - Push schema changes to database
- `npm run db:migrate` - Run database migrations  
- `npm run db:generate` - Generate Prisma client

### CLI Usage
- `npx pastevault up` - Start complete application (backend + frontend)
- `npx pastevault up --port 3000 --host 0.0.0.0` - Custom port/host
- `npx pastevault version` - Show version information

## Architecture

### Backend (`src/`)
- **Entry Point**: `src/index.ts` - Basic Fastify server
- **CLI Entry**: `src/cli.ts` - CLI with integrated Next.js frontend serving
- **Routes**: `src/routes/pastes.ts` - REST API endpoints for paste operations
- **Database**: `src/lib/db.ts` - Prisma client setup
- **Config**: `src/lib/config.ts` - Environment configuration
- **Utils**: `src/lib/utils.ts` - Slug generation, date utilities
- **Validation**: `src/lib/validation.ts` - Zod schemas for request validation
- **Cleanup**: `src/lib/cleanup.ts` - Cron job for expired paste cleanup

### Frontend (`frontend/src/`)
- **Framework**: Next.js 14 with App Router
- **UI**: Radix UI components + Tailwind CSS + shadcn/ui patterns
- **Editor**: Monaco Editor for code editing with syntax highlighting
- **Crypto**: `frontend/src/lib/crypto.ts` - Client-side XChaCha20-Poly1305 encryption
- **API**: `frontend/src/lib/api.ts` - API client with React Query integration
- **State**: React Query for server state, local storage for drafts
- **i18n**: next-intl for internationalization support

### Database Schema (`prisma/schema.prisma`)
```prisma
model Paste {
  id             String   @id @default(cuid())
  slug           String   @unique
  ciphertext     String   // Base64 encrypted content
  nonce          String   // Base64 encryption nonce
  salt           String?  // Base64 salt for password-based encryption
  kdf_params     String?  // JSON KDF parameters
  created_at     DateTime @default(now())
  expires_at     DateTime?
  burn_after_read Boolean  @default(false)
  is_burned      Boolean  @default(false)
  view_count     Int      @default(0)
}
```

### Encryption Architecture
- **Algorithm**: XChaCha20-Poly1305 with authenticated encryption
- **Key Storage**: Decryption keys stored in URL fragment (`#k=...`) - never sent to server
- **Password Mode**: PBKDF2 key derivation (600,000 iterations) with server-stored salt
- **Associated Data**: Includes paste ID and version for additional security
- **Zero Knowledge**: Server never has access to plaintext or decryption keys

### Configuration

#### Environment Variables (Backend)
```env
DATABASE_URL=file:./prisma/pastevault.db  # SQLite default
DATABASE_PROVIDER=sqlite                   # or "postgresql"  
PORT=3001
CORS_ORIGIN=http://localhost:3000
RATE_LIMIT_MAX=2000
RATE_LIMIT_WINDOW_MS=60000
MAX_PASTE_SIZE_BYTES=1048576
CLEANUP_INTERVAL_MINUTES=60
```

#### Environment Variables (Frontend)
```env
NEXT_PUBLIC_API_URL=http://localhost:3001/api
```

### Key Dependencies
- **@noble/ciphers**: Cryptographic primitives
- **@prisma/client**: Database ORM  
- **@monaco-editor/react**: VS Code-like editor
- **@tanstack/react-query**: Server state management
- **fastify**: High-performance web framework
- **next-intl**: Internationalization
- **zod**: Runtime type validation

## Development Workflow

1. **Database Setup**: Run `npm run db:push` to initialize database
2. **Backend**: Run `npm run dev` for API server
3. **Frontend**: Run `cd frontend && npm run dev` for Next.js app
4. **Full Stack**: Use `npx pastevault up` for integrated development
5. **Type Safety**: Always run `npm run typecheck` and `cd frontend && npm run typecheck`
6. **Linting**: Run `npm run lint` and `cd frontend && npm run lint`

## Testing

No automated tests are currently configured. Manual testing workflow:
1. Create paste via frontend or API
2. Verify encryption/decryption works
3. Test expiry and burn-after-read functionality
4. Check different content types (code, markdown, plain text)

## Deployment

- **CLI Distribution**: `npm run prepublishOnly` builds for npm package
- **Docker**: Use `docker-compose.all.yml` for containerized deployment
- **Manual**: Build with `npm run build:cli` and run `node dist/cli.js up`
