# PasteVault

A secure, end-to-end encrypted paste sharing platform with zero-knowledge architecture. Share code, text, and markdown securely with automatic expiry and burn-after-read options.

## 🚀 Installation

### NPX (Recommended)
```bash
# Run directly without installation
npx pastevault up
```

### Global Installation
```bash
# Install globally for repeated use
npm install -g pastevault
pastevault up
```

### From Source
```bash
# Clone and run locally
git clone https://github.com/arc53/pastevault.git
cd pastevault
npm install
npx pastevault up
```

## 🚀 Features

### Core Security
- **End-to-End Encryption**: XChaCha20-Poly1305 encryption with client-side key generation
- **Zero-Knowledge Architecture**: Server never sees plaintext content

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Frontend                             │
│  Next.js 14 + TypeScript + shadcn/ui + Tailwind             │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │           Client-Side Encryption                    │    │
│  │  • XChaCha20-Poly1305 encryption                    │    │
│  │  • PBKDF2 key derivation                            │    │
│  │  • Monaco editor with Markdown                      │    │
│  │  • Shiki syntax highlighting                        │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTPS + Encrypted Payloads
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                        Backend                              │
│              Fastify + TypeScript + Prisma                  │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              RESTful API                            │    │
│  │  • Paste storage (ciphertext only)                  │    │
│  │  • Metadata management                              │    │
│  │  • Rate limiting & validation                       │    │
│  │  • Automatic expiry cleanup                         │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────┬───────────────────────────────────┘
                          │
┌─────────────────────────▼───────────────────────────────────┐
│                     Database                                │
│          PostgreSQL (default) or SQLite                   │
│                                                             │
│  • Encrypted paste content (ciphertext)                     │
│  • Metadata (expiry, burn status, view counts)              │
│  • Salt & KDF parameters (password mode)                    │
│  • No plaintext content ever stored                         │
└─────────────────────────────────────────────────────────────┘
```

## 🔐 Security Model

### Encryption Flow

**Random Key Mode (Zero-Knowledge)**:
1. Generate random 32-byte key client-side
2. Encrypt content: `XChaCha20-Poly1305(content, key, nonce, aad)`
3. Send only ciphertext to server
4. Embed key in URL fragment: `#k=base64url(key)`
5. Fragment never sent to server logs

**Password Mode**:
1. Derive key: `PBKDF2(password, salt, 600k iterations)`
2. Store salt on server, key stays client-side
3. Same encryption, password-based decryption

### Associated Authenticated Data (AAD)
```
AAD = "pastevault:" + paste_id + ":v1"
```

Prevents:
- Ciphertext substitution attacks
- Cross-paste replay attacks  
- Version confusion attacks

## 🛠️ Quick Start

### One-Command Setup (Recommended)
No need to clone the repository! Just run:

```bash
npx pastevault up
```

That's it! This will:
- Download and install PasteVault automatically  
- Install all dependencies
- Set up SQLite database (no external dependencies)
- Build and serve the frontend
- Start the backend API
- Run everything on `http://localhost:3000`

> **Note**: The first run will take a bit longer as it downloads dependencies and builds the frontend. Subsequent runs will be much faster.

### Advanced Options

The CLI supports several options to customize your setup:

```bash
# Custom ports
npx pastevault up --port 8080     # Backend port
npx pastevault up --frontend-port 3002  # Frontend port

# Disable features
npx pastevault up --no-frontend  # Backend only
npx pastevault up --no-open     # Don't auto-open browser

# Example with all options
npx pastevault up --port 8080 --frontend-port 3002 --no-open
```

### Development Setup (For Contributors)

Want to contribute or modify PasteVault? Clone the repository for development:

```bash
git clone https://github.com/arc53/pastevault.git
cd pastevault
```

#### Prerequisites
- Node.js 18+
- PostgreSQL (via Docker) for production setups
- Or use SQLite for simple development/testing (no external dependencies)

#### 1. Start the Database
```bash
docker compose up -d
```

#### 2. Setup Backend
```bash
# Install dependencies
npm install

# Setup database
npm run db:push

# Start backend
npm run dev
```
Backend runs on `http://localhost:3001`

#### 3. Setup Frontend  
```bash
cd frontend

# Install dependencies
npm install

# Start frontend
npm run dev
```
Frontend runs on `http://localhost:3000`

### Create Your First Paste
1. Open your PasteVault instance (default: `http://localhost:3000`)
2. Enter your content (Markdown supported!)
3. Configure expiry and options
4. Click "Create Paste"
5. Share the generated URL securely

## 📁 Project Structure

```
pastevault/
├── README.md              # This file
├── docker-compose.yml     # PostgreSQL setup
├── package.json          # Backend dependencies
├── prisma/
│   └── schema.prisma     # Database schema
├── src/                  # Backend source
│   ├── index.ts         # Fastify server
│   ├── routes/          # API endpoints
│   ├── lib/             # Utilities & config
│   └── types/           # TypeScript definitions
└── frontend/            # Next.js frontend
    ├── package.json
    ├── src/
    │   ├── app/         # Next.js 14 App Router
    │   ├── components/  # React components
    │   ├── lib/         # Crypto & utilities
    │   ├── hooks/       # React hooks
    │   └── types/       # TypeScript definitions
    └── ...
```

## 🔧 Configuration

### Backend Environment (.env)
```env
# PostgreSQL (default)
DATABASE_URL="postgresql://pastevault:pastevault_dev_password@localhost:5432/pastevault"
DATABASE_PROVIDER="postgresql"

# SQLite (uncomment to use SQLite instead)
# DATABASE_URL="file:./pastevault.db"
# DATABASE_PROVIDER="sqlite"

PORT=3001
NODE_ENV=development
CORS_ORIGIN=http://localhost:3000
RATE_LIMIT_MAX=10
RATE_LIMIT_WINDOW_MS=60000
MAX_PASTE_SIZE_BYTES=1048576
CLEANUP_INTERVAL_MINUTES=60
```

### Frontend Environment (.env.local)
```env
NEXT_PUBLIC_API_URL=http://localhost:3001/api
```

## 🚀 Deployment

### Backend
```bash
npm run build
npm start
```

### Frontend
```bash
cd frontend
npm run build
npm start
```

### Database Migration
```bash
npm run db:migrate
```
