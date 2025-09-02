# PasteVault

An open-source, E2EE pastebin with a VS Code-like editor


<img width="2880" height="1634" alt="CleanShot 2025-09-02 at 13 59 55@2x" src="https://github.com/user-attachments/assets/221c0d5d-825a-4366-9ba0-685b71060549" />


## Quickstart

### A) One command (Node.js)

Requirements: Node.js 18 or 20 and npm.

```bash
npx pastevault up
```

### B) Docker Compose (all-in-one)

Requirements: Docker and Docker Compose.

```bash
git clone https://github.com/arc53/pastevault.git
cd pastevault
docker compose -f docker-compose.all.yml up -d
```

- Frontend: http://localhost:3000
- Backend: http://localhost:3001

Shutdown:
```bash
docker compose -f docker-compose.all.yml down
```

## Features

- End-to-end encryption (XChaCha20-Poly1305) with client-side key generation
- Zero-knowledge: decryption key kept in URL fragment (#), never sent to server
- Optional password mode (PBKDF2) and per-paste expiry/burn-after-read
- Markdown support with code syntax highlighting
- Simple REST API with validation and rate limiting
- SQLite (default) or PostgreSQL storage

## Minimal configuration

Backend (.env):
```env
DATABASE_URL=postgresql://pastevault:pastevault_dev_password@localhost:5432/pastevault
DATABASE_PROVIDER=postgresql
PORT=3001
CORS_ORIGIN=http://localhost:3000
```

Frontend (.env.local):
```env
# Important: include /api at the end
NEXT_PUBLIC_API_URL=http://localhost:3001/api
```

## License

GNU General Public License v3.0
