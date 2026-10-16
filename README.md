# PasteVault

An open-source, E2EE pastebin with a VS Code-like editor


<img width="2880" height="1634" alt="CleanShot 2025-09-02 at 13 59 55@2x" src="https://github.com/user-attachments/assets/221c0d5d-825a-4366-9ba0-685b71060549" />


## Quickstart

### A) Share or download files from the terminal

macOS/Linux:

```bash
curl -fsSL https://raw.githubusercontent.com/arc53/pastevault/main/scripts/install.sh | sh
```

Windows PowerShell:

```powershell
irm https://raw.githubusercontent.com/arc53/pastevault/main/scripts/install.ps1 | iex
```

Usage:

```bash
pastevault login
pastevault put ./report.pdf
pastevault put --burn --expires 1h ./secret.txt
echo "some text" | pastevault put -
pastevault get https://your-server.example/f/abc123#k=yourkey
pastevault get abc123#k=yourkey --stdout
pastevault whoami
pastevault logout
```

Every command, flag, JSON output shape and exit code is listed in [docs/cli-reference.md](docs/cli-reference.md).

The native CLI talks to `https://api.pastevault.dev` by default and emits public share links on `https://pastevault.dev`. `pastevault login` uses a browser link or short code flow on `/device`, and logged-in CLI uploads show up later in the web account dashboard. Override the defaults with `PASTEVAULT_SERVER`, `PASTEVAULT_PUBLIC_URL`, or `--server` when testing against another deployment.

### Native CLI updates

Direct binary installs check for a signed release in the background at most once a day. A verified update is staged without delaying the current command and installed on the next invocation. Homebrew-managed and non-writable installations only show a notification.

```bash
pastevault update                         # Check, confirm, and install now
pastevault update --check                 # Check without installing
pastevault update --yes                   # Install without confirmation
pastevault update --rollback              # Restore the previous binary
pastevault config set-auto-update on      # Automatic staging/installing (default)
pastevault config set-auto-update notify  # Notify only
pastevault config set-auto-update off     # Disable update checks
```

Set `PASTEVAULT_NO_UPDATE_CHECK=1` to suppress passive checks for a particular environment. Automatic update output is written to stderr so machine-readable command output remains clean.

### B) One command self-hosting (Node.js)

Requirements: Node.js 22.13+ or 24+ and npm.

```bash
npx pastevault up
```

### C) Docker Compose (all-in-one)

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
- Native Go client for terminal upload/download workflows
- Markdown support with code syntax highlighting
- Simple REST API with validation and rate limiting
- SQLite (default) or PostgreSQL storage

## CLI install paths

- Native client: `curl | sh` on macOS/Linux, `irm | iex` on Windows
- Self-hosted server launcher: `npx pastevault up`
- Homebrew: `brew install --cask arc53/DocsGPT-cli/pastevault`
- Distribution details are documented in [docs/distribution.md](./docs/distribution.md)

## Minimal configuration

Backend (.env):
```env
DATABASE_URL=postgresql://pastevault:pastevault_dev_password@localhost:5432/pastevault
DATABASE_PROVIDER=postgresql
PORT=3001
CORS_ORIGIN=http://localhost:3000
DISABLE_SIGNUP=false
DISABLE_AUTH=false
```

Set `DISABLE_SIGNUP=true` to keep existing account sign-in available while preventing new
registrations. Set `DISABLE_AUTH=true` to run without authentication, account routes, or account UI.

Frontend (.env.local):
```env
# Important: include /api at the end
NEXT_PUBLIC_API_URL=http://localhost:3001/api
```

## License

GNU General Public License v3.0
