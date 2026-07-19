# CLI Distribution

The native PasteVault client is released from `./cmd/pastevault` using GoReleaser and published as GitHub release artifacts via `.goreleaser.yaml`.

## Supported install paths

- macOS/Linux quick install: `curl -fsSL https://raw.githubusercontent.com/arc53/pastevault/main/scripts/install.sh | sh`
- Windows PowerShell quick install: `irm https://raw.githubusercontent.com/arc53/pastevault/main/scripts/install.ps1 | iex`
- Existing self-hosting path: `npx pastevault up`
- Homebrew: `brew install --cask arc53/DocsGPT-cli/pastevault`

## Signed releases and auto-update

The native CLI accepts automatic updates only when `checksums.txt` has a valid minisign signature. GoReleaser embeds the signing public key in every release binary and publishes the detached signature as `checksums.txt.minisig`.

The release workflow requires one repository secret:

- `PASTEVAULT_MINISIGN_PRIVATE_KEY`: the complete unencrypted minisign private-key text. This key must never be committed to the repository.

Generate the signing identity on a trusted offline machine:

```bash
go run ./cmd/pastevault-release-sign generate ./pastevault-release.key ./pastevault-release.pub
gh secret set PASTEVAULT_MINISIGN_PRIVATE_KEY --repo arc53/pastevault < ./pastevault-release.key
```

Keep an offline backup of both files, then remove the working copy of the private key. Losing the private key prevents older PasteVault binaries from authenticating newer releases. The current updater embeds one public key; rotation therefore requires adding dual-key verification first and shipping that transition in a release signed by the old key.

During a release, the workflow derives the public key from the secret, passes it to the Go linker, signs `checksums.txt`, and uploads the signature with the platform archives. Release creation fails when the signing secret is missing or invalid.

## Homebrew Tap

The Homebrew cask is published to [`arc53/homebrew-DocsGPT-cli`](https://github.com/arc53/homebrew-DocsGPT-cli). GoReleaser auto-updates the cask on each release.

### Setup

1. Generate a fine-grained PAT scoped to `arc53/homebrew-DocsGPT-cli` with **Contents: Read and write**
2. Add the PAT as `HOMEBREW_TAP_TOKEN` secret in `arc53/pastevault` repo settings
3. The `homebrew_casks:` block in `.goreleaser.yaml` and `HOMEBREW_TAP_TOKEN` env in `release-cli.yml` handle the rest

### Install command

```
brew install --cask arc53/DocsGPT-cli/pastevault
```
