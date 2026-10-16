# PasteVault CLI reference

The native `pastevault` CLI (`cmd/pastevault`) shares text and files end-to-end encrypted. Content is encrypted before it leaves your machine; the key travels in the link's `#k=` fragment, which is never sent to the server.

This page covers the commands, flags, JSON output, exit codes and environment variables. Scripts and agents should use `--json` and the exit codes, never parse human output.

## Global behaviour

Every command that talks to a server accepts:

| Flag | Meaning |
|---|---|
| `--server URL` | Server base URL. Default: `$PASTEVAULT_SERVER`, else `https://api.pastevault.dev`. |
| `--json` | Print exactly one JSON object on stdout. Also enabled by `PASTEVAULT_JSON=1`. |
| `-q`, `--quiet` | Print only the essential result (for `put`, just the URL). |

- Flags may appear before or after positional arguments (`pastevault put notes.txt --json`). Everything after `--` is positional, which is how you pass a slug that starts with `-`: `pastevault get -- -abc123`.
- Results go to stdout. Progress, notices and warnings go to stderr.
- With `--json`, a failure prints `{"error":{"code":"…","message":"…","exit_code":N}}` on stdout and a one-line `Error: …` on stderr.
- Passive update checks never run when stderr is not a terminal, nor for `update`, `config`, `mcp` and `run`. `PASTEVAULT_NO_UPDATE_CHECK=1` disables them entirely.

### Credentials

Commands use the first credential that applies:

1. `PASTEVAULT_TOKEN`, an API token. It is sent **only** to the configured server (`--server` / `PASTEVAULT_SERVER`), never to another host named in a share URL.
2. An API token stored by `pastevault login --with-token`.
3. The login session stored by `pastevault login` (browser approval).

Credentials live in `auth.json` in the config directory: `$PASTEVAULT_CONFIG_DIR`, else `<user config dir>/pastevault` (for example `~/.config/pastevault` on Linux). The directory is created `0700` and the file is written `0600`. The auto-update settings (`pastevault config`) are not affected by `PASTEVAULT_CONFIG_DIR`.

Managing API tokens (`token create|list|revoke`) needs the **login session**. The server refuses token management with an API token, so a leaked token cannot mint new tokens or extend itself.

## Exit codes

| Code | Meaning | JSON `error.code` |
|---|---|---|
| 0 | OK | |
| 1 | Unexpected or internal error | `internal` |
| 2 | Usage or flag error; invalid request (HTTP 400); too large (413); missing key or password | `usage`, `invalid_request`, `too_large`, `key_required`, `password_required` |
| 3 | Authentication: not logged in, 401, 403, missing scope, session required | `auth`, `not_logged_in`, `session_required` |
| 4 | Not found (404) | `not_found` |
| 5 | Gone: burned, expired or revoked (410); a share that stops existing while `status --wait` waits | `gone` |
| 6 | Request declined or cancelled (secret requests, future) | `declined` |
| 7 | Decryption or integrity failure: wrong key or password, tampering, sealed share you cannot open | `decrypt_failed`, `sealed_share` |
| 8 | Fingerprint or pin mismatch (agents, future) | `fingerprint_mismatch` |
| 9 | Timeout (`status --wait`, login code expiry) | `timeout` |
| 10 | Rate limited (429) | `rate_limited` |
| 11 | Network or server error (5xx, connection failure) | `network` |
| 12 | Conflict (409) | `conflict` |
| 13 | Local file exists, or a path cannot be used | `local_file` |
| 14 | The server lacks a required feature | `unsupported` |
| 130 | Interrupted (Ctrl-C) | `interrupted` |

## Environment variables

| Variable | Meaning |
|---|---|
| `PASTEVAULT_SERVER` | Default server base URL. |
| `PASTEVAULT_PUBLIC_URL` | Base URL for printed links, when the web app is not at the server URL minus `api.`/`/api`. |
| `PASTEVAULT_TOKEN` | API token (`pv_pat_…`), used only for the configured server. |
| `PASTEVAULT_PASSWORD` | Share password for `get`, and for `put --password` (instead of a prompt). |
| `PASTEVAULT_CONFIG_DIR` | Directory for `auth.json`. |
| `PASTEVAULT_JSON` | `1` turns on `--json` for every command. |
| `PASTEVAULT_NO_UPDATE_CHECK` | Disables passive update checks. |

## `put`: share text or files

```
pastevault put [flags] [<file>... | -]
```

Input:

- `-`, or no arguments while stdin is not a terminal: share stdin as a paste (UTF-8 text, up to the server's paste limit, 1 MiB by default).
- `--text STR`: share STR as a paste. It is visible in the process list and shell history (the CLI warns); prefer stdin.
- File paths: one or more files.

Paste or file share (`--as auto|paste|files`, default `auto`):

- `auto`: a single file named like `.env`, `.env.local` or `prod.env` that fits the paste limit becomes a paste (title = file name, `render_mode` `plain`, `language_hint` `bash`). Everything else is a file share.
- `paste`: exactly one UTF-8 text file becomes a paste.
- `files`: always a file share.

Pastes are created in the same `/p/` format as the web app, so the browser opens them. Stdin and `--text` pastes default to `plain` without a language hint.

| Flag | Meaning |
|---|---|
| `--title T` | Paste title (default: the file name, or empty). |
| `--format plain\|markdown` | Paste rendering (default `plain`). |
| `--language L` | Syntax highlighting hint for plain pastes, e.g. `go`, `bash`. |
| `--expires D` | Lifetime: `15m`, `2h`, `7d` (1 minute to 365 days). Default `24h`. |
| `--expires-hours N` | Deprecated alias for `--expires Nh` (prints a warning). |
| `--max-views N` | Destroy the share after N views (1–1000). |
| `--burn` | Same as `--max-views 1`. `--burn-after-read` is an alias. |
| `--password` | Password-protect. The password comes from `--password-file`, else `PASTEVAULT_PASSWORD`, else a terminal prompt. `PASTEVAULT_PASSWORD` alone never turns protection on. |
| `--password-file F` | Password-protect with the password in F (one trailing newline is ignored). |
| `--key-out F` | Also write the share key (base64url) to the new file F, mode `0600`. Refuses an existing file. |
| `--no-key-in-output` | Print the link without `#k=`. Requires `--key-out`. |

Older servers: without `expires_in_minutes` support, whole-hour expiries are sent as hours and anything else exits 14. Without `max_views` support, `--max-views` above 1 exits 14.

Human output: the link on stdout, then a `pastevault get …` line (omitted with `-q`); notices on stderr.

JSON output:

```json
{
  "slug": "Vb3kq9TQx2Zp",
  "kind": "paste",
  "url": "https://pastevault.dev/p/Vb3kq9TQx2Zp#k=…",
  "key_in_url": true,
  "key_file": "share.key",
  "expires_at": "2026-10-17T12:00:00.000Z",
  "max_views": 1,
  "burn_after_read": true,
  "recipient": null,
  "password_protected": false,
  "file_count": 2,
  "total_size_bytes": 20009
}
```

`kind` is `paste` or `file_share`. `key_file` appears with `--key-out`. `file_count` and `total_size_bytes` appear for file shares. `recipient` is reserved for shares sealed to an agent (`{name, fingerprint}`) and is `null` otherwise.

## `get`: open a share

```
pastevault get [flags] <ref>
```

References:

- `https://host/p/<slug>#k=KEY` (paste) or `https://host/f/<slug>#k=KEY` (file share). A link on the default web origin is fetched from `--server`; any other host is contacted directly.
- `<slug>#k=KEY` or a bare `<slug>` on `--server`. Bare references try pastes first, then file shares.
- `pv://share/<slug>[?server=HOST][#k=KEY]`.

`get` always reads the share's metadata first. A missing key or password, an output path that cannot be written, or a sealed share all fail **before** a view is consumed, so a burn-after-read share is not wasted.

| Flag | Meaning |
|---|---|
| `--key-file F` | Read the key from F (the bare key, `k=KEY`, or a link with `#k=`). |
| `--key-env VAR` | Read the key from environment variable VAR. |
| `--key-stdin` | Read the key from stdin. |
| `--key KEY` | Deprecated: the key is visible in the process list and shell history (prints a warning). |
| `--password` | Prompt for the password. Password-protected shares also prompt automatically on a terminal. |
| `--password-file F` | Read the password from F. `PASTEVAULT_PASSWORD` also works. |
| `--stdout` | Write the content to stdout (pastes, or a file share with exactly one file). |
| `-o F`, `--output F` | Write the paste, or the only file of a share, to the new file F (mode `0600`). |
| `--out DIR` | Write into DIR. Pastes are named after their title when it is a plain file name (e.g. `.env`), else `<slug>.txt`/`.md`. File shares default to the current directory. |
| `--overwrite` | Replace existing files. Without it, `-o` refuses an existing file (exit 13, checked before opening). With `--out`, a paste is saved as `name (1)` instead; a file share is renamed the same way once the open burned it, and otherwise fails with exit 13. |

Pastes go to stdout by default. With `--json`, a paste needs an explicit destination: `--stdout` (the content is then included as `content`), `-o` or `--out`. This is checked before the paste is opened.

On a terminal, a wrong password for a share that the open just burned can be retried twice.

JSON output (paste with `--stdout`):

```json
{
  "slug": "Vb3kq9TQx2Zp",
  "kind": "paste",
  "title": "deploy notes",
  "render_mode": "plain",
  "language_hint": "bash",
  "size_bytes": 42,
  "view_count": 1,
  "max_views": 2,
  "views_remaining": 1,
  "burned": false,
  "expires_at": "2026-10-17T12:00:00.000Z",
  "content": "…"
}
```

File shares add `files: [{name, size, path}]` and `written_to`, and never include content.

## `list`: shares you own

```
pastevault list [--type paste|files] [--status S] [--limit N] [--cursor C]
```

Needs credentials with the `shares:read` scope. `--status` is one of `active`, `burned`, `expired`, `deleted`, `uploading`, `abandoned`. `--limit` defaults to 50 (max 200).

JSON: `{"shares":[{id, share_type, slug, status, created_at, expires_at, view_count, max_views, burn_after_read, is_password_protected, file_count, total_size_bytes, first_viewed_at, last_viewed_at, recipient_fingerprint, recipient_agent_name, can_delete, deleted_at}], "next_cursor": "…"|null}`. An active share past its expiry is reported as `expired`.

## `revoke`: delete shares you own

```
pastevault revoke <slug | url | id>...
```

Needs `shares:revoke`. Accepts slugs, links and ids from `list`. JSON: `{"revoked":[{ref, id, slug, status}]}`. If any share fails, the exit code is that of the first failure.

## `status`: views, activity and read receipts

```
pastevault status <slug | url | id> [--wait viewed|burned] [--timeout 10m] [--interval 2s]
```

Needs `shares:read`. Prints the share and its activity (`share.created`, `share.viewed`, `share.burned`, …).

- `--wait viewed` returns once the share has been viewed at least once (or burned).
- `--wait burned` returns once its last view is used.
- A share that expires or is revoked while waiting exits 5; running out of `--timeout` exits 9.

JSON: the `list` fields plus `views_remaining`, `events: [{id, event, actor_kind, actor_agent, client, created_at, details, …}]` and `waited_for`.

## `audit`: the account audit log

```
pastevault audit [--since 24h] [--event share.viewed] [--limit 50] [--cursor C]
```

Needs `audit:read`. `--since` takes `15m`/`24h`/`7d` or an RFC 3339 time. JSON: `{"events":[…], "next_cursor": …}`. The log holds metadata only (never content or keys) and is kept for 90 days by default.

## `token`: API tokens

```
pastevault token create --name N [--scopes a,b] [--expires 90d|never]
pastevault token list
pastevault token revoke <id | prefix>
```

These commands need the login session (`pastevault login`); `PASTEVAULT_TOKEN` and stored tokens are not used for them.

- `create` prints the token **once**, alone on stdout (`token create --name ci -q > ci.token`). Default scopes are all except `agents:write`. Known scopes: `shares:create`, `shares:read`, `shares:revoke`, `shares:receive`, `agents:read`, `agents:write`, `requests:create`, `audit:read`. `--expires` takes `1d`–`365d` or `never` (default `90d`). JSON: `{id, token, name, prefix, scopes, agent_id, expires_at}`.
- `list` never shows token values. JSON: `{"tokens":[{id, name, prefix, scopes, agent, created_at, expires_at, last_used_at, revoked_at}]}`.
- `revoke` takes the id or the 12-character prefix (`pv_pat_xxxxx`). JSON: `{"token":{…}}`.

Use a token as `PASTEVAULT_TOKEN`, or store it with `login --with-token`.

## `login`, `whoami`, `logout`

```
pastevault login                       # browser approval (device code)
pastevault login --with-token < token  # store an API token read from stdin
pastevault whoami
pastevault logout [--revoke]
```

- `login --with-token` reads one line from stdin, checks it with the server and stores it in `auth.json`. The token never appears in argv or output.
- `whoami` shows the account and where the credential came from. JSON: `{server, user:{id, username, name, email?}, auth:{kind:"session"|"token", source:"env_token"|"stored_token"|"session", token_id?, scopes, agent?}}`.
- `logout` removes the stored token and session for the server, revoking the session on the server. `--revoke` also revokes the stored API token on the server first; that needs the session too. A `PASTEVAULT_TOKEN` in the environment is not affected (the CLI warns).

## Security notes

- Keys live only in link fragments, key files and memory. The server never receives them.
- `--text` and `--key` put secrets in argv, which other local users and shell history can see. Prefer stdin, `--key-file`, `--key-env` or `--key-stdin`.
- `--no-key-in-output --key-out F` keeps the key out of stdout and logs, for example when an agent creates a share whose key must stay in a file.
- Files the CLI writes with secret content (downloads, `--key-out`, `-o`) are created `0600` and never replace an existing file unless `--overwrite` is given. On Windows the file inherits the directory's ACL.
- Error messages never include keys, passwords or tokens.
- `PASTEVAULT_TOKEN` is not tied to a server, so the CLI only sends it to the configured server.
- `put --password` derives the key with PBKDF2-SHA256 (600,000 iterations) like the web app. A password is only as strong as its entropy; prefer the default random link key.

## Formats and test vectors

Pastes use the web format: plaintext `{"title","body","render_mode","language_hint"?}` (JSON), XChaCha20-Poly1305 with a 24-byte nonce and AAD `pastevault:<slug>:v1`. File shares use per-chunk AAD `pastevault:file-share:chunk:<slug>:<file_id>:<index>:v1` and manifest AAD `pastevault:file-share:manifest:<slug>:v1`.

`testdata/crypto/vectors.json` is generated from the web app's code by `node scripts/crypto-vectors.mjs` and checked with `--check` in CI; the Go tests read it. `npm run test:crypto` runs both.
