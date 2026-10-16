# PasteVault CLI reference

The native `pastevault` CLI (`cmd/pastevault`) shares text and files end-to-end encrypted. Content is encrypted before it leaves your machine; the key travels in the link's `#k=` fragment, which is never sent to the server.

This page covers the commands, flags, JSON output, exit codes and environment variables. Scripts and agents should use `--json` and the exit codes, never parse human output.

## Global behaviour

Every command that talks to a server accepts:

| Flag | Meaning |
|---|---|
| `--server URL` | Server base URL. Default: `$PASTEVAULT_SERVER`, else `https://api.pastevault.dev`. |
| `--json` | Print exactly one JSON object on stdout. Also enabled by `PASTEVAULT_JSON=1`; `--json=false` overrides the variable. |
| `-q`, `--quiet` | Print only the essential result (for `put`, just the URL). |

- Flags may appear before or after positional arguments (`pastevault put notes.txt --json`). Everything after `--` is positional, which is how you pass a slug that starts with `-`: `pastevault get -- -abc123`.
- Results go to stdout. Progress, notices and warnings go to stderr.
- With `--json`, a failure prints `{"error":{"code":"…","message":"…","exit_code":N}}` on stdout and a one-line `Error: …` on stderr. `--help` prints `{"usage":"…"}` (exit 0), and running `pastevault` without a command is a usage error (exit 2).
- The CLI never follows HTTP redirects (the API doesn't use them, and following one could hand credentials, upload tokens or download grants to another host). A redirect is reported as an error (exit 11); point `--server` at the final URL, e.g. `https://`.
- Passive update checks never run when stderr is not a terminal, nor for `update`, `config`, `mcp` and `run`. `PASTEVAULT_NO_UPDATE_CHECK=1` disables them entirely.

### Credentials

Commands use the first credential that applies:

1. `PASTEVAULT_TOKEN`, an API token. It is sent **only** to the configured server (`--server` / `PASTEVAULT_SERVER`), never to another host named in a share URL.
2. An API token stored by `pastevault login --with-token`.
3. The login session stored by `pastevault login` (browser approval).

Credentials live in `auth.json` in the config directory: `$PASTEVAULT_CONFIG_DIR`, else `<user config dir>/pastevault` (for example `~/.config/pastevault` on Linux). The directory is created `0700` and the file is written `0600`. The auto-update settings (`pastevault config`) are not affected by `PASTEVAULT_CONFIG_DIR`.

The config directory also holds (all files `0600`, directories `0700`):

| File | Contents |
|---|---|
| `agents/<server>/<name>.json` | An agent key: `{v:1, name, server, agent_id, public_key, private_key, fingerprint, created_at}`. `<server>` is the server URL made file-safe, e.g. `https_api.pastevault.dev`. After `agent revoke` the file moves to `agents/<server>/revoked/<name>-<time>.json` and is kept, so shares already sealed to it can still be opened. |
| `known_agents.json` | Pinned agent keys: `{servers:{<server URL>:{<name>:{fingerprint, public_key, first_seen, source:"self"\|"tofu"\|"manual"}}}}`. |
| `cli.json` | CLI settings: `{servers:{<server URL>:{default_agent}}}`. Separate from the updater's `config.json`, which stays in `<user config dir>/pastevault`. |

Managing API tokens (`token create|list|revoke`) needs the **login session**. The server refuses token management with an API token, so a leaked token cannot mint new tokens or extend itself.

## Exit codes

| Code | Meaning | JSON `error.code` |
|---|---|---|
| 0 | OK | |
| 1 | Unexpected or internal error | `internal` |
| 2 | Usage or flag error; invalid request (HTTP 400); too large (413); missing key or password | `usage`, `invalid_request`, `too_large`, `key_required`, `password_required` |
| 3 | Authentication: not logged in, 401, 403, missing scope, session required, a sealed share opened without the recipient account | `auth`, `not_logged_in`, `session_required` |
| 4 | Not found (404). This includes shares their owner revoked: revoking deletes the share, so the server can no longer tell it from one that never existed | `not_found` |
| 5 | Gone: burned or expired (410); a share that stops existing while `status --wait` waits | `gone` |
| 6 | Request declined or cancelled (secret requests, future) | `declined` |
| 7 | Decryption or integrity failure: wrong key or password, tampering, sealed share you cannot open, a link with a key that the server claims is sealed | `decrypt_failed`, `sealed_share`, `sealed_share_conflict` |
| 8 | Fingerprint or pin mismatch: an agent's key differs from the pinned one or from this machine's key file, or the server's fingerprint for the agent differs | `fingerprint_mismatch` |
| 9 | Timeout (`status --wait`, login code expiry) | `timeout` |
| 10 | Rate limited (429) | `rate_limited` |
| 11 | Network or server error (5xx, connection failure, a redirect) | `network` |
| 12 | Conflict (409) | `conflict` |
| 13 | Local file exists, or a path cannot be used | `local_file` |
| 14 | The server lacks a required feature (e.g. accounts are disabled for `list`/`status`/`revoke`/`audit`/`token`/`whoami`, or an old server without the audit log or API tokens) | `unsupported` |
| 130 | Interrupted (Ctrl-C) | `interrupted` |

## Environment variables

| Variable | Meaning |
|---|---|
| `PASTEVAULT_SERVER` | Default server base URL. |
| `PASTEVAULT_PUBLIC_URL` | Base URL for printed links, when the web app is not at the server URL minus `api.`/`/api`. |
| `PASTEVAULT_TOKEN` | API token (`pv_pat_…`), used only for the configured server. |
| `PASTEVAULT_PASSWORD` | Share password for `get`, and for `put --password` (instead of a prompt). |
| `PASTEVAULT_CONFIG_DIR` | Directory for `auth.json`, agent keys, `known_agents.json` and `cli.json`. |
| `PASTEVAULT_AGENT` | Default agent name (overrides `cli.json`). |
| `PASTEVAULT_AGENT_KEY` | An agent private key (base64url, 32 bytes) used instead of key files, for CI and containers. `get` opens shares sealed to it. |
| `PASTEVAULT_JSON` | `1` turns on `--json` for every command. |
| `PASTEVAULT_NO_UPDATE_CHECK` | Disables passive update checks. |

## `put`: share text or files

```
pastevault put [flags] [<file>... | -]
```

Input:

- `-`, or no arguments while stdin is not a terminal: share stdin as a paste (UTF-8 text that fits the server's paste limits, see below).
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
| `--password` | Password-protect. The password comes from `--password-file`, else `PASTEVAULT_PASSWORD`, else a terminal prompt. `PASTEVAULT_PASSWORD` alone never turns protection on. The password is used exactly as given, like the web app (surrounding spaces count); a password that is empty or only whitespace is refused (exit 2). |
| `--password-file F` | Password-protect with the password in F (one trailing newline is ignored, other whitespace is kept). |
| `--key-out F` | Also write the share key (base64url) to the new file F, mode `0600`. Refuses an existing file. |
| `--no-key-in-output` | Print the link without `#k=`. Requires `--key-out`. |
| `--to NAME\|FP` | Seal the share to an agent of your account, by name, full `pvk1_…` fingerprint, or a fingerprint prefix (`pvk1_` plus at least 8 characters) of a key already pinned or held on this machine. Needs a credential. |
| `--to-key PK` | Seal the share to a raw X25519 public key (base64url, from `pastevault agent pubkey`). Works without an account. |

**Sealed shares** (`--to`, `--to-key`). The share's key is wrapped (PVWRAP1) to the agent's public key and the printed link has **no** `#k=`: only the holder of the matching private key can open it, with `pastevault get`. `--to`/`--to-key` cannot be combined with a password, `--key-out` or `--no-key-in-output`. They default to `--max-views 1` and `--expires 1h` unless given. With `--to`, the agent's public key comes from the server but its fingerprint is computed locally and checked against `known_agents.json`: the first use pins it once the share has been created (`Pinned NAME pvk1_…` on stderr; a failed `put` pins nothing), and a different key later fails with exit 8 before anything is uploaded. A fingerprint **prefix** only selects a key this machine already trusts (pinned, or its own key file); a prefix is too short to verify a new key (40 bits), so for an unknown key give the full fingerprint (exit 2 otherwise). After verifying the new fingerprint with the agent's owner (`pastevault agent show` on its machine), accept it with `pastevault agent trust NAME FP`. A full fingerprint in `--to` is itself the verification. A share sealed to an account agent can only be **opened** (consumed) with credentials of that account holding `shares:receive`; anyone else gets 403 and no view is used; the same applies to downloading its file chunks. A share sealed with `--to-key` (or any sealed share on a server with `DISABLE_AUTH`) has no recipient account: anyone holding the link can open it and so use up its views or burn it, although only the key holder can decrypt it. Servers without sealed shares or agents exit 14.

**Paste size.** A paste must fit two server limits: the encrypted content (`MAX_PASTE_SIZE_BYTES`, 1 MiB by default) and the whole request body, which carries it base64-encoded, so about 4/3 larger (1 MiB by default). In practice that is about 780 KB of text by default, less for text with many characters that JSON escapes (newlines, quotes). Servers report both in `/capabilities` (`limits.max_paste_size_bytes`, `limits.max_paste_request_bytes`); for older servers the defaults are assumed. A paste over the limit exits 2 (`too_large`) before anything is uploaded; with `--as auto` a large `.env` file becomes a file share instead.

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

`kind` is `paste` or `file_share`. `key_file` appears with `--key-out`. `file_count` and `total_size_bytes` appear for file shares. `recipient` is `{name, fingerprint}` for a sealed share (`name` is omitted with `--to-key`) and `null` otherwise.

## `get`: open a share

```
pastevault get [flags] <ref>
```

References:

- `https://host/p/<slug>#k=KEY` (paste) or `https://host/f/<slug>#k=KEY` (file share). A link on the default web origin is fetched from `--server`; any other host is contacted directly.
- `<slug>#k=KEY` or a bare `<slug>` on `--server`. Bare references try pastes first, then file shares. On servers without `/meta` endpoints (before PR1), a reference with a key opens the paste if one exists (a missing paste costs nothing), and otherwise the file share; without a key only file shares are tried. If such a paste turns out to be password-protected, the password is asked for on a terminal after it was opened.
- `pv://share/<slug>[?server=HOST][#k=KEY]`.

`get` always reads the share's metadata first. A missing key or password, an output path that cannot be written, or a sealed share that no local agent key matches all fail **before** a view is consumed, so a burn-after-read share is not wasted.

Sealed shares are opened with the local agent key whose fingerprint equals the share's recipient (key files under `agents/`, including revoked ones, or `PASTEVAULT_AGENT_KEY`). No key matches: exit 7 (`sealed_share`). A sealed share never has a link key or a password, so when the link carries `#k=` (or a key/password is given, or the share is password-protected) but the server says the share is sealed, `get` refuses with exit 7 (`sealed_share_conflict`) before opening anything: a server could otherwise relabel a normal link and serve content of its choosing wrapped to your agent key. A share sealed to an account agent also needs that account's credentials (exit 3 without any, checked before opening). The JSON output then adds `recipient: {name, fingerprint}` naming the key used.

| Flag | Meaning |
|---|---|
| `--key-file F` | Read the key from F (the bare key, `k=KEY`, or a link with `#k=`). |
| `--key-env VAR` | Read the key from environment variable VAR. |
| `--key-stdin` | Read the key from stdin. |
| `--key KEY` | Deprecated: the key is visible in the process list and shell history (prints a warning). |
| `--password` | Prompt for the password. Password-protected shares also prompt automatically on a terminal. Typed passwords are used exactly as typed. |
| `--password-file F` | Read the password from F (one trailing newline is ignored). `PASTEVAULT_PASSWORD` also works. |
| `--stdout` | Write the content to stdout (pastes, or a file share with exactly one file). |
| `-o F`, `--output F` | Write the paste, or the only file of a share, to the new file F (mode `0600`). |
| `--out DIR` | Write into DIR. Pastes are named after their title when it is a plain file name (e.g. `.env`), else `<slug>.txt`/`.md`. File shares default to the current directory. |
| `--overwrite` | Replace existing files. Without it, `-o` refuses an existing file (exit 13, checked before opening). With `--out`, file names are only known after the share is opened (and its view used), so a clash never fails: the file is saved as `name (1).ext` and stderr says so. |

Pastes go to stdout by default. With `--json`, a paste needs an explicit destination: `--stdout` (the content is then included as `content`), `-o` or `--out`. This is checked before the paste is opened.

On a terminal, a wrong password for a share that the open just burned can be retried twice.

An invalid API token (`PASTEVAULT_TOKEN` or a stored one that was revoked or expired) does not block reading a public share: `get` warns on stderr (`… token is invalid …; continuing without it`) and retries without it. A sealed share that needs the recipient account then fails with exit 3.

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

Needs credentials with the `shares:read` scope, on a server with accounts enabled (otherwise exit 14, as for `revoke`, `status`, `audit`, `token` and `whoami`). `--status` is one of `active`, `burned`, `expired`, `deleted`, `uploading`, `abandoned`. `--limit` defaults to 50 (max 200).

JSON: `{"shares":[{id, share_type, slug, status, created_at, expires_at, view_count, max_views, burn_after_read, is_password_protected, file_count, total_size_bytes, first_viewed_at, last_viewed_at, recipient_fingerprint, recipient_agent_name, can_delete, deleted_at}], "next_cursor": "…"|null}`. An active share past its expiry is reported as `expired`.

## `revoke`: delete shares you own

```
pastevault revoke <slug | url | id>...
```

Needs `shares:revoke`. Accepts slugs, links and ids from `list`; a link must be on the `--server` (otherwise exit 2). JSON: `{"revoked":[{ref, id, slug, status}]}`. If any share fails, the exit code is that of the first failure.

## `status`: views, activity and read receipts

```
pastevault status <slug | url | id> [--wait viewed|burned] [--timeout 10m] [--interval 2s]
```

Needs `shares:read`. Prints the share and its activity (`share.created`, `share.viewed`, `share.burned`, …).

- `--wait viewed` returns once the share has been viewed at least once (or burned).
- `--wait burned` returns once its last view is used. A share without a view limit never burns, so this exits 2 at once.
- A share that expires or is revoked while waiting exits 5; running out of `--timeout` exits 9.
- After `revoke`, the share is deleted: `get` then exits 4 (not found), not 5.

Events need a server with the audit log; on older servers `events` is empty.

JSON: the `list` fields plus `views_remaining`, `events: [{id, event, actor_kind, actor_agent, client, created_at, details, …}]` and `waited_for`.

## `audit`: the account audit log

```
pastevault audit [--since 24h] [--event share.viewed] [--limit 50] [--cursor C]
```

Needs `audit:read` and a server with the audit log (exit 14 otherwise). `--since` takes `15m`/`24h`/`7d` or an RFC 3339 time. JSON: `{"events":[…], "next_cursor": …}`. The log holds metadata only (never content or keys) and is kept for 90 days by default.

## `token`: API tokens

```
pastevault token create --name N [--scopes a,b] [--expires 90d|never] [--agent NAME] [--out FILE]
pastevault token list
pastevault token revoke <id | prefix>
```

These commands need the login session (`pastevault login`); `PASTEVAULT_TOKEN` and stored tokens are not used for them.

- `create` prints the token **once**, alone on stdout. To save it, use `--out FILE`: the file is created `0600` (refused if it exists, checked before the token is created), the token stays out of stdout, and JSON output has `token_file` instead of `token`. Avoid `> file` redirection, which creates the file with your umask (often world-readable). Default scopes are all except `agents:write`. Known scopes: `shares:create`, `shares:read`, `shares:revoke`, `shares:receive`, `agents:read`, `agents:write`, `requests:create`, `audit:read`. `--expires` takes `1d`–`365d` or `never` (default `90d`). JSON: `{id, token, name, prefix, scopes, agent_id, expires_at}`.
- `--agent NAME` (name, full fingerprint or id) binds the token to an agent: it then acts as that agent, can only open shares sealed to that agent (not to the account's other agents), and is revoked with the agent.
- `list` never shows token values. JSON: `{"tokens":[{id, name, prefix, scopes, agent, created_at, expires_at, last_used_at, revoked_at}]}`.
- `revoke` takes the id or the 12-character prefix (`pv_pat_xxxxx`). JSON: `{"token":{…}}`.

Use a token as `PASTEVAULT_TOKEN`, or store it with `login --with-token` (`pastevault login --with-token < ci.token`).

## `agent`: agent keys for sealed shares

```
pastevault agent init [--name N] [--force] [--default]
pastevault agent list [--all]
pastevault agent show [NAME]
pastevault agent pubkey [NAME]
pastevault agent revoke NAME
pastevault agent trust NAME FINGERPRINT
pastevault agent default [NAME]
```

An agent is an X25519 key pair. The private key stays on its machine; the public key is registered with the account so others in the account can `put --to NAME`. Fingerprints look like `pvk1_` plus 32 base32 characters; the short form is the first 8 characters after `pvk1_` and is for display only.

- `init` generates a key, writes it (`0600`) before registering it, registers it (`agents:write`; a login session has it, default API tokens don't), pins it as `self`, and prints the fingerprint on stdout. `--name` defaults to the host name. The first agent on a server becomes the default; `--default` forces that. `--force` replaces this machine's key for the name, revoking the old agent. If an unbound API token registers the agent, the token becomes bound to it (`token_bound: true`). JSON: `{agent:{id, name, fingerprint, public_key, created_at, local_key, key_file, default, pin}, server, token_bound}`.
- `list` shows the account's agents with locally computed fingerprints, whether this machine holds the key (`local_key`), the pin state (`self`, `tofu`, `manual`, `none`, `mismatch`) and `fingerprint_mismatch` when the server's claimed fingerprint is not its key's. JSON: `{"agents":[…]}`.
- `show` prints an agent's full fingerprint; without NAME, the default agent (`PASTEVAULT_AGENT_KEY`, `PASTEVAULT_AGENT`, `cli.json`, or the only local key). Works offline for local keys. JSON: `{agent, server_status:"active"|"revoked"|"missing"|"unknown", server}`.
- `pubkey` prints a local agent's public key for `put --to-key`.
- `revoke` revokes an agent (by name, full fingerprint or id) and every API token bound to it. A local key for it is kept, moved to `revoked/`, so shares sealed to it before can still be opened. An API token bound to an agent can only revoke that agent (403 `other_agent` for others). JSON: `{agent, tokens_revoked}`.
- `trust` pins NAME's current server key after you verified FINGERPRINT out of band. It refuses (exit 8) when the server's key has another fingerprint.
- `default` shows or sets the default agent for the server.

## `login`, `whoami`, `logout`

```
pastevault login                       # browser approval (device code)
pastevault login --with-token < token  # store an API token read from stdin
pastevault whoami
pastevault logout [--revoke]
```

- `login --with-token` reads one line from stdin (on a terminal, without echo), checks it with the server and stores it in `auth.json`. The token never appears in argv or output.
- `whoami` shows the account and where the credential came from. JSON: `{server, user:{id, username, name, email?}, auth:{kind:"session"|"token", source:"env_token"|"stored_token"|"session", token_id?, scopes, agent?}}`.
- `logout` removes the stored token and session for the server, revoking the session on the server. `--revoke` also revokes the stored API token on the server first; that needs the session too. A `PASTEVAULT_TOKEN` in the environment is not affected (the CLI warns).

## Security notes

- Keys live only in link fragments, key files and memory. The server never receives them.
- `--text` and `--key` put secrets in argv, which other local users and shell history can see. Prefer stdin, `--key-file`, `--key-env` or `--key-stdin`.
- `--no-key-in-output --key-out F` keeps the key out of stdout and logs, for example when an agent creates a share whose key must stay in a file.
- Files the CLI writes with secret content (downloads, `--key-out`, `-o`) are created `0600` and never replace an existing file unless `--overwrite` is given. On Windows the file inherits the directory's ACL.
- Error messages never include keys, passwords or tokens.
- `PASTEVAULT_TOKEN` is not tied to a server, so the CLI only sends it to the configured server.
- HTTP redirects are never followed, so credentials, upload tokens and download grants only go to the server you named.
- `put --password` derives the key with PBKDF2-SHA256 (600,000 iterations) like the web app. A password is only as strong as its entropy; prefer the default random link key.
- Agent private keys are files readable only by your OS user (`0600`; on Windows they inherit the profile directory's ACL). Anything running as that user can read them. They are never printed or sent; `PASTEVAULT_AGENT_KEY` is for CI secrets.
- The server lists agents' public keys and could substitute its own. The CLI always computes fingerprints itself and pins keys, so a substituted key fails with exit 8 instead of being used. Compare fingerprints out of band before `agent trust`.
- **Sealed shares protect confidentiality, not sender authenticity.** Only the recipient's private key can decrypt a sealed share, but PVWRAP1 is anonymous public-key encryption: anyone who knows the recipient's public key (including the server, or whoever can write to its database) can seal content to it. A malicious server can therefore replace a sealed share's content and key with its own, and the recipient cannot tell. Treat sealed content as coming from "someone who knows the agent's public key", not from a verified sender. A normal `#k=` link does protect integrity against the server, because the key never reaches it. Sender signatures are a possible follow-up.
- Sealed shares without a recipient account (`--to-key`, or `DISABLE_AUTH`) can be consumed or burned by anyone who has the link, without being decrypted.

## Formats and test vectors

Pastes use the web format: plaintext `{"title","body","render_mode","language_hint"?}` (JSON), XChaCha20-Poly1305 with a 24-byte nonce and AAD `pastevault:<slug>:v1`. File shares use per-chunk AAD `pastevault:file-share:chunk:<slug>:<file_id>:<index>:v1` and manifest AAD `pastevault:file-share:manifest:<slug>:v1`.

Sealed shares keep these formats and wrap the 32-byte share key with **PVWRAP1**: an ephemeral X25519 key, HKDF-SHA256 (`salt = e_pk || recipient_pk`, `info = "pastevault:wrap:v1"`), then XChaCha20-Poly1305 with AAD `pastevault:wrap:v1:<context>:<recipient fingerprint>`. The envelope is `0x01 || e_pk(32) || nonce(24) || ciphertext(48)`, 105 bytes or 140 base64url characters. Contexts are `paste:<slug>` and `file-share:<slug>`. Fingerprints are `pvk1_` + base32 (lowercase, unpadded) of the first 20 bytes of `SHA-256("pastevault:agent-key:v1" || 0x00 || public_key)`. Low-order public keys (all-zero shared secret) and non-canonical ones (top bit set, or u ≥ 2^255−19) are refused, and keys and envelopes must use canonical base64url (no padding bits set).

`testdata/crypto/vectors.json` is generated from the web app's code by `node scripts/crypto-vectors.mjs` and checked with `--check` in CI. It includes fingerprint and wrap vectors and negative wrap cases (wrong context, wrong recipient, wrong fingerprint in the AAD, tampering, low-order and non-canonical keys). The Go tests and `frontend/src/lib/__tests__/crypto-vectors.test.ts` both read it; `npm run test:crypto` runs all three.
