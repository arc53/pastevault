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
| `store/<server>/<agent>/<NAME>.pvs` | A local secret, sealed to the agent key: `{v:1, name, kind, created_at, source:{type:"request"\|"share"\|"import", ref}, fingerprint, wrapped_key, nonce, ciphertext}`. `<agent>` is the agent name (for a bare `PASTEVAULT_AGENT_KEY` without a matching key file: its fingerprint). See [`secret`](#secret-the-local-store). |
| `requests/<id>.json` | An open secret request: its poll token and ephemeral private key, name, `save_as`, server and expiry. Deleted once the answer is stored and acknowledged, or the request is declined, cancelled or expired. |

Managing API tokens (`token create|list|revoke`) needs the **login session**. The server refuses token management with an API token, so a leaked token cannot mint new tokens or extend itself.

## Exit codes

| Code | Meaning | JSON `error.code` |
|---|---|---|
| 0 | OK | |
| 1 | Unexpected or internal error | `internal` |
| 2 | Usage or flag error; invalid request (HTTP 400); too large (413); missing key or password | `usage`, `invalid_request`, `too_large`, `key_required`, `password_required` |
| 3 | Authentication: not logged in, 401, 403, missing scope, session required, a sealed share opened without the recipient account | `auth`, `not_logged_in`, `session_required` |
| 4 | Not found (404). This includes shares their owner revoked: revoking deletes the share, so the server can no longer tell it from one that never existed | `not_found` |
| 5 | Gone: burned or expired (410); a share that stops existing while `status --wait` waits; a secret request that expired, or whose answer was already collected and wiped | `gone` |
| 6 | Secret request declined or cancelled | `declined`, `cancelled` |
| 7 | Decryption or integrity failure: wrong key or password, tampering, sealed share you cannot open, a link with a key that the server claims is sealed | `decrypt_failed`, `sealed_share`, `sealed_share_conflict` |
| 8 | Fingerprint or pin mismatch: an agent's key differs from the pinned one or from this machine's key file, or the server's fingerprint for the agent differs | `fingerprint_mismatch` |
| 9 | Timeout (`status --wait`, `request --wait`, `await`, login code expiry) | `timeout` |
| 10 | Rate limited (429) | `rate_limited` |
| 11 | Network or server error (5xx, connection failure, a redirect) | `network` |
| 12 | Conflict (409) | `conflict` |
| 13 | Local file exists, or a path cannot be used | `local_file` |
| 14 | The server lacks a required feature (e.g. accounts are disabled for `list`/`status`/`revoke`/`audit`/`token`/`whoami`, or an old server without the audit log or API tokens) | `unsupported` |
| 130 | Interrupted (Ctrl-C) | `interrupted` |

`run` and `inject` add their own codes:

| Code | Meaning |
|---|---|
| 125 | A handle could not be resolved (missing secret, a share with a view limit, bad `.env.pv` line, ...). Nothing was run. |
| 126 | The command was found but could not be executed (permissions, not a program). |
| 127 | The command was not found. |
| other | `run` exits with the command's own exit code, or 128+N when it was killed by signal N. |

## Environment variables

| Variable | Meaning |
|---|---|
| `PASTEVAULT_SERVER` | Default server base URL. |
| `PASTEVAULT_PUBLIC_URL` | Base URL for printed links, when the web app is not at the server URL minus `api.`/`/api`. |
| `PASTEVAULT_TOKEN` | API token (`pv_pat_…`), used only for the configured server. |
| `PASTEVAULT_PASSWORD` | Share password for `get`, and for `put --password` (instead of a prompt). |
| `PASTEVAULT_CONFIG_DIR` | Directory for `auth.json`, agent keys, `known_agents.json` and `cli.json`. |
| `PASTEVAULT_AGENT` | Default agent name (overrides `cli.json`). |
| `PASTEVAULT_AGENT_KEY` | An agent private key (base64url, 32 bytes) used instead of key files, for CI and containers. `get` opens shares sealed to it; `request` and the local store use it as the default agent. |
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
| `--overwrite` | Replace existing files. Without it, `-o` refuses an existing file (exit 13, checked before opening). With `--out`, file names are only known after the share is opened (and its view used), so a clash never fails: the file is saved as `name (1).ext` and stderr says so. With `--save`, replace an existing secret. |
| `--save NAME` | Store the content in the local store as `NAME` (sealed to the default agent) instead of writing it anywhere, and print `pv://secret/NAME`. Works for pastes and file shares with exactly one file (at most 10 MiB). The name, the default agent and an existing secret are checked before opening. JSON adds `saved_as`. This is how a view-limited or burn-after-read share becomes usable by `run` and `inject`. |

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

## `request` and `await`: ask a human for a secret

```
pastevault request NAME [--why TEXT] [--ttl 10m] [--accept text|file|any] [--save-as NAME] [--agent NAME] [--overwrite] [--wait [--timeout D]]
pastevault await <id|code> [--timeout D] [--save-as NAME] [--overwrite]
pastevault request list [--status S]
pastevault request cancel <id|code>...
pastevault request fulfil <code|url> [--from-file F | --from-stdin] [--kind text|file] [--fingerprint FP]
pastevault request decline <code|url>
```

An agent never asks for a secret in chat. It asks the human of its own account through PasteVault, and receives the answer sealed to a fresh key that only it holds:

1. `request NAME` (as the default agent, or `--agent`) generates an ephemeral X25519 key pair for this request, creates the request on the server with its public key, and saves `requests/<id>.json` (poll token and private key, `0600`). It prints a link like `https://pastevault.dev/r/ABCD-EFGH#fp=pvk1_…` and the key's fingerprint.
2. The human opens the link **signed in to the same account**. The page checks that the request key matches `#fp=`, shows the agent and the reason (as untrusted text), and seals the answer to the request key in the browser. Only the human's login session can answer; an API token (an agent) never can.
3. `await` (or `request --wait`) polls, decrypts the answer, seals it into the local store as `--save-as` (default `NAME`), writes the store file, and only then acknowledges it, which wipes it from the server. It prints `pv://secret/NAME`. Use it with `run` or `inject`; the value is never printed.

- `request` needs an agent key on this machine (`pastevault agent init`; exit 2 otherwise) and a credential that may speak for that agent: the **login session**, or an API token **bound to the agent** (`pastevault token create --agent NAME`) with `requests:create`. An unbound token is refused (exit 3, `agent_bound_token_required`): a request shows the human "agent X asks for…", so a leaked general-purpose token must not be able to say that. With `PASTEVAULT_AGENT_KEY`, bind the token to the agent whose key that is. The name must match `[A-Za-z_][A-Za-z0-9_.-]{0,127}`. A secret with the `--save-as` name must not exist yet (exit 13) unless `--overwrite`.
- `--why` is shown to the human, labelled as a message from the agent that must not be trusted. At most 500 characters (Unicode code points); control characters (other than tab and newline), bidirectional marks and line separators are refused.
- `--ttl` is how long the request stays open: at least the server minimum (`limits.min_secret_request_ttl_seconds`, default 60s), at most 24h. Default 10m.
- `--accept`: `text` (default), `file` or `any`.
- `--wait` waits for the answer. `--timeout` limits the wait (default: until the request expires); a timeout exits 9 and keeps the request file, so `await` can resume. Ctrl-C (exit 130) does the same.
- Outcomes: answered → exit 0 and the handle; declined or cancelled → exit 6; expired → exit 5; the answer was already collected elsewhere and wiped → exit 5.
- Without `--wait` and `--json`, the link is printed on stdout and the instructions on stderr. With `--wait`, the instructions (including the link) go to stderr and the handle to stdout.
- An account may have 20 pending requests and create 30 per hour (429, exit 10). Polling is limited to the server's interval (3s); `await` backs off on `slow_down` by itself.
- If the CLI dies after receiving the answer but before acknowledging it, `await` within two minutes gets the same answer again. After two minutes (or the acknowledgement, or expiry) the server has deleted it.
- `await --save-as NAME` stores the answer under another name, and `--overwrite` lets it replace an existing secret (both are remembered in the request file). If the name was taken by the time the answer arrives (another request or `secret import` used it), the answer is **not** dropped: it is stored as `NAME.<code>` (e.g. `OPENAI_API_KEY.ABCDEFGH`), stderr says so, and the printed handle and JSON `save_as` name the actual entry.
- The request file is only deleted once the request is over (answered and stored, declined, cancelled, expired, or already collected). Errors (401/403/404, network, a server outage) keep it, so `await` can be retried.
- Revoking an agent cancels its open requests and wipes answers it has not collected.

JSON (`request --json`, and with `--wait` or `await` once stored):

```json
{
  "id": "6f0c…",
  "code": "ABCD-EFGH",
  "url": "https://pastevault.dev/r/ABCD-EFGH#fp=pvk1_…",
  "fingerprint": "pvk1_…",
  "name": "OPENAI_API_KEY",
  "save_as": "OPENAI_API_KEY",
  "agent": "laptop",
  "expires_at": "2026-10-16T12:10:00.000Z",
  "status": "pending",
  "handle": "pv://secret/OPENAI_API_KEY"
}
```

`status` is `pending` right after `request`, and `delivered` (with `handle`) once the answer is in the local store.

- `request list` shows the account's requests (an API token bound to an agent sees only that agent's), newest first, with `local: true` when this machine holds the request file. Metadata only. JSON: `{"requests":[{id, code, name, reason, accept, fingerprint, status, requester:{agent:{id,name}}, response_kind, response_size, created_at, expires_at, opened_at, fulfilled_at, delivered_at, acked_at, closed_at, local}]}`.
- `request cancel` withdraws pending (or answered but not yet collected) requests and deletes their request files. The requester's token or the session may cancel.
- `request fulfil` answers a request from the command line, with the **login session** (`pastevault login`; exit 3 otherwise). Give the full link with `#fp=`, or the code plus `--fingerprint` (the full fingerprint as the agent printed it, or at least `pvk1_` plus its first 26 characters; the 8-character short form is for display only and is refused); the CLI recomputes the fingerprint from the request's public key and refuses with exit 8 if it differs, before reading the value. The value comes from `--from-file`, `--from-stdin`, or a hidden prompt on a terminal. For `text`, one trailing newline (`\n` or `\r\n`) from a file or stdin is dropped. `--kind file` sends the bytes as a file (name from `--from-file` or `--filename`). The sealed answer may be at most `max_bytes` (the server's `MAX_SECRET_REQUEST_BYTES`).
- `request decline` declines a pending request (session only); the agent's `await` then exits 6.

## `secret`: the local store

```
pastevault secret list [--agent NAME]
pastevault secret import NAME (--from-file F | --from-stdin) [--kind text|file] [--overwrite]
pastevault secret rm NAME...
pastevault secret reveal NAME
```

Secrets in the local store are sealed to the default agent's key (the same PVWRAP1 wrap as sealed shares, context `store:<NAME>`), one file per secret under `store/<server>/<agent>/` (`0600`, directories `0700`). They are referenced as `pv://secret/NAME`. `request`/`await` and `get --save` add them; `import` adds one from a file or stdin (for `text`, one trailing newline is dropped; content that isn't UTF-8 becomes a `file`). Nothing here contacts the server.

- `list` never shows values. JSON: `{"agent":"laptop","secrets":[{name, handle, kind, created_at, source:{type, ref}}]}`.
- `reveal` prints a secret only when both stdin and stdout are a terminal (exit 2 otherwise). That is friction against an agent capturing it, **not** a security boundary: any program running as your user can read the store and the agent key, and `run --no-mask` or `inject --stdout` print values without a terminal.
- After `agent init --force` or `agent revoke`, older secrets stay readable with the retired key.

## `run`: a command with secrets in its environment

```
pastevault run [--env-file .env.pv]... [--no-mask] [--no-inherit] [--resolve-inherited] -- COMMAND [ARGS...]
```

`run` starts COMMAND with the current environment plus the variables from each `--env-file` (later files win). Every `pv://` handle in the env files is resolved first. If any handle can't be resolved, nothing runs (exit 125).

In the **inherited** environment, only `pv://secret/…` handles are resolved (they are local; `OPENAI_API_KEY=pv://secret/OPENAI_API_KEY pastevault run -- …` works). A `pv://share/…` value there is passed through unchanged with a warning, because resolving it opens a share on a server: use an `--env-file`, or `--resolve-inherited`. A value that starts with `pv://` but is not a valid handle is passed through with a warning.

- `PASTEVAULT_TOKEN`, `PASTEVAULT_PASSWORD` and `PASTEVAULT_AGENT_KEY` are removed from the inherited environment, so the command never sees the CLI's own credentials. (An `--env-file` may still set them explicitly.)
- `--no-inherit` starts from an empty environment, keeping only `PATH`, `HOME`, `USER`, `LOGNAME`, the temp directory variables and Windows system variables.
- stdin is passed through. Signals (SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1/2) are forwarded to the command; Ctrl-C on a terminal reaches it directly. The exit code is the command's (128+N if it was killed by signal N), or 125/126/127 (see [Exit codes](#exit-codes)).
- The command's stdout and stderr are **masked**: every resolved value is replaced by `[masked:VAR]`. Because of that they are pipes, not a terminal (programs may turn off colours or prompts). `--no-mask` passes them through untouched.
- With masking, `run` exits at most 1.5 s after the command does, even if the command left processes running in the background (`server &`, `docker compose up -d`) that still hold its output open. Their output after that is lost, and they may get `SIGPIPE` when they write; run such commands with `--no-mask`, or redirect the background process's output.
- Share handles must point at a paste **without a view limit**: `run` would otherwise use up (or burn) a view on every run. A view-limited, burn-after-read, password-protected or file share is refused with exit 125 and the hint `pastevault get <ref> --save NAME`; then use `pv://secret/NAME`.

### Handles and `.env.pv`

```
pv://secret/NAME[?agent=AGENT&var=KEY&server=URL]   a secret in the local store (default agent of --server)
pv://share/SLUG[?server=URL&var=KEY][#k=KEY]         a paste on the server
https://host/p/SLUG#k=KEY                            a paste link (inject templates only)
```

`var=KEY` treats the content as a dotenv file and takes `KEY` from it, so one stored `.env` can feed several variables.

`.env.pv` files use dotenv syntax: `KEY=value`, an optional `export ` prefix, `#` comments (also after an unquoted value, preceded by a space), double quotes with `\n \r \t \\ \" \$` escapes, and single quotes for literal text. Quoted values may span lines. There is no `$VAR` interpolation. Values that are not `pv://` handles pass through literally, so the file can be committed:

```
# .env.pv
OPENAI_API_KEY=pv://secret/OPENAI_API_KEY
DATABASE_URL=pv://secret/prod-env?var=DATABASE_URL
LOG_LEVEL=debug
```

### What masking does and does not do

Masking keeps secrets out of **transcripts**: terminal scrollback, CI logs, and the context of an agent that runs the command. It is not a security boundary. The command can read its own environment and can always get a secret out some other way.

For each value, the masker looks for:

- the value itself;
- standard and URL-safe base64 (padded, unpadded, and inside a longer base64 stream at each of the three byte alignments);
- lower and upper case hex;
- percent-encoding, each with upper- and lower-case hex digits: Go's query and path escaping (= Python `quote_plus`), strict RFC 3986 (everything but `A-Za-z0-9-._~`, as `curl --data-urlencode`), JavaScript `encodeURIComponent`, Python `quote` (keeps `/`), and URL userinfo escaping as Go and browsers/Node do it (a password inside `postgres://user:PASSWORD@host`);
- JSON string escaping (Go's, without HTML escaping, and ASCII-only `\uXXXX`);
- for a value with several lines: the value with LF and with CRLF line endings, and every line on its own that has at least 6 non-blank characters (so a PEM key printed with CRLF or with a log prefix on each line is still masked line by line).

It replaces leftmost-longest matches. Output that ends in what could be the start of a secret is held back until more output arrives or the command exits; there is no timer, so a partial secret is never printed early, but a prompt that happens to end that way appears late.

It does **not** catch:

- values shorter than 6 bytes (`run` warns and does not mask them), and lines of a multi-line value shorter than 6 non-blank characters;
- line-wrapped encodings (`base64` wraps at 76 characters, so values longer than 57 bytes), the encodings of a single line of a multi-line value, other encodings (shell quoting, HTML entities, URL encoding of a whole multi-line value with CRLF, ...), compression, encryption, or a value split up, reversed or re-cased;
- a few bits at the edges of base64 inside a longer stream (the characters next to `[masked:…]` can depend on the neighbouring bytes);
- anything written to files, sockets or other processes instead of stdout/stderr.

If two variables hold the same value, the replacement names one of them.

stdout and stderr are masked independently. Bytes held back on one stream (a possible secret prefix) can appear after later output on the other, so the interleaving of the two streams is not exact.

Masking, `secret reveal`'s terminal check, and the absence of plaintext in MCP results are **friction, not access control**. Anything that can run the CLI as your user can print a secret, for example `pastevault run --no-mask -- printenv NAME` or `echo '{{ pv://secret/NAME }}' | pastevault inject -i - --stdout`.

## `inject`: fill a template

```
pastevault inject -i TEMPLATE [-o OUT [--overwrite] | --stdout]
```

Replaces every `{{ pv://… }}` (or `{{ https://host/p/…#k=… }}`) placeholder in TEMPLATE (`-` for stdin) with the secret it names, with the same rules as `run`. Other `{{ … }}` text is left alone. `-o` writes a new file `0600` (exit 13 if it exists, checked before anything is resolved, unless `--overwrite`); `--stdout` writes to stdout. Any unresolvable placeholder exits 125 and writes nothing. JSON (with `-o`): `{"written_to":"…","placeholders":N}`.

## `mcp`: the MCP server for agents

```
pastevault mcp [--agent NAME] [--root DIR]... [--allow-plaintext] [--allow-any-host] [--allow-home-root] [--server URL]
```

Serves the Model Context Protocol on stdin/stdout for agent harnesses (Claude Code, Codex, Gemini CLI, Cursor, ...). stdout carries only protocol messages; diagnostics go to stderr. It uses the same credentials, agent keys, pins and local store as the other commands. Setup per harness, the tools and their schemas: [agents.md](agents.md#mcp-server).

- Tools: `send_text`, `send_file`, `receive`, `request_secret`, `request_status`, `list_secrets`, `share_status`, `audit`, `revoke_share`. None returns a stored secret's value.
- `--agent` acts as that agent (default: the default agent); it cannot be combined with `PASTEVAULT_AGENT_KEY`.
- `--root DIR` (repeatable) allows `send_file` and `receive` to use DIR. The client's MCP roots are allowed too; without either, the working directory. The home directory, `/` and ancestors of the home directory are refused as roots (and dropped from client roots) unless `--allow-home-root` is given. Credential locations (`.git`, `~/.ssh`, `~/.aws`, harness login files, shell histories, ...) are never readable, even inside a root.
- `receive` writes to `output_path`, or to `pastevault-received/` in the first root. Sender-chosen names that agents or tools load (dot files, `.mcp.json`, `CLAUDE.md`, `package.json`, scripts, ...) are saved as `received-<slug>-<name>`; it never writes into `.git`, `.github`, `.claude` and similar directories, and `overwrite` only replaces files it wrote earlier in the same session.
- `receive` only opens shares on the configured server (or its public URL) unless `--allow-any-host` is given.
- `--allow-plaintext` lets `receive` return share content when the call sets `allow_plaintext` and the content does not look like a secret.
- Tool errors carry the CLI's error object as text: `{"error":{"code","message","exit_code"}}`, with the exit codes above.

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
- Secret requests: the server sees the request's name, reason, agent and timing, but only ever stores the answer encrypted to the request's own key, and deletes it on acknowledgement, two minutes after delivery, or at expiry. The `#fp=` check (web) and `request fulfil`'s fingerprint check stop a server from swapping in its own key. The request's private key and poll token live only in `requests/<id>.json` and are deleted with it. A request's reason is untrusted text written by the agent; the CLI prints it quoted.
- The local store and agent keys protect secrets from transcripts and from the server, not from code running as your user. `run` masking is a transcript guard too (see [`run`](#run-a-command-with-secrets-in-its-environment)).

## Formats and test vectors

Pastes use the web format: plaintext `{"title","body","render_mode","language_hint"?}` (JSON), XChaCha20-Poly1305 with a 24-byte nonce and AAD `pastevault:<slug>:v1`. File shares use per-chunk AAD `pastevault:file-share:chunk:<slug>:<file_id>:<index>:v1` and manifest AAD `pastevault:file-share:manifest:<slug>:v1`.

Secret request answers and local store entries are a JSON payload, `{"v":1,"name":"…","kind":"text","value":"…"}` or `{"v":1,"name":"…","kind":"file","filename":"…","content_type":"…","data":"<base64url>"}`, encrypted with a random 32-byte key and 24-byte nonce (XChaCha20-Poly1305) under AAD `pastevault:request:<request id>:v1` or `pastevault:store:<NAME>:v1`; the key is wrapped with PVWRAP1 (below) for context `request:<request id>` (to the request's ephemeral key) or `store:<NAME>` (to the agent key).

Sealed shares keep these formats and wrap the 32-byte share key with **PVWRAP1**: an ephemeral X25519 key, HKDF-SHA256 (`salt = e_pk || recipient_pk`, `info = "pastevault:wrap:v1"`), then XChaCha20-Poly1305 with AAD `pastevault:wrap:v1:<context>:<recipient fingerprint>`. The envelope is `0x01 || e_pk(32) || nonce(24) || ciphertext(48)`, 105 bytes or 140 base64url characters. Contexts are `paste:<slug>`, `file-share:<slug>`, `request:<id>` and `store:<NAME>`. Fingerprints are `pvk1_` + base32 (lowercase, unpadded) of the first 20 bytes of `SHA-256("pastevault:agent-key:v1" || 0x00 || public_key)`. Low-order public keys (all-zero shared secret) and non-canonical ones (top bit set, or u ≥ 2^255−19) are refused, and keys and envelopes must use canonical base64url (no padding bits set).

`testdata/crypto/vectors.json` is generated from the web app's code by `node scripts/crypto-vectors.mjs` and checked with `--check` in CI. It includes fingerprint and wrap vectors and negative wrap cases (wrong context, wrong recipient, wrong fingerprint in the AAD, tampering, low-order and non-canonical keys). The Go tests and `frontend/src/lib/__tests__/crypto-vectors.test.ts` both read it; `npm run test:crypto` runs all three.
