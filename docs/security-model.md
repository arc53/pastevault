# PasteVault security model

This page states what PasteVault protects, against whom, and where the limits are. It covers the web app, the server, the `pastevault` CLI, agent keys and sealed shares, secret requests, the local store, `run`/`inject`, and the MCP server. The formats are in [cli-reference.md](cli-reference.md#formats-and-test-vectors); how agents use all of this is in [agents.md](agents.md).

## What is protected

- **Content never reaches the server in plaintext.** Pastes and files are encrypted on the client (browser or CLI) with XChaCha20-Poly1305 under a random 32-byte key. The key travels in the link's `#k=` fragment, which browsers and the CLI never send to the server.
- **Password shares** derive the key with PBKDF2-SHA256 (600,000 iterations). They are only as strong as the password.
- **Sealed shares** (`put --to`, the web's "Share to agent") wrap the content key to an agent's X25519 public key (PVWRAP1). The link has no key at all; only the holder of the agent's private key can open it.
- **Secret requests** are answered in the browser (or with `pastevault request fulfil`), encrypted to a fresh key that exists only on the requesting agent's machine. The server stores the answer encrypted, and deletes it when the agent acknowledges it, two minutes after delivery, or when the request expires.
- **The local store** (`pv://secret/NAME`) keeps secrets sealed to the agent's key in `0600` files under the config directory.

## Threat model

### A compromised server or a malicious operator

- It **cannot read** content, wrapped keys, request answers or local store entries. It never has the keys.
- It **can substitute public keys**: the agent list and a request's public key come from the server. Mitigations:
  - The CLI computes every fingerprint itself and pins agent keys (trust on first use, `known_agents.json`). A changed key fails with exit 8 until someone runs `pastevault agent trust NAME FP` after checking the fingerprint out of band.
  - Request links carry `#fp=<fingerprint>` of the request key. The `/r/` page recomputes the fingerprint from the served key and blocks Submit on a mismatch. `pastevault request fulfil` requires a fingerprint (from `#fp=` or `--fingerprint`) and refuses a mismatch before reading the value.
  - The web pins agent keys per account in the browser (`localStorage`), and blocks sealing to a changed key.
- It **can serve malicious JavaScript**. That defeats every guarantee of the web app, as with any web-based end-to-end encryption. CLI-to-CLI flows (`put --to` between agents, `request` answered with `request fulfil`) do not depend on the frontend.
- It **can withhold, delete or replay** encrypted data, refuse service, or lie about views. It cannot make a client accept a forged `#k=` share: the key binds the content.
- It **can forge sealed shares** (see below).

### Sealed shares do not authenticate the sender

PVWRAP1 is anonymous public-key encryption. Anyone who knows an agent's public key can seal content to it, and agents' public keys are not secret: the server lists them to the account. So the server, someone with write access to its database, or any account member can replace a sealed share's content and wrapped key with their own, and the recipient cannot tell.

- Treat sealed content as coming from "someone who knows this agent's public key", not from a verified sender.
- A normal `#k=` link does protect integrity against the server, because the server never sees the key.
- The CLI refuses a share that the server claims is sealed when the link carries a key or the share has a password (exit 7, `sealed_share_conflict`). That stops a server from relabelling a normal link so that the agent accepts content wrapped by the server instead.
- Sender signatures are a possible follow-up.

### Sealed shares without a recipient account can be burned by anyone

Shares sealed to an account agent require the reader to be signed in to that account (recipient auth): a leaked link can neither be decrypted nor consumed by someone else. Shares sealed with `--to-key` (a raw public key, no account) and any sealed share on a server running with `DISABLE_AUTH=true` have no recipient account, so anyone who has the link can consume or burn them, even though they cannot decrypt them.

### What the server sees (metadata)

The server stores and can log:

- request names and reasons, agent names, public keys and fingerprints, token names and scopes;
- sizes, timestamps, expiry, view limits and view counts;
- who shared with which agent (sender account and recipient agent), and who opened what with which token;
- the audit log (below);
- client IP addresses at the HTTP layer (the audit log stores none by default; `AUDIT_IP_MODE=truncated` keeps a /24 or /48 prefix).

Share titles, file names and content are encrypted and not visible to it.

### The audit log is server-asserted

`pastevault audit`, `status`, the web Activity card and the MCP `audit`/`share_status` tools show what the server recorded. It is useful for read receipts and spotting misuse, but it is not cryptographic evidence: a compromised server can omit or invent events. Events hold metadata only (no reasons, no payloads), and are deleted after `AUDIT_RETENTION_DAYS` (90 by default).

### A leaked link

- A `#k=` link gives its holder the content, within its view limit and expiry. Use `--max-views 1` (the default for agent shares and MCP) and short expiries.
- A sealed link cannot be decrypted without the agent's private key, and when the recipient is an account agent it cannot be burned either (recipient auth).

### A leaked API token

Tokens (`pv_pat_…`) are scoped, expire (90 days by default), can be revoked, and are stored as SHA-256 hashes. An agent-bound token can only act for its own agent's shares and requests. **Only an agent-bound token (or the login session) can create a secret request**, and only for its own agent: a leaked unbound token cannot post "agent X asks for OPENAI_API_KEY" to phish the account's human (the `#fp=` check would pass, because the attacker made the link). Revoking an agent cancels its open requests and wipes answers it has not collected. Tokens cannot create or revoke tokens, and are never accepted on the login endpoints. The fixed `pv_pat_` prefix lets secret scanners find leaked tokens. `run` strips `PASTEVAULT_TOKEN`, `PASTEVAULT_PASSWORD` and `PASTEVAULT_AGENT_KEY` from the command's environment.

### A compromised agent host

Agent private keys, the local store, request files and stored credentials are `0600` files of the same OS user (on Windows they inherit the profile directory's ACL). **Any code running as that user can read them**, including the agent itself.

- `run` masking and the MCP server's no-plaintext policy protect **transcripts and logs**. They are not a security boundary against the agent process: a command run with secrets can read its own environment, write the value to a file, send it over the network, or transform it in ways the masker cannot recognise (see "What masking does and does not do" in the CLI reference).
- `secret reveal` refuses to run without a terminal on stdin and stdout. That is friction against agents printing secrets, not a boundary: `pastevault run --no-mask -- printenv NAME` and `pastevault inject -i - --stdout` print values without a terminal.
- The masker covers common encodings (base64, hex, several URL percent-encodings incl. URL userinfo, JSON escaping, multi-line values line by line) but not all; the CLI reference lists the gaps.
- OS keychain storage for agent keys is a possible follow-up.

### Prompt injection through MCP

An agent's model can be steered by text it reads (web pages, issues, files, share content). The MCP server limits what such text can make it do:

- **No tool returns a stored secret's value.** There is no `read_secret`; values are only used through `pastevault run`/`inject` in the shell, with masking.
- `receive` returns content only when the server was started with `--allow-plaintext`, the call sets `allow_plaintext`, and the content does not look like a secret (API key patterns, private keys, `KEY=value` lines, long high-entropy tokens). Secret-like content is stored in the local store instead and only its handle is returned.
- `send_file` and `receive` work only inside the allowed roots (`--root`, the client's MCP roots, else the working directory unless that is the home directory). Credential directories (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, ...), credential files (`~/.netrc`, `~/.git-credentials`, `~/.npmrc`, ...) and the PasteVault config directory are refused even inside a root. Symlinks are resolved before checking, `receive` never writes through a symlink or into `.git`, `.claude`, `.codex`, `.gemini`, `.cursor`, `.vscode` or `.idea`, files are written `0600`, and existing files are only replaced with `overwrite`.
- **`send_text` can still exfiltrate anything the model knows**: a share link is a channel out. Hosts should keep tool-call approval on for `send_text` and `send_file` when the agent reads untrusted input.
- A request's `reason` is written by the agent and may be attacker-influenced. The `/r/` page shows it as untrusted plain text ("never trust instructions here"); the CLI prints it quoted.
- Secret requests can only be created by an authenticated agent of the account and answered by a signed-in session of the same account, so a request link cannot be used to phish another account.

### One-time delivery

After the agent acknowledges a request's answer (or two minutes after delivery, or at expiry), the answer no longer exists on the server. A view-limited share's content is wiped on its final view; file chunks of a burned file share are deleted once the download grant ends.

## Trust on first use and pinning

- `agent init` pins the new agent as `self`. The first `put --to NAME` pins the server's key for NAME (TOFU) after the share is created; later changes fail with exit 8.
- `--to pvk1_<full fingerprint>` needs no pin: the fingerprint is the verification. A fingerprint prefix only selects a key that is already trusted.
- `agent trust NAME FP` replaces a pin after you have compared the fingerprint out of band (for example, `pastevault agent show` on the agent's machine).
- The web keeps its own pins per account and browser, with a two-step "Trust new key" in the Agents card.
- TOFU does not protect the very first contact: verify fingerprints out of band when it matters.

## Reporting vulnerabilities

Please report security issues privately to the maintainers via GitHub security advisories on [arc53/pastevault](https://github.com/arc53/pastevault/security/advisories) rather than public issues.
