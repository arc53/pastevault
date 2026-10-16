# PasteVault for agents

Coding agents need credentials (API keys, database passwords, tokens) and need to hand files to people and to other agents. Pasting those into a chat puts them in transcripts, logs and model context. PasteVault gives agents three things instead:

- **Secret requests.** The agent asks; you answer on a PasteVault page signed in to your account; the agent gets a handle like `pv://secret/OPENAI_API_KEY`, never the value.
- **`pastevault run`.** Handles become environment variables of one command, and the values are masked in its output.
- **Encrypted sharing.** Text and files are encrypted on the machine; shares sealed to an agent have no key in the link at all.

All of it works from the CLI (`--json`, stable exit codes) and from an MCP server (`pastevault mcp`) that agent harnesses load as a plugin or extension. The security properties and limits are in [security-model.md](security-model.md); every command and flag is in [cli-reference.md](cli-reference.md).

## 1. Install and sign in

Install the native CLI on the machine where the agent runs:

```bash
curl -fsSL https://raw.githubusercontent.com/arc53/pastevault/main/scripts/install.sh | sh     # macOS, Linux
irm https://raw.githubusercontent.com/arc53/pastevault/main/scripts/install.ps1 | iex          # Windows PowerShell
brew install --cask arc53/DocsGPT-cli/pastevault                                               # Homebrew
```

The CLI uses `https://api.pastevault.dev` unless you set `PASTEVAULT_SERVER` (or pass `--server`) for a self-hosted server.

Sign in, one of:

- **Interactive machine:** `pastevault login` (approve in the browser). This login session can do everything, including creating agent keys and API tokens.
- **Headless agent, CI, container:** create a token on a signed-in machine and give it to the agent:

  ```bash
  pastevault token create --name build-bot --agent build-bot --out build-bot.token   # after agent init, see below
  # on the agent's machine:
  pastevault login --with-token < build-bot.token     # or: export PASTEVAULT_TOKEN=pv_pat_...
  ```

  Tokens are scoped, expire after 90 days by default, and can be revoked (`pastevault token revoke`, or the web account page). A token bound to an agent (`--agent`) can only act for that agent. Tokens cannot create tokens, and default tokens cannot register agents.

  **Secret requests need an agent-bound token** (or the login session): `request` and the MCP `request_secret` tool refuse an unbound token (exit 3, `agent_bound_token_required`), because a request tells you "agent X asks for…" and a leaked general token must not be able to say that. Create the agent's token with `--agent NAME`, as above, or run `agent init` with an unbound token that has `agents:write`, which binds it to the new agent.

Check with `pastevault whoami --json`.

## 2. Give the agent a key

```bash
pastevault agent init --name build-bot
```

This creates an X25519 key pair on this machine (private key `0600` in the config directory), registers the public key with your account, and prints its fingerprint (`pvk1_…`). The agent needs it to make secret requests, to keep a local secret store, and to receive sealed shares. It needs a login session (or a token with `agents:write`).

For CI and containers, run `agent init` once elsewhere and provide the key through `PASTEVAULT_AGENT_KEY` (the `private_key` from the key file) as a CI secret.

## 3. Ask the human for a secret

```bash
pastevault request OPENAI_API_KEY --why "run the eval suite" --wait --json
```

1. The CLI makes a fresh key pair for this request and prints a link like `https://pastevault.dev/r/ABCD-EFGH#fp=pvk1_…`.
2. You open the link **signed in to the same account**. The page checks that the request key matches the `#fp=` in the link (a server can't swap it), shows which agent is asking and its reason (as untrusted text), and lets you type the value or drop a file. It is encrypted in your browser to the request key.
3. The agent receives it, stores it sealed to its own key in the local store, and prints `pv://secret/OPENAI_API_KEY`. The server deletes its encrypted copy.

You can also answer from a terminal: `pastevault request fulfil 'https://…/r/ABCD-EFGH#fp=pvk1_…' --from-stdin`, or decline with `pastevault request decline ABCD-EFGH`. Requests expire after 10 minutes by default (`--ttl`).

Without `--wait`, resume later with `pastevault await ABCD-EFGH`. Outcomes: exit 0 and the handle; 6 declined or cancelled; 5 expired; 9 timeout (the request stays open).

## 4. Use secrets: `run` and `.env.pv`

A `.env.pv` file lists handles instead of values, so it is safe to keep in the project (but still keep it out of public repos if the names are sensitive):

```
OPENAI_API_KEY=pv://secret/OPENAI_API_KEY
DATABASE_URL=pv://secret/DATABASE_URL
LOG_LEVEL=debug
```

```bash
pastevault run --env-file .env.pv -- npm test
```

`run` resolves the handles into the command's environment, strips `PASTEVAULT_TOKEN`, `PASTEVAULT_PASSWORD` and `PASTEVAULT_AGENT_KEY` from it, and replaces each value (and its base64, hex, URL and JSON encodings) with `[masked:NAME]` in the output. It keeps the command's exit code. Masking keeps values out of transcripts; it does not stop the command itself from using or leaking them. For config files: `pastevault inject -i config.tmpl -o config.yml` fills `{{ pv://secret/NAME }}` placeholders (written `0600`).

`pastevault secret list` shows what is stored; `secret import NAME --from-file F` adds a secret yourself; `secret rm NAME` deletes one.

## 5. Share with people and agents

```bash
pastevault put report.pdf --json                     # a link with #k=; 24h, or set --expires 1h --max-views 1
pastevault put .env --to build-bot --json            # sealed to an agent of your account: no key in the link
echo "notes" | pastevault put - --to build-bot
pastevault get https://pastevault.dev/p/abc123 -o notes.txt     # the recipient agent
pastevault get https://pastevault.dev/p/abc123 --save DEPLOY_ENV  # straight into the local store
pastevault status abc123 --wait viewed --json        # read receipt
```

- Sealed shares (`--to`) default to one view and one hour. Only the named agent's key can decrypt them, and only your account can open (or burn) them.
- The first `--to NAME` pins the agent's key; if the server later reports a different key, `put` fails with exit 8. Check the fingerprint with whoever runs that agent (`pastevault agent show`), then `pastevault agent trust NAME pvk1_…`.
- In the web app, "Share to agent" on the home page seals a paste or files to one of your agents; the agent opens it with `pastevault get`.

## 6. MCP server

`pastevault mcp` serves these tools over stdio:

| Tool | What it does | Annotations |
|---|---|---|
| `send_text` | Share text (defaults: 1 view, 1h; `to` seals it to an agent). Returns the link. | open world |
| `send_file` | Share files inside the allowed roots. | open world |
| `receive` | Open a share into `output_path` (inside the roots, `0600`) or the local store (`save_as`). Returns content only with `--allow-plaintext` + `allow_plaintext` and never if it looks like a secret. | destructive (uses a view) |
| `request_secret` | Ask the user for a secret; returns a `pv://secret/NAME` handle, never the value. | open world |
| `request_status` | Check a request; stores the answer when it has arrived. | read-only |
| `list_secrets` | Handles in the local store (no values). | read-only |
| `share_status` | Status, views and activity of a share you made; can wait for a read receipt. | read-only |
| `audit` | The account's audit log. | read-only |
| `revoke_share` | Delete a share you made. | destructive |

There is deliberately no tool that reads a secret's value: agents use `pastevault run` in their shell. The tool list and full JSON schemas are in [`internal/mcpserver/testdata/tools.golden.json`](../internal/mcpserver/testdata/tools.golden.json).

How `request_secret` reaches the user:

- If the client supports **URL-mode elicitation**, the server asks the client to show the request page; the user opens it, answers, and the tool returns the handle (waiting up to `timeout_seconds`, default 300).
- Otherwise the tool returns at once with `status: "pending"`, the `url` and the key fingerprint. The agent shows you the link, and calls `request_status` until it gets the handle.

Options:

```
pastevault mcp [--agent NAME] [--root DIR]... [--allow-plaintext] [--server URL]
```

- File tools are confined to roots: `--root` directories, plus the client's MCP roots; without either, the working directory (never the home directory or `/`). Credential directories (`~/.ssh`, `~/.aws`, ...) and the PasteVault config directory are refused even inside a root, symlinks may not lead out, and files are never overwritten unless the call says `overwrite`.
- The server uses the same configuration as the CLI: `PASTEVAULT_SERVER`, the stored login or token (or `PASTEVAULT_TOKEN`), the default agent (or `PASTEVAULT_AGENT`/`--agent`), `PASTEVAULT_CONFIG_DIR`. Some harnesses start MCP servers with a reduced environment: set these in the server's `env` block if you rely on them.
- Logs go to stderr; stdout carries only MCP messages.

### Claude Code

Install the plugin (MCP server + skill) from this repository's marketplace:

```
/plugin install pastevault --marketplace arc53/pastevault
```

or from a shell:

```bash
claude plugin marketplace add arc53/pastevault
claude plugin install pastevault@pastevault
```

Without the plugin, add only the MCP server:

```bash
claude mcp add --transport stdio --scope user pastevault -- pastevault mcp
claude mcp add --transport stdio --scope user --env PASTEVAULT_SERVER=https://paste.example.com pastevault -- pastevault mcp --root /path/to/project
```

Claude Code supports URL elicitation, so `request_secret` shows the request page directly. The plugin starts `pastevault mcp` with the default server and your stored login; for a self-hosted server, add the server with `claude mcp add … --env PASTEVAULT_SERVER=…` instead of (or as well as) the plugin.

### Codex

Install the plugin (MCP server + skill) from this repository's Codex marketplace (`.agents/plugins/marketplace.json`):

```bash
codex plugin marketplace add arc53/pastevault
codex plugin add pastevault@pastevault
```

Or configure only the MCP server, with `codex mcp add pastevault -- pastevault mcp` or the block in [`integrations/codex-config.toml`](../integrations/codex-config.toml) in `~/.codex/config.toml`:

```toml
[mcp_servers.pastevault]
command = "pastevault"
args = ["mcp"]
env_vars = ["PASTEVAULT_SERVER", "PASTEVAULT_TOKEN"]
tool_timeout_sec = 900
```

Codex passes only selected environment variables to MCP servers: list the PasteVault ones in `env_vars` (or set them under `[mcp_servers.pastevault.env]`). Raise `tool_timeout_sec` (default 60) so `request_secret` can wait for you. Without the plugin, copy `integrations/pastevault/skills/pastevault` to `~/.agents/skills/` or `.agents/skills/` in the project, or add [`integrations/AGENTS.snippet.md`](../integrations/AGENTS.snippet.md) to `AGENTS.md`.

### Gemini CLI

Gemini CLI installs extensions from a repository's root, so this repository has a root `gemini-extension.json` that points at the same MCP server and rules:

```bash
gemini extensions install https://github.com/arc53/pastevault
```

From a clone, `gemini extensions install ./integrations/pastevault` installs the extension directory itself (which also bundles the skill). Gemini CLI does not pass your shell environment to extensions: it asks for the optional settings `PASTEVAULT_SERVER` (self-hosted servers) and `PASTEVAULT_TOKEN` at install time (`gemini extensions config pastevault` changes them later). Leave them empty to use `pastevault login`.

Only the MCP server: `gemini mcp add -s user pastevault pastevault mcp`.

### Cursor, Windsurf, VS Code and other MCP clients

Most clients take the same JSON shape (for Cursor: `~/.cursor/mcp.json` or `.cursor/mcp.json` in the project):

```json
{
  "mcpServers": {
    "pastevault": {
      "type": "stdio",
      "command": "pastevault",
      "args": ["mcp"],
      "env": { "PASTEVAULT_SERVER": "https://api.pastevault.dev" }
    }
  }
}
```

Cursor expands `${env:NAME}` in `env` values (for example `"PASTEVAULT_TOKEN": "${env:PASTEVAULT_TOKEN}"`). Add the rules from [`integrations/AGENTS.snippet.md`](../integrations/AGENTS.snippet.md) to the project's `AGENTS.md` (or the client's rules file) so the agent knows to use `request_secret` instead of asking for secrets in chat.

### GitHub Copilot coding agent

Copilot's cloud agent takes MCP servers in the repository settings (Settings → Copilot → MCP servers). Install the CLI in the agent's environment in `.github/workflows/copilot-setup-steps.yml` (for example with the install script), then:

```json
{
  "mcpServers": {
    "pastevault": {
      "type": "local",
      "command": "pastevault",
      "args": ["mcp", "--root", "."],
      "env": {
        "PASTEVAULT_TOKEN": "$COPILOT_MCP_PASTEVAULT_TOKEN",
        "PASTEVAULT_AGENT_KEY": "$COPILOT_MCP_PASTEVAULT_AGENT_KEY"
      },
      "tools": ["*"]
    }
  }
}
```

Secrets for the MCP configuration must be **Agents** secrets (Settings → Secrets and variables → Agents) whose names start with `COPILOT_MCP_`; only those are passed, and they are hidden from the agent's shell. Use an API token bound to the agent (`pastevault token create --agent …`) and that agent's private key. If the agent's client does not offer URL elicitation, `request_secret` returns the link and the agent passes it on to you.

### DocsGPT

DocsGPT agents use MCP servers through **Settings → Connectors → Add custom connector → MCP server**. DocsGPT connects only to remote MCP servers (Streamable HTTP or SSE) on the public internet; it does not start stdio servers, and `pastevault mcp` speaks stdio only. To use PasteVault from DocsGPT you therefore have to run `pastevault mcp` behind a stdio-to-HTTP MCP gateway on a public HTTPS URL, with bearer or API-key authentication configured in the connector.

Think about that before doing it: whoever can call the gateway acts as that agent (shares, secret requests, its local store handles), and the store lives on the gateway's machine. Use a dedicated agent and an agent-bound token there, keep `--allow-plaintext` off, give it a dedicated `--root`, and protect the gateway like any credential. A native HTTP transport for `pastevault mcp` is a possible follow-up.

## 7. JSON and exit codes

Every CLI command takes `--json`: stdout is exactly one JSON object, errors are `{"error":{"code","message","exit_code"}}` (plus a line on stderr). MCP tool errors carry the same object as their text. The codes: 0 ok, 1 internal, 2 usage, 3 auth, 4 not found, 5 gone, 6 declined, 7 decryption failed, 8 fingerprint mismatch, 9 timeout, 10 rate limited, 11 network, 12 conflict, 13 local file exists or path refused, 14 server lacks the feature; `run` adds 125/126/127 and the command's own code. Details: [cli-reference.md](cli-reference.md#exit-codes).

## 8. Agent rules (skill)

The plugin ships an [Agent Skill](../integrations/pastevault/skills/pastevault/SKILL.md) with the rules agents should follow: never ask for secrets in chat (use `request_secret`), use `pv://secret` handles with `pastevault run`, prefer `to` for agent-to-agent shares, use `--json` and exit codes, never print secrets. For agents without plugin support, paste [`integrations/AGENTS.snippet.md`](../integrations/AGENTS.snippet.md) into `AGENTS.md` or `CLAUDE.md`.
