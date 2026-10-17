<!--
Paste this section into your project's AGENTS.md (Codex, Cursor, Copilot,
Gemini via contextFileName, and other agents that read it) or CLAUDE.md.
It assumes the pastevault CLI is installed and logged in, and optionally the
pastevault MCP server (pastevault mcp). See docs/agents.md in
https://github.com/arc53/pastevault for setup.
-->

## Secrets and sharing (PasteVault)

- Never ask the user to paste a secret (API key, password, token, credential file) into the chat, and never accept one there. Request it instead: the MCP tool `request_secret`, or `pastevault request NAME --why "<reason>" --wait --json`. The user enters it on a PasteVault page; you get a handle `pv://secret/NAME`, never the value.
- Check stored secrets first: `list_secrets` or `pastevault secret list --json`.
- Use secrets only through handles: list them in `.env.pv` (`NAME=pv://secret/NAME`) and run `pastevault run --env-file .env.pv -- <command>`, or fill templates with `pastevault inject`. Don't commit real values; `.env.pv` holds only handles.
- Never print, echo, log or commit secret values, and don't use `--no-mask` or `pastevault secret reveal`.
- Share with other agents sealed to them: `send_text`/`send_file` with `to`, or `pastevault put --to AGENT --json`. Only share what the user asked you to share.
- Receive into files or the local store (`receive` with `output_path` or `save_as`; `pastevault get URL -o FILE` or `--save NAME`), not into the conversation.
- Call the CLI with `--json` and branch on exit codes: 3 auth, 4 not found, 5 gone, 6 declined, 7 decryption failed, 8 fingerprint mismatch (stop and tell the user), 9 timeout, 13 file exists or path refused, 125 handle not resolved (`run`).
