# PasteVault

The `pastevault` MCP server gives you encrypted sharing and a way to get secrets without them entering the chat. The full rules are in the PasteVault skill (`skills/pastevault/SKILL.md` in this extension, or https://github.com/arc53/pastevault/blob/main/integrations/pastevault/skills/pastevault/SKILL.md). In short:

- Never ask the user to paste a secret into the chat. Call `request_secret`; the user answers on a PasteVault page and you get a `pv://secret/NAME` handle, never the value. Without URL elicitation, show the user the returned `url` and call `request_status` until it is `delivered`.
- Check `list_secrets` first. Use handles only from the shell: `NAME=pv://secret/NAME` lines in `.env.pv`, then `pastevault run --env-file .env.pv -- <command>`.
- Never print, echo, log or commit secret values; don't use `--no-mask` or `pastevault secret reveal`.
- For agent-to-agent shares use `send_text`/`send_file` with `to`. Only share what the user asked you to share.
- Receive into files (`output_path`) or the store (`save_as`), not into the conversation.
- With the CLI, always pass `--json` and branch on exit codes (3 auth, 4 not found, 5 gone, 6 declined, 7 decryption failed, 8 fingerprint mismatch: stop and tell the user, 13 path refused, 125 handle not resolved).
