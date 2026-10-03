# ClaudeKeys

Session-scoped, encrypted, read-only secrets for [Claude Code](https://code.claude.com). You
store a token once in the session, and Claude uses it in commands as `{{ck:NAME}}`. Claude
never sees the value: it is filled in when the command runs, and masked everywhere it could
come back.

![ClaudeKeys demo: a secret is added in the /keys pane, Claude sends it as a bearer token, the server confirms it received the real value, and Claude only ever sees [ck:DEMO_TOKEN]](docs/demo.gif)

[Watch the demo as MP4](docs/demo.mp4). In the demo the local server reports
`"token_matches_the_real_secret": true`, so the real value arrived, while Claude reads
`Bearer [ck:DEMO_TOKEN]`.

## What you get

- **A key pill inside the prompt box** (`🔑 2`) with the number of secrets in this session.
  It sits in the prompt's footer, after Claude Code's mode labels: beside the submit and
  stop button in the Desktop app, and at the right end of the footer row in the terminal.
  Press it, or run `/keys`, to open the pane.
- **The pane**: every secret with its name, its length shown as dots, and when it was
  added. You add a secret by name, then type the value into a hidden dialog (zenity) or the
  pane's field. Delete with `x`.
- **Read-only secrets**: a name can't be overwritten. Delete it and add it again to replace
  it. Claude has no tool to add, change or read a value.
- **A stdio MCP server** with one read-only tool, `list_secrets`, which lists and filters
  this session's secrets by name (substring or glob such as `GH_*`). It returns names,
  lengths and placeholders, never values.
- **Injection**: Claude writes the placeholder in a Bash command, inside double quotes:

  ```bash
  curl -H "Authorization: Bearer {{ck:API_TOKEN}}" https://api.example.com/me
  GH_TOKEN="{{ck:GH_TOKEN}}" gh pr list
  ```

- **Masking**: any tool result, transcript row or notification that contains a value
  shows `[ck:NAME]` instead. If you paste a stored value into a prompt, it becomes its
  placeholder before Claude reads it.

## Install

Requirements: Claude Code **2.1.287 or later** (mods), Node.js 22 or later, Linux with
`$XDG_RUNTIME_DIR` (any systemd desktop). Optional: `zenity` for the hidden input dialog,
and `libsecret-tools` (`sudo apt install libsecret-tools`) to keep the master key in the
GNOME keyring instead of a 0600 file.

```text
/plugin marketplace add dixonSolutions/ClaudeKeys
/plugin install claudekeys@dixonsolutions
```

Two options appear in `/config`: `retain_hours`, how long an unused session's secrets
are kept (default 24, so they survive `/resume`), and `show_badge`, which shows or hides the pill.

## Privacy model

ClaudeKeys has three parts. The **mod** (`src/mod`) runs inside Claude Code: it draws the
pill and pane, and rewrites and masks tool calls. The **vault** (`src/vault`) is a small
Node program that does the encryption. The **MCP server** (`src/mcp`) lists names.
Encryption lives in Node because the mods runtime only offers `crypto.subtle.digest`,
with no AES or HKDF.

### Encryption at rest

```
master key (32 random bytes)          GNOME keyring via secret-tool, or ~/.config/claudekeys/master.key (0600)
   │
   └─ HKDF-SHA256(master, salt = 16 random bytes per session, info = "claudekeys/v1/session/<session id>")
        │
        └─ session key ── AES-256-GCM, fresh 96-bit IV per secret,
                           AAD = "claudekeys/v1|<session id>|<NAME>"
```

- The **master key** is your ClaudeKeys private key. It is generated on first use and only
  the vault reads it. It never enters the mod, a command line or the conversation.
- The **session id** separates keys, but it is not a key itself: it isn't secret, and it
  is not a public key. Mixed into HKDF, it gives every session its own AES key, so a record
  copied into another session can't be opened there.
- The **AAD** binds each ciphertext to its session and name. A value moved to another name
  fails to decrypt, so you never get the wrong value under the right name.
- Each session is one file, `~/.local/state/claudekeys/sessions/<session id>.json` (0600).
  It holds the salt, the ciphertexts, and the names, lengths and times in the clear, which
  is what the MCP server reads.

### Getting a value into a command without Claude seeing it

1. You type the value into the zenity dialog or the pane. It goes from the mod to the vault
   over **stdin**, never through argv or the conversation.
2. When Claude's Bash command contains `{{ck:NAME}}`, the mod asks the vault for the value
   once per session and keeps it in Claude Code's own memory. It writes the value to a
   **one-time 0600 file on tmpfs** (`$XDG_RUNTIME_DIR/claudekeys-<random>`) and rewrites
   the command:

   ```bash
   CK_API_TOKEN="$(sh '<plugin>/bin/ck-take' '/run/user/1000/claudekeys-9f3…')" || exit 97; export CK_API_TOKEN
   curl -H "Authorization: Bearer ${CK_API_TOKEN}" https://api.example.com/me
   ```

   `ck-take` prints the file and deletes it. The value lives only in that one shell's
   environment. It never appears in the command text, the transcript, or any process's
   argv. The transcript keeps the command Claude wrote, with the placeholder.
3. The permission check sees the command as Claude meant it (`curl … ${CK_API_TOKEN}`), so
   rules such as `Bash(curl *)` still match.
4. Before Claude reads the result, every string in it is scanned for the value and its
   common encodings: base64, base64url, hex, URL-encoding, JSON-escaping, reversed. Each
   match becomes `[ck:NAME]`. A masked result is also what the transcript stores. If
   masking fails for any reason, the output is withheld rather than shown.

### Guard

Before anything runs, ClaudeKeys refuses tool calls that:

- read the vault's files, the master key or a one-time file
- run the vault CLI, ask `secret-tool` for the ClaudeKeys key, or name a `CK_` variable directly
- put a placeholder next to `echo`, `printf`, `env`, `set`, `base64`, `xxd`, `tee` and similar
- put a placeholder in any tool other than Bash, such as Write or an MCP tool, so a value
  is never written to a file or sent as text

## Limits

This is a **privacy** tool, not a security boundary. It keeps secrets out of the model's
context, the transcript and your screen recordings, and it makes leaking one by accident
very unlikely. It does not stop a model, or a person, set on extracting one:

- Claude chooses the command, so the program the value goes to can do anything with it,
  such as print it in a form the masking doesn't recognise.
- Masking matches exact values and the encodings listed above. Values shorter than 8
  characters are masked only verbatim, and values shorter than 4 not at all.
- Everything runs as you. Any process of yours can read the master key file, or ask the
  keyring if it is unlocked. The guard blocks only the obvious routes.
- `$(…)` drops trailing newlines, so a value that ends in a newline loses it.
- The pane's own field shows the value as you type. Use the hidden dialog when someone is
  watching, or when you're recording.
- Developed and tested on Linux (Ubuntu, GNOME) with Claude Code 2.1.288. The mods API is
  new and may change between releases.

## Develop

```bash
npm install
npm run types        # one short headless session, so Claude Code writes its mod types for your version
npm run build        # tsc: src/ → dist/ (the plugin runs dist/)
npm test             # build, Node specs (vault, crypto, MCP), mod tests (claude plugin test), validate
claude --plugin-dir .   # try it; rebuilt files reload within ~30 s
```

```
src/shared/names.ts   names, placeholders, filters: used by all three parts
src/mod/register.ts   the mod: pill, pane, /keys, tool.call guard + injection + masking
src/mod/inject.ts     pure helpers: command rewrite, guard, masking
src/vault/            Node: crypto.ts (HKDF + AES-GCM), keys.ts (keyring/file), store.ts, cli.ts
src/mcp/server.ts     Node: stdio MCP server with list_secrets
bin/ck-take           prints a one-time file and deletes it
spec/                 Node tests (compiled with tsc, run with node --test)
tests/                mod tests (claude plugin test)
```

`dist/` is committed, because installing from a marketplace doesn't run a build.
`.claude-plugin/types/` is written by Claude Code for the version you run, whenever it
loads the mod from `--plugin-dir`, and is ignored by git (Claude Code says so itself).

## License

MIT
