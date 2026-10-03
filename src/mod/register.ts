// ClaudeKeys mod: session-scoped, encrypted, read-only secrets that Claude
// uses in Bash commands as {{ck:NAME}} without ever reading the values.
//
// How a value travels (README.md, "Privacy model"):
//   1. You type it into a hidden zenity dialog, or the pane's field. It goes
//      straight to this module and on to the vault over stdin, never into the
//      conversation.
//   2. The vault (src/vault, Node) seals it with AES-256-GCM under a
//      per-session key derived from the master key in your keyring.
//   3. When Claude's Bash command holds {{ck:NAME}}, the value is written to a
//      one-time 0600 file on tmpfs; the shell reads it into $CK_NAME and
//      deletes it (inject.ts).
//   4. Tool results, prompts and transcript rows are masked before Claude
//      reads them or they are stored.

import type { EngineInterface, On, PluginOptions } from 'claude-code'
import { findPlaceholders, NAME_RE, normalizeName, placeholderFor, type SecretInfo } from '../shared/names.ts'
import {
  changed,
  effectiveCommand,
  guardReason,
  isRewritten,
  makeRedactor,
  maskOf,
  rewriteCommand,
  storagePatterns,
  type Redactor,
} from './inject.ts'

type VaultReply = { ok: boolean; error?: string; secrets?: SecretInfo[]; values?: Record<string, string> }
type Files = Record<string, string>

const PANE = 'claudekeys'
const LIST_TOOL = /^mcp__.*claudekeys.*__list_secrets$/

// Session state, rebuilt on load and after /clear, /resume and /branch.
let sessionId = ''
let dirs = { state: '', config: '', runtime: '' }
let meta: SecretInfo[] = []
let values: Record<string, string> | null = null
let announced = ''
// The placeholder-expanded command behind each rewritten one.
const effective = new Map<string, string>()

// Pane state.
let step: 'list' | 'value' = 'list'
let pendingName = ''
let confirmDelete = ''

// Options from userConfig.
let retainHours = 24
let showBadge = true

export function register(on: On, options: PluginOptions): void {
  if (typeof options.retain_hours === 'number') retainHours = options.retain_hours
  if (options.show_badge === false) showBadge = false

  on('session.start', async ($, e, next) => {
    await init($)
    try {
      await $.command.register({
        name: 'keys',
        description: "Open ClaudeKeys: this session's secrets (add, list, delete)",
        argumentHint: '[forget]',
        immediate: true,
      })
    } catch {
      // Registered already, after a reload.
    }
    return next(e)
  })

  // /clear, /resume and /branch move to another session id.
  on('classic.SessionStart', { source: ['clear', 'resume', 'fork'] }, async ($, e, next) => {
    await init($)
    return next(e)
  })

  on('session.end', async ($, e, next) => {
    values = null
    return next(e)
  })

  on('command.run', { command: 'keys' }, async ($, e) => {
    if (String(e.args ?? '').trim() === 'forget') {
      await vault($, { op: 'forget', sessionId })
      await refresh($)
      return { text: 'ClaudeKeys: forgot every secret of this session.' }
    }
    await openPane($)
    return {}
  })

  // Guard, inject and mask every tool call, subagents' and MCP tools' included.
  on('tool.call', async ($, e, next) => {
    const reason = guardReason(e as Record<string, unknown>, storagePatterns(dirs))
    if (reason) return { deny: reason }

    if (LIST_TOOL.test(e.tool)) return next({ ...e, session_id: sessionId } as typeof e)

    if (e.tool === 'Bash' && findPlaceholders(e.command).length > 0) {
      const prep = await prepareInjection($, e.command)
      if ('deny' in prep) return { deny: prep.deny }
      effective.set(prep.command, effectiveCommand(e.command))
      let result
      try {
        result = await next({ ...e, command: prep.command })
      } finally {
        effective.delete(prep.command)
        // A background command may not have read its files yet.
        if (e.run_in_background) $.clock.after(120000, () => void removeFiles($, prep.files))
        else await removeFiles($, prep.files)
      }
      return maskResult($, result)
    }

    if (meta.length === 0) return next(e)
    return maskResult($, await next(e))
  }).catch(async ($, e, next) => {
    // Fail closed: never hand Claude output that could not be checked.
    const kind = next.error?.kind ?? 'error'
    if (next.called) return { deny: 'ClaudeKeys could not check this output for secrets, so it was withheld (' + kind + ').' }
    return { deny: 'ClaudeKeys failed before running this call (' + kind + '): ' + (next.error?.message ?? '') }
  })

  // Decide a rewritten command as the command it stands for, so permission
  // rules such as Bash(gh *) still match and the ck-take prefix trips nothing.
  on('tool.check', { tool: 'Bash' }, async ($, e, next) => {
    const input = (e.input ?? {}) as Record<string, unknown>
    const cmd = input.command
    if (!isRewritten(cmd) || typeof cmd !== 'string' || !effective.has(cmd)) return next(e)
    try {
      return await $.tool.check({ tool: 'Bash', input: { ...input, command: effective.get(cmd) } })
    } catch {
      return next(e)
    }
  })

  // A secret pasted into a prompt becomes its placeholder before Claude reads
  // it, and Claude learns which names exist whenever the set changes.
  on('prompt.submit', async ($, e, next) => {
    if (meta.length === 0) return next(e)
    let text = e.text
    const red = await redactor($)
    const replaced = red.toPlaceholders(text)
    if (replaced !== text) {
      text = replaced
      void $.ui.toast('ClaudeKeys replaced a pasted secret with its placeholder.')
    }
    const names = meta.map((m) => m.name).join(',')
    const context = [...(e.context ?? [])]
    if (names !== announced) {
      announced = names
      context.push(announcement())
    }
    return next({ ...e, text, context })
  })

  // Last line of defence: mask anything else headed for the transcript, such
  // as task notifications, hook output and messages from other sessions.
  on('session.append', async ($, e, next) => {
    if (meta.length === 0) return next(e)
    const red = await redactor($)
    if (red.isEmpty) return next(e)
    const content = red.deep(e.message.content)
    if (!changed(content, e.message.content)) return next(e)
    return next({ ...e, message: { ...e.message, content } })
  })

  // The key badge, right-aligned in the band above the prompt.
  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    const theirs = await next(e)
    if (!showBadge) return theirs
    const { Box, Button } = $.ui.resolve(e)
    const n = meta.length
    const badge = Button({ key: 'ck-badge', label: '🔑 ' + n, plain: true, dimColor: n === 0, onPress: () => void openPane($) })
    // Claude Code draws the band's collapse control, [-], over its last
    // columns, so the badge keeps clear of them.
    const right = Box({ flexShrink: 0, paddingRight: 4, children: [badge] })
    return Box({
      flexDirection: 'row',
      justifyContent: 'flex-end',
      children: theirs ? [Box({ flexGrow: 1, flexShrink: 1, children: [theirs] }), right] : [right],
    })
  })

  // The popover: every secret with its length, and a form to add one.
  on('ui.render', { component: 'Pane' }, async ($, e, next) => {
    if (e.requestId !== PANE) return next(e)
    const elements = $.ui.resolve(e)
    const { Box, Text, Button } = elements
    // Not every surface has a text field; without one, only the dialog is offered.
    const Input = 'Input' in elements ? elements.Input : undefined
    const redraw = () => $.ui.invalidate('ui.render')
    const width = Math.max(30, Number(e.props.bodyColumns ?? 60))
    // Fit each row to the pane: name, dots, length, time, delete.
    const nameWidth = Math.min(Math.max(8, ...meta.map((m) => m.name.length)), Math.floor(width / 2))
    const dotsWidth = Math.max(3, Math.min(20, width - nameWidth - 26))

    const header = Box({
      flexDirection: 'row',
      justifyContent: 'space-between',
      children: [
        Text({ bold: true, children: ['🔑 ClaudeKeys · ' + meta.length + (meta.length === 1 ? ' secret' : ' secrets')] }),
        Text({ dimColor: true, children: [sessionId.slice(0, 8) + '   '] }),
      ],
    })

    const rows = meta.length === 0
      ? [Text({ dimColor: true, children: ['No secrets in this session yet.'] })]
      : meta.map((m) =>
          confirmDelete === m.name
            ? Box({
                key: 'row-' + m.name,
                flexDirection: 'row',
                columnGap: 2,
                children: [
                  Text({ color: 'red', children: ['Delete ' + m.name + '?'] }),
                  Button({ key: 'del-yes-' + m.name, label: 'Delete', onPress: async () => { confirmDelete = ''; await deleteSecret($, m.name); redraw() } }),
                  Button({ key: 'del-no-' + m.name, label: 'Keep', onPress: () => { confirmDelete = ''; redraw() } }),
                ],
              })
            : Box({
                key: 'row-' + m.name,
                flexDirection: 'row',
                columnGap: 2,
                children: [
                  Text({ bold: true, wrap: 'truncate', children: [m.name.padEnd(nameWidth)] }),
                  Text({ dimColor: true, children: [maskOf(m.length, dotsWidth)] }),
                  Text({ children: [m.length + (m.length === 1 ? ' char' : ' chars')] }),
                  Text({ dimColor: true, children: [timeOf(m.addedAt)] }),
                  Button({ key: 'del-' + m.name, label: 'x', plain: true, onPress: () => { confirmDelete = m.name; redraw() } }),
                ],
              }),
        )

    const form = step === 'value'
      ? [
          Text({ children: ['Value for ' + pendingName + ' (Claude only ever sees its length):'] }),
          Button({ key: 'ck-hidden', label: 'Type it in a hidden dialog', hotkey: 'h', autoFocus: true, onPress: async () => { await addFromDialog($); redraw() } }),
          Input?.({
            key: 'ck-value',
            label: 'Or here',
            placeholder: 'visible as you type; Enter saves',
            value: '',
            submitLabel: 'save',
            onSubmit: async (value: string) => { await addSecret($, pendingName, value); redraw() },
          }),
          Button({ key: 'ck-cancel', label: 'Cancel', plain: true, dimColor: true, onPress: () => { step = 'list'; pendingName = ''; redraw() } }),
        ]
      : [
          Input?.({
            key: 'ck-name',
            label: 'Add',
            placeholder: 'NAME, e.g. GH_TOKEN',
            value: '',
            submitLabel: 'next',
            autoFocus: true,
            onSubmit: (value: string) => { startAdd($, value); redraw() },
          }),
        ]

    return Box({
      flexDirection: 'column',
      children: [
        header,
        ...rows,
        Text({ dimColor: true, children: ['─'.repeat(Math.min(width, 60))] }),
        ...form.filter((x) => x !== undefined),
        Text({ dimColor: true, wrap: 'wrap', children: ['Claude writes {{ck:NAME}} in Bash commands; values are filled in at run time and masked in all output.'] }),
      ],
    })
  })
}

// --- Vault ------------------------------------------------------------------------

// One request to the Node vault, over stdin so a value never reaches argv.
async function vault($: EngineInterface, req: Record<string, unknown>): Promise<VaultReply> {
  const r = await $.process.run(['node', $.plugin.root + '/dist/vault/cli.js'], { stdin: JSON.stringify(req), timeoutMs: 120000 })
  let reply: VaultReply
  try {
    reply = JSON.parse(r.stdout) as VaultReply
  } catch {
    throw new Error('ClaudeKeys vault failed (exit ' + r.exitCode + '): ' + r.stderr.trim().slice(0, 300))
  }
  if (!reply.ok) throw new Error(reply.error ?? 'ClaudeKeys vault failed')
  return reply
}

async function init($: EngineInterface): Promise<void> {
  sessionId = await $.session.id()
  const home = (await $.env.get('HOME')) ?? ''
  dirs = {
    state: (await $.env.get('XDG_STATE_HOME')) || home + '/.local/state',
    config: (await $.env.get('XDG_CONFIG_HOME')) || home + '/.config',
    runtime: (await $.env.get('XDG_RUNTIME_DIR')) ?? '',
  }
  values = null
  announced = ''
  step = 'list'
  pendingName = ''
  confirmDelete = ''
  try {
    await vault($, { op: 'purge', retainHours })
  } catch {
    // Purging is housekeeping; a failure must not stop the session.
  }
  await refresh($)
}

async function refresh($: EngineInterface): Promise<void> {
  try {
    meta = (await vault($, { op: 'list', sessionId })).secrets ?? []
  } catch (err) {
    meta = []
    void $.ui.toast(String(err instanceof Error ? err.message : err))
  }
  values = null
  $.ui.invalidate('ui.render')
}

// Every value, decrypted once per session and kept in this process only.
async function secretValues($: EngineInterface): Promise<Record<string, string>> {
  if (values) return values
  if (meta.length === 0) return (values = {})
  values = (await vault($, { op: 'reveal', sessionId })).values ?? {}
  return values
}

async function redactor($: EngineInterface): Promise<Redactor> {
  return makeRedactor(await secretValues($))
}

// --- Adding and deleting -------------------------------------------------------------

function startAdd($: EngineInterface, raw: string): void {
  const name = normalizeName(raw)
  if (!NAME_RE.test(name)) {
    void $.ui.toast('Names start with a letter and use A-Z, 0-9 and _ (up to 64).')
    return
  }
  if (meta.some((m) => m.name === name)) {
    void $.ui.toast(name + ' is already set. Secrets are read-only: delete it first to replace it.')
    return
  }
  pendingName = name
  step = 'value'
}

async function addFromDialog($: EngineInterface): Promise<void> {
  let r
  try {
    r = await $.process.run(['zenity', '--password', '--title=ClaudeKeys: ' + pendingName], { timeoutMs: 300000 })
  } catch {
    void $.ui.toast('No hidden dialog available (zenity). Type the value in the field instead.')
    return
  }
  if (r.exitCode !== 0) return
  await addSecret($, pendingName, r.stdout.replace(/\r?\n$/, ''))
}

async function addSecret($: EngineInterface, name: string, value: string): Promise<void> {
  if (!name || step !== 'value') return
  if (!value) {
    void $.ui.toast('Empty value: nothing saved.')
    return
  }
  try {
    meta = (await vault($, { op: 'add', sessionId, name, value })).secrets ?? meta
  } catch (err) {
    void $.ui.toast(String(err instanceof Error ? err.message : err))
    return
  }
  if (values) values[name] = value
  step = 'list'
  pendingName = ''
  $.ui.invalidate('ui.render')
  void $.ui.toast(name + ' saved (' + value.length + ' chars)' + (value.length < 8 ? '. Short values are masked only as typed, not in encoded forms.' : '.'))
}

async function deleteSecret($: EngineInterface, name: string): Promise<void> {
  try {
    meta = (await vault($, { op: 'delete', sessionId, name })).secrets ?? []
  } catch (err) {
    void $.ui.toast(String(err instanceof Error ? err.message : err))
    return
  }
  if (values) delete values[name]
  $.ui.invalidate('ui.render')
  void $.ui.toast(name + ' deleted.')
}

// --- Injection -------------------------------------------------------------------

async function prepareInjection($: EngineInterface, command: string): Promise<{ deny: string } | { command: string; files: Files }> {
  const names = findPlaceholders(command)
  const known = new Set(meta.map((m) => m.name))
  const missing = names.filter((n) => !known.has(n))
  if (missing.length > 0) {
    const have = meta.map((m) => placeholderFor(m.name)).join(', ') || 'none'
    return { deny: 'No ClaudeKeys secret named ' + missing.join(', ') + '. Available: ' + have + '. Ask the user to add it with /keys.' }
  }
  if (!dirs.runtime) return { deny: 'ClaudeKeys needs $XDG_RUNTIME_DIR (a private tmpfs) to hand values to commands, and it is not set.' }
  const vals = await secretValues($)
  const files: Files = {}
  for (const name of names) {
    const file = dirs.runtime + '/claudekeys-' + nonce()
    await writePrivate($, file, vals[name] ?? '')
    files[name] = file
  }
  return { command: rewriteCommand(command, files, $.plugin.root + '/bin/ck-take'), files }
}

async function removeFiles($: EngineInterface, files: Files): Promise<void> {
  const paths = Object.values(files)
  if (paths.length > 0) await $.process.run(['rm', '-f', '--', ...paths])
}

// Write a file only this user can read. The text goes through stdin.
async function writePrivate($: EngineInterface, path: string, text: string): Promise<void> {
  const r = await $.process.run(['sh', '-c', 'umask 077 && cat > "$1"', 'sh', path], { stdin: text })
  if (r.exitCode !== 0) throw new Error('could not write ' + path + ': ' + r.stderr.trim())
}

// Mask secrets in a tool result. An unchanged result goes back as it came, so
// Claude Code keeps its own rendering of it.
async function maskResult<R>($: EngineInterface, result: R): Promise<R> {
  const r = result as { deny?: string; result?: unknown; text?: string; context?: readonly string[]; isError?: boolean }
  if (!r || r.deny !== undefined) return result
  const shape = r.result as { isImage?: boolean; type?: string } | undefined
  if (shape?.isImage || shape?.type === 'image') return result
  const red = await redactor($)
  if (red.isEmpty) return result
  const masked = red.deep(r.result)
  const text = typeof r.text === 'string' ? red.text(r.text) : r.text
  const context = r.context ? r.context.map((c) => red.text(c)) : undefined
  const dirty = changed(masked, r.result) || text !== r.text || (context !== undefined && changed(context, r.context))
  if (!dirty) return result
  if (r.isError) return { deny: text ?? 'The command failed, and its output held a secret, so it was withheld.' } as R
  return (context ? { result: masked, context } : { result: masked }) as R
}

// --- Helpers --------------------------------------------------------------------

async function openPane($: EngineInterface): Promise<void> {
  step = 'list'
  pendingName = ''
  confirmDelete = ''
  await $.ui.open({ id: PANE, title: 'ClaudeKeys', focus: true, closeOnEscape: true, rows: 14 })
}

function nonce(): string {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  let out = ''
  for (const b of bytes) out += b.toString(16).padStart(2, '0')
  return out
}

function announcement(): string {
  const list = meta.map((m) => placeholderFor(m.name) + ' (' + m.length + ' chars)').join(', ')
  return (
    'ClaudeKeys: the user has stored ' + meta.length + ' secret(s) for this session: ' + list + '. ' +
    'To use one, write its placeholder inside double quotes in a Bash command where the value goes, for example ' +
    'curl -H "Authorization: Bearer {{ck:API_TOKEN}}" https://... or GH_TOKEN="{{ck:GH_TOKEN}}" gh pr list. ' +
    'ClaudeKeys fills it in when the command runs. You cannot see the values and must not try to print or decode them; ' +
    'any output that contains one shows [ck:NAME] instead. The list_secrets tool lists them again.'
  )
}

function timeOf(ms: number): string {
  if (!ms) return ''
  const d = new Date(ms)
  return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0')
}
