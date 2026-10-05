// The /keys command line, so secrets can be managed where no pane is drawn
// (the web and mobile clients over Remote Control). Pure: no mods API, so
// tests can call every function directly.
//
//   /keys                          the pane (a text summary where none is drawn)
//   /keys list                     names and lengths
//   /keys add NAME --env VAR       read the value on this machine: an
//   /keys add NAME --file PATH       environment variable, a file, or a
//   /keys add NAME --cmd COMMAND     command's output (gh auth token, pass ...)
//   /keys add NAME                 ask for the value in a dialog
//   /keys add NAME VALUE           the value inline (masked in the echo)
//   /keys rm NAME                  delete one
//   /keys forget                   delete every secret of this session

import { maskFor, NAME_RE, normalizeName } from '../shared/names.ts'

export type Source = { kind: 'env' | 'file' | 'cmd'; ref: string }

export type KeysCommand =
  | { op: 'open' }
  | { op: 'help' }
  | { op: 'list' }
  | { op: 'forget' }
  | { op: 'rm'; name: string }
  | { op: 'add'; name: string; value?: string; source?: Source }
  | { op: 'error'; message: string }

const ADD_RE = /^\s*add\s+(\S+)(?:\s+([\s\S]*))?$/i
const SOURCE_RE = /^--(env|file|cmd)(?:\s+([\s\S]*))?$/

export const USAGE = [
  '/keys add NAME --env VAR       value from an environment variable on this machine',
  '/keys add NAME --file PATH     value from a file on this machine',
  '/keys add NAME --cmd COMMAND   value from a command\'s output (gh auth token, pass show x)',
  '/keys add NAME                 type the value into a dialog',
  '/keys add NAME VALUE           the value inline (sent with the command)',
  '/keys list | rm NAME | forget',
].join('\n')

/** Strips one pair of matching quotes around the whole string. */
function unquote(s: string): string {
  const m = /^(["'])([\s\S]*)\1$/.exec(s)
  return m ? m[2]! : s
}

export function parseKeysArgs(args: string): KeysCommand {
  const text = args.trim()
  if (text === '') return { op: 'open' }
  const [word = '', ...rest] = text.split(/\s+/)
  switch (word.toLowerCase()) {
    case 'help':
      return { op: 'help' }
    case 'list':
    case 'ls':
      return { op: 'list' }
    case 'forget':
      return { op: 'forget' }
    case 'rm':
    case 'del':
    case 'delete': {
      const name = normalizeName(rest.join(' '))
      return NAME_RE.test(name) ? { op: 'rm', name } : { op: 'error', message: 'Usage: /keys rm NAME' }
    }
    case 'add': {
      const m = ADD_RE.exec(text)
      if (!m) return { op: 'error', message: 'Usage:\n' + USAGE }
      const name = normalizeName(m[1]!)
      if (!NAME_RE.test(name)) return { op: 'error', message: 'Names start with a letter and use A-Z, 0-9 and _ (up to 64).' }
      const tail = (m[2] ?? '').trim()
      if (tail === '') return { op: 'add', name }
      const src = SOURCE_RE.exec(tail)
      if (src) {
        const ref = unquote((src[2] ?? '').trim())
        if (!ref) return { op: 'error', message: '--' + src[1] + ' needs a value: ' + USAGE.split('\n').find((l) => l.includes('--' + src[1]))!.trim() }
        return { op: 'add', name, source: { kind: src[1] as Source['kind'], ref } }
      }
      return { op: 'add', name, value: unquote(tail) }
    }
    default:
      return { op: 'error', message: 'Unknown /keys command "' + word + '". Usage:\n' + USAGE }
  }
}

/** The args with an inline value replaced by its mask; anything else unchanged. */
export function maskKeysArgs(args: string): string {
  const cmd = parseKeysArgs(args)
  if (cmd.op !== 'add' || cmd.value === undefined) return args
  const m = ADD_RE.exec(args)!
  return args.slice(0, args.length - m[2]!.length) + maskFor(cmd.name)
}

const ECHO_RE = /(<command-name>\/(?:[\w-]+:)?keys<\/command-name>[\s\S]*?<command-args>)([\s\S]*?)(<\/command-args>)/g
const TYPED_RE = /^(\s*\/(?:[\w-]+:)?keys\s+)([\s\S]*)$/

/**
 * Masks an inline value in a recorded /keys command: the engine's echo row
 * (`<command-name>/keys</command-name> ... <command-args>add N V</command-args>`)
 * or the line as typed (`/keys add N V`).
 */
export function maskKeysCommandText(text: string): string {
  if (text.includes('<command-args>')) return text.replace(ECHO_RE, (_all, a: string, args: string, b: string) => a + maskKeysArgs(args) + b)
  const m = TYPED_RE.exec(text)
  return m ? m[1]! + maskKeysArgs(m[2]!) : text
}

// Masks the inline value of a /keys add echo in a row's text blocks.
export function maskEcho<T>(content: T): T {
  if (!Array.isArray(content)) return content
  let dirty = false
  const out = content.map((block: unknown) => {
    const b = block as { type?: string; text?: unknown }
    if (b?.type !== 'text' || typeof b.text !== 'string') return block
    const text = maskKeysCommandText(b.text)
    if (text === b.text) return block
    dirty = true
    return { ...b, text }
  })
  return (dirty ? out : content) as T
}

/** Whether a Skill tool call would run /keys (Claude must not manage secrets). */
export function isKeysSkill(e: Record<string, unknown>): boolean {
  if (e.tool !== 'Skill') return false
  const skill = String(e.skill ?? e.command ?? '').trim().replace(/^\//, '').split(/\s/)[0] ?? ''
  return /(^|:)keys$/.test(skill)
}

/** Expands a leading ~/ against HOME. */
export function expandHome(path: string, home: string): string {
  return path === '~' ? home : path.startsWith('~/') ? home + path.slice(1) : path
}

/** A value read from a file or a command, without the one trailing newline. */
export function chompValue(s: string): string {
  return s.replace(/\r?\n$/, '')
}
