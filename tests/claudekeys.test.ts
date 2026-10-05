// Mod tests: `claude plugin test`. No session, model or network: every call
// the mod makes to Claude Code is answered by a stub, and the vault is faked.

import type { On } from 'claude-code'
import { expect, mock, test } from 'claude-code/testing'
import { guardReason, makeRedactor, rewriteCommand, storagePatterns, variantsOf } from '../src/mod/inject.ts'
import { findPlaceholders, filterMatches, normalizeName } from '../src/shared/names.ts'
import { isKeysSkill, maskEcho, maskKeysCommandText, parseKeysArgs } from '../src/mod/command.ts'

const SECRET = 'ghp_TopSecretValue12345'
const DIRS = { state: '/home/u/.local/state', config: '/home/u/.config', runtime: '/run/user/1000' }

// --- Pure functions -----------------------------------------------------------

test('placeholders are found once each, in order', async () => {
  expect(findPlaceholders('a {{ck:B}} {{ck:A}} {{ ck:B }}')).toEqual(['B', 'A'])
  expect(normalizeName(' gh token ')).toBe('GH_TOKEN')
  expect(filterMatches('GH_TOKEN', 'gh_*')).toBe(true)
  expect(filterMatches('GH_TOKEN', 'npm')).toBe(false)
})

test('the rewritten command carries file paths, never the value', async () => {
  const cmd = rewriteCommand('curl -H "Authorization: Bearer {{ck:GH_TOKEN}}" https://x', { GH_TOKEN: '/run/user/1000/claudekeys-abc' }, '/p/bin/ck-take')
  expect(cmd).toContain("sh '/p/bin/ck-take' '/run/user/1000/claudekeys-abc'")
  expect(cmd).toContain('Bearer ${CK_GH_TOKEN}')
  expect(cmd).not.toContain('{{ck:')
})

test('masking catches the value and its common encodings', async () => {
  const red = makeRedactor({ GH_TOKEN: SECRET })
  const b64 = btoa(SECRET)
  expect(red.text('token=' + SECRET)).toBe('token=[ck:GH_TOKEN]')
  expect(red.text(b64)).toBe('[ck:GH_TOKEN]')
  expect(red.text([...SECRET].reverse().join(''))).toBe('[ck:GH_TOKEN]')
  expect(red.deep({ stdout: 'x ' + SECRET, n: 1 })).toEqual({ stdout: 'x [ck:GH_TOKEN]', n: 1 })
  expect(red.toPlaceholders('use ' + SECRET)).toBe('use {{ck:GH_TOKEN}}')
  expect(variantsOf('abc')).toEqual([])
  expect(variantsOf('1122x')).toEqual(['1122x'])
})

test('the guard refuses storage, internals and printing commands', async () => {
  const p = storagePatterns(DIRS)
  expect(guardReason({ tool: 'Read', file_path: '/home/u/.local/state/claudekeys/sessions/s.json' }, p)).toContain('off limits')
  expect(guardReason({ tool: 'Bash', command: 'cat ~/.config/claudekeys/master.key' }, p)).toContain('off limits')
  expect(guardReason({ tool: 'Bash', command: 'node /x/dist/vault/cli.js' }, p)).toContain('off limits')
  expect(guardReason({ tool: 'Bash', command: 'echo $CK_GH_TOKEN' }, p)).toContain('off limits')
  expect(guardReason({ tool: 'Bash', command: 'echo "{{ck:GH_TOKEN}}"' }, p)).toContain('could print')
  expect(guardReason({ tool: 'Bash', command: 'GH_TOKEN="{{ck:GH_TOKEN}}" env' }, p)).toContain('could print')
  expect(guardReason({ tool: 'Write', file_path: '.env', content: 'T={{ck:GH_TOKEN}}' }, p)).toContain('only inside Bash')
  expect(guardReason({ tool: 'Bash', command: 'set -e; GH_TOKEN="{{ck:GH_TOKEN}}" gh pr list' }, p)).toBe(null)
  expect(guardReason({ tool: 'Bash', command: 'ls' }, p)).toBe(null)
})

// --- The mod, through Claude Code's events -----------------------------------

type Vault = Map<string, string>

// Stubs for everything the mod calls. The vault CLI is faked in memory.
function harness(on: On, vault: Vault) {
  const toasts: string[] = []
  const ran: string[][] = []
  const writes = new Map<string, string>()
  mock.clock(on)
  on('session.id', () => ({ value: 'sess-1234abcd' }))
  on('env.get', ($, e) => ({ value: ({ HOME: '/home/u', XDG_RUNTIME_DIR: '/run/user/1000' } as Record<string, string>)[e.name] }))
  on('command.register', () => ({ value: undefined }) as never)
  // The engine's record of a /keys run: what it was handed is what it keeps.
  const recorded: string[] = []
  on('command.run', ($, e) => {
    recorded.push(e.args)
    return {}
  })
  on('ui.toast', ($, e) => {
    toasts.push(e.text)
    return { value: undefined } as never
  })
  on('ui.open', () => ({ value: { isPlaced: true } }) as never)
  on('process.run', ($, e) => {
    ran.push([...e.argv])
    if (e.argv[1]?.endsWith('/dist/vault/cli.js')) {
      const req = JSON.parse(e.init?.stdin ?? '{}')
      const list = () => [...vault.keys()].map((name, i) => ({ name, length: vault.get(name)!.length, addedAt: i + 1 }))
      let reply: object = { ok: true }
      if (req.op === 'list') reply = { ok: true, secrets: list() }
      if (req.op === 'add') {
        vault.set(req.name, req.value)
        reply = { ok: true, secrets: list() }
      }
      if (req.op === 'reveal') reply = { ok: true, values: Object.fromEntries(vault) }
      if (req.op === 'delete') {
        vault.delete(req.name)
        reply = { ok: true, secrets: list() }
      }
      return { value: { exitCode: 0, stdout: JSON.stringify(reply), stderr: '' } } as never
    }
    if (e.argv[0] === 'printenv') {
      const v = e.argv[2] === 'HOST_TOKEN' ? 'from-the-environment-123\n' : ''
      return { value: { exitCode: v ? 0 : 1, stdout: v, stderr: '' } } as never
    }
    if (e.argv[0] === 'sh' && e.argv[1] === '-c' && e.argv[2] === 'gh auth token') {
      return { value: { exitCode: 0, stdout: 'gho_FromTheCommand9876\n', stderr: '' } } as never
    }
    if (e.argv[0] === 'sh' && e.argv[4]) writes.set(e.argv[4], e.init?.stdin ?? '')
    return { value: { exitCode: 0, stdout: '', stderr: '' } } as never
  })
  return { toasts, ran, writes, recorded }
}

test('a placeholder is injected through a one-time file and the output is masked', async ($, on) => {
  const vault: Vault = new Map([['GH_TOKEN', SECRET]])
  const h = harness(on, vault)
  let seen = ''
  on('tool.call', ($, e: { tool: string; command?: string }) => {
    seen = e.command ?? ''
    return { result: { stdout: 'Authorization: Bearer ' + SECRET, stderr: '', interrupted: false } }
  })
  on('session.start', () => ({ cwd: '/work' }))
  await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })

  const out = (await $.tool.call({ tool: 'Bash', command: 'curl -H "Authorization: Bearer {{ck:GH_TOKEN}}" https://httpbin.org/headers' })) as {
    result: { stdout: string }
  }
  // Bash got a command with a file path and a variable, not the value.
  expect(seen).toContain('ck-take')
  expect(seen).toContain('${CK_GH_TOKEN}')
  expect(seen).not.toContain(SECRET)
  // The value went to a private file through stdin, and the file was removed.
  expect([...h.writes.values()]).toEqual([SECRET])
  const file = [...h.writes.keys()][0]!
  expect(file.startsWith('/run/user/1000/claudekeys-')).toBe(true)
  expect(h.ran.some((argv) => argv[0] === 'rm' && argv.includes(file))).toBe(true)
  // Claude reads the mask.
  expect(out.result.stdout).toBe('Authorization: Bearer [ck:GH_TOKEN]')
})

test('an unknown placeholder is refused with the names that exist', async ($, on) => {
  harness(on, new Map([['GH_TOKEN', SECRET]]))
  on('tool.call', () => ({ result: 'should not run' }))
  on('session.start', () => ({ cwd: '/work' }))
  await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
  const out = (await $.tool.call({ tool: 'Bash', command: 'curl -u "{{ck:MISSING}}" x' })) as { deny: string }
  expect(out.deny).toContain('No ClaudeKeys secret named MISSING')
  expect(out.deny).toContain('{{ck:GH_TOKEN}}')
})

test('other tools are masked too, and a pasted secret becomes its placeholder', async ($, on) => {
  harness(on, new Map([['GH_TOKEN', SECRET]]))
  on('tool.call', () => ({ result: { file: { content: 'token: ' + SECRET } } }))
  on('prompt.submit', ($, e) => ({ text: e.text, context: e.context }) as never)
  on('session.start', () => ({ cwd: '/work' }))
  await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
  const read = (await $.tool.call({ tool: 'Read', file_path: '/work/.env' })) as { result: { file: { content: string } } }
  expect(read.result.file.content).toBe('token: [ck:GH_TOKEN]')
  const sent = (await $.prompt.submit({ text: 'my token is ' + SECRET } as never)) as unknown as { text: string; context: string[] }
  expect(sent.text).toBe('my token is {{ck:GH_TOKEN}}')
  expect(sent.context.join(' ')).toContain('{{ck:GH_TOKEN}} (23 chars)')
})

test('the list tool gets this session id, whatever Claude passed', async ($, on) => {
  harness(on, new Map())
  let args: Record<string, unknown> = {}
  on('tool.call', ($, e: Record<string, unknown>) => {
    args = e
    return { result: 'ok' }
  })
  on('session.start', () => ({ cwd: '/work' }))
  await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
  await $.tool.call({ tool: 'mcp__plugin_claudekeys_claudekeys__list_secrets', session_id: 'someone-else' })
  expect(args.session_id).toBe('sess-1234abcd')
})

const PANE = {
  plugin: 'claudekeys',
  component: 'Pane',
  requestId: 'claudekeys',
  viewport: { columns: 100, rows: 30 },
  props: { title: 'ClaudeKeys', isFocused: true, bodyColumns: 70, placement: 'inline', scroll: { offset: 0, bodyRows: 12 }, view: {} },
} as const

test('the pane adds a secret and lists it by length only', async ($, on) => {
  const vault: Vault = new Map()
  harness(on, vault)
  on('session.start', () => ({ cwd: '/work' }))
  await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
  const ui = await $.ui.mount({ ...PANE, surface: 'terminal' })
  await ui.input({ key: 'ck-name', text: 'demo token' })
  await ui.input({ key: 'ck-value', text: 'abcdefghij0123456789' })
  expect(vault.get('DEMO_TOKEN')).toBe('abcdefghij0123456789')
  expect(await ui.find({ type: 'Text', text: '20 chars' })).toBeDefined()
  expect(await ui.find({ type: 'Text', text: /abcdefghij/ })).toBeUndefined()
  await ui.unmount()
})

test('the pill sits after the footer labels and counts the secrets, on both surfaces', async ($, on) => {
  harness(on, new Map([['A_TOKEN', 'aaaaaaaaaa'], ['B_TOKEN', 'bbbbbbbbbb']]))
  on('ui.render', () => ({ type: 'Text', props: {}, children: ['auto mode'] }))
  on('session.start', () => ({ cwd: '/work' }))
  await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
  for (const surface of ['terminal', 'desktop'] as const) {
    const footer = await $.ui.mount({
      plugin: 'claudekeys',
      component: 'SessionMode',
      requestId: 'modes',
      surface,
      viewport: { columns: 100, rows: 30 },
      props: { modes: ['auto mode'] },
    })
    expect((await footer.find({ key: 'ck-pill' }))?.props.label).toBe('🔑 2')
    // Claude Code's own labels are still drawn, ahead of the pill.
    expect(await footer.find({ type: 'Text', text: 'auto mode' })).toBeDefined()
    await footer.unmount()
  }
})

// --- The /keys command line ------------------------------------------------------

// Runs /keys as a plugin would; the engine stamps origin and presentation.
function keys($: { command: { run: (input: never) => Promise<unknown> } }, args: string): Promise<{ text?: string }> {
  return $.command.run({ command: 'keys', args } as never) as Promise<{ text?: string }>
}

test('the command line parses sources, inline values and the rest', async () => {
  expect(parseKeysArgs('')).toEqual({ op: 'open' })
  expect(parseKeysArgs(' list ')).toEqual({ op: 'list' })
  expect(parseKeysArgs('rm gh_token')).toEqual({ op: 'rm', name: 'GH_TOKEN' })
  expect(parseKeysArgs('add gh_token')).toEqual({ op: 'add', name: 'GH_TOKEN' })
  expect(parseKeysArgs('add GH_TOKEN --env GITHUB_TOKEN')).toEqual({ op: 'add', name: 'GH_TOKEN', source: { kind: 'env', ref: 'GITHUB_TOKEN' } })
  expect(parseKeysArgs('add NPM --file ~/.npm token')).toEqual({ op: 'add', name: 'NPM', source: { kind: 'file', ref: '~/.npm token' } })
  expect(parseKeysArgs('add GH --cmd "gh auth token"')).toEqual({ op: 'add', name: 'GH', source: { kind: 'cmd', ref: 'gh auth token' } })
  expect(parseKeysArgs('add GH ' + SECRET)).toEqual({ op: 'add', name: 'GH', value: SECRET })
  expect(parseKeysArgs('add 1BAD x').op).toBe('error')
  expect(parseKeysArgs('frobnicate').op).toBe('error')
})

test('an inline value is masked in the echo and as typed, nothing else is touched', async () => {
  const echo = '<command-name>/keys</command-name>\n<command-message>keys</command-message>\n<command-args>add GH_TOKEN ' + SECRET + '</command-args>'
  expect(maskKeysCommandText(echo)).toBe('<command-name>/keys</command-name>\n<command-message>keys</command-message>\n<command-args>add GH_TOKEN [ck:GH_TOKEN]</command-args>')
  expect(maskKeysCommandText('/keys add gh_token "' + SECRET + '"')).toBe('/keys add gh_token [ck:GH_TOKEN]')
  expect(maskKeysCommandText('/keys add GH --env X')).toBe('/keys add GH --env X')
  expect(maskKeysCommandText('/other add GH ' + SECRET)).toBe('/other add GH ' + SECRET)
  expect(isKeysSkill({ tool: 'Skill', skill: 'keys', args: 'add X y' })).toBe(true)
  expect(isKeysSkill({ tool: 'Skill', skill: 'claudekeys:keys' })).toBe(true)
  expect(isKeysSkill({ tool: 'Skill', skill: 'monkeys' })).toBe(false)
})

test('/keys add reads the value on this machine, from the environment or a command', async ($, on) => {
  const vault: Vault = new Map()
  harness(on, vault)
  on('session.start', () => ({ cwd: '/work' }))
  await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
  const env = await keys($, 'add HOST --env HOST_TOKEN')
  expect(vault.get('HOST')).toBe('from-the-environment-123')
  expect(env.text).toContain('HOST saved (24 chars)')
  expect(env.text).not.toContain('from-the-environment')
  await keys($, 'add GH --cmd "gh auth token"')
  expect(vault.get('GH')).toBe('gho_FromTheCommand9876')
  const missing = await keys($, 'add NOPE --env NOT_SET')
  expect(missing.text).toContain('not set')
  expect(vault.has('NOPE')).toBe(false)
  const list = await keys($, 'list')
  expect(list.text).toContain('ck:GH}}  22 chars')
  const again = await keys($, 'add GH x1234567')
  expect(again.text).toContain('already set')
  await keys($, 'rm gh')
  expect(vault.has('GH')).toBe(false)
})

test('/keys add NAME VALUE stores the value, and its recorded echo shows only the mask', async ($, on) => {
  const vault: Vault = new Map()
  const h = harness(on, vault)
  on('session.start', () => ({ cwd: '/work' }))
  await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
  const out = await keys($, 'add GH_TOKEN ' + SECRET)
  expect(vault.get('GH_TOKEN')).toBe(SECRET)
  expect(out.text).not.toContain(SECRET)
  expect(out.text).toContain('--env, --file or --cmd')
  // The run the engine records holds the mask, not the value.
  expect(h.recorded).toEqual(['add GH_TOKEN [ck:GH_TOKEN]'])
  // The echo row, as session.append hands it over, keeps only the mask.
  const row = [{ type: 'text', text: '<command-name>/keys</command-name>\n<command-args>add GH_TOKEN ' + SECRET + '</command-args>' }, { type: 'image' }]
  const masked = JSON.stringify(maskEcho(row))
  expect(masked).not.toContain(SECRET)
  expect(masked).toContain('add GH_TOKEN [ck:GH_TOKEN]')
  const other = [{ type: 'text', text: 'hello' }]
  expect(maskEcho(other)).toBe(other)
})

test('Claude cannot run /keys through the Skill tool', async ($, on) => {
  harness(on, new Map())
  on('tool.call', () => ({ result: 'ran' }))
  on('session.start', () => ({ cwd: '/work' }))
  await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
  const out = (await $.tool.call({ tool: 'Skill', skill: 'keys', args: 'add X --file ~/.ssh/id_ed25519' } as never)) as { deny?: string }
  expect(out.deny).toContain('Only the user manages')
})
