// Node tests for the vault and the MCP server: `npm run test:node`.
// Each test runs against a throwaway XDG_STATE_HOME / XDG_CONFIG_HOME, with
// the master key in a file so the real keyring is never touched.

import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { beforeEach, test } from 'node:test'

// Compiled to .spec-out/spec/, beside .spec-out/src/.
const src = join(import.meta.dirname, '..', 'src')

function sandbox(): Record<string, string> {
  const dir = mkdtempSync(join(tmpdir(), 'claudekeys-spec-'))
  const env = { XDG_STATE_HOME: join(dir, 'state'), XDG_CONFIG_HOME: join(dir, 'config'), CLAUDEKEYS_KEY_SOURCE: 'file' }
  Object.assign(process.env, env)
  return env
}

let env: Record<string, string>
beforeEach(() => {
  env = sandbox()
})

const crypto = await import('../src/vault/crypto.ts')
const store = await import('../src/vault/store.ts')
const mcp = await import('../src/mcp/server.ts')

test('a sealed value opens only with the same session and name', () => {
  const master = crypto.newMasterKey()
  const salt = crypto.newSalt()
  const key = crypto.deriveSessionKey(master, salt, 'session-a')
  const sealed = crypto.seal(key, 'session-a', 'GH_TOKEN', 'ghp_secret_value')
  assert.equal(crypto.unseal(key, 'session-a', 'GH_TOKEN', sealed), 'ghp_secret_value')
  assert.throws(() => crypto.unseal(key, 'session-a', 'OTHER', sealed))
  const otherKey = crypto.deriveSessionKey(master, salt, 'session-b')
  assert.throws(() => crypto.unseal(otherKey, 'session-b', 'GH_TOKEN', sealed))
  assert.throws(() => crypto.unseal(otherKey, 'session-a', 'GH_TOKEN', sealed))
})

test('two seals of one value differ (fresh IV each time)', () => {
  const key = crypto.deriveSessionKey(crypto.newMasterKey(), crypto.newSalt(), 's')
  assert.notEqual(crypto.seal(key, 's', 'A', 'same').ct, crypto.seal(key, 's', 'A', 'same').ct)
})

test('the session file holds no plaintext and is private', () => {
  store.addSecret('s1', 'API_TOKEN', 'super-secret-value-123')
  const file = store.sessionFile('s1')
  const text = readFileSync(file, 'utf8')
  assert.ok(!text.includes('super-secret-value-123'))
  assert.equal(statSync(file).mode & 0o777, 0o600)
  assert.deepEqual(store.listSecrets('s1').map((s) => [s.name, s.length]), [['API_TOKEN', 22]])
  assert.deepEqual(store.revealAll('s1'), { API_TOKEN: 'super-secret-value-123' })
})

test('secrets are read-only: an existing name is refused', () => {
  store.addSecret('s2', 'A', 'first-value')
  assert.throws(() => store.addSecret('s2', 'A', 'second-value'), /read-only/)
  assert.deepEqual(store.revealAll('s2'), { A: 'first-value' })
  store.deleteSecret('s2', 'A')
  store.addSecret('s2', 'A', 'second-value')
  assert.deepEqual(store.revealAll('s2'), { A: 'second-value' })
})

test('bad names, empty values and bad session ids are refused', () => {
  assert.throws(() => store.addSecret('s3', 'lower', 'x'))
  assert.throws(() => store.addSecret('s3', 'OK', ''))
  assert.throws(() => store.addSecret('../escape', 'OK', 'x'))
})

test('sessions are separate', () => {
  store.addSecret('one', 'A', 'value-one')
  assert.deepEqual(store.listSecrets('two'), [])
  assert.deepEqual(store.revealAll('two'), {})
})

test('purge removes sessions unused for longer than the retention', () => {
  store.addSecret('old', 'A', 'v', Date.now() - 48 * 3600 * 1000)
  store.addSecret('new', 'A', 'v')
  assert.deepEqual(store.purgeExpired(24), ['old'])
  assert.deepEqual(store.listSecrets('new').length, 1)
})

test('the CLI speaks JSON over stdin and never echoes a value on add', () => {
  const run = (req: object) => {
    const r = spawnSync('node', [join(src, 'vault/cli.js')], { input: JSON.stringify(req), encoding: 'utf8', env: { ...process.env, ...env } })
    return JSON.parse(r.stdout) as Record<string, unknown>
  }
  const added = run({ op: 'add', sessionId: 'cli', name: 'TOKEN', value: 'cli-secret-999' })
  assert.equal(added.ok, true)
  assert.ok(!JSON.stringify(added).includes('cli-secret-999'))
  assert.deepEqual(run({ op: 'reveal', sessionId: 'cli' }).values, { TOKEN: 'cli-secret-999' })
  assert.equal(run({ op: 'nope' }).ok, false)
})

test('MCP list_secrets lists names and lengths, never values', () => {
  store.addSecret('m1', 'GH_TOKEN', 'ghp_abcdefghijklmnop')
  store.addSecret('m1', 'NPM_TOKEN', 'npm_zyxwvutsrq')
  const out = mcp.handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: 'list_secrets', arguments: { session_id: 'm1', filter: 'GH_*' } } }) as {
    result: { content: { text: string }[]; structuredContent: { total: number; secrets: { name: string; placeholder: string; length: number }[] } }
  }
  assert.equal(out.result.structuredContent.total, 2)
  assert.deepEqual(out.result.structuredContent.secrets.map((s) => [s.name, s.placeholder, s.length]), [['GH_TOKEN', '{{ck:GH_TOKEN}}', 20]])
  assert.ok(!JSON.stringify(out).includes('ghp_abcdefghijklmnop'))
})

test('MCP list_secrets refuses a call the mod did not fill in', () => {
  const out = mcp.handle({ jsonrpc: '2.0', id: 2, method: 'tools/call', params: { name: 'list_secrets', arguments: {} } }) as { result: { isError: boolean } }
  assert.equal(out.result.isError, true)
})

test('the MCP server answers initialize and tools/list over stdio', () => {
  const lines = [
    { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 't', version: '1' } } },
    { jsonrpc: '2.0', method: 'notifications/initialized' },
    { jsonrpc: '2.0', id: 2, method: 'tools/list' },
  ]
  const r = spawnSync('node', [join(src, 'mcp/server.js')], { input: lines.map((l) => JSON.stringify(l)).join('\n') + '\n', encoding: 'utf8' })
  const replies = r.stdout.trim().split('\n').map((l) => JSON.parse(l))
  assert.equal(replies.length, 2)
  assert.equal(replies[0].result.protocolVersion, '2025-06-18')
  assert.deepEqual(replies[1].result.tools.map((t: { name: string }) => t.name), ['list_secrets'])
  assert.equal(replies[1].result.tools[0].annotations.readOnlyHint, true)
})
