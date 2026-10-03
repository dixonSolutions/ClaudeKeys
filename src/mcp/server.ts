#!/usr/bin/env node
// ClaudeKeys MCP server: stdio, newline-delimited JSON-RPC 2.0, no
// dependencies.
//
// Read-only by design. Its one tool, list_secrets, returns the names, lengths
// and placeholders of the current session's secrets. It never decrypts and
// never returns a value. The ClaudeKeys mod fills in `session_id` on every
// call, so Claude cannot list another session's secrets by passing an id.

import { createInterface } from 'node:readline'
import { filterMatches, placeholderFor, SESSION_RE } from '../shared/names.ts'
import { listSecrets } from '../vault/store.ts'

const SERVER = { name: 'claudekeys', version: '0.1.0' }
const PROTOCOLS = ['2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05']

type JsonRpcRequest = { jsonrpc?: string; id?: string | number | null; method?: string; params?: Record<string, unknown> }
type ToolResult = { content: { type: 'text'; text: string }[]; structuredContent?: unknown; isError?: boolean }

export const LIST_TOOL = {
  name: 'list_secrets',
  title: 'List ClaudeKeys secrets',
  description:
    'List the secrets the user stored for this session with ClaudeKeys: name, length and placeholder. Values are never returned. ' +
    'To use a secret, write its placeholder, such as {{ck:GH_TOKEN}}, inside double quotes in a Bash command where the value goes; ' +
    'ClaudeKeys fills it in when the command runs and masks it in all output as [ck:NAME]. ' +
    'Do not try to print, echo, encode or save a value. If a secret you need is missing, ask the user to add it with /keys.',
  inputSchema: {
    type: 'object',
    properties: {
      filter: { type: 'string', description: 'Optional. A substring of the name (case-insensitive), or a glob such as GH_* or *TOKEN.' },
      session_id: { type: 'string', description: 'Filled in by ClaudeKeys. Leave it out.' },
    },
    additionalProperties: false,
  },
  outputSchema: {
    type: 'object',
    properties: {
      total: { type: 'number' },
      secrets: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string' },
            placeholder: { type: 'string' },
            length: { type: 'number' },
            added_at: { type: ['string', 'null'] },
          },
          required: ['name', 'placeholder', 'length'],
        },
      },
    },
    required: ['total', 'secrets'],
  },
  annotations: { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false },
}

function toolError(text: string): ToolResult {
  return { content: [{ type: 'text', text }], isError: true }
}

export function callListSecrets(args: Record<string, unknown>): ToolResult {
  const sessionId = String(args.session_id ?? '')
  if (!sessionId) {
    return toolError('ClaudeKeys is not active in this session: its mod did not fill in the session. Ask the user to check that the claudekeys plugin is enabled.')
  }
  if (!SESSION_RE.test(sessionId)) return toolError('Invalid session id.')
  let all
  try {
    all = listSecrets(sessionId)
  } catch (err) {
    return toolError('Could not read this session\'s secrets: ' + (err instanceof Error ? err.message : String(err)))
  }
  const secrets = all
    .filter((s) => filterMatches(s.name, args.filter))
    .map((s) => ({ name: s.name, placeholder: placeholderFor(s.name), length: s.length, added_at: s.addedAt ? new Date(s.addedAt).toISOString() : null }))
  const summary =
    all.length === 0
      ? 'No secrets are stored for this session. The user can add them with /keys.'
      : secrets.length + ' of ' + all.length + ' secret(s) match. Put a placeholder inside double quotes in a Bash command; the value is filled in at run time.'
  return {
    content: [{ type: 'text', text: summary + '\n' + JSON.stringify(secrets, null, 2) }],
    structuredContent: { total: all.length, secrets },
  }
}

export function handle(msg: JsonRpcRequest): object | null {
  const { id, method, params } = msg
  const isNotification = id === undefined || id === null
  const reply = (result: unknown) => ({ jsonrpc: '2.0', id, result })
  const fail = (code: number, message: string) => ({ jsonrpc: '2.0', id: id ?? null, error: { code, message } })
  switch (method) {
    case 'initialize': {
      const asked = String(params?.protocolVersion ?? '')
      return reply({
        protocolVersion: PROTOCOLS.includes(asked) ? asked : PROTOCOLS[0],
        capabilities: { tools: { listChanged: false } },
        serverInfo: SERVER,
        instructions: 'ClaudeKeys lists session secrets by name only. Use {{ck:NAME}} in Bash commands; values are injected at run time and never shown.',
      })
    }
    case 'ping':
      return reply({})
    case 'tools/list':
      return reply({ tools: [LIST_TOOL] })
    case 'tools/call': {
      if (params?.name !== LIST_TOOL.name) return fail(-32602, 'Unknown tool: ' + String(params?.name))
      const args = (params.arguments ?? {}) as Record<string, unknown>
      return reply(callListSecrets(args))
    }
    default:
      return isNotification ? null : fail(-32601, 'Method not found: ' + String(method))
  }
}

function main(): void {
  const rl = createInterface({ input: process.stdin, crlfDelay: Infinity })
  rl.on('line', (line) => {
    if (!line.trim()) return
    let out: object | null
    try {
      out = handle(JSON.parse(line) as JsonRpcRequest)
    } catch {
      out = { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }
    }
    if (out) process.stdout.write(JSON.stringify(out) + '\n')
  })
  rl.on('close', () => process.exit(0))
}

if (import.meta.filename === process.argv[1]) main()
