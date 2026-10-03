// Directories and private file writes.

import { chmodSync, mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

export function stateDir(): string {
  return join(process.env.XDG_STATE_HOME || join(homedir(), '.local', 'state'), 'claudekeys')
}

export function sessionsDir(): string {
  return join(stateDir(), 'sessions')
}

export function configDir(): string {
  return join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'claudekeys')
}

/** Write a file only this user can read, atomically (temp file, then rename). */
export function writePrivate(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
  const tmp = path + '.' + process.pid + '.tmp'
  writeFileSync(tmp, text, { mode: 0o600 })
  chmodSync(tmp, 0o600)
  renameSync(tmp, path)
}

export function removeFile(path: string): void {
  rmSync(path, { force: true })
}
