// Encryption at rest, with node:crypto.
//
// One 256-bit master key per machine (the ClaudeKeys private key) lives in the
// GNOME keyring, or in a 0600 file when libsecret-tools is missing (keys.ts).
// Each session gets its own AES-256-GCM key, derived with HKDF-SHA256 from the
// master key, a random 128-bit salt kept with the session, and the session id
// as HKDF's `info`. The session id is not a secret and not a public key: it is
// a label that separates one session's key from every other's, so a record
// copied into another session's file cannot be opened there.
//
// Each secret is sealed with a fresh 96-bit IV, and authenticated against
// `claudekeys/v1|<session id>|<name>`, so a ciphertext moved to another name
// or session fails to decrypt instead of handing over the wrong value.

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto'

const VERSION = 'claudekeys/v1'
const TAG_BYTES = 16

/** A sealed value as stored: base64 IV, and base64 ciphertext with its tag. */
export type Sealed = { iv: string; ct: string }

export function newMasterKey(): string {
  return randomBytes(32).toString('base64')
}

export function newSalt(): string {
  return randomBytes(16).toString('base64')
}

export function deriveSessionKey(masterB64: string, saltB64: string, sessionId: string): Buffer {
  const master = Buffer.from(masterB64, 'base64')
  if (master.length !== 32) throw new Error('the ClaudeKeys master key is not 32 bytes')
  const info = Buffer.from(VERSION + '/session/' + sessionId, 'utf8')
  return Buffer.from(hkdfSync('sha256', master, Buffer.from(saltB64, 'base64'), info, 32))
}

function aad(sessionId: string, name: string): Buffer {
  return Buffer.from(VERSION + '|' + sessionId + '|' + name, 'utf8')
}

export function seal(key: Buffer, sessionId: string, name: string, value: string): Sealed {
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES })
  cipher.setAAD(aad(sessionId, name))
  const ct = Buffer.concat([cipher.update(value, 'utf8'), cipher.final(), cipher.getAuthTag()])
  return { iv: iv.toString('base64'), ct: ct.toString('base64') }
}

export function unseal(key: Buffer, sessionId: string, name: string, sealed: Sealed): string {
  const data = Buffer.from(sealed.ct, 'base64')
  if (data.length < TAG_BYTES) throw new Error('sealed value is truncated')
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(sealed.iv, 'base64'), { authTagLength: TAG_BYTES })
  decipher.setAAD(aad(sessionId, name))
  decipher.setAuthTag(data.subarray(data.length - TAG_BYTES))
  return Buffer.concat([decipher.update(data.subarray(0, data.length - TAG_BYTES)), decipher.final()]).toString('utf8')
}
