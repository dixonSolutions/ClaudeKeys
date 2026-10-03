// One encrypted file per session: ~/.local/state/claudekeys/sessions/<id>.json,
// mode 0600. Names, lengths and times are in the clear, so the MCP server can
// list them without a key; values are sealed (crypto.ts).
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { NAME_RE, SESSION_RE } from '../shared/names.js';
import { deriveSessionKey, newSalt, seal, unseal } from './crypto.js';
import { getMasterKey } from './keys.js';
import { removeFile, sessionsDir, writePrivate } from './paths.js';
export const MAX_VALUE_LENGTH = 65536;
export class VaultError extends Error {
}
function checkSession(sessionId) {
    if (!SESSION_RE.test(sessionId))
        throw new VaultError('invalid session id');
}
export function sessionFile(sessionId) {
    checkSession(sessionId);
    return join(sessionsDir(), sessionId + '.json');
}
export function readSession(sessionId) {
    const file = sessionFile(sessionId);
    if (!existsSync(file))
        return null;
    const rec = JSON.parse(readFileSync(file, 'utf8'));
    if (rec.v !== 1 || rec.sessionId !== sessionId)
        throw new VaultError('session file does not belong to this session');
    return rec;
}
function writeSession(rec) {
    writePrivate(sessionFile(rec.sessionId), JSON.stringify(rec, null, 2) + '\n');
}
function infoOf(rec) {
    if (!rec)
        return [];
    return Object.entries(rec.secrets)
        .map(([name, s]) => ({ name, length: s.length, addedAt: s.addedAt }))
        .sort((a, b) => a.addedAt - b.addedAt || a.name.localeCompare(b.name));
}
/** Names, lengths and times. Needs no key and never decrypts. */
export function listSecrets(sessionId) {
    return infoOf(readSession(sessionId));
}
/** Seal and store a new secret. Secrets are read-only: an existing name is refused. */
export function addSecret(sessionId, name, value, now = Date.now()) {
    if (!NAME_RE.test(name))
        throw new VaultError('names start with a letter and use A-Z, 0-9 and _ (up to 64)');
    if (typeof value !== 'string' || value.length === 0)
        throw new VaultError('the value is empty');
    if (value.length > MAX_VALUE_LENGTH)
        throw new VaultError('values are limited to 64 KiB');
    const rec = readSession(sessionId) ?? {
        v: 1,
        sessionId,
        salt: newSalt(),
        createdAt: now,
        usedAt: now,
        secrets: {},
    };
    if (rec.secrets[name])
        throw new VaultError(name + ' is already set; secrets are read-only, so delete it first to replace it');
    const key = deriveSessionKey(getMasterKey().key, rec.salt, sessionId);
    rec.secrets[name] = { ...seal(key, sessionId, name, value), length: value.length, addedAt: now };
    rec.usedAt = now;
    writeSession(rec);
    return infoOf(rec);
}
export function deleteSecret(sessionId, name) {
    const rec = readSession(sessionId);
    if (!rec || !rec.secrets[name])
        return infoOf(rec);
    delete rec.secrets[name];
    if (Object.keys(rec.secrets).length === 0)
        removeFile(sessionFile(sessionId));
    else
        writeSession(rec);
    return infoOf(Object.keys(rec.secrets).length === 0 ? null : rec);
}
/**
 * Every value of a session, for the mod to inject and mask. The only call
 * that decrypts. Marks the session as used.
 */
export function revealAll(sessionId, now = Date.now()) {
    const rec = readSession(sessionId);
    if (!rec || Object.keys(rec.secrets).length === 0)
        return {};
    const key = deriveSessionKey(getMasterKey().key, rec.salt, sessionId);
    const out = {};
    for (const [name, s] of Object.entries(rec.secrets))
        out[name] = unseal(key, sessionId, name, s);
    rec.usedAt = now;
    writeSession(rec);
    return out;
}
export function forgetSession(sessionId) {
    removeFile(sessionFile(sessionId));
}
/** Delete sessions nobody has used for `retainHours`. Returns their ids. */
export function purgeExpired(retainHours, now = Date.now()) {
    const dir = sessionsDir();
    if (!existsSync(dir))
        return [];
    const cutoff = now - retainHours * 3600 * 1000;
    const removed = [];
    for (const entry of readdirSync(dir)) {
        if (!entry.endsWith('.json'))
            continue;
        const id = entry.slice(0, -'.json'.length);
        if (!SESSION_RE.test(id))
            continue;
        const path = join(dir, entry);
        let usedAt = 0;
        try {
            usedAt = JSON.parse(readFileSync(path, 'utf8')).usedAt ?? 0;
        }
        catch {
            usedAt = statSync(path).mtimeMs;
        }
        if (usedAt < cutoff) {
            removeFile(path);
            removed.push(id);
        }
    }
    return removed;
}
