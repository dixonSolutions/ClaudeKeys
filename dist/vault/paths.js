// Directories and private file writes.
import { chmodSync, mkdirSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
export function stateDir() {
    return join(process.env.XDG_STATE_HOME || join(homedir(), '.local', 'state'), 'claudekeys');
}
export function sessionsDir() {
    return join(stateDir(), 'sessions');
}
export function configDir() {
    return join(process.env.XDG_CONFIG_HOME || join(homedir(), '.config'), 'claudekeys');
}
/** Write a file only this user can read, atomically (temp file, then rename). */
export function writePrivate(path, text) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    const tmp = path + '.' + process.pid + '.tmp';
    writeFileSync(tmp, text, { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, path);
}
export function removeFile(path) {
    rmSync(path, { force: true });
}
