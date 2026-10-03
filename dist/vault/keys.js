// Where the master key lives. Prefer the GNOME keyring (libsecret, encrypted
// at rest and unlocked with your login); fall back to a 0600 file.
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { newMasterKey } from './crypto.js';
import { configDir, writePrivate } from './paths.js';
const ATTRS = ['service', 'claudekeys', 'key', 'master'];
function hasSecretTool() {
    return spawnSync('sh', ['-c', 'command -v secret-tool'], { stdio: 'ignore' }).status === 0;
}
export function masterKeyFile() {
    return join(configDir(), 'master.key');
}
/** The master key, created on first use. Never written to argv or stdout. */
export function getMasterKey() {
    if (process.env.CLAUDEKEYS_KEY_SOURCE !== 'file' && hasSecretTool()) {
        const found = spawnSync('secret-tool', ['lookup', ...ATTRS], { encoding: 'utf8', timeout: 120000 });
        const existing = found.status === 0 ? found.stdout.trim() : '';
        if (existing)
            return { key: existing, source: 'keyring' };
        const created = newMasterKey();
        const stored = spawnSync('secret-tool', ['store', '--label=ClaudeKeys master key', ...ATTRS], {
            input: created,
            encoding: 'utf8',
            timeout: 120000,
        });
        if (stored.status !== 0)
            throw new Error('secret-tool store failed: ' + String(stored.stderr).trim());
        return { key: created, source: 'keyring' };
    }
    const file = masterKeyFile();
    if (existsSync(file)) {
        const text = readFileSync(file, 'utf8').trim();
        if (text)
            return { key: text, source: 'file' };
    }
    const created = newMasterKey();
    writePrivate(file, created);
    return { key: created, source: 'file' };
}
