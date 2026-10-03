#!/usr/bin/env node
// The vault the mod calls. One JSON request on stdin, one JSON reply on
// stdout, so values never appear in argv. The mods runtime has no AES or HKDF
// (only crypto.subtle.digest), which is why encryption lives here in Node.
//
//   {"op":"list","sessionId":"..."}                       -> {"ok":true,"secrets":[...]}
//   {"op":"add","sessionId":"...","name":"X","value":"…"}  -> {"ok":true,"secrets":[...]}
//   {"op":"delete","sessionId":"...","name":"X"}           -> {"ok":true,"secrets":[...]}
//   {"op":"reveal","sessionId":"..."}                     -> {"ok":true,"values":{...}}
//   {"op":"forget","sessionId":"..."}                     -> {"ok":true}
//   {"op":"purge","retainHours":24}                       -> {"ok":true,"removed":[...]}
//
// The ClaudeKeys guard refuses Bash commands that run this file, so only the
// mod reaches it.
import { addSecret, deleteSecret, forgetSession, listSecrets, purgeExpired, revealAll, VaultError } from './store.js';
export function run(req) {
    const sessionId = String(req.sessionId ?? '');
    switch (req.op) {
        case 'list':
            return { ok: true, secrets: listSecrets(sessionId) };
        case 'add':
            return { ok: true, secrets: addSecret(sessionId, String(req.name ?? ''), String(req.value ?? '')) };
        case 'delete':
            return { ok: true, secrets: deleteSecret(sessionId, String(req.name ?? '')) };
        case 'reveal':
            return { ok: true, values: revealAll(sessionId) };
        case 'forget':
            forgetSession(sessionId);
            return { ok: true };
        case 'purge':
            return { ok: true, removed: purgeExpired(Number(req.retainHours ?? 24)) };
        default:
            throw new VaultError('unknown op: ' + String(req.op));
    }
}
async function main() {
    const chunks = [];
    for await (const chunk of process.stdin)
        chunks.push(chunk);
    let reply;
    try {
        reply = run(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
    }
    catch (err) {
        const message = err instanceof VaultError ? err.message : 'vault error: ' + (err instanceof Error ? err.message : String(err));
        reply = { ok: false, error: message };
    }
    process.stdout.write(JSON.stringify(reply) + '\n');
}
if (import.meta.filename === process.argv[1])
    await main();
