// ClaudeKeys mod: session-scoped, encrypted, read-only secrets that Claude
// uses in Bash commands as {{ck:NAME}} without ever reading the values.
//
// How a value travels (README.md, "Privacy model"):
//   1. You type it into a hidden zenity dialog, or the pane's field. It goes
//      straight to this module and on to the vault over stdin, never into the
//      conversation.
//   2. The vault (src/vault, Node) seals it with AES-256-GCM under a
//      per-session key derived from the master key in your keyring.
//   3. When Claude's Bash command holds {{ck:NAME}}, the value is written to a
//      one-time 0600 file on tmpfs; the shell reads it into $CK_NAME and
//      deletes it (inject.ts).
//   4. Tool results, prompts and transcript rows are masked before Claude
//      reads them or they are stored.
import { findPlaceholders, NAME_RE, normalizeName, placeholderFor } from '../shared/names.js';
import { changed, effectiveCommand, guardReason, isRewritten, makeRedactor, maskOf, rewriteCommand, storagePatterns, } from './inject.js';
import { chompValue, expandHome, isKeysSkill, maskEcho, maskKeysArgs, maskKeysCommandText, parseKeysArgs, USAGE } from './command.js';
const PANE = 'claudekeys';
const LIST_TOOL = /^mcp__.*claudekeys.*__list_secrets$/;
// Session state, rebuilt on load and after /clear, /resume and /branch.
let sessionId = '';
let dirs = { state: '', config: '', runtime: '' };
let meta = [];
let values = null;
let announced = '';
// The placeholder-expanded command behind each rewritten one.
const effective = new Map();
// Pane state.
let step = 'list';
let pendingName = '';
let confirmDelete = '';
// Options from userConfig.
let retainHours = 24;
let showBadge = true;
export function register(on, options) {
    if (typeof options.retain_hours === 'number')
        retainHours = options.retain_hours;
    if (options.show_badge === false)
        showBadge = false;
    on('session.start', async ($, e, next) => {
        await init($);
        try {
            await $.command.register({
                name: 'keys',
                description: "ClaudeKeys: this session's secrets. /keys opens the pane; /keys add NAME --env VAR|--file PATH|--cmd CMD, list, rm NAME",
                argumentHint: '[add NAME [--env VAR | --file PATH | --cmd CMD | VALUE] | list | rm NAME | forget]',
                immediate: true,
            });
        }
        catch {
            // Registered already, after a reload.
        }
        return next(e);
    });
    // /clear, /resume and /branch move to another session id.
    on('classic.SessionStart', { source: ['clear', 'resume', 'fork'] }, async ($, e, next) => {
        await init($);
        return next(e);
    });
    on('session.end', async ($, e, next) => {
        values = null;
        return next(e);
    });
    // The command line works on every surface. Over Remote Control (a web or
    // phone client) no pane reaches the person, so text and dialogs stand in.
    on('command.run', { command: 'keys' }, async ($, e, next) => {
        const remote = e.origin?.kind === 'bridge';
        const args = String(e.args ?? '');
        let text;
        try {
            text = await runKeys($, parseKeysArgs(args), remote);
        }
        catch (err) {
            text = 'ClaudeKeys: ' + String(err instanceof Error ? err.message : err);
        }
        // Hand the engine the masked args, so the run it records holds no value.
        const recorded = await next({ ...e, args: maskKeysArgs(args) });
        return text ? { ...recorded, text } : recorded;
    });
    // Guard, inject and mask every tool call, subagents' and MCP tools' included.
    on('tool.call', async ($, e, next) => {
        const reason = guardReason(e, storagePatterns(dirs));
        if (reason)
            return { deny: reason };
        if (isKeysSkill(e))
            return { deny: 'Only the user manages ClaudeKeys secrets. Ask them to run /keys.' };
        if (LIST_TOOL.test(e.tool))
            return next({ ...e, session_id: sessionId });
        if (e.tool === 'Bash' && findPlaceholders(e.command).length > 0) {
            const prep = await prepareInjection($, e.command);
            if ('deny' in prep)
                return { deny: prep.deny };
            effective.set(prep.command, effectiveCommand(e.command));
            let result;
            try {
                result = await next({ ...e, command: prep.command });
            }
            finally {
                effective.delete(prep.command);
                // A background command may not have read its files yet.
                if (e.run_in_background)
                    $.clock.after(120000, () => void removeFiles($, prep.files));
                else
                    await removeFiles($, prep.files);
            }
            return maskResult($, result);
        }
        if (meta.length === 0)
            return next(e);
        return maskResult($, await next(e));
    }).catch(async ($, e, next) => {
        // Fail closed: never hand Claude output that could not be checked.
        const kind = next.error?.kind ?? 'error';
        if (next.called)
            return { deny: 'ClaudeKeys could not check this output for secrets, so it was withheld (' + kind + ').' };
        return { deny: 'ClaudeKeys failed before running this call (' + kind + '): ' + (next.error?.message ?? '') };
    });
    // Decide a rewritten command as the command it stands for, so permission
    // rules such as Bash(gh *) still match and the ck-take prefix trips nothing.
    on('tool.check', { tool: 'Bash' }, async ($, e, next) => {
        const input = (e.input ?? {});
        const cmd = input.command;
        if (!isRewritten(cmd) || typeof cmd !== 'string' || !effective.has(cmd))
            return next(e);
        try {
            return await $.tool.check({ tool: 'Bash', input: { ...input, command: effective.get(cmd) } });
        }
        catch {
            return next(e);
        }
    });
    // A secret pasted into a prompt becomes its placeholder before Claude reads
    // it, and Claude learns which names exist whenever the set changes.
    on('prompt.submit', async ($, e, next) => {
        const typed = maskKeysCommandText(e.text);
        if (meta.length === 0)
            return typed === e.text ? next(e) : next({ ...e, text: typed });
        let text = typed;
        const red = await redactor($);
        const replaced = red.toPlaceholders(text);
        if (replaced !== text) {
            text = replaced;
            void $.ui.toast('ClaudeKeys replaced a pasted secret with its placeholder.');
        }
        const names = meta.map((m) => m.name).join(',');
        const context = [...(e.context ?? [])];
        if (names !== announced) {
            announced = names;
            context.push(announcement());
        }
        return next({ ...e, text, context });
    });
    // Last line of defence: mask anything else headed for the transcript, such
    // as task notifications, hook output and messages from other sessions.
    // A /keys add NAME VALUE echo is masked by its shape, whether it is recorded
    // before or after the value is stored.
    on('session.append', async ($, e, next) => {
        const echo = maskEcho(e.message.content);
        if (meta.length === 0)
            return echo === e.message.content ? next(e) : next({ ...e, message: { ...e.message, content: echo } });
        const red = await redactor($);
        if (red.isEmpty)
            return echo === e.message.content ? next(e) : next({ ...e, message: { ...e.message, content: echo } });
        const content = red.deep(echo);
        if (!changed(content, e.message.content))
            return next(e);
        return next({ ...e, message: { ...e.message, content } });
    });
    // The key pill, inside the prompt box: the footer's mode labels site, which
    // the Desktop app draws in the composer beside submit/stop and the terminal
    // at the right of the footer under the prompt. Drawn after Claude Code's own
    // labels, so it sits rightmost, nearest the submit button.
    on('ui.render', { component: 'SessionMode' }, async ($, e, next) => {
        const theirs = await next(e);
        if (!showBadge)
            return theirs;
        const { Box, Button } = $.ui.resolve(e);
        const n = meta.length;
        const pill = Button({ key: 'ck-pill', label: '🔑 ' + n, dimColor: n === 0, onPress: () => void openPane($) });
        return Box({
            flexDirection: 'row',
            alignItems: 'center',
            columnGap: 1,
            children: theirs ? [theirs, Box({ flexShrink: 0, children: [pill] })] : [Box({ flexShrink: 0, children: [pill] })],
        });
    });
    // The popover: every secret with its length, and a form to add one.
    on('ui.render', { component: 'Pane' }, async ($, e, next) => {
        if (e.requestId !== PANE)
            return next(e);
        const elements = $.ui.resolve(e);
        const { Box, Text, Button } = elements;
        // Not every surface has a text field; without one, only the dialog is offered.
        const Input = 'Input' in elements ? elements.Input : undefined;
        const redraw = () => $.ui.invalidate('ui.render');
        const width = Math.max(30, Number(e.props.bodyColumns ?? 60));
        // Fit each row to the pane: name, dots, length, time, delete.
        const nameWidth = Math.min(Math.max(8, ...meta.map((m) => m.name.length)), Math.floor(width / 2));
        const dotsWidth = Math.max(3, Math.min(20, width - nameWidth - 26));
        const header = Box({
            flexDirection: 'row',
            justifyContent: 'space-between',
            children: [
                Text({ bold: true, children: ['🔑 ClaudeKeys · ' + meta.length + (meta.length === 1 ? ' secret' : ' secrets')] }),
                Text({ dimColor: true, children: [sessionId.slice(0, 8) + '   '] }),
            ],
        });
        const rows = meta.length === 0
            ? [Text({ dimColor: true, children: ['No secrets in this session yet.'] })]
            : meta.map((m) => confirmDelete === m.name
                ? Box({
                    key: 'row-' + m.name,
                    flexDirection: 'row',
                    columnGap: 2,
                    children: [
                        Text({ color: 'red', children: ['Delete ' + m.name + '?'] }),
                        Button({ key: 'del-yes-' + m.name, label: 'Delete', onPress: async () => { confirmDelete = ''; await deleteSecret($, m.name); redraw(); } }),
                        Button({ key: 'del-no-' + m.name, label: 'Keep', onPress: () => { confirmDelete = ''; redraw(); } }),
                    ],
                })
                : Box({
                    key: 'row-' + m.name,
                    flexDirection: 'row',
                    columnGap: 2,
                    children: [
                        Text({ bold: true, wrap: 'truncate', children: [m.name.padEnd(nameWidth)] }),
                        Text({ dimColor: true, children: [maskOf(m.length, dotsWidth)] }),
                        Text({ children: [m.length + (m.length === 1 ? ' char' : ' chars')] }),
                        Text({ dimColor: true, children: [timeOf(m.addedAt)] }),
                        Button({ key: 'del-' + m.name, label: 'x', plain: true, onPress: () => { confirmDelete = m.name; redraw(); } }),
                    ],
                }));
        const form = step === 'value'
            ? [
                Text({ children: ['Value for ' + pendingName + ' (Claude only ever sees its length):'] }),
                Button({ key: 'ck-hidden', label: 'Type it in a hidden dialog', hotkey: 'h', autoFocus: true, onPress: async () => { await addFromDialog($); redraw(); } }),
                Input?.({
                    key: 'ck-value',
                    label: 'Or here',
                    placeholder: 'visible as you type; Enter saves',
                    value: '',
                    submitLabel: 'save',
                    onSubmit: async (value) => { await addSecret($, pendingName, value); redraw(); },
                }),
                Button({ key: 'ck-cancel', label: 'Cancel', plain: true, dimColor: true, onPress: () => { step = 'list'; pendingName = ''; redraw(); } }),
            ]
            : [
                Input?.({
                    key: 'ck-name',
                    label: 'Add',
                    placeholder: 'NAME, e.g. GH_TOKEN',
                    value: '',
                    submitLabel: 'next',
                    autoFocus: true,
                    onSubmit: (value) => { startAdd($, value); redraw(); },
                }),
            ];
        return Box({
            flexDirection: 'column',
            children: [
                header,
                ...rows,
                Text({ dimColor: true, children: ['─'.repeat(Math.min(width, 60))] }),
                ...form.filter((x) => x !== undefined),
                Text({ dimColor: true, wrap: 'wrap', children: ['Claude writes {{ck:NAME}} in Bash commands; values are filled in at run time and masked in all output.'] }),
            ],
        });
    });
}
// --- Vault ------------------------------------------------------------------------
// One request to the Node vault, over stdin so a value never reaches argv.
async function vault($, req) {
    const r = await $.process.run(['node', $.plugin.root + '/dist/vault/cli.js'], { stdin: JSON.stringify(req), timeoutMs: 120000 });
    let reply;
    try {
        reply = JSON.parse(r.stdout);
    }
    catch {
        throw new Error('ClaudeKeys vault failed (exit ' + r.exitCode + '): ' + r.stderr.trim().slice(0, 300));
    }
    if (!reply.ok)
        throw new Error(reply.error ?? 'ClaudeKeys vault failed');
    return reply;
}
async function init($) {
    sessionId = await $.session.id();
    const home = (await $.env.get('HOME')) ?? '';
    dirs = {
        state: (await $.env.get('XDG_STATE_HOME')) || home + '/.local/state',
        config: (await $.env.get('XDG_CONFIG_HOME')) || home + '/.config',
        runtime: (await $.env.get('XDG_RUNTIME_DIR')) ?? '',
    };
    values = null;
    announced = '';
    step = 'list';
    pendingName = '';
    confirmDelete = '';
    try {
        await vault($, { op: 'purge', retainHours });
    }
    catch {
        // Purging is housekeeping; a failure must not stop the session.
    }
    await refresh($);
}
async function refresh($) {
    try {
        meta = (await vault($, { op: 'list', sessionId })).secrets ?? [];
    }
    catch (err) {
        meta = [];
        void $.ui.toast(String(err instanceof Error ? err.message : err));
    }
    values = null;
    $.ui.invalidate('ui.render');
}
// Every value, decrypted once per session and kept in this process only.
async function secretValues($) {
    if (values)
        return values;
    if (meta.length === 0)
        return (values = {});
    values = (await vault($, { op: 'reveal', sessionId })).values ?? {};
    return values;
}
async function redactor($) {
    return makeRedactor(await secretValues($));
}
// --- Adding and deleting -------------------------------------------------------------
function startAdd($, raw) {
    const name = normalizeName(raw);
    if (!NAME_RE.test(name)) {
        void $.ui.toast('Names start with a letter and use A-Z, 0-9 and _ (up to 64).');
        return;
    }
    if (meta.some((m) => m.name === name)) {
        void $.ui.toast(name + ' is already set. Secrets are read-only: delete it first to replace it.');
        return;
    }
    pendingName = name;
    step = 'value';
}
async function addFromDialog($) {
    let r;
    try {
        r = await $.process.run(['zenity', '--password', '--title=ClaudeKeys: ' + pendingName], { timeoutMs: 300000 });
    }
    catch {
        void $.ui.toast('No hidden dialog available (zenity). Type the value in the field instead.');
        return;
    }
    if (r.exitCode !== 0)
        return;
    await addSecret($, pendingName, r.stdout.replace(/\r?\n$/, ''));
}
async function addSecret($, name, value) {
    if (!name || step !== 'value')
        return;
    try {
        void $.ui.toast(await saveSecret($, name, value));
    }
    catch (err) {
        void $.ui.toast(String(err instanceof Error ? err.message : err));
        return;
    }
    step = 'list';
    pendingName = '';
}
// Stores one value and says so; throws with a message the person can act on.
async function saveSecret($, name, value) {
    if (!value)
        throw new Error('Empty value: nothing saved.');
    if (meta.some((m) => m.name === name))
        throw new Error(name + ' is already set. Secrets are read-only: /keys rm ' + name + ' first to replace it.');
    meta = (await vault($, { op: 'add', sessionId, name, value })).secrets ?? meta;
    if (values)
        values[name] = value;
    $.ui.invalidate('ui.render');
    return name + ' saved (' + value.length + ' chars). Claude uses it as ' + placeholderFor(name) + (value.length < 8 ? '. Short values are masked only as typed, not in encoded forms.' : '.');
}
async function deleteSecret($, name) {
    try {
        void $.ui.toast(await removeSecret($, name));
    }
    catch (err) {
        void $.ui.toast(String(err instanceof Error ? err.message : err));
    }
}
async function removeSecret($, name) {
    if (!meta.some((m) => m.name === name))
        throw new Error('No secret named ' + name + '.');
    meta = (await vault($, { op: 'delete', sessionId, name })).secrets ?? [];
    if (values)
        delete values[name];
    $.ui.invalidate('ui.render');
    return name + ' deleted.';
}
// --- The /keys command line ---------------------------------------------------------
async function runKeys($, cmd, remote) {
    switch (cmd.op) {
        case 'error':
            return cmd.message;
        case 'help':
            return 'ClaudeKeys commands:\n' + USAGE;
        case 'list':
            return listText();
        case 'forget':
            await vault($, { op: 'forget', sessionId });
            await refresh($);
            return 'Forgot every secret of this session.';
        case 'rm':
            return await removeSecret($, cmd.name);
        case 'open': {
            // A pane opened from a phone would land on this machine's terminal.
            if (!remote && (await openPane($)))
                return '';
            return listText() + '\n\n' + USAGE;
        }
        case 'add': {
            if (meta.some((m) => m.name === cmd.name))
                return cmd.name + ' is already set. Secrets are read-only: /keys rm ' + cmd.name + ' first to replace it.';
            if (cmd.source)
                return await saveSecret($, cmd.name, await readSource($, cmd.source));
            if (cmd.value !== undefined) {
                const saved = await saveSecret($, cmd.name, cmd.value);
                return saved + '\nThe value as typed stays in this session\'s transcript file; next time use /keys add ' + cmd.name + ' --env, --file or --cmd.';
            }
            if (!remote) {
                step = 'value';
                pendingName = cmd.name;
                confirmDelete = '';
                if (await placePane($))
                    return '';
            }
            return await askForValue($, cmd.name);
        }
    }
}
// The value, read on this machine: it never travels with the command.
async function readSource($, source) {
    if (source.kind === 'env') {
        // $.env.get takes literal names only; the variable is the person's to pick.
        const r = await $.process.run(['printenv', '--', source.ref]);
        const v = chompValue(r.stdout);
        if (r.exitCode !== 0 || !v)
            throw new Error('$' + source.ref + ' is not set in Claude Code\'s environment on this machine.');
        return v;
    }
    if (source.kind === 'file') {
        const home = (await $.env.get('HOME')) ?? '';
        return chompValue(String(await $.fs.read(expandHome(source.ref, home))));
    }
    const r = await $.process.run(['sh', '-c', source.ref], { timeoutMs: 60000 });
    if (r.exitCode !== 0)
        throw new Error('the command exited ' + r.exitCode + '; nothing saved.');
    return chompValue(r.stdout);
}
// Claude Code's own question dialog, which every client draws. The answer is
// typed under "Other", visible as it is typed.
async function askForValue($, name) {
    let answer;
    try {
        answer = await $.ui.ask('Type the value for ' + name + ' under Other (visible while you type; Claude only sees its placeholder).', {
            header: 'ClaudeKeys',
            options: ['Cancel', 'Not now'],
        });
    }
    catch {
        return 'No dialog could be shown. Use /keys add ' + name + ' --env VAR, --file PATH or --cmd COMMAND instead.';
    }
    if (answer === 'Cancel' || answer === 'Not now' || answer === '')
        return 'Nothing saved.';
    return await saveSecret($, name, answer);
}
function listText() {
    if (meta.length === 0)
        return 'No secrets in this session yet. Add one with /keys add NAME --env VAR (or --file, --cmd).';
    return meta.length + (meta.length === 1 ? ' secret:\n' : ' secrets:\n') + meta.map((m) => '  ' + placeholderFor(m.name) + '  ' + m.length + ' chars').join('\n');
}
// --- Injection -------------------------------------------------------------------
async function prepareInjection($, command) {
    const names = findPlaceholders(command);
    const known = new Set(meta.map((m) => m.name));
    const missing = names.filter((n) => !known.has(n));
    if (missing.length > 0) {
        const have = meta.map((m) => placeholderFor(m.name)).join(', ') || 'none';
        return { deny: 'No ClaudeKeys secret named ' + missing.join(', ') + '. Available: ' + have + '. Ask the user to add it with /keys.' };
    }
    if (!dirs.runtime)
        return { deny: 'ClaudeKeys needs $XDG_RUNTIME_DIR (a private tmpfs) to hand values to commands, and it is not set.' };
    const vals = await secretValues($);
    const files = {};
    for (const name of names) {
        const file = dirs.runtime + '/claudekeys-' + nonce();
        await writePrivate($, file, vals[name] ?? '');
        files[name] = file;
    }
    return { command: rewriteCommand(command, files, $.plugin.root + '/bin/ck-take'), files };
}
async function removeFiles($, files) {
    const paths = Object.values(files);
    if (paths.length > 0)
        await $.process.run(['rm', '-f', '--', ...paths]);
}
// Write a file only this user can read. The text goes through stdin.
async function writePrivate($, path, text) {
    const r = await $.process.run(['sh', '-c', 'umask 077 && cat > "$1"', 'sh', path], { stdin: text });
    if (r.exitCode !== 0)
        throw new Error('could not write ' + path + ': ' + r.stderr.trim());
}
// Mask secrets in a tool result. An unchanged result goes back as it came, so
// Claude Code keeps its own rendering of it.
async function maskResult($, result) {
    const r = result;
    if (!r || r.deny !== undefined)
        return result;
    const shape = r.result;
    if (shape?.isImage || shape?.type === 'image')
        return result;
    const red = await redactor($);
    if (red.isEmpty)
        return result;
    const masked = red.deep(r.result);
    const text = typeof r.text === 'string' ? red.text(r.text) : r.text;
    const context = r.context ? r.context.map((c) => red.text(c)) : undefined;
    const dirty = changed(masked, r.result) || text !== r.text || (context !== undefined && changed(context, r.context));
    if (!dirty)
        return result;
    if (r.isError)
        return { deny: text ?? 'The command failed, and its output held a secret, so it was withheld.' };
    return (context ? { result: masked, context } : { result: masked });
}
// --- Helpers --------------------------------------------------------------------
async function openPane($) {
    step = 'list';
    pendingName = '';
    confirmDelete = '';
    return placePane($);
}
// Opens the pane; where no attached surface draws one, closes it again so it
// does not pop up later, and says so.
async function placePane($) {
    const r = await $.ui.open({ id: PANE, title: 'ClaudeKeys', focus: true, closeOnEscape: true, rows: 14 });
    if (r?.isPlaced !== false)
        return true;
    await $.ui.close({ id: PANE });
    return false;
}
function nonce() {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    let out = '';
    for (const b of bytes)
        out += b.toString(16).padStart(2, '0');
    return out;
}
function announcement() {
    const list = meta.map((m) => placeholderFor(m.name) + ' (' + m.length + ' chars)').join(', ');
    return ('ClaudeKeys: the user has stored ' + meta.length + ' secret(s) for this session: ' + list + '. ' +
        'To use one, write its placeholder inside double quotes in a Bash command where the value goes, for example ' +
        'curl -H "Authorization: Bearer {{ck:API_TOKEN}}" https://... or GH_TOKEN="{{ck:GH_TOKEN}}" gh pr list. ' +
        'ClaudeKeys fills it in when the command runs. You cannot see the values and must not try to print or decode them; ' +
        'any output that contains one shows [ck:NAME] instead. The list_secrets tool lists them again.');
}
function timeOf(ms) {
    if (!ms)
        return '';
    const d = new Date(ms);
    return String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');
}
