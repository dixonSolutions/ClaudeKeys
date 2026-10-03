// Command rewriting, guarding and output masking for the mod. Pure: no mods
// API, so tests can call every function directly.
//
// Claude writes `{{ck:NAME}}` in a Bash command. Before the command runs, the
// mod writes each value to a one-time 0600 file in $XDG_RUNTIME_DIR (tmpfs,
// never on disk) and rewrites the command so the shell reads the file into
// $CK_NAME, deletes it, and expands `${CK_NAME}` where the placeholder was.
// The value never appears in the command text, the transcript, or any argv;
// it lives only in that one shell's environment. Whatever comes back is
// scanned for the value, and its common encodings, before Claude reads it.
import { envNameFor, findPlaceholders, maskFor, placeholderFor, replacePlaceholders } from '../shared/names.js';
/** Values shorter than this are not masked at all: they would match noise. */
const MIN_MASK_LENGTH = 4;
/** Encodings are masked only for values at least this long. */
const MIN_VARIANT_LENGTH = 8;
/** The placeholder-free command a rewritten one stands for, for permission rules. */
export function effectiveCommand(command) {
    return replacePlaceholders(command, (name) => '${' + envNameFor(name) + '}');
}
function shellQuote(s) {
    return "'" + s.replace(/'/g, "'\\''") + "'";
}
/**
 * The command Bash actually runs. `files` maps each name to its one-time
 * file, and `take` is the absolute path of bin/ck-take, which prints a file
 * and deletes it. A missing file stops the command with exit status 97.
 */
export function rewriteCommand(command, files, take) {
    const lines = Object.entries(files).map(([name, file]) => {
        const v = envNameFor(name);
        return v + '="$(sh ' + shellQuote(take) + ' ' + shellQuote(file) + ')" || exit 97; export ' + v;
    });
    return lines.join('\n') + '\n' + effectiveCommand(command);
}
export function isRewritten(command) {
    return typeof command === 'string' && /^CK_[A-Z0-9_]+="\$\(sh '[^']*ck-take' /.test(command);
}
/** Paths the model must not touch: the vault's files, the key, the one-time files. */
export function storagePatterns(dirs) {
    const p = [dirs.state + '/claudekeys/', dirs.config + '/claudekeys/', '.local/state/claudekeys', '.config/claudekeys'];
    if (dirs.runtime)
        p.push(dirs.runtime + '/claudekeys-');
    return p;
}
// Running the vault, reading a one-time file, asking the keyring, or naming a
// CK_ variable directly. Reading the plugin's source stays allowed.
const SNOOP_RE = /claudekeys-[0-9a-f]{8,}|dist\/vault\/cli|\bsecret-tool\b[^\n]*\bclaudekeys\b|\$\{?CK_[A-Z0-9_]+/;
// Commands that would print or transform a value once it sits in a variable.
// A heuristic: it keeps an honest model from echoing a secret by accident; it
// does not stop a model set on leaking one (see README, "Limits").
const PRINT_RE = /(^|[\s;&|(`])(echo|printf|printenv|declare|typeset|export\s+-p|compgen|base64|base32|xxd|od|hexdump|rev|tee|strings)(\s|$|[;&|)`])|(^|[\s;&|(`])(env|set)\s*($|[;&|)`>])|\/proc\/|\/dev\/tcp\//;
function collectStrings(v, out) {
    if (typeof v === 'string')
        out.push(v);
    else if (Array.isArray(v))
        for (const x of v)
            collectStrings(x, out);
    else if (v && typeof v === 'object')
        for (const x of Object.values(v))
            collectStrings(x, out);
}
/** The tool's own arguments, without the envelope fields. */
function argsOf(e) {
    const { tool: _t, tool_use_id: _id, agentId: _a, ...args } = e;
    return args;
}
/** Why a tool call has to be refused before anything else happens, or null. */
export function guardReason(e, patterns) {
    const strings = [];
    collectStrings(argsOf(e), strings);
    if (strings.some((s) => patterns.some((p) => s.includes(p)))) {
        return 'ClaudeKeys storage is off limits. Secrets are usable only through {{ck:NAME}} placeholders in Bash commands; list them with the list_secrets tool.';
    }
    if (e.tool === 'Bash') {
        const cmd = String(e.command ?? '');
        if (SNOOP_RE.test(cmd)) {
            return 'ClaudeKeys internals and CK_ variables are off limits. Write {{ck:NAME}} where the value goes and ClaudeKeys fills it in.';
        }
        if (findPlaceholders(cmd).length > 0 && PRINT_RE.test(cmd)) {
            return 'This command could print a secret: it uses echo, printf, env, base64, tee or similar alongside a {{ck:...}} placeholder. Pass the placeholder straight to the program that needs it, as a header, flag or environment variable, and nothing else.';
        }
        return null;
    }
    if (strings.some((s) => findPlaceholders(s).length > 0)) {
        return 'ClaudeKeys placeholders work only inside Bash commands, so a value is never written to a file or sent to a tool as text. Use the placeholder in a Bash command instead.';
    }
    return null;
}
// --- Masking ------------------------------------------------------------------
function utf8Base64(s) {
    let bin = '';
    for (const b of new TextEncoder().encode(s))
        bin += String.fromCharCode(b);
    return btoa(bin);
}
function utf8Hex(s) {
    let out = '';
    for (const b of new TextEncoder().encode(s))
        out += b.toString(16).padStart(2, '0');
    return out;
}
/** The value, and the encodings a command is most likely to turn it into. */
export function variantsOf(value) {
    if (value.length < MIN_MASK_LENGTH)
        return [];
    if (value.length < MIN_VARIANT_LENGTH)
        return [value];
    const b64 = utf8Base64(value);
    const set = new Set([
        value,
        b64,
        b64.replace(/=+$/, ''),
        b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
        utf8Hex(value),
        utf8Hex(value).toUpperCase(),
        encodeURIComponent(value),
        JSON.stringify(value).slice(1, -1),
        [...value].reverse().join(''),
    ]);
    return [...set].filter((x) => x.length >= MIN_MASK_LENGTH);
}
export function makeRedactor(secrets) {
    // Longest first, so a value that contains another one is masked whole.
    const pairs = [];
    for (const [name, value] of Object.entries(secrets))
        for (const v of variantsOf(value))
            pairs.push([v, name]);
    pairs.sort((a, b) => b[0].length - a[0].length);
    const replaceAll = (s, to) => {
        let out = s;
        for (const [needle, name] of pairs)
            if (out.includes(needle))
                out = out.split(needle).join(to(name));
        return out;
    };
    const text = (s) => replaceAll(s, maskFor);
    const deep = (v) => {
        if (typeof v === 'string')
            return text(v);
        if (Array.isArray(v))
            return v.map(deep);
        if (v && typeof v === 'object') {
            const out = {};
            for (const [k, x] of Object.entries(v))
                out[k] = deep(x);
            return out;
        }
        return v;
    };
    return { isEmpty: pairs.length === 0, text, deep, toPlaceholders: (s) => replaceAll(s, placeholderFor) };
}
/** Whether masking changed anything. */
export function changed(a, b) {
    return JSON.stringify(a) !== JSON.stringify(b);
}
/** Dots as long as the value, up to `max` cells, for the pane. */
export function maskOf(length, max = 20) {
    return length <= max ? '•'.repeat(length) : '•'.repeat(Math.max(1, max - 1)) + '…';
}
