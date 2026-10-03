// Names, placeholders and filters, shared by the mod, the vault and the MCP
// server. Pure: no Node APIs and no mods API, so every side can import it.
/** A secret's name: an environment-variable style identifier. */
export const NAME_RE = /^[A-Z][A-Z0-9_]{0,63}$/;
/** A session id as Claude Code issues it; also safe as a file name. */
export const SESSION_RE = /^[A-Za-z0-9_-]{1,128}$/;
const PLACEHOLDER_RE = /\{\{\s*ck:([A-Za-z0-9_]+)\s*\}\}/g;
/** What Claude writes where a value goes: `{{ck:GH_TOKEN}}`. */
export function placeholderFor(name) {
    return '{{ck:' + name + '}}';
}
/** What the output shows where a value was: `[ck:GH_TOKEN]`. */
export function maskFor(name) {
    return '[ck:' + name + ']';
}
/** The shell variable a value is handed over in: `CK_GH_TOKEN`. */
export function envNameFor(name) {
    return 'CK_' + name;
}
/** Names used in a string, in order of first use, without duplicates. */
export function findPlaceholders(text) {
    if (typeof text !== 'string')
        return [];
    const names = [];
    for (const m of text.matchAll(PLACEHOLDER_RE)) {
        const name = m[1];
        if (name !== undefined && !names.includes(name))
            names.push(name);
    }
    return names;
}
/** Replace each placeholder with what `replace` returns for its name. */
export function replacePlaceholders(text, replace) {
    return text.replace(PLACEHOLDER_RE, (_, name) => replace(name));
}
/** Normalize what the user typed as a name: `gh token` becomes `GH_TOKEN`. */
export function normalizeName(raw) {
    return String(raw ?? '').trim().toUpperCase().replace(/[^A-Z0-9_]+/g, '_');
}
/**
 * Whether a name matches a list filter: a case-insensitive substring, or a
 * glob such as `GH_*` or `*TOKEN` when it holds `*` or `?`.
 */
export function filterMatches(name, filter) {
    const f = String(filter ?? '').trim();
    if (!f)
        return true;
    if (f.includes('*') || f.includes('?')) {
        const pattern = f.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.');
        return new RegExp('^' + pattern + '$', 'i').test(name);
    }
    return name.toLowerCase().includes(f.toLowerCase());
}
