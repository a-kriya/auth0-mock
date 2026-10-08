/**
 * A pragmatic subset of the Lucene query syntax accepted by Auth0's user search (`search_engine=v3`):
 *
 *   field:value            field:"exact phrase"        field:(a b "c d")      field:(a AND b)
 *   a AND b   a OR b   NOT a   !a   -a   (grouping)     field:[low TO high]    field:{low TO high}
 *   _exists_:field         field:*                     wildcards `*` and `?`  escapes `\.` `\@` ...
 *
 * The default operator between adjacent clauses is OR (Lucene/Elasticsearch default), so callers join
 * clauses with an explicit AND when they want conjunction, as Auth0 users do.
 *
 * Matching rules mirror Auth0's index mapping closely enough for test suites: fields under
 * `app_metadata`, `user_metadata`, `identities` and `user_id` are keyword fields (exact, case-sensitive);
 * other text fields (`email`, `name`, ...) are analysed (case-insensitive). Array-valued fields match
 * when any element matches.
 */
import { getPath } from './util/merge.ts';

export class QuerySyntaxError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'QuerySyntaxError';
    }
}

type TokenType =
    | 'lparen'
    | 'rparen'
    | 'lbracket'
    | 'rbracket'
    | 'lbrace'
    | 'rbrace'
    | 'colon'
    | 'and'
    | 'or'
    | 'not'
    | 'to'
    | 'word'
    | 'quoted'
    | 'end';

interface Token {
    type: TokenType;
    value: string;
    pos: number;
}

const SINGLE: Record<string, TokenType> = {
    '(': 'lparen',
    ')': 'rparen',
    '[': 'lbracket',
    ']': 'rbracket',
    '{': 'lbrace',
    '}': 'rbrace',
    ':': 'colon',
};

export function tokenize(input: string): Token[] {
    const tokens: Token[] = [];
    let i = 0;
    const isSpace = (c: string) => /\s/.test(c);
    while (i < input.length) {
        const ch = input[i]!;
        if (isSpace(ch)) {
            i++;
            continue;
        }
        const single = SINGLE[ch];
        if (single) {
            tokens.push({ type: single, value: ch, pos: i });
            i++;
            continue;
        }
        if (ch === '"') {
            let j = i + 1;
            let text = '';
            while (j < input.length && input[j] !== '"') {
                if (input[j] === '\\' && j + 1 < input.length) {
                    text += input[j + 1];
                    j += 2;
                } else {
                    text += input[j];
                    j++;
                }
            }
            if (j >= input.length) throw new QuerySyntaxError(`Unterminated quoted string at position ${i}`);
            tokens.push({ type: 'quoted', value: text, pos: i });
            i = j + 1;
            continue;
        }
        const prev = tokens.at(-1);
        const atClauseStart = !prev || ['lparen', 'and', 'or', 'not', 'colon'].includes(prev.type);
        if ((ch === '!' || (ch === '-' && atClauseStart)) && i + 1 < input.length && !isSpace(input[i + 1]!)) {
            tokens.push({ type: 'not', value: ch, pos: i });
            i++;
            continue;
        }
        if (ch === '+' && atClauseStart) {
            i++;
            continue;
        }
        // Word: everything up to whitespace or a structural character; backslash escapes the next character.
        let j = i;
        let raw = '';
        while (j < input.length) {
            const c = input[j]!;
            if (c === '\\' && j + 1 < input.length) {
                raw += c + input[j + 1];
                j += 2;
                continue;
            }
            if (isSpace(c) || c in SINGLE || c === '"') break;
            raw += c;
            j++;
        }
        if (raw.length === 0) throw new QuerySyntaxError(`Unexpected character '${ch}' at position ${i}`);
        const upper = raw.toUpperCase();
        const type: TokenType =
            upper === 'AND' || upper === '&&'
                ? 'and'
                : upper === 'OR' || upper === '||'
                  ? 'or'
                  : upper === 'NOT'
                    ? 'not'
                    : upper === 'TO'
                      ? 'to'
                      : 'word';
        tokens.push({ type, value: raw, pos: i });
        i = j;
    }
    tokens.push({ type: 'end', value: '', pos: input.length });
    return tokens;
}

export type QueryNode =
    | { type: 'and'; children: QueryNode[] }
    | { type: 'or'; children: QueryNode[] }
    | { type: 'not'; child: QueryNode }
    | { type: 'term'; field: string | undefined; text: string; phrase: boolean }
    | { type: 'exists'; field: string }
    | {
          type: 'range';
          field: string | undefined;
          lower: string;
          upper: string;
          includeLower: boolean;
          includeUpper: boolean;
      }
    | { type: 'all' };

class Parser {
    private index = 0;
    private readonly tokens: Token[];

    constructor(tokens: Token[]) {
        this.tokens = tokens;
    }

    private peek(): Token {
        return this.tokens[this.index]!;
    }

    private next(): Token {
        return this.tokens[this.index++]!;
    }

    private expect(type: TokenType): Token {
        const token = this.next();
        if (token.type !== type) {
            throw new QuerySyntaxError(
                `Expected ${type} but found '${token.value || token.type}' at position ${token.pos}`
            );
        }
        return token;
    }

    parse(): QueryNode {
        if (this.peek().type === 'end') return { type: 'all' };
        const node = this.parseOr(undefined);
        if (this.peek().type !== 'end') {
            const t = this.peek();
            throw new QuerySyntaxError(`Unexpected '${t.value || t.type}' at position ${t.pos}`);
        }
        return node;
    }

    private parseOr(field: string | undefined): QueryNode {
        const children = [this.parseAnd(field)];
        for (;;) {
            const t = this.peek();
            if (t.type === 'or') {
                this.next();
                children.push(this.parseAnd(field));
            } else if (t.type === 'end' || t.type === 'rparen' || t.type === 'and') {
                break;
            } else {
                // Implicit operator between adjacent clauses is OR.
                children.push(this.parseAnd(field));
            }
        }
        return children.length === 1 ? children[0]! : { type: 'or', children };
    }

    private parseAnd(field: string | undefined): QueryNode {
        const children = [this.parseUnary(field)];
        while (this.peek().type === 'and') {
            this.next();
            children.push(this.parseUnary(field));
        }
        return children.length === 1 ? children[0]! : { type: 'and', children };
    }

    private parseUnary(field: string | undefined): QueryNode {
        if (this.peek().type === 'not') {
            this.next();
            return { type: 'not', child: this.parseUnary(field) };
        }
        return this.parsePrimary(field);
    }

    private parsePrimary(field: string | undefined): QueryNode {
        const t = this.peek();
        if (t.type === 'lparen') {
            this.next();
            const node = this.parseOr(field);
            this.expect('rparen');
            return node;
        }
        if (t.type === 'lbracket' || t.type === 'lbrace') return this.parseRange(field);
        if (t.type === 'quoted') {
            this.next();
            return { type: 'term', field, text: t.value, phrase: true };
        }
        if (t.type === 'word') {
            this.next();
            if (this.peek().type === 'colon') {
                this.next();
                const name = unescape(t.value);
                if (name === '_exists_') {
                    const target = this.expect('word');
                    return { type: 'exists', field: unescape(target.value) };
                }
                return this.parseValue(name);
            }
            return { type: 'term', field, text: t.value, phrase: false };
        }
        throw new QuerySyntaxError(`Unexpected '${t.value || t.type}' at position ${t.pos}`);
    }

    private parseValue(field: string): QueryNode {
        const t = this.peek();
        if (t.type === 'lparen') {
            this.next();
            const node = this.parseOr(field);
            this.expect('rparen');
            return node;
        }
        if (t.type === 'lbracket' || t.type === 'lbrace') return this.parseRange(field);
        if (t.type === 'quoted') {
            this.next();
            return { type: 'term', field, text: t.value, phrase: true };
        }
        if (t.type === 'word') {
            this.next();
            if (t.value === '*') return { type: 'exists', field };
            return { type: 'term', field, text: t.value, phrase: false };
        }
        throw new QuerySyntaxError(`Expected a value for field '${field}' at position ${t.pos}`);
    }

    private parseRange(field: string | undefined): QueryNode {
        const open = this.next();
        const lower = this.rangeBound();
        this.expect('to');
        const upper = this.rangeBound();
        const close = this.next();
        if (close.type !== 'rbracket' && close.type !== 'rbrace') {
            throw new QuerySyntaxError(`Expected ']' or '}' at position ${close.pos}`);
        }
        return {
            type: 'range',
            field,
            lower,
            upper,
            includeLower: open.type === 'lbracket',
            includeUpper: close.type === 'rbracket',
        };
    }

    private rangeBound(): string {
        const t = this.next();
        if (t.type === 'word' || t.type === 'quoted') return t.type === 'word' ? unescape(t.value) : t.value;
        throw new QuerySyntaxError(`Expected a range bound at position ${t.pos}`);
    }
}

function unescape(raw: string): string {
    return raw.replace(/\\(.)/g, '$1');
}

export function parseQuery(input: string): QueryNode {
    return new Parser(tokenize(input)).parse();
}

const KEYWORD_PREFIXES = ['app_metadata', 'user_metadata', 'identities', 'user_id'];
const FREE_TEXT_FIELDS = ['email', 'name', 'nickname', 'user_id', 'given_name', 'family_name', 'username'];

function isKeywordField(field: string): boolean {
    return KEYWORD_PREFIXES.some((p) => field === p || field.startsWith(`${p}.`));
}

/** Convert a Lucene word (with `\` escapes and `*`/`?` wildcards) into an anchored RegExp. */
function wordPattern(raw: string, caseInsensitive: boolean): RegExp {
    let pattern = '';
    for (let i = 0; i < raw.length; i++) {
        const c = raw[i]!;
        if (c === '\\' && i + 1 < raw.length) {
            pattern += escapeRegExp(raw[++i]!);
        } else if (c === '*') {
            pattern += '.*';
        } else if (c === '?') {
            pattern += '.';
        } else {
            pattern += escapeRegExp(c);
        }
    }
    return new RegExp(`^${pattern}$`, caseInsensitive ? 'is' : 's');
}

function escapeRegExp(c: string): string {
    return c.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

function valuesOf(entity: unknown, field: string | undefined): unknown[] {
    const fields = field ? [field] : FREE_TEXT_FIELDS;
    return fields.flatMap((f) => getPath(entity, f)).filter((v) => v !== undefined && v !== null);
}

function compareBound(value: unknown, bound: string): number {
    const num = Number(value);
    const boundNum = Number(bound);
    if (typeof value === 'number' || (Number.isFinite(num) && Number.isFinite(boundNum) && bound.trim() !== '')) {
        if (Number.isFinite(boundNum)) return num - boundNum;
    }
    const a = String(value);
    return a < bound ? -1 : a > bound ? 1 : 0;
}

export type Predicate = (entity: unknown) => boolean;

export function compile(node: QueryNode): Predicate {
    switch (node.type) {
        case 'all':
            return () => true;
        case 'and': {
            const children = node.children.map(compile);
            return (e) => children.every((c) => c(e));
        }
        case 'or': {
            const children = node.children.map(compile);
            return (e) => children.some((c) => c(e));
        }
        case 'not': {
            const child = compile(node.child);
            return (e) => !child(e);
        }
        case 'exists':
            return (e) => valuesOf(e, node.field).length > 0;
        case 'term': {
            const keyword = node.field ? isKeywordField(node.field) : false;
            if (node.phrase) {
                const wanted = keyword ? node.text : node.text.toLowerCase();
                return (e) =>
                    valuesOf(e, node.field).some((v) => (keyword ? String(v) : String(v).toLowerCase()) === wanted);
            }
            const pattern = wordPattern(node.text, !keyword);
            return (e) => valuesOf(e, node.field).some((v) => pattern.test(String(v)));
        }
        case 'range':
            return (e) =>
                valuesOf(e, node.field).some((v) => {
                    if (node.lower !== '*') {
                        const c = compareBound(v, node.lower);
                        if (c < 0 || (c === 0 && !node.includeLower)) return false;
                    }
                    if (node.upper !== '*') {
                        const c = compareBound(v, node.upper);
                        if (c > 0 || (c === 0 && !node.includeUpper)) return false;
                    }
                    return true;
                });
    }
}

/** Parse and compile a query string into a predicate; throws `QuerySyntaxError` on malformed input. */
export function compileQuery(input: string): Predicate {
    return compile(parseQuery(input));
}
