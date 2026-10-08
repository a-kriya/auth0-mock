import { readFileSync } from 'node:fs';
import { z } from 'zod';

const list = z.array(z.string().min(1));

export const configSchema = z.object({
    /** TCP port to listen on. */
    port: z.number().int().min(0).max(65535).default(4400),
    /** Interface to bind. */
    host: z.string().default('0.0.0.0'),
    /** Issuer URL placed in tokens (with trailing slash). Defaults to `https://localhost:<port>/`. */
    issuer: z.string().optional(),
    /** `auto` generates a local CA + certificate in `tlsDir`; `provided` uses `tlsCert`/`tlsKey`; `off` serves HTTP. */
    tls: z.enum(['auto', 'provided', 'off']).default('auto'),
    tlsDir: z.string().default('./certs'),
    tlsSans: list.default(['localhost', '127.0.0.1', 'host.docker.internal']),
    tlsCert: z.string().optional(),
    tlsKey: z.string().optional(),
    /** PEM file holding the RS256 signing key. Generated (and persisted next to the TLS material) when absent. */
    signingKey: z.string().optional(),
    /** Static bearer accepted by the Management API with every scope (used to bootstrap with Terraform). */
    adminToken: z.string().optional(),
    /** JSON seed/snapshot loaded at boot. */
    seed: z.string().optional(),
    /** JSON file pinning generated identifiers by resource name. */
    idPins: z.string().optional(),
    /** Skip client secret verification on `client_credentials` grants. */
    acceptAnyClientSecret: z.boolean().default(false),
    /** Fallback access token lifetime (seconds) when the audience has no resource server. */
    accessTokenTtl: z.number().int().positive().default(86400),
    idTokenTtl: z.number().int().positive().default(36000),
    refreshTokenTtl: z.number().int().positive().default(2592000),
    /** Failed logins per identifier/IP before a block, when attack protection does not specify one. */
    bruteForceMaxAttempts: z.number().int().positive().default(10),
    logLevel: z.enum(['silent', 'error', 'warn', 'info', 'debug']).default('info'),
});

export type Config = z.output<typeof configSchema>;
export type ConfigInput = z.input<typeof configSchema>;

type FieldKind = 'string' | 'number' | 'boolean' | 'list';

/** Environment variable suffix (after `AUTH0_MOCK_`) and value kind for every field. */
export const configFields: Record<keyof ConfigInput, { env: string; kind: FieldKind; flag: string }> = {
    port: { env: 'PORT', kind: 'number', flag: 'port' },
    host: { env: 'HOST', kind: 'string', flag: 'host' },
    issuer: { env: 'ISSUER', kind: 'string', flag: 'issuer' },
    tls: { env: 'TLS', kind: 'string', flag: 'tls' },
    tlsDir: { env: 'TLS_DIR', kind: 'string', flag: 'tls-dir' },
    tlsSans: { env: 'TLS_SANS', kind: 'list', flag: 'tls-sans' },
    tlsCert: { env: 'TLS_CERT', kind: 'string', flag: 'tls-cert' },
    tlsKey: { env: 'TLS_KEY', kind: 'string', flag: 'tls-key' },
    signingKey: { env: 'SIGNING_KEY', kind: 'string', flag: 'signing-key' },
    adminToken: { env: 'ADMIN_TOKEN', kind: 'string', flag: 'admin-token' },
    seed: { env: 'SEED', kind: 'string', flag: 'seed' },
    idPins: { env: 'ID_PINS', kind: 'string', flag: 'id-pins' },
    acceptAnyClientSecret: { env: 'ACCEPT_ANY_CLIENT_SECRET', kind: 'boolean', flag: 'accept-any-client-secret' },
    accessTokenTtl: { env: 'ACCESS_TOKEN_TTL', kind: 'number', flag: 'access-token-ttl' },
    idTokenTtl: { env: 'ID_TOKEN_TTL', kind: 'number', flag: 'id-token-ttl' },
    refreshTokenTtl: { env: 'REFRESH_TOKEN_TTL', kind: 'number', flag: 'refresh-token-ttl' },
    bruteForceMaxAttempts: { env: 'BRUTE_FORCE_MAX_ATTEMPTS', kind: 'number', flag: 'brute-force-max-attempts' },
    logLevel: { env: 'LOG_LEVEL', kind: 'string', flag: 'log-level' },
};

export const ENV_PREFIX = 'AUTH0_MOCK_';

function coerce(kind: FieldKind, raw: string): unknown {
    switch (kind) {
        case 'number': {
            const n = Number(raw);
            if (!Number.isFinite(n)) throw new Error(`expected a number, got '${raw}'`);
            return n;
        }
        case 'boolean':
            if (['true', '1', 'yes', 'on'].includes(raw.toLowerCase())) return true;
            if (['false', '0', 'no', 'off', ''].includes(raw.toLowerCase())) return false;
            throw new Error(`expected a boolean, got '${raw}'`);
        case 'list':
            return raw
                .split(',')
                .map((s) => s.trim())
                .filter(Boolean);
        default:
            return raw;
    }
}

/** Read `AUTH0_MOCK_*` variables into a partial config (strings coerced by field kind). */
export function configFromEnv(env: NodeJS.ProcessEnv = process.env): Partial<ConfigInput> {
    const out: Record<string, unknown> = {};
    for (const [key, field] of Object.entries(configFields)) {
        const raw = env[`${ENV_PREFIX}${field.env}`];
        if (raw === undefined) continue;
        try {
            out[key] = coerce(field.kind, raw);
        } catch (error) {
            throw new Error(`Invalid ${ENV_PREFIX}${field.env}: ${(error as Error).message}`);
        }
    }
    return out as Partial<ConfigInput>;
}

/** Read a JSON config file (keys are the camelCase field names). */
export function configFromFile(path: string): Partial<ConfigInput> {
    const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new Error(`Config file ${path} must contain a JSON object`);
    }
    return parsed as Partial<ConfigInput>;
}

/** Parse CLI-style string values (`--port 4400`) using the same coercion as environment variables. */
export function configFromFlags(values: Record<string, string | boolean | undefined>): Partial<ConfigInput> {
    const out: Record<string, unknown> = {};
    for (const [key, field] of Object.entries(configFields)) {
        const raw = values[field.flag];
        if (raw === undefined) continue;
        out[key] = typeof raw === 'boolean' ? raw : coerce(field.kind, raw);
    }
    return out as Partial<ConfigInput>;
}

function stripUndefined<T extends object>(value: T): T {
    return Object.fromEntries(Object.entries(value).filter(([, v]) => v !== undefined)) as T;
}

/** Merge partial sources in increasing precedence and validate. */
export function resolveConfig(...sources: Array<Partial<ConfigInput> | undefined>): Config {
    const merged = Object.assign({}, ...sources.map((s) => (s ? stripUndefined(s) : {})));
    const result = configSchema.safeParse(merged);
    if (!result.success) {
        const issues = result.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ');
        throw new Error(`Invalid configuration: ${issues}`);
    }
    return result.data;
}

/** The issuer, always with a trailing slash (Auth0 issuers end with `/`). */
export function resolveIssuer(config: Config, boundPort = config.port): string {
    const raw = config.issuer ?? `${config.tls === 'off' ? 'http' : 'https'}://localhost:${boundPort}/`;
    return raw.endsWith('/') ? raw : `${raw}/`;
}
