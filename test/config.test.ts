import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
    ENV_PREFIX,
    configFields,
    configFromEnv,
    configFromFile,
    configFromFlags,
    resolveConfig,
    resolveIssuer,
} from '../src/config.ts';

describe('configFields', () => {
    it('declares a unique env suffix and flag for every field', () => {
        const fields = Object.values(configFields);
        expect(new Set(fields.map((f) => f.env)).size).toBe(fields.length);
        expect(new Set(fields.map((f) => f.flag)).size).toBe(fields.length);
        expect(ENV_PREFIX).toBe('AUTH0_MOCK_');
        expect(configFields.tlsDir).toEqual({ env: 'TLS_DIR', kind: 'string', flag: 'tls-dir' });
        expect(configFields.acceptAnyClientSecret.kind).toBe('boolean');
        expect(configFields.tlsSans.kind).toBe('list');
        expect(configFields.port.kind).toBe('number');
    });
});

describe('configFromEnv', () => {
    it('ignores unrelated and unset variables', () => {
        expect(configFromEnv({})).toEqual({});
        expect(configFromEnv({ PATH: '/bin', PORT: '9999', AUTH0_MOCK_UNKNOWN: 'x' })).toEqual({});
    });

    it('passes strings through untouched', () => {
        expect(
            configFromEnv({
                AUTH0_MOCK_HOST: '127.0.0.1',
                AUTH0_MOCK_TLS: 'off',
                AUTH0_MOCK_ISSUER: 'https://auth.local/',
                AUTH0_MOCK_ADMIN_TOKEN: 'secret',
                AUTH0_MOCK_LOG_LEVEL: 'debug',
            })
        ).toEqual({
            host: '127.0.0.1',
            tls: 'off',
            issuer: 'https://auth.local/',
            adminToken: 'secret',
            logLevel: 'debug',
        });
    });

    it('coerces numbers', () => {
        expect(configFromEnv({ AUTH0_MOCK_PORT: '4400' })).toEqual({ port: 4400 });
        expect(configFromEnv({ AUTH0_MOCK_ACCESS_TOKEN_TTL: '3600' })).toEqual({ accessTokenTtl: 3600 });
        expect(configFromEnv({ AUTH0_MOCK_BRUTE_FORCE_MAX_ATTEMPTS: '3' })).toEqual({ bruteForceMaxAttempts: 3 });
        expect(configFromEnv({ AUTH0_MOCK_PORT: '1e3' })).toEqual({ port: 1000 });
    });

    it('rejects invalid numbers naming the variable', () => {
        expect(() => configFromEnv({ AUTH0_MOCK_PORT: 'abc' })).toThrow(
            "Invalid AUTH0_MOCK_PORT: expected a number, got 'abc'"
        );
        expect(() => configFromEnv({ AUTH0_MOCK_ID_TOKEN_TTL: 'Infinity' })).toThrow(/Invalid AUTH0_MOCK_ID_TOKEN_TTL/);
        expect(() => configFromEnv({ AUTH0_MOCK_REFRESH_TOKEN_TTL: '12abc' })).toThrow(
            /Invalid AUTH0_MOCK_REFRESH_TOKEN_TTL: expected a number/
        );
    });

    it('coerces booleans (true/1/yes/on, false/0/no/off, case-insensitive)', () => {
        for (const raw of ['true', '1', 'yes', 'on', 'TRUE', 'Yes', 'ON']) {
            expect(configFromEnv({ AUTH0_MOCK_ACCEPT_ANY_CLIENT_SECRET: raw }), raw).toEqual({
                acceptAnyClientSecret: true,
            });
        }
        for (const raw of ['false', '0', 'no', 'off', 'FALSE', 'No', 'OFF', '']) {
            expect(configFromEnv({ AUTH0_MOCK_ACCEPT_ANY_CLIENT_SECRET: raw }), JSON.stringify(raw)).toEqual({
                acceptAnyClientSecret: false,
            });
        }
    });

    it('rejects invalid booleans naming the variable', () => {
        expect(() => configFromEnv({ AUTH0_MOCK_ACCEPT_ANY_CLIENT_SECRET: 'maybe' })).toThrow(
            "Invalid AUTH0_MOCK_ACCEPT_ANY_CLIENT_SECRET: expected a boolean, got 'maybe'"
        );
        expect(() => configFromEnv({ AUTH0_MOCK_ACCEPT_ANY_CLIENT_SECRET: '2' })).toThrow(
            /Invalid AUTH0_MOCK_ACCEPT_ANY_CLIENT_SECRET/
        );
    });

    it('splits comma-separated lists and trims entries', () => {
        expect(configFromEnv({ AUTH0_MOCK_TLS_SANS: 'localhost,127.0.0.1' })).toEqual({
            tlsSans: ['localhost', '127.0.0.1'],
        });
        expect(configFromEnv({ AUTH0_MOCK_TLS_SANS: ' localhost , 127.0.0.1 ,, api.local ' })).toEqual({
            tlsSans: ['localhost', '127.0.0.1', 'api.local'],
        });
        expect(configFromEnv({ AUTH0_MOCK_TLS_SANS: 'single' })).toEqual({ tlsSans: ['single'] });
        expect(configFromEnv({ AUTH0_MOCK_TLS_SANS: '' })).toEqual({ tlsSans: [] });
    });

    it('reads several variables at once', () => {
        expect(
            configFromEnv({
                AUTH0_MOCK_PORT: '4500',
                AUTH0_MOCK_TLS: 'off',
                AUTH0_MOCK_TLS_SANS: 'a,b',
                AUTH0_MOCK_ACCEPT_ANY_CLIENT_SECRET: 'yes',
                HOME: '/home/x',
            })
        ).toEqual({ port: 4500, tls: 'off', tlsSans: ['a', 'b'], acceptAnyClientSecret: true });
    });
});

describe('configFromFlags', () => {
    it('maps kebab-case flag names from configFields to config keys with the same coercion', () => {
        expect(
            configFromFlags({
                port: '5000',
                'tls-dir': '/tmp/certs',
                'tls-sans': 'a, b',
                'admin-token': 'tok',
                'log-level': 'warn',
                'access-token-ttl': '60',
                'accept-any-client-secret': 'true',
            })
        ).toEqual({
            port: 5000,
            tlsDir: '/tmp/certs',
            tlsSans: ['a', 'b'],
            adminToken: 'tok',
            logLevel: 'warn',
            accessTokenTtl: 60,
            acceptAnyClientSecret: true,
        });
    });

    it('passes boolean flag values through and ignores undefined and unknown keys', () => {
        expect(configFromFlags({ 'accept-any-client-secret': true })).toEqual({ acceptAnyClientSecret: true });
        expect(configFromFlags({ 'accept-any-client-secret': false })).toEqual({ acceptAnyClientSecret: false });
        expect(configFromFlags({ port: undefined, config: 'x.json', help: true })).toEqual({});
        expect(configFromFlags({})).toEqual({});
    });

    it('uses the same coercion errors as the environment reader', () => {
        expect(() => configFromFlags({ port: 'abc' })).toThrow(/expected a number, got 'abc'/);
        expect(() => configFromFlags({ 'accept-any-client-secret': 'maybe' })).toThrow(/expected a boolean/);
    });

    it('accepts every flag declared in configFields', () => {
        const values = Object.fromEntries(
            Object.values(configFields).map((f) => [
                f.flag,
                f.kind === 'number' ? '1' : f.kind === 'boolean' ? 'true' : 'x',
            ])
        );
        const parsed = configFromFlags(values) as Record<string, unknown>;
        expect(Object.keys(parsed).sort()).toEqual(Object.keys(configFields).sort());
    });
});

describe('resolveConfig', () => {
    it('applies defaults', () => {
        expect(resolveConfig()).toEqual({
            port: 4400,
            host: '0.0.0.0',
            tls: 'auto',
            tlsDir: './certs',
            tlsSans: ['localhost', '127.0.0.1', 'host.docker.internal'],
            acceptAnyClientSecret: false,
            accessTokenTtl: 86400,
            idTokenTtl: 36000,
            refreshTokenTtl: 2592000,
            bruteForceMaxAttempts: 10,
            logLevel: 'info',
        });
        expect(resolveConfig({})).toEqual(resolveConfig());
    });

    it('lets later sources win', () => {
        const config = resolveConfig({ port: 1, host: 'a' }, { port: 2 }, { port: 3, logLevel: 'silent' });
        expect(config.port).toBe(3);
        expect(config.host).toBe('a');
        expect(config.logLevel).toBe('silent');
    });

    it('ignores undefined values and undefined sources', () => {
        const config = resolveConfig({ port: 1, adminToken: 'keep' }, undefined, {
            port: undefined,
            adminToken: undefined,
        });
        expect(config.port).toBe(1);
        expect(config.adminToken).toBe('keep');
        expect(resolveConfig(undefined, undefined).port).toBe(4400);
    });

    it('rejects a port out of range or non-integer', () => {
        expect(() => resolveConfig({ port: 70000 })).toThrow(/^Invalid configuration: port: /);
        expect(() => resolveConfig({ port: -1 })).toThrow(/Invalid configuration: port/);
        expect(() => resolveConfig({ port: 1.5 })).toThrow(/Invalid configuration: port/);
        expect(resolveConfig({ port: 0 }).port).toBe(0);
        expect(resolveConfig({ port: 65535 }).port).toBe(65535);
    });

    it('rejects a bad tls enum and other invalid enum values', () => {
        expect(() => resolveConfig({ tls: 'maybe' as never })).toThrow(/Invalid configuration: tls: /);
        expect(() => resolveConfig({ logLevel: 'loud' as never })).toThrow(/Invalid configuration: logLevel: /);
        for (const tls of ['auto', 'provided', 'off'] as const) expect(resolveConfig({ tls }).tls).toBe(tls);
    });

    it('rejects non-positive lifetimes and empty list entries', () => {
        expect(() => resolveConfig({ accessTokenTtl: 0 })).toThrow(/accessTokenTtl/);
        expect(() => resolveConfig({ idTokenTtl: -5 })).toThrow(/idTokenTtl/);
        expect(() => resolveConfig({ tlsSans: [''] })).toThrow(/tlsSans/);
    });

    it('reports every issue in one message', () => {
        expect(() => resolveConfig({ port: 70000, tls: 'maybe' as never })).toThrow(/port: .*; tls: /);
    });

    it('rejects wrong primitive types', () => {
        expect(() => resolveConfig({ port: '4400' as never })).toThrow(/Invalid configuration: port/);
        expect(() => resolveConfig({ acceptAnyClientSecret: 'yes' as never })).toThrow(/acceptAnyClientSecret/);
    });
});

describe('resolveIssuer', () => {
    it('defaults to https://localhost:<port>/', () => {
        expect(resolveIssuer(resolveConfig({ port: 4400 }))).toBe('https://localhost:4400/');
        expect(resolveIssuer(resolveConfig({ port: 4400, tls: 'provided' }))).toBe('https://localhost:4400/');
    });

    it('uses http when tls is off', () => {
        expect(resolveIssuer(resolveConfig({ port: 4400, tls: 'off' }))).toBe('http://localhost:4400/');
    });

    it('prefers the bound port when given', () => {
        expect(resolveIssuer(resolveConfig({ port: 0 }), 51234)).toBe('https://localhost:51234/');
        expect(resolveIssuer(resolveConfig({ port: 0, tls: 'off' }), 51234)).toBe('http://localhost:51234/');
    });

    it('uses a configured issuer and always ends with a slash', () => {
        expect(resolveIssuer(resolveConfig({ issuer: 'https://auth.local' }))).toBe('https://auth.local/');
        expect(resolveIssuer(resolveConfig({ issuer: 'https://auth.local/' }))).toBe('https://auth.local/');
        expect(resolveIssuer(resolveConfig({ issuer: 'https://auth.local/tenant' }), 9)).toBe(
            'https://auth.local/tenant/'
        );
        expect(resolveIssuer(resolveConfig({ issuer: 'http://custom:1234', tls: 'off', port: 1 }))).toBe(
            'http://custom:1234/'
        );
    });
});

describe('configFromFile', () => {
    let dir: string;
    beforeAll(() => {
        dir = mkdtempSync(join(tmpdir(), 'auth0-mock-config-'));
    });
    afterAll(() => rmSync(dir, { recursive: true, force: true }));

    const write = (name: string, content: string): string => {
        const path = join(dir, name);
        writeFileSync(path, content);
        return path;
    };

    it('reads a JSON object keyed by camelCase field names', () => {
        const path = write('ok.json', JSON.stringify({ port: 4500, tls: 'off', tlsSans: ['a'] }));
        expect(configFromFile(path)).toEqual({ port: 4500, tls: 'off', tlsSans: ['a'] });
        expect(configFromFile(write('empty.json', '{}'))).toEqual({});
    });

    it('rejects non-object documents', () => {
        expect(() => configFromFile(write('array.json', '[1, 2]'))).toThrow(/must contain a JSON object/);
        expect(() => configFromFile(write('string.json', '"port"'))).toThrow(/must contain a JSON object/);
        expect(() => configFromFile(write('null.json', 'null'))).toThrow(/must contain a JSON object/);
        expect(() => configFromFile(write('number.json', '42'))).toThrow(/must contain a JSON object/);
    });

    it('names the offending file', () => {
        const path = write('bad.json', 'true');
        expect(() => configFromFile(path)).toThrow(path);
    });

    it('propagates JSON syntax and missing-file errors', () => {
        expect(() => configFromFile(write('syntax.json', '{ port: 1 }'))).toThrow(SyntaxError);
        expect(() => configFromFile(join(dir, 'missing.json'))).toThrow(/ENOENT/);
    });

    it('composes with the other sources in precedence order', () => {
        const file = write('base.json', JSON.stringify({ port: 4500, tls: 'off', host: 'file' }));
        const config = resolveConfig(
            configFromFile(file),
            configFromEnv({ AUTH0_MOCK_PORT: '4600' }),
            configFromFlags({ host: 'flag' })
        );
        expect(config).toMatchObject({ port: 4600, tls: 'off', host: 'flag' });
        expect(resolveIssuer(config)).toBe('http://localhost:4600/');
    });
});
