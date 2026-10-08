#!/usr/bin/env node
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs, type ParseArgsConfig } from 'node:util';
import { configFields, configFromEnv, configFromFile, configFromFlags, resolveConfig } from '../src/config.ts';
import { createAuth0Mock } from '../src/index.ts';
import { TLS_FILES } from '../src/tls.ts';

type OptionSpec = NonNullable<ParseArgsConfig['options']>;

const options: OptionSpec = {
    config: { type: 'string', short: 'c' },
    help: { type: 'boolean', short: 'h' },
    version: { type: 'boolean', short: 'v' },
};
for (const field of Object.values(configFields)) {
    options[field.flag] = { type: field.kind === 'boolean' ? 'boolean' : 'string' };
}

function usage(): string {
    const lines = Object.entries(configFields).map(
        ([key, f]) => `  --${f.flag.padEnd(26)} ${`AUTH0_MOCK_${f.env}`.padEnd(38)} (${key})`
    );
    return [
        'Usage: auth0-mock [options]',
        '',
        'Options (flags override environment variables, which override --config file values):',
        '  --config, -c <file>            JSON config file',
        ...lines,
        '  --help, -h',
        '  --version, -v',
    ].join('\n');
}

const { values } = parseArgs({ options, strict: true, allowPositionals: false });

if (values.help) {
    console.log(usage());
    process.exit(0);
}
if (values.version) {
    // bin/ lives next to package.json in the repo and one level deeper in the published dist/.
    const candidates = ['../package.json', '../../package.json'].map((p) => new URL(p, import.meta.url));
    const found = candidates.find((url) => existsSync(url));
    const pkg = found ? (JSON.parse(readFileSync(found, 'utf8')) as { version: string }) : { version: 'unknown' };
    console.log(pkg.version);
    process.exit(0);
}

const flagValues = Object.fromEntries(
    Object.entries(values).filter(([k]) => !['config', 'help', 'version'].includes(k))
) as Record<string, string | boolean | undefined>;

const config = resolveConfig(
    typeof values.config === 'string' ? configFromFile(values.config) : undefined,
    configFromEnv(),
    configFromFlags(flagValues)
);

const mock = await createAuth0Mock(config);
const server = await mock.listen();

console.log(`auth0-mock ready`);
console.log(`  issuer        ${server.issuer}`);
console.log(`  jwks          ${server.issuer}.well-known/jwks.json`);
console.log(`  management    ${server.issuer}api/v2/`);
if (mock.tls?.dir) console.log(`  ca cert       ${join(mock.tls.dir, TLS_FILES.caCert)}`);
console.log(
    `  admin token   ${config.adminToken ? 'configured' : 'not configured (Management API needs a client token)'}`
);
console.log(`  seed          ${config.seed ?? 'none'}`);

const shutdown = async () => {
    await server.close();
    process.exit(0);
};
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
