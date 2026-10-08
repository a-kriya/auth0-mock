import { readFileSync } from 'node:fs';
import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import { join } from 'node:path';
import type { Express } from 'express';
import { createApp } from './app.ts';
import { resolveConfig, resolveIssuer, type Config, type ConfigInput } from './config.ts';
import type { AppContext } from './context.ts';
import { loadSigningKey, type SigningKey } from './keys.ts';
import { createLogger, type Logger } from './logger.ts';
import { ensureManagementResourceServer } from './model/resource-servers.ts';
import { parseIdPins } from './store/ids.ts';
import { importSeed as importSeedDocument } from './store/seed.ts';
import { Store, type Snapshot } from './store/store.ts';
import { ensureTls, type TlsMaterial } from './tls.ts';

export type { Config, ConfigInput } from './config.ts';
export type { Snapshot } from './store/store.ts';
export { Store } from './store/store.ts';
export { configFromEnv, configFromFile, configFromFlags, resolveConfig } from './config.ts';

export interface Auth0MockServer {
    /** Base URL without trailing slash, e.g. `https://localhost:4400`. */
    url: string;
    /** Issuer with trailing slash. */
    issuer: string;
    port: number;
    server: Server;
    close(): Promise<void>;
}

export interface Auth0Mock {
    config: Config;
    store: Store;
    key: SigningKey;
    log: Logger;
    tls: TlsMaterial | undefined;
    /** Bind the server. The issuer defaults to the bound address when not configured. */
    listen(): Promise<Auth0MockServer>;
    /** Restore boot state (defaults + seed). */
    reset(): void;
    /** Load a seed/snapshot document into the store. */
    importSeed(snapshot: Snapshot): void;
}

/** Create an emulator instance from programmatic options (same keys as the config file). */
export async function createAuth0Mock(options: Partial<ConfigInput> = {}): Promise<Auth0Mock> {
    const config = resolveConfig(options);
    const log = createLogger(config.logLevel);
    const tls = await ensureTls(config);
    const keyPath = config.signingKey ?? (tls?.dir ? join(tls.dir, 'jwt-signing-key.pem') : undefined);
    const key = await loadSigningKey(keyPath);
    const store = new Store();
    if (config.idPins) store.pins = parseIdPins(JSON.parse(readFileSync(config.idPins, 'utf8')));
    const seed: Snapshot | undefined = config.seed
        ? (JSON.parse(readFileSync(config.seed, 'utf8')) as Snapshot)
        : undefined;

    let ctx: AppContext | undefined;
    let app: Express | undefined;

    const seedContext = () => ({
        issuer: ctx?.issuer ?? resolveIssuer(config),
        tenantName: typeof store.tenant.friendly_name === 'string' ? store.tenant.friendly_name : 'auth0-mock',
        signingCertificate: tls?.ca ?? '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
    });
    const importSeed = (snapshot: Snapshot) => {
        importSeedDocument(store, snapshot, seedContext());
    };
    const reset = () => {
        store.reset();
        if (ctx) ensureManagementResourceServer(store, ctx.issuer);
        if (seed) importSeed(seed);
    };

    const listen = async (): Promise<Auth0MockServer> => {
        type NodeHandler = (req: IncomingMessage, res: ServerResponse) => void;
        const handler: NodeHandler = (req, res) => {
            if (!app) {
                res.statusCode = 503;
                res.end('starting');
                return;
            }
            (app as unknown as NodeHandler)(req, res);
        };
        const server = tls ? createHttpsServer({ key: tls.key, cert: tls.cert }, handler) : createHttpServer(handler);
        await new Promise<void>((resolve, reject) => {
            server.once('error', reject);
            server.listen(config.port, config.host, () => resolve());
        });
        const port = (server.address() as AddressInfo).port;
        const issuer = resolveIssuer(config, port);
        ctx = { config, issuer, store, key, log, ...(tls ? { tls } : {}) };
        reset();
        app = createApp(ctx, { reset, importSeed });
        log.info(`listening on ${issuer} (tls: ${config.tls})`);
        return {
            url: issuer.replace(/\/$/, ''),
            issuer,
            port,
            server,
            close: () =>
                new Promise<void>((resolve, reject) => {
                    server.closeIdleConnections();
                    server.close((error) => (error ? reject(error) : resolve()));
                    server.closeAllConnections();
                }),
        };
    };

    return { config, store, key, log, tls, listen, reset, importSeed };
}
