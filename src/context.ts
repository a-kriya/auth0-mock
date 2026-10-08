import type { Config } from './config.ts';
import type { SigningKey } from './keys.ts';
import type { Logger } from './logger.ts';
import type { Store } from './store/store.ts';
import type { TlsMaterial } from './tls.ts';

/** Everything route handlers need; created once per running emulator. */
export interface AppContext {
    config: Config;
    /** Issuer URL with trailing slash, e.g. `https://localhost:4400/`. */
    issuer: string;
    store: Store;
    key: SigningKey;
    log: Logger;
    tls?: TlsMaterial;
}

export function tenantName(ctx: AppContext): string {
    const name = ctx.store.tenant.friendly_name;
    return typeof name === 'string' && name ? name : 'auth0-mock';
}
