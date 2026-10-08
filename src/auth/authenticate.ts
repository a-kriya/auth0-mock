import type { AppContext } from '../context.ts';
import { oauthError } from '../errors.ts';
import { findUserByEmail, verifyPassword } from '../model/users.ts';
import type { Entity } from '../store/collection.ts';

export const BRUTE_FORCE_MESSAGE =
    "Your account has been blocked after multiple consecutive login attempts. We've sent you a notification via your preferred contact method with instructions on how to unblock it.";

export interface Credentials {
    connection: Entity;
    username: string;
    password: string;
    ip: string;
}

function bruteForce(ctx: AppContext) {
    const settings = ctx.store.attackProtection.bruteForce;
    const shields = Array.isArray(settings.shields) ? (settings.shields as string[]) : [];
    return {
        enabled: settings.enabled !== false && shields.includes('block'),
        maxAttempts:
            typeof settings.max_attempts === 'number' && settings.max_attempts > 0
                ? settings.max_attempts
                : ctx.config.bruteForceMaxAttempts,
        perIp: settings.mode !== 'count_per_identifier',
    };
}

function attemptKey(userId: string, ip: string, perIp: boolean): string {
    return `${userId}\u0000${perIp ? ip : '*'}`;
}

/**
 * Validate database-connection credentials with Auth0's failure semantics: unknown user or wrong
 * password → `invalid_grant`, blocked user → `unauthorized`, too many failures → `too_many_attempts`
 * (and the user is marked `blocked_for` the identifier/IP until unblocked).
 */
export function authenticateWithPassword(ctx: AppContext, creds: Credentials): Entity {
    const { store } = ctx;
    const connectionName = String(creds.connection.name);
    const identifier = creds.username.trim().toLowerCase();
    const user =
        findUserByEmail(store, identifier, connectionName) ??
        store.users.find(
            (u) =>
                typeof u.username === 'string' &&
                u.username.toLowerCase() === identifier &&
                Array.isArray(u.identities) &&
                (u.identities as Entity[]).some((i) => i.connection === connectionName)
        );
    if (!user) throw oauthError(403, 'invalid_grant', 'Wrong email or password.');

    const userId = String(user.user_id);
    const protection = bruteForce(ctx);
    const blocks = store.userBlocks.get(userId) ?? [];
    if (blocks.some((b) => b.identifier === identifier && (!protection.perIp || b.ip === creds.ip))) {
        throw oauthError(429, 'too_many_attempts', BRUTE_FORCE_MESSAGE);
    }
    if (user.blocked === true) throw oauthError(403, 'unauthorized', 'user is blocked');

    if (!verifyPassword(user.password_hash, creds.password)) {
        if (protection.enabled) {
            const key = attemptKey(userId, creds.ip, protection.perIp);
            const attempts = store.loginAttempts.get(key) ?? { count: 0, last: 0 };
            attempts.count += 1;
            attempts.last = Date.now();
            store.loginAttempts.set(key, attempts);
            if (attempts.count >= protection.maxAttempts) {
                blocks.push({ identifier, ...(protection.perIp ? { ip: creds.ip } : {}), connection: connectionName });
                store.userBlocks.set(userId, blocks);
                store.loginAttempts.delete(key);
                throw oauthError(429, 'too_many_attempts', BRUTE_FORCE_MESSAGE);
            }
        }
        throw oauthError(403, 'invalid_grant', 'Wrong email or password.');
    }

    store.loginAttempts.delete(attemptKey(userId, creds.ip, protection.perIp));
    return user;
}

/** Record a successful login on the user record. */
export function recordLogin(ctx: AppContext, user: Entity, ip: string): Entity {
    const count = typeof user.logins_count === 'number' ? user.logins_count : 0;
    return ctx.store.users.patch(
        String(user.user_id),
        { last_login: new Date().toISOString(), last_ip: ip, logins_count: count + 1 },
        { silent: true }
    );
}

/** Resolve the database connection for a password grant: explicit realm, else the tenant default directory. */
export function resolveConnection(ctx: AppContext, realm: string | undefined, client: Entity): Entity {
    const { store } = ctx;
    const name =
        realm ?? (typeof store.tenant.default_directory === 'string' ? store.tenant.default_directory : undefined);
    const connection = name ? store.connectionByName(name) : store.connections.find((c) => c.strategy === 'auth0');
    if (!connection) {
        throw oauthError(
            403,
            'invalid_request',
            realm ? `Unknown realm '${realm}'` : 'No default directory configured'
        );
    }
    const enabled = Array.isArray(connection.enabled_clients) ? (connection.enabled_clients as string[]) : [];
    if (!enabled.includes(String(client.client_id))) {
        throw oauthError(403, 'unauthorized_client', 'The connection is not enabled for this client');
    }
    return connection;
}
