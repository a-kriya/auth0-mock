import { createHash, randomBytes, scryptSync, timingSafeEqual } from 'node:crypto';
import { badRequest, conflict } from '../errors.ts';
import type { Entity } from '../store/collection.ts';
import { generateId } from '../store/ids.ts';
import type { Store } from '../store/store.ts';
import { optionalString, requireString } from './validate.ts';

const SCRYPT = { N: 1024, r: 8, p: 1 };

export function hashPassword(password: string): string {
    const salt = randomBytes(16);
    const hash = scryptSync(password, salt, 32, SCRYPT);
    return `scrypt$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

export function verifyPassword(stored: unknown, password: string): boolean {
    if (typeof stored !== 'string') return false;
    const [scheme, salt, hash] = stored.split('$');
    if (scheme !== 'scrypt' || !salt || !hash) return false;
    const expected = Buffer.from(hash, 'base64url');
    const actual = scryptSync(password, Buffer.from(salt, 'base64url'), expected.length, SCRYPT);
    return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export function gravatar(email: string): string {
    const digest = createHash('md5').update(email.trim().toLowerCase()).digest('hex');
    const initials = email.slice(0, 2).toLowerCase();
    return `https://s.gravatar.com/avatar/${digest}?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2F${initials}.png`;
}

export function identitiesOf(user: Entity): Entity[] {
    return Array.isArray(user.identities) ? (user.identities as Entity[]) : [];
}

export function userConnection(user: Entity): string | undefined {
    const first = identitiesOf(user)[0];
    return typeof first?.connection === 'string' ? first.connection : undefined;
}

export function findUserByEmail(store: Store, email: string, connection?: string): Entity | undefined {
    const wanted = email.toLowerCase();
    return store.users.find(
        (u) =>
            typeof u.email === 'string' &&
            u.email.toLowerCase() === wanted &&
            (connection === undefined || userConnection(u) === connection)
    );
}

/** The view returned by the Management API: internal fields removed, brute-force blocks attached. */
export function publicUser(store: Store, user: Entity): Entity {
    const { password_hash: _p, ...view } = user;
    const blocks = store.userBlocks.get(String(user.user_id));
    if (blocks && blocks.length > 0) view.blocked_for = blocks.map((b) => ({ ...b }));
    return view;
}

export function buildUser(store: Store, input: Entity): Entity {
    const connectionName = requireString(input, 'connection');
    const connection = store.connectionByName(connectionName);
    if (!connection) throw badRequest('The connection does not exist.', 'inexistent_connection');
    const strategy = String(connection.strategy);
    const isDatabase = strategy === 'auth0';

    const email = optionalString(input, 'email')?.toLowerCase();
    const username = optionalString(input, 'username');
    if (isDatabase && !email) throw badRequest("Payload validation error: 'Missing required property: email'.");
    if (email && findUserByEmail(store, email, connectionName))
        throw conflict('The user already exists.', 'auth0_idp_error');

    const password = optionalString(input, 'password');
    if (isDatabase && !password) throw badRequest("Payload validation error: 'Missing required property: password'.");

    const provider = isDatabase ? 'auth0' : strategy;
    const providedId = optionalString(input, 'user_id');
    const localId = providedId?.includes('|')
        ? providedId.slice(providedId.indexOf('|') + 1)
        : (providedId ?? generateId.userId());
    const userId = `${provider}|${localId}`;
    if (store.users.has(userId)) throw conflict('The user already exists.', 'auth0_idp_error');

    const now = new Date().toISOString();
    const user: Entity = {
        user_id: userId,
        ...(email ? { email, email_verified: input.email_verified === true } : {}),
        ...(username ? { username } : {}),
        name: optionalString(input, 'name') ?? email ?? username ?? userId,
        nickname: optionalString(input, 'nickname') ?? email?.split('@')[0] ?? username ?? localId,
        picture: optionalString(input, 'picture') ?? gravatar(email ?? userId),
        identities: [{ connection: connectionName, user_id: localId, provider, isSocial: false }],
        created_at: now,
        updated_at: now,
    };
    for (const key of ['given_name', 'family_name', 'phone_number', 'user_metadata', 'app_metadata']) {
        if (input[key] !== undefined && input[key] !== null) user[key] = input[key];
    }
    if (input.phone_number !== undefined) user.phone_verified = input.phone_verified === true;
    if (input.blocked === true) user.blocked = true;
    if (password) user.password_hash = hashPassword(password);
    return user;
}

/** Apply Auth0 PATCH /users/:id semantics and return the changes to store. */
export function userPatchChanges(store: Store, user: Entity, body: Entity): Entity {
    const changes: Entity = {};
    const ignored = new Set([
        'user_id',
        'connection',
        'client_id',
        'verify_email',
        'verify_password',
        'verify_phone_number',
        'identities',
        'created_at',
        'updated_at',
        'last_login',
        'last_ip',
        'logins_count',
        'password_hash',
    ]);
    for (const [key, value] of Object.entries(body)) {
        if (ignored.has(key) || value === undefined) continue;
        changes[key] = value;
    }
    if ('password' in changes) {
        const password = requireString(body, 'password');
        changes.password_hash = hashPassword(password);
        changes.last_password_reset = new Date().toISOString();
        delete changes.password;
    }
    if ('email' in changes) {
        const email = requireString(body, 'email').toLowerCase();
        const other = findUserByEmail(store, email, userConnection(user));
        if (other && other.user_id !== user.user_id) throw conflict('The user already exists.', 'auth0_idp_error');
        changes.email = email;
        if (!('email_verified' in body)) changes.email_verified = false;
    }
    if ('username' in changes && typeof changes.username !== 'string') {
        throw badRequest("Payload validation error: 'username' must be a string");
    }
    return changes;
}

export function deleteUser(store: Store, userId: string): void {
    store.users.delete(userId);
    store.userRoles.delete(userId);
    store.userPermissions.delete(userId);
    store.userBlocks.delete(userId);
    for (const [key, session] of store.sessions) if (session.user_id === userId) store.sessions.delete(key);
    for (const [key, token] of store.refreshTokens) if (token.user_id === userId) store.refreshTokens.delete(key);
}
