import { createRequire } from 'node:module';
import vm from 'node:vm';
import type { AppContext } from '../context.ts';
import { describePermissions } from '../model/roles.ts';
import { publicUser, userPatchChanges } from '../model/users.ts';
import type { Entity } from '../store/collection.ts';
import { isPlainObject, mergeShallow } from '../util/merge.ts';

export interface PostLoginInput {
    user: Entity;
    client: Entity;
    connection: Entity;
    /** OAuth protocol the login came through, e.g. `oauth2-password`, `oidc-basic-profile`, `oauth2-refresh-token`. */
    protocol: string;
    requestedScopes: string[];
    audience?: string;
    request: {
        ip: string;
        hostname: string;
        userAgent?: string;
        method: string;
        query: Record<string, unknown>;
        body: Record<string, unknown>;
    };
    session?: { id: string; createdAt: number };
    transaction?: Record<string, unknown>;
}

export interface PostLoginResult {
    denied?: { reason: string; code: string };
    accessTokenClaims: Record<string, unknown>;
    idTokenClaims: Record<string, unknown>;
    scopeAdjustments: { add: string[]; remove: string[] };
    /** User after any metadata mutations performed by the actions. */
    user: Entity;
    sessionRevoked?: string;
}

const ACTION_TIMEOUT_MS = 20_000;
const ALLOWED_BUILTINS = new Set([
    'assert',
    'buffer',
    'crypto',
    'events',
    'querystring',
    'stream',
    'string_decoder',
    'timers',
    'url',
    'util',
    'zlib',
]);

const nodeRequire = createRequire(import.meta.url);

/** `require('auth0')` inside an Action returns this store-backed facade (v4/v5 response shapes). */
function auth0Facade(ctx: AppContext) {
    const { store } = ctx;
    const data = <T>(value: T) => ({ data: value, status: 200, statusText: 'OK', headers: {} });
    class ManagementClient {
        readonly users = {
            get: async ({ id }: { id: string }) => data(publicUser(store, store.users.require(id))),
            getRoles: async ({ id }: { id: string }) => data(store.rolesOf(id)),
            getPermissions: async ({ id }: { id: string }) => data(describePermissions(store, store.permissionsOf(id))),
            update: async ({ id }: { id: string }, body: Entity) => {
                const user = store.users.require(id);
                return data(publicUser(store, store.users.patch(id, userPatchChanges(store, user, body))));
            },
            getAll: async (params: Record<string, unknown> = {}) => {
                const users = store.users.all().map((u) => publicUser(store, u));
                return data(
                    params.include_totals ? { users, total: users.length, start: 0, limit: users.length } : users
                );
            },
            assignRoles: async ({ id }: { id: string }, body: { roles: string[] }) => {
                const roles = store.userRoles.get(id) ?? [];
                for (const r of body.roles) if (!roles.includes(r)) roles.push(r);
                store.userRoles.set(id, roles);
                return data(undefined);
            },
            deleteRoles: async ({ id }: { id: string }, body: { roles: string[] }) => {
                store.userRoles.set(
                    id,
                    (store.userRoles.get(id) ?? []).filter((r) => !body.roles.includes(r))
                );
                return data(undefined);
            },
        };
        readonly usersByEmail = {
            getByEmail: async ({ email }: { email: string }) =>
                data(
                    store.users
                        .filter((u) => String(u.email).toLowerCase() === email.toLowerCase())
                        .map((u) => publicUser(store, u))
                ),
        };
        readonly roles = {
            getAll: async () => data(store.roles.all()),
            get: async ({ id }: { id: string }) => data(store.roles.require(id)),
        };
        readonly connections = {
            getAll: async () => data(store.connections.all()),
        };
    }
    class AuthenticationClient {
        readonly database = {
            changePassword: async () => data("We've just sent you an email to reset your password."),
        };
    }
    return { ManagementClient, AuthenticationClient };
}

function sandboxRequire(ctx: AppContext) {
    const facade = auth0Facade(ctx);
    return (name: string): unknown => {
        if (name === 'auth0') return facade;
        const bare = name.replace(/^node:/, '');
        if (ALLOWED_BUILTINS.has(bare)) return nodeRequire(`node:${bare}`);
        throw new Error(
            `Module '${name}' is not available in the auth0-mock Actions runtime (only 'auth0' and Node built-ins are)`
        );
    };
}

interface LoadedAction {
    name: string;
    handler: (event: unknown, api: unknown) => unknown;
    secrets: Record<string, string>;
}

function loadAction(ctx: AppContext, version: Entity): LoadedAction | undefined {
    const code = typeof version.code === 'string' ? version.code : '';
    const actionName = String((version.action as Entity | undefined)?.name ?? version.action_id);
    const moduleObject = { exports: {} as Record<string, unknown> };
    const context = vm.createContext({
        module: moduleObject,
        exports: moduleObject.exports,
        require: sandboxRequire(ctx),
        console: {
            log: (...args: unknown[]) => ctx.log.info(`[action ${actionName}]`, ...args),
            info: (...args: unknown[]) => ctx.log.info(`[action ${actionName}]`, ...args),
            warn: (...args: unknown[]) => ctx.log.warn(`[action ${actionName}]`, ...args),
            error: (...args: unknown[]) => ctx.log.error(`[action ${actionName}]`, ...args),
            debug: (...args: unknown[]) => ctx.log.debug(`[action ${actionName}]`, ...args),
        },
        setTimeout,
        clearTimeout,
        setInterval,
        clearInterval,
        URL,
        URLSearchParams,
        TextEncoder,
        TextDecoder,
        Buffer,
        fetch: globalThis.fetch,
        process: { env: {} },
    });
    new vm.Script(code, { filename: `${actionName}.js` }).runInContext(context, { timeout: 5_000 });
    const handler = moduleObject.exports.onExecutePostLogin;
    if (typeof handler !== 'function') return undefined;
    const secrets: Record<string, string> = {};
    for (const s of Array.isArray(version.secrets) ? (version.secrets as Entity[]) : []) {
        if (typeof s.name === 'string' && typeof s.value === 'string') secrets[s.name] = s.value;
    }
    return { name: actionName, handler: handler as LoadedAction['handler'], secrets };
}

/** Errors thrown inside the vm come from another realm, so `instanceof Error` cannot be used. */
function errorMessage(error: unknown): string {
    if (typeof error === 'object' && error !== null && typeof (error as { message?: unknown }).message === 'string') {
        return (error as { message: string }).message;
    }
    return String(error);
}

class DenyError extends Error {
    readonly code: string;
    constructor(code: string, reason: string) {
        super(reason);
        this.code = code;
    }
}

/**
 * Run every deployed action bound to the `post-login` trigger, in order, against a login. Implements the
 * subset of the post-login `event`/`api` objects that server-side flows use; redirects and MFA are no-ops.
 */
export async function runPostLogin(ctx: AppContext, input: PostLoginInput): Promise<PostLoginResult> {
    const { store } = ctx;
    const result: PostLoginResult = {
        accessTokenClaims: {},
        idTokenClaims: {},
        scopeAdjustments: { add: [], remove: [] },
        user: input.user,
    };
    const bound = (store.triggerBindings.get('post-login') ?? []).flatMap((binding) => {
        const action = store.actions.get(String((binding.action as Entity).id));
        const version = action && isPlainObject(action.deployed_version) ? action.deployed_version : undefined;
        return version ? [version] : [];
    });
    if (bound.length === 0) return result;

    let appMetadata: Entity = {};
    let userMetadata: Entity = {};
    const cache = new Map<string, string>();

    for (const version of bound) {
        let loaded: LoadedAction | undefined;
        try {
            loaded = loadAction(ctx, version);
        } catch (error) {
            // A module-level failure (e.g. a top-level require of an unavailable package) fails the login
            // like a thrown handler does, instead of escaping as a 500.
            const actionName = String((version.action as Entity | undefined)?.name ?? version.action_id);
            ctx.log.error(`[action ${actionName}] failed to load:`, error);
            result.denied = {
                code: 'access_denied',
                reason: `Action '${actionName}' failed: ${errorMessage(error)}`,
            };
            break;
        }
        if (!loaded) continue;
        const currentUser = store.users.require(String(input.user.user_id));
        const publicView = publicUser(store, currentUser);
        const event = {
            transaction: {
                id: `tx-${Date.now()}`,
                protocol: input.protocol,
                requested_scopes: input.requestedScopes,
                acr_values: [],
                locale: 'en',
                ui_locales: [],
                ...input.transaction,
            },
            authentication: { methods: [{ name: 'pwd', timestamp: new Date().toISOString() }] },
            authorization: { roles: store.rolesOf(String(currentUser.user_id)).map((r) => String(r.name)) },
            client: {
                client_id: input.client.client_id,
                name: input.client.name,
                metadata: isPlainObject(input.client.client_metadata) ? input.client.client_metadata : {},
            },
            connection: {
                id: input.connection.id,
                name: input.connection.name,
                strategy: input.connection.strategy,
                metadata: isPlainObject(input.connection.metadata) ? input.connection.metadata : {},
            },
            request: {
                ip: input.request.ip,
                hostname: input.request.hostname,
                method: input.request.method,
                query: input.request.query,
                body: input.request.body,
                geoip: {},
                user_agent: input.request.userAgent ?? '',
                language: 'en',
            },
            ...(input.audience ? { resource_server: { identifier: input.audience } } : {}),
            secrets: loaded.secrets,
            ...(input.session
                ? { session: { id: input.session.id, created_at: new Date(input.session.createdAt).toISOString() } }
                : {}),
            stats: { logins_count: typeof currentUser.logins_count === 'number' ? currentUser.logins_count : 0 },
            tenant: { id: String(store.tenant.friendly_name ?? 'auth0-mock') },
            user: {
                ...publicView,
                app_metadata: isPlainObject(publicView.app_metadata) ? publicView.app_metadata : {},
                user_metadata: isPlainObject(publicView.user_metadata) ? publicView.user_metadata : {},
            },
        };

        const api = {
            access: {
                deny(reason: string) {
                    throw new DenyError('access_denied', reason);
                },
            },
            accessToken: {
                setCustomClaim(name: string, value: unknown) {
                    result.accessTokenClaims[name] = value;
                },
                addScope(scope: string) {
                    result.scopeAdjustments.add.push(scope);
                },
                removeScope(scope: string) {
                    result.scopeAdjustments.remove.push(scope);
                },
            },
            idToken: {
                setCustomClaim(name: string, value: unknown) {
                    result.idTokenClaims[name] = value;
                },
            },
            user: {
                setAppMetadata(name: string, value: unknown) {
                    appMetadata = { ...appMetadata, [name]: value };
                },
                setUserMetadata(name: string, value: unknown) {
                    userMetadata = { ...userMetadata, [name]: value };
                },
            },
            session: {
                revoke(reason: string) {
                    result.sessionRevoked = reason;
                    throw new DenyError('access_denied', reason);
                },
            },
            multifactor: { enable() {} },
            authentication: {
                challengeWith() {},
                challengeWithAny() {},
                enrollWith() {},
                enrollWithAny() {},
                recordMethod() {},
                setPrimaryUser() {},
            },
            redirect: {
                sendUserTo() {
                    ctx.log.warn(
                        `[action ${loaded.name}] api.redirect.sendUserTo is not supported by auth0-mock; ignored`
                    );
                },
                encodeToken: () => '',
                canRedirect: () => false,
                validateToken: () => ({}),
            },
            cache: {
                get: (key: string) => (cache.has(key) ? { value: cache.get(key) } : undefined),
                set: (key: string, value: string) => {
                    cache.set(key, value);
                    return { type: 'success' as const };
                },
                delete: (key: string) => {
                    cache.delete(key);
                    return { type: 'success' as const };
                },
            },
            samlResponse: new Proxy({}, { get: () => () => {} }),
            prompt: { render() {} },
            rules: { wasExecuted: () => false },
            validation: {
                error(code: string, message: string) {
                    throw new DenyError(code, message);
                },
            },
        };

        try {
            await Promise.race([
                Promise.resolve(loaded.handler(event, api)),
                new Promise((_, reject) =>
                    setTimeout(() => reject(new Error(`Action '${loaded.name}' timed out`)), ACTION_TIMEOUT_MS)
                ),
            ]);
        } catch (error) {
            if (error instanceof DenyError) {
                result.denied = { code: error.code, reason: error.message };
            } else {
                ctx.log.error(`[action ${loaded.name}] failed:`, error);
                result.denied = {
                    code: 'access_denied',
                    reason: `Action '${loaded.name}' failed: ${errorMessage(error)}`,
                };
            }
        }

        // Metadata changes are persisted even when a later action denies (Auth0 applies them per action).
        if (Object.keys(appMetadata).length > 0 || Object.keys(userMetadata).length > 0) {
            const changes: Entity = {};
            if (Object.keys(appMetadata).length > 0)
                changes.app_metadata = mergeShallow(currentUser.app_metadata, appMetadata);
            if (Object.keys(userMetadata).length > 0)
                changes.user_metadata = mergeShallow(currentUser.user_metadata, userMetadata);
            store.users.patch(String(currentUser.user_id), changes, { silent: true });
            appMetadata = {};
            userMetadata = {};
        }
        if (result.denied) break;
    }
    result.user = store.users.require(String(input.user.user_id));
    return result;
}
