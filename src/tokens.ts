import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import type { AppContext } from './context.ts';
import { oauthError } from './errors.ts';
import { grantScopes } from './model/clients.ts';
import { scopesOf } from './model/resource-servers.ts';
import type { Entity } from './store/collection.ts';
import { generateId } from './store/ids.ts';
import type { RefreshTokenRecord } from './store/store.ts';
import { isPlainObject } from './util/merge.ts';

export const OIDC_SCOPES = new Set(['openid', 'profile', 'email', 'address', 'phone', 'offline_access']);

export interface IssueOptions {
    client: Entity;
    grantType: string;
    /** Requested audience; resolved against resource servers (undefined → userinfo token). */
    audience: string | undefined;
    /** Requested scopes (already split). */
    scope: string[];
    user?: Entity;
    nonce?: string;
    sessionId?: string;
    authTime?: number;
    /** Claims added by post-login Actions. */
    accessTokenClaims?: Record<string, unknown>;
    idTokenClaims?: Record<string, unknown>;
    /** Scopes added/removed by Actions (`api.accessToken.addScope` / `removeScope`). */
    scopeAdjustments?: { add: string[]; remove: string[] };
    /** Existing refresh-token record when exchanging a refresh token (for rotation). */
    refreshedFrom?: RefreshTokenRecord;
}

export interface TokenSet {
    access_token: string;
    id_token?: string;
    refresh_token?: string;
    scope: string;
    expires_in: number;
    token_type: 'Bearer';
}

export const splitScope = (value: unknown): string[] =>
    typeof value === 'string' ? value.split(/[\s,]+/).filter(Boolean) : [];

/** Scopes a user may receive for a resource server, following Auth0 RBAC semantics. */
export function grantedUserScopes(
    ctx: AppContext,
    user: Entity,
    resourceServer: Entity | undefined,
    requested: string[]
): {
    scopes: string[];
    permissions: string[];
} {
    const oidc = requested.filter((s) => OIDC_SCOPES.has(s));
    const api = requested.filter((s) => !OIDC_SCOPES.has(s));
    if (!resourceServer) return { scopes: oidc, permissions: [] };
    const identifier = String(resourceServer.identifier);
    const declared = new Set(scopesOf(resourceServer).map((s) => s.value));
    const permissions = ctx.store
        .permissionsOf(String(user.user_id))
        .filter((p) => p.resource_server_identifier === identifier)
        .map((p) => p.permission_name);
    if (resourceServer.enforce_policies === true) {
        const allowed = new Set(permissions);
        return { scopes: [...oidc, ...api.filter((s) => allowed.has(s))], permissions };
    }
    return { scopes: [...oidc, ...api.filter((s) => declared.has(s))], permissions };
}

/** Scopes a client receives for `client_credentials`; throws when no grant exists. */
export function grantedClientScopes(ctx: AppContext, client: Entity, audience: string, requested: string[]): string[] {
    const grant = ctx.store.clientGrants.find((g) => g.client_id === client.client_id && g.audience === audience);
    if (!grant) {
        throw oauthError(
            403,
            'access_denied',
            `Client is not authorized to access "${audience}". You need to create a "client-grant" associated to this API.`
        );
    }
    const allowed = grantScopes(grant);
    if (requested.length === 0) return allowed;
    const disallowed = requested.filter((s) => !allowed.includes(s));
    if (disallowed.length > 0) {
        throw oauthError(403, 'access_denied', `Client has not been granted scopes: ${disallowed.join(', ')}`);
    }
    return requested;
}

function lifetimeOf(ctx: AppContext, resourceServer: Entity | undefined): number {
    return typeof resourceServer?.token_lifetime === 'number'
        ? resourceServer.token_lifetime
        : ctx.config.accessTokenTtl;
}

function idTokenLifetime(ctx: AppContext, client: Entity): number {
    const jwt = isPlainObject(client.jwt_configuration) ? client.jwt_configuration : {};
    return typeof jwt.lifetime_in_seconds === 'number' ? jwt.lifetime_in_seconds : ctx.config.idTokenTtl;
}

function profileClaims(user: Entity, scopes: Set<string>): Record<string, unknown> {
    const claims: Record<string, unknown> = {};
    if (scopes.has('profile')) {
        for (const key of ['name', 'given_name', 'family_name', 'middle_name', 'nickname', 'picture', 'updated_at']) {
            if (user[key] !== undefined) claims[key] = user[key];
        }
    }
    if (scopes.has('email')) {
        if (user.email !== undefined) claims.email = user.email;
        claims.email_verified = user.email_verified === true;
    }
    if (scopes.has('phone') && user.phone_number !== undefined) {
        claims.phone_number = user.phone_number;
        claims.phone_verified = user.phone_verified === true;
    }
    return claims;
}

export async function issueTokens(ctx: AppContext, options: IssueOptions): Promise<TokenSet> {
    const { client, user, grantType } = options;
    const store = ctx.store;
    const resourceServer = options.audience ? store.resourceServerByIdentifier(options.audience) : undefined;
    if (options.audience && !resourceServer) {
        throw oauthError(403, 'access_denied', `Service not found: ${options.audience}`);
    }

    let scopes: string[];
    let permissions: string[] = [];
    if (user) {
        ({ scopes, permissions } = grantedUserScopes(ctx, user, resourceServer, options.scope));
    } else {
        if (!options.audience)
            throw oauthError(403, 'access_denied', 'Non-global clients are not allowed access to APIv1');
        scopes = grantedClientScopes(ctx, client, options.audience, options.scope);
    }
    if (options.scopeAdjustments) {
        scopes = [...new Set([...scopes, ...options.scopeAdjustments.add])].filter(
            (s) => !options.scopeAdjustments?.remove.includes(s)
        );
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresIn = lifetimeOf(ctx, resourceServer);
    const clientId = String(client.client_id);
    const audiences = options.audience
        ? scopes.includes('openid') && user
            ? [options.audience, `${ctx.issuer}userinfo`]
            : options.audience
        : `${ctx.issuer}userinfo`;

    const accessPayload: JWTPayload = {
        iss: ctx.issuer,
        sub: user ? String(user.user_id) : `${clientId}@clients`,
        aud: audiences,
        iat: now,
        exp: now + expiresIn,
        scope: scopes.join(' '),
        azp: clientId,
        ...options.accessTokenClaims,
    };
    if (grantType === 'client_credentials') accessPayload.gty = 'client-credentials';
    else if (grantType !== 'authorization_code') accessPayload.gty = grantType.split('/').pop();
    if (user && resourceServer?.token_dialect === 'access_token_authz') accessPayload.permissions = permissions;
    if (options.sessionId && user) accessPayload.sid = options.sessionId;

    const sign = (payload: JWTPayload) =>
        new SignJWT(payload)
            .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: ctx.key.kid })
            .sign(ctx.key.privateKey);

    const result: TokenSet = {
        access_token: await sign(accessPayload),
        scope: scopes.join(' '),
        expires_in: expiresIn,
        token_type: 'Bearer',
    };

    if (user && scopes.includes('openid')) {
        const idPayload: JWTPayload = {
            iss: ctx.issuer,
            sub: String(user.user_id),
            aud: clientId,
            iat: now,
            exp: now + idTokenLifetime(ctx, client),
            ...profileClaims(user, new Set(scopes)),
            ...options.idTokenClaims,
        };
        if (options.nonce) idPayload.nonce = options.nonce;
        if (options.sessionId) idPayload.sid = options.sessionId;
        if (options.authTime) idPayload.auth_time = options.authTime;
        result.id_token = await sign(idPayload);
    }

    if (user && shouldIssueRefreshToken(client, resourceServer, scopes, grantType, options.refreshedFrom)) {
        result.refresh_token = createRefreshToken(ctx, {
            user,
            client,
            scope: scopes,
            ...(options.audience ? { audience: options.audience } : {}),
            ...(options.sessionId ? { sessionId: options.sessionId } : {}),
            ...(options.refreshedFrom ? { previous: options.refreshedFrom } : {}),
        });
    }
    return result;
}

function shouldIssueRefreshToken(
    client: Entity,
    resourceServer: Entity | undefined,
    scopes: string[],
    grantType: string,
    previous: RefreshTokenRecord | undefined
): boolean {
    const grantTypes = Array.isArray(client.grant_types) ? (client.grant_types as string[]) : [];
    if (!grantTypes.includes('refresh_token')) return false;
    if (grantType === 'refresh_token') {
        const rt = isPlainObject(client.refresh_token) ? client.refresh_token : {};
        return rt.rotation_type === 'rotating' || previous === undefined;
    }
    if (!scopes.includes('offline_access')) return false;
    if (resourceServer && resourceServer.allow_offline_access !== true) return false;
    return true;
}

function createRefreshToken(
    ctx: AppContext,
    input: {
        user: Entity;
        client: Entity;
        scope: string[];
        audience?: string;
        sessionId?: string;
        previous?: RefreshTokenRecord;
    }
): string {
    const rt = isPlainObject(input.client.refresh_token) ? input.client.refresh_token : {};
    const now = Date.now();
    const lifetime =
        rt.infinite_token_lifetime === true || rt.expiration_type === 'non-expiring'
            ? 100 * 365 * 24 * 3600
            : typeof rt.token_lifetime === 'number'
              ? rt.token_lifetime
              : ctx.config.refreshTokenTtl;
    const token = generateId.refreshToken();
    ctx.store.refreshTokens.set(token, {
        token,
        user_id: String(input.user.user_id),
        client_id: String(input.client.client_id),
        scope: input.scope.join(' '),
        ...(input.audience ? { audience: input.audience } : {}),
        ...(input.sessionId ? { session_id: input.sessionId } : {}),
        created_at: now,
        // Absolute lifetime carries over from the first token of the chain when rotating.
        expires_at: input.previous ? input.previous.expires_at : now + lifetime * 1000,
    });
    if (input.previous && rt.rotation_type === 'rotating') {
        input.previous.rotated_at = now;
    }
    return token;
}

/** Verify a token issued by this emulator and return its payload. */
export async function verifyAccessToken(ctx: AppContext, token: string): Promise<JWTPayload> {
    const { payload } = await jwtVerify(token, ctx.key.publicKey, { issuer: ctx.issuer, algorithms: ['RS256'] });
    return payload;
}
