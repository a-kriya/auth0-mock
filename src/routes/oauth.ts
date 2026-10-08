import { createHash } from 'node:crypto';
import { Router, type Request } from 'express';
import { authenticateWithPassword, recordLogin, resolveConnection } from '../auth/authenticate.ts';
import { runPostLogin, type PostLoginInput } from '../actions/runtime.ts';
import type { AppContext } from '../context.ts';
import { oauthError } from '../errors.ts';
import { clientGrantTypes } from '../model/clients.ts';
import type { Entity } from '../store/collection.ts';
import { issueTokens, splitScope } from '../tokens.ts';
import { isPlainObject } from '../util/merge.ts';

const PASSWORD_REALM = 'http://auth0.com/oauth/grant-type/password-realm';

export function requestInfo(req: Request): PostLoginInput['request'] {
    const body = isPlainObject(req.body) ? req.body : {};
    return {
        ip: req.ip ?? '127.0.0.1',
        hostname: req.hostname,
        method: req.method,
        query: req.query as Record<string, unknown>,
        body: Object.fromEntries(Object.entries(body).filter(([k]) => k !== 'password' && k !== 'client_secret')),
        ...(req.headers['user-agent'] ? { userAgent: req.headers['user-agent'] } : {}),
    };
}

/** Identify and (for confidential clients) authenticate the caller of the token endpoint. */
export function resolveClient(ctx: AppContext, req: Request, body: Entity): Entity {
    let clientId = typeof body.client_id === 'string' ? body.client_id : undefined;
    let clientSecret = typeof body.client_secret === 'string' ? body.client_secret : undefined;
    const header = req.headers.authorization;
    if (header?.startsWith('Basic ')) {
        const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
        const separator = decoded.indexOf(':');
        if (separator > 0) {
            clientId ??= decodeURIComponent(decoded.slice(0, separator));
            clientSecret ??= decodeURIComponent(decoded.slice(separator + 1));
        }
    }
    if (!clientId) throw oauthError(401, 'invalid_client', 'Missing client_id');
    const client = ctx.store.clients.get(clientId);
    if (!client) throw oauthError(401, 'access_denied', 'Unauthorized');
    const confidential = client.token_endpoint_auth_method !== 'none';
    if (confidential && !ctx.config.acceptAnyClientSecret) {
        if (!clientSecret || clientSecret !== client.client_secret)
            throw oauthError(401, 'access_denied', 'Unauthorized');
    }
    return client;
}

export function oauthRoutes(ctx: AppContext): Router {
    const router = Router();
    const { store } = ctx;

    router.post('/oauth/token', async (req, res) => {
        res.setHeader('Cache-Control', 'no-store');
        res.setHeader('Pragma', 'no-cache');
        const body: Entity = isPlainObject(req.body) ? req.body : {};
        const grantType = typeof body.grant_type === 'string' ? body.grant_type : undefined;
        if (!grantType) throw oauthError(400, 'invalid_request', 'Missing required parameter: grant_type');
        const client = resolveClient(ctx, req, body);
        if (!clientGrantTypes(client).includes(grantType)) {
            throw oauthError(403, 'unauthorized_client', `Grant type '${grantType}' not allowed for the client.`);
        }
        const audience = typeof body.audience === 'string' && body.audience ? body.audience : undefined;
        const requestedScopes = splitScope(body.scope);
        const request = requestInfo(req);

        switch (grantType) {
            case 'client_credentials': {
                res.json(await issueTokens(ctx, { client, grantType, audience, scope: requestedScopes }));
                return;
            }
            case 'password':
            case PASSWORD_REALM: {
                const username = typeof body.username === 'string' ? body.username : undefined;
                const password = typeof body.password === 'string' ? body.password : undefined;
                if (!username) throw oauthError(400, 'invalid_request', 'Missing required parameter: username');
                if (!password) throw oauthError(400, 'invalid_request', 'Missing required parameter: password');
                const realm = grantType === PASSWORD_REALM && typeof body.realm === 'string' ? body.realm : undefined;
                const connection = resolveConnection(ctx, realm, client);
                const user = authenticateWithPassword(ctx, { connection, username, password, ip: request.ip });
                const outcome = await runPostLogin(ctx, {
                    user,
                    client,
                    connection,
                    protocol: 'oauth2-password',
                    requestedScopes,
                    request,
                    ...(audience ? { audience } : {}),
                });
                if (outcome.denied) throw oauthError(403, outcome.denied.code, outcome.denied.reason);
                const loggedIn = recordLogin(ctx, outcome.user, request.ip);
                res.json(
                    await issueTokens(ctx, {
                        client,
                        grantType,
                        audience,
                        scope: requestedScopes,
                        user: loggedIn,
                        accessTokenClaims: outcome.accessTokenClaims,
                        idTokenClaims: outcome.idTokenClaims,
                        scopeAdjustments: outcome.scopeAdjustments,
                    })
                );
                return;
            }
            case 'authorization_code': {
                const code = typeof body.code === 'string' ? body.code : undefined;
                if (!code) throw oauthError(400, 'invalid_request', 'Missing required parameter: code');
                const record = store.authCodes.get(code);
                store.authCodes.delete(code); // single use
                if (!record || record.client_id !== client.client_id || record.expires_at < Date.now()) {
                    throw oauthError(403, 'invalid_grant', 'Invalid authorization code');
                }
                if (typeof body.redirect_uri === 'string' && body.redirect_uri !== record.redirect_uri) {
                    throw oauthError(403, 'invalid_grant', 'Invalid authorization code');
                }
                if (record.code_challenge) {
                    const verifier = typeof body.code_verifier === 'string' ? body.code_verifier : '';
                    const expected =
                        record.code_challenge_method === 'plain'
                            ? verifier
                            : createHash('sha256').update(verifier).digest('base64url');
                    if (!verifier || expected !== record.code_challenge) {
                        throw oauthError(403, 'invalid_grant', 'Failed to verify code verifier');
                    }
                }
                const user = store.users.get(record.user_id);
                if (!user) throw oauthError(403, 'invalid_grant', 'Invalid authorization code');
                res.json(
                    await issueTokens(ctx, {
                        client,
                        grantType,
                        audience: record.audience,
                        scope: splitScope(record.scope),
                        user,
                        ...(record.nonce ? { nonce: record.nonce } : {}),
                        ...(record.session_id ? { sessionId: record.session_id } : {}),
                        ...(record.auth_time ? { authTime: record.auth_time } : {}),
                        ...(record.access_token_claims ? { accessTokenClaims: record.access_token_claims } : {}),
                        ...(record.id_token_claims ? { idTokenClaims: record.id_token_claims } : {}),
                        ...(record.scope_adjustments ? { scopeAdjustments: record.scope_adjustments } : {}),
                    })
                );
                return;
            }
            case 'refresh_token': {
                const token = typeof body.refresh_token === 'string' ? body.refresh_token : undefined;
                if (!token) throw oauthError(400, 'invalid_request', 'Missing required parameter: refresh_token');
                const record = store.refreshTokens.get(token);
                if (
                    !record ||
                    record.client_id !== client.client_id ||
                    record.expires_at < Date.now() ||
                    record.rotated_at
                ) {
                    if (record?.rotated_at) store.refreshTokens.delete(token);
                    throw oauthError(403, 'invalid_grant', 'Unknown or invalid refresh token.');
                }
                const user = store.users.get(record.user_id);
                if (!user || user.blocked === true)
                    throw oauthError(403, 'invalid_grant', 'Unknown or invalid refresh token.');
                const session = record.session_id ? store.sessions.get(record.session_id) : undefined;
                if (record.session_id && (!session || session.revoked)) {
                    throw oauthError(403, 'invalid_grant', 'Unknown or invalid refresh token.');
                }
                const originalScopes = splitScope(record.scope);
                const scope =
                    requestedScopes.length > 0
                        ? requestedScopes.filter((s) => originalScopes.includes(s))
                        : originalScopes;
                const connection =
                    (Array.isArray(user.identities) &&
                        store.connectionByName(String((user.identities as Entity[])[0]?.connection))) ||
                    store.connections.find((c) => c.strategy === 'auth0');
                let outcome;
                if (connection) {
                    outcome = await runPostLogin(ctx, {
                        user,
                        client,
                        connection,
                        protocol: 'oauth2-refresh-token',
                        requestedScopes: scope,
                        request,
                        ...(record.audience ? { audience: record.audience } : {}),
                        ...(session ? { session: { id: session.id, createdAt: session.created_at } } : {}),
                    });
                    if (outcome.denied) {
                        if (outcome.sessionRevoked && session) session.revoked = outcome.sessionRevoked;
                        throw oauthError(403, outcome.denied.code, outcome.denied.reason);
                    }
                }
                const tokens = await issueTokens(ctx, {
                    client,
                    grantType,
                    audience: record.audience,
                    scope,
                    user: outcome?.user ?? user,
                    refreshedFrom: record,
                    ...(record.session_id ? { sessionId: record.session_id } : {}),
                    ...(outcome
                        ? { accessTokenClaims: outcome.accessTokenClaims, idTokenClaims: outcome.idTokenClaims }
                        : {}),
                    ...(outcome ? { scopeAdjustments: outcome.scopeAdjustments } : {}),
                });
                if (!tokens.refresh_token) tokens.refresh_token = token; // non-rotating: the same token stays valid
                res.json(tokens);
                return;
            }
            default:
                throw oauthError(403, 'unsupported_grant_type', `Grant type '${grantType}' is not supported`);
        }
    });

    router.post('/oauth/revoke', (req, res) => {
        const body: Entity = isPlainObject(req.body) ? req.body : {};
        const token = typeof body.token === 'string' ? body.token : undefined;
        if (!token) throw oauthError(400, 'invalid_request', 'Missing required parameter: token');
        const record = store.refreshTokens.get(token);
        if (record) {
            if (typeof body.client_id === 'string' && body.client_id !== record.client_id) {
                throw oauthError(403, 'invalid_client', 'The client is not authorized to revoke this token');
            }
            store.refreshTokens.delete(token);
        }
        res.status(200).json({});
    });

    return router;
}
