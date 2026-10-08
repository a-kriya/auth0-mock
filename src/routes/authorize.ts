import { Router, type Request, type Response } from 'express';
import { runPostLogin } from '../actions/runtime.ts';
import { authenticateWithPassword, recordLogin, resolveConnection, BRUTE_FORCE_MESSAGE } from '../auth/authenticate.ts';
import { tenantName, type AppContext } from '../context.ts';
import { HttpError, oauthError } from '../errors.ts';
import type { Entity } from '../store/collection.ts';
import { generateId } from '../store/ids.ts';
import type { AuthorizeTransaction, Session } from '../store/store.ts';
import { issueTokens, splitScope, verifyAccessToken } from '../tokens.ts';
import { isPlainObject } from '../util/merge.ts';
import { loginView } from '../views/login.ts';
import { escapeHtml, page } from '../views/layout.ts';
import { formPostView, webMessageView } from '../views/web-message.ts';
import { requestInfo } from './oauth.ts';

const SESSION_COOKIE = 'auth0-mock.sid';
const CODE_TTL_MS = 5 * 60 * 1000;
const TRANSACTION_TTL_MS = 30 * 60 * 1000;

function readCookies(req: Request): Record<string, string> {
    const out: Record<string, string> = {};
    for (const part of (req.headers.cookie ?? '').split(';')) {
        const [k, ...rest] = part.trim().split('=');
        if (k) out[k] = decodeURIComponent(rest.join('='));
    }
    return out;
}

function currentSession(ctx: AppContext, req: Request): Session | undefined {
    const sid = readCookies(req)[SESSION_COOKIE];
    const session = sid ? ctx.store.sessions.get(sid) : undefined;
    return session && !session.revoked ? session : undefined;
}

function setSessionCookie(ctx: AppContext, res: Response, sid: string | null): void {
    const secure = ctx.config.tls !== 'off';
    const attributes = [`Path=/`, 'HttpOnly', secure ? 'SameSite=None; Secure' : 'SameSite=Lax'];
    if (sid === null) attributes.push('Max-Age=0');
    else attributes.push(`Max-Age=${7 * 24 * 3600}`);
    res.append('Set-Cookie', `${SESSION_COOKIE}=${sid ?? ''}; ${attributes.join('; ')}`);
}

function errorPage(res: Response, status: number, title: string, description: string): void {
    res.status(status)
        .type('html')
        .send(page(title, `<h1>${escapeHtml(title)}</h1><p class="description">${escapeHtml(description)}</p>`));
}

function str(value: unknown): string | undefined {
    return typeof value === 'string' && value.length > 0 ? value : undefined;
}

/** Deliver an authorization response (success or error) using the transaction's response_mode. */
function respond(res: Response, tx: AuthorizeTransaction, params: Record<string, string | undefined>): void {
    const fields = { ...params, ...(tx.state ? { state: tx.state } : {}) };
    if (tx.response_mode === 'web_message') {
        res.type('html').send(webMessageView(tx.redirect_uri, fields));
        return;
    }
    if (tx.response_mode === 'form_post') {
        res.type('html').send(formPostView(tx.redirect_uri, fields));
        return;
    }
    const url = new URL(tx.redirect_uri);
    const query = new URLSearchParams(Object.entries(fields).filter((e): e is [string, string] => e[1] !== undefined));
    if (tx.response_mode === 'fragment') url.hash = query.toString();
    else for (const [k, v] of query) url.searchParams.set(k, v);
    res.redirect(302, url.toString());
}

export function authorizeRoutes(ctx: AppContext): Router {
    const router = Router();
    const { store } = ctx;

    /** Finish an authorization for an authenticated user: run Actions, mint a code and/or tokens, respond. */
    async function complete(
        req: Request,
        res: Response,
        tx: AuthorizeTransaction,
        user: Entity,
        session: Session
    ): Promise<void> {
        const client = store.clients.require(tx.client_id);
        const connection =
            (tx.connection ? store.connectionByName(tx.connection) : undefined) ??
            store.connectionByName(String((user.identities as Entity[] | undefined)?.[0]?.connection)) ??
            store.connections.find((c) => c.strategy === 'auth0');
        if (!connection) throw oauthError(500, 'server_error', 'No database connection configured');
        const requestedScopes = splitScope(tx.scope);
        const outcome = await runPostLogin(ctx, {
            user,
            client,
            connection,
            protocol: 'oidc-basic-profile',
            requestedScopes,
            request: requestInfo(req),
            session: { id: session.id, createdAt: session.created_at },
            ...(tx.audience ? { audience: tx.audience } : {}),
            transaction: {
                redirect_uri: tx.redirect_uri,
                response_type: tx.response_type,
                response_mode: tx.response_mode,
                ...(tx.state ? { state: tx.state } : {}),
                ...(tx.login_hint ? { login_hint: tx.login_hint } : {}),
                ...(tx.prompt ? { prompt: [tx.prompt] } : {}),
            },
        });
        if (outcome.denied) {
            if (outcome.sessionRevoked) {
                session.revoked = outcome.sessionRevoked;
                setSessionCookie(ctx, res, null);
            }
            respond(res, tx, { error: outcome.denied.code, error_description: outcome.denied.reason });
            return;
        }
        const loggedIn = recordLogin(ctx, outcome.user, req.ip ?? '127.0.0.1');
        const responseTypes = tx.response_type.split(' ');
        const params: Record<string, string | undefined> = {};
        if (responseTypes.includes('code')) {
            const code = generateId.authorizationCode();
            const now = Date.now();
            store.authCodes.set(code, {
                code,
                user_id: String(loggedIn.user_id),
                client_id: tx.client_id,
                redirect_uri: tx.redirect_uri,
                scope: tx.scope,
                session_id: session.id,
                auth_time: Math.floor(session.created_at / 1000),
                access_token_claims: outcome.accessTokenClaims,
                id_token_claims: outcome.idTokenClaims,
                scope_adjustments: outcome.scopeAdjustments,
                created_at: now,
                expires_at: now + CODE_TTL_MS,
                ...(tx.audience ? { audience: tx.audience } : {}),
                ...(tx.nonce ? { nonce: tx.nonce } : {}),
                ...(tx.code_challenge ? { code_challenge: tx.code_challenge } : {}),
                ...(tx.code_challenge_method ? { code_challenge_method: tx.code_challenge_method } : {}),
            });
            params.code = code;
        }
        if (responseTypes.includes('token') || responseTypes.includes('id_token')) {
            const tokens = await issueTokens(ctx, {
                client,
                grantType: 'implicit',
                audience: tx.audience,
                scope: requestedScopes,
                user: loggedIn,
                sessionId: session.id,
                authTime: Math.floor(session.created_at / 1000),
                accessTokenClaims: outcome.accessTokenClaims,
                idTokenClaims: outcome.idTokenClaims,
                scopeAdjustments: outcome.scopeAdjustments,
                ...(tx.nonce ? { nonce: tx.nonce } : {}),
            });
            if (responseTypes.includes('token')) {
                params.access_token = tokens.access_token;
                params.token_type = 'Bearer';
                params.expires_in = String(tokens.expires_in);
                params.scope = tokens.scope;
            }
            if (responseTypes.includes('id_token')) params.id_token = tokens.id_token;
        }
        respond(res, tx, params);
    }

    router.get('/authorize', async (req, res) => {
        const q = req.query as Record<string, unknown>;
        const clientId = str(q.client_id);
        const client = clientId ? store.clients.get(clientId) : undefined;
        if (!client)
            return errorPage(res, 400, 'Oops!, something went wrong', `Unknown client: ${clientId ?? '(missing)'}`);
        const redirectUri = str(q.redirect_uri);
        const callbacks = Array.isArray(client.callbacks) ? (client.callbacks as string[]) : [];
        if (!redirectUri || !callbacks.includes(redirectUri)) {
            return errorPage(
                res,
                400,
                'Callback URL mismatch.',
                `${redirectUri ?? '(missing)'} is not in the list of allowed callback URLs. Please go to the Application Settings page and make sure you are sending a valid callback url from your application.`
            );
        }
        const responseType = str(q.response_type) ?? 'code';
        const responseMode =
            str(q.response_mode) ?? (responseType.split(' ').every((t) => t === 'code') ? 'query' : 'fragment');
        if (!['query', 'fragment', 'web_message', 'form_post'].includes(responseMode)) {
            return errorPage(res, 400, 'Oops!, something went wrong', `Unsupported response_mode: ${responseMode}`);
        }
        const now = Date.now();
        for (const [key, value] of store.transactions)
            if (value.created_at + TRANSACTION_TTL_MS < now) store.transactions.delete(key);
        const audience = str(q.audience);
        const nonce = str(q.nonce);
        const codeChallenge = str(q.code_challenge);
        const codeChallengeMethod = str(q.code_challenge_method);
        const loginHint = str(q.login_hint);
        const prompt = str(q.prompt);
        const connectionName = str(q.connection);
        const tx: AuthorizeTransaction = {
            state: generateId.sessionId(),
            client_id: String(client.client_id),
            redirect_uri: redirectUri,
            scope: str(q.scope) ?? 'openid',
            response_type: responseType,
            response_mode: responseMode,
            created_at: now,
            ...(audience ? { audience } : {}),
            ...(nonce ? { nonce } : {}),
            ...(codeChallenge ? { code_challenge: codeChallenge } : {}),
            ...(codeChallengeMethod ? { code_challenge_method: codeChallengeMethod } : {}),
            ...(loginHint ? { login_hint: loginHint } : {}),
            ...(prompt ? { prompt } : {}),
            ...(connectionName ? { connection: connectionName } : {}),
        };
        // The OAuth `state` the client sent is echoed back verbatim; our own id travels in the login form.
        const clientState = str(q.state);
        const record: AuthorizeTransaction = { ...tx, ...(clientState ? { state: clientState } : {}) };
        store.transactions.set(tx.state, record);

        const session = currentSession(ctx, req);
        if (session && tx.prompt !== 'login') {
            const user = store.users.get(session.user_id);
            if (user && user.blocked !== true) {
                await complete(req, res, record, user, session);
                store.transactions.delete(tx.state);
                return;
            }
        }
        if (tx.prompt === 'none') {
            store.transactions.delete(tx.state);
            respond(res, record, { error: 'login_required', error_description: 'Login required' });
            return;
        }
        res.redirect(302, `/u/login?state=${encodeURIComponent(tx.state)}`);
    });

    const renderLogin = (
        res: Response,
        txId: string,
        tx: AuthorizeTransaction,
        username: string | undefined,
        error: string | undefined
    ) => {
        const client = store.clients.get(tx.client_id);
        const passwordOnly =
            store.prompts.identifier_first === true && Boolean(tx.login_hint) && !error ? true : Boolean(tx.login_hint);
        res.status(error ? 400 : 200)
            .type('html')
            .send(
                loginView({
                    state: txId,
                    tenantName: tenantName(ctx),
                    clientName: String(client?.name ?? 'the application'),
                    passwordOnly,
                    ...(username !== undefined ? { username } : {}),
                    ...(error ? { error } : {}),
                })
            );
    };

    router.get('/u/login', (req, res) => {
        const txId = str(req.query.state);
        const tx = txId ? store.transactions.get(txId) : undefined;
        if (!txId || !tx)
            return errorPage(res, 400, 'Oops!, something went wrong', 'Invalid or expired login transaction (state).');
        renderLogin(res, txId, tx, tx.login_hint, undefined);
    });

    router.post('/u/login', async (req, res) => {
        const body: Entity = isPlainObject(req.body) ? req.body : {};
        const txId = str(req.query.state) ?? str(body.state);
        const tx = txId ? store.transactions.get(txId) : undefined;
        if (!txId || !tx)
            return errorPage(res, 400, 'Oops!, something went wrong', 'Invalid or expired login transaction (state).');
        const username = str(body.username) ?? tx.login_hint ?? '';
        const password = str(body.password) ?? '';
        const client = store.clients.require(tx.client_id);
        try {
            const connection = resolveConnection(ctx, tx.connection, client);
            const user = authenticateWithPassword(ctx, { connection, username, password, ip: req.ip ?? '127.0.0.1' });
            const session: Session = {
                id: generateId.sessionId(),
                user_id: String(user.user_id),
                client_id: tx.client_id,
                created_at: Date.now(),
            };
            store.sessions.set(session.id, session);
            setSessionCookie(ctx, res, session.id);
            store.transactions.delete(txId);
            await complete(req, res, tx, user, session);
        } catch (error) {
            if (error instanceof HttpError) {
                const code = error.body.error;
                const message =
                    code === 'invalid_grant'
                        ? 'Wrong email or password'
                        : code === 'too_many_attempts'
                          ? BRUTE_FORCE_MESSAGE
                          : String(error.body.error_description ?? error.message);
                renderLogin(res, txId, tx, username, message);
                return;
            }
            throw error;
        }
    });

    const logout = (req: Request, res: Response) => {
        const q = req.query as Record<string, unknown>;
        const sid = readCookies(req)[SESSION_COOKIE];
        if (sid) {
            store.sessions.delete(sid);
            for (const [token, record] of store.refreshTokens)
                if (record.session_id === sid) store.refreshTokens.delete(token);
        }
        setSessionCookie(ctx, res, null);
        const returnTo = str(q.returnTo) ?? str(q.post_logout_redirect_uri);
        if (!returnTo) {
            res.status(200)
                .type('html')
                .send(page('Logged out', '<h1>OK</h1><p class="description">You have been logged out.</p>'));
            return;
        }
        const clientId = str(q.client_id);
        const client = clientId ? store.clients.get(clientId) : undefined;
        const allowed = [
            ...(client && Array.isArray(client.allowed_logout_urls) ? (client.allowed_logout_urls as string[]) : []),
            ...(Array.isArray(store.tenant.allowed_logout_urls) ? (store.tenant.allowed_logout_urls as string[]) : []),
        ];
        if (
            !allowed.includes(returnTo) &&
            !allowed.some((a) => a.endsWith('*') && returnTo.startsWith(a.slice(0, -1)))
        ) {
            res.status(400)
                .type('text')
                .send(
                    `The "returnTo" querystring parameter "${returnTo}" is not defined as a valid URL in "Allowed Logout URLs".`
                );
            return;
        }
        res.redirect(302, returnTo);
    };
    router.get('/v2/logout', logout);
    router.get('/oidc/logout', logout);

    router.get('/userinfo', async (req, res) => {
        const header = req.headers.authorization;
        const token = header?.startsWith('Bearer ') ? header.slice(7) : str(req.query.access_token);
        if (!token) throw oauthError(401, 'invalid_token', 'Missing bearer token');
        let payload;
        try {
            payload = await verifyAccessToken(ctx, token);
        } catch {
            throw oauthError(401, 'invalid_token', 'Invalid or expired token');
        }
        const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
        if (!audiences.includes(`${ctx.issuer}userinfo`))
            throw oauthError(401, 'invalid_token', 'Token is not valid for userinfo');
        const user = payload.sub ? store.users.get(payload.sub) : undefined;
        if (!user) throw oauthError(401, 'invalid_token', 'Unknown subject');
        const scopes = new Set(splitScope(payload.scope));
        const claims: Record<string, unknown> = { sub: user.user_id };
        if (scopes.has('profile')) {
            for (const key of ['name', 'given_name', 'family_name', 'nickname', 'picture', 'updated_at']) {
                if (user[key] !== undefined) claims[key] = user[key];
            }
        }
        if (scopes.has('email')) {
            claims.email = user.email;
            claims.email_verified = user.email_verified === true;
        }
        res.json(claims);
    });

    return router;
}
