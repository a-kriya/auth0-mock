import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { PASSWORD_REALM, REALM, tokenRequest } from './auth-flows.ts';
import { API_AUDIENCE, PASSWORD, decodeJwt, provisionTenant, startMock, type Harness, type Tenant } from './helpers.ts';

const BRUTE_FORCE_MESSAGE =
    "Your account has been blocked after multiple consecutive login attempts. We've sent you a notification via your preferred contact method with instructions on how to unblock it.";
const WRONG_CREDENTIALS = { error: 'invalid_grant', error_description: 'Wrong email or password.' };
const UNAUTHORIZED_CLIENT = { error: 'access_denied', error_description: 'Unauthorized' };
const REFRESH_REJECTED = { error: 'invalid_grant', error_description: 'Unknown or invalid refresh token.' };
const ALL_SCOPES = 'openid profile email offline_access read:things write:things admin:things';

describe('POST /oauth/token', () => {
    let h: Harness;
    let t: Tenant;
    beforeAll(async () => {
        h = await startMock();
        t = await provisionTenant(h);
    });
    afterAll(() => h.close());

    const clientCredentials = (extra: Record<string, unknown> = {}) =>
        h.token({
            grant_type: 'client_credentials',
            client_id: t.clients.backend.client_id,
            client_secret: t.clients.backend.client_secret,
            audience: API_AUDIENCE,
            ...extra,
        });
    const passwordRealm = (username: string, password: string, extra: Record<string, unknown> = {}) =>
        h.token({
            grant_type: PASSWORD_REALM,
            client_id: t.clients.spa.client_id,
            realm: REALM,
            username,
            password,
            audience: API_AUDIENCE,
            scope: ALL_SCOPES,
            ...extra,
        });
    const refresh = (token: string, extra: Record<string, unknown> = {}) =>
        h.token({ grant_type: 'refresh_token', client_id: t.clients.spa.client_id, refresh_token: token, ...extra });
    const userOf = async (id: string) => (await h.mgmt('GET', `/users/${encodeURIComponent(id)}`)).body;

    describe('client_credentials', () => {
        it('returns an access token carrying the grant scopes', async () => {
            const res = await clientCredentials();
            expect(res.status).toBe(200);
            expect(res.headers.get('cache-control')).toBe('no-store');
            expect(Object.keys(res.body).sort()).toEqual(['access_token', 'expires_in', 'scope', 'token_type']);
            expect(res.body).toMatchObject({ scope: 'read:things', expires_in: 900, token_type: 'Bearer' });
            const claims = decodeJwt(res.body.access_token);
            expect(claims).toMatchObject({
                iss: h.issuer,
                sub: `${t.clients.backend.client_id}@clients`,
                aud: API_AUDIENCE,
                azp: t.clients.backend.client_id,
                gty: 'client-credentials',
                scope: 'read:things',
            });
            expect(claims.exp - claims.iat).toBe(900);
            expect(claims.permissions).toBeUndefined();
        });

        it('honours a requested subset of the granted scopes', async () => {
            const res = await clientCredentials({ audience: h.managementAudience, scope: 'read:roles read:users' });
            expect(res.status).toBe(200);
            expect(res.body.scope).toBe('read:roles read:users');
            expect(decodeJwt(res.body.access_token).scope).toBe('read:roles read:users');
        });

        it('rejects a scope outside the grant', async () => {
            const res = await clientCredentials({ scope: 'read:things write:things' });
            expect(res.status).toBe(403);
            expect(res.body).toEqual({
                error: 'access_denied',
                error_description: 'Client has not been granted scopes: write:things',
            });
        });

        it('rejects an audience the client has no grant for', async () => {
            const other = await h.mgmt('POST', '/resource-servers', {
                name: 'Other API',
                identifier: 'https://other.example.com',
            });
            expect(other.status).toBe(201);
            const res = await clientCredentials({ audience: 'https://other.example.com' });
            expect(res.status).toBe(403);
            expect(res.body).toEqual({
                error: 'access_denied',
                error_description:
                    'Client is not authorized to access "https://other.example.com". You need to create a "client-grant" associated to this API.',
            });
        });

        it('rejects an unknown audience', async () => {
            const res = await clientCredentials({ audience: 'https://unknown.example.com' });
            expect(res.status).toBe(403);
            expect(res.body).toEqual({
                error: 'access_denied',
                error_description: 'Service not found: https://unknown.example.com',
            });
        });

        it('rejects a missing audience', async () => {
            const res = await clientCredentials({ audience: undefined });
            expect(res.status).toBe(403);
            expect(res.body).toEqual({
                error: 'access_denied',
                error_description: 'Non-global clients are not allowed access to APIv1',
            });
        });

        it('uses the Management API lifetime and grant for its audience', async () => {
            const res = await clientCredentials({ audience: h.managementAudience });
            expect(res.status).toBe(200);
            expect(res.body).toMatchObject({
                expires_in: 86400,
                scope: 'read:users create:users update:users read:roles',
            });
            const claims = decodeJwt(res.body.access_token);
            expect(claims.aud).toBe(h.managementAudience);
            expect(claims.exp - claims.iat).toBe(86400);
        });

        it('rejects a wrong or missing client secret', async () => {
            const wrong = await clientCredentials({ client_secret: 'wrong' });
            expect(wrong.status).toBe(401);
            expect(wrong.body).toEqual(UNAUTHORIZED_CLIENT);
            const missing = await clientCredentials({ client_secret: undefined });
            expect(missing.status).toBe(401);
            expect(missing.body).toEqual(UNAUTHORIZED_CLIENT);
        });

        it('rejects an unknown client', async () => {
            const res = await clientCredentials({ client_id: 'x'.repeat(32) });
            expect(res.status).toBe(401);
            expect(res.body).toEqual(UNAUTHORIZED_CLIENT);
        });

        it('rejects a missing client_id', async () => {
            const res = await h.token({ grant_type: 'client_credentials', audience: API_AUDIENCE });
            expect(res.status).toBe(401);
            expect(res.body).toEqual({ error: 'invalid_client', error_description: 'Missing client_id' });
        });

        it('rejects a grant type the client is not allowed to use', async () => {
            const res = await h.token({
                grant_type: 'client_credentials',
                client_id: t.clients.spa.client_id,
                audience: API_AUDIENCE,
            });
            expect(res.status).toBe(403);
            expect(res.body).toEqual({
                error: 'unauthorized_client',
                error_description: "Grant type 'client_credentials' not allowed for the client.",
            });
        });

        it('accepts HTTP Basic client authentication', async () => {
            const basic = (secret: string) =>
                `Basic ${Buffer.from(`${t.clients.backend.client_id}:${secret}`).toString('base64')}`;
            const body = { grant_type: 'client_credentials', audience: API_AUDIENCE };
            const res = await tokenRequest(h, body, { authorization: basic(t.clients.backend.client_secret) });
            expect(res.status).toBe(200);
            expect(decodeJwt(res.body.access_token).sub).toBe(`${t.clients.backend.client_id}@clients`);
            const wrong = await tokenRequest(h, body, { authorization: basic('wrong') });
            expect(wrong.status).toBe(401);
            expect(wrong.body).toEqual(UNAUTHORIZED_CLIENT);
        });

        it('requires grant_type', async () => {
            const res = await h.token({
                client_id: t.clients.backend.client_id,
                client_secret: t.clients.backend.client_secret,
                audience: API_AUDIENCE,
            });
            expect(res.status).toBe(400);
            expect(res.body).toEqual({
                error: 'invalid_request',
                error_description: 'Missing required parameter: grant_type',
            });
        });
    });

    describe('password-realm and password grants', () => {
        it('issues access, id and refresh tokens to alice', async () => {
            const res = await passwordRealm('alice@example.com', PASSWORD);
            expect(res.status).toBe(200);
            expect(Object.keys(res.body).sort()).toEqual([
                'access_token',
                'expires_in',
                'id_token',
                'refresh_token',
                'scope',
                'token_type',
            ]);
            expect(res.body).toMatchObject({ token_type: 'Bearer', expires_in: 900, scope: ALL_SCOPES });
            expect(res.body.refresh_token).toMatch(/^v1\.M[A-Za-z0-9_-]{60}$/);

            const access = decodeJwt(res.body.access_token);
            expect(access).toMatchObject({
                iss: h.issuer,
                sub: 'auth0|alice',
                aud: [API_AUDIENCE, `${h.issuer}userinfo`],
                azp: t.clients.spa.client_id,
                gty: 'password-realm',
                scope: ALL_SCOPES,
            });
            expect([...access.permissions].sort()).toEqual(['admin:things', 'read:things', 'write:things']);
            expect(access.exp - access.iat).toBe(900);
            expect(access.sid).toBeUndefined();

            const id = decodeJwt(res.body.id_token);
            expect(id).toMatchObject({
                iss: h.issuer,
                sub: 'auth0|alice',
                aud: t.clients.spa.client_id,
                name: 'Alice Example',
                given_name: 'Alice',
                family_name: 'Example',
                nickname: 'alice',
                email: 'alice@example.com',
                email_verified: true,
            });
            expect(id.exp - id.iat).toBe(36000);
        });

        it('only issues an id_token for openid and a refresh_token for offline_access', async () => {
            const plain = await passwordRealm('alice@example.com', PASSWORD, { scope: 'read:things' });
            expect(plain.status).toBe(200);
            expect(Object.keys(plain.body).sort()).toEqual(['access_token', 'expires_in', 'scope', 'token_type']);
            expect(decodeJwt(plain.body.access_token).aud).toBe(API_AUDIENCE);

            const openid = await passwordRealm('alice@example.com', PASSWORD, { scope: 'openid read:things' });
            expect(openid.status).toBe(200);
            expect(Object.keys(openid.body).sort()).toEqual([
                'access_token',
                'expires_in',
                'id_token',
                'scope',
                'token_type',
            ]);
            expect(decodeJwt(openid.body.access_token).aud).toEqual([API_AUDIENCE, `${h.issuer}userinfo`]);
            const id = decodeJwt(openid.body.id_token);
            expect(id.sub).toBe('auth0|alice');
            expect(id.aud).toBe(t.clients.spa.client_id);
            for (const claim of ['name', 'given_name', 'family_name', 'nickname', 'email', 'email_verified']) {
                expect(id[claim]).toBeUndefined();
            }

            const profileOnly = await passwordRealm('alice@example.com', PASSWORD, { scope: 'openid profile' });
            const profile = decodeJwt(profileOnly.body.id_token);
            expect(profile).toMatchObject({ name: 'Alice Example', given_name: 'Alice', family_name: 'Example' });
            expect(profile.email).toBeUndefined();
            expect(profile.email_verified).toBeUndefined();
        });

        it('applies RBAC to the requested API scopes and permissions claim', async () => {
            const bob = await passwordRealm('bob@example.com', PASSWORD, { scope: 'read:things write:things' });
            expect(bob.status).toBe(200);
            expect(bob.body.scope).toBe('read:things');
            const bobClaims = decodeJwt(bob.body.access_token);
            expect(bobClaims.scope).toBe('read:things');
            expect(bobClaims.permissions).toEqual(['read:things']);

            const alice = await passwordRealm('alice@example.com', PASSWORD, {
                scope: 'read:things write:things admin:things',
            });
            expect(alice.body.scope).toBe('read:things write:things admin:things');
            expect([...decodeJwt(alice.body.access_token).permissions].sort()).toEqual([
                'admin:things',
                'read:things',
                'write:things',
            ]);
        });

        it('passes OIDC scopes through untouched', async () => {
            const res = await passwordRealm('bob@example.com', PASSWORD, {
                scope: 'openid profile email write:things read:things',
            });
            expect(res.status).toBe(200);
            expect(res.body.scope).toBe('openid profile email read:things');
        });

        it('supports the password grant against the tenant default directory', async () => {
            const res = await h.token({
                grant_type: 'password',
                client_id: t.clients.spa.client_id,
                username: 'bob@example.com',
                password: PASSWORD,
                audience: API_AUDIENCE,
                scope: 'openid read:things',
            });
            expect(res.status).toBe(200);
            expect(decodeJwt(res.body.access_token)).toMatchObject({
                gty: 'password',
                sub: 'auth0|bob',
                permissions: ['read:things'],
            });
            expect(decodeJwt(res.body.id_token).sub).toBe('auth0|bob');
        });

        it('records last_login, last_ip and logins_count', async () => {
            const before = await userOf(t.users.bob);
            const res = await tokenRequest(
                h,
                {
                    grant_type: PASSWORD_REALM,
                    client_id: t.clients.spa.client_id,
                    realm: REALM,
                    username: 'bob@example.com',
                    password: PASSWORD,
                    audience: API_AUDIENCE,
                    scope: 'read:things',
                },
                { 'x-forwarded-for': '203.0.113.7' }
            );
            expect(res.status).toBe(200);
            const after = await userOf(t.users.bob);
            expect(after.logins_count).toBe((before.logins_count ?? 0) + 1);
            expect(after.last_ip).toBe('203.0.113.7');
            expect(Date.now() - Date.parse(after.last_login)).toBeLessThan(5_000);
        });

        it('rejects a wrong password', async () => {
            const res = await passwordRealm('alice@example.com', 'nope');
            expect(res.status).toBe(403);
            expect(res.body).toEqual(WRONG_CREDENTIALS);
        });

        it('rejects an unknown user with the same error', async () => {
            const res = await passwordRealm('nobody@example.com', PASSWORD);
            expect(res.status).toBe(403);
            expect(res.body).toEqual(WRONG_CREDENTIALS);
        });

        it('rejects a blocked user', async () => {
            const blocked = await h.mgmt('PATCH', `/users/${encodeURIComponent(t.users.bob)}`, { blocked: true });
            expect(blocked.status).toBe(200);
            expect(blocked.body.blocked).toBe(true);
            try {
                const res = await passwordRealm('bob@example.com', PASSWORD);
                expect(res.status).toBe(403);
                expect(res.body).toEqual({ error: 'unauthorized', error_description: 'user is blocked' });
            } finally {
                await h.mgmt('PATCH', `/users/${encodeURIComponent(t.users.bob)}`, { blocked: false });
            }
            expect((await passwordRealm('bob@example.com', PASSWORD)).status).toBe(200);
        });

        it('rejects an unknown realm', async () => {
            const res = await passwordRealm('alice@example.com', PASSWORD, { realm: 'nope' });
            expect(res.status).toBe(403);
            expect(res.body).toEqual({ error: 'invalid_request', error_description: "Unknown realm 'nope'" });
        });

        it('rejects a client the connection is not enabled for', async () => {
            const created = await h.mgmt('POST', '/clients', {
                name: 'Unlisted App',
                app_type: 'spa',
                grant_types: [PASSWORD_REALM, 'password'],
            });
            expect(created.status).toBe(201);
            const res = await passwordRealm('alice@example.com', PASSWORD, { client_id: created.body.client_id });
            expect(res.status).toBe(403);
            expect(res.body).toEqual({
                error: 'unauthorized_client',
                error_description: 'The connection is not enabled for this client',
            });
        });

        it('requires username and password', async () => {
            const base = { grant_type: PASSWORD_REALM, client_id: t.clients.spa.client_id, realm: REALM };
            const noUsername = await h.token({ ...base, password: PASSWORD });
            expect(noUsername.status).toBe(400);
            expect(noUsername.body).toEqual({
                error: 'invalid_request',
                error_description: 'Missing required parameter: username',
            });
            const noPassword = await h.token({ ...base, username: 'alice@example.com' });
            expect(noPassword.status).toBe(400);
            expect(noPassword.body).toEqual({
                error: 'invalid_request',
                error_description: 'Missing required parameter: password',
            });
        });
    });

    describe('refresh_token', () => {
        it('rotates the refresh token and rejects the previous one', async () => {
            const login = await passwordRealm('alice@example.com', PASSWORD);
            const first = login.body.refresh_token as string;

            const res = await refresh(first);
            expect(res.status).toBe(200);
            expect(Object.keys(res.body).sort()).toEqual([
                'access_token',
                'expires_in',
                'id_token',
                'refresh_token',
                'scope',
                'token_type',
            ]);
            expect(res.body.refresh_token).not.toBe(first);
            expect(res.body).toMatchObject({ scope: ALL_SCOPES, expires_in: 900 });
            expect(decodeJwt(res.body.access_token)).toMatchObject({
                sub: 'auth0|alice',
                gty: 'refresh_token',
                aud: [API_AUDIENCE, `${h.issuer}userinfo`],
                scope: ALL_SCOPES,
            });
            expect(decodeJwt(res.body.id_token)).toMatchObject({ sub: 'auth0|alice', email: 'alice@example.com' });

            const reused = await refresh(first);
            expect(reused.status).toBe(403);
            expect(reused.body).toEqual(REFRESH_REJECTED);

            const next = await refresh(res.body.refresh_token);
            expect(next.status).toBe(200);
        });

        it('narrows the scope on request but never widens it', async () => {
            const login = await passwordRealm('alice@example.com', PASSWORD);
            const res = await refresh(login.body.refresh_token, { scope: 'openid read:things' });
            expect(res.status).toBe(200);
            expect(res.body.scope).toBe('openid read:things');
            expect(decodeJwt(res.body.access_token).scope).toBe('openid read:things');

            const wider = await refresh(res.body.refresh_token, { scope: 'openid read:things admin:things' });
            expect(wider.status).toBe(200);
            expect(wider.body.scope).toBe('openid read:things');
        });

        it('rejects a token issued to another client', async () => {
            const other = await h.mgmt('POST', '/clients', {
                name: 'Other SPA',
                app_type: 'spa',
                grant_types: ['authorization_code', 'refresh_token'],
            });
            expect(other.status).toBe(201);
            const login = await passwordRealm('alice@example.com', PASSWORD);
            const res = await refresh(login.body.refresh_token, { client_id: other.body.client_id });
            expect(res.status).toBe(403);
            expect(res.body).toEqual(REFRESH_REJECTED);
            expect((await refresh(login.body.refresh_token)).status).toBe(200);
        });

        it('returns the same token for a non-rotating client', async () => {
            const spa = `/clients/${t.clients.spa.client_id}`;
            const patched = await h.mgmt('PATCH', spa, {
                refresh_token: { rotation_type: 'non-rotating', expiration_type: 'expiring', token_lifetime: 43200 },
            });
            expect(patched.status).toBe(200);
            expect(patched.body.refresh_token.rotation_type).toBe('non-rotating');
            try {
                const login = await passwordRealm('alice@example.com', PASSWORD);
                const token = login.body.refresh_token as string;
                const first = await refresh(token);
                expect(first.status).toBe(200);
                expect(first.body.refresh_token).toBe(token);
                const second = await refresh(token);
                expect(second.status).toBe(200);
                expect(second.body.refresh_token).toBe(token);
            } finally {
                await h.mgmt('PATCH', spa, {
                    refresh_token: { rotation_type: 'rotating', expiration_type: 'expiring', token_lifetime: 43200 },
                });
            }
        });

        it('POST /oauth/revoke invalidates the token', async () => {
            const login = await passwordRealm('alice@example.com', PASSWORD);
            const revoked = await h.fetch('/oauth/revoke', {
                method: 'POST',
                headers: { 'content-type': 'application/json' },
                body: JSON.stringify({ client_id: t.clients.spa.client_id, token: login.body.refresh_token }),
            });
            expect(revoked.status).toBe(200);
            expect(await revoked.json()).toEqual({});
            const res = await refresh(login.body.refresh_token);
            expect(res.status).toBe(403);
            expect(res.body).toEqual(REFRESH_REJECTED);
        });

        it('rejects a refresh for a user blocked in the meantime', async () => {
            const login = await passwordRealm('bob@example.com', PASSWORD);
            expect(login.status).toBe(200);
            await h.mgmt('PATCH', `/users/${encodeURIComponent(t.users.bob)}`, { blocked: true });
            try {
                const res = await refresh(login.body.refresh_token);
                expect(res.status).toBe(403);
                expect(res.body).toEqual(REFRESH_REJECTED);
            } finally {
                await h.mgmt('PATCH', `/users/${encodeURIComponent(t.users.bob)}`, { blocked: false });
            }
        });
    });

    describe('GET /userinfo', () => {
        const userinfo = (token?: string) =>
            h.fetch('/userinfo', token ? { headers: { authorization: `Bearer ${token}` } } : {});

        it('returns the claims allowed by the token scopes', async () => {
            const login = await passwordRealm('alice@example.com', PASSWORD, {
                scope: 'openid profile email read:things',
            });
            const res = await userinfo(login.body.access_token);
            expect(res.status).toBe(200);
            expect(await res.json()).toEqual({
                sub: 'auth0|alice',
                name: 'Alice Example',
                given_name: 'Alice',
                family_name: 'Example',
                nickname: 'alice',
                picture: expect.stringContaining('https://s.gravatar.com/avatar/'),
                updated_at: expect.any(String),
                email: 'alice@example.com',
                email_verified: true,
            });

            const minimal = await passwordRealm('alice@example.com', PASSWORD, { scope: 'openid' });
            expect(await (await userinfo(minimal.body.access_token)).json()).toEqual({ sub: 'auth0|alice' });
        });

        it('rejects a token whose audience does not include userinfo', async () => {
            const login = await passwordRealm('alice@example.com', PASSWORD, { scope: 'read:things' });
            const res = await userinfo(login.body.access_token);
            expect(res.status).toBe(401);
            expect(await res.json()).toEqual({
                error: 'invalid_token',
                error_description: 'Token is not valid for userinfo',
            });
        });

        it('rejects requests without a bearer token', async () => {
            const res = await userinfo();
            expect(res.status).toBe(401);
            expect(await res.json()).toEqual({ error: 'invalid_token', error_description: 'Missing bearer token' });
        });

        it('rejects a token it did not sign', async () => {
            const res = await userinfo('eyJhbGciOiJSUzI1NiJ9.e30.invalid');
            expect(res.status).toBe(401);
            expect(await res.json()).toEqual({ error: 'invalid_token', error_description: 'Invalid or expired token' });
        });
    });
});

describe('POST /oauth/token with acceptAnyClientSecret', () => {
    let h: Harness;
    let t: Tenant;
    beforeAll(async () => {
        h = await startMock({ acceptAnyClientSecret: true });
        t = await provisionTenant(h);
    });
    afterAll(() => h.close());

    it('accepts any secret for a known client', async () => {
        const res = await h.token({
            grant_type: 'client_credentials',
            client_id: t.clients.backend.client_id,
            client_secret: 'definitely-not-the-secret',
            audience: API_AUDIENCE,
        });
        expect(res.status).toBe(200);
        expect(decodeJwt(res.body.access_token).sub).toBe(`${t.clients.backend.client_id}@clients`);
        const noSecret = await h.token({
            grant_type: 'client_credentials',
            client_id: t.clients.backend.client_id,
            audience: API_AUDIENCE,
        });
        expect(noSecret.status).toBe(200);
    });

    it('still rejects unknown clients', async () => {
        const res = await h.token({
            grant_type: 'client_credentials',
            client_id: 'y'.repeat(32),
            client_secret: 'whatever',
            audience: API_AUDIENCE,
        });
        expect(res.status).toBe(401);
        expect(res.body).toEqual(UNAUTHORIZED_CLIENT);
    });
});

describe('brute-force protection', () => {
    let h: Harness;
    let t: Tenant;
    beforeAll(async () => {
        h = await startMock();
        t = await provisionTenant(h);
        const patched = await h.mgmt('PATCH', '/attack-protection/brute-force-protection', { max_attempts: 3 });
        expect(patched.status).toBe(200);
        expect(patched.body).toMatchObject({
            enabled: true,
            max_attempts: 3,
            mode: 'count_per_identifier_and_ip',
            shields: ['block', 'user_notification'],
        });
    });
    afterAll(() => h.close());

    const attempt = (ip: string, password: string, username = 'bob@example.com') =>
        tokenRequest(
            h,
            {
                grant_type: PASSWORD_REALM,
                client_id: t.clients.spa.client_id,
                realm: REALM,
                username,
                password,
                audience: API_AUDIENCE,
                scope: 'read:things',
            },
            { 'x-forwarded-for': ip }
        );
    const TOO_MANY = { error: 'too_many_attempts', error_description: BRUTE_FORCE_MESSAGE };

    it('blocks the identifier/IP pair after max_attempts failures', async () => {
        for (let i = 0; i < 2; i++) {
            const res = await attempt('192.0.2.10', 'wrong');
            expect(res.status).toBe(403);
            expect(res.body).toEqual(WRONG_CREDENTIALS);
        }
        const third = await attempt('192.0.2.10', 'wrong');
        expect(third.status).toBe(429);
        expect(third.body).toEqual(TOO_MANY);

        const correct = await attempt('192.0.2.10', PASSWORD);
        expect(correct.status).toBe(429);
        expect(correct.body).toEqual(TOO_MANY);

        const user = await h.mgmt('GET', `/users/${encodeURIComponent(t.users.bob)}`);
        expect(user.body.blocked_for).toEqual([{ identifier: 'bob@example.com', ip: '192.0.2.10', connection: REALM }]);
        expect(user.body.blocked).toBeUndefined();
        const blocks = await h.mgmt('GET', `/user-blocks/${encodeURIComponent(t.users.bob)}`);
        expect(blocks.body.blocked_for).toHaveLength(1);
    });

    it('counts attempts from another IP separately', async () => {
        const ok = await attempt('192.0.2.11', PASSWORD);
        expect(ok.status).toBe(200);
        for (let i = 0; i < 2; i++) {
            const res = await attempt('192.0.2.11', 'wrong');
            expect(res.status).toBe(403);
            expect(res.body).toEqual(WRONG_CREDENTIALS);
        }
        // Still blocked from the original address.
        expect((await attempt('192.0.2.10', PASSWORD)).status).toBe(429);
    });

    it('DELETE /api/v2/user-blocks/:id lifts the block', async () => {
        const removed = await h.mgmt('DELETE', `/user-blocks/${encodeURIComponent(t.users.bob)}`);
        expect(removed.status).toBe(204);
        const user = await h.mgmt('GET', `/users/${encodeURIComponent(t.users.bob)}`);
        expect(user.body.blocked_for).toBeUndefined();
        const res = await attempt('192.0.2.10', PASSWORD);
        expect(res.status).toBe(200);
    });

    it('resets the failure counter after a successful login', async () => {
        expect((await attempt('192.0.2.12', 'wrong')).status).toBe(403);
        expect((await attempt('192.0.2.12', 'wrong')).status).toBe(403);
        expect((await attempt('192.0.2.12', PASSWORD)).status).toBe(200);
        expect((await attempt('192.0.2.12', 'wrong')).status).toBe(403);
        expect((await attempt('192.0.2.12', 'wrong')).status).toBe(403);
        expect((await attempt('192.0.2.12', PASSWORD)).status).toBe(200);
        const blocked = await attempt('192.0.2.12', 'wrong');
        expect(blocked.status).toBe(403);
        expect(blocked.body).toEqual(WRONG_CREDENTIALS);
    });

    it('never blocks while protection is disabled', async () => {
        const disabled = await h.mgmt('PATCH', '/attack-protection/brute-force-protection', { enabled: false });
        expect(disabled.status).toBe(200);
        expect(disabled.body.enabled).toBe(false);
        try {
            for (let i = 0; i < 5; i++) {
                const res = await attempt('192.0.2.13', 'wrong', 'alice@example.com');
                expect(res.status).toBe(403);
                expect(res.body).toEqual(WRONG_CREDENTIALS);
            }
            expect((await attempt('192.0.2.13', PASSWORD, 'alice@example.com')).status).toBe(200);
            const user = await h.mgmt('GET', `/users/${encodeURIComponent(t.users.alice)}`);
            expect(user.body.blocked_for).toBeUndefined();
        } finally {
            await h.mgmt('PATCH', '/attack-protection/brute-force-protection', { enabled: true });
        }
    });
});
