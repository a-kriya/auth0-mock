import { createHash } from 'node:crypto';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
    PASSWORD_REALM,
    REALM,
    REDIRECT_URI,
    authorize,
    browserLogin,
    pkce,
    sessionCookies,
    tokenRequest,
    type AuthorizeParams,
} from './auth-flows.ts';
import {
    API_AUDIENCE,
    PASSWORD,
    decodeJwt,
    deployPostLoginAction,
    provisionTenant,
    startMock,
    type Harness,
    type Tenant,
} from './helpers.ts';

const CLAIM = 'https://example.com/claims';
const BINDINGS = '/actions/triggers/post-login/bindings';

/** The customer action under test, uploaded verbatim. */
const ROLE_TYPE_ACTION = `const ManagementClient = require('auth0').ManagementClient;
function getUserTypeFromRole(role) { if (role.startsWith('Internal')) return 'internal'; if (role.startsWith('External')) return 'external'; }
exports.onExecutePostLogin = async (event, api) => {
  const mgmt = new ManagementClient({ domain: event.secrets.AUTH0_DOMAIN, clientId: event.secrets.AUTH0_CLIENT_ID, clientSecret: event.secrets.AUTH0_CLIENT_SECRET, audience: event.secrets.AUTH0_MGMT_AUDIENCE });
  const [{ data: userRoles }, { data: userPermissions }] = await Promise.all([mgmt.users.getRoles({ id: event.user.user_id }), mgmt.users.getPermissions({ id: event.user.user_id })]);
  if (!userRoles || userRoles.length === 0) return api.access.deny('User has no roles');
  const userType = getUserTypeFromRole(userRoles[0].name);
  api.user.setAppMetadata('type', userType);
  api.user.setAppMetadata('roles', userRoles);
  const { institutionIds } = event.user.app_metadata;
  api.accessToken.setCustomClaim('https://example.com/user', { institutionIds, userType });
  const permissions = userPermissions.map(({ permission_name }) => permission_name);
  if (event.client.name === 'Example SPA' && permissions.includes('read:things')) return;
  return api.access.deny('Unauthorized');
};
`;

describe('post-login Actions', () => {
    let h: Harness;
    let t: Tenant;
    let seq = 0;
    beforeAll(async () => {
        h = await startMock();
        t = await provisionTenant(h);
    });
    afterAll(() => h.close());
    beforeEach(async () => {
        const cleared = await h.mgmt('PATCH', BINDINGS, { bindings: [] });
        expect(cleared.status).toBe(200);
        expect(cleared.body.bindings).toEqual([]);
    });

    const name = (base: string) => `${base}-${++seq}`;
    const userOf = async (id: string) => (await h.mgmt('GET', `/users/${encodeURIComponent(id)}`)).body;
    const login = (username: string, extra: Record<string, unknown> = {}, headers: Record<string, string> = {}) =>
        tokenRequest(
            h,
            {
                grant_type: PASSWORD_REALM,
                client_id: t.clients.spa.client_id,
                realm: REALM,
                username,
                password: PASSWORD,
                audience: API_AUDIENCE,
                scope: 'openid read:things',
                ...extra,
            },
            headers
        );
    const codeParams = (extra: AuthorizeParams = {}): AuthorizeParams => ({
        client_id: t.clients.spa.client_id,
        redirect_uri: REDIRECT_URI,
        response_type: 'code',
        scope: 'openid read:things',
        audience: API_AUDIENCE,
        state: 'browser-state',
        ...extra,
    });
    const exchange = (code: string | null, extra: Record<string, unknown> = {}) =>
        h.token({
            grant_type: 'authorization_code',
            client_id: t.clients.spa.client_id,
            code,
            redirect_uri: REDIRECT_URI,
            ...extra,
        });
    const refresh = (token: string) =>
        h.token({ grant_type: 'refresh_token', client_id: t.clients.spa.client_id, refresh_token: token });
    const accessClaim = (body: Record<string, any>) => decodeJwt(body.access_token)[CLAIM];

    it('adds custom claims to the access and id tokens on every grant', async () => {
        await deployPostLoginAction(
            h,
            name('claims'),
            `exports.onExecutePostLogin = async (event, api) => {
  api.accessToken.setCustomClaim('${CLAIM}', { protocol: event.transaction.protocol, roles: event.authorization.roles });
  api.idToken.setCustomClaim('${CLAIM}/id', { protocol: event.transaction.protocol, user: event.user.user_id });
};`
        );

        const password = await login('alice@example.com', { scope: 'openid offline_access read:things' });
        expect(password.status).toBe(200);
        expect(accessClaim(password.body)).toEqual({ protocol: 'oauth2-password', roles: ['Admin'] });
        expect(decodeJwt(password.body.id_token)[`${CLAIM}/id`]).toEqual({
            protocol: 'oauth2-password',
            user: 'auth0|alice',
        });

        const refreshed = await refresh(password.body.refresh_token);
        expect(refreshed.status).toBe(200);
        expect(accessClaim(refreshed.body)).toEqual({ protocol: 'oauth2-refresh-token', roles: ['Admin'] });
        expect(decodeJwt(refreshed.body.id_token)[`${CLAIM}/id`]).toEqual({
            protocol: 'oauth2-refresh-token',
            user: 'auth0|alice',
        });

        const { verifier, challenge } = pkce();
        const browser = await browserLogin(
            h,
            codeParams({ code_challenge: challenge, code_challenge_method: 'S256' }),
            'alice@example.com',
            PASSWORD
        );
        expect(browser.response.status).toBe(302);
        expect(browser.code).not.toBeNull();
        // The claims travel with the code: unbinding before the exchange must not lose them.
        await h.mgmt('PATCH', BINDINGS, { bindings: [] });
        const exchanged = await exchange(browser.code, { code_verifier: verifier });
        expect(exchanged.status).toBe(200);
        expect(accessClaim(exchanged.body)).toEqual({ protocol: 'oidc-basic-profile', roles: ['Admin'] });
        expect(decodeJwt(exchanged.body.id_token)[`${CLAIM}/id`]).toEqual({
            protocol: 'oidc-basic-profile',
            user: 'auth0|alice',
        });
    });

    it('persists metadata written by actions and exposes it to later actions', async () => {
        await deployPostLoginAction(
            h,
            name('metadata-writer'),
            `exports.onExecutePostLogin = async (event, api) => {
  api.user.setAppMetadata('type', 'internal');
  api.user.setUserMetadata('theme', 'dark');
};`
        );
        await deployPostLoginAction(
            h,
            name('metadata-reader'),
            `exports.onExecutePostLogin = async (event, api) => {
  api.accessToken.setCustomClaim('${CLAIM}', {
    type: event.user.app_metadata.type,
    tenantIds: event.user.app_metadata.tenantIds,
    theme: event.user.user_metadata.theme,
  });
};`
        );
        const res = await login('alice@example.com');
        expect(res.status).toBe(200);
        expect(accessClaim(res.body)).toEqual({ type: 'internal', tenantIds: ['T1'], theme: 'dark' });
        const alice = await userOf(t.users.alice);
        expect(alice.app_metadata).toMatchObject({ tenantIds: ['T1'], type: 'internal' });
        expect(alice.user_metadata).toMatchObject({ theme: 'dark' });
    });

    it("answers Management API calls made through require('auth0')", async () => {
        await deployPostLoginAction(
            h,
            name('management'),
            `const { ManagementClient } = require('auth0');
exports.onExecutePostLogin = async (event, api) => {
  const mgmt = new ManagementClient({ domain: event.secrets.DOMAIN, clientId: 'id', clientSecret: 'secret' });
  const roles = await mgmt.users.getRoles({ id: event.user.user_id });
  const permissions = await mgmt.users.getPermissions({ id: event.user.user_id });
  api.accessToken.setCustomClaim('${CLAIM}', {
    rolesIsArray: Array.isArray(roles.data),
    roleIds: roles.data.map((r) => r.id),
    roles: roles.data.map((r) => r.name),
    permissions: permissions.data.map((p) => p.permission_name),
    resourceServers: permissions.data.map((p) => p.resource_server_identifier),
  });
};`,
            [{ name: 'DOMAIN', value: 'tenant.example.auth0.com' }]
        );
        const res = await login('bob@example.com');
        expect(res.status).toBe(200);
        expect(accessClaim(res.body)).toEqual({
            rolesIsArray: true,
            roleIds: [t.roles.reader],
            roles: ['Reader'],
            permissions: ['read:things'],
            resourceServers: [API_AUDIENCE],
        });
    });

    it('fails the login when an action requires a module that is not available', async () => {
        const inside = name('axios-inside');
        await deployPostLoginAction(
            h,
            inside,
            `exports.onExecutePostLogin = async (event, api) => {
  const axios = require('axios');
  await axios.get('https://example.com');
};`
        );
        const res = await login('alice@example.com');
        expect(res.status).toBe(403);
        expect(res.body.error).toBe('access_denied');
        expect(res.body.error_description).toContain(`Action '${inside}' failed`);
        expect(res.body.error_description).toContain("Module 'axios' is not available");

        await h.mgmt('PATCH', BINDINGS, { bindings: [] });
        const top = name('axios-top-level');
        await deployPostLoginAction(
            h,
            top,
            `const axios = require('axios');
exports.onExecutePostLogin = async (event, api) => {};`
        );
        const topLevel = await login('alice@example.com');
        expect(topLevel.status).toBe(403);
        expect(topLevel.body.error).toBe('access_denied');
        expect(topLevel.body.error_description).toContain(`Action '${top}' failed`);
        expect(topLevel.body.error_description).toContain("Module 'axios' is not available");
    });

    it('allows Node built-ins', async () => {
        await deployPostLoginAction(
            h,
            name('crypto'),
            `const crypto = require('crypto');
const { createHash } = require('node:crypto');
exports.onExecutePostLogin = async (event, api) => {
  api.accessToken.setCustomClaim('${CLAIM}', {
    sha: crypto.createHash('sha256').update(event.user.email).digest('hex'),
    prefixed: createHash('sha256').update(event.user.email).digest('hex'),
    uuid: typeof crypto.randomUUID(),
  });
};`
        );
        const res = await login('alice@example.com');
        expect(res.status).toBe(200);
        const sha = createHash('sha256').update('alice@example.com').digest('hex');
        expect(accessClaim(res.body)).toEqual({ sha, prefixed: sha, uuid: 'string' });
    });

    it('populates the event object', async () => {
        const erin = await h.mgmt('POST', '/users', {
            connection: REALM,
            email: 'erin@example.com',
            password: PASSWORD,
            app_metadata: { plan: 'gold' },
        });
        expect(erin.status).toBe(201);
        await h.mgmt('POST', `/users/${encodeURIComponent(erin.body.user_id)}/roles`, { roles: [t.roles.reader] });
        await deployPostLoginAction(
            h,
            name('event'),
            `exports.onExecutePostLogin = async (event, api) => {
  api.accessToken.setCustomClaim('${CLAIM}', {
    secrets: event.secrets,
    client: event.client.name,
    clientId: event.client.client_id,
    connection: event.connection.name,
    strategy: event.connection.strategy,
    appMetadata: event.user.app_metadata,
    userId: event.user.user_id,
    email: event.user.email,
    hasPasswordHash: 'password_hash' in event.user,
    roles: event.authorization.roles,
    ip: event.request.ip,
    scopes: event.transaction.requested_scopes,
    protocol: event.transaction.protocol,
    audience: event.resource_server.identifier,
    logins: event.stats.logins_count,
  });
};`,
            [
                { name: 'API_KEY', value: 'k-123' },
                { name: 'REGION', value: 'eu' },
            ]
        );
        const expected = {
            secrets: { API_KEY: 'k-123', REGION: 'eu' },
            client: 'Example SPA',
            clientId: t.clients.spa.client_id,
            connection: REALM,
            strategy: 'auth0',
            appMetadata: { plan: 'gold' },
            userId: erin.body.user_id,
            email: 'erin@example.com',
            hasPasswordHash: false,
            roles: ['Reader'],
            ip: '198.51.100.4',
            scopes: ['openid', 'read:things', 'write:things'],
            protocol: 'oauth2-password',
            audience: API_AUDIENCE,
        };
        const first = await login(
            'erin@example.com',
            { scope: 'openid read:things write:things' },
            { 'x-forwarded-for': '198.51.100.4' }
        );
        expect(first.status).toBe(200);
        expect(accessClaim(first.body)).toEqual({ ...expected, logins: 0 });
        const second = await login(
            'erin@example.com',
            { scope: 'openid read:things write:things' },
            { 'x-forwarded-for': '198.51.100.4' }
        );
        expect(accessClaim(second.body)).toEqual({ ...expected, logins: 1 });
    });

    it('api.access.deny rejects the login, keeps earlier metadata and stops later actions', async () => {
        await deployPostLoginAction(
            h,
            name('deny-bob'),
            `exports.onExecutePostLogin = async (event, api) => {
  if (event.user.user_id === '${t.users.bob}') {
    api.user.setAppMetadata('deniedAt', 'first-action');
    api.access.deny('User has no roles');
  }
};`
        );
        await deployPostLoginAction(
            h,
            name('after-deny'),
            `exports.onExecutePostLogin = async (event, api) => {
  api.user.setAppMetadata('secondRan', true);
  api.accessToken.setCustomClaim('${CLAIM}', 'second-ran');
};`
        );

        const loginsBefore = (await userOf(t.users.bob)).logins_count ?? 0;
        const denied = await login('bob@example.com');
        expect(denied.status).toBe(403);
        expect(denied.body).toEqual({ error: 'access_denied', error_description: 'User has no roles' });
        const bob = await userOf(t.users.bob);
        expect(bob.app_metadata).toEqual({ deniedAt: 'first-action' });
        // A denied login is not recorded as a login.
        expect(bob.logins_count ?? 0).toBe(loginsBefore);

        const allowed = await login('alice@example.com');
        expect(allowed.status).toBe(200);
        expect(accessClaim(allowed.body)).toBe('second-ran');
        expect((await userOf(t.users.alice)).app_metadata.secondRan).toBe(true);

        const browser = await browserLogin(h, codeParams({ state: 'deny-state' }), 'bob@example.com', PASSWORD);
        expect(browser.response.status).toBe(302);
        expect(browser.location.href).toBe(
            'http://localhost:3000/?error=access_denied&error_description=User+has+no+roles&state=deny-state'
        );
        expect(browser.code).toBeNull();
    });

    it('reports a thrown exception as a failed action', async () => {
        const boom = name('boom');
        await deployPostLoginAction(
            h,
            boom,
            `exports.onExecutePostLogin = async (event, api) => { throw new Error('kaboom'); };`
        );
        const res = await login('alice@example.com');
        expect(res.status).toBe(403);
        expect(res.body.error).toBe('access_denied');
        expect(res.body.error_description).toContain(`Action '${boom}' failed`);
        expect(res.body.error_description).toContain('kaboom');
    });

    it('api.validation.error uses the given error code', async () => {
        await deployPostLoginAction(
            h,
            name('validation'),
            `exports.onExecutePostLogin = async (event, api) => {
  api.validation.error('invalid_email_domain', 'Email domain not allowed');
};`
        );
        const res = await login('alice@example.com');
        expect(res.status).toBe(403);
        expect(res.body).toEqual({ error: 'invalid_email_domain', error_description: 'Email domain not allowed' });
    });

    it('api.session.revoke ends the browser session', async () => {
        await deployPostLoginAction(
            h,
            name('revoke-alice'),
            `exports.onExecutePostLogin = async (event, api) => {
  if (event.user.user_id === '${t.users.alice}') api.session.revoke('Session revoked by policy');
};`
        );
        const alice = await browserLogin(h, codeParams({ state: 'revoked' }), 'alice@example.com', PASSWORD);
        expect(alice.response.status).toBe(302);
        expect(alice.location.href).toBe(
            'http://localhost:3000/?error=access_denied&error_description=Session+revoked+by+policy&state=revoked'
        );
        expect(alice.sid).toMatch(/^[A-Za-z0-9_-]{32}$/);
        expect(sessionCookies(alice.response)).toEqual([alice.sid, '']);

        const silent = await authorize(h, codeParams({ prompt: 'none', state: 'after-revoke' }), alice.sid);
        expect(silent.status).toBe(302);
        expect(silent.headers.get('location')).toBe(
            'http://localhost:3000/?error=login_required&error_description=Login+required&state=after-revoke'
        );

        const bob = await browserLogin(h, codeParams(), 'bob@example.com', PASSWORD);
        expect(bob.code).toMatch(/^[A-Za-z0-9_-]{43}$/);
        const bobSilent = await authorize(h, codeParams({ prompt: 'none' }), bob.sid);
        expect(bobSilent.headers.get('location')).toMatch(/\?code=/);
    });

    it('api.session.revoke during a refresh tied to a session rejects the refresh', async () => {
        const browser = await browserLogin(
            h,
            codeParams({ scope: 'openid offline_access read:things' }),
            'alice@example.com',
            PASSWORD
        );
        const exchanged = await exchange(browser.code);
        expect(exchanged.status).toBe(200);
        expect(decodeJwt(exchanged.body.access_token).sid).toBe(browser.sid);
        const token = exchanged.body.refresh_token as string;
        expect(token).toMatch(/^v1\.M/);

        const before = await authorize(h, codeParams({ prompt: 'none' }), browser.sid);
        expect(before.headers.get('location')).toMatch(/\?code=/);

        await deployPostLoginAction(
            h,
            name('revoke-on-refresh'),
            `exports.onExecutePostLogin = async (event, api) => {
  if (event.transaction.protocol === 'oauth2-refresh-token' && event.session) api.session.revoke('Session revoked by policy');
};`
        );
        const denied = await refresh(token);
        expect(denied.status).toBe(403);
        expect(denied.body).toEqual({ error: 'access_denied', error_description: 'Session revoked by policy' });

        const after = await authorize(h, codeParams({ prompt: 'none', state: 'gone' }), browser.sid);
        expect(after.headers.get('location')).toBe(
            'http://localhost:3000/?error=login_required&error_description=Login+required&state=gone'
        );
        const again = await refresh(token);
        expect(again.status).toBe(403);
        expect(again.body).toEqual({ error: 'invalid_grant', error_description: 'Unknown or invalid refresh token.' });
    });

    it('runs only deployed and bound actions', async () => {
        const denyAll = `exports.onExecutePostLogin = async (event, api) => { api.access.deny('nope'); };`;
        const created = await h.mgmt('POST', '/actions/actions', {
            name: name('deny-all'),
            supported_triggers: [{ id: 'post-login', version: 'v3' }],
            code: denyAll,
            runtime: 'node22',
        });
        expect(created.status).toBe(201);
        expect(created.body.deployed_version).toBeUndefined();

        // Not deployed: cannot be bound, and does not run.
        const bindUndeployed = await h.mgmt('PATCH', BINDINGS, {
            bindings: [{ ref: { type: 'action_id', value: created.body.id } }],
        });
        expect(bindUndeployed.status).toBe(400);
        expect(bindUndeployed.body.errorCode).toBe('action_not_deployed');
        expect((await login('alice@example.com')).status).toBe(200);

        // Deployed but unbound: does not run.
        const deployed = await h.mgmt('POST', `/actions/actions/${created.body.id}/deploy`);
        expect(deployed.status).toBe(200);
        expect((await login('alice@example.com')).status).toBe(200);

        // Bound: runs.
        const bound = await h.mgmt('PATCH', BINDINGS, {
            bindings: [{ ref: { type: 'action_id', value: created.body.id } }],
        });
        expect(bound.status).toBe(200);
        const denied = await login('alice@example.com');
        expect(denied.status).toBe(403);
        expect(denied.body).toEqual({ error: 'access_denied', error_description: 'nope' });

        // Unbound again: stops running.
        expect((await h.mgmt('PATCH', BINDINGS, { bindings: [] })).status).toBe(200);
        expect((await login('alice@example.com')).status).toBe(200);
    });

    it('keeps running the deployed version until the new code is deployed', async () => {
        const version = (v: string) =>
            `exports.onExecutePostLogin = async (event, api) => { api.accessToken.setCustomClaim('${CLAIM}', '${v}'); };`;
        const action = await deployPostLoginAction(h, name('versioned'), version('v1'));
        expect(accessClaim((await login('alice@example.com')).body)).toBe('v1');

        const patched = await h.mgmt('PATCH', `/actions/actions/${action.id}`, { code: version('v2') });
        expect(patched.status).toBe(200);
        expect(patched.body.all_changes_deployed).toBe(false);
        expect(accessClaim((await login('alice@example.com')).body)).toBe('v1');

        const redeployed = await h.mgmt('POST', `/actions/actions/${action.id}/deploy`);
        expect(redeployed.status).toBe(200);
        expect(redeployed.body.number).toBe(2);
        expect(accessClaim((await login('alice@example.com')).body)).toBe('v2');
    });

    it('does not run for client_credentials', async () => {
        await deployPostLoginAction(
            h,
            name('deny-everything'),
            `exports.onExecutePostLogin = async (event, api) => { api.access.deny('nope'); };`
        );
        expect((await login('alice@example.com')).status).toBe(403);
        const res = await h.token({
            grant_type: 'client_credentials',
            client_id: t.clients.backend.client_id,
            client_secret: t.clients.backend.client_secret,
            audience: API_AUDIENCE,
        });
        expect(res.status).toBe(200);
        expect(decodeJwt(res.body.access_token)[CLAIM]).toBeUndefined();
    });

    it('runs the real-world role-based action', async () => {
        const role = await h.mgmt('POST', '/roles', {
            name: 'Internal - Administrator',
            description: 'Internal admins',
        });
        expect(role.status).toBe(200);
        expect(
            (
                await h.mgmt('POST', `/roles/${role.body.id}/permissions`, {
                    permissions: [{ permission_name: 'read:things', resource_server_identifier: API_AUDIENCE }],
                })
            ).status
        ).toBe(201);
        const internal = await h.mgmt('POST', '/users', {
            connection: REALM,
            email: 'internal@example.com',
            password: PASSWORD,
            app_metadata: { institutionIds: ['inst-1', 'inst-2'] },
        });
        expect(internal.status).toBe(201);
        expect(
            (
                await h.mgmt('POST', `/users/${encodeURIComponent(internal.body.user_id)}/roles`, {
                    roles: [role.body.id],
                })
            ).status
        ).toBe(204);
        const nobody = await h.mgmt('POST', '/users', {
            connection: REALM,
            email: 'nobody@example.com',
            password: PASSWORD,
        });
        expect(nobody.status).toBe(201);
        const otherApp = await h.mgmt('POST', '/clients', {
            name: 'Other App',
            app_type: 'spa',
            grant_types: [PASSWORD_REALM],
        });
        expect(otherApp.status).toBe(201);
        expect(
            (
                await h.mgmt('PATCH', `/connections/${t.connection.id}/clients`, [
                    { client_id: otherApp.body.client_id, status: true },
                ])
            ).status
        ).toBe(204);

        await deployPostLoginAction(h, name('role-types'), ROLE_TYPE_ACTION, [
            { name: 'AUTH0_DOMAIN', value: 'tenant.eu.auth0.com' },
            { name: 'AUTH0_CLIENT_ID', value: t.clients.backend.client_id },
            { name: 'AUTH0_CLIENT_SECRET', value: t.clients.backend.client_secret },
            { name: 'AUTH0_MGMT_AUDIENCE', value: h.managementAudience },
        ]);

        const res = await login('internal@example.com');
        expect(res.status).toBe(200);
        expect(res.body.scope).toBe('openid read:things');
        const claims = decodeJwt(res.body.access_token);
        expect(claims['https://example.com/user']).toEqual({
            institutionIds: ['inst-1', 'inst-2'],
            userType: 'internal',
        });
        expect(claims.permissions).toEqual(['read:things']);
        const user = await userOf(internal.body.user_id);
        expect(user.app_metadata).toEqual({
            institutionIds: ['inst-1', 'inst-2'],
            type: 'internal',
            roles: [{ id: role.body.id, name: 'Internal - Administrator', description: 'Internal admins' }],
        });
        expect(user.logins_count).toBe(1);

        const denied = await login('nobody@example.com');
        expect(denied.status).toBe(403);
        expect(denied.body).toEqual({ error: 'access_denied', error_description: 'User has no roles' });
        expect((await userOf(nobody.body.user_id)).app_metadata).toBeUndefined();

        const wrongApp = await login('internal@example.com', { client_id: otherApp.body.client_id });
        expect(wrongApp.status).toBe(403);
        expect(wrongApp.body).toEqual({ error: 'access_denied', error_description: 'Unauthorized' });
    });
});
