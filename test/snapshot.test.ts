import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Snapshot } from '../src/index.ts';
import { API_AUDIENCE, PASSWORD, decodeJwt, provisionTenant, startMock, type Harness, type Tenant } from './helpers.ts';

const PASSWORD_REALM = 'http://auth0.com/oauth/grant-type/password-realm';

describe('/__mock snapshot, reset and import', () => {
    let source: Harness;
    let target: Harness;
    let tenant: Tenant;
    let snapshot: Snapshot;

    beforeAll(async () => {
        source = await startMock();
        tenant = await provisionTenant(source);
        target = await startMock();
    });
    afterAll(async () => {
        await source.close();
        await target.close();
    });

    const loginAs = (h: Harness) =>
        h.token({
            grant_type: PASSWORD_REALM,
            realm: 'Username-Password-Authentication',
            client_id: tenant.clients.spa.client_id,
            username: 'alice@example.com',
            password: PASSWORD,
            audience: API_AUDIENCE,
            scope: 'openid read:things',
        });
    const health = async (h: Harness) => (await h.fetch('/__mock/health')).json() as Promise<Record<string, unknown>>;
    const postJson = (h: Harness, path: string, body: unknown) =>
        h.fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

    it('GET /__mock/snapshot exports the provisioned tenant', async () => {
        const res = await source.fetch('/__mock/snapshot');
        expect(res.status).toBe(200);
        snapshot = (await res.json()) as Snapshot;

        expect(snapshot.version).toBe(1);
        const users = snapshot.users ?? [];
        expect(users.map((u) => u.user_id).sort()).toEqual([tenant.users.alice, tenant.users.bob]);
        expect(users.every((u) => typeof u.password_hash === 'string')).toBe(true);
        expect((snapshot.clients ?? []).map((c) => c.client_id).sort()).toEqual(
            [tenant.clients.spa.client_id, tenant.clients.backend.client_id].sort()
        );
        expect(snapshot.connections).toEqual([
            expect.objectContaining({
                id: tenant.connection.id,
                name: 'Username-Password-Authentication',
                strategy: 'auth0',
            }),
        ]);
        const resourceServers = snapshot.resourceServers ?? [];
        expect(resourceServers.some((r) => r.identifier === API_AUDIENCE)).toBe(true);
        expect(resourceServers.some((r) => r.is_system === true && r.identifier === source.managementAudience)).toBe(
            true
        );
        expect((snapshot.roles ?? []).map((r) => r.name).sort()).toEqual(['Admin', 'Reader']);
        expect(snapshot.userRoles).toEqual({
            [tenant.users.alice]: [tenant.roles.admin],
            [tenant.users.bob]: [tenant.roles.reader],
        });
        expect(snapshot.rolePermissions?.[tenant.roles.reader]).toEqual([
            { permission_name: 'read:things', resource_server_identifier: API_AUDIENCE },
        ]);
        expect(snapshot.clientGrants).toHaveLength(2);
        expect(snapshot.tenant).toMatchObject({ default_directory: 'Username-Password-Authentication' });
        expect(snapshot.emailProvider).toBeNull();
        expect(snapshot.actions).toEqual([]);
        expect(snapshot.triggerBindings).toEqual({});
        // Runtime-only state is never exported.
        for (const key of ['sessions', 'refreshTokens', 'authCodes', 'transactions', 'tickets', 'userBlocks']) {
            expect(snapshot, key).not.toHaveProperty(key);
        }
    });

    it('the target instance starts empty', async () => {
        expect(await health(target)).toEqual({ status: 'ok', issuer: target.issuer, tls: 'off', users: 0 });
        expect(target.issuer).not.toBe(source.issuer);
        const refused = await loginAs(target);
        expect(refused.status).toBe(401);
        expect(refused.body).toEqual({ error: 'access_denied', error_description: 'Unauthorized' });
    });

    it('POST /__mock/snapshot restores the tenant and a password-realm login works', async () => {
        const res = await postJson(target, '/__mock/snapshot', snapshot);
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual({ status: 'ok' });
        expect((await health(target)).users).toBe(2);

        const sourceLogin = await loginAs(source);
        expect(sourceLogin.status).toBe(200);
        const targetLogin = await loginAs(target);
        expect(targetLogin.status).toBe(200);
        expect(targetLogin.body).toMatchObject({ token_type: 'Bearer', scope: 'openid read:things', expires_in: 900 });
        expect(targetLogin.body.id_token).toEqual(expect.any(String));

        const claims = decodeJwt(targetLogin.body.access_token);
        expect(claims.sub).toBe(tenant.users.alice);
        expect(claims.sub).toBe(decodeJwt(sourceLogin.body.access_token).sub);
        expect(claims.iss).toBe(target.issuer);
        expect(claims.aud).toEqual([API_AUDIENCE, `${target.issuer}userinfo`]);
        expect(claims.azp).toBe(tenant.clients.spa.client_id);
        expect(claims.scope).toBe('openid read:things');
        expect(claims.permissions).toEqual(['read:things', 'write:things', 'admin:things']);
        expect(decodeJwt(targetLogin.body.id_token).sub).toBe(tenant.users.alice);

        // The Management API sees the same users; the target keeps its own Management API resource server.
        const alice = await target.mgmt('GET', `/users/${encodeURIComponent(tenant.users.alice)}`);
        expect(alice.status).toBe(200);
        expect(alice.body).toMatchObject({ email: 'alice@example.com', name: 'Alice Example' });
        expect(alice.body).not.toHaveProperty('password_hash');
        expect((await target.mgmt('GET', `/users/${encodeURIComponent(tenant.users.alice)}/roles`)).body).toEqual([
            { id: tenant.roles.admin, name: 'Admin', description: 'Full access' },
        ]);
        const servers = await target.mgmt('GET', '/resource-servers');
        expect(
            servers.body.some(
                (r: { is_system?: boolean; identifier: string }) =>
                    r.is_system === true && r.identifier === target.managementAudience
            )
        ).toBe(true);
        expect((await target.mgmt('GET', `/resource-servers/${encodeURIComponent(API_AUDIENCE)}`)).status).toBe(200);
        expect((await target.mgmt('GET', `/clients/${tenant.clients.spa.client_id}`)).body.name).toBe('Example SPA');
        expect((await target.mgmt('GET', `/connections/${tenant.connection.id}`)).body.enabled_clients).toEqual(
            expect.arrayContaining([tenant.clients.spa.client_id, tenant.clients.backend.client_id])
        );
    });

    it('POST /__mock/snapshot rejects non-object bodies', async () => {
        const res = await postJson(target, '/__mock/snapshot', [1]);
        expect(res.status).toBe(400);
        expect(await res.json()).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: 'Expected a snapshot JSON object',
            errorCode: 'invalid_body',
        });
        expect((await health(target)).users).toBe(2);
    });

    it('POST /__mock/reset empties users and keeps the Management API resource server', async () => {
        const res = await target.fetch('/__mock/reset', { method: 'POST' });
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual({ status: 'ok' });
        expect((await health(target)).users).toBe(0);

        const servers = await target.mgmt('GET', '/resource-servers');
        expect(servers.status).toBe(200);
        expect(servers.body).toHaveLength(1);
        expect(servers.body[0]).toMatchObject({
            is_system: true,
            identifier: target.managementAudience,
            name: 'Auth0 Management API',
        });
        expect((await target.mgmt('GET', '/clients')).body).toEqual([]);
        expect((await target.mgmt('GET', '/connections')).body).toEqual([]);
        expect((await target.mgmt('GET', '/roles')).body).toEqual([]);
        expect((await target.mgmt('GET', '/tenants/settings')).body).not.toHaveProperty('default_directory');
        expect((await loginAs(target)).status).toBe(401);
        // The admin token keeps working after a reset.
        expect((await target.mgmt('GET', '/users')).body).toEqual([]);
    });

    it('mock.importSeed(snapshot) imports programmatically', async () => {
        target.mock.importSeed(snapshot);
        expect(target.mock.store.users.size).toBe(2);
        expect((await health(target)).users).toBe(2);

        const res = await loginAs(target);
        expect(res.status).toBe(200);
        expect(decodeJwt(res.body.access_token).sub).toBe(tenant.users.alice);
        expect((await target.mgmt('GET', `/users/${encodeURIComponent(tenant.users.bob)}/roles`)).body).toEqual([
            { id: tenant.roles.reader, name: 'Reader', description: 'Read only' },
        ]);

        // mock.reset() is the programmatic counterpart of POST /__mock/reset.
        target.mock.reset();
        expect(target.mock.store.users.size).toBe(0);
        expect(target.mock.store.resourceServers.size).toBe(1);
        expect((await health(target)).users).toBe(0);
    });

    it('GET /__mock/ca.pem returns 404 when tls is off', async () => {
        const res = await source.fetch('/__mock/ca.pem');
        expect(res.status).toBe(404);
        expect(await res.json()).toEqual({
            statusCode: 404,
            error: 'Not Found',
            message: 'No emulator-managed CA (tls is not "auto")',
            errorCode: 'inexistent_resource',
        });
        expect(source.mock.tls).toBeUndefined();
    });

    it('POST /__mock/users/:id/unblock clears blocks and 404s for unknown users', async () => {
        const ok = await source.fetch(`/__mock/users/${encodeURIComponent(tenant.users.alice)}/unblock`, {
            method: 'POST',
        });
        expect(ok.status).toBe(200);
        expect(await ok.json()).toEqual({ status: 'ok' });
        const missing = await source.fetch('/__mock/users/auth0%7Cnope/unblock', { method: 'POST' });
        expect(missing.status).toBe(404);
        expect(await missing.json()).toMatchObject({ statusCode: 404, message: 'The user does not exist' });
    });
});
