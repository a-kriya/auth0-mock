import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
    ADMIN_TOKEN,
    API_AUDIENCE,
    decodeJwt,
    provisionTenant,
    startMock,
    type Harness,
    type Tenant,
} from './helpers.ts';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

describe('Management API authentication', () => {
    let h: Harness;
    let tenant: Tenant;
    beforeAll(async () => {
        h = await startMock();
        tenant = await provisionTenant(h);
    });
    afterAll(() => h.close());

    const managementToken = async (scope?: string) => {
        const res = await h.token({
            grant_type: 'client_credentials',
            client_id: tenant.clients.backend.client_id,
            client_secret: tenant.clients.backend.client_secret,
            audience: h.managementAudience,
            ...(scope ? { scope } : {}),
        });
        expect(res.status).toBe(200);
        return res.body.access_token as string;
    };

    it('rejects requests without a bearer token', async () => {
        const res = await h.mgmt('GET', '/users', undefined, null);
        expect(res.status).toBe(401);
        expect(res.body).toEqual({ statusCode: 401, error: 'Unauthorized', message: 'Missing authentication' });
    });

    it('rejects non-bearer authorization schemes', async () => {
        const res = await h.fetch('/api/v2/users', { headers: { authorization: 'Basic abc' } });
        expect(res.status).toBe(401);
        expect(await res.json()).toEqual({ statusCode: 401, error: 'Unauthorized', message: 'Missing authentication' });
    });

    it('rejects garbage tokens', async () => {
        const res = await h.mgmt('GET', '/users', undefined, 'not-a-jwt');
        expect(res.status).toBe(401);
        expect(res.body).toEqual({ statusCode: 401, error: 'Unauthorized', message: 'Invalid token' });
    });

    it('rejects a token minted for another audience', async () => {
        const token = await h.token({
            grant_type: 'client_credentials',
            client_id: tenant.clients.backend.client_id,
            client_secret: tenant.clients.backend.client_secret,
            audience: API_AUDIENCE,
        });
        expect(token.status).toBe(200);
        const res = await h.mgmt('GET', '/users', undefined, token.body.access_token);
        expect(res.status).toBe(401);
        expect(res.body.message).toBe('Invalid token');
    });

    it('accepts a client_credentials token for the Management API within its granted scopes', async () => {
        const token = await managementToken();
        const claims = decodeJwt(token);
        expect(claims.aud).toBe(h.managementAudience);
        expect(claims.iss).toBe(h.issuer);
        expect(claims.sub).toBe(`${tenant.clients.backend.client_id}@clients`);
        expect(claims.gty).toBe('client-credentials');
        expect(String(claims.scope).split(' ').sort()).toEqual([
            'create:users',
            'read:roles',
            'read:users',
            'update:users',
        ]);

        const users = await h.mgmt('GET', '/users', undefined, token);
        expect(users.status).toBe(200);
        expect(users.body).toHaveLength(2);
        expect((await h.mgmt('GET', '/roles', undefined, token)).status).toBe(200);
        expect(
            (await h.mgmt('GET', `/users/${encodeURIComponent(tenant.users.alice)}/roles`, undefined, token)).status
        ).toBe(200);
    });

    it('returns 403 insufficient_scope outside the granted scopes', async () => {
        const token = await managementToken();
        const clients = await h.mgmt('GET', '/clients', undefined, token);
        expect(clients.status).toBe(403);
        expect(clients.body).toEqual({
            statusCode: 403,
            error: 'Forbidden',
            message: 'Insufficient scope, expected any of: read:clients',
            errorCode: 'insufficient_scope',
        });
        const del = await h.mgmt('DELETE', `/users/${encodeURIComponent(tenant.users.bob)}`, undefined, token);
        expect(del.status).toBe(403);
        expect(del.body.message).toBe('Insufficient scope, expected any of: delete:users');
        expect((await h.mgmt('GET', `/users/${encodeURIComponent(tenant.users.bob)}`)).status).toBe(200);
    });

    it('honours a narrower requested scope', async () => {
        const token = await managementToken('read:users');
        expect(decodeJwt(token).scope).toBe('read:users');
        expect((await h.mgmt('GET', '/users', undefined, token)).status).toBe(200);
        expect((await h.mgmt('GET', '/roles', undefined, token)).status).toBe(403);
    });

    it('the admin token passes every scope check', async () => {
        for (const path of [
            '/users',
            '/clients',
            '/client-grants',
            '/connections',
            '/resource-servers',
            '/roles',
            '/tenants/settings',
            '/branding',
            '/prompts',
            '/actions/actions',
            '/actions/triggers',
            '/attack-protection/brute-force-protection',
        ]) {
            const res = await h.mgmt('GET', path, undefined, ADMIN_TOKEN);
            expect(res.status, path).toBe(200);
        }
    });

    it('returns the Management error envelope for unknown routes and invalid JSON', async () => {
        const unknown = await h.mgmt('GET', '/does-not-exist');
        expect(unknown.status).toBe(404);
        expect(unknown.body).toEqual({ statusCode: 404, error: 'Not Found', message: 'Not Found' });

        const invalid = await h.fetch('/api/v2/roles', {
            method: 'POST',
            headers: { authorization: `Bearer ${ADMIN_TOKEN}`, 'content-type': 'application/json' },
            body: '{bad json',
        });
        expect(invalid.status).toBe(400);
        expect(await invalid.json()).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: 'Invalid JSON body',
            errorCode: 'invalid_body',
        });
    });
});

describe('Tenant settings', () => {
    let h: Harness;
    beforeAll(async () => {
        h = await startMock();
    });
    afterAll(() => h.close());

    it('GET returns the default settings', async () => {
        const res = await h.mgmt('GET', '/tenants/settings');
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({
            friendly_name: 'auth0-mock',
            enabled_locales: ['en'],
            flags: {},
            sandbox_version: '22',
            default_audience: '',
            session_lifetime: 168,
            idle_session_lifetime: 72,
            session_cookie: { mode: 'persistent' },
            allowed_logout_urls: [],
        });
        expect(res.body).not.toHaveProperty('default_directory');
    });

    it('PATCH merges nested objects instead of replacing them', async () => {
        const first = await h.mgmt('PATCH', '/tenants/settings', {
            flags: { enable_client_connections: true },
            friendly_name: 'Acme',
        });
        expect(first.status).toBe(200);
        expect(first.body.flags).toEqual({ enable_client_connections: true });
        expect(first.body.friendly_name).toBe('Acme');

        const second = await h.mgmt('PATCH', '/tenants/settings', {
            flags: { disable_clickjack_protection_headers: false },
        });
        expect(second.body.flags).toEqual({
            enable_client_connections: true,
            disable_clickjack_protection_headers: false,
        });

        const third = await h.mgmt('PATCH', '/tenants/settings', {
            flags: { enable_client_connections: null },
            session_cookie: { mode: 'non-persistent' },
        });
        expect(third.body.flags).toEqual({ disable_clickjack_protection_headers: false });
        expect(third.body.session_cookie).toEqual({ mode: 'non-persistent' });

        // Scalars and arrays are replaced, new keys are added.
        const fourth = await h.mgmt('PATCH', '/tenants/settings', {
            enabled_locales: ['en', 'de'],
            default_directory: 'Username-Password-Authentication',
            session_lifetime: 24,
        });
        expect(fourth.body).toMatchObject({
            enabled_locales: ['en', 'de'],
            default_directory: 'Username-Password-Authentication',
            session_lifetime: 24,
        });

        const get = await h.mgmt('GET', '/tenants/settings');
        expect(get.body).toEqual(fourth.body);
        expect(get.body).toMatchObject({
            friendly_name: 'Acme',
            flags: { disable_clickjack_protection_headers: false },
            session_cookie: { mode: 'non-persistent' },
        });
    });

    it('PATCH rejects a non-object body', async () => {
        const res = await h.mgmt('PATCH', '/tenants/settings', [1]);
        expect(res.status).toBe(400);
        expect(res.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: 'Payload validation error: expected a JSON object body',
            errorCode: 'invalid_body',
        });
    });

    it('supports fields / include_fields filtering', async () => {
        const only = await h.mgmt('GET', '/tenants/settings?fields=friendly_name,flags');
        expect(Object.keys(only.body).sort()).toEqual(['flags', 'friendly_name']);
        const without = await h.mgmt('GET', '/tenants/settings?fields=friendly_name,flags&include_fields=false');
        expect(without.body).not.toHaveProperty('friendly_name');
        expect(without.body).not.toHaveProperty('flags');
        expect(without.body).toHaveProperty('session_lifetime');
        const spaced = await h.mgmt('GET', '/tenants/settings?fields=friendly_name,%20enabled_locales');
        expect(Object.keys(spaced.body).sort()).toEqual(['enabled_locales', 'friendly_name']);
    });
});

describe('Resource servers', () => {
    let h: Harness;
    let ordersId: string;
    let shortId: string;
    let longId: string;
    beforeAll(async () => {
        h = await startMock();
    });
    afterAll(() => h.close());

    it('POST applies defaults and normalises scopes', async () => {
        const res = await h.mgmt('POST', '/resource-servers', {
            name: 'Orders API',
            identifier: 'https://orders.example.com',
            scopes: [
                { value: 'read:orders', description: 'Read orders' },
                { value: 'write:orders', extra: 'dropped' },
            ],
        });
        expect(res.status).toBe(201);
        expect(res.body).toEqual({
            id: expect.stringMatching(/^[0-9a-f]{24}$/),
            name: 'Orders API',
            identifier: 'https://orders.example.com',
            is_system: false,
            scopes: [{ value: 'read:orders', description: 'Read orders' }, { value: 'write:orders' }],
            signing_alg: 'RS256',
            allow_offline_access: false,
            skip_consent_for_verifiable_first_party_clients: false,
            token_lifetime: 86400,
            token_lifetime_for_web: 7200,
            enforce_policies: false,
            token_dialect: 'access_token',
        });
        ordersId = res.body.id;
    });

    it('token_lifetime_for_web is min(token_lifetime, 7200); provided fields override defaults', async () => {
        const short = await h.mgmt('POST', '/resource-servers', {
            identifier: 'https://short.example.com',
            token_lifetime: 900,
            enforce_policies: true,
            token_dialect: 'access_token_authz',
            allow_offline_access: true,
            signing_alg: 'HS256',
        });
        expect(short.status).toBe(201);
        expect(short.body).toMatchObject({
            name: 'https://short.example.com',
            token_lifetime: 900,
            token_lifetime_for_web: 900,
            enforce_policies: true,
            token_dialect: 'access_token_authz',
            allow_offline_access: true,
            signing_alg: 'HS256',
            scopes: [],
        });
        shortId = short.body.id;

        const long = await h.mgmt('POST', '/resource-servers', {
            identifier: 'https://long.example.com',
            token_lifetime: 100000,
        });
        expect(long.body).toMatchObject({ token_lifetime: 100000, token_lifetime_for_web: 7200 });
        longId = long.body.id;
    });

    it('POST validates the payload', async () => {
        const missing = await h.mgmt('POST', '/resource-servers', { name: 'x' });
        expect(missing.status).toBe(400);
        expect(missing.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Payload validation error: 'identifier' is required and must be a non-empty string",
            errorCode: 'invalid_body',
        });
        const badScopes = await h.mgmt('POST', '/resource-servers', {
            identifier: 'https://bad.example.com',
            scopes: 'read',
        });
        expect(badScopes.status).toBe(400);
        expect(badScopes.body.message).toBe("Payload validation error: 'scopes' must be an array");
        const badScope = await h.mgmt('POST', '/resource-servers', {
            identifier: 'https://bad.example.com',
            scopes: [{ description: 'no value' }],
        });
        expect(badScope.status).toBe(400);
        expect(badScope.body.message).toBe("Payload validation error: every scope requires a non-empty 'value'");
        expect((await h.mgmt('GET', `/resource-servers/${encodeURIComponent('https://bad.example.com')}`)).status).toBe(
            404
        );
    });

    it('rejects a duplicate identifier with 409', async () => {
        const res = await h.mgmt('POST', '/resource-servers', { identifier: 'https://orders.example.com' });
        expect(res.status).toBe(409);
        expect(res.body).toEqual({
            statusCode: 409,
            error: 'Conflict',
            message: 'A resource server with the same identifier already exists',
            errorCode: 'resource_server_conflict',
        });
    });

    it('GET by id and by URL-encoded identifier', async () => {
        const byId = await h.mgmt('GET', `/resource-servers/${ordersId}`);
        const byIdentifier = await h.mgmt(
            'GET',
            `/resource-servers/${encodeURIComponent('https://orders.example.com')}`
        );
        expect(byId.status).toBe(200);
        expect(byIdentifier.status).toBe(200);
        expect(byIdentifier.body).toEqual(byId.body);
        expect(byId.body.identifier).toBe('https://orders.example.com');

        const missing = await h.mgmt('GET', '/resource-servers/nope');
        expect(missing.status).toBe(404);
        expect(missing.body).toEqual({
            statusCode: 404,
            error: 'Not Found',
            message: 'The resource server does not exist',
            errorCode: 'inexistent_resource',
        });

        const fields = await h.mgmt('GET', `/resource-servers/${ordersId}?fields=name`);
        expect(fields.body).toEqual({ id: ordersId, identifier: 'https://orders.example.com', name: 'Orders API' });
    });

    it('PATCH replaces the scope list and rejects identifier changes', async () => {
        const patched = await h.mgmt('PATCH', `/resource-servers/${ordersId}`, {
            scopes: [{ value: 'admin:orders', description: 'Admin', extra: 'dropped' }],
            name: 'Orders API v2',
        });
        expect(patched.status).toBe(200);
        expect(patched.body.scopes).toEqual([{ value: 'admin:orders', description: 'Admin' }]);
        expect(patched.body.name).toBe('Orders API v2');
        expect(patched.body.id).toBe(ordersId);

        const sameIdentifier = await h.mgmt(
            'PATCH',
            `/resource-servers/${encodeURIComponent('https://orders.example.com')}`,
            { identifier: 'https://orders.example.com', token_lifetime: 3600 }
        );
        expect(sameIdentifier.status).toBe(200);
        expect(sameIdentifier.body.token_lifetime).toBe(3600);

        const changed = await h.mgmt('PATCH', `/resource-servers/${ordersId}`, {
            identifier: 'https://other.example.com',
        });
        expect(changed.status).toBe(400);
        expect(changed.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Payload validation error: 'identifier' cannot be changed",
            errorCode: 'invalid_body',
        });
        expect((await h.mgmt('GET', `/resource-servers/${ordersId}`)).body.identifier).toBe(
            'https://orders.example.com'
        );

        const cleared = await h.mgmt('PATCH', `/resource-servers/${ordersId}`, { scopes: null });
        expect(cleared.body.scopes).toEqual([]);
        const badScopes = await h.mgmt('PATCH', `/resource-servers/${ordersId}`, { scopes: [{ value: '' }] });
        expect(badScopes.status).toBe(400);

        expect((await h.mgmt('PATCH', '/resource-servers/nope', { name: 'x' })).status).toBe(404);
    });

    it('lists as a bare array or a totals envelope and filters by identifiers', async () => {
        const bare = await h.mgmt('GET', '/resource-servers');
        expect(bare.status).toBe(200);
        expect(Array.isArray(bare.body)).toBe(true);
        expect(bare.body).toHaveLength(4); // Management API + orders + short + long

        const totals = await h.mgmt('GET', '/resource-servers?include_totals=true&per_page=2&page=1');
        expect(totals.body).toEqual({ start: 2, limit: 2, length: 2, total: 4, resource_servers: expect.any(Array) });
        expect(totals.body.resource_servers).toHaveLength(2);

        const filtered = await h.mgmt(
            'GET',
            `/resource-servers?identifiers=${encodeURIComponent('https://orders.example.com')},${encodeURIComponent('https://short.example.com')}`
        );
        expect(filtered.body.map((r: { identifier: string }) => r.identifier).sort()).toEqual([
            'https://orders.example.com',
            'https://short.example.com',
        ]);

        const fields = await h.mgmt('GET', '/resource-servers?fields=name');
        for (const r of fields.body) expect(Object.keys(r).sort()).toEqual(['id', 'identifier', 'name']);
    });

    it('the Management API resource server is a system resource and cannot be deleted', async () => {
        const list = await h.mgmt('GET', '/resource-servers');
        const systems = list.body.filter((r: { is_system?: boolean }) => r.is_system === true);
        expect(systems).toHaveLength(1);
        const mgmt = systems[0];
        expect(mgmt).toMatchObject({
            name: 'Auth0 Management API',
            identifier: h.managementAudience,
            is_system: true,
            signing_alg: 'RS256',
            token_lifetime: 86400,
            token_lifetime_for_web: 7200,
            enforce_policies: false,
            token_dialect: 'access_token',
        });
        expect(mgmt.scopes).toEqual(
            expect.arrayContaining([
                { value: 'read:users', description: 'read:users' },
                { value: 'create:clients', description: 'create:clients' },
                { value: 'update:actions', description: 'update:actions' },
            ])
        );

        const del = await h.mgmt('DELETE', `/resource-servers/${mgmt.id}`);
        expect(del.status).toBe(400);
        expect(del.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: 'System resource servers cannot be deleted',
            errorCode: 'invalid_body',
        });
        const byIdentifier = await h.mgmt('DELETE', `/resource-servers/${encodeURIComponent(h.managementAudience)}`);
        expect(byIdentifier.status).toBe(400);
        expect((await h.mgmt('GET', `/resource-servers/${mgmt.id}`)).status).toBe(200);
    });

    it('DELETE removes a resource server (by id or identifier) and is idempotent', async () => {
        const del = await h.mgmt('DELETE', `/resource-servers/${longId}`);
        expect(del.status).toBe(204);
        expect(del.body).toBeUndefined();
        expect((await h.mgmt('GET', `/resource-servers/${longId}`)).status).toBe(404);
        expect((await h.mgmt('DELETE', `/resource-servers/${longId}`)).status).toBe(204);

        expect(
            (await h.mgmt('DELETE', `/resource-servers/${encodeURIComponent('https://short.example.com')}`)).status
        ).toBe(204);
        expect((await h.mgmt('GET', `/resource-servers/${shortId}`)).status).toBe(404);
        expect((await h.mgmt('GET', '/resource-servers')).body).toHaveLength(2);
    });
});

describe('Roles', () => {
    let h: Harness;
    let tenant: Tenant;
    let auditorId: string;
    let supportId: string;
    beforeAll(async () => {
        h = await startMock();
        tenant = await provisionTenant(h);
    });
    afterAll(() => h.close());

    const permission = (permission_name: string) => ({ permission_name, resource_server_identifier: API_AUDIENCE });

    it('POST returns 200 with a rol_ id and an empty description by default', async () => {
        const res = await h.mgmt('POST', '/roles', { name: 'Auditor' });
        expect(res.status).toBe(200);
        expect(res.body).toEqual({
            id: expect.stringMatching(/^rol_[A-Za-z0-9]{16}$/),
            name: 'Auditor',
            description: '',
        });
        auditorId = res.body.id;

        const described = await h.mgmt('POST', '/roles', { name: 'Support', description: 'Support staff' });
        expect(described.status).toBe(200);
        expect(described.body).toMatchObject({ name: 'Support', description: 'Support staff' });
        supportId = described.body.id;

        const missing = await h.mgmt('POST', '/roles', { description: 'x' });
        expect(missing.status).toBe(400);
        expect(missing.body.message).toBe(
            "Payload validation error: 'name' is required and must be a non-empty string"
        );
    });

    it('rejects a duplicate name with 409', async () => {
        const res = await h.mgmt('POST', '/roles', { name: 'Admin' });
        expect(res.status).toBe(409);
        expect(res.body).toEqual({
            statusCode: 409,
            error: 'Conflict',
            message: 'A role with the same name already exists',
            errorCode: 'role_conflict',
        });
    });

    it('GET / PATCH / DELETE a role', async () => {
        const created = (await h.mgmt('POST', '/roles', { name: 'Temp', description: 'temp' })).body;
        const got = await h.mgmt('GET', `/roles/${created.id}`);
        expect(got.status).toBe(200);
        expect(got.body).toEqual(created);

        const patched = await h.mgmt('PATCH', `/roles/${created.id}`, { name: 'Temporary', description: 'renamed' });
        expect(patched.status).toBe(200);
        expect(patched.body).toEqual({ id: created.id, name: 'Temporary', description: 'renamed' });
        const onlyDescription = await h.mgmt('PATCH', `/roles/${created.id}`, {
            description: 'again',
            id: 'rol_hijack',
        });
        expect(onlyDescription.body).toEqual({ id: created.id, name: 'Temporary', description: 'again' });

        const clash = await h.mgmt('PATCH', `/roles/${created.id}`, { name: 'Admin' });
        expect(clash.status).toBe(400);
        expect(clash.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: 'A role with the same name already exists',
            errorCode: 'role_conflict',
        });
        expect((await h.mgmt('PATCH', `/roles/${created.id}`, { name: 'Temporary' })).status).toBe(200);

        const del = await h.mgmt('DELETE', `/roles/${created.id}`);
        expect(del.status).toBe(204);
        const gone = await h.mgmt('GET', `/roles/${created.id}`);
        expect(gone.status).toBe(404);
        expect(gone.body).toEqual({
            statusCode: 404,
            error: 'Not Found',
            message: 'The role does not exist',
            errorCode: 'inexistent_resource',
        });
        expect((await h.mgmt('PATCH', `/roles/${created.id}`, { name: 'x' })).status).toBe(404);
        expect((await h.mgmt('DELETE', `/roles/${created.id}`)).status).toBe(204);
    });

    it('lists roles with name_filter and pagination', async () => {
        const all = await h.mgmt('GET', '/roles');
        expect(all.body.map((r: { name: string }) => r.name).sort()).toEqual(['Admin', 'Auditor', 'Reader', 'Support']);

        const filtered = await h.mgmt('GET', '/roles?name_filter=adm');
        expect(filtered.body.map((r: { name: string }) => r.name)).toEqual(['Admin']);
        const caseInsensitive = await h.mgmt('GET', '/roles?name_filter=READ');
        expect(caseInsensitive.body.map((r: { name: string }) => r.name)).toEqual(['Reader']);

        const totals = await h.mgmt('GET', '/roles?include_totals=true&per_page=2');
        expect(totals.body).toMatchObject({ start: 0, limit: 2, length: 2, total: 4 });
        expect(totals.body.roles).toHaveLength(2);
        const none = await h.mgmt('GET', '/roles?name_filter=zzz&include_totals=true');
        expect(none.body).toEqual({ start: 0, limit: 50, length: 0, total: 0, roles: [] });
    });

    it('POST /roles/:id/permissions returns 201 and validates against resource server scopes', async () => {
        const ok = await h.mgmt('POST', `/roles/${auditorId}/permissions`, {
            permissions: [permission('read:things'), permission('write:things')],
        });
        expect(ok.status).toBe(201);
        expect(ok.body).toEqual({});

        const unknownServer = await h.mgmt('POST', `/roles/${auditorId}/permissions`, {
            permissions: [{ permission_name: 'read:things', resource_server_identifier: 'https://nope.example.com' }],
        });
        expect(unknownServer.status).toBe(400);
        expect(unknownServer.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Resource server 'https://nope.example.com' does not exist",
            errorCode: 'invalid_body',
        });

        const unknownScope = await h.mgmt('POST', `/roles/${auditorId}/permissions`, {
            permissions: [permission('fly:things')],
        });
        expect(unknownScope.status).toBe(400);
        expect(unknownScope.body.message).toBe(
            `Permission 'fly:things' does not exist on resource server '${API_AUDIENCE}'`
        );

        const empty = await h.mgmt('POST', `/roles/${auditorId}/permissions`, { permissions: [] });
        expect(empty.status).toBe(400);
        expect(empty.body.message).toBe("Payload validation error: 'permissions' must be a non-empty array");
        const malformed = await h.mgmt('POST', `/roles/${auditorId}/permissions`, {
            permissions: [{ permission_name: 'read:things' }],
        });
        expect(malformed.status).toBe(400);
        expect(malformed.body.message).toBe(
            "Payload validation error: each permission requires 'permission_name' and 'resource_server_identifier'"
        );

        const unknownRole = await h.mgmt('POST', '/roles/rol_nope/permissions', {
            permissions: [permission('read:things')],
        });
        expect(unknownRole.status).toBe(404);
        expect(unknownRole.body.message).toBe('The role does not exist');

        // Re-adding an assigned permission is idempotent.
        expect(
            (await h.mgmt('POST', `/roles/${auditorId}/permissions`, { permissions: [permission('read:things')] }))
                .status
        ).toBe(201);
        expect((await h.mgmt('GET', `/roles/${auditorId}/permissions`)).body).toHaveLength(2);
    });

    it('GET /roles/:id/permissions describes every permission', async () => {
        const reader = await h.mgmt('GET', `/roles/${tenant.roles.reader}/permissions`);
        expect(reader.status).toBe(200);
        expect(reader.body).toEqual([
            {
                permission_name: 'read:things',
                description: 'Read things',
                resource_server_name: 'Example API',
                resource_server_identifier: API_AUDIENCE,
            },
        ]);

        const admin = await h.mgmt('GET', `/roles/${tenant.roles.admin}/permissions?include_totals=true`);
        expect(admin.body).toEqual({ start: 0, limit: 50, length: 3, total: 3, permissions: expect.any(Array) });
        expect(admin.body.permissions.map((p: { permission_name: string }) => p.permission_name)).toEqual([
            'read:things',
            'write:things',
            'admin:things',
        ]);
        for (const p of admin.body.permissions) {
            expect(Object.keys(p).sort()).toEqual([
                'description',
                'permission_name',
                'resource_server_identifier',
                'resource_server_name',
            ]);
        }

        expect((await h.mgmt('GET', `/roles/${supportId}/permissions`)).body).toEqual([]);
        expect((await h.mgmt('GET', '/roles/rol_nope/permissions')).status).toBe(404);
    });

    it('DELETE /roles/:id/permissions removes only the listed permissions', async () => {
        const res = await h.mgmt('DELETE', `/roles/${auditorId}/permissions`, {
            permissions: [permission('write:things'), permission('admin:things')],
        });
        expect(res.status).toBe(204);
        const list = await h.mgmt('GET', `/roles/${auditorId}/permissions`);
        expect(list.body.map((p: { permission_name: string }) => p.permission_name)).toEqual(['read:things']);
        expect((await h.mgmt('DELETE', `/roles/${auditorId}/permissions`, { permissions: [] })).status).toBe(400);
        expect(
            (await h.mgmt('DELETE', '/roles/rol_nope/permissions', { permissions: [permission('read:things')] })).status
        ).toBe(404);
    });

    it('GET/POST /roles/:id/users manage membership', async () => {
        const admins = await h.mgmt('GET', `/roles/${tenant.roles.admin}/users`);
        expect(admins.status).toBe(200);
        expect(admins.body).toEqual([
            {
                user_id: tenant.users.alice,
                email: 'alice@example.com',
                picture: expect.any(String),
                name: 'Alice Example',
            },
        ]);
        expect((await h.mgmt('GET', `/roles/${supportId}/users`)).body).toEqual([]);

        const add = await h.mgmt('POST', `/roles/${supportId}/users`, {
            users: [tenant.users.bob, tenant.users.alice],
        });
        expect(add.status).toBe(200);
        expect(add.body).toEqual({});
        const after = await h.mgmt('GET', `/roles/${supportId}/users?include_totals=true`);
        expect(after.body).toMatchObject({ start: 0, limit: 50, length: 2, total: 2 });
        expect(after.body.users.map((u: { user_id: string }) => u.user_id).sort()).toEqual(
            [tenant.users.alice, tenant.users.bob].sort()
        );
        expect(
            (await h.mgmt('GET', `/users/${encodeURIComponent(tenant.users.bob)}/roles`)).body.map(
                (r: { id: string }) => r.id
            )
        ).toEqual([tenant.roles.reader, supportId]);

        const unknownUser = await h.mgmt('POST', `/roles/${supportId}/users`, { users: ['auth0|nobody'] });
        expect(unknownUser.status).toBe(400);
        expect(unknownUser.body.message).toBe("User 'auth0|nobody' does not exist");
        const notArray = await h.mgmt('POST', `/roles/${supportId}/users`, { users: 'auth0|bob' });
        expect(notArray.status).toBe(400);
        expect(notArray.body.message).toBe("Payload validation error: 'users' must be an array of user ids");
        expect((await h.mgmt('GET', '/roles/rol_nope/users')).status).toBe(404);
        expect((await h.mgmt('POST', '/roles/rol_nope/users', { users: [tenant.users.bob] })).status).toBe(404);
    });

    it('deleting a role removes it from users and drops its permissions', async () => {
        const bob = encodeURIComponent(tenant.users.bob);
        const role = (await h.mgmt('POST', '/roles', { name: 'Ephemeral' })).body;
        expect(
            (await h.mgmt('POST', `/roles/${role.id}/permissions`, { permissions: [permission('admin:things')] }))
                .status
        ).toBe(201);
        expect((await h.mgmt('POST', `/users/${bob}/roles`, { roles: [role.id] })).status).toBe(204);

        const rolesBefore = await h.mgmt('GET', `/users/${bob}/roles`);
        expect(rolesBefore.body.map((r: { id: string }) => r.id)).toContain(role.id);
        const permissionsBefore = await h.mgmt('GET', `/users/${bob}/permissions`);
        expect(permissionsBefore.body.map((p: { permission_name: string }) => p.permission_name)).toEqual([
            'read:things',
            'admin:things',
        ]);

        expect((await h.mgmt('DELETE', `/roles/${role.id}`)).status).toBe(204);

        const rolesAfter = await h.mgmt('GET', `/users/${bob}/roles`);
        expect(rolesAfter.body.map((r: { id: string }) => r.id)).toEqual([tenant.roles.reader, supportId]);
        const permissionsAfter = await h.mgmt('GET', `/users/${bob}/permissions`);
        expect(permissionsAfter.body.map((p: { permission_name: string }) => p.permission_name)).toEqual([
            'read:things',
        ]);
        expect((await h.mgmt('GET', `/roles/${role.id}/permissions`)).status).toBe(404);
        expect((await h.mgmt('GET', '/roles')).body.map((r: { name: string }) => r.name)).not.toContain('Ephemeral');
    });
});

describe('Branding', () => {
    let h: Harness;
    beforeAll(async () => {
        h = await startMock();
    });
    afterAll(() => h.close());

    const theme = {
        displayName: 'Default theme',
        borders: {
            button_border_radius: 3,
            button_border_weight: 1,
            buttons_style: 'rounded',
            input_border_radius: 3,
            input_border_weight: 1,
            inputs_style: 'rounded',
            show_widget_shadow: true,
            widget_border_weight: 0,
            widget_corner_radius: 5,
        },
        colors: { primary_button: '#0059d6', primary_button_label: '#ffffff' },
        fonts: { font_url: '', title: { bold: false, size: 150 } },
        page_background: { background_color: '#000000', page_layout: 'center' },
        widget: {
            header_text_alignment: 'center',
            logo_height: 52,
            logo_position: 'center',
            logo_url: '',
            social_buttons_layout: 'bottom',
        },
    };

    it('GET /branding returns defaults and PATCH merges nested objects', async () => {
        const res = await h.mgmt('GET', '/branding');
        expect(res.status).toBe(200);
        expect(res.body).toEqual({
            colors: { primary: '#0059d6', page_background: '#000000' },
            favicon_url: 'https://cdn.auth0.com/website/new-homepage/dark-favicon.png',
            logo_url: 'https://cdn.auth0.com/manhattan/versions/1.5240.0/assets/badge.png',
            font: { url: '' },
        });

        const patched = await h.mgmt('PATCH', '/branding', {
            colors: { primary: '#ff0000' },
            logo_url: 'https://example.com/logo.png',
        });
        expect(patched.status).toBe(200);
        expect(patched.body).toEqual({
            colors: { primary: '#ff0000', page_background: '#000000' },
            favicon_url: 'https://cdn.auth0.com/website/new-homepage/dark-favicon.png',
            logo_url: 'https://example.com/logo.png',
            font: { url: '' },
        });
        expect((await h.mgmt('GET', '/branding')).body).toEqual(patched.body);
        expect((await h.mgmt('PATCH', '/branding', 'nope')).status).toBe(400);
    });

    it('POST /branding/themes requires every section', async () => {
        for (const section of ['borders', 'colors', 'fonts', 'page_background', 'widget']) {
            const partial: Record<string, unknown> = { ...theme };
            delete partial[section];
            const res = await h.mgmt('POST', '/branding/themes', partial);
            expect(res.status, section).toBe(400);
            expect(res.body).toEqual({
                statusCode: 400,
                error: 'Bad Request',
                message: `Payload validation error: '${section}' is required`,
                errorCode: 'invalid_body',
            });
        }
        const nullSection = await h.mgmt('POST', '/branding/themes', { ...theme, widget: null });
        expect(nullSection.status).toBe(400);
        expect((await h.mgmt('GET', '/branding/themes/default')).status).toBe(404);
    });

    it('creates, reads, patches and deletes the single tenant theme', async () => {
        const created = await h.mgmt('POST', '/branding/themes', { ...theme, themeId: 'ignored' });
        expect(created.status).toBe(201);
        expect(created.body).toEqual({ themeId: expect.stringMatching(UUID), ...theme });
        const id = created.body.themeId as string;

        const second = await h.mgmt('POST', '/branding/themes', theme);
        expect(second.status).toBe(400);
        expect(second.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: 'You have reached the maximum number of themes for this tenant',
            errorCode: 'themes_limit_reached',
        });

        expect((await h.mgmt('GET', '/branding/themes/default')).body).toEqual(created.body);
        expect((await h.mgmt('GET', `/branding/themes/${id}`)).body).toEqual(created.body);
        const missing = await h.mgmt('GET', '/branding/themes/nope');
        expect(missing.status).toBe(404);
        expect(missing.body.message).toBe('Theme not found');

        const patched = await h.mgmt('PATCH', `/branding/themes/${id}`, {
            displayName: 'Renamed',
            colors: { primary_button: '#00ff00' },
            themeId: 'nope',
        });
        expect(patched.status).toBe(200);
        expect(patched.body.themeId).toBe(id);
        expect(patched.body.displayName).toBe('Renamed');
        expect(patched.body.colors).toEqual({ primary_button: '#00ff00' });
        expect(patched.body.borders).toEqual(theme.borders);
        expect((await h.mgmt('GET', '/branding/themes/default')).body).toEqual(patched.body);
        expect((await h.mgmt('PATCH', '/branding/themes/nope', { displayName: 'x' })).status).toBe(404);

        expect((await h.mgmt('DELETE', `/branding/themes/${id}`)).status).toBe(204);
        const gone = await h.mgmt('GET', '/branding/themes/default');
        expect(gone.status).toBe(404);
        expect(gone.body).toEqual({
            statusCode: 404,
            error: 'Not Found',
            message: 'Theme not found',
            errorCode: 'theme_not_found',
        });
        expect((await h.mgmt('GET', `/branding/themes/${id}`)).status).toBe(404);
        expect((await h.mgmt('DELETE', `/branding/themes/${id}`)).status).toBe(204);
        expect((await h.mgmt('POST', '/branding/themes', theme)).status).toBe(201);
    });
});

describe('Email templates and provider', () => {
    let h: Harness;
    beforeAll(async () => {
        h = await startMock();
    });
    afterAll(() => h.close());

    it('POST creates a template (200) and validates the template name', async () => {
        const res = await h.mgmt('POST', '/email-templates', {
            template: 'verify_email',
            body: '<p>Verify</p>',
            from: 'no-reply@example.com',
            subject: 'Verify',
            syntax: 'liquid',
            enabled: true,
            resultUrl: 'https://app.example.com',
        });
        expect(res.status).toBe(200);
        expect(res.body).toEqual({
            template: 'verify_email',
            body: '<p>Verify</p>',
            from: 'no-reply@example.com',
            subject: 'Verify',
            syntax: 'liquid',
            enabled: true,
            resultUrl: 'https://app.example.com',
        });

        const unknown = await h.mgmt('POST', '/email-templates', { template: 'bogus', body: 'x' });
        expect(unknown.status).toBe(400);
        expect(unknown.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Unknown email template 'bogus'",
            errorCode: 'invalid_template',
        });
        const missing = await h.mgmt('POST', '/email-templates', { body: 'x' });
        expect(missing.status).toBe(400);
        expect(missing.body.message).toBe("Payload validation error: 'template' is required");
    });

    it('rejects a duplicate template with 400 email_template_conflict', async () => {
        const dup = await h.mgmt('POST', '/email-templates', { template: 'verify_email', body: 'y' });
        expect(dup.status).toBe(400);
        expect(dup.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "The email template 'verify_email' already exists",
            errorCode: 'email_template_conflict',
        });
    });

    it('defaults enabled and syntax', async () => {
        const res = await h.mgmt('POST', '/email-templates', { template: 'welcome_email', body: 'hi' });
        expect(res.status).toBe(200);
        expect(res.body).toEqual({ enabled: true, syntax: 'liquid', template: 'welcome_email', body: 'hi' });
        const disabled = await h.mgmt('POST', '/email-templates', { template: 'blocked_account', enabled: false });
        expect(disabled.body).toEqual({ enabled: false, syntax: 'liquid', template: 'blocked_account' });
    });

    it('GET returns the template, 404 when missing, 400 for unknown names', async () => {
        const got = await h.mgmt('GET', '/email-templates/verify_email');
        expect(got.status).toBe(200);
        expect(got.body).toMatchObject({ template: 'verify_email', subject: 'Verify' });
        const missing = await h.mgmt('GET', '/email-templates/reset_email');
        expect(missing.status).toBe(404);
        expect(missing.body).toEqual({
            statusCode: 404,
            error: 'Not Found',
            message: 'The email template does not exist',
            errorCode: 'inexistent_email_template',
        });
        const unknown = await h.mgmt('GET', '/email-templates/bogus');
        expect(unknown.status).toBe(400);
        expect(unknown.body.errorCode).toBe('invalid_template');
    });

    it('PUT replaces and PATCH merges', async () => {
        const put = await h.mgmt('PUT', '/email-templates/verify_email', {
            body: '<p>New</p>',
            subject: 'New subject',
            template: 'ignored-name',
        });
        expect(put.status).toBe(200);
        expect(put.body).toEqual({
            enabled: true,
            syntax: 'liquid',
            body: '<p>New</p>',
            subject: 'New subject',
            template: 'verify_email',
        });
        expect((await h.mgmt('GET', '/email-templates/verify_email')).body).toEqual(put.body);

        const patch = await h.mgmt('PATCH', '/email-templates/verify_email', {
            enabled: false,
            from: 'x@example.com',
            template: 'ignored-name',
        });
        expect(patch.status).toBe(200);
        expect(patch.body).toEqual({
            enabled: false,
            syntax: 'liquid',
            body: '<p>New</p>',
            subject: 'New subject',
            template: 'verify_email',
            from: 'x@example.com',
        });

        // PUT creates a missing template, PATCH does not.
        const created = await h.mgmt('PUT', '/email-templates/reset_email', { body: 'reset', syntax: 'html' });
        expect(created.status).toBe(200);
        expect(created.body).toEqual({ enabled: true, syntax: 'html', body: 'reset', template: 'reset_email' });
        const missing = await h.mgmt('PATCH', '/email-templates/stolen_credentials', { enabled: true });
        expect(missing.status).toBe(404);
        expect(missing.body.errorCode).toBe('inexistent_email_template');
        expect((await h.mgmt('PUT', '/email-templates/bogus', { body: 'x' })).status).toBe(400);
        expect((await h.mgmt('PATCH', '/email-templates/bogus', { body: 'x' })).status).toBe(400);
    });

    it('email provider: 404 when none, POST/GET hide credentials, DELETE → 204', async () => {
        const none = await h.mgmt('GET', '/emails/provider');
        expect(none.status).toBe(404);
        expect(none.body).toEqual({
            statusCode: 404,
            error: 'Not Found',
            message: 'There is no configured email provider',
            errorCode: 'inexistent_email_provider',
        });

        const noName = await h.mgmt('POST', '/emails/provider', { credentials: {} });
        expect(noName.status).toBe(400);
        expect(noName.body.message).toBe("Payload validation error: 'name' is required");

        const credentials = { smtp_host: 'smtp.example.com', smtp_port: 587, smtp_user: 'user', smtp_pass: 'p4ss' };
        const created = await h.mgmt('POST', '/emails/provider', {
            name: 'smtp',
            default_from_address: 'no-reply@example.com',
            credentials,
            settings: { headers: {} },
        });
        expect(created.status).toBe(201);
        expect(created.body).toEqual({
            enabled: true,
            name: 'smtp',
            default_from_address: 'no-reply@example.com',
            settings: { headers: {} },
        });
        expect(JSON.stringify(created.body)).not.toContain('p4ss');

        const duplicate = await h.mgmt('POST', '/emails/provider', { name: 'sendgrid' });
        expect(duplicate.status).toBe(400);
        expect(duplicate.body).toMatchObject({
            message: 'An email provider is already configured',
            errorCode: 'email_provider_conflict',
        });

        const got = await h.mgmt('GET', '/emails/provider');
        expect(got.status).toBe(200);
        expect(got.body).toEqual(created.body);
        expect(got.body).not.toHaveProperty('credentials');
        const withCredentials = await h.mgmt('GET', '/emails/provider?include_fields=true&fields=credentials,name');
        expect(withCredentials.body.credentials).toEqual(credentials);
        expect((await h.mgmt('GET', '/emails/provider?fields=credentials')).body).not.toHaveProperty('credentials');

        const patched = await h.mgmt('PATCH', '/emails/provider', {
            enabled: false,
            credentials: { smtp_pass: 'changed' },
        });
        expect(patched.status).toBe(200);
        expect(patched.body).toEqual({ ...created.body, enabled: false });
        expect(patched.body).not.toHaveProperty('credentials');
        expect(
            (await h.mgmt('GET', '/emails/provider?include_fields=true&fields=credentials')).body.credentials
        ).toEqual({
            ...credentials,
            smtp_pass: 'changed',
        });

        expect((await h.mgmt('DELETE', '/emails/provider')).status).toBe(204);
        expect((await h.mgmt('GET', '/emails/provider')).status).toBe(404);
        expect((await h.mgmt('PATCH', '/emails/provider', { enabled: true })).status).toBe(404);
        expect((await h.mgmt('DELETE', '/emails/provider')).status).toBe(204);
    });
});

describe('Attack protection and prompts', () => {
    let h: Harness;
    beforeAll(async () => {
        h = await startMock();
    });
    afterAll(() => h.close());

    it('brute-force-protection: GET defaults, PATCH merges', async () => {
        const get = await h.mgmt('GET', '/attack-protection/brute-force-protection');
        expect(get.status).toBe(200);
        expect(get.body).toEqual({
            enabled: true,
            shields: ['block', 'user_notification'],
            allowlist: [],
            mode: 'count_per_identifier_and_ip',
            max_attempts: 10,
        });
        const patched = await h.mgmt('PATCH', '/attack-protection/brute-force-protection', {
            max_attempts: 3,
            allowlist: ['10.0.0.1'],
        });
        expect(patched.status).toBe(200);
        expect(patched.body).toEqual({
            enabled: true,
            shields: ['block', 'user_notification'],
            allowlist: ['10.0.0.1'],
            mode: 'count_per_identifier_and_ip',
            max_attempts: 3,
        });
        expect((await h.mgmt('GET', '/attack-protection/brute-force-protection')).body).toEqual(patched.body);
        expect((await h.mgmt('PATCH', '/attack-protection/brute-force-protection', [1])).status).toBe(400);
    });

    it('suspicious-ip-throttling merges nested stage settings one level deep', async () => {
        const get = await h.mgmt('GET', '/attack-protection/suspicious-ip-throttling');
        expect(get.body).toEqual({
            enabled: true,
            shields: ['admin_notification', 'block'],
            allowlist: [],
            stage: {
                'pre-login': { max_attempts: 100, rate: 864000 },
                'pre-user-registration': { max_attempts: 50, rate: 1200 },
            },
        });
        const patched = await h.mgmt('PATCH', '/attack-protection/suspicious-ip-throttling', {
            shields: ['block'],
            stage: { 'pre-login': { max_attempts: 50, rate: 1000 } },
        });
        expect(patched.body).toEqual({
            enabled: true,
            shields: ['block'],
            allowlist: [],
            stage: {
                'pre-login': { max_attempts: 50, rate: 1000 },
                'pre-user-registration': { max_attempts: 50, rate: 1200 },
            },
        });
    });

    it('breached-password-detection', async () => {
        const get = await h.mgmt('GET', '/attack-protection/breached-password-detection');
        expect(get.body).toEqual({
            enabled: false,
            shields: [],
            admin_notification_frequency: [],
            method: 'standard',
            stage: { 'pre-user-registration': { shields: [] }, 'pre-change-password': { shields: [] } },
        });
        const patched = await h.mgmt('PATCH', '/attack-protection/breached-password-detection', {
            enabled: true,
            shields: ['block', 'admin_notification'],
            admin_notification_frequency: ['immediately'],
            stage: { 'pre-user-registration': { shields: ['block'] } },
        });
        expect(patched.body).toEqual({
            enabled: true,
            shields: ['block', 'admin_notification'],
            admin_notification_frequency: ['immediately'],
            method: 'standard',
            stage: { 'pre-user-registration': { shields: ['block'] }, 'pre-change-password': { shields: [] } },
        });
    });

    it('bot-detection merges the response object', async () => {
        const get = await h.mgmt('GET', '/attack-protection/bot-detection');
        expect(get.body).toEqual({
            bot_detection_level: 'low',
            allowlist: [],
            response: {
                policy: 'off',
                selected_captcha_provider: 'auth0_v2',
                password_reset_policy: 'off',
                passwordless_policy: 'off',
            },
            monitoring: { enabled: false },
        });
        const patched = await h.mgmt('PATCH', '/attack-protection/bot-detection', {
            bot_detection_level: 'high',
            response: { policy: 'high_risk' },
        });
        expect(patched.body).toEqual({
            bot_detection_level: 'high',
            allowlist: [],
            response: {
                policy: 'high_risk',
                selected_captcha_provider: 'auth0_v2',
                password_reset_policy: 'off',
                passwordless_policy: 'off',
            },
            monitoring: { enabled: false },
        });
    });

    it('captcha merges providers', async () => {
        const get = await h.mgmt('GET', '/attack-protection/captcha');
        expect(get.body).toEqual({ active_provider: 'auth0_v2', providers: {} });
        const first = await h.mgmt('PATCH', '/attack-protection/captcha', {
            active_provider: 'recaptcha_v2',
            providers: { recaptcha_v2: { site_key: 'site', secret: 'secret' } },
        });
        expect(first.body).toEqual({
            active_provider: 'recaptcha_v2',
            providers: { recaptcha_v2: { site_key: 'site', secret: 'secret' } },
        });
        const second = await h.mgmt('PATCH', '/attack-protection/captcha', {
            providers: { hcaptcha: { site_key: 'h', secret: 's' } },
        });
        expect(second.body).toEqual({
            active_provider: 'recaptcha_v2',
            providers: {
                recaptcha_v2: { site_key: 'site', secret: 'secret' },
                hcaptcha: { site_key: 'h', secret: 's' },
            },
        });
    });

    it('prompts GET/PATCH', async () => {
        const get = await h.mgmt('GET', '/prompts');
        expect(get.status).toBe(200);
        expect(get.body).toEqual({
            universal_login_experience: 'new',
            identifier_first: false,
            webauthn_platform_first_factor: false,
        });
        const patched = await h.mgmt('PATCH', '/prompts', { identifier_first: true });
        expect(patched.status).toBe(200);
        expect(patched.body).toEqual({
            universal_login_experience: 'new',
            identifier_first: true,
            webauthn_platform_first_factor: false,
        });
        expect((await h.mgmt('GET', '/prompts')).body).toEqual(patched.body);
        expect((await h.mgmt('PATCH', '/prompts', 'x')).status).toBe(400);
    });
});
