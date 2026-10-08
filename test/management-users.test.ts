import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { API_AUDIENCE, PASSWORD, provisionTenant, startMock, type Harness, type Tenant } from './helpers.ts';

const CONNECTION = 'Username-Password-Authentication';
const PASSWORD_REALM = 'http://auth0.com/oauth/grant-type/password-realm';
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const enc = encodeURIComponent;

describe('Users', () => {
    let h: Harness;
    let tenant: Tenant;
    let otherAlice: string;
    beforeAll(async () => {
        h = await startMock();
        tenant = await provisionTenant(h);
    });
    afterAll(() => h.close());

    const login = (username: string, password: string) =>
        h.token({
            grant_type: PASSWORD_REALM,
            realm: CONNECTION,
            client_id: tenant.clients.spa.client_id,
            username,
            password,
            scope: 'openid',
        });
    const ids = (users: Array<{ user_id: string }>) => users.map((u) => u.user_id);

    it('POST creates a database user with Auth0 defaults', async () => {
        const res = await h.mgmt('POST', '/users', {
            connection: CONNECTION,
            email: 'Carol.Danvers@Example.COM',
            password: PASSWORD,
        });
        expect(res.status).toBe(201);
        const user = res.body;
        expect(user.user_id).toMatch(/^auth0\|[0-9a-f]{24}$/);
        expect(user).toEqual({
            user_id: user.user_id,
            email: 'carol.danvers@example.com',
            email_verified: false,
            name: 'carol.danvers@example.com',
            nickname: 'carol.danvers',
            picture: expect.stringMatching(
                /^https:\/\/s\.gravatar\.com\/avatar\/[0-9a-f]{32}\?s=480&r=pg&d=https%3A%2F%2Fcdn\.auth0\.com%2Favatars%2Fca\.png$/
            ),
            identities: [
                {
                    connection: CONNECTION,
                    user_id: user.user_id.slice('auth0|'.length),
                    provider: 'auth0',
                    isSocial: false,
                },
            ],
            created_at: expect.stringMatching(ISO),
            updated_at: expect.stringMatching(ISO),
        });
        expect(user).not.toHaveProperty('password');
        expect(user).not.toHaveProperty('password_hash');
    });

    it('honours provided profile fields, metadata and user_id (bare or prefixed)', async () => {
        const res = await h.mgmt('POST', '/users', {
            connection: CONNECTION,
            user_id: 'carol',
            email: 'carol@example.com',
            password: PASSWORD,
            email_verified: true,
            name: 'Carol',
            nickname: 'cd',
            given_name: 'Carol',
            family_name: 'Danvers',
            picture: 'https://example.com/c.png',
            user_metadata: { theme: 'dark' },
            app_metadata: { type: 'internal' },
            blocked: false,
        });
        expect(res.status).toBe(201);
        expect(res.body).toMatchObject({
            user_id: 'auth0|carol',
            email: 'carol@example.com',
            email_verified: true,
            name: 'Carol',
            nickname: 'cd',
            given_name: 'Carol',
            family_name: 'Danvers',
            picture: 'https://example.com/c.png',
            user_metadata: { theme: 'dark' },
            app_metadata: { type: 'internal' },
            identities: [{ connection: CONNECTION, user_id: 'carol', provider: 'auth0', isSocial: false }],
        });
        expect(res.body).not.toHaveProperty('blocked');

        const prefixed = await h.mgmt('POST', '/users', {
            connection: CONNECTION,
            user_id: 'auth0|dave',
            email: 'dave@example.com',
            password: PASSWORD,
            blocked: true,
        });
        expect(prefixed.status).toBe(201);
        expect(prefixed.body.user_id).toBe('auth0|dave');
        expect(prefixed.body.identities[0].user_id).toBe('dave');
        expect(prefixed.body.blocked).toBe(true);

        const duplicateId = await h.mgmt('POST', '/users', {
            connection: CONNECTION,
            user_id: 'dave',
            email: 'dave2@example.com',
            password: PASSWORD,
        });
        expect(duplicateId.status).toBe(409);
        expect(duplicateId.body).toMatchObject({ message: 'The user already exists.', errorCode: 'auth0_idp_error' });
    });

    it('validates required fields and the connection', async () => {
        const noConnection = await h.mgmt('POST', '/users', { email: 'x@example.com', password: PASSWORD });
        expect(noConnection.status).toBe(400);
        expect(noConnection.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Payload validation error: 'connection' is required and must be a non-empty string",
            errorCode: 'invalid_body',
        });
        const noEmail = await h.mgmt('POST', '/users', { connection: CONNECTION, password: PASSWORD });
        expect(noEmail.status).toBe(400);
        expect(noEmail.body.message).toBe("Payload validation error: 'Missing required property: email'.");
        const noPassword = await h.mgmt('POST', '/users', { connection: CONNECTION, email: 'x@example.com' });
        expect(noPassword.status).toBe(400);
        expect(noPassword.body.message).toBe("Payload validation error: 'Missing required property: password'.");
        const unknown = await h.mgmt('POST', '/users', {
            connection: 'Nope',
            email: 'x@example.com',
            password: PASSWORD,
        });
        expect(unknown.status).toBe(400);
        expect(unknown.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: 'The connection does not exist.',
            errorCode: 'inexistent_connection',
        });
        expect((await h.mgmt('POST', '/users', [])).status).toBe(400);
        expect((await h.mgmt('GET', '/users')).body).toHaveLength(5);
    });

    it('rejects a duplicate email in the same connection with 409 auth0_idp_error', async () => {
        const res = await h.mgmt('POST', '/users', {
            connection: CONNECTION,
            email: 'ALICE@example.com',
            password: PASSWORD,
        });
        expect(res.status).toBe(409);
        expect(res.body).toEqual({
            statusCode: 409,
            error: 'Conflict',
            message: 'The user already exists.',
            errorCode: 'auth0_idp_error',
        });

        // The same email in another database connection is allowed.
        expect((await h.mgmt('POST', '/connections', { name: 'Other-DB', strategy: 'auth0' })).status).toBe(201);
        const other = await h.mgmt('POST', '/users', {
            connection: 'Other-DB',
            email: 'alice@example.com',
            password: PASSWORD,
        });
        expect(other.status).toBe(201);
        expect(other.body.identities[0].connection).toBe('Other-DB');
        expect(other.body.user_id).not.toBe(tenant.users.alice);
        otherAlice = other.body.user_id;
    });

    it('GET /users/:id', async () => {
        const res = await h.mgmt('GET', `/users/${enc(tenant.users.alice)}`);
        expect(res.status).toBe(200);
        expect(res.body).toMatchObject({
            user_id: 'auth0|alice',
            email: 'alice@example.com',
            email_verified: true,
            name: 'Alice Example',
            given_name: 'Alice',
            family_name: 'Example',
            app_metadata: { tenantIds: ['T1'] },
        });
        expect(res.body).not.toHaveProperty('password_hash');

        const fields = await h.mgmt('GET', `/users/${enc(tenant.users.alice)}?fields=email,name`);
        expect(fields.body).toEqual({ user_id: 'auth0|alice', email: 'alice@example.com', name: 'Alice Example' });
        const excluded = await h.mgmt(
            'GET',
            `/users/${enc(tenant.users.alice)}?fields=identities,picture&include_fields=false`
        );
        expect(excluded.body).not.toHaveProperty('identities');
        expect(excluded.body.user_id).toBe('auth0|alice');

        const missing = await h.mgmt('GET', '/users/auth0%7Cnope');
        expect(missing.status).toBe(404);
        expect(missing.body).toEqual({
            statusCode: 404,
            error: 'Not Found',
            message: 'The user does not exist.',
            errorCode: 'inexistent_resource',
        });
    });

    it('PATCH merges metadata one level deep (null deletes) and replaces other fields', async () => {
        const id = enc('auth0|carol');
        const first = await h.mgmt('PATCH', `/users/${id}`, {
            user_metadata: { lang: 'en' },
            app_metadata: { institutionIds: ['A'], nested: { a: 1 } },
            name: 'Carol D.',
        });
        expect(first.status).toBe(200);
        expect(first.body.user_metadata).toEqual({ theme: 'dark', lang: 'en' });
        expect(first.body.app_metadata).toEqual({ type: 'internal', institutionIds: ['A'], nested: { a: 1 } });
        expect(first.body.name).toBe('Carol D.');
        expect(first.body.updated_at >= first.body.created_at).toBe(true);

        const second = await h.mgmt('PATCH', `/users/${id}`, {
            user_metadata: { theme: null },
            app_metadata: { nested: { b: 2 }, institutionIds: null },
        });
        expect(second.body.user_metadata).toEqual({ lang: 'en' });
        // Nested objects inside metadata are replaced, not merged.
        expect(second.body.app_metadata).toEqual({ type: 'internal', nested: { b: 2 } });

        const cleared = await h.mgmt('PATCH', `/users/${id}`, { user_metadata: null });
        expect(cleared.body.user_metadata).toEqual({});
        expect(cleared.body.app_metadata).toEqual({ type: 'internal', nested: { b: 2 } });

        const ignored = await h.mgmt('PATCH', `/users/${id}`, {
            user_id: 'auth0|hijack',
            identities: [],
            created_at: '2000-01-01T00:00:00.000Z',
            logins_count: 99,
            password_hash: 'x',
            connection: 'Other-DB',
            given_name: 'Carol',
        });
        expect(ignored.status).toBe(200);
        expect(ignored.body.user_id).toBe('auth0|carol');
        expect(ignored.body.identities).toEqual([
            { connection: CONNECTION, user_id: 'carol', provider: 'auth0', isSocial: false },
        ]);
        expect(ignored.body.created_at).toBe(first.body.created_at);
        expect(ignored.body).not.toHaveProperty('logins_count');
        expect(ignored.body).not.toHaveProperty('password_hash');
        expect(ignored.body.given_name).toBe('Carol');
        expect((await h.mgmt('GET', '/users/auth0%7Chijack')).status).toBe(404);

        expect((await h.mgmt('PATCH', '/users/auth0%7Cnope', { name: 'x' })).status).toBe(404);
        expect((await h.mgmt('PATCH', `/users/${id}`, [])).status).toBe(400);
    });

    it('PATCH password sets last_password_reset and never echoes the password', async () => {
        const id = enc('auth0|carol');
        const newPassword = 'N3w-Passw0rd!N3w';
        const res = await h.mgmt('PATCH', `/users/${id}`, { password: newPassword });
        expect(res.status).toBe(200);
        expect(res.body.last_password_reset).toMatch(ISO);
        expect(res.body).not.toHaveProperty('password');
        expect(res.body).not.toHaveProperty('password_hash');
        expect(JSON.stringify(res.body)).not.toContain(newPassword);

        expect((await login('carol@example.com', newPassword)).status).toBe(200);
        const old = await login('carol@example.com', PASSWORD);
        expect(old.status).toBe(403);
        expect(old.body).toEqual({ error: 'invalid_grant', error_description: 'Wrong email or password.' });

        const bad = await h.mgmt('PATCH', `/users/${id}`, { password: 123 });
        expect(bad.status).toBe(400);
    });

    it('PATCH email lower-cases, resets email_verified unless provided, and rejects duplicates', async () => {
        const id = enc('auth0|carol');
        const res = await h.mgmt('PATCH', `/users/${id}`, { email: 'Carol.New@Example.com' });
        expect(res.status).toBe(200);
        expect(res.body.email).toBe('carol.new@example.com');
        expect(res.body.email_verified).toBe(false);

        const verified = await h.mgmt('PATCH', `/users/${id}`, {
            email: 'carol.verified@example.com',
            email_verified: true,
        });
        expect(verified.body).toMatchObject({ email: 'carol.verified@example.com', email_verified: true });
        const onlyFlag = await h.mgmt('PATCH', `/users/${id}`, { email_verified: false });
        expect(onlyFlag.body).toMatchObject({ email: 'carol.verified@example.com', email_verified: false });

        const duplicate = await h.mgmt('PATCH', `/users/${id}`, { email: 'alice@example.com' });
        expect(duplicate.status).toBe(409);
        expect(duplicate.body).toEqual({
            statusCode: 409,
            error: 'Conflict',
            message: 'The user already exists.',
            errorCode: 'auth0_idp_error',
        });
        expect((await h.mgmt('PATCH', `/users/${id}`, { email: 'CAROL.VERIFIED@example.com' })).status).toBe(200);
        expect((await h.mgmt('GET', `/users/${id}`)).body.email).toBe('carol.verified@example.com');
    });

    it('PATCH blocked toggles the block and refuses logins', async () => {
        const id = enc('auth0|dave');
        const unblocked = await h.mgmt('PATCH', `/users/${id}`, { blocked: false });
        expect(unblocked.body.blocked).toBe(false);
        expect((await login('dave@example.com', PASSWORD)).status).toBe(200);

        const blocked = await h.mgmt('PATCH', `/users/${id}`, { blocked: true });
        expect(blocked.body.blocked).toBe(true);
        const refused = await login('dave@example.com', PASSWORD);
        expect(refused.status).toBe(403);
        expect(refused.body).toEqual({ error: 'unauthorized', error_description: 'user is blocked' });
    });

    it('GET /users-by-email is case-insensitive and supports fields', async () => {
        const res = await h.mgmt('GET', '/users-by-email?email=ALICE%40EXAMPLE.COM');
        expect(res.status).toBe(200);
        expect(Array.isArray(res.body)).toBe(true);
        expect(ids(res.body).sort()).toEqual([tenant.users.alice, otherAlice].sort());
        for (const user of res.body) expect(user).not.toHaveProperty('password_hash');

        const fields = await h.mgmt('GET', '/users-by-email?email=bob%40example.com&fields=email');
        expect(fields.body).toEqual([{ user_id: 'auth0|bob', email: 'bob@example.com' }]);
        expect((await h.mgmt('GET', '/users-by-email?email=nobody%40example.com')).body).toEqual([]);

        const missing = await h.mgmt('GET', '/users-by-email');
        expect(missing.status).toBe(400);
        expect(missing.body.message).toBe("Query parameter 'email' is required");
    });

    it('GET /users paginates, sorts and filters by connection', async () => {
        const bare = await h.mgmt('GET', '/users');
        expect(bare.status).toBe(200);
        expect(Array.isArray(bare.body)).toBe(true);
        expect(bare.body).toHaveLength(6);

        const totals = await h.mgmt('GET', '/users?include_totals=true&per_page=2&page=1');
        expect(totals.body).toEqual({ start: 2, limit: 2, length: 2, total: 6, users: expect.any(Array) });
        const lastPage = await h.mgmt('GET', '/users?include_totals=true&per_page=4&page=1');
        expect(lastPage.body).toMatchObject({ start: 4, limit: 4, length: 2, total: 6 });

        const desc = await h.mgmt('GET', '/users?sort=email:-1&fields=email');
        const emails: string[] = desc.body.map((u: { email: string }) => u.email);
        expect(emails).toHaveLength(6);
        expect(emails).toEqual([...emails].sort((a, b) => b.localeCompare(a)));
        const asc = await h.mgmt('GET', '/users?sort=email:1');
        expect(asc.body.map((u: { email: string }) => u.email)).toEqual([...emails].sort((a, b) => a.localeCompare(b)));

        const inConnection = await h.mgmt('GET', '/users?connection=Other-DB');
        expect(ids(inConnection.body)).toEqual([otherAlice]);
        expect((await h.mgmt('GET', `/users?connection=${CONNECTION}`)).body).toHaveLength(5);
        expect((await h.mgmt('GET', '/users?connection=Nope')).body).toEqual([]);

        const tooMany = await h.mgmt('GET', '/users?per_page=101');
        expect(tooMany.status).toBe(400);
        expect(tooMany.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Query parameter 'per_page' must be less than or equal to 100",
            errorCode: 'invalid_body',
        });
        expect((await h.mgmt('GET', '/users?per_page=100')).status).toBe(200);
        const badPage = await h.mgmt('GET', '/users?page=-1');
        expect(badPage.status).toBe(400);
        expect(badPage.body.message).toBe("Query parameter 'page' must be a non-negative integer");
    });

    it('GET /users?q= filters with Lucene syntax (search_engine=v3)', async () => {
        const q = (query: string) => h.mgmt('GET', `/users?search_engine=v3&q=${enc(query)}`);

        const alice = await q('email:alice@example.com');
        expect(alice.status).toBe(200);
        expect(ids(alice.body).sort()).toEqual([tenant.users.alice, otherAlice].sort());
        const inConnection = await h.mgmt('GET', `/users?q=${enc('email:alice@example.com')}&connection=${CONNECTION}`);
        expect(ids(inConnection.body)).toEqual([tenant.users.alice]);

        expect(ids((await q('app_metadata.tenantIds:"T1"')).body)).toEqual([tenant.users.alice]);
        expect(ids((await q('blocked:true')).body)).toEqual(['auth0|dave']);
        expect(ids((await q('_exists_:last_password_reset')).body)).toEqual(['auth0|carol']);
        expect((await q('email:*@example.com')).body).toHaveLength(6);
        expect((await q('-email:*@example.com')).body).toEqual([]);
        expect(ids((await q('name:"Alice Example" OR nickname:bob')).body).sort()).toEqual([
            tenant.users.alice,
            'auth0|bob',
        ]);

        const composite = await q(
            '!blocked:true AND app_metadata.type:internal AND (user_id:(carol) OR email:(*carol*) OR name:(*carol*))'
        );
        expect(ids(composite.body)).toEqual(['auth0|carol']);

        const totals = await h.mgmt('GET', `/users?q=${enc('nickname:bob')}&include_totals=true`);
        expect(totals.body).toEqual({
            start: 0,
            limit: 50,
            length: 1,
            total: 1,
            users: [expect.objectContaining({ user_id: 'auth0|bob' })],
        });
        expect((await q('   ')).body).toHaveLength(6);
        expect((await h.mgmt('GET', `/users?q=${enc('nickname:bob')}&fields=nickname`)).body).toEqual([
            { user_id: 'auth0|bob', nickname: 'bob' },
        ]);
    });

    it('rejects a malformed q with 400 invalid_query_string', async () => {
        const res = await h.mgmt('GET', `/users?q=${enc('email:(alice')}`);
        expect(res.status).toBe(400);
        expect(res.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: expect.stringMatching(/^Query validation error: /),
            errorCode: 'invalid_query_string',
        });
        expect((await h.mgmt('GET', `/users?q=${enc('email:"unterminated')}`)).status).toBe(400);
        expect((await h.mgmt('GET', `/users?q=${enc('email:')}`)).status).toBe(400);
    });

    it('assigns and removes roles', async () => {
        const id = enc('auth0|carol');
        expect((await h.mgmt('GET', `/users/${id}/roles`)).body).toEqual([]);

        const assign = await h.mgmt('POST', `/users/${id}/roles`, { roles: [tenant.roles.reader, tenant.roles.admin] });
        expect(assign.status).toBe(204);
        expect(assign.body).toBeUndefined();
        const roles = await h.mgmt('GET', `/users/${id}/roles`);
        expect(roles.body).toEqual([
            { id: tenant.roles.reader, name: 'Reader', description: 'Read only' },
            { id: tenant.roles.admin, name: 'Admin', description: 'Full access' },
        ]);
        const totals = await h.mgmt('GET', `/users/${id}/roles?include_totals=true`);
        expect(totals.body).toEqual({ start: 0, limit: 50, length: 2, total: 2, roles: roles.body });

        expect((await h.mgmt('POST', `/users/${id}/roles`, { roles: [tenant.roles.reader] })).status).toBe(204);
        expect((await h.mgmt('GET', `/users/${id}/roles`)).body).toHaveLength(2);

        const unknown = await h.mgmt('POST', `/users/${id}/roles`, { roles: ['rol_nope'] });
        expect(unknown.status).toBe(400);
        expect(unknown.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Role 'rol_nope' does not exist",
            errorCode: 'inexistent_role',
        });
        const empty = await h.mgmt('POST', `/users/${id}/roles`, { roles: [] });
        expect(empty.status).toBe(400);
        expect(empty.body.message).toBe("Payload validation error: 'roles' must be a non-empty array");
        const notStrings = await h.mgmt('POST', `/users/${id}/roles`, { roles: [1] });
        expect(notStrings.status).toBe(400);
        expect(notStrings.body.message).toBe("Payload validation error: 'roles' must be an array of strings");

        const remove = await h.mgmt('DELETE', `/users/${id}/roles`, { roles: [tenant.roles.admin] });
        expect(remove.status).toBe(204);
        expect((await h.mgmt('GET', `/users/${id}/roles`)).body.map((r: { id: string }) => r.id)).toEqual([
            tenant.roles.reader,
        ]);
        expect((await h.mgmt('DELETE', `/users/${id}/roles`, { roles: ['rol_nope'] })).status).toBe(400);
        expect((await h.mgmt('DELETE', `/users/${id}/roles`, { roles: [tenant.roles.admin] })).status).toBe(204);

        expect((await h.mgmt('GET', '/users/auth0%7Cnope/roles')).status).toBe(404);
        expect((await h.mgmt('POST', '/users/auth0%7Cnope/roles', { roles: [tenant.roles.reader] })).status).toBe(404);
        expect((await h.mgmt('DELETE', '/users/auth0%7Cnope/roles', { roles: [tenant.roles.reader] })).status).toBe(
            404
        );
    });

    it('lists role permissions together with direct permissions', async () => {
        const id = enc('auth0|carol'); // Reader → read:things
        const permission = (permission_name: string) => ({ permission_name, resource_server_identifier: API_AUDIENCE });

        const viaRole = await h.mgmt('GET', `/users/${id}/permissions`);
        expect(viaRole.status).toBe(200);
        expect(viaRole.body).toEqual([
            {
                permission_name: 'read:things',
                description: 'Read things',
                resource_server_name: 'Example API',
                resource_server_identifier: API_AUDIENCE,
                sources: [{ source_id: tenant.roles.reader, source_name: 'Reader', source_type: 'ROLE' }],
            },
        ]);

        const add = await h.mgmt('POST', `/users/${id}/permissions`, {
            permissions: [permission('write:things'), permission('read:things')],
        });
        expect(add.status).toBe(201);
        expect(add.body).toEqual({});
        const all = await h.mgmt('GET', `/users/${id}/permissions?include_totals=true`);
        expect(all.body).toMatchObject({ start: 0, limit: 50, length: 2, total: 2 });
        expect(all.body.permissions.map((p: { permission_name: string }) => p.permission_name)).toEqual([
            'read:things',
            'write:things',
        ]);
        // read:things is also assigned directly now, so Auth0 reports it as DIRECT; write:things is direct only.
        expect(
            all.body.permissions.map((p: { sources: Array<{ source_type: string }> }) => p.sources[0]?.source_type)
        ).toEqual(['DIRECT', 'DIRECT']);
        expect(
            (await h.mgmt('POST', `/users/${id}/permissions`, { permissions: [permission('write:things')] })).status
        ).toBe(201);
        expect((await h.mgmt('GET', `/users/${id}/permissions`)).body).toHaveLength(2);

        const unknownScope = await h.mgmt('POST', `/users/${id}/permissions`, {
            permissions: [permission('fly:things')],
        });
        expect(unknownScope.status).toBe(400);
        expect(unknownScope.body.message).toBe(
            `Permission 'fly:things' does not exist on resource server '${API_AUDIENCE}'`
        );
        const unknownServer = await h.mgmt('POST', `/users/${id}/permissions`, {
            permissions: [{ permission_name: 'read:things', resource_server_identifier: 'https://nope.example.com' }],
        });
        expect(unknownServer.status).toBe(400);
        expect(unknownServer.body.message).toBe("Resource server 'https://nope.example.com' does not exist");
        expect((await h.mgmt('POST', `/users/${id}/permissions`, { permissions: [] })).status).toBe(400);

        const remove = await h.mgmt('DELETE', `/users/${id}/permissions`, {
            permissions: [permission('write:things'), permission('read:things')],
        });
        expect(remove.status).toBe(204);
        // Direct permissions are gone; the role-derived one remains.
        expect(
            (await h.mgmt('GET', `/users/${id}/permissions`)).body.map(
                (p: { permission_name: string }) => p.permission_name
            )
        ).toEqual(['read:things']);
        expect((await h.mgmt('GET', '/users/auth0%7Cnope/permissions')).status).toBe(404);
        expect(
            (await h.mgmt('POST', '/users/auth0%7Cnope/permissions', { permissions: [permission('read:things')] }))
                .status
        ).toBe(404);
    });

    it('GET /users/:id/enrollments and /logs return empty lists', async () => {
        const id = enc(tenant.users.alice);
        const enrollments = await h.mgmt('GET', `/users/${id}/enrollments`);
        expect(enrollments.status).toBe(200);
        expect(enrollments.body).toEqual([]);
        expect((await h.mgmt('GET', `/users/${id}/logs`)).body).toEqual([]);
        expect((await h.mgmt('GET', '/users/auth0%7Cnope/enrollments')).status).toBe(404);
        expect((await h.mgmt('GET', '/users/auth0%7Cnope/logs')).status).toBe(404);
    });

    it('user-blocks are reported per user and cleared by id or identifier', async () => {
        const id = enc(tenant.users.bob);
        expect((await h.mgmt('GET', `/user-blocks/${id}`)).body).toEqual({ blocked_for: [] });
        expect((await h.mgmt('GET', '/user-blocks?identifier=bob%40example.com')).body).toEqual({ blocked_for: [] });
        expect((await h.mgmt('GET', '/user-blocks?identifier=nobody%40example.com')).body).toEqual({ blocked_for: [] });
        const missingIdentifier = await h.mgmt('GET', '/user-blocks');
        expect(missingIdentifier.status).toBe(400);
        expect(missingIdentifier.body.message).toBe("Query parameter 'identifier' is required");
        expect((await h.mgmt('GET', '/user-blocks/auth0%7Cnope')).status).toBe(404);

        // Trigger a brute-force block: lower the threshold and fail twice.
        await h.mgmt('PATCH', '/attack-protection/brute-force-protection', { max_attempts: 2 });
        const attempt = () => login('bob@example.com', 'wrong-password');
        expect((await attempt()).status).toBe(403);
        const blocked = await attempt();
        expect(blocked.status).toBe(429);
        expect(blocked.body.error).toBe('too_many_attempts');

        const blocks = await h.mgmt('GET', `/user-blocks/${id}`);
        expect(blocks.status).toBe(200);
        expect(blocks.body.blocked_for).toEqual([
            { identifier: 'bob@example.com', ip: expect.any(String), connection: CONNECTION },
        ]);
        expect((await h.mgmt('GET', '/user-blocks?identifier=bob%40example.com')).body).toEqual(blocks.body);
        expect((await h.mgmt('GET', `/users/${id}`)).body.blocked_for).toEqual(blocks.body.blocked_for);
        expect((await login('bob@example.com', PASSWORD)).status).toBe(429);

        expect((await h.mgmt('DELETE', '/user-blocks?identifier=bob%40example.com')).status).toBe(204);
        expect((await h.mgmt('GET', `/user-blocks/${id}`)).body).toEqual({ blocked_for: [] });
        expect((await h.mgmt('GET', `/users/${id}`)).body).not.toHaveProperty('blocked_for');
        expect((await login('bob@example.com', PASSWORD)).status).toBe(200);

        await attempt();
        await attempt();
        expect((await h.mgmt('GET', `/user-blocks/${id}`)).body.blocked_for).toHaveLength(1);
        expect((await h.mgmt('DELETE', `/user-blocks/${id}`)).status).toBe(204);
        expect((await h.mgmt('GET', `/user-blocks/${id}`)).body).toEqual({ blocked_for: [] });
        expect((await login('bob@example.com', PASSWORD)).status).toBe(200);

        const missingDelete = await h.mgmt('DELETE', '/user-blocks');
        expect(missingDelete.status).toBe(400);
        expect((await h.mgmt('DELETE', '/user-blocks?identifier=nobody%40example.com')).status).toBe(204);
        expect((await h.mgmt('DELETE', '/user-blocks/auth0%7Cnope')).status).toBe(204);
        await h.mgmt('PATCH', '/attack-protection/brute-force-protection', { max_attempts: 10 });
    });

    it('DELETE /users/:id removes the user and its role assignments', async () => {
        const id = enc('auth0|carol');
        expect(ids((await h.mgmt('GET', `/roles/${tenant.roles.reader}/users`)).body)).toContain('auth0|carol');

        const del = await h.mgmt('DELETE', `/users/${id}`);
        expect(del.status).toBe(204);
        expect(del.body).toBeUndefined();
        expect((await h.mgmt('GET', `/users/${id}`)).status).toBe(404);
        expect(ids((await h.mgmt('GET', `/roles/${tenant.roles.reader}/users`)).body)).not.toContain('auth0|carol');
        expect((await h.mgmt('GET', '/users-by-email?email=carol.verified%40example.com')).body).toEqual([]);
        expect((await h.mgmt('GET', '/users')).body).toHaveLength(5);
        expect((await h.mgmt('DELETE', `/users/${id}`)).status).toBe(204);

        // The identifier can be reused and starts with no roles or permissions.
        const again = await h.mgmt('POST', '/users', {
            connection: CONNECTION,
            user_id: 'carol',
            email: 'carol@example.com',
            password: PASSWORD,
        });
        expect(again.status).toBe(201);
        expect((await h.mgmt('GET', `/users/${id}/roles`)).body).toEqual([]);
        expect((await h.mgmt('GET', `/users/${id}/permissions`)).body).toEqual([]);
    });
});

describe('Tickets', () => {
    let h: Harness;
    let tenant: Tenant;
    beforeAll(async () => {
        h = await startMock();
        tenant = await provisionTenant(h);
    });
    afterAll(() => h.close());

    const expectTicket = (ticket: unknown, path: string): string => {
        expect(typeof ticket).toBe('string');
        const url = ticket as string;
        const prefix = `${h.issuer}${path}?ticket=`;
        expect(url.startsWith(prefix)).toBe(true);
        expect(url.endsWith('#')).toBe(true);
        const id = url.slice(prefix.length, -1);
        expect(id).toMatch(/^[A-Za-z0-9_-]{43}$/);
        return id;
    };

    it('POST /tickets/password-change returns a reset URL under lo/reset', async () => {
        const res = await h.mgmt('POST', '/tickets/password-change', { user_id: tenant.users.alice });
        expect(res.status).toBe(201);
        expect(Object.keys(res.body)).toEqual(['ticket']);
        const first = expectTicket(res.body.ticket, 'lo/reset');

        const second = await h.mgmt('POST', '/tickets/password-change', {
            user_id: tenant.users.alice,
            ttl_sec: 3600,
            mark_email_as_verified: true,
            includeEmailInRedirect: true,
            result_url: 'https://app.example.com/done',
        });
        expect(second.status).toBe(201);
        expect(expectTicket(second.body.ticket, 'lo/reset')).not.toBe(first);
    });

    it('POST /tickets/email-verification returns a URL under u/email-verification', async () => {
        const res = await h.mgmt('POST', '/tickets/email-verification', {
            user_id: tenant.users.bob,
            client_id: tenant.clients.spa.client_id,
        });
        expect(res.status).toBe(201);
        expect(Object.keys(res.body)).toEqual(['ticket']);
        expectTicket(res.body.ticket, 'u/email-verification');
    });

    it('resolves the user by email + connection_id', async () => {
        const res = await h.mgmt('POST', '/tickets/password-change', {
            email: 'ALICE@example.com',
            connection_id: tenant.connection.id,
        });
        expect(res.status).toBe(201);
        expectTicket(res.body.ticket, 'lo/reset');

        const unknownConnection = await h.mgmt('POST', '/tickets/password-change', {
            email: 'alice@example.com',
            connection_id: 'con_nope',
        });
        expect(unknownConnection.status).toBe(400);
        expect(unknownConnection.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: 'The connection does not exist.',
            errorCode: 'inexistent_connection',
        });
        const unknownEmail = await h.mgmt('POST', '/tickets/password-change', {
            email: 'nobody@example.com',
            connection_id: tenant.connection.id,
        });
        expect(unknownEmail.status).toBe(404);
        expect(unknownEmail.body.message).toBe('The user does not exist.');

        const emailOnly = await h.mgmt('POST', '/tickets/email-verification', { email: 'alice@example.com' });
        expect(emailOnly.status).toBe(400);
        expect(emailOnly.body.message).toBe(
            "Payload validation error: 'user_id' or both 'email' and 'connection_id' are required"
        );
        expect((await h.mgmt('POST', '/tickets/password-change', {})).status).toBe(400);
    });

    it('404 for an unknown user; 400 for client_id with result_url or an unknown client', async () => {
        const unknown = await h.mgmt('POST', '/tickets/password-change', { user_id: 'auth0|nope' });
        expect(unknown.status).toBe(404);
        expect(unknown.body).toEqual({
            statusCode: 404,
            error: 'Not Found',
            message: 'The user does not exist.',
            errorCode: 'inexistent_resource',
        });
        expect((await h.mgmt('POST', '/tickets/email-verification', { user_id: 'auth0|nope' })).status).toBe(404);

        const both = await h.mgmt('POST', '/tickets/password-change', {
            user_id: tenant.users.alice,
            client_id: tenant.clients.spa.client_id,
            result_url: 'https://app.example.com/done',
        });
        expect(both.status).toBe(400);
        expect(both.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Payload validation error: 'client_id' and 'result_url' are mutually exclusive",
            errorCode: 'invalid_body',
        });

        const badClient = await h.mgmt('POST', '/tickets/password-change', {
            user_id: tenant.users.alice,
            client_id: 'nope',
        });
        expect(badClient.status).toBe(400);
        expect(badClient.body.message).toBe("Client 'nope' does not exist");
    });
});
