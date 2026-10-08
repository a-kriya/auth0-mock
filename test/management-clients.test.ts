import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { API_AUDIENCE, PASSWORD, provisionTenant, startMock, type Harness, type Tenant } from './helpers.ts';

const REGULAR_WEB_GRANTS = ['authorization_code', 'implicit', 'refresh_token', 'client_credentials'];
const PUBLIC_GRANTS = ['authorization_code', 'implicit', 'refresh_token'];
const DEFAULT_REFRESH_TOKEN = {
    rotation_type: 'non-rotating',
    expiration_type: 'non-expiring',
    leeway: 0,
    token_lifetime: 2592000,
    idle_token_lifetime: 1296000,
    infinite_token_lifetime: true,
    infinite_idle_token_lifetime: true,
};

describe('Clients', () => {
    let h: Harness;
    let spaId: string;
    beforeAll(async () => {
        h = await startMock();
    });
    afterAll(() => h.close());

    it('POST a SPA applies public-client defaults', async () => {
        const res = await h.mgmt('POST', '/clients', {
            name: 'My SPA',
            app_type: 'spa',
            callbacks: ['http://localhost:3000'],
        });
        expect(res.status).toBe(201);
        const client = res.body;
        expect(client.client_id).toMatch(/^[A-Za-z0-9]{32}$/);
        expect(client.client_secret).toMatch(/^[A-Za-z0-9_-]{64}$/);
        expect(client).toMatchObject({
            tenant: 'auth0-mock',
            name: 'My SPA',
            description: '',
            global: false,
            app_type: 'spa',
            logo_uri: '',
            is_first_party: true,
            oidc_conformant: true,
            callbacks: ['http://localhost:3000'],
            allowed_origins: [],
            web_origins: [],
            allowed_clients: [],
            allowed_logout_urls: [],
            grant_types: PUBLIC_GRANTS,
            jwt_configuration: { alg: 'RS256', lifetime_in_seconds: 36000, secret_encoded: false },
            sso: false,
            sso_disabled: false,
            cross_origin_auth: false,
            custom_login_page_on: true,
            token_endpoint_auth_method: 'none',
            client_metadata: {},
            refresh_token: DEFAULT_REFRESH_TOKEN,
            is_token_endpoint_ip_header_trusted: false,
            require_pushed_authorization_requests: false,
        });
        expect(client.signing_keys).toEqual([
            { cert: expect.stringContaining('-----BEGIN CERTIFICATE-----'), subject: '/CN=auth0-mock' },
        ]);
        spaId = client.client_id;
    });

    it('applies grant types and auth method per app_type', async () => {
        const cases = [
            ['native', PUBLIC_GRANTS, 'none'],
            ['regular_web', REGULAR_WEB_GRANTS, 'client_secret_post'],
            ['non_interactive', ['client_credentials'], 'client_secret_post'],
        ] as const;
        for (const [appType, grants, method] of cases) {
            const res = await h.mgmt('POST', '/clients', { name: `client-${appType}`, app_type: appType });
            expect(res.status, appType).toBe(201);
            expect(res.body.app_type).toBe(appType);
            expect(res.body.grant_types, appType).toEqual(grants);
            expect(res.body.token_endpoint_auth_method, appType).toBe(method);
            expect(res.body.client_secret, appType).toMatch(/^[A-Za-z0-9_-]{64}$/);
        }
        const untyped = await h.mgmt('POST', '/clients', { name: 'untyped' });
        expect(untyped.status).toBe(201);
        expect(untyped.body).not.toHaveProperty('app_type');
        expect(untyped.body.grant_types).toEqual(REGULAR_WEB_GRANTS);
        expect(untyped.body.token_endpoint_auth_method).toBe('client_secret_post');
        const other = await h.mgmt('POST', '/clients', { name: 'other-type', app_type: 'sso_integration' });
        expect(other.body.grant_types).toEqual(REGULAR_WEB_GRANTS);
        expect(other.body.token_endpoint_auth_method).toBe('client_secret_post');
    });

    it('merges jwt_configuration with defaults and honours explicit grant_types / auth method', async () => {
        const res = await h.mgmt('POST', '/clients', {
            name: 'jwt',
            app_type: 'spa',
            jwt_configuration: { lifetime_in_seconds: 7200 },
            grant_types: ['authorization_code', 'refresh_token', 'password'],
            token_endpoint_auth_method: 'client_secret_basic',
            oidc_conformant: false,
        });
        expect(res.status).toBe(201);
        expect(res.body.jwt_configuration).toEqual({ alg: 'RS256', lifetime_in_seconds: 7200, secret_encoded: false });
        expect(res.body.grant_types).toEqual(['authorization_code', 'refresh_token', 'password']);
        expect(res.body.token_endpoint_auth_method).toBe('client_secret_basic');
        expect(res.body.oidc_conformant).toBe(false);
        const hs = await h.mgmt('POST', '/clients', {
            name: 'hs256',
            jwt_configuration: { alg: 'HS256', secret_encoded: true },
        });
        expect(hs.body.jwt_configuration).toEqual({ alg: 'HS256', lifetime_in_seconds: 36000, secret_encoded: true });
    });

    it('derives refresh_token infinite flags from the expiration settings', async () => {
        const expiring = await h.mgmt('POST', '/clients', {
            name: 'rt-expiring',
            app_type: 'spa',
            refresh_token: { rotation_type: 'rotating', expiration_type: 'expiring', token_lifetime: 43200 },
        });
        expect(expiring.body.refresh_token).toEqual({
            rotation_type: 'rotating',
            expiration_type: 'expiring',
            leeway: 0,
            token_lifetime: 43200,
            idle_token_lifetime: 1296000,
            infinite_token_lifetime: false,
            infinite_idle_token_lifetime: true,
        });

        const idle = await h.mgmt('POST', '/clients', {
            name: 'rt-idle',
            refresh_token: { expiration_type: 'expiring', idle_token_lifetime: 3600 },
        });
        expect(idle.body.refresh_token).toMatchObject({
            expiration_type: 'expiring',
            idle_token_lifetime: 3600,
            infinite_token_lifetime: false,
            infinite_idle_token_lifetime: false,
        });

        const explicit = await h.mgmt('POST', '/clients', {
            name: 'rt-explicit',
            refresh_token: {
                expiration_type: 'expiring',
                idle_token_lifetime: 3600,
                infinite_idle_token_lifetime: true,
                infinite_token_lifetime: true,
            },
        });
        expect(explicit.body.refresh_token).toMatchObject({
            infinite_token_lifetime: true,
            infinite_idle_token_lifetime: true,
        });

        const nonExpiring = await h.mgmt('POST', '/clients', {
            name: 'rt-default',
            refresh_token: { rotation_type: 'rotating' },
        });
        expect(nonExpiring.body.refresh_token).toEqual({ ...DEFAULT_REFRESH_TOKEN, rotation_type: 'rotating' });
    });

    it('accepts a caller-provided client_id / client_secret, rejects duplicates and a missing name', async () => {
        const res = await h.mgmt('POST', '/clients', {
            name: 'pinned',
            client_id: 'pinnedclientid',
            client_secret: 'pinnedsecret',
        });
        expect(res.status).toBe(201);
        expect(res.body).toMatchObject({ client_id: 'pinnedclientid', client_secret: 'pinnedsecret' });

        const dup = await h.mgmt('POST', '/clients', { name: 'pinned-again', client_id: 'pinnedclientid' });
        expect(dup.status).toBe(409);
        expect(dup.body).toEqual({
            statusCode: 409,
            error: 'Conflict',
            message: "A client with id 'pinnedclientid' already exists",
            errorCode: 'client_conflict',
        });

        const missingName = await h.mgmt('POST', '/clients', { app_type: 'spa' });
        expect(missingName.status).toBe(400);
        expect(missingName.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Payload validation error: 'name' is required and must be a non-empty string",
            errorCode: 'invalid_body',
        });
    });

    it('GET by id, 404 for unknown, fields filtering keeps client_id', async () => {
        const got = await h.mgmt('GET', `/clients/${spaId}`);
        expect(got.status).toBe(200);
        expect(got.body).toMatchObject({ client_id: spaId, name: 'My SPA', app_type: 'spa' });

        const fields = await h.mgmt('GET', `/clients/${spaId}?fields=name,app_type`);
        expect(fields.body).toEqual({ client_id: spaId, name: 'My SPA', app_type: 'spa' });
        const onlyId = await h.mgmt('GET', `/clients/${spaId}?fields=client_id`);
        expect(onlyId.body).toEqual({ client_id: spaId });
        const excluded = await h.mgmt(
            'GET',
            `/clients/${spaId}?fields=client_secret,signing_keys&include_fields=false`
        );
        expect(excluded.body).not.toHaveProperty('client_secret');
        expect(excluded.body).not.toHaveProperty('signing_keys');
        expect(excluded.body).toMatchObject({ client_id: spaId, name: 'My SPA' });

        const missing = await h.mgmt('GET', '/clients/nope');
        expect(missing.status).toBe(404);
        expect(missing.body).toEqual({
            statusCode: 404,
            error: 'Not Found',
            message: 'The client does not exist',
            errorCode: 'inexistent_resource',
        });
    });

    it('PATCH updates fields, merges client_metadata and ignores protected fields', async () => {
        const before = (await h.mgmt('GET', `/clients/${spaId}`)).body;
        const patched = await h.mgmt('PATCH', `/clients/${spaId}`, {
            name: 'Renamed SPA',
            client_id: 'hijack',
            tenant: 'other-tenant',
            global: true,
            signing_keys: [{ cert: 'nope' }],
            callbacks: ['http://localhost:4000'],
            client_metadata: { env: 'dev' },
            jwt_configuration: { alg: 'RS256', lifetime_in_seconds: 600 },
        });
        expect(patched.status).toBe(200);
        expect(patched.body).toMatchObject({
            client_id: spaId,
            name: 'Renamed SPA',
            tenant: 'auth0-mock',
            global: false,
            callbacks: ['http://localhost:4000'],
            client_metadata: { env: 'dev' },
            jwt_configuration: { alg: 'RS256', lifetime_in_seconds: 600 },
        });
        expect(patched.body.signing_keys).toEqual(before.signing_keys);
        expect(patched.body.client_secret).toBe(before.client_secret);
        expect((await h.mgmt('GET', '/clients/hijack')).status).toBe(404);

        const merged = await h.mgmt('PATCH', `/clients/${spaId}`, { client_metadata: { team: 'core', env: null } });
        expect(merged.body.client_metadata).toEqual({ team: 'core' });
        const cleared = await h.mgmt('PATCH', `/clients/${spaId}`, { client_metadata: null });
        expect(cleared.body.client_metadata).toEqual({});

        expect((await h.mgmt('PATCH', '/clients/nope', { name: 'x' })).status).toBe(404);
        const notObject = await h.mgmt('PATCH', `/clients/${spaId}`, []);
        expect(notObject.status).toBe(400);
        expect(notObject.body.message).toBe('Payload validation error: expected a JSON object body');
    });

    it('GET /clients filters by app_type, is_first_party and q=name', async () => {
        const spas = await h.mgmt('GET', '/clients?app_type=spa');
        expect(spas.status).toBe(200);
        expect(spas.body.length).toBeGreaterThan(0);
        expect(spas.body.every((c: { app_type: string }) => c.app_type === 'spa')).toBe(true);

        const two = await h.mgmt('GET', '/clients?app_type=native,non_interactive');
        expect(two.body.map((c: { name: string }) => c.name).sort()).toEqual([
            'client-native',
            'client-non_interactive',
        ]);

        const firstParty = await h.mgmt('GET', '/clients?is_first_party=true&include_totals=true');
        expect(firstParty.body).toMatchObject({ start: 0, limit: 50 });
        expect(firstParty.body.total).toBe(firstParty.body.clients.length);
        expect(firstParty.body.total).toBeGreaterThan(5);
        expect((await h.mgmt('GET', '/clients?is_first_party=false')).body).toEqual([]);
        expect((await h.mgmt('GET', '/clients?is_global=true')).body).toEqual([]);

        const byName = await h.mgmt('GET', `/clients?q=${encodeURIComponent('name:"Renamed SPA"')}`);
        expect(byName.body.map((c: { name: string }) => c.name)).toEqual(['Renamed SPA']);
        const unquoted = await h.mgmt('GET', `/clients?q=${encodeURIComponent('name:renamed spa')}`);
        expect(unquoted.body.map((c: { name: string }) => c.name)).toEqual(['Renamed SPA']);
        expect((await h.mgmt('GET', `/clients?q=${encodeURIComponent('name:"Nobody"')}`)).body).toEqual([]);

        const fields = await h.mgmt('GET', '/clients?fields=name');
        for (const c of fields.body) expect(Object.keys(c).sort()).toEqual(['client_id', 'name']);
        const onlyId = await h.mgmt('GET', '/clients?fields=client_id');
        for (const c of onlyId.body) expect(Object.keys(c)).toEqual(['client_id']);

        const paged = await h.mgmt('GET', '/clients?per_page=2&page=1&include_totals=true');
        expect(paged.body).toMatchObject({ start: 2, limit: 2, length: 2 });
        expect(paged.body.clients).toHaveLength(2);
        expect((await h.mgmt('GET', '/clients?per_page=101')).status).toBe(400);
    });

    it('rotate-secret replaces the secret', async () => {
        const before = (await h.mgmt('GET', `/clients/${spaId}`)).body.client_secret;
        const rotated = await h.mgmt('POST', `/clients/${spaId}/rotate-secret`);
        expect(rotated.status).toBe(200);
        expect(rotated.body.client_id).toBe(spaId);
        expect(rotated.body.client_secret).toMatch(/^[A-Za-z0-9_-]{64}$/);
        expect(rotated.body.client_secret).not.toBe(before);
        expect((await h.mgmt('GET', `/clients/${spaId}`)).body.client_secret).toBe(rotated.body.client_secret);
        expect((await h.mgmt('POST', '/clients/nope/rotate-secret')).status).toBe(404);
    });

    it('DELETE removes the client and cascades to its grants', async () => {
        expect((await h.mgmt('POST', '/resource-servers', { identifier: 'https://cascade.example.com' })).status).toBe(
            201
        );
        const client = (await h.mgmt('POST', '/clients', { name: 'doomed', app_type: 'non_interactive' })).body;
        const grant = await h.mgmt('POST', '/client-grants', {
            client_id: client.client_id,
            audience: 'https://cascade.example.com',
            scope: [],
        });
        expect(grant.status).toBe(201);
        expect((await h.mgmt('GET', `/client-grants?client_id=${client.client_id}`)).body).toHaveLength(1);

        const del = await h.mgmt('DELETE', `/clients/${client.client_id}`);
        expect(del.status).toBe(204);
        expect(del.body).toBeUndefined();
        expect((await h.mgmt('GET', `/clients/${client.client_id}`)).status).toBe(404);
        expect((await h.mgmt('GET', `/client-grants?client_id=${client.client_id}`)).body).toEqual([]);
        expect((await h.mgmt('GET', `/client-grants/${grant.body.id}`)).status).toBe(404);
        expect((await h.mgmt('DELETE', `/clients/${client.client_id}`)).status).toBe(204);
    });
});

describe('Client grants', () => {
    let h: Harness;
    let tenant: Tenant;
    let spaGrant: Record<string, unknown> & { id: string };
    let extraClientId: string;
    beforeAll(async () => {
        h = await startMock();
        tenant = await provisionTenant(h);
    });
    afterAll(() => h.close());

    it('POST creates a grant with a cgr_ id', async () => {
        const res = await h.mgmt('POST', '/client-grants', {
            client_id: tenant.clients.spa.client_id,
            audience: API_AUDIENCE,
            scope: ['read:things'],
        });
        expect(res.status).toBe(201);
        expect(res.body).toEqual({
            id: expect.stringMatching(/^cgr_[A-Za-z0-9]{16}$/),
            client_id: tenant.clients.spa.client_id,
            audience: API_AUDIENCE,
            scope: ['read:things'],
        });
        spaGrant = res.body;
    });

    it('validates client, audience, scope shape and duplicates', async () => {
        const unknownClient = await h.mgmt('POST', '/client-grants', {
            client_id: 'nope',
            audience: API_AUDIENCE,
            scope: [],
        });
        expect(unknownClient.status).toBe(400);
        expect(unknownClient.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Client 'nope' does not exist",
            errorCode: 'client_not_found',
        });

        const unknownAudience = await h.mgmt('POST', '/client-grants', {
            client_id: tenant.clients.spa.client_id,
            audience: 'https://nope.example.com',
            scope: [],
        });
        expect(unknownAudience.status).toBe(400);
        expect(unknownAudience.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "The audience 'https://nope.example.com' is not a known resource server",
            errorCode: 'invalid_body',
        });

        const duplicate = await h.mgmt('POST', '/client-grants', {
            client_id: tenant.clients.spa.client_id,
            audience: API_AUDIENCE,
            scope: [],
        });
        expect(duplicate.status).toBe(409);
        expect(duplicate.body).toEqual({
            statusCode: 409,
            error: 'Conflict',
            message: 'Client grant already exists',
            errorCode: 'client_grant_conflict',
        });

        const badScope = await h.mgmt('POST', '/client-grants', {
            client_id: tenant.clients.spa.client_id,
            audience: h.managementAudience,
            scope: 'read:users',
        });
        expect(badScope.status).toBe(400);
        expect(badScope.body.message).toBe("Payload validation error: 'scope' must be an array of strings");

        const missingClient = await h.mgmt('POST', '/client-grants', { audience: API_AUDIENCE });
        expect(missingClient.status).toBe(400);
        expect(missingClient.body.message).toBe(
            "Payload validation error: 'client_id' is required and must be a non-empty string"
        );
        const missingAudience = await h.mgmt('POST', '/client-grants', { client_id: tenant.clients.spa.client_id });
        expect(missingAudience.status).toBe(400);
        expect(missingAudience.body.message).toBe(
            "Payload validation error: 'audience' is required and must be a non-empty string"
        );
    });

    it('does not validate scopes against the resource server', async () => {
        const res = await h.mgmt('POST', '/client-grants', {
            client_id: tenant.clients.spa.client_id,
            audience: h.managementAudience,
            scope: ['read:users', 'made:up'],
        });
        expect(res.status).toBe(201);
        expect(res.body.scope).toEqual(['read:users', 'made:up']);
    });

    it('defaults scope to [] and keeps extra fields', async () => {
        const client = (await h.mgmt('POST', '/clients', { name: 'extra', app_type: 'non_interactive' })).body;
        extraClientId = client.client_id;
        const res = await h.mgmt('POST', '/client-grants', {
            client_id: extraClientId,
            audience: API_AUDIENCE,
            organization_usage: 'allow',
            allow_any_organization: true,
        });
        expect(res.status).toBe(201);
        expect(res.body).toEqual({
            id: expect.stringMatching(/^cgr_/),
            client_id: extraClientId,
            audience: API_AUDIENCE,
            scope: [],
            organization_usage: 'allow',
            allow_any_organization: true,
        });
    });

    it('GET list filters by client_id and audience, with and without totals', async () => {
        const all = await h.mgmt('GET', '/client-grants');
        expect(all.status).toBe(200);
        expect(all.body).toHaveLength(5); // backend x2 (provisioned), spa x2, extra x1

        const byClient = await h.mgmt(
            'GET',
            `/client-grants?client_id=${tenant.clients.backend.client_id}&include_totals=true`
        );
        expect(byClient.body).toEqual({ start: 0, limit: 50, length: 2, total: 2, client_grants: expect.any(Array) });
        expect(byClient.body.client_grants.map((g: { audience: string }) => g.audience).sort()).toEqual(
            [API_AUDIENCE, h.managementAudience].sort()
        );

        const byAudience = await h.mgmt('GET', `/client-grants?audience=${encodeURIComponent(API_AUDIENCE)}`);
        expect(byAudience.body.map((g: { client_id: string }) => g.client_id).sort()).toEqual(
            [tenant.clients.backend.client_id, tenant.clients.spa.client_id, extraClientId].sort()
        );

        const both = await h.mgmt(
            'GET',
            `/client-grants?client_id=${tenant.clients.spa.client_id}&audience=${encodeURIComponent(h.managementAudience)}`
        );
        expect(both.body).toHaveLength(1);
        expect(both.body[0].scope).toEqual(['read:users', 'made:up']);

        const none = await h.mgmt('GET', '/client-grants?client_id=nope&include_totals=true');
        expect(none.body).toEqual({ start: 0, limit: 50, length: 0, total: 0, client_grants: [] });
        const paged = await h.mgmt('GET', '/client-grants?per_page=2&page=2&include_totals=true');
        expect(paged.body).toMatchObject({ start: 4, limit: 2, length: 1, total: 5 });
    });

    it('GET / PATCH / DELETE by id', async () => {
        const got = await h.mgmt('GET', `/client-grants/${spaGrant.id}`);
        expect(got.status).toBe(200);
        expect(got.body).toEqual(spaGrant);
        const missing = await h.mgmt('GET', '/client-grants/cgr_nope');
        expect(missing.status).toBe(404);
        expect(missing.body).toEqual({
            statusCode: 404,
            error: 'Not Found',
            message: 'The client grant does not exist',
            errorCode: 'inexistent_resource',
        });

        const patched = await h.mgmt('PATCH', `/client-grants/${spaGrant.id}`, {
            scope: ['read:things', 'write:things'],
            client_id: 'ignored',
            audience: 'ignored',
            organization_usage: 'require',
        });
        expect(patched.status).toBe(200);
        expect(patched.body).toEqual({
            ...spaGrant,
            scope: ['read:things', 'write:things'],
            organization_usage: 'require',
        });
        const badScope = await h.mgmt('PATCH', `/client-grants/${spaGrant.id}`, { scope: 'x' });
        expect(badScope.status).toBe(400);
        const untouched = await h.mgmt('PATCH', `/client-grants/${spaGrant.id}`, { something: 'else' });
        expect(untouched.body).toEqual(patched.body);
        expect((await h.mgmt('PATCH', '/client-grants/cgr_nope', { scope: [] })).status).toBe(404);

        const del = await h.mgmt('DELETE', `/client-grants/${spaGrant.id}`);
        expect(del.status).toBe(204);
        expect((await h.mgmt('GET', `/client-grants/${spaGrant.id}`)).status).toBe(404);
        expect((await h.mgmt('DELETE', `/client-grants/${spaGrant.id}`)).status).toBe(204);
        expect((await h.mgmt('GET', '/client-grants')).body).toHaveLength(4);
    });
});

describe('Connections', () => {
    let h: Harness;
    let tenant: Tenant;
    let conn: { id: string; name: string };
    beforeAll(async () => {
        h = await startMock();
        tenant = await provisionTenant(h);
    });
    afterAll(() => h.close());

    it('POST (auth0 strategy) fills option defaults and realms', async () => {
        const res = await h.mgmt('POST', '/connections', {
            name: 'Second-DB',
            strategy: 'auth0',
            options: { disable_signup: true, passwordPolicy: 'excellent' },
        });
        expect(res.status).toBe(201);
        expect(res.body).toEqual({
            id: expect.stringMatching(/^con_[A-Za-z0-9]{16}$/),
            name: 'Second-DB',
            strategy: 'auth0',
            options: {
                auth_params: {},
                configuration: {},
                custom_scripts: {},
                scripts: {},
                precedence: [],
                id_token_signed_response_algs: [],
                password_dictionary: { enable: false, dictionary: [] },
                passwordPolicy: 'excellent',
                strategy_version: 2,
                disable_signup: true,
            },
            enabled_clients: [],
            is_domain_connection: false,
            realms: ['Second-DB'],
            metadata: {},
        });
        conn = res.body;

        const social = await h.mgmt('POST', '/connections', {
            name: 'google-oauth2',
            strategy: 'google-oauth2',
            options: { client_id: 'g' },
            realms: ['google'],
            display_name: 'Google',
        });
        expect(social.status).toBe(201);
        expect(social.body).toMatchObject({ options: { client_id: 'g' }, realms: ['google'], display_name: 'Google' });
        expect(social.body.options).not.toHaveProperty('strategy_version');

        const withClients = await h.mgmt('POST', '/connections', {
            name: 'With-Clients',
            strategy: 'auth0',
            enabled_clients: [tenant.clients.spa.client_id],
        });
        expect(withClients.body.enabled_clients).toEqual([tenant.clients.spa.client_id]);

        const badClients = await h.mgmt('POST', '/connections', {
            name: 'Bad-Clients',
            strategy: 'auth0',
            enabled_clients: ['nope'],
        });
        expect(badClients.status).toBe(400);
        expect(badClients.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Client 'nope' does not exist",
            errorCode: 'inexistent_client',
        });
        const missingStrategy = await h.mgmt('POST', '/connections', { name: 'x' });
        expect(missingStrategy.status).toBe(400);
        expect(missingStrategy.body.message).toBe(
            "Payload validation error: 'strategy' is required and must be a non-empty string"
        );
    });

    it('rejects a duplicate name with 409', async () => {
        const res = await h.mgmt('POST', '/connections', {
            name: 'Username-Password-Authentication',
            strategy: 'auth0',
        });
        expect(res.status).toBe(409);
        expect(res.body).toEqual({
            statusCode: 409,
            error: 'Conflict',
            message: 'A connection with the same name already exists',
            errorCode: 'connection_conflict',
        });
    });

    it('GET by id keeps id with fields; list supports filters, totals and checkpoints', async () => {
        const got = await h.mgmt('GET', `/connections/${conn.id}`);
        expect(got.status).toBe(200);
        expect(got.body).toEqual(conn);
        const fields = await h.mgmt('GET', `/connections/${conn.id}?fields=strategy,name`);
        expect(fields.body).toEqual({ id: conn.id, name: 'Second-DB', strategy: 'auth0' });
        const missing = await h.mgmt('GET', '/connections/con_nope');
        expect(missing.status).toBe(404);
        expect(missing.body).toEqual({
            statusCode: 404,
            error: 'Not Found',
            message: 'The connection does not exist',
            errorCode: 'inexistent_resource',
        });

        const databases = await h.mgmt('GET', '/connections?strategy=auth0');
        expect(databases.body.map((c: { name: string }) => c.name).sort()).toEqual([
            'Second-DB',
            'Username-Password-Authentication',
            'With-Clients',
        ]);
        const social = await h.mgmt('GET', '/connections?strategy=google-oauth2&fields=name');
        expect(social.body).toEqual([{ id: expect.stringMatching(/^con_/), name: 'google-oauth2' }]);
        expect((await h.mgmt('GET', '/connections?name=Second-DB')).body).toEqual([conn]);
        expect((await h.mgmt('GET', '/connections?name=Nope')).body).toEqual([]);

        const totals = await h.mgmt('GET', '/connections?include_totals=true&per_page=2');
        expect(totals.body).toMatchObject({ start: 0, limit: 2, length: 2, total: 4 });
        expect(totals.body.connections).toHaveLength(2);

        const first = await h.mgmt('GET', '/connections?take=3');
        expect(first.body.connections).toHaveLength(3);
        expect(first.body.next).toBe('3');
        const last = await h.mgmt('GET', `/connections?from=${first.body.next}&take=3`);
        expect(last.body.connections).toHaveLength(1);
        expect(last.body).not.toHaveProperty('next');
    });

    it('PATCH rejects name/strategy changes and replaces options wholesale', async () => {
        const rename = await h.mgmt('PATCH', `/connections/${conn.id}`, { name: 'Other' });
        expect(rename.status).toBe(400);
        expect(rename.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Payload validation error: 'name' and 'strategy' cannot be changed",
            errorCode: 'invalid_body',
        });
        expect((await h.mgmt('PATCH', `/connections/${conn.id}`, { strategy: 'auth0' })).status).toBe(400);

        const patched = await h.mgmt('PATCH', `/connections/${conn.id}`, {
            options: { disable_signup: false },
            metadata: { owner: 'team' },
            id: 'con_hijack',
        });
        expect(patched.status).toBe(200);
        expect(patched.body.options).toEqual({ disable_signup: false });
        expect(patched.body).toMatchObject({
            id: conn.id,
            name: 'Second-DB',
            strategy: 'auth0',
            metadata: { owner: 'team' },
        });
        expect((await h.mgmt('GET', '/connections/con_hijack')).status).toBe(404);

        const badOptions = await h.mgmt('PATCH', `/connections/${conn.id}`, { options: 'x' });
        expect(badOptions.status).toBe(400);
        expect(badOptions.body.message).toBe("Payload validation error: 'options' must be an object");

        const enabled = await h.mgmt('PATCH', `/connections/${conn.id}`, {
            enabled_clients: [tenant.clients.spa.client_id, tenant.clients.backend.client_id],
        });
        expect(enabled.body.enabled_clients).toEqual([tenant.clients.spa.client_id, tenant.clients.backend.client_id]);
        const badEnabled = await h.mgmt('PATCH', `/connections/${conn.id}`, { enabled_clients: ['nope'] });
        expect(badEnabled.status).toBe(400);
        expect(badEnabled.body.errorCode).toBe('inexistent_client');
        expect((await h.mgmt('PATCH', '/connections/con_nope', { options: {} })).status).toBe(404);
    });

    it('GET /connections/:id/clients uses checkpoint pagination', async () => {
        const { spa, backend } = tenant.clients;
        const all = await h.mgmt('GET', `/connections/${conn.id}/clients`);
        expect(all.status).toBe(200);
        expect(all.body).toEqual({ clients: [{ client_id: spa.client_id }, { client_id: backend.client_id }] });

        const first = await h.mgmt('GET', `/connections/${conn.id}/clients?take=1`);
        expect(first.body).toEqual({ clients: [{ client_id: spa.client_id }], next: '1' });
        const second = await h.mgmt('GET', `/connections/${conn.id}/clients?from=${first.body.next}&take=1`);
        expect(second.body).toEqual({ clients: [{ client_id: backend.client_id }] });
        const beyond = await h.mgmt('GET', `/connections/${conn.id}/clients?from=5`);
        expect(beyond.body).toEqual({ clients: [] });
        expect((await h.mgmt('GET', '/connections/con_nope/clients')).status).toBe(404);
    });

    it('PATCH /connections/:id/clients toggles enabled clients and returns 204', async () => {
        const { spa, backend } = tenant.clients;
        const path = `/connections/${conn.id}/clients`;
        const disable = await h.mgmt('PATCH', path, [{ client_id: spa.client_id, status: false }]);
        expect(disable.status).toBe(204);
        expect(disable.body).toBeUndefined();
        expect((await h.mgmt('GET', path)).body.clients).toEqual([{ client_id: backend.client_id }]);

        const enable = await h.mgmt('PATCH', path, [
            { client_id: spa.client_id, status: true },
            { client_id: backend.client_id, status: true },
        ]);
        expect(enable.status).toBe(204);
        const ids = (await h.mgmt('GET', path)).body.clients.map((c: { client_id: string }) => c.client_id).sort();
        expect(ids).toEqual([spa.client_id, backend.client_id].sort());
        expect([...(await h.mgmt('GET', `/connections/${conn.id}`)).body.enabled_clients].sort()).toEqual(ids);

        const unknown = await h.mgmt('PATCH', path, [{ client_id: 'nope', status: true }]);
        expect(unknown.status).toBe(400);
        expect(unknown.body).toEqual({
            statusCode: 400,
            error: 'Bad Request',
            message: "Client 'nope' does not exist",
            errorCode: 'inexistent_client',
        });
        const notArray = await h.mgmt('PATCH', path, { client_id: spa.client_id, status: true });
        expect(notArray.status).toBe(400);
        expect(notArray.body.message).toBe('Payload validation error: expected an array of clients');
        const badEntry = await h.mgmt('PATCH', path, [{ client_id: spa.client_id, status: 'yes' }]);
        expect(badEntry.status).toBe(400);
        expect(badEntry.body.message).toBe(
            "Payload validation error: each entry requires 'client_id' and boolean 'status'"
        );
        expect((await h.mgmt('PATCH', '/connections/con_nope/clients', [])).status).toBe(404);
        // Failed requests leave the list untouched.
        expect((await h.mgmt('GET', path)).body.clients).toHaveLength(2);
    });

    it('GET /connections/:id/status', async () => {
        const res = await h.mgmt('GET', `/connections/${conn.id}/status`);
        expect(res.status).toBe(200);
        expect(res.body).toEqual({});
        expect((await h.mgmt('GET', '/connections/con_nope/status')).status).toBe(404);
    });

    it('DELETE /connections/:id/users?email= deletes that user only within the connection', async () => {
        const created = await h.mgmt('POST', '/users', {
            connection: 'Username-Password-Authentication',
            email: 'Carol@Example.com',
            password: PASSWORD,
        });
        expect(created.status).toBe(201);
        const carol = encodeURIComponent(created.body.user_id);
        const alice = encodeURIComponent(tenant.users.alice);

        const noEmail = await h.mgmt('DELETE', `/connections/${tenant.connection.id}/users`);
        expect(noEmail.status).toBe(400);
        expect(noEmail.body.message).toBe("Query parameter 'email' is required");

        const del = await h.mgmt('DELETE', `/connections/${tenant.connection.id}/users?email=carol%40example.com`);
        expect(del.status).toBe(204);
        expect((await h.mgmt('GET', `/users/${carol}`)).status).toBe(404);
        expect((await h.mgmt('GET', `/users/${alice}`)).status).toBe(200);

        // Same email, different connection: nothing is deleted.
        const other = await h.mgmt('DELETE', `/connections/${conn.id}/users?email=alice%40example.com`);
        expect(other.status).toBe(204);
        expect((await h.mgmt('GET', `/users/${alice}`)).status).toBe(200);
        expect(
            (await h.mgmt('DELETE', `/connections/${tenant.connection.id}/users?email=nobody%40example.com`)).status
        ).toBe(204);
        expect((await h.mgmt('DELETE', '/connections/con_nope/users?email=x%40y.z')).status).toBe(404);
    });

    it('DELETE /connections/:id', async () => {
        expect((await h.mgmt('DELETE', `/connections/${conn.id}`)).status).toBe(204);
        expect((await h.mgmt('GET', `/connections/${conn.id}`)).status).toBe(404);
        expect((await h.mgmt('DELETE', `/connections/${conn.id}`)).status).toBe(204);
        expect((await h.mgmt('GET', '/connections')).body).toHaveLength(3);
    });
});
