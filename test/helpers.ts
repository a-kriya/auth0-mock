import { createAuth0Mock, type Auth0Mock, type Auth0MockServer, type ConfigInput } from '../src/index.ts';

export const ADMIN_TOKEN = 'test-admin-token';
export const PASSWORD = 'Passw0rd!Passw0rd!';
export const API_AUDIENCE = 'https://api.example.com';

export interface JsonResponse<T = any> {
    status: number;
    body: T;
    headers: Headers;
}

export interface Harness {
    mock: Auth0Mock;
    server: Auth0MockServer;
    /** Base URL without trailing slash. */
    base: string;
    /** Issuer with trailing slash. */
    issuer: string;
    /** Management API audience (`<issuer>api/v2/`). */
    managementAudience: string;
    /** Raw fetch against the emulator. */
    fetch(path: string, init?: RequestInit): Promise<Response>;
    /** JSON request; `body` objects are serialised. Adds the admin bearer unless `auth` is given (null disables). */
    mgmt<T = any>(method: string, path: string, body?: unknown, auth?: string | null): Promise<JsonResponse<T>>;
    /** POST /oauth/token with a JSON body. */
    token<T = any>(body: Record<string, unknown>): Promise<JsonResponse<T>>;
    close(): Promise<void>;
}

/** Boot an emulator on a random port over plain HTTP (no certificate trust needed in tests). */
export async function startMock(overrides: Partial<ConfigInput> = {}): Promise<Harness> {
    const mock = await createAuth0Mock({
        tls: 'off',
        port: 0,
        adminToken: ADMIN_TOKEN,
        logLevel: 'silent',
        ...overrides,
    });
    const server = await mock.listen();
    const base = server.url;
    const doFetch = (path: string, init?: RequestInit) => fetch(`${base}${path}`, { redirect: 'manual', ...init });
    const parse = async (res: Response): Promise<JsonResponse> => {
        const text = await res.text();
        let body: unknown = text;
        try {
            body = text ? JSON.parse(text) : undefined;
        } catch {
            // keep text
        }
        return { status: res.status, body, headers: res.headers };
    };
    return {
        mock,
        server,
        base,
        issuer: server.issuer,
        managementAudience: `${server.issuer}api/v2/`,
        fetch: doFetch,
        async mgmt(method, path, body, auth = ADMIN_TOKEN) {
            const headers: Record<string, string> = { accept: 'application/json' };
            if (body !== undefined) headers['content-type'] = 'application/json';
            if (auth) headers.authorization = `Bearer ${auth}`;
            const init: RequestInit = { method, headers };
            if (body !== undefined) init.body = JSON.stringify(body);
            return parse(await doFetch(`/api/v2${path}`, init));
        },
        async token(body) {
            return parse(
                await doFetch('/oauth/token', {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    body: JSON.stringify(body),
                })
            );
        },
        close: () => server.close(),
    };
}

export function decodeJwt(token: string): Record<string, any> {
    const [, payload] = token.split('.');
    return JSON.parse(Buffer.from(payload!, 'base64url').toString('utf8'));
}

export interface Tenant {
    connection: { id: string; name: string };
    resourceServer: { id: string; identifier: string };
    roles: { admin: string; reader: string };
    clients: {
        spa: { client_id: string };
        backend: { client_id: string; client_secret: string };
    };
    users: { alice: string; bob: string };
}

/**
 * Provision a small tenant through the Management API, with the payload shapes the Terraform provider
 * sends: a database connection, an RBAC resource server with three scopes, two roles, a SPA client
 * (code/refresh/password-realm grants), a backend client with grants to the API and to the Management
 * API, and two users (alice: Admin, bob: Reader).
 */
export async function provisionTenant(h: Harness): Promise<Tenant> {
    const ok = <T>(r: JsonResponse<T>, ...expected: number[]): T => {
        if (!expected.includes(r.status)) throw new Error(`Unexpected ${r.status}: ${JSON.stringify(r.body)}`);
        return r.body;
    };
    const connection = ok(
        await h.mgmt('POST', '/connections', {
            name: 'Username-Password-Authentication',
            strategy: 'auth0',
            options: { disable_signup: true, brute_force_protection: true, password_policy: 'good' },
        }),
        201
    );
    ok(await h.mgmt('PATCH', '/tenants/settings', { default_directory: 'Username-Password-Authentication' }), 200);
    const resourceServer = ok(
        await h.mgmt('POST', '/resource-servers', {
            name: 'Example API',
            identifier: API_AUDIENCE,
            signing_alg: 'RS256',
            enforce_policies: true,
            token_dialect: 'access_token_authz',
            token_lifetime: 900,
            allow_offline_access: true,
        }),
        201
    );
    ok(
        await h.mgmt('PATCH', `/resource-servers/${encodeURIComponent(API_AUDIENCE)}`, {
            scopes: [
                { value: 'read:things', description: 'Read things' },
                { value: 'write:things', description: 'Write things' },
                { value: 'admin:things', description: 'Administer things' },
            ],
        }),
        200
    );
    const admin = ok(await h.mgmt('POST', '/roles', { name: 'Admin', description: 'Full access' }), 200);
    const reader = ok(await h.mgmt('POST', '/roles', { name: 'Reader', description: 'Read only' }), 200);
    ok(
        await h.mgmt('POST', `/roles/${admin.id}/permissions`, {
            permissions: ['read:things', 'write:things', 'admin:things'].map((permission_name) => ({
                permission_name,
                resource_server_identifier: API_AUDIENCE,
            })),
        }),
        201
    );
    ok(
        await h.mgmt('POST', `/roles/${reader.id}/permissions`, {
            permissions: [{ permission_name: 'read:things', resource_server_identifier: API_AUDIENCE }],
        }),
        201
    );
    const spa = ok(
        await h.mgmt('POST', '/clients', {
            name: 'Example SPA',
            app_type: 'spa',
            callbacks: ['http://localhost:3000', 'http://localhost:3000/callback'],
            allowed_logout_urls: ['http://localhost:3000'],
            web_origins: ['http://localhost:3000'],
            oidc_conformant: true,
            grant_types: [
                'authorization_code',
                'refresh_token',
                'http://auth0.com/oauth/grant-type/password-realm',
                'password',
            ],
            jwt_configuration: { alg: 'RS256', lifetime_in_seconds: 36000 },
            refresh_token: { rotation_type: 'rotating', expiration_type: 'expiring', token_lifetime: 43200 },
        }),
        201
    );
    ok(await h.mgmt('PATCH', `/clients/${spa.client_id}`, { token_endpoint_auth_method: 'none' }), 200);
    const backend = ok(
        await h.mgmt('POST', '/clients', {
            name: 'Example Backend',
            app_type: 'non_interactive',
            oidc_conformant: true,
            grant_types: ['client_credentials'],
            jwt_configuration: { alg: 'RS256' },
        }),
        201
    );
    ok(
        await h.mgmt('POST', '/client-grants', {
            client_id: backend.client_id,
            audience: API_AUDIENCE,
            scope: ['read:things'],
        }),
        201
    );
    ok(
        await h.mgmt('POST', '/client-grants', {
            client_id: backend.client_id,
            audience: h.managementAudience,
            scope: ['read:users', 'create:users', 'update:users', 'read:roles'],
        }),
        201
    );
    ok(
        await h.mgmt('PATCH', `/connections/${connection.id}/clients`, [
            { client_id: spa.client_id, status: true },
            { client_id: backend.client_id, status: true },
        ]),
        204
    );
    const alice = ok(
        await h.mgmt('POST', '/users', {
            connection: 'Username-Password-Authentication',
            user_id: 'alice',
            email: 'alice@example.com',
            email_verified: true,
            name: 'Alice Example',
            given_name: 'Alice',
            family_name: 'Example',
            password: PASSWORD,
            app_metadata: { tenantIds: ['T1'] },
        }),
        201
    );
    const bob = ok(
        await h.mgmt('POST', '/users', {
            connection: 'Username-Password-Authentication',
            user_id: 'bob',
            email: 'bob@example.com',
            email_verified: true,
            name: 'Bob Example',
            password: PASSWORD,
        }),
        201
    );
    ok(await h.mgmt('POST', `/users/${encodeURIComponent(alice.user_id)}/roles`, { roles: [admin.id] }), 204);
    ok(await h.mgmt('POST', `/users/${encodeURIComponent(bob.user_id)}/roles`, { roles: [reader.id] }), 204);
    return {
        connection: { id: connection.id, name: connection.name },
        resourceServer: { id: resourceServer.id, identifier: API_AUDIENCE },
        roles: { admin: admin.id, reader: reader.id },
        clients: {
            spa: { client_id: spa.client_id },
            backend: { client_id: backend.client_id, client_secret: backend.client_secret },
        },
        users: { alice: alice.user_id, bob: bob.user_id },
    };
}

/** Upload and deploy a post-login Action, then bind it to the trigger (appending to existing bindings). */
export async function deployPostLoginAction(
    h: Harness,
    name: string,
    code: string,
    secrets: Array<{ name: string; value: string }> = []
) {
    const created = await h.mgmt('POST', '/actions/actions', {
        name,
        supported_triggers: [{ id: 'post-login', version: 'v3' }],
        code,
        runtime: 'node22',
        dependencies: [{ name: 'auth0', version: '4.3.1' }],
        secrets,
    });
    if (created.status !== 201) throw new Error(`action create failed: ${JSON.stringify(created.body)}`);
    const deployed = await h.mgmt('POST', `/actions/actions/${created.body.id}/deploy`);
    if (deployed.status !== 200) throw new Error(`deploy failed: ${JSON.stringify(deployed.body)}`);
    const current = await h.mgmt('GET', '/actions/triggers/post-login/bindings');
    const refs = [
        ...(current.body.bindings as Array<{ action: { id: string }; display_name: string }>).map((b) => ({
            ref: { type: 'action_id', value: b.action.id },
            display_name: b.display_name,
        })),
        { ref: { type: 'action_id', value: created.body.id }, display_name: name },
    ];
    const bound = await h.mgmt('PATCH', '/actions/triggers/post-login/bindings', { bindings: refs });
    if (bound.status !== 200) throw new Error(`bind failed: ${JSON.stringify(bound.body)}`);
    return created.body as { id: string };
}
