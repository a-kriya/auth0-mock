import { readFileSync } from 'node:fs';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { Snapshot } from '../src/index.ts';
import { decodeJwt, startMock, type Harness } from './helpers.ts';

const seed = JSON.parse(readFileSync(new URL('../examples/seed.json', import.meta.url), 'utf8')) as Snapshot;

describe('declarative seed import', () => {
    let h: Harness;
    beforeAll(async () => {
        h = await startMock();
        h.mock.importSeed(seed);
    });
    afterAll(() => h.close());

    it('creates roles with the given ids and resolves role permissions by name', async () => {
        const roles = await h.mgmt('GET', '/roles');
        expect(roles.body.map((r: { id: string; name: string }) => [r.id, r.name])).toEqual([
            ['rol_admin000000000', 'Administrator'],
            ['rol_reader00000000', 'Reader'],
        ]);
        const perms = await h.mgmt('GET', '/roles/rol_reader00000000/permissions');
        expect(perms.body.map((p: { permission_name: string }) => p.permission_name)).toEqual(['read:things']);
    });

    it('hashes plain passwords, assigns roles by name and keeps provided client ids and secrets', async () => {
        const users = await h.mgmt('GET', '/users');
        const alice = users.body.find((u: { email: string }) => u.email === 'alice@example.com');
        expect(alice.user_id).toBe('auth0|alice');
        expect(alice.password_hash).toBeUndefined();
        expect(alice.password).toBeUndefined();
        const aliceRoles = await h.mgmt('GET', `/users/${encodeURIComponent(alice.user_id)}/roles`);
        expect(aliceRoles.body.map((r: { name: string }) => r.name)).toEqual(['Administrator']);
        const backend = await h.mgmt('GET', '/clients/exampleBackendClientId0000000000');
        expect(backend.body).toMatchObject({ name: 'Example Backend', client_secret: 'example-backend-secret' });
    });

    it('deploys actions flagged with deploy and binds them by name', async () => {
        const bindings = await h.mgmt('GET', '/actions/triggers/post-login/bindings');
        expect(bindings.body.bindings.map((b: { display_name: string }) => b.display_name)).toEqual([
            'Add roles claim',
        ]);
        const actions = await h.mgmt('GET', '/actions/actions');
        expect(actions.body.actions[0]).toMatchObject({ name: 'Add roles claim', all_changes_deployed: true });
    });

    it('lets seeded users log in with RBAC scopes and the seeded action running', async () => {
        const res = await h.token({
            grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
            realm: 'Username-Password-Authentication',
            client_id: 'exampleSpaClientId00000000000000',
            audience: 'https://api.example.com',
            username: 'bob@example.com',
            password: 'Passw0rd!Passw0rd!',
            scope: 'openid read:things write:things',
        });
        expect(res.status).toBe(200);
        expect(res.body.scope).toBe('openid read:things');
        const claims = decodeJwt(res.body.access_token);
        expect(claims['https://example.com/roles']).toEqual(['Reader']);
        expect(claims.permissions).toEqual(['read:things']);
        expect(res.body.expires_in).toBe(900);
    });

    it('re-importing the same seed replaces entities instead of duplicating them', async () => {
        h.mock.importSeed(seed);
        const roles = await h.mgmt('GET', '/roles');
        expect(roles.body).toHaveLength(2);
        const users = await h.mgmt('GET', '/users');
        expect(users.body).toHaveLength(2);
        const clients = await h.mgmt('GET', '/clients');
        expect(clients.body.map((c: { name: string }) => c.name).sort()).toEqual(['Example Backend', 'Example SPA']);
    });

    it('boots from the seed when configured and reloads it on reset', async () => {
        const seeded = await startMock({ seed: new URL('../examples/seed.json', import.meta.url).pathname });
        try {
            const health = await seeded.fetch('/__mock/health').then((r) => r.json() as Promise<{ users: number }>);
            expect(health.users).toBe(2);
            await seeded.mgmt('DELETE', '/users/auth0%7Cbob');
            expect((await seeded.mgmt('GET', '/users')).body).toHaveLength(1);
            await seeded.fetch('/__mock/reset', { method: 'POST' });
            expect((await seeded.mgmt('GET', '/users')).body).toHaveLength(2);
        } finally {
            await seeded.close();
        }
    });
});
