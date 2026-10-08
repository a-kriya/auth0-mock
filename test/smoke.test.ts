import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { provisionTenant, startMock, type Harness, type Tenant } from './helpers.ts';

describe('smoke', () => {
    let h: Harness;
    let tenant: Tenant;
    beforeAll(async () => {
        h = await startMock();
        tenant = await provisionTenant(h);
    });
    afterAll(() => h.close());

    it('serves JWKS and health over http', async () => {
        const jwks = (await h.fetch('/.well-known/jwks.json').then((r) => r.json())) as {
            keys: Record<string, unknown>[];
        };
        expect(jwks.keys[0]).toMatchObject({ kty: 'RSA', alg: 'RS256', use: 'sig' });
        const health = (await h.fetch('/__mock/health').then((r) => r.json())) as Record<string, unknown>;
        expect(health).toMatchObject({ status: 'ok', issuer: h.issuer, users: 2 });
    });

    it('provisions a tenant through the Management API', () => {
        expect(tenant.users.alice).toBe('auth0|alice');
        expect(tenant.clients.spa.client_id).toHaveLength(32);
    });
});
