import { Router } from 'express';
import type { AppContext } from '../../context.ts';
import { applyFields, ensureBody } from '../../model/validate.ts';
import { isPlainObject, mergeShallow } from '../../util/merge.ts';
import { requireScope } from './auth.ts';

export function tenantRoutes(ctx: AppContext): Router {
    const router = Router();
    const { store } = ctx;

    router.get('/tenants/settings', requireScope('read:tenant_settings'), (req, res) => {
        res.json(applyFields(store.tenant, req.query as Record<string, unknown>));
    });

    router.patch('/tenants/settings', requireScope('update:tenant_settings'), (req, res) => {
        const body = ensureBody(req.body);
        const next = { ...store.tenant };
        for (const [key, value] of Object.entries(body)) {
            // Auth0 merges nested settings objects (flags, session_cookie, ...) instead of replacing them.
            next[key] = isPlainObject(value) && isPlainObject(next[key]) ? mergeShallow(next[key], value) : value;
        }
        store.tenant = next;
        res.json(store.tenant);
    });

    return router;
}
