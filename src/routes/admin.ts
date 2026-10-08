import { Router } from 'express';
import type { AppContext } from '../context.ts';
import { badRequest, notFound } from '../errors.ts';
import type { Snapshot } from '../store/store.ts';
import { isPlainObject } from '../util/merge.ts';
import { param } from './util.ts';

export interface AdminHooks {
    /** Reset the store to its boot state (defaults + seed). */
    reset(): Promise<void> | void;
    /** Import a snapshot/seed document. */
    importSeed(snapshot: Snapshot): Promise<void> | void;
}

/** `/__mock` control plane used by test harnesses; never part of a real tenant. */
export function adminRoutes(ctx: AppContext, hooks: AdminHooks): Router {
    const router = Router();
    const { store } = ctx;

    router.get('/health', (_req, res) => {
        res.json({ status: 'ok', issuer: ctx.issuer, tls: ctx.config.tls, users: store.users.size });
    });

    router.get('/ca.pem', (_req, res) => {
        if (!ctx.tls?.ca) throw notFound('No emulator-managed CA (tls is not "auto")');
        res.type('application/x-pem-file').send(ctx.tls.ca);
    });

    router.post('/reset', async (_req, res) => {
        await hooks.reset();
        res.json({ status: 'ok' });
    });

    router.get('/snapshot', (_req, res) => {
        res.json(store.export());
    });

    router.post('/snapshot', async (req, res) => {
        if (!isPlainObject(req.body)) throw badRequest('Expected a snapshot JSON object');
        await hooks.importSeed(req.body as unknown as Snapshot);
        res.json({ status: 'ok' });
    });

    router.post('/users/:id/unblock', (req, res) => {
        if (!store.users.has(param(req, 'id'))) throw notFound('The user does not exist');
        store.userBlocks.delete(param(req, 'id'));
        const prefix = `${param(req, 'id')}\u0000`;
        const stale = [...store.loginAttempts.keys()].filter((key) => key.startsWith(prefix));
        for (const key of stale) store.loginAttempts.delete(key);
        res.json({ status: 'ok' });
    });

    return router;
}
