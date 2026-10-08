import { Router } from 'express';
import type { AppContext } from '../../context.ts';
import { badRequest, notFound } from '../../errors.ts';
import { assertClientsExist, buildConnection, enabledClientsOf } from '../../model/connections.ts';
import { applyFields, ensureBody, optionalStringArray } from '../../model/validate.ts';
import { isPlainObject } from '../../util/merge.ts';
import { pageResponse, paginate, parsePageQuery } from '../../util/pagination.ts';
import { param } from '../util.ts';
import { requireScope } from './auth.ts';

export function connectionRoutes(ctx: AppContext): Router {
    const router = Router();
    const { store } = ctx;

    router.get('/connections', requireScope('read:connections'), (req, res) => {
        const query = req.query as Record<string, unknown>;
        const strategies = Array.isArray(query.strategy)
            ? (query.strategy as string[])
            : typeof query.strategy === 'string'
              ? query.strategy.split(',')
              : undefined;
        const items = store.connections
            .all()
            .filter((c) => !strategies || strategies.includes(String(c.strategy)))
            .filter((c) => !query.name || c.name === query.name)
            .map((c) => applyFields(c, query, ['id']));
        if (query.from !== undefined || query.take !== undefined) {
            // Checkpoint pagination: `from` is the index encoded as a string, `take` the page size.
            const from = Number(query.from ?? 0) || 0;
            const take = Math.min(Number(query.take ?? 50) || 50, 100);
            const slice = items.slice(from, from + take);
            const next = from + take < items.length ? String(from + take) : undefined;
            res.json({ connections: slice, ...(next ? { next } : {}) });
            return;
        }
        const page = parsePageQuery(query);
        res.json(pageResponse(paginate(items, page), 'connections', page));
    });

    router.post('/connections', requireScope('create:connections'), (req, res) => {
        res.status(201).json(store.connections.insert(buildConnection(store, ensureBody(req.body))));
    });

    router.get('/connections/:id', requireScope('read:connections'), (req, res) => {
        const connection = store.connections.require(param(req, 'id'), 'The connection does not exist');
        res.json(applyFields(connection, req.query as Record<string, unknown>, ['id']));
    });

    router.patch('/connections/:id', requireScope('update:connections'), (req, res) => {
        const id = param(req, 'id');
        if (!store.connections.has(id)) throw notFound('The connection does not exist');
        const body = ensureBody(req.body);
        if ('name' in body || 'strategy' in body) {
            throw badRequest("Payload validation error: 'name' and 'strategy' cannot be changed");
        }
        const changes = { ...body };
        delete changes.id;
        const enabled = optionalStringArray(body, 'enabled_clients');
        if (enabled) assertClientsExist(store, enabled);
        if ('options' in changes && !isPlainObject(changes.options)) {
            throw badRequest("Payload validation error: 'options' must be an object");
        }
        res.json(store.connections.patch(id, changes));
    });

    router.delete('/connections/:id', requireScope('delete:connections'), (req, res) => {
        store.connections.delete(param(req, 'id'));
        res.status(204).end();
    });

    router.get('/connections/:id/clients', requireScope('read:connections'), (req, res) => {
        const connection = store.connections.require(param(req, 'id'), 'The connection does not exist');
        const query = req.query as Record<string, unknown>;
        const all = enabledClientsOf(connection).map((client_id) => ({ client_id }));
        const from = Number(query.from ?? 0) || 0;
        const take = Math.min(Number(query.take ?? 50) || 50, 100);
        const slice = all.slice(from, from + take);
        const next = from + take < all.length ? String(from + take) : undefined;
        res.json({ clients: slice, ...(next ? { next } : {}) });
    });

    router.patch('/connections/:id/clients', requireScope('update:connections'), (req, res) => {
        const id = param(req, 'id');
        const connection = store.connections.require(id, 'The connection does not exist');
        const body: unknown = req.body;
        if (!Array.isArray(body)) throw badRequest('Payload validation error: expected an array of clients');
        const enabled = new Set(enabledClientsOf(connection));
        for (const entry of body) {
            if (!isPlainObject(entry) || typeof entry.client_id !== 'string' || typeof entry.status !== 'boolean') {
                throw badRequest("Payload validation error: each entry requires 'client_id' and boolean 'status'");
            }
            assertClientsExist(store, [entry.client_id]);
            if (entry.status) enabled.add(entry.client_id);
            else enabled.delete(entry.client_id);
        }
        store.connections.patch(id, { enabled_clients: [...enabled] });
        res.status(204).end();
    });

    router.get('/connections/:id/status', requireScope('read:connections'), (req, res) => {
        store.connections.require(param(req, 'id'), 'The connection does not exist');
        res.status(200).json({});
    });

    router.delete('/connections/:id/users', requireScope('delete:users'), (req, res) => {
        const connection = store.connections.require(param(req, 'id'), 'The connection does not exist');
        const email = typeof req.query.email === 'string' ? req.query.email.toLowerCase() : undefined;
        if (!email) throw badRequest("Query parameter 'email' is required");
        const user = store.users.find(
            (u) =>
                String(u.email).toLowerCase() === email &&
                Array.isArray(u.identities) &&
                (u.identities as Entity[]).some((i) => i.connection === connection.name)
        );
        if (user) store.users.delete(String(user.user_id));
        res.status(204).end();
    });

    return router;
}

type Entity = Record<string, unknown>;
