import { Router } from 'express';
import type { AppContext } from '../../context.ts';
import { badRequest, notFound } from '../../errors.ts';
import { buildResourceServer, findResourceServer, normalizeScopes } from '../../model/resource-servers.ts';
import { applyFields, ensureBody } from '../../model/validate.ts';
import { pageResponse, paginate, parsePageQuery } from '../../util/pagination.ts';
import { param } from '../util.ts';
import { requireScope } from './auth.ts';

export function resourceServerRoutes(ctx: AppContext): Router {
    const router = Router();
    const { store } = ctx;

    router.get('/resource-servers', requireScope('read:resource_servers'), (req, res) => {
        const query = req.query as Record<string, unknown>;
        const page = parsePageQuery(query);
        const identifiers = typeof query.identifiers === 'string' ? query.identifiers.split(',') : undefined;
        const items = store.resourceServers
            .all()
            .filter((r) => !identifiers || identifiers.includes(String(r.identifier)))
            .map((r) => applyFields(r, query, ['id', 'identifier']));
        res.json(pageResponse(paginate(items, page), 'resource_servers', page));
    });

    router.post('/resource-servers', requireScope('create:resource_servers'), (req, res) => {
        const created = store.resourceServers.insert(buildResourceServer(store, ensureBody(req.body)));
        res.status(201).json(created);
    });

    router.get('/resource-servers/:id', requireScope('read:resource_servers'), (req, res) => {
        const rs = findResourceServer(store, param(req, 'id'));
        if (!rs) throw notFound('The resource server does not exist');
        res.json(applyFields(rs, req.query as Record<string, unknown>, ['id', 'identifier']));
    });

    router.patch('/resource-servers/:id', requireScope('update:resource_servers'), (req, res) => {
        const rs = findResourceServer(store, param(req, 'id'));
        if (!rs) throw notFound('The resource server does not exist');
        const body = ensureBody(req.body);
        if ('identifier' in body && body.identifier !== rs.identifier) {
            throw badRequest("Payload validation error: 'identifier' cannot be changed");
        }
        const changes = { ...body };
        delete changes.identifier;
        if ('scopes' in changes) changes.scopes = normalizeScopes(changes.scopes);
        res.json(store.resourceServers.patch(String(rs.id), changes));
    });

    router.delete('/resource-servers/:id', requireScope('delete:resource_servers'), (req, res) => {
        const rs = findResourceServer(store, param(req, 'id'));
        if (rs && rs.is_system === true) throw badRequest('System resource servers cannot be deleted');
        if (rs) store.resourceServers.delete(String(rs.id));
        res.status(204).end();
    });

    return router;
}
