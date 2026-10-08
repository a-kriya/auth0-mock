import { Router } from 'express';
import { tenantName, type AppContext } from '../../context.ts';
import { notFound } from '../../errors.ts';
import { generateId } from '../../store/ids.ts';
import { buildClient, buildClientGrant } from '../../model/clients.ts';
import { applyFields, ensureBody, optionalStringArray } from '../../model/validate.ts';
import { parseBoolean, pageResponse, paginate, parsePageQuery } from '../../util/pagination.ts';
import { param } from '../util.ts';
import { requireScope } from './auth.ts';

export function clientRoutes(ctx: AppContext): Router {
    const router = Router();
    const { store } = ctx;
    const clientContext = () => ({
        tenantName: tenantName(ctx),
        signingCertificate: ctx.tls?.ca ?? '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
    });

    router.get('/clients', requireScope('read:clients'), (req, res) => {
        const query = req.query as Record<string, unknown>;
        const page = parsePageQuery(query);
        const appTypes = typeof query.app_type === 'string' ? query.app_type.split(',') : undefined;
        const isGlobal = parseBoolean(query.is_global);
        const isFirstParty = parseBoolean(query.is_first_party);
        const q = typeof query.q === 'string' ? query.q : undefined;
        const nameMatch = q?.match(/^name:"?([^"]+)"?$/);
        const items = store.clients
            .all()
            .filter((c) => !appTypes || appTypes.includes(String(c.app_type)))
            .filter((c) => isGlobal === undefined || c.global === isGlobal)
            .filter((c) => isFirstParty === undefined || c.is_first_party === isFirstParty)
            .filter((c) => !nameMatch || String(c.name).toLowerCase() === nameMatch[1]?.toLowerCase())
            .map((c) => applyFields(c, query, ['client_id']));
        res.json(pageResponse(paginate(items, page), 'clients', page));
    });

    router.post('/clients', requireScope('create:clients'), (req, res) => {
        const created = store.clients.insert(buildClient(store, ensureBody(req.body), clientContext()));
        res.status(201).json(created);
    });

    router.get('/clients/:id', requireScope('read:clients'), (req, res) => {
        const client = store.clients.require(param(req, 'id'), 'The client does not exist');
        res.json(applyFields(client, req.query as Record<string, unknown>, ['client_id']));
    });

    router.patch('/clients/:id', requireScope('update:clients'), (req, res) => {
        if (!store.clients.has(param(req, 'id'))) throw notFound('The client does not exist');
        const body = ensureBody(req.body);
        const changes = { ...body };
        delete changes.client_id;
        delete changes.tenant;
        delete changes.global;
        delete changes.signing_keys;
        res.json(store.clients.patch(param(req, 'id'), changes));
    });

    router.delete('/clients/:id', requireScope('delete:clients'), (req, res) => {
        store.clients.delete(param(req, 'id'));
        for (const grant of store.clientGrants.filter((g) => g.client_id === param(req, 'id'))) {
            store.clientGrants.delete(String(grant.id));
        }
        res.status(204).end();
    });

    router.post('/clients/:id/rotate-secret', requireScope('update:client_keys'), (req, res) => {
        if (!store.clients.has(param(req, 'id'))) throw notFound('The client does not exist');
        res.json(store.clients.patch(param(req, 'id'), { client_secret: generateId.clientSecret() }));
    });

    // --- Client grants ---

    router.get('/client-grants', requireScope('read:client_grants'), (req, res) => {
        const query = req.query as Record<string, unknown>;
        const page = parsePageQuery(query);
        const items = store.clientGrants
            .all()
            .filter((g) => !query.client_id || g.client_id === query.client_id)
            .filter((g) => !query.audience || g.audience === query.audience);
        res.json(pageResponse(paginate(items, page), 'client_grants', page));
    });

    router.post('/client-grants', requireScope('create:client_grants'), (req, res) => {
        res.status(201).json(store.clientGrants.insert(buildClientGrant(store, ensureBody(req.body))));
    });

    router.get('/client-grants/:id', requireScope('read:client_grants'), (req, res) => {
        res.json(store.clientGrants.require(param(req, 'id'), 'The client grant does not exist'));
    });

    router.patch('/client-grants/:id', requireScope('update:client_grants'), (req, res) => {
        store.clientGrants.require(param(req, 'id'), 'The client grant does not exist');
        const body = ensureBody(req.body);
        const scope = optionalStringArray(body, 'scope');
        const changes: Record<string, unknown> = {};
        if (scope) changes.scope = scope;
        for (const key of ['organization_usage', 'allow_any_organization', 'authorization_details_types']) {
            if (key in body) changes[key] = body[key];
        }
        res.json(store.clientGrants.patch(param(req, 'id'), changes));
    });

    router.delete('/client-grants/:id', requireScope('delete:client_grants'), (req, res) => {
        store.clientGrants.delete(param(req, 'id'));
        res.status(204).end();
    });

    return router;
}
