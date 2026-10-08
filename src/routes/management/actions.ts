import { Router } from 'express';
import type { AppContext } from '../../context.ts';
import { notFound } from '../../errors.ts';
import {
    TRIGGERS,
    buildAction,
    deleteAction,
    deployAction,
    publicAction,
    publicVersion,
    replaceBindings,
    updateAction,
} from '../../model/actions.ts';
import { ensureBody } from '../../model/validate.ts';
import type { Entity } from '../../store/collection.ts';
import { parseBoolean, parsePageQuery } from '../../util/pagination.ts';
import { param } from '../util.ts';
import { requireScope } from './auth.ts';

/**
 * Actions endpoints return `{ <items>, total, per_page, page }` objects. go-auth0 (and therefore the
 * Terraform provider) detects the last page from `start`/`limit`, so both conventions are included.
 */
function actionsPage<T>(items: T[], query: Record<string, unknown>, key: string): Record<string, unknown> {
    const page = parsePageQuery(query, { defaultPerPage: 20, maxPerPage: 100 });
    const start = page.page * page.perPage;
    const slice = items.slice(start, start + page.perPage);
    return {
        [key]: slice,
        total: items.length,
        per_page: page.perPage,
        page: page.page,
        start,
        limit: page.perPage,
        length: slice.length,
    };
}

export function actionRoutes(ctx: AppContext): Router {
    const router = Router();
    const { store } = ctx;

    router.get('/actions/actions', requireScope('read:actions'), (req, res) => {
        const query = req.query as Record<string, unknown>;
        const deployed = parseBoolean(query.deployed);
        const items = store.actions
            .all()
            .filter((a) => !query.triggerId || (a.supported_triggers as Entity[]).some((t) => t.id === query.triggerId))
            .filter((a) => !query.actionName || a.name === query.actionName)
            .filter((a) => deployed === undefined || Boolean(a.deployed_version) === deployed)
            .map(publicAction);
        res.json(actionsPage(items, query, 'actions'));
    });

    router.post('/actions/actions', requireScope('create:actions'), (req, res) => {
        res.status(201).json(publicAction(store.actions.insert(buildAction(store, ensureBody(req.body)))));
    });

    router.get('/actions/actions/:id', requireScope('read:actions'), (req, res) => {
        res.json(publicAction(store.actions.require(param(req, 'id'), 'The action does not exist')));
    });

    router.patch('/actions/actions/:id', requireScope('update:actions'), (req, res) => {
        res.json(publicAction(updateAction(store, param(req, 'id'), ensureBody(req.body))));
    });

    router.delete('/actions/actions/:id', requireScope('delete:actions'), (req, res) => {
        deleteAction(store, param(req, 'id'), parseBoolean(req.query.force) ?? false);
        res.status(204).end();
    });

    router.post('/actions/actions/:id/deploy', requireScope('create:actions', 'update:actions'), (req, res) => {
        res.json(publicVersion(deployAction(store, param(req, 'id'))));
    });

    router.get('/actions/actions/:id/versions', requireScope('read:actions'), (req, res) => {
        const id = param(req, 'id');
        if (!store.actions.has(id)) throw notFound('The action does not exist');
        const versions = [...(store.actionVersions.get(id) ?? [])].reverse().map(publicVersion);
        res.json(actionsPage(versions, req.query as Record<string, unknown>, 'versions'));
    });

    router.get('/actions/actions/:id/versions/:versionId', requireScope('read:actions'), (req, res) => {
        const version = (store.actionVersions.get(param(req, 'id')) ?? []).find(
            (v) => v.id === param(req, 'versionId')
        );
        if (!version) throw notFound('The action version does not exist');
        res.json(publicVersion(version));
    });

    router.post('/actions/actions/:id/versions/:versionId/deploy', requireScope('update:actions'), (req, res) => {
        const id = param(req, 'id');
        const target = (store.actionVersions.get(id) ?? []).find((v) => v.id === param(req, 'versionId'));
        if (!target) throw notFound('The action version does not exist');
        // Rolling back republishes the old code as a new version.
        store.actions.patch(id, { code: target.code, dependencies: target.dependencies, runtime: target.runtime });
        res.json(publicVersion(deployAction(store, id)));
    });

    router.get('/actions/triggers', requireScope('read:actions'), (_req, res) => {
        res.json({ triggers: TRIGGERS });
    });

    router.get('/actions/triggers/:trigger/bindings', requireScope('read:actions'), (req, res) => {
        const trigger = param(req, 'trigger');
        if (!TRIGGERS.some((t) => t.id === trigger)) throw notFound(`Unknown trigger '${trigger}'`, 'invalid_trigger');
        const bindings = store.triggerBindings.get(trigger) ?? [];
        res.json(actionsPage(bindings, req.query as Record<string, unknown>, 'bindings'));
    });

    router.patch('/actions/triggers/:trigger/bindings', requireScope('update:actions'), (req, res) => {
        const body = ensureBody(req.body);
        res.json({ bindings: replaceBindings(store, param(req, 'trigger'), body.bindings) });
    });

    router.get('/actions/status', requireScope('read:actions'), (_req, res) => {
        res.json({ status: 'active' });
    });

    return router;
}
