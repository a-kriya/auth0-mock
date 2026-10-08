import { Router } from 'express';
import type { AppContext } from '../../context.ts';
import { badRequest, notFound } from '../../errors.ts';
import {
    addRolePermissions,
    buildRole,
    describePermissions,
    parsePermissions,
    removeRolePermissions,
} from '../../model/roles.ts';
import { ensureBody, optionalString } from '../../model/validate.ts';
import { pageResponse, paginate, parsePageQuery } from '../../util/pagination.ts';
import { param } from '../util.ts';
import { requireScope } from './auth.ts';

export function roleRoutes(ctx: AppContext): Router {
    const router = Router();
    const { store } = ctx;

    router.get('/roles', requireScope('read:roles'), (req, res) => {
        const query = req.query as Record<string, unknown>;
        const page = parsePageQuery(query);
        const filter = typeof query.name_filter === 'string' ? query.name_filter.toLowerCase() : undefined;
        const items = store.roles.all().filter((r) => !filter || String(r.name).toLowerCase().includes(filter));
        res.json(pageResponse(paginate(items, page), 'roles', page));
    });

    router.post('/roles', requireScope('create:roles'), (req, res) => {
        res.status(200).json(store.roles.insert(buildRole(store, ensureBody(req.body))));
    });

    router.get('/roles/:id', requireScope('read:roles'), (req, res) => {
        res.json(store.roles.require(param(req, 'id'), 'The role does not exist'));
    });

    router.patch('/roles/:id', requireScope('update:roles'), (req, res) => {
        const body = ensureBody(req.body);
        const name = optionalString(body, 'name');
        if (name && store.roles.find((r) => r.name === name && r.id !== param(req, 'id'))) {
            throw badRequest('A role with the same name already exists', 'role_conflict');
        }
        const changes: Record<string, unknown> = {};
        if (name !== undefined) changes.name = name;
        const description = optionalString(body, 'description');
        if (description !== undefined) changes.description = description;
        res.json(store.roles.patch(param(req, 'id'), changes));
    });

    router.delete('/roles/:id', requireScope('delete:roles'), (req, res) => {
        store.roles.delete(param(req, 'id'));
        store.rolePermissions.delete(param(req, 'id'));
        for (const [userId, roles] of store.userRoles) {
            store.userRoles.set(
                userId,
                roles.filter((r) => r !== param(req, 'id'))
            );
        }
        res.status(204).end();
    });

    router.get('/roles/:id/permissions', requireScope('read:roles'), (req, res) => {
        if (!store.roles.has(param(req, 'id'))) throw notFound('The role does not exist');
        const page = parsePageQuery(req.query as Record<string, unknown>);
        const items = describePermissions(store, store.rolePermissions.get(param(req, 'id')) ?? []);
        res.json(pageResponse(paginate(items, page), 'permissions', page));
    });

    router.post('/roles/:id/permissions', requireScope('update:roles'), (req, res) => {
        addRolePermissions(store, param(req, 'id'), parsePermissions(ensureBody(req.body)));
        res.status(201).json({});
    });

    router.delete('/roles/:id/permissions', requireScope('update:roles'), (req, res) => {
        removeRolePermissions(store, param(req, 'id'), parsePermissions(ensureBody(req.body)));
        res.status(204).end();
    });

    router.get('/roles/:id/users', requireScope('read:roles', 'read:users'), (req, res) => {
        if (!store.roles.has(param(req, 'id'))) throw notFound('The role does not exist');
        const page = parsePageQuery(req.query as Record<string, unknown>);
        const items = [...store.userRoles.entries()]
            .filter(([, roles]) => roles.includes(param(req, 'id')))
            .flatMap(([userId]) => {
                const user = store.users.get(userId);
                return user
                    ? [{ user_id: user.user_id, email: user.email, picture: user.picture, name: user.name }]
                    : [];
            });
        res.json(pageResponse(paginate(items, page), 'users', page));
    });

    router.post('/roles/:id/users', requireScope('update:roles', 'update:users'), (req, res) => {
        if (!store.roles.has(param(req, 'id'))) throw notFound('The role does not exist');
        const body = ensureBody(req.body);
        if (!Array.isArray(body.users) || body.users.some((u) => typeof u !== 'string')) {
            throw badRequest("Payload validation error: 'users' must be an array of user ids");
        }
        for (const userId of body.users as string[]) {
            if (!store.users.has(userId)) throw badRequest(`User '${userId}' does not exist`);
            const roles = store.userRoles.get(userId) ?? [];
            if (!roles.includes(param(req, 'id'))) roles.push(param(req, 'id'));
            store.userRoles.set(userId, roles);
        }
        res.status(200).json({});
    });

    return router;
}
