import { Router } from 'express';
import type { AppContext } from '../../context.ts';
import { badRequest, mgmtError, notFound } from '../../errors.ts';
import { QuerySyntaxError, compileQuery } from '../../lucene.ts';
import { describePermissions, parsePermissions, assertPermissionsExist } from '../../model/roles.ts';
import { buildUser, deleteUser, findUserByEmail, publicUser, userPatchChanges } from '../../model/users.ts';
import { applyFields, ensureBody, optionalStringArray } from '../../model/validate.ts';
import type { Entity } from '../../store/collection.ts';
import type { Permission } from '../../store/store.ts';
import { getPath } from '../../util/merge.ts';
import { pageResponse, paginate, parsePageQuery } from '../../util/pagination.ts';
import { param } from '../util.ts';
import { requireScope } from './auth.ts';

function sortUsers(users: Entity[], sort: unknown): Entity[] {
    if (typeof sort !== 'string' || !sort.includes(':')) return users;
    const [field, dir] = sort.split(':');
    const direction = dir === '-1' ? -1 : 1;
    const key = (u: Entity) => getPath(u, field ?? '')[0];
    return [...users].sort((a, b) => {
        const x = key(a);
        const y = key(b);
        if (x === undefined || x === null) return y === undefined || y === null ? 0 : 1;
        if (y === undefined || y === null) return -1;
        if (typeof x === 'number' && typeof y === 'number') return (x - y) * direction;
        return String(x).localeCompare(String(y)) * direction;
    });
}

export function userRoutes(ctx: AppContext): Router {
    const router = Router();
    const { store } = ctx;
    const view = (u: Entity) => publicUser(store, u);

    router.get('/users', requireScope('read:users'), (req, res) => {
        const query = req.query as Record<string, unknown>;
        const page = parsePageQuery(query, { defaultPerPage: 50, maxPerPage: 100 });
        let predicate = (_u: Entity) => true;
        if (typeof query.q === 'string' && query.q.trim() !== '') {
            try {
                predicate = compileQuery(query.q) as (u: Entity) => boolean;
            } catch (error) {
                if (error instanceof QuerySyntaxError) {
                    throw mgmtError(400, `Query validation error: ${error.message}`, 'invalid_query_string');
                }
                throw error;
            }
        }
        const connection = typeof query.connection === 'string' ? query.connection : undefined;
        const items = sortUsers(
            store.users
                .all()
                .map(view)
                .filter((u) => !connection || (u.identities as Entity[]).some((i) => i.connection === connection))
                .filter(predicate),
            query.sort
        ).map((u) => applyFields(u, query, ['user_id']));
        res.json(pageResponse(paginate(items, page), 'users', page));
    });

    router.post('/users', requireScope('create:users'), (req, res) => {
        res.status(201).json(view(store.users.insert(buildUser(store, ensureBody(req.body)))));
    });

    router.get('/users-by-email', requireScope('read:users'), (req, res) => {
        const query = req.query as Record<string, unknown>;
        if (typeof query.email !== 'string' || !query.email) throw badRequest("Query parameter 'email' is required");
        const wanted = query.email.toLowerCase();
        const items = store.users
            .filter((u) => typeof u.email === 'string' && u.email.toLowerCase() === wanted)
            .map(view)
            .map((u) => applyFields(u, query, ['user_id']));
        res.json(items);
    });

    router.get('/users/:id', requireScope('read:users'), (req, res) => {
        const user = store.users.require(param(req, 'id'), 'The user does not exist.');
        res.json(applyFields(view(user), req.query as Record<string, unknown>, ['user_id']));
    });

    router.patch('/users/:id', requireScope('update:users', 'update:users_app_metadata'), (req, res) => {
        const id = param(req, 'id');
        const user = store.users.require(id, 'The user does not exist.');
        const changes = userPatchChanges(store, user, ensureBody(req.body));
        res.json(view(store.users.patch(id, changes)));
    });

    router.delete('/users/:id', requireScope('delete:users'), (req, res) => {
        deleteUser(store, param(req, 'id'));
        res.status(204).end();
    });

    // --- Roles ---

    router.get('/users/:id/roles', requireScope('read:users', 'read:roles'), (req, res) => {
        const id = param(req, 'id');
        if (!store.users.has(id)) throw notFound('The user does not exist.');
        const page = parsePageQuery(req.query as Record<string, unknown>);
        res.json(pageResponse(paginate(store.rolesOf(id), page), 'roles', page));
    });

    const parseRoleIds = (body: Entity): string[] => {
        const roles = optionalStringArray(body, 'roles');
        if (!roles || roles.length === 0)
            throw badRequest("Payload validation error: 'roles' must be a non-empty array");
        for (const roleId of roles) {
            if (!store.roles.has(roleId)) throw badRequest(`Role '${roleId}' does not exist`, 'inexistent_role');
        }
        return roles;
    };

    router.post('/users/:id/roles', requireScope('update:users'), (req, res) => {
        const id = param(req, 'id');
        if (!store.users.has(id)) throw notFound('The user does not exist.');
        const current = store.userRoles.get(id) ?? [];
        for (const roleId of parseRoleIds(ensureBody(req.body))) if (!current.includes(roleId)) current.push(roleId);
        store.userRoles.set(id, current);
        res.status(204).end();
    });

    router.delete('/users/:id/roles', requireScope('update:users'), (req, res) => {
        const id = param(req, 'id');
        if (!store.users.has(id)) throw notFound('The user does not exist.');
        const remove = new Set(parseRoleIds(ensureBody(req.body)));
        store.userRoles.set(
            id,
            (store.userRoles.get(id) ?? []).filter((r) => !remove.has(r))
        );
        res.status(204).end();
    });

    // --- Permissions ---

    router.get('/users/:id/permissions', requireScope('read:users'), (req, res) => {
        const id = param(req, 'id');
        if (!store.users.has(id)) throw notFound('The user does not exist.');
        const page = parsePageQuery(req.query as Record<string, unknown>);
        const direct = store.userPermissions.get(id) ?? [];
        const items = describePermissions(store, store.permissionsOf(id)).map((p) => {
            const isDirect = direct.some(
                (d) =>
                    d.permission_name === p.permission_name &&
                    d.resource_server_identifier === p.resource_server_identifier
            );
            const role = isDirect
                ? undefined
                : store
                      .rolesOf(id)
                      .find((r) =>
                          (store.rolePermissions.get(String(r.id)) ?? []).some(
                              (rp) =>
                                  rp.permission_name === p.permission_name &&
                                  rp.resource_server_identifier === p.resource_server_identifier
                          )
                      );
            return {
                ...p,
                sources: [
                    isDirect
                        ? { source_id: '', source_name: '', source_type: 'DIRECT' }
                        : {
                              source_id: String(role?.id ?? ''),
                              source_name: String(role?.name ?? ''),
                              source_type: 'ROLE',
                          },
                ],
            };
        });
        res.json(pageResponse(paginate(items, page), 'permissions', page));
    });

    router.post('/users/:id/permissions', requireScope('update:users'), (req, res) => {
        const id = param(req, 'id');
        if (!store.users.has(id)) throw notFound('The user does not exist.');
        const permissions = parsePermissions(ensureBody(req.body));
        assertPermissionsExist(store, permissions);
        const current = store.userPermissions.get(id) ?? [];
        for (const p of permissions) {
            if (!current.some(same(p))) current.push(p);
        }
        store.userPermissions.set(id, current);
        res.status(201).json({});
    });

    router.delete('/users/:id/permissions', requireScope('update:users'), (req, res) => {
        const id = param(req, 'id');
        if (!store.users.has(id)) throw notFound('The user does not exist.');
        const permissions = parsePermissions(ensureBody(req.body));
        store.userPermissions.set(
            id,
            (store.userPermissions.get(id) ?? []).filter((c) => !permissions.some(same(c)))
        );
        res.status(204).end();
    });

    router.get('/users/:id/enrollments', requireScope('read:users'), (req, res) => {
        if (!store.users.has(param(req, 'id'))) throw notFound('The user does not exist.');
        res.json([]);
    });

    router.get('/users/:id/logs', requireScope('read:users', 'read:logs'), (req, res) => {
        if (!store.users.has(param(req, 'id'))) throw notFound('The user does not exist.');
        res.json([]);
    });

    // --- Brute-force blocks ---

    router.get('/user-blocks', requireScope('read:users'), (req, res) => {
        const identifier = typeof req.query.identifier === 'string' ? req.query.identifier : undefined;
        if (!identifier) throw badRequest("Query parameter 'identifier' is required");
        const user = findUserByEmail(store, identifier);
        res.json({ blocked_for: user ? (store.userBlocks.get(String(user.user_id)) ?? []) : [] });
    });

    router.delete('/user-blocks', requireScope('update:users'), (req, res) => {
        const identifier = typeof req.query.identifier === 'string' ? req.query.identifier : undefined;
        if (!identifier) throw badRequest("Query parameter 'identifier' is required");
        const user = findUserByEmail(store, identifier);
        if (user) clearBlocks(String(user.user_id));
        res.status(204).end();
    });

    router.get('/user-blocks/:id', requireScope('read:users'), (req, res) => {
        const id = param(req, 'id');
        if (!store.users.has(id)) throw notFound('The user does not exist.');
        res.json({ blocked_for: store.userBlocks.get(id) ?? [] });
    });

    router.delete('/user-blocks/:id', requireScope('update:users'), (req, res) => {
        clearBlocks(param(req, 'id'));
        res.status(204).end();
    });

    function clearBlocks(userId: string): void {
        store.userBlocks.delete(userId);
        const prefix = `${userId}\u0000`;
        for (const key of [...store.loginAttempts.keys()].filter((k) => k.startsWith(prefix))) {
            store.loginAttempts.delete(key);
        }
    }

    return router;
}

const same = (a: Permission) => (b: Permission) =>
    a.permission_name === b.permission_name && a.resource_server_identifier === b.resource_server_identifier;
