import { badRequest, conflict, notFound } from '../errors.ts';
import type { Entity } from '../store/collection.ts';
import { generateId } from '../store/ids.ts';
import type { Permission, Store } from '../store/store.ts';
import { isPlainObject } from '../util/merge.ts';
import { scopesOf } from './resource-servers.ts';
import { optionalString, requireString } from './validate.ts';

export function buildRole(store: Store, input: Entity): Entity {
    const name = requireString(input, 'name');
    if (store.roles.find((r) => r.name === name)) {
        throw conflict('A role with the same name already exists', 'role_conflict');
    }
    const id = optionalString(input, 'id') ?? store.pins.roles[name] ?? generateId.roleId();
    if (store.roles.has(id)) throw conflict(`A role with id '${id}' already exists`, 'role_conflict');
    return { id, name, description: optionalString(input, 'description') ?? '' };
}

export function parsePermissions(body: Entity): Permission[] {
    const list = body.permissions;
    if (!Array.isArray(list) || list.length === 0) {
        throw badRequest("Payload validation error: 'permissions' must be a non-empty array");
    }
    return list.map((p) => {
        if (
            !isPlainObject(p) ||
            typeof p.permission_name !== 'string' ||
            typeof p.resource_server_identifier !== 'string'
        ) {
            throw badRequest(
                "Payload validation error: each permission requires 'permission_name' and 'resource_server_identifier'"
            );
        }
        return { permission_name: p.permission_name, resource_server_identifier: p.resource_server_identifier };
    });
}

/** Validate that every permission exists as a scope on its resource server. */
export function assertPermissionsExist(store: Store, permissions: Permission[]): void {
    for (const p of permissions) {
        const rs = store.resourceServerByIdentifier(p.resource_server_identifier);
        if (!rs) throw badRequest(`Resource server '${p.resource_server_identifier}' does not exist`);
        if (!scopesOf(rs).some((s) => s.value === p.permission_name)) {
            throw badRequest(
                `Permission '${p.permission_name}' does not exist on resource server '${p.resource_server_identifier}'`
            );
        }
    }
}

export function addRolePermissions(store: Store, roleId: string, permissions: Permission[]): void {
    if (!store.roles.has(roleId)) throw notFound('The role does not exist');
    assertPermissionsExist(store, permissions);
    const current = store.rolePermissions.get(roleId) ?? [];
    for (const p of permissions) {
        if (
            !current.some(
                (c) =>
                    c.permission_name === p.permission_name &&
                    c.resource_server_identifier === p.resource_server_identifier
            )
        ) {
            current.push({ ...p });
        }
    }
    store.rolePermissions.set(roleId, current);
}

export function removeRolePermissions(store: Store, roleId: string, permissions: Permission[]): void {
    if (!store.roles.has(roleId)) throw notFound('The role does not exist');
    const current = store.rolePermissions.get(roleId) ?? [];
    store.rolePermissions.set(
        roleId,
        current.filter(
            (c) =>
                !permissions.some(
                    (p) =>
                        p.permission_name === c.permission_name &&
                        p.resource_server_identifier === c.resource_server_identifier
                )
        )
    );
}

/** Permission objects in the shape `GET /roles/:id/permissions` and `GET /users/:id/permissions` return. */
export function describePermissions(store: Store, permissions: Permission[]): Entity[] {
    return permissions.map((p) => {
        const rs = store.resourceServerByIdentifier(p.resource_server_identifier);
        const scope = rs ? scopesOf(rs).find((s) => s.value === p.permission_name) : undefined;
        return {
            permission_name: p.permission_name,
            description: scope?.description ?? '',
            resource_server_name: (rs?.name as string | undefined) ?? '',
            resource_server_identifier: p.resource_server_identifier,
        };
    });
}
