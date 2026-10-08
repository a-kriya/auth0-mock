import { buildAction, deployAction, replaceBindings } from '../model/actions.ts';
import { buildClient, buildClientGrant } from '../model/clients.ts';
import { buildConnection } from '../model/connections.ts';
import { buildResourceServer, ensureManagementResourceServer } from '../model/resource-servers.ts';
import { buildRole } from '../model/roles.ts';
import { buildUser, findUserByEmail, hashPassword } from '../model/users.ts';
import type { Entity } from './collection.ts';
import type { Snapshot, Store, TriggerBinding } from './store.ts';
import { isPlainObject } from '../util/merge.ts';

export interface SeedContext {
    issuer: string;
    tenantName: string;
    signingCertificate: string;
}

/**
 * Load a seed document. Sections use the Management API object shapes; entries may be complete
 * (as exported by `GET /__mock/snapshot`) or partial (a declarative seed: e.g. a client with only a
 * `name`, a user with a plain `password`). Existing entities with the same identifier are replaced.
 */
export function importSeed(store: Store, seed: Snapshot, ctx: SeedContext): void {
    const s = structuredClone(seed);
    if (s.tenant) store.tenant = { ...store.tenant, ...s.tenant };
    if (s.prompts) store.prompts = { ...store.prompts, ...s.prompts };
    if (s.branding) store.branding = { ...store.branding, ...s.branding };
    if (s.emailProvider !== undefined) store.emailProvider = s.emailProvider;
    if (s.attackProtection) {
        for (const key of ['bruteForce', 'suspiciousIp', 'breachedPassword', 'botDetection', 'captcha'] as const) {
            const value = s.attackProtection[key];
            if (value) store.attackProtection[key] = { ...store.attackProtection[key], ...value };
        }
    }
    ensureManagementResourceServer(store, ctx.issuer);

    for (const item of s.resourceServers ?? []) {
        if (typeof item.id === 'string' && store.resourceServers.has(item.id)) store.resourceServers.put(item);
        else if (typeof item.identifier === 'string' && store.resourceServerByIdentifier(item.identifier)) {
            const existing = store.resourceServerByIdentifier(item.identifier)!;
            store.resourceServers.put({ ...existing, ...item, id: existing.id });
        } else store.resourceServers.insert(buildResourceServer(store, item));
    }
    for (const item of s.clients ?? []) {
        const existing =
            typeof item.client_id === 'string'
                ? store.clients.get(item.client_id)
                : store.clients.find((c) => c.name === item.name);
        if (existing) store.clients.put({ ...existing, ...item, client_id: existing.client_id });
        else store.clients.insert(buildClient(store, item, ctx));
    }
    for (const item of s.connections ?? []) {
        const existing =
            typeof item.id === 'string'
                ? store.connections.get(item.id)
                : typeof item.name === 'string'
                  ? store.connectionByName(item.name)
                  : undefined;
        if (existing) store.connections.put({ ...existing, ...item, id: existing.id });
        else store.connections.insert(buildConnection(store, item));
    }
    for (const item of s.clientGrants ?? []) {
        const existing = store.clientGrants.find((g) => g.client_id === item.client_id && g.audience === item.audience);
        if (existing) store.clientGrants.put({ ...existing, ...item, id: existing.id });
        else store.clientGrants.insert(buildClientGrant(store, item));
    }
    for (const item of s.roles ?? []) {
        const existing =
            typeof item.id === 'string' ? store.roles.get(item.id) : store.roles.find((r) => r.name === item.name);
        if (existing) store.roles.put({ ...existing, ...item, id: existing.id });
        else store.roles.insert(buildRole(store, item));
    }
    for (const [roleId, permissions] of Object.entries(s.rolePermissions ?? {})) {
        store.rolePermissions.set(resolveRoleId(store, roleId), permissions);
    }
    for (const item of s.users ?? []) importUser(store, item);
    for (const [userId, roles] of Object.entries(s.userRoles ?? {})) {
        store.userRoles.set(
            userId,
            roles.map((r) => resolveRoleId(store, r))
        );
    }
    for (const [userId, permissions] of Object.entries(s.userPermissions ?? {}))
        store.userPermissions.set(userId, permissions);

    for (const item of s.actions ?? []) {
        const existing =
            typeof item.id === 'string' ? store.actions.get(item.id) : store.actions.find((a) => a.name === item.name);
        const { deploy, ...rest } = item;
        let action: Entity;
        if (existing) action = store.actions.put({ ...existing, ...rest, id: existing.id });
        else action = store.actions.insert(buildAction(store, rest));
        const versions = s.actionVersions?.[String(action.id)];
        if (versions) store.actionVersions.set(String(action.id), versions);
        if (deploy === true || (rest.deployed_version && !versions)) deployAction(store, String(action.id));
    }
    for (const [trigger, bindings] of Object.entries(s.triggerBindings ?? {})) {
        const complete = bindings.every((b) => typeof b.id === 'string' && isPlainObject(b.action));
        if (complete) store.triggerBindings.set(trigger, bindings as TriggerBinding[]);
        else {
            replaceBindings(
                store,
                trigger,
                bindings.map((b) => ({
                    ref: b.ref ?? {
                        type: 'action_name',
                        value: (b.action as Entity | undefined)?.name ?? b.display_name,
                    },
                    display_name: b.display_name,
                }))
            );
        }
    }
    for (const t of s.emailTemplates ?? []) if (typeof t.template === 'string') store.emailTemplates.set(t.template, t);
    for (const theme of s.brandingThemes ?? []) {
        if (typeof theme.themeId === 'string') store.brandingThemes.put(theme);
        else store.brandingThemes.insert({ themeId: crypto.randomUUID(), ...theme });
    }
}

/** Roles in seeds may be referenced by id or by name. */
function resolveRoleId(store: Store, idOrName: string): string {
    if (store.roles.has(idOrName)) return idOrName;
    const byName = store.roles.find((r) => r.name === idOrName);
    return byName ? String(byName.id) : idOrName;
}

function importUser(store: Store, item: Entity): void {
    const { password, roles, ...rest } = item;
    let user: Entity;
    if (Array.isArray(rest.identities) && typeof rest.user_id === 'string') {
        // Complete record (snapshot export). Re-hash a plain password when one is given.
        user = { ...rest };
        if (typeof password === 'string') user.password_hash = hashPassword(password);
        const now = new Date().toISOString();
        user.created_at ??= now;
        user.updated_at ??= now;
        store.users.put(user);
    } else {
        // Declarative record: needs `connection` (+ `password` for database connections).
        const input = { ...rest, ...(typeof password === 'string' ? { password } : {}) };
        const connectionName = typeof rest.connection === 'string' ? rest.connection : undefined;
        const existing =
            typeof rest.user_id === 'string'
                ? store.users.get(rest.user_id.includes('|') ? rest.user_id : `auth0|${rest.user_id}`)
                : typeof rest.email === 'string'
                  ? findUserByEmail(store, rest.email, connectionName)
                  : undefined;
        if (existing) store.users.delete(String(existing.user_id));
        user = store.users.insert(buildUser(store, input));
        if (existing) store.userRoles.set(String(user.user_id), store.userRoles.get(String(existing.user_id)) ?? []);
    }
    if (Array.isArray(roles)) {
        store.userRoles.set(
            String(user.user_id),
            (roles as string[]).map((r) => resolveRoleId(store, r))
        );
    }
}
