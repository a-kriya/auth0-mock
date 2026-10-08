import { badRequest, conflict } from '../errors.ts';
import type { Entity } from '../store/collection.ts';
import { generateId } from '../store/ids.ts';
import { MANAGEMENT_SCOPES, type Store } from '../store/store.ts';
import { isPlainObject } from '../util/merge.ts';
import { optionalString, requireString } from './validate.ts';

export interface Scope {
    value: string;
    description?: string;
}

export function normalizeScopes(input: unknown): Scope[] {
    if (input === undefined || input === null) return [];
    if (!Array.isArray(input)) throw badRequest("Payload validation error: 'scopes' must be an array");
    return input.map((entry) => {
        if (!isPlainObject(entry) || typeof entry.value !== 'string' || entry.value.length === 0) {
            throw badRequest("Payload validation error: every scope requires a non-empty 'value'");
        }
        const scope: Scope = { value: entry.value };
        if (typeof entry.description === 'string') scope.description = entry.description;
        return scope;
    });
}

export function scopesOf(resourceServer: Entity): Scope[] {
    return Array.isArray(resourceServer.scopes) ? (resourceServer.scopes as Scope[]) : [];
}

export const managementAudience = (issuer: string): string => `${issuer}api/v2/`;

export function buildResourceServer(store: Store, input: Entity): Entity {
    const identifier = requireString(input, 'identifier');
    if (store.resourceServerByIdentifier(identifier)) {
        throw conflict('A resource server with the same identifier already exists', 'resource_server_conflict');
    }
    const id = optionalString(input, 'id') ?? store.pins.resourceServers[identifier] ?? generateId.resourceServerId();
    if (store.resourceServers.has(id)) throw conflict(`A resource server with id '${id}' already exists`);
    const tokenLifetime = typeof input.token_lifetime === 'number' ? input.token_lifetime : 86400;
    const { id: _id, identifier: _identifier, scopes, token_lifetime: _lifetime, ...rest } = input;
    return {
        id,
        name: optionalString(input, 'name') ?? identifier,
        identifier,
        is_system: false,
        scopes: normalizeScopes(scopes),
        signing_alg: 'RS256',
        allow_offline_access: false,
        skip_consent_for_verifiable_first_party_clients: false,
        token_lifetime: tokenLifetime,
        token_lifetime_for_web: Math.min(tokenLifetime, 7200),
        enforce_policies: false,
        token_dialect: 'access_token',
        ...rest,
    };
}

/** The tenant's own Management API resource server, always present like on a real tenant. */
export function ensureManagementResourceServer(store: Store, issuer: string): Entity {
    const identifier = managementAudience(issuer);
    const existing = store.resourceServerByIdentifier(identifier);
    if (existing) return existing;
    return store.resourceServers.insert({
        id: store.pins.resourceServers[identifier] ?? generateId.resourceServerId(),
        name: 'Auth0 Management API',
        identifier,
        is_system: true,
        scopes: MANAGEMENT_SCOPES.map((value) => ({ value, description: value })),
        signing_alg: 'RS256',
        allow_offline_access: false,
        skip_consent_for_verifiable_first_party_clients: false,
        token_lifetime: 86400,
        token_lifetime_for_web: 7200,
        enforce_policies: false,
        token_dialect: 'access_token',
    });
}

/** Look a resource server up by id or by (URL-encoded) identifier, as the Management API allows both. */
export function findResourceServer(store: Store, idOrIdentifier: string): Entity | undefined {
    return store.resourceServers.get(idOrIdentifier) ?? store.resourceServerByIdentifier(idOrIdentifier);
}
