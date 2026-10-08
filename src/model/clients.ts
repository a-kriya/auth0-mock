import { badRequest, conflict } from '../errors.ts';
import type { Entity } from '../store/collection.ts';
import { generateId } from '../store/ids.ts';
import type { Store } from '../store/store.ts';
import { isPlainObject } from '../util/merge.ts';
import { optionalString, optionalStringArray, requireString } from './validate.ts';

export const PUBLIC_APP_TYPES = new Set(['spa', 'native']);

const DEFAULT_GRANT_TYPES: Record<string, string[]> = {
    spa: ['authorization_code', 'implicit', 'refresh_token'],
    native: ['authorization_code', 'implicit', 'refresh_token'],
    regular_web: ['authorization_code', 'implicit', 'refresh_token', 'client_credentials'],
    non_interactive: ['client_credentials'],
};

export const DEFAULT_JWT_CONFIGURATION = { alg: 'RS256', lifetime_in_seconds: 36000, secret_encoded: false };

export const DEFAULT_REFRESH_TOKEN = {
    rotation_type: 'non-rotating',
    expiration_type: 'non-expiring',
    leeway: 0,
    token_lifetime: 2592000,
    idle_token_lifetime: 1296000,
    infinite_token_lifetime: true,
    infinite_idle_token_lifetime: true,
};

export interface ClientContext {
    tenantName: string;
    /** PEM certificate exposed in `signing_keys` (any certificate works for clients that only read it). */
    signingCertificate: string;
}

export function buildClient(store: Store, input: Entity, ctx: ClientContext): Entity {
    const name = requireString(input, 'name');
    const appType = optionalString(input, 'app_type');
    const clientId = optionalString(input, 'client_id') ?? store.pins.clients[name] ?? generateId.clientId();
    if (store.clients.has(clientId)) throw conflict(`A client with id '${clientId}' already exists`, 'client_conflict');
    const clientSecret =
        optionalString(input, 'client_secret') ?? store.pins.clientSecrets[name] ?? generateId.clientSecret();
    const isPublic = appType !== undefined && PUBLIC_APP_TYPES.has(appType);
    const { client_id: _id, client_secret: _secret, name: _name, jwt_configuration, refresh_token, ...rest } = input;
    const provided = isPlainObject(refresh_token) ? refresh_token : {};
    const refreshToken = { ...DEFAULT_REFRESH_TOKEN, ...provided };
    // Auth0 derives the "infinite" flags from the lifetimes unless the caller sets them explicitly.
    if (!('infinite_token_lifetime' in provided) && provided.expiration_type === 'expiring') {
        refreshToken.infinite_token_lifetime = false;
    }
    if (!('infinite_idle_token_lifetime' in provided) && 'idle_token_lifetime' in provided) {
        refreshToken.infinite_idle_token_lifetime = false;
    }

    return {
        client_id: clientId,
        tenant: ctx.tenantName,
        name,
        description: '',
        global: false,
        client_secret: clientSecret,
        ...(appType !== undefined ? { app_type: appType } : {}),
        logo_uri: '',
        is_first_party: true,
        oidc_conformant: true,
        callbacks: [],
        allowed_origins: [],
        web_origins: [],
        allowed_clients: [],
        allowed_logout_urls: [],
        grant_types: DEFAULT_GRANT_TYPES[appType ?? 'regular_web'] ?? DEFAULT_GRANT_TYPES.regular_web,
        jwt_configuration: {
            ...DEFAULT_JWT_CONFIGURATION,
            ...(isPlainObject(jwt_configuration) ? jwt_configuration : {}),
        },
        signing_keys: [{ cert: ctx.signingCertificate, subject: `/CN=${ctx.tenantName}` }],
        sso: false,
        sso_disabled: false,
        cross_origin_auth: false,
        custom_login_page_on: true,
        token_endpoint_auth_method: isPublic ? 'none' : 'client_secret_post',
        client_metadata: {},
        refresh_token: refreshToken,
        is_token_endpoint_ip_header_trusted: false,
        require_pushed_authorization_requests: false,
        ...rest,
    };
}

export function clientGrantTypes(client: Entity): string[] {
    return Array.isArray(client.grant_types) ? (client.grant_types as string[]) : [];
}

export function buildClientGrant(store: Store, input: Entity): Entity {
    const clientId = requireString(input, 'client_id');
    const audience = requireString(input, 'audience');
    if (!store.clients.has(clientId)) throw badRequest(`Client '${clientId}' does not exist`, 'client_not_found');
    const resourceServer = store.resourceServerByIdentifier(audience);
    if (!resourceServer) throw badRequest(`The audience '${audience}' is not a known resource server`);
    if (store.clientGrants.find((g) => g.client_id === clientId && g.audience === audience)) {
        throw conflict('Client grant already exists', 'client_grant_conflict');
    }
    // Auth0 does not validate grant scopes against the resource server's declared scopes (Terraform
    // creates grants and scopes in parallel, and grants may carry scopes the API never declared).
    const scope = optionalStringArray(input, 'scope') ?? [];
    const { id, client_id: _c, audience: _a, scope: _s, ...rest } = input;
    return {
        id: typeof id === 'string' && id ? id : generateId.clientGrantId(),
        client_id: clientId,
        audience,
        scope,
        ...rest,
    };
}

/** Effective scopes of a grant, validated against the current resource server scopes. */
export function grantScopes(grant: Entity): string[] {
    return Array.isArray(grant.scope) ? (grant.scope as string[]) : [];
}
