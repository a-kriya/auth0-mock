import { Collection, type Entity } from './collection.ts';
import { emptyPins, type IdPins } from './ids.ts';
import { clone } from '../util/merge.ts';

export interface Permission {
    permission_name: string;
    resource_server_identifier: string;
}

export interface TriggerBinding extends Entity {
    id: string;
    trigger_id: string;
    action: Entity;
    display_name: string;
    created_at: string;
    updated_at: string;
}

export interface Session {
    id: string;
    user_id: string;
    client_id: string;
    created_at: number;
    /** Set when the tenant revokes the session (post-login Action `api.session.revoke`). */
    revoked?: string;
}

export interface AuthorizeTransaction {
    state: string;
    client_id: string;
    redirect_uri: string;
    scope: string;
    audience?: string;
    nonce?: string;
    response_type: string;
    response_mode: string;
    code_challenge?: string;
    code_challenge_method?: string;
    login_hint?: string;
    prompt?: string;
    connection?: string;
    created_at: number;
}

export interface AuthorizationCode {
    code: string;
    user_id: string;
    client_id: string;
    redirect_uri: string;
    scope: string;
    audience?: string;
    nonce?: string;
    code_challenge?: string;
    code_challenge_method?: string;
    session_id?: string;
    auth_time?: number;
    /** Claims and scope changes produced by post-login Actions at login time. */
    access_token_claims?: Record<string, unknown>;
    id_token_claims?: Record<string, unknown>;
    scope_adjustments?: { add: string[]; remove: string[] };
    created_at: number;
    expires_at: number;
}

export interface RefreshTokenRecord {
    token: string;
    user_id: string;
    client_id: string;
    scope: string;
    audience?: string;
    session_id?: string;
    created_at: number;
    expires_at: number;
    /** Grant that started the chain (`password`, `password-realm`, `authorization_code`); refreshes keep it. */
    grant_type?: string;
    /** Set once rotated; a reused token is rejected. */
    rotated_at?: number;
}

export interface LoginAttempts {
    count: number;
    last: number;
}

export interface UserBlock {
    identifier: string;
    ip?: string;
    connection?: string;
}

export interface Snapshot {
    version: 1;
    tenant?: Entity;
    prompts?: Entity;
    attackProtection?: {
        bruteForce?: Entity;
        suspiciousIp?: Entity;
        breachedPassword?: Entity;
        botDetection?: Entity;
        captcha?: Entity;
    };
    connections?: Entity[];
    clients?: Entity[];
    clientGrants?: Entity[];
    resourceServers?: Entity[];
    roles?: Entity[];
    rolePermissions?: Record<string, Permission[]>;
    users?: Entity[];
    userRoles?: Record<string, string[]>;
    userPermissions?: Record<string, Permission[]>;
    branding?: Entity;
    emailProvider?: Entity | null;
    actions?: Entity[];
    actionVersions?: Record<string, Entity[]>;
    triggerBindings?: Record<string, TriggerBinding[]>;
    emailTemplates?: Entity[];
    brandingThemes?: Entity[];
}

export const MANAGEMENT_SCOPES = [
    'read:client_grants',
    'create:client_grants',
    'delete:client_grants',
    'update:client_grants',
    'read:users',
    'update:users',
    'delete:users',
    'create:users',
    'read:users_app_metadata',
    'update:users_app_metadata',
    'delete:users_app_metadata',
    'create:users_app_metadata',
    'read:user_custom_blocks',
    'create:user_custom_blocks',
    'delete:user_custom_blocks',
    'create:user_tickets',
    'read:clients',
    'update:clients',
    'delete:clients',
    'create:clients',
    'read:client_keys',
    'update:client_keys',
    'delete:client_keys',
    'create:client_keys',
    'read:connections',
    'update:connections',
    'delete:connections',
    'create:connections',
    'read:resource_servers',
    'update:resource_servers',
    'delete:resource_servers',
    'create:resource_servers',
    'read:tenant_settings',
    'update:tenant_settings',
    'read:roles',
    'create:roles',
    'delete:roles',
    'update:roles',
    'read:prompts',
    'update:prompts',
    'read:branding',
    'update:branding',
    'delete:branding',
    'read:email_templates',
    'create:email_templates',
    'update:email_templates',
    'read:actions',
    'update:actions',
    'delete:actions',
    'create:actions',
    'read:attack_protection',
    'update:attack_protection',
    'read:email_provider',
    'update:email_provider',
    'create:email_provider',
    'delete:email_provider',
    'read:logs',
    'read:stats',
    'read:insights',
];

const defaultTenant = (): Entity => ({
    friendly_name: 'auth0-mock',
    enabled_locales: ['en'],
    flags: {},
    sandbox_version: '22',
    sandbox_versions_available: ['22', '18'],
    default_audience: '',
    session_lifetime: 168,
    idle_session_lifetime: 72,
    session_cookie: { mode: 'persistent' },
    sessions: { oidc_logout_prompt_enabled: false },
    oidc_logout: { rp_logout_end_session_endpoint_discovery: true },
    allowed_logout_urls: [],
    customize_mfa_in_postlogin_action: false,
    pushed_authorization_requests_supported: false,
    allow_organization_name_in_authentication_api: false,
});

const defaultBranding = (): Entity => ({
    colors: { primary: '#0059d6', page_background: '#000000' },
    favicon_url: 'https://cdn.auth0.com/website/new-homepage/dark-favicon.png',
    logo_url: 'https://cdn.auth0.com/manhattan/versions/1.5240.0/assets/badge.png',
    font: { url: '' },
});

const defaultPrompts = (): Entity => ({
    universal_login_experience: 'new',
    identifier_first: false,
    webauthn_platform_first_factor: false,
});

const defaultAttackProtection = () => ({
    bruteForce: {
        enabled: true,
        shields: ['block', 'user_notification'],
        allowlist: [],
        mode: 'count_per_identifier_and_ip',
        max_attempts: 10,
    } as Entity,
    suspiciousIp: {
        enabled: true,
        shields: ['admin_notification', 'block'],
        allowlist: [],
        stage: {
            'pre-login': { max_attempts: 100, rate: 864000 },
            'pre-user-registration': { max_attempts: 50, rate: 1200 },
        },
    } as Entity,
    breachedPassword: {
        enabled: false,
        shields: [],
        admin_notification_frequency: [],
        method: 'standard',
        stage: { 'pre-user-registration': { shields: [] }, 'pre-change-password': { shields: [] } },
    } as Entity,
    botDetection: {
        bot_detection_level: 'low',
        allowlist: [],
        response: {
            policy: 'off',
            selected_captcha_provider: 'auth0_v2',
            password_reset_policy: 'off',
            passwordless_policy: 'off',
        },
        monitoring: { enabled: false },
    } as Entity,
    captcha: {
        active_provider: 'auth0_v2',
        providers: {},
    } as Entity,
});

/** All emulator state. Provisioned tables are snapshot-able; runtime tables (sessions, codes, ...) are not. */
export class Store {
    pins: IdPins = emptyPins();

    tenant: Entity = defaultTenant();
    prompts: Entity = defaultPrompts();
    branding: Entity = defaultBranding();
    emailProvider: Entity | null = null;
    attackProtection = defaultAttackProtection();

    readonly connections = new Collection('connections', { idField: 'id' });
    readonly clients = new Collection('clients', { idField: 'client_id', mergeKeys: ['client_metadata'] });
    readonly clientGrants = new Collection('client_grants', { idField: 'id' });
    readonly resourceServers = new Collection('resource_servers', { idField: 'id' });
    readonly roles = new Collection('roles', { idField: 'id' });
    readonly rolePermissions = new Map<string, Permission[]>();
    readonly users = new Collection('users', {
        idField: 'user_id',
        timestamps: true,
        mergeKeys: ['user_metadata', 'app_metadata'],
    });
    readonly userRoles = new Map<string, string[]>();
    readonly userPermissions = new Map<string, Permission[]>();
    readonly actions = new Collection('actions', { idField: 'id', timestamps: true });
    readonly actionVersions = new Map<string, Entity[]>();
    readonly triggerBindings = new Map<string, TriggerBinding[]>();
    readonly emailTemplates = new Map<string, Entity>();
    readonly brandingThemes = new Collection('branding_themes', { idField: 'themeId' });
    readonly tickets = new Collection('tickets', { idField: 'id' });

    // Runtime-only state
    readonly sessions = new Map<string, Session>();
    readonly transactions = new Map<string, AuthorizeTransaction>();
    readonly authCodes = new Map<string, AuthorizationCode>();
    readonly refreshTokens = new Map<string, RefreshTokenRecord>();
    readonly loginAttempts = new Map<string, LoginAttempts>();
    readonly userBlocks = new Map<string, UserBlock[]>();

    reset(): void {
        this.tenant = defaultTenant();
        this.prompts = defaultPrompts();
        this.branding = defaultBranding();
        this.emailProvider = null;
        this.attackProtection = defaultAttackProtection();
        for (const c of [
            this.connections,
            this.clients,
            this.clientGrants,
            this.resourceServers,
            this.roles,
            this.users,
            this.actions,
            this.brandingThemes,
            this.tickets,
        ]) {
            c.clear();
        }
        for (const m of [
            this.rolePermissions,
            this.userRoles,
            this.userPermissions,
            this.actionVersions,
            this.triggerBindings,
            this.emailTemplates,
            this.sessions,
            this.transactions,
            this.authCodes,
            this.refreshTokens,
            this.loginAttempts,
            this.userBlocks,
        ]) {
            m.clear();
        }
    }

    /** Roles assigned to a user, in assignment order. */
    rolesOf(userId: string): Entity[] {
        return (this.userRoles.get(userId) ?? []).flatMap((id) => {
            const role = this.roles.get(id);
            return role ? [role] : [];
        });
    }

    /** Distinct permissions granted through a user's roles, grouped per resource server. */
    permissionsOf(userId: string): Permission[] {
        const seen = new Set<string>();
        const result: Permission[] = [];
        const sources = [
            ...(this.userRoles.get(userId) ?? []).map((roleId) => this.rolePermissions.get(roleId) ?? []),
            this.userPermissions.get(userId) ?? [],
        ];
        for (const list of sources) {
            for (const p of list) {
                const key = `${p.resource_server_identifier}\u0000${p.permission_name}`;
                if (seen.has(key)) continue;
                seen.add(key);
                result.push({ ...p });
            }
        }
        return result;
    }

    resourceServerByIdentifier(identifier: string): Entity | undefined {
        return this.resourceServers.find((r) => r.identifier === identifier);
    }

    connectionByName(name: string): Entity | undefined {
        return this.connections.find((c) => c.name === name);
    }

    export(): Snapshot {
        const toRecord = <V>(map: Map<string, V>): Record<string, V> => Object.fromEntries(map);
        return clone({
            version: 1 as const,
            tenant: this.tenant,
            prompts: this.prompts,
            branding: this.branding,
            emailProvider: this.emailProvider,
            attackProtection: this.attackProtection,
            connections: this.connections.all(),
            clients: this.clients.all(),
            clientGrants: this.clientGrants.all(),
            resourceServers: this.resourceServers.all(),
            roles: this.roles.all(),
            rolePermissions: toRecord(this.rolePermissions),
            users: this.users.all(),
            userRoles: toRecord(this.userRoles),
            userPermissions: toRecord(this.userPermissions),
            actions: this.actions.all(),
            actionVersions: toRecord(this.actionVersions),
            triggerBindings: toRecord(this.triggerBindings),
            emailTemplates: [...this.emailTemplates.values()],
            brandingThemes: this.brandingThemes.all(),
        });
    }

    /** Load a snapshot verbatim (entities must be complete). Use `importSeed` for partial/declarative input. */
    loadSnapshot(snapshot: Snapshot): void {
        const s = clone(snapshot);
        if (s.tenant) this.tenant = { ...defaultTenant(), ...s.tenant };
        if (s.prompts) this.prompts = { ...defaultPrompts(), ...s.prompts };
        if (s.branding) this.branding = { ...defaultBranding(), ...s.branding };
        if (s.emailProvider !== undefined) this.emailProvider = s.emailProvider;
        if (s.attackProtection) {
            const d = defaultAttackProtection();
            this.attackProtection = {
                bruteForce: { ...d.bruteForce, ...s.attackProtection.bruteForce },
                suspiciousIp: { ...d.suspiciousIp, ...s.attackProtection.suspiciousIp },
                breachedPassword: { ...d.breachedPassword, ...s.attackProtection.breachedPassword },
                botDetection: { ...d.botDetection, ...s.attackProtection.botDetection },
                captcha: { ...d.captcha, ...s.attackProtection.captcha },
            };
        }
        this.connections.load(s.connections ?? []);
        this.clients.load(s.clients ?? []);
        this.clientGrants.load(s.clientGrants ?? []);
        this.resourceServers.load(s.resourceServers ?? []);
        this.roles.load(s.roles ?? []);
        for (const [k, v] of Object.entries(s.rolePermissions ?? {})) this.rolePermissions.set(k, v);
        this.users.load(s.users ?? []);
        for (const [k, v] of Object.entries(s.userRoles ?? {})) this.userRoles.set(k, v);
        for (const [k, v] of Object.entries(s.userPermissions ?? {})) this.userPermissions.set(k, v);
        this.actions.load(s.actions ?? []);
        for (const [k, v] of Object.entries(s.actionVersions ?? {})) this.actionVersions.set(k, v);
        for (const [k, v] of Object.entries(s.triggerBindings ?? {})) this.triggerBindings.set(k, v);
        for (const t of s.emailTemplates ?? [])
            if (typeof t.template === 'string') this.emailTemplates.set(t.template, t);
        this.brandingThemes.load(s.brandingThemes ?? []);
    }
}
