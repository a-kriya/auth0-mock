import { randomBytes, randomInt, randomUUID } from 'node:crypto';
import { z } from 'zod';

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const URL_SAFE = `${ALNUM}-_`;

export function randomString(length: number, alphabet: string = ALNUM): string {
    let out = '';
    for (let i = 0; i < length; i++) out += alphabet[randomInt(alphabet.length)];
    return out;
}

export const randomHex = (bytes: number): string => randomBytes(bytes).toString('hex');

/** Identifier formats matching what Auth0 issues for each resource type. */
export const generateId = {
    clientId: () => randomString(32),
    clientSecret: () => randomString(64, URL_SAFE),
    roleId: () => `rol_${randomString(16)}`,
    connectionId: () => `con_${randomString(16)}`,
    clientGrantId: () => `cgr_${randomString(16)}`,
    resourceServerId: () => randomHex(12),
    userId: () => randomHex(12),
    actionId: () => randomUUID(),
    versionId: () => randomUUID(),
    bindingId: () => randomUUID(),
    themeId: () => randomUUID(),
    ticketId: () => randomString(43, URL_SAFE),
    authorizationCode: () => randomString(43, URL_SAFE),
    refreshToken: () => `v1.M${randomString(60, URL_SAFE)}`,
    sessionId: () => randomString(32, URL_SAFE),
    logId: () => `90020${randomHex(12)}`,
};

export const idPinsSchema = z
    .object({
        /** Client name → client_id */
        clients: z.record(z.string(), z.string()).default({}),
        /** Client name → client_secret */
        clientSecrets: z.record(z.string(), z.string()).default({}),
        /** Role name → role id */
        roles: z.record(z.string(), z.string()).default({}),
        /** Resource server identifier (audience) → id */
        resourceServers: z.record(z.string(), z.string()).default({}),
        /** Connection name → connection id */
        connections: z.record(z.string(), z.string()).default({}),
    })
    .partial();

export interface IdPins {
    clients: Record<string, string>;
    clientSecrets: Record<string, string>;
    roles: Record<string, string>;
    resourceServers: Record<string, string>;
    connections: Record<string, string>;
}

export const emptyPins = (): IdPins => ({
    clients: {},
    clientSecrets: {},
    roles: {},
    resourceServers: {},
    connections: {},
});

export function parseIdPins(json: unknown): IdPins {
    const parsed = idPinsSchema.parse(json);
    const base = emptyPins();
    return {
        clients: parsed.clients ?? base.clients,
        clientSecrets: parsed.clientSecrets ?? base.clientSecrets,
        roles: parsed.roles ?? base.roles,
        resourceServers: parsed.resourceServers ?? base.resourceServers,
        connections: parsed.connections ?? base.connections,
    };
}
