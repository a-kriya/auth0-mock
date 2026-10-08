import { badRequest, conflict } from '../errors.ts';
import type { Entity } from '../store/collection.ts';
import { generateId } from '../store/ids.ts';
import type { Store } from '../store/store.ts';
import { isPlainObject } from '../util/merge.ts';
import { optionalString, optionalStringArray, requireString } from './validate.ts';

export function assertClientsExist(store: Store, clientIds: string[]): void {
    for (const id of clientIds) {
        if (!store.clients.has(id)) throw badRequest(`Client '${id}' does not exist`, 'inexistent_client');
    }
}

export function buildConnection(store: Store, input: Entity): Entity {
    const name = requireString(input, 'name');
    const strategy = requireString(input, 'strategy');
    if (store.connectionByName(name)) {
        throw conflict('A connection with the same name already exists', 'connection_conflict');
    }
    const id = optionalString(input, 'id') ?? store.pins.connections[name] ?? generateId.connectionId();
    if (store.connections.has(id)) throw conflict(`A connection with id '${id}' already exists`, 'connection_conflict');
    const enabledClients = optionalStringArray(input, 'enabled_clients') ?? [];
    assertClientsExist(store, enabledClients);
    const { id: _id, name: _name, strategy: _strategy, enabled_clients: _ec, options, realms, ...rest } = input;
    const baseOptions: Entity =
        strategy === 'auth0'
            ? {
                  auth_params: {},
                  configuration: {},
                  custom_scripts: {},
                  scripts: {},
                  precedence: [],
                  id_token_signed_response_algs: [],
                  password_dictionary: { enable: false, dictionary: [] },
                  passwordPolicy: 'good',
                  strategy_version: 2,
              }
            : {};
    return {
        id,
        name,
        strategy,
        options: { ...baseOptions, ...(isPlainObject(options) ? options : {}) },
        enabled_clients: enabledClients,
        is_domain_connection: false,
        realms: Array.isArray(realms) ? realms : [name],
        metadata: {},
        ...rest,
    };
}

export function enabledClientsOf(connection: Entity): string[] {
    return Array.isArray(connection.enabled_clients) ? (connection.enabled_clients as string[]) : [];
}
