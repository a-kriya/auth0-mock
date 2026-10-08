import { badRequest, conflict, notFound } from '../errors.ts';
import type { Entity } from '../store/collection.ts';
import { generateId } from '../store/ids.ts';
import type { Store, TriggerBinding } from '../store/store.ts';
import { isPlainObject } from '../util/merge.ts';
import { optionalString, requireString } from './validate.ts';

export const TRIGGERS: Entity[] = [
    { id: 'post-login', version: 'v3', status: 'CURRENT', runtimes: ['node18', 'node22'], default_runtime: 'node22' },
    { id: 'post-login', version: 'v2', status: 'DEPRECATED', runtimes: ['node18'], default_runtime: 'node18' },
    {
        id: 'credentials-exchange',
        version: 'v2',
        status: 'CURRENT',
        runtimes: ['node18', 'node22'],
        default_runtime: 'node22',
    },
    {
        id: 'pre-user-registration',
        version: 'v2',
        status: 'CURRENT',
        runtimes: ['node18', 'node22'],
        default_runtime: 'node22',
    },
    {
        id: 'post-user-registration',
        version: 'v2',
        status: 'CURRENT',
        runtimes: ['node18', 'node22'],
        default_runtime: 'node22',
    },
    {
        id: 'post-change-password',
        version: 'v2',
        status: 'CURRENT',
        runtimes: ['node18', 'node22'],
        default_runtime: 'node22',
    },
    {
        id: 'send-phone-message',
        version: 'v2',
        status: 'CURRENT',
        runtimes: ['node18', 'node22'],
        default_runtime: 'node22',
    },
    {
        id: 'password-reset-post-challenge',
        version: 'v1',
        status: 'CURRENT',
        runtimes: ['node18', 'node22'],
        default_runtime: 'node22',
    },
    {
        id: 'custom-phone-provider',
        version: 'v1',
        status: 'CURRENT',
        runtimes: ['node18', 'node22'],
        default_runtime: 'node22',
    },
    {
        id: 'custom-email-provider',
        version: 'v1',
        status: 'CURRENT',
        runtimes: ['node18', 'node22'],
        default_runtime: 'node22',
    },
];

interface Secret {
    name: string;
    value?: string;
    updated_at: string;
}

function parseSecrets(input: unknown, previous: Secret[] = []): Secret[] {
    if (input === undefined) return previous;
    if (!Array.isArray(input)) throw badRequest("Payload validation error: 'secrets' must be an array");
    const now = new Date().toISOString();
    return input.map((s) => {
        if (!isPlainObject(s) || typeof s.name !== 'string') {
            throw badRequest("Payload validation error: each secret requires a 'name'");
        }
        const prior = previous.find((p) => p.name === s.name);
        const value = typeof s.value === 'string' ? s.value : prior?.value;
        return {
            name: s.name,
            ...(value !== undefined ? { value } : {}),
            updated_at: value !== prior?.value ? now : (prior?.updated_at ?? now),
        };
    });
}

function parseTriggers(input: unknown): Entity[] {
    if (!Array.isArray(input) || input.length === 0) {
        throw badRequest("Payload validation error: 'supported_triggers' must be a non-empty array");
    }
    return input.map((t) => {
        if (!isPlainObject(t) || typeof t.id !== 'string') {
            throw badRequest("Payload validation error: every trigger requires an 'id'");
        }
        const known = TRIGGERS.find((k) => k.id === t.id && (t.version === undefined || k.version === t.version));
        if (!known) throw badRequest(`Unknown trigger '${t.id}' ${t.version ?? ''}`.trim(), 'invalid_trigger');
        return { id: t.id, version: known.version };
    });
}

function parseDependencies(input: unknown): Entity[] {
    if (input === undefined) return [];
    if (!Array.isArray(input)) throw badRequest("Payload validation error: 'dependencies' must be an array");
    return input.map((d) => {
        if (!isPlainObject(d) || typeof d.name !== 'string') {
            throw badRequest("Payload validation error: every dependency requires a 'name'");
        }
        return { name: d.name, version: typeof d.version === 'string' ? d.version : 'latest' };
    });
}

/** Strip secret values the way the Management API does. */
export function publicAction(action: Entity): Entity {
    const secrets = Array.isArray(action.secrets)
        ? (action.secrets as Secret[]).map(({ name, updated_at }) => ({ name, updated_at }))
        : [];
    const deployed = isPlainObject(action.deployed_version) ? publicVersion(action.deployed_version) : undefined;
    const current = isPlainObject(action.current_version) ? publicVersion(action.current_version) : undefined;
    const { code: _c, ...rest } = action;
    return {
        ...rest,
        code: action.code,
        secrets,
        ...(deployed ? { deployed_version: deployed } : {}),
        ...(current ? { current_version: current } : {}),
    };
}

export function publicVersion(version: Entity): Entity {
    const secrets = Array.isArray(version.secrets)
        ? (version.secrets as Secret[]).map(({ name, updated_at }) => ({ name, updated_at }))
        : [];
    return { ...version, secrets };
}

export function buildAction(store: Store, input: Entity): Entity {
    const name = requireString(input, 'name');
    if (store.actions.find((a) => a.name === name)) {
        throw conflict(`An action with the name '${name}' already exists`, 'action_conflict');
    }
    const now = new Date().toISOString();
    const triggers = parseTriggers(input.supported_triggers);
    const runtime = optionalString(input, 'runtime') ?? 'node22';
    return {
        id: optionalString(input, 'id') ?? generateId.actionId(),
        name,
        supported_triggers: triggers,
        code: optionalString(input, 'code') ?? '',
        dependencies: parseDependencies(input.dependencies),
        runtime,
        secrets: parseSecrets(input.secrets),
        status: 'built',
        all_changes_deployed: false,
        built_at: now,
        created_at: now,
        updated_at: now,
    };
}

export function updateAction(store: Store, id: string, input: Entity): Entity {
    const current = store.actions.require(id, 'The action does not exist');
    const changes: Entity = {};
    const name = optionalString(input, 'name');
    if (name !== undefined && name !== current.name) {
        if (store.actions.find((a) => a.name === name)) {
            throw conflict(`An action with the name '${name}' already exists`, 'action_conflict');
        }
        changes.name = name;
    }
    if (input.supported_triggers !== undefined) changes.supported_triggers = parseTriggers(input.supported_triggers);
    if (input.code !== undefined) changes.code = requireString(input, 'code');
    if (input.dependencies !== undefined) changes.dependencies = parseDependencies(input.dependencies);
    if (input.runtime !== undefined) changes.runtime = requireString(input, 'runtime');
    if (input.secrets !== undefined) changes.secrets = parseSecrets(input.secrets, current.secrets as Secret[]);
    const codeChanged = ['code', 'dependencies', 'runtime', 'secrets'].some((k) => k in changes);
    if (codeChanged) {
        changes.status = 'built';
        changes.built_at = new Date().toISOString();
        changes.all_changes_deployed = false;
    }
    return store.actions.patch(id, changes);
}

/** Snapshot the current code into a new deployed version. */
export function deployAction(store: Store, id: string): Entity {
    const action = store.actions.require(id, 'The action does not exist');
    const versions = store.actionVersions.get(id) ?? [];
    const now = new Date().toISOString();
    for (const v of versions) v.deployed = false;
    const version: Entity = {
        id: generateId.versionId(),
        action_id: id,
        code: action.code,
        dependencies: action.dependencies,
        runtime: action.runtime,
        secrets: action.secrets,
        status: 'built',
        number: versions.length + 1,
        deployed: true,
        built_at: now,
        created_at: now,
        updated_at: now,
        supported_triggers: action.supported_triggers,
        action: summarizeAction(action),
    };
    versions.push(version);
    store.actionVersions.set(id, versions);
    store.actions.patch(id, { deployed_version: version, current_version: version, all_changes_deployed: true });
    // Bindings embed the action summary; refresh it so name/trigger changes are reflected.
    for (const bindings of store.triggerBindings.values()) {
        for (const b of bindings)
            if ((b.action as Entity).id === id) b.action = summarizeAction(store.actions.require(id));
    }
    return version;
}

export function summarizeAction(action: Entity): Entity {
    const { code: _c, secrets: _s, deployed_version: _d, current_version: _v, ...rest } = action;
    return { ...rest };
}

export function deleteAction(store: Store, id: string, force: boolean): void {
    if (!store.actions.has(id)) return;
    const bound = [...store.triggerBindings.entries()].filter(([, bs]) =>
        bs.some((b) => (b.action as Entity).id === id)
    );
    if (bound.length > 0 && !force) {
        throw badRequest('The action is bound to a trigger; unbind it or use force=true', 'action_bound');
    }
    for (const [trigger, bindings] of bound) {
        store.triggerBindings.set(
            trigger,
            bindings.filter((b) => (b.action as Entity).id !== id)
        );
    }
    store.actions.delete(id);
    store.actionVersions.delete(id);
}

export function replaceBindings(store: Store, triggerId: string, input: unknown): TriggerBinding[] {
    if (!TRIGGERS.some((t) => t.id === triggerId)) throw notFound(`Unknown trigger '${triggerId}'`, 'invalid_trigger');
    if (!Array.isArray(input)) throw badRequest("Payload validation error: 'bindings' must be an array");
    const existing = store.triggerBindings.get(triggerId) ?? [];
    const now = new Date().toISOString();
    const bindings = input.map((b): TriggerBinding => {
        const ref = isPlainObject(b) ? b.ref : undefined;
        if (!isPlainObject(b) || !isPlainObject(ref) || typeof ref.value !== 'string') {
            throw badRequest("Payload validation error: every binding requires 'ref.type' and 'ref.value'");
        }
        const refValue = ref.value;
        const action =
            ref.type === 'action_name' ? store.actions.find((a) => a.name === refValue) : store.actions.get(refValue);
        if (!action) throw badRequest(`Action '${refValue}' does not exist`, 'inexistent_action');
        if (!isPlainObject(action.deployed_version)) {
            throw badRequest(`Action '${action.name}' must be deployed before it can be bound`, 'action_not_deployed');
        }
        if (!(action.supported_triggers as Entity[]).some((t) => t.id === triggerId)) {
            throw badRequest(`Action '${action.name}' does not support trigger '${triggerId}'`, 'invalid_trigger');
        }
        const prior = existing.find((e) => (e.action as Entity).id === action.id);
        return {
            id: prior?.id ?? generateId.bindingId(),
            trigger_id: triggerId,
            action: summarizeAction(action),
            display_name: typeof b.display_name === 'string' ? b.display_name : String(action.name),
            created_at: prior?.created_at ?? now,
            updated_at: now,
        };
    });
    store.triggerBindings.set(triggerId, bindings);
    return bindings;
}

/** Deployed actions bound to a trigger, in execution order. */
export function boundActions(store: Store, triggerId: string): Array<{ binding: TriggerBinding; version: Entity }> {
    return (store.triggerBindings.get(triggerId) ?? []).flatMap((binding) => {
        const action = store.actions.get(String((binding.action as Entity).id));
        const version = action && isPlainObject(action.deployed_version) ? action.deployed_version : undefined;
        return version ? [{ binding, version }] : [];
    });
}
