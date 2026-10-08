import { badRequest } from '../errors.ts';
import type { Entity } from '../store/collection.ts';
import { isPlainObject } from '../util/merge.ts';

export function ensureBody(body: unknown): Entity {
    if (!isPlainObject(body)) throw badRequest('Payload validation error: expected a JSON object body');
    return body;
}

export function requireString(body: Entity, field: string): string {
    const value = body[field];
    if (typeof value !== 'string' || value.length === 0) {
        throw badRequest(`Payload validation error: '${field}' is required and must be a non-empty string`);
    }
    return value;
}

export function optionalString(body: Entity, field: string): string | undefined {
    const value = body[field];
    if (value === undefined || value === null) return undefined;
    if (typeof value !== 'string') throw badRequest(`Payload validation error: '${field}' must be a string`);
    return value;
}

export function optionalStringArray(body: Entity, field: string): string[] | undefined {
    const value = body[field];
    if (value === undefined || value === null) return undefined;
    if (!Array.isArray(value) || value.some((v) => typeof v !== 'string')) {
        throw badRequest(`Payload validation error: '${field}' must be an array of strings`);
    }
    return value as string[];
}

/**
 * Split a comma-separated `fields` query parameter and apply `include_fields` semantics. The resource's
 * identifier (`keep`) is always returned, as clients such as the Terraform provider rely on it even when
 * they request a subset of fields.
 */
export function applyFields<T extends Entity>(item: T, query: Record<string, unknown>, keep: string[] = []): Entity {
    const raw = typeof query.fields === 'string' ? query.fields : undefined;
    if (!raw) return item;
    const fields = raw
        .split(',')
        .map((f) => f.trim())
        .filter(Boolean);
    const include = query.include_fields === undefined ? true : String(query.include_fields) !== 'false';
    const out: Entity = {};
    for (const [key, value] of Object.entries(item)) {
        if (keep.includes(key) || fields.includes(key) === include) out[key] = value;
    }
    return out;
}
