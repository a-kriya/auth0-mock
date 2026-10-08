export type JsonObject = Record<string, unknown>;

export function isPlainObject(value: unknown): value is JsonObject {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * One-level merge used by Auth0 for metadata-like objects: keys in `changes` overwrite keys in `base`,
 * a `null` value deletes the key, nested objects are replaced (not merged).
 */
export function mergeShallow(base: unknown, changes: unknown): JsonObject {
    const result: JsonObject = isPlainObject(base) ? { ...base } : {};
    if (!isPlainObject(changes)) return result;
    for (const [key, value] of Object.entries(changes)) {
        if (value === null) delete result[key];
        else result[key] = value;
    }
    return result;
}

/** Deep clone via structured cloning (all store entities are plain JSON). */
export function clone<T>(value: T): T {
    return structuredClone(value);
}

/** Read a dotted path (`app_metadata.roles.name`) from an object; arrays are flattened one level per hop. */
export function getPath(value: unknown, path: string): unknown[] {
    let current: unknown[] = [value];
    for (const segment of path.split('.')) {
        const next: unknown[] = [];
        for (const item of current) {
            if (Array.isArray(item)) {
                for (const element of item) {
                    if (isPlainObject(element) && segment in element) next.push(element[segment]);
                }
            } else if (isPlainObject(item) && segment in item) {
                next.push(item[segment]);
            }
        }
        current = next;
    }
    return current.flatMap((item) => (Array.isArray(item) ? item : [item]));
}
