import { notFound } from '../errors.ts';
import { clone, isPlainObject, mergeShallow, type JsonObject } from '../util/merge.ts';

export type Entity = JsonObject;

export interface CollectionOptions {
    /** Name of the identifier property (`client_id`, `user_id`, `id`, ...). */
    idField: string;
    /** Maintain `created_at` / `updated_at` ISO timestamps. */
    timestamps?: boolean;
    /** Keys whose values are merged one level deep on patch (Auth0 metadata semantics) instead of replaced. */
    mergeKeys?: string[];
}

export interface PatchOptions {
    /** Extra keys merged one level deep for this call. */
    mergeKeys?: string[];
    /** Do not touch `updated_at`. */
    silent?: boolean;
}

/** In-memory table of JSON entities with Auth0-flavoured create/patch semantics. */
export class Collection<T extends Entity = Entity> {
    readonly name: string;
    readonly idField: string;
    private readonly timestamps: boolean;
    private readonly mergeKeys: Set<string>;
    private readonly items = new Map<string, T>();

    constructor(name: string, options: CollectionOptions) {
        this.name = name;
        this.idField = options.idField;
        this.timestamps = options.timestamps ?? false;
        this.mergeKeys = new Set(options.mergeKeys ?? []);
    }

    get size(): number {
        return this.items.size;
    }

    idOf(item: T): string {
        const id = item[this.idField];
        if (typeof id !== 'string' || id.length === 0) {
            throw new Error(`${this.name}: entity is missing its '${this.idField}' identifier`);
        }
        return id;
    }

    has(id: string): boolean {
        return this.items.has(id);
    }

    get(id: string): T | undefined {
        const item = this.items.get(id);
        return item ? clone(item) : undefined;
    }

    require(id: string, message?: string): T {
        const item = this.items.get(id);
        if (!item) throw notFound(message ?? `The ${this.name.replace(/s$/, '')} does not exist`);
        return clone(item);
    }

    all(): T[] {
        return [...this.items.values()].map((item) => clone(item));
    }

    filter(predicate: (item: T) => boolean): T[] {
        return this.all().filter(predicate);
    }

    find(predicate: (item: T) => boolean): T | undefined {
        for (const item of this.items.values()) if (predicate(item)) return clone(item);
        return undefined;
    }

    /** Insert a complete entity (identifier must already be set). */
    insert(item: T): T {
        const id = this.idOf(item);
        if (this.items.has(id)) throw new Error(`${this.name}: duplicate identifier '${id}'`);
        const stored = clone(item);
        if (this.timestamps) {
            const now = new Date().toISOString();
            if (typeof stored.created_at !== 'string') (stored as Entity).created_at = now;
            if (typeof stored.updated_at !== 'string') (stored as Entity).updated_at = now;
        }
        this.items.set(id, stored);
        return clone(stored);
    }

    /** Replace or insert an entity as-is (used by snapshot import). */
    put(item: T): T {
        const id = this.idOf(item);
        this.items.set(id, clone(item));
        return clone(item);
    }

    /** Auth0 PATCH: top-level properties are replaced, `mergeKeys` are merged one level, `null` deletes on merge keys. */
    patch(id: string, changes: Entity, options: PatchOptions = {}): T {
        const current = this.items.get(id);
        if (!current) throw notFound(`The ${this.name.replace(/s$/, '')} does not exist`);
        const merge = new Set([...this.mergeKeys, ...(options.mergeKeys ?? [])]);
        const next: Entity = { ...current };
        for (const [key, value] of Object.entries(changes)) {
            if (key === this.idField || value === undefined) continue;
            if (merge.has(key) && (isPlainObject(value) || value === null)) {
                next[key] = value === null ? {} : mergeShallow(current[key], value);
            } else {
                next[key] = clone(value);
            }
        }
        if (this.timestamps && !options.silent) next.updated_at = new Date().toISOString();
        this.items.set(id, next as T);
        return clone(next as T);
    }

    delete(id: string): boolean {
        return this.items.delete(id);
    }

    clear(): void {
        this.items.clear();
    }

    load(items: T[]): void {
        for (const item of items) this.put(item);
    }

    toJSON(): T[] {
        return this.all();
    }
}
