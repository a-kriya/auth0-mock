import { badRequest } from '../errors.ts';

export interface PageQuery {
    page: number;
    perPage: number;
    includeTotals: boolean;
}

export interface PageResult<T> {
    start: number;
    limit: number;
    length: number;
    total: number;
    items: T[];
}

function toInt(value: unknown, name: string): number | undefined {
    if (value === undefined || value === '') return undefined;
    const n = Number(value);
    if (!Number.isInteger(n) || n < 0) throw badRequest(`Query parameter '${name}' must be a non-negative integer`);
    return n;
}

export function parseBoolean(value: unknown): boolean | undefined {
    if (value === undefined || value === '') return undefined;
    if (typeof value === 'boolean') return value;
    return String(value).toLowerCase() === 'true';
}

export function parsePageQuery(
    query: Record<string, unknown>,
    options: { defaultPerPage?: number; maxPerPage?: number } = {}
): PageQuery {
    const { defaultPerPage = 50, maxPerPage = 100 } = options;
    const perPage = toInt(query.per_page, 'per_page') ?? defaultPerPage;
    if (perPage > maxPerPage)
        throw badRequest(`Query parameter 'per_page' must be less than or equal to ${maxPerPage}`);
    return {
        page: toInt(query.page, 'page') ?? 0,
        perPage,
        includeTotals: parseBoolean(query.include_totals) ?? false,
    };
}

export function paginate<T>(items: T[], query: PageQuery): PageResult<T> {
    const start = query.page * query.perPage;
    const slice = items.slice(start, start + query.perPage);
    return { start, limit: query.perPage, length: slice.length, total: items.length, items: slice };
}

/** Shape the result the way Auth0 does: a bare array, or a totals object keyed by the collection name. */
export function pageResponse<T>(result: PageResult<T>, key: string, query: PageQuery): unknown {
    if (!query.includeTotals) return result.items;
    return {
        start: result.start,
        limit: result.limit,
        length: result.length,
        total: result.total,
        [key]: result.items,
    };
}
