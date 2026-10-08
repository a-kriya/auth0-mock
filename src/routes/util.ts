import type { Request } from 'express';
import { badRequest } from '../errors.ts';

/** Read a single string route parameter (Express 5 types params as `string | string[] | undefined`). */
export function param(req: Request, name: string): string {
    const value = (req.params as Record<string, string | string[] | undefined>)[name];
    if (typeof value !== 'string' || value.length === 0) throw badRequest(`Missing route parameter '${name}'`);
    return value;
}
