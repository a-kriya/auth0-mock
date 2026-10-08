import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { jwtVerify } from 'jose';
import type { AppContext } from '../../context.ts';
import { forbidden, unauthorized } from '../../errors.ts';
import { managementAudience } from '../../model/resource-servers.ts';

export interface ManagementAuth {
    admin: boolean;
    scopes: Set<string>;
    subject: string;
}

export function authOf(res: Response): ManagementAuth {
    const auth = res.locals.managementAuth as ManagementAuth | undefined;
    if (!auth) throw unauthorized();
    return auth;
}

/** Authenticate Management API calls: the static admin token, or a token minted by this emulator for its own API. */
export function managementAuthentication(ctx: AppContext): RequestHandler {
    return async (req: Request, res: Response, next: NextFunction) => {
        try {
            const header = req.headers.authorization;
            if (!header?.startsWith('Bearer ')) throw unauthorized('Missing authentication');
            const token = header.slice('Bearer '.length).trim();
            if (ctx.config.adminToken && token === ctx.config.adminToken) {
                res.locals.managementAuth = {
                    admin: true,
                    scopes: new Set(),
                    subject: 'admin',
                } satisfies ManagementAuth;
                return next();
            }
            let payload;
            try {
                ({ payload } = await jwtVerify(token, ctx.key.publicKey, {
                    issuer: ctx.issuer,
                    audience: managementAudience(ctx.issuer),
                    algorithms: ['RS256'],
                }));
            } catch {
                throw unauthorized('Invalid token');
            }
            const scopes = typeof payload.scope === 'string' ? payload.scope.split(' ').filter(Boolean) : [];
            res.locals.managementAuth = {
                admin: false,
                scopes: new Set(scopes),
                subject: payload.sub ?? '',
            } satisfies ManagementAuth;
            next();
        } catch (error) {
            next(error);
        }
    };
}

/** Require any one of the given scopes (admin token passes everything). */
export function requireScope(...scopes: string[]): RequestHandler {
    return (_req, res, next) => {
        const auth = authOf(res);
        if (auth.admin || scopes.some((s) => auth.scopes.has(s))) return next();
        next(forbidden(`Insufficient scope, expected any of: ${scopes.join(',')}`));
    };
}
