import express, { type ErrorRequestHandler, type Express, type RequestHandler } from 'express';
import type { AppContext } from './context.ts';
import { HttpError } from './errors.ts';
import { adminRoutes, type AdminHooks } from './routes/admin.ts';
import { managementRouter } from './routes/management/index.ts';
import { authorizeRoutes } from './routes/authorize.ts';
import { oauthRoutes } from './routes/oauth.ts';
import { openidRoutes } from './routes/openid.ts';
import { ticketPages } from './routes/reset.ts';

/** Reflect the caller's origin so browser SDKs (auth0-spa-js) can call the emulator with credentials. */
const cors: RequestHandler = (req, res, next) => {
    const origin = req.headers.origin;
    res.setHeader('Access-Control-Allow-Origin', origin ?? '*');
    res.setHeader('Vary', 'Origin');
    if (origin) res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.setHeader(
        'Access-Control-Allow-Headers',
        req.headers['access-control-request-headers'] ?? 'Authorization, Content-Type, Auth0-Client'
    );
    res.setHeader('Access-Control-Max-Age', '600');
    if (req.method === 'OPTIONS') return res.status(204).end();
    next();
};

function requestLogger(ctx: AppContext): RequestHandler {
    return (req, res, next) => {
        if (ctx.log.level !== 'debug') return next();
        const started = Date.now();
        res.on('finish', () => {
            ctx.log.debug(`${req.method} ${req.originalUrl} -> ${res.statusCode} (${Date.now() - started}ms)`);
        });
        next();
    };
}

function errorHandler(ctx: AppContext): ErrorRequestHandler {
    return (error: unknown, req, res, _next) => {
        if (error instanceof HttpError) {
            if (error.status >= 500) ctx.log.error(`${req.method} ${req.originalUrl}: ${error.message}`);
            res.status(error.status).json(error.body);
            return;
        }
        const parseFailure = (error as { type?: string }).type === 'entity.parse.failed';
        if (parseFailure) {
            res.status(400).json({
                statusCode: 400,
                error: 'Bad Request',
                message: 'Invalid JSON body',
                errorCode: 'invalid_body',
            });
            return;
        }
        ctx.log.error(`${req.method} ${req.originalUrl}: unexpected error`, error);
        res.status(500).json({
            statusCode: 500,
            error: 'Internal Server Error',
            message: error instanceof Error ? error.message : String(error),
        });
    };
}

export function createApp(ctx: AppContext, hooks: AdminHooks): Express {
    const app = express();
    app.disable('x-powered-by');
    app.set('trust proxy', true);
    app.set('etag', false);

    app.use(cors);
    app.use(express.json({ limit: '5mb', type: ['application/json', 'application/*+json'] }));
    app.use(express.urlencoded({ extended: false }));
    app.use(requestLogger(ctx));

    app.use('/__mock', adminRoutes(ctx, hooks));
    app.use('/api/v2', managementRouter(ctx));
    app.use(openidRoutes(ctx));
    app.use(oauthRoutes(ctx));
    app.use(authorizeRoutes(ctx));
    app.use(ticketPages(ctx));

    app.use('/api/v2', (_req, res) => {
        res.status(404).json({ statusCode: 404, error: 'Not Found', message: 'Not Found' });
    });
    app.use((_req, res) => {
        res.status(404).json({ error: 'not_found', error_description: 'The requested resource does not exist' });
    });
    app.use(errorHandler(ctx));
    return app;
}
