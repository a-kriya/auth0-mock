import { Router } from 'express';
import type { AppContext } from '../../context.ts';
import { badRequest, notFound } from '../../errors.ts';
import { findUserByEmail } from '../../model/users.ts';
import { ensureBody, optionalString } from '../../model/validate.ts';
import type { Entity } from '../../store/collection.ts';
import { generateId } from '../../store/ids.ts';
import { requireScope } from './auth.ts';

const DEFAULT_TTL = 432_000; // 5 days, Auth0's default and maximum

export function ticketRoutes(ctx: AppContext): Router {
    const router = Router();
    const { store } = ctx;

    const resolveUser = (body: Entity): Entity => {
        const userId = optionalString(body, 'user_id');
        if (userId) {
            const user = store.users.get(userId);
            if (!user) throw notFound('The user does not exist.');
            return user;
        }
        const email = optionalString(body, 'email');
        const connectionId = optionalString(body, 'connection_id');
        if (!email || !connectionId) {
            throw badRequest("Payload validation error: 'user_id' or both 'email' and 'connection_id' are required");
        }
        const connection = store.connections.get(connectionId);
        if (!connection) throw badRequest('The connection does not exist.', 'inexistent_connection');
        const user = findUserByEmail(store, email, String(connection.name));
        if (!user) throw notFound('The user does not exist.');
        return user;
    };

    const createTicket = (type: 'password-change' | 'email-verification', body: Entity, path: string) => {
        const user = resolveUser(body);
        const ttl =
            typeof body.ttl_sec === 'number' && body.ttl_sec > 0 ? Math.min(body.ttl_sec, DEFAULT_TTL) : DEFAULT_TTL;
        if (body.client_id !== undefined && body.result_url !== undefined) {
            throw badRequest("Payload validation error: 'client_id' and 'result_url' are mutually exclusive");
        }
        const clientId = optionalString(body, 'client_id');
        if (clientId && !store.clients.has(clientId)) throw badRequest(`Client '${clientId}' does not exist`);
        const id = generateId.ticketId();
        const now = Date.now();
        store.tickets.insert({
            id,
            type,
            user_id: user.user_id,
            client_id: clientId,
            result_url: optionalString(body, 'result_url'),
            mark_email_as_verified: body.mark_email_as_verified === true,
            include_email_in_redirect: body.includeEmailInRedirect === true,
            created_at: now,
            expires_at: now + ttl * 1000,
        });
        return { ticket: `${ctx.issuer}${path}?ticket=${id}#` };
    };

    router.post('/tickets/password-change', requireScope('create:user_tickets'), (req, res) => {
        res.status(201).json(createTicket('password-change', ensureBody(req.body), 'lo/reset'));
    });

    router.post('/tickets/email-verification', requireScope('create:user_tickets'), (req, res) => {
        res.status(201).json(createTicket('email-verification', ensureBody(req.body), 'u/email-verification'));
    });

    return router;
}
