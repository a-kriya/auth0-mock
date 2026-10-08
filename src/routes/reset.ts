import { Router, type Response } from 'express';
import type { AppContext } from '../context.ts';
import { userPatchChanges } from '../model/users.ts';
import type { Entity } from '../store/collection.ts';
import { isPlainObject } from '../util/merge.ts';
import { messageView, resetPasswordView } from '../views/reset.ts';

/** Completion pages for password-change and email-verification tickets. */
export function ticketPages(ctx: AppContext): Router {
    const router = Router();
    const { store } = ctx;

    const loadTicket = (res: Response, id: unknown, type: string): { ticket: Entity; user: Entity } | undefined => {
        const ticket = typeof id === 'string' ? store.tickets.get(id) : undefined;
        const user = ticket ? store.users.get(String(ticket.user_id)) : undefined;
        if (!ticket || !user || ticket.type !== type || ticket.used_at || Number(ticket.expires_at) < Date.now()) {
            res.status(400)
                .type('html')
                .send(messageView('This link is invalid or has expired', 'Request a new link and try again.'));
            return undefined;
        }
        return { ticket, user };
    };

    const finish = (res: Response, ticket: Entity, message: string) => {
        store.tickets.patch(String(ticket.id), { used_at: Date.now() });
        const resultUrl = typeof ticket.result_url === 'string' ? ticket.result_url : undefined;
        if (resultUrl) {
            const url = new URL(resultUrl);
            url.searchParams.set('success', 'true');
            url.searchParams.set('message', message);
            if (ticket.include_email_in_redirect === true) {
                const user = store.users.get(String(ticket.user_id));
                if (user?.email) url.searchParams.set('email', String(user.email));
            }
            res.redirect(302, url.toString());
            return;
        }
        res.type('html').send(messageView('Success', message));
    };

    router.get('/lo/reset', (req, res) => {
        const loaded = loadTicket(res, req.query.ticket, 'password-change');
        if (!loaded) return;
        res.type('html').send(
            resetPasswordView({ ticket: String(loaded.ticket.id), email: String(loaded.user.email ?? '') })
        );
    });

    router.post('/lo/reset', (req, res) => {
        const body: Entity = isPlainObject(req.body) ? req.body : {};
        const loaded = loadTicket(res, req.query.ticket ?? body.ticket, 'password-change');
        if (!loaded) return;
        const password = typeof body.password === 'string' ? body.password : '';
        const confirm = typeof body['re-password'] === 'string' ? body['re-password'] : '';
        const email = String(loaded.user.email ?? '');
        if (password.length < 8) {
            res.status(400)
                .type('html')
                .send(resetPasswordView({ ticket: String(loaded.ticket.id), email, error: 'Password is too weak' }));
            return;
        }
        if (password !== confirm) {
            res.status(400)
                .type('html')
                .send(resetPasswordView({ ticket: String(loaded.ticket.id), email, error: 'Passwords do not match' }));
            return;
        }
        const changes = userPatchChanges(store, loaded.user, { password });
        if (loaded.ticket.mark_email_as_verified === true) changes.email_verified = true;
        store.users.patch(String(loaded.user.user_id), changes);
        store.userBlocks.delete(String(loaded.user.user_id));
        finish(res, loaded.ticket, 'You can now login to the application with the new password.');
    });

    router.get('/u/email-verification', (req, res) => {
        const loaded = loadTicket(res, req.query.ticket, 'email-verification');
        if (!loaded) return;
        store.users.patch(String(loaded.user.user_id), { email_verified: true });
        finish(res, loaded.ticket, 'Your email was verified. You can continue using the application.');
    });

    return router;
}
