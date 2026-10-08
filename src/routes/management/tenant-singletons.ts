import { Router } from 'express';
import type { AppContext } from '../../context.ts';
import { badRequest, notFound } from '../../errors.ts';
import { ensureBody } from '../../model/validate.ts';
import type { Entity } from '../../store/collection.ts';
import { isPlainObject, mergeShallow } from '../../util/merge.ts';
import { requireScope } from './auth.ts';

/** Merge one level of nested objects (Auth0 PATCH semantics for settings objects). */
export function mergeSettings(base: Entity, changes: Entity): Entity {
    const next = { ...base };
    for (const [key, value] of Object.entries(changes)) {
        next[key] = isPlainObject(value) && isPlainObject(next[key]) ? mergeShallow(next[key], value) : value;
    }
    return next;
}

/** Attack protection, prompts, branding and email provider: tenant-wide singletons. */
export function tenantSingletonRoutes(ctx: AppContext): Router {
    const router = Router();
    const { store } = ctx;

    const protectionKeys = {
        'breached-password-detection': 'breachedPassword',
        'brute-force-protection': 'bruteForce',
        'suspicious-ip-throttling': 'suspiciousIp',
        'bot-detection': 'botDetection',
        captcha: 'captcha',
    } as const;

    for (const [path, key] of Object.entries(protectionKeys) as Array<
        [keyof typeof protectionKeys, (typeof protectionKeys)[keyof typeof protectionKeys]]
    >) {
        router.get(`/attack-protection/${path}`, requireScope('read:attack_protection'), (_req, res) => {
            res.json(store.attackProtection[key]);
        });
        router.patch(`/attack-protection/${path}`, requireScope('update:attack_protection'), (req, res) => {
            store.attackProtection[key] = mergeSettings(store.attackProtection[key], ensureBody(req.body));
            res.json(store.attackProtection[key]);
        });
    }

    router.get('/prompts', requireScope('read:prompts'), (_req, res) => {
        res.json(store.prompts);
    });
    router.patch('/prompts', requireScope('update:prompts'), (req, res) => {
        store.prompts = mergeSettings(store.prompts, ensureBody(req.body));
        res.json(store.prompts);
    });

    router.get('/branding', requireScope('read:branding'), (_req, res) => {
        res.json(store.branding);
    });
    router.patch('/branding', requireScope('update:branding'), (req, res) => {
        store.branding = mergeSettings(store.branding, ensureBody(req.body));
        res.json(store.branding);
    });

    router.get('/emails/provider', requireScope('read:email_provider'), (req, res) => {
        if (!store.emailProvider) throw notFound('There is no configured email provider', 'inexistent_email_provider');
        const provider = { ...store.emailProvider };
        if (String(req.query.include_fields) !== 'true' || !String(req.query.fields ?? '').includes('credentials')) {
            delete provider.credentials;
        }
        res.json(provider);
    });
    router.post('/emails/provider', requireScope('create:email_provider'), (req, res) => {
        const body = ensureBody(req.body);
        if (typeof body.name !== 'string') throw badRequest("Payload validation error: 'name' is required");
        if (store.emailProvider) throw badRequest('An email provider is already configured', 'email_provider_conflict');
        store.emailProvider = { enabled: true, ...body };
        const { credentials: _c, ...view } = store.emailProvider;
        res.status(201).json(view);
    });
    router.patch('/emails/provider', requireScope('update:email_provider'), (req, res) => {
        if (!store.emailProvider) throw notFound('There is no configured email provider', 'inexistent_email_provider');
        store.emailProvider = mergeSettings(store.emailProvider, ensureBody(req.body));
        const { credentials: _c, ...view } = store.emailProvider;
        res.json(view);
    });
    router.delete('/emails/provider', requireScope('delete:email_provider'), (_req, res) => {
        store.emailProvider = null;
        res.status(204).end();
    });

    return router;
}
