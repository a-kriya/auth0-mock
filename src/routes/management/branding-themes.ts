import { Router } from 'express';
import type { AppContext } from '../../context.ts';
import { badRequest, notFound } from '../../errors.ts';
import { ensureBody } from '../../model/validate.ts';
import { generateId } from '../../store/ids.ts';
import { param } from '../util.ts';
import { requireScope } from './auth.ts';

const THEME_SECTIONS = ['borders', 'colors', 'fonts', 'page_background', 'widget'] as const;

const EMAIL_TEMPLATE_NAMES = new Set([
    'verify_email',
    'verify_email_by_code',
    'reset_email',
    'reset_email_by_code',
    'welcome_email',
    'blocked_account',
    'stolen_credentials',
    'enrollment_email',
    'mfa_oob_code',
    'user_invitation',
    'change_password',
    'password_reset',
]);

/** Branding themes (one per tenant, like Auth0) and email templates. */
export function brandingThemeRoutes(ctx: AppContext): Router {
    const router = Router();
    const { store } = ctx;

    router.get('/branding/themes/default', requireScope('read:branding'), (_req, res) => {
        const theme = store.brandingThemes.all()[0];
        if (!theme) throw notFound('Theme not found', 'theme_not_found');
        res.json(theme);
    });

    router.post('/branding/themes', requireScope('create:branding', 'update:branding'), (req, res) => {
        const body = ensureBody(req.body);
        if (store.brandingThemes.size > 0) {
            throw badRequest('You have reached the maximum number of themes for this tenant', 'themes_limit_reached');
        }
        for (const section of THEME_SECTIONS) {
            if (typeof body[section] !== 'object' || body[section] === null) {
                throw badRequest(`Payload validation error: '${section}' is required`);
            }
        }
        const { themeId: _t, ...rest } = body;
        res.status(201).json(store.brandingThemes.insert({ themeId: generateId.themeId(), ...rest }));
    });

    router.get('/branding/themes/:id', requireScope('read:branding'), (req, res) => {
        res.json(store.brandingThemes.require(param(req, 'id'), 'Theme not found'));
    });

    router.patch('/branding/themes/:id', requireScope('update:branding'), (req, res) => {
        const body = ensureBody(req.body);
        const changes = { ...body };
        delete changes.themeId;
        res.json(store.brandingThemes.patch(param(req, 'id'), changes));
    });

    router.delete('/branding/themes/:id', requireScope('delete:branding'), (req, res) => {
        store.brandingThemes.delete(param(req, 'id'));
        res.status(204).end();
    });

    // --- Email templates ---

    const templateName = (raw: string): string => {
        if (!EMAIL_TEMPLATE_NAMES.has(raw)) throw badRequest(`Unknown email template '${raw}'`, 'invalid_template');
        return raw;
    };

    router.post('/email-templates', requireScope('create:email_templates'), (req, res) => {
        const body = ensureBody(req.body);
        if (typeof body.template !== 'string') throw badRequest("Payload validation error: 'template' is required");
        const name = templateName(body.template);
        if (store.emailTemplates.has(name)) {
            throw badRequest(`The email template '${name}' already exists`, 'email_template_conflict');
        }
        const template = { enabled: true, syntax: 'liquid', ...body, template: name };
        store.emailTemplates.set(name, template);
        res.status(200).json(template);
    });

    router.get('/email-templates/:name', requireScope('read:email_templates'), (req, res) => {
        const template = store.emailTemplates.get(templateName(param(req, 'name')));
        if (!template) throw notFound('The email template does not exist', 'inexistent_email_template');
        res.json(template);
    });

    router.put('/email-templates/:name', requireScope('update:email_templates'), (req, res) => {
        const name = templateName(param(req, 'name'));
        const body = ensureBody(req.body);
        const template = { enabled: true, syntax: 'liquid', ...body, template: name };
        store.emailTemplates.set(name, template);
        res.json(template);
    });

    router.patch('/email-templates/:name', requireScope('update:email_templates'), (req, res) => {
        const name = templateName(param(req, 'name'));
        const current = store.emailTemplates.get(name);
        if (!current) throw notFound('The email template does not exist', 'inexistent_email_template');
        const template = { ...current, ...ensureBody(req.body), template: name };
        store.emailTemplates.set(name, template);
        res.json(template);
    });

    return router;
}
