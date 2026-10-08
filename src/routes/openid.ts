import { Router } from 'express';
import type { AppContext } from '../context.ts';
import { jwksDocument } from '../keys.ts';

export function openidRoutes(ctx: AppContext): Router {
    const router = Router();
    const { issuer } = ctx;

    router.get('/.well-known/jwks.json', (_req, res) => {
        res.json(jwksDocument(ctx.key));
    });

    router.get('/.well-known/openid-configuration', (_req, res) => {
        res.json({
            issuer,
            authorization_endpoint: `${issuer}authorize`,
            token_endpoint: `${issuer}oauth/token`,
            device_authorization_endpoint: `${issuer}oauth/device/code`,
            userinfo_endpoint: `${issuer}userinfo`,
            mfa_challenge_endpoint: `${issuer}mfa/challenge`,
            jwks_uri: `${issuer}.well-known/jwks.json`,
            registration_endpoint: `${issuer}oidc/register`,
            revocation_endpoint: `${issuer}oauth/revoke`,
            scopes_supported: [
                'openid',
                'profile',
                'offline_access',
                'name',
                'given_name',
                'family_name',
                'nickname',
                'email',
                'email_verified',
                'picture',
                'created_at',
                'identities',
                'phone',
                'address',
            ],
            response_types_supported: [
                'code',
                'token',
                'id_token',
                'code token',
                'code id_token',
                'token id_token',
                'code token id_token',
            ],
            code_challenge_methods_supported: ['S256', 'plain'],
            response_modes_supported: ['query', 'fragment', 'form_post', 'web_message'],
            subject_types_supported: ['public'],
            token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'private_key_jwt'],
            claims_supported: [
                'aud',
                'auth_time',
                'created_at',
                'email',
                'email_verified',
                'exp',
                'family_name',
                'given_name',
                'iat',
                'identities',
                'iss',
                'name',
                'nickname',
                'phone_number',
                'picture',
                'sub',
            ],
            request_uri_parameter_supported: false,
            request_parameter_supported: false,
            id_token_signing_alg_values_supported: ['RS256'],
            token_endpoint_auth_signing_alg_values_supported: ['RS256'],
            end_session_endpoint: `${issuer}oidc/logout`,
        });
    });

    return router;
}
