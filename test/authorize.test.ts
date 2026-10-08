import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
    PASSWORD_REALM,
    REALM,
    REDIRECT_URI,
    authorize,
    browserLogin,
    cookieHeader,
    loginState,
    pkce,
    postForm,
    sessionCookies,
    submitLogin,
    type AuthorizeParams,
} from './auth-flows.ts';
import { API_AUDIENCE, PASSWORD, decodeJwt, provisionTenant, startMock, type Harness, type Tenant } from './helpers.ts';

describe('GET /authorize and the login page', () => {
    let h: Harness;
    let t: Tenant;
    beforeAll(async () => {
        h = await startMock();
        t = await provisionTenant(h);
    });
    afterAll(() => h.close());

    const params = (extra: AuthorizeParams = {}): AuthorizeParams => ({
        client_id: t.clients.spa.client_id,
        redirect_uri: REDIRECT_URI,
        response_type: 'code',
        scope: 'openid profile email',
        audience: API_AUDIENCE,
        state: 'client-state',
        ...extra,
    });
    const exchange = (code: string | null, extra: Record<string, unknown> = {}) =>
        h.token({
            grant_type: 'authorization_code',
            client_id: t.clients.spa.client_id,
            code,
            redirect_uri: REDIRECT_URI,
            ...extra,
        });

    it('rejects an unknown client with an HTML error page', async () => {
        const res = await authorize(h, params({ client_id: 'nope' }));
        expect(res.status).toBe(400);
        expect(res.headers.get('content-type')).toContain('text/html');
        const html = await res.text();
        expect(html).toContain('Oops!, something went wrong');
        expect(html).toContain('Unknown client: nope');
    });

    it('rejects a redirect_uri that is not a registered callback', async () => {
        const res = await authorize(h, params({ redirect_uri: 'http://evil.example/cb' }));
        expect(res.status).toBe(400);
        expect(res.headers.get('content-type')).toContain('text/html');
        const html = await res.text();
        expect(html).toContain('Callback URL mismatch');
        expect(html).toContain('http://evil.example/cb is not in the list of allowed callback URLs');
    });

    it('redirects a valid request to the login page', async () => {
        const res = await authorize(h, params());
        expect(res.status).toBe(302);
        expect(res.headers.get('location')).toMatch(/^\/u\/login\?state=[A-Za-z0-9_-]{32}$/);
        expect(sessionCookies(res)).toEqual([]);
    });

    it('renders the login form, prefilled and read-only with a login_hint', async () => {
        const state = loginState(await authorize(h, params({ login_hint: 'alice@example.com' })));
        const res = await h.fetch(`/u/login?state=${encodeURIComponent(state)}`);
        expect(res.status).toBe(200);
        expect(res.headers.get('content-type')).toContain('text/html');
        const html = await res.text();
        expect(html).toContain(
            '<input id="username" name="username" type="email" value="alice@example.com" readonly autocomplete="username">'
        );
        expect(html).toContain('<input id="password" name="password" type="password"');
        expect(html).toContain('<button type="submit" name="action" value="default">');
        expect(html).toContain(`<form method="post" action="/u/login?state=${state}"`);
        expect(html).toContain(`<input type="hidden" name="state" value="${state}">`);
        expect(html).toContain('Example SPA');
        expect(html).not.toContain('error-element-password');

        const plain = await h.fetch(`/u/login?state=${loginState(await authorize(h, params()))}`);
        const plainHtml = await plain.text();
        expect(plainHtml).toContain('<input id="username" name="username" type="email" value="" required');
        expect(plainHtml).not.toContain('readonly');
    });

    it('re-renders the form with an error on a wrong password', async () => {
        const state = loginState(await authorize(h, params()));
        const res = await submitLogin(h, state, 'alice@example.com', 'nope');
        expect(res.status).toBe(400);
        expect(res.headers.get('content-type')).toContain('text/html');
        const html = await res.text();
        expect(html).toContain(
            '<span id="error-element-password" class="error-message">Wrong email or password</span>'
        );
        expect(html).toContain('value="alice@example.com"');
        expect(html).toContain('class="error"');
        expect(res.headers.get('location')).toBeNull();
        expect(sessionCookies(res)).toEqual([]);

        const unknown = await submitLogin(h, state, 'nobody@example.com', PASSWORD);
        expect(unknown.status).toBe(400);
        expect(await unknown.text()).toContain('Wrong email or password');
    });

    it('redirects with a code, sets a session cookie and exchanges the code with PKCE', async () => {
        const { verifier, challenge } = pkce();
        const login = await browserLogin(
            h,
            params({
                scope: 'openid profile email read:things write:things',
                nonce: 'nonce-1',
                state: 'client-state-42',
                code_challenge: challenge,
                code_challenge_method: 'S256',
            }),
            'alice@example.com',
            PASSWORD
        );
        expect(login.response.status).toBe(302);
        expect(`${login.location.origin}${login.location.pathname}`).toBe('http://localhost:3000/');
        expect([...login.params.keys()].sort()).toEqual(['code', 'state']);
        expect(login.params.get('state')).toBe('client-state-42');
        expect(login.code).toMatch(/^[A-Za-z0-9_-]{43}$/);
        expect(login.sid).toMatch(/^[A-Za-z0-9_-]{32}$/);
        expect(login.response.headers.getSetCookie()).toEqual([
            `auth0-mock.sid=${login.sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800`,
        ]);

        const before = Math.floor(Date.now() / 1000);
        const exchanged = await exchange(login.code, { code_verifier: verifier });
        expect(exchanged.status).toBe(200);
        expect(Object.keys(exchanged.body).sort()).toEqual([
            'access_token',
            'expires_in',
            'id_token',
            'scope',
            'token_type',
        ]);
        expect(exchanged.body).toMatchObject({
            token_type: 'Bearer',
            expires_in: 900,
            scope: 'openid profile email read:things write:things',
        });

        const id = decodeJwt(exchanged.body.id_token);
        expect(id).toMatchObject({
            iss: h.issuer,
            sub: 'auth0|alice',
            aud: t.clients.spa.client_id,
            nonce: 'nonce-1',
            sid: login.sid,
            email: 'alice@example.com',
            name: 'Alice Example',
        });
        expect(id.auth_time).toBeGreaterThan(before - 10);
        expect(id.auth_time).toBeLessThanOrEqual(before + 1);

        const access = decodeJwt(exchanged.body.access_token);
        expect(access).toMatchObject({
            sub: 'auth0|alice',
            sid: login.sid,
            azp: t.clients.spa.client_id,
            aud: [API_AUDIENCE, `${h.issuer}userinfo`],
            scope: 'openid profile email read:things write:things',
        });
        expect([...access.permissions].sort()).toEqual(['admin:things', 'read:things', 'write:things']);
        expect(access.gty).toBeUndefined();
    });

    it('rejects a wrong code_verifier', async () => {
        const { challenge } = pkce();
        const login = await browserLogin(
            h,
            params({ code_challenge: challenge, code_challenge_method: 'S256' }),
            'alice@example.com',
            PASSWORD
        );
        expect(login.code).not.toBeNull();
        const res = await exchange(login.code, { code_verifier: 'not-the-verifier' });
        expect(res.status).toBe(403);
        expect(res.body).toEqual({ error: 'invalid_grant', error_description: 'Failed to verify code verifier' });

        const missing = await browserLogin(
            h,
            params({ code_challenge: challenge, code_challenge_method: 'S256' }),
            'alice@example.com',
            PASSWORD
        );
        const noVerifier = await exchange(missing.code);
        expect(noVerifier.status).toBe(403);
        expect(noVerifier.body).toEqual({
            error: 'invalid_grant',
            error_description: 'Failed to verify code verifier',
        });
    });

    it('rejects a reused code', async () => {
        const login = await browserLogin(h, params(), 'alice@example.com', PASSWORD);
        expect((await exchange(login.code)).status).toBe(200);
        const res = await exchange(login.code);
        expect(res.status).toBe(403);
        expect(res.body).toEqual({ error: 'invalid_grant', error_description: 'Invalid authorization code' });
    });

    it('rejects a mismatched redirect_uri and codes of another client', async () => {
        const login = await browserLogin(h, params(), 'alice@example.com', PASSWORD);
        const res = await exchange(login.code, { redirect_uri: 'http://localhost:3000/callback' });
        expect(res.status).toBe(403);
        expect(res.body).toEqual({ error: 'invalid_grant', error_description: 'Invalid authorization code' });

        const other = await h.mgmt('POST', '/clients', {
            name: 'Other SPA',
            app_type: 'spa',
            grant_types: ['authorization_code'],
        });
        const again = await browserLogin(h, params(), 'alice@example.com', PASSWORD);
        const foreign = await exchange(again.code, { client_id: other.body.client_id });
        expect(foreign.status).toBe(403);
        expect(foreign.body).toEqual({ error: 'invalid_grant', error_description: 'Invalid authorization code' });
    });

    it('answers prompt=none over web_message when a session exists', async () => {
        const login = await browserLogin(h, params(), 'alice@example.com', PASSWORD);
        const res = await authorize(
            h,
            params({ prompt: 'none', response_mode: 'web_message', state: 'silent-1', nonce: 'silent-nonce' }),
            login.sid
        );
        expect(res.status).toBe(200);
        expect(res.headers.get('content-type')).toContain('text/html');
        const html = await res.text();
        expect(html).toContain('"type":"authorization_response"');
        expect(html).toContain('"state":"silent-1"');
        expect(html).toContain('var targetOrigin = "http://localhost:3000"');
        const code = html.match(/"code":"([A-Za-z0-9_-]{43})"/)?.[1];
        expect(code).toBeDefined();

        const exchanged = await exchange(code ?? null);
        expect(exchanged.status).toBe(200);
        expect(decodeJwt(exchanged.body.id_token)).toMatchObject({
            sub: 'auth0|alice',
            sid: login.sid,
            nonce: 'silent-nonce',
        });
    });

    it('redirects prompt=none without a session with login_required', async () => {
        const res = await authorize(h, params({ prompt: 'none', state: 'silent-2' }));
        expect(res.status).toBe(302);
        expect(res.headers.get('location')).toBe(
            'http://localhost:3000/?error=login_required&error_description=Login+required&state=silent-2'
        );

        const webMessage = await authorize(h, params({ prompt: 'none', response_mode: 'web_message' }));
        expect(webMessage.status).toBe(200);
        expect(await webMessage.text()).toContain('"error":"login_required"');
    });

    it('shows the login page for prompt=login despite a session', async () => {
        const login = await browserLogin(h, params(), 'alice@example.com', PASSWORD);
        const res = await authorize(h, params({ prompt: 'login' }), login.sid);
        expect(res.status).toBe(302);
        expect(res.headers.get('location')).toMatch(/^\/u\/login\?state=/);

        const silent = await authorize(h, params({ state: 'sso' }), login.sid);
        expect(silent.status).toBe(302);
        expect(silent.headers.get('location')).toMatch(/^http:\/\/localhost:3000\/\?code=[A-Za-z0-9_-]{43}&state=sso$/);
    });

    it('delivers the response in the fragment for response_mode=fragment', async () => {
        const login = await browserLogin(
            h,
            params({ response_mode: 'fragment', state: 'frag' }),
            'alice@example.com',
            PASSWORD
        );
        expect(login.response.status).toBe(302);
        expect(login.location.search).toBe('');
        expect(login.location.hash).toMatch(/^#code=[A-Za-z0-9_-]{43}&state=frag$/);
        expect((await exchange(login.code)).status).toBe(200);
    });

    it('returns an auto-submitting form for response_mode=form_post', async () => {
        const login = await browserLogin(
            h,
            params({ response_mode: 'form_post', state: 'form' }),
            'alice@example.com',
            PASSWORD
        );
        expect(login.response.status).toBe(200);
        expect(login.response.headers.get('content-type')).toContain('text/html');
        const html = await login.response.text();
        expect(html).toContain('<body onload="document.forms[0].submit()">');
        expect(html).toContain('<form method="post" action="http://localhost:3000">');
        expect(html).toContain('<input type="hidden" name="state" value="form">');
        const code = html.match(/<input type="hidden" name="code" value="([A-Za-z0-9_-]{43})">/)?.[1];
        expect(code).toBeDefined();
        expect((await exchange(code ?? null)).status).toBe(200);
    });

    it('returns tokens in the fragment for response_type=token id_token', async () => {
        const login = await browserLogin(
            h,
            params({ response_type: 'token id_token', nonce: 'implicit-nonce', scope: 'openid email read:things' }),
            'alice@example.com',
            PASSWORD
        );
        expect(login.response.status).toBe(302);
        expect(login.location.search).toBe('');
        expect([...login.params.keys()].sort()).toEqual([
            'access_token',
            'expires_in',
            'id_token',
            'scope',
            'state',
            'token_type',
        ]);
        expect(login.params.get('token_type')).toBe('Bearer');
        expect(login.params.get('expires_in')).toBe('900');
        expect(login.params.get('scope')).toBe('openid email read:things');
        expect(login.params.get('state')).toBe('client-state');
        const access = decodeJwt(login.params.get('access_token') ?? '');
        expect(access).toMatchObject({
            sub: 'auth0|alice',
            gty: 'implicit',
            sid: login.sid,
            scope: 'openid email read:things',
        });
        const id = decodeJwt(login.params.get('id_token') ?? '');
        expect(id).toMatchObject({
            sub: 'auth0|alice',
            nonce: 'implicit-nonce',
            email: 'alice@example.com',
            sid: login.sid,
        });
        expect(id.name).toBeUndefined();
    });

    it('GET /v2/logout clears the session and honours returnTo', async () => {
        const login = await browserLogin(h, params(), 'alice@example.com', PASSWORD);
        const query = `client_id=${t.clients.spa.client_id}&returnTo=${encodeURIComponent(REDIRECT_URI)}`;
        const res = await h.fetch(`/v2/logout?${query}`, { headers: cookieHeader(login.sid) });
        expect(res.status).toBe(302);
        expect(res.headers.get('location')).toBe(REDIRECT_URI);
        expect(res.headers.getSetCookie()).toEqual(['auth0-mock.sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0']);

        const silent = await authorize(h, params({ prompt: 'none', state: 'after-logout' }), login.sid);
        expect(silent.status).toBe(302);
        expect(silent.headers.get('location')).toBe(
            'http://localhost:3000/?error=login_required&error_description=Login+required&state=after-logout'
        );

        const noReturn = await h.fetch('/v2/logout');
        expect(noReturn.status).toBe(200);
        expect(await noReturn.text()).toContain('You have been logged out.');
    });

    it('rejects a returnTo outside the Allowed Logout URLs', async () => {
        const res = await h.fetch(
            `/v2/logout?client_id=${t.clients.spa.client_id}&returnTo=${encodeURIComponent('http://evil.example/')}`
        );
        expect(res.status).toBe(400);
        expect(res.headers.get('content-type')).toContain('text/plain');
        expect(await res.text()).toBe(
            'The "returnTo" querystring parameter "http://evil.example/" is not defined as a valid URL in "Allowed Logout URLs".'
        );
    });

    it('serves the same logout at /oidc/logout', async () => {
        const login = await browserLogin(h, params(), 'alice@example.com', PASSWORD);
        const ok = await h.fetch(
            `/oidc/logout?client_id=${t.clients.spa.client_id}&post_logout_redirect_uri=${encodeURIComponent(REDIRECT_URI)}`,
            { headers: cookieHeader(login.sid) }
        );
        expect(ok.status).toBe(302);
        expect(ok.headers.get('location')).toBe(REDIRECT_URI);
        expect(sessionCookies(ok)).toEqual(['']);
        const silent = await authorize(h, params({ prompt: 'none' }), login.sid);
        expect(silent.headers.get('location')).toContain('error=login_required');

        const bad = await h.fetch(
            `/oidc/logout?client_id=${t.clients.spa.client_id}&returnTo=${encodeURIComponent('http://evil.example/')}`
        );
        expect(bad.status).toBe(400);
        expect(await bad.text()).toContain('Allowed Logout URLs');
    });

    it('rejects an invalid or expired state on /u/login', async () => {
        const get = await h.fetch('/u/login?state=does-not-exist');
        expect(get.status).toBe(400);
        expect(get.headers.get('content-type')).toContain('text/html');
        expect(await get.text()).toContain('Invalid or expired login transaction (state).');

        const post = await submitLogin(h, 'does-not-exist', 'alice@example.com', PASSWORD);
        expect(post.status).toBe(400);
        expect(await post.text()).toContain('Invalid or expired login transaction (state).');

        const noState = await h.fetch('/u/login');
        expect(noState.status).toBe(400);
    });
});

describe('password-change and email-verification tickets', () => {
    let h: Harness;
    let t: Tenant;
    beforeAll(async () => {
        h = await startMock();
        t = await provisionTenant(h);
    });
    afterAll(() => h.close());

    const login = (username: string, password: string) =>
        h.token({
            grant_type: PASSWORD_REALM,
            client_id: t.clients.spa.client_id,
            realm: REALM,
            username,
            password,
            audience: API_AUDIENCE,
            scope: 'read:things',
        });
    const ticketOf = (url: string) => new URL(url).searchParams.get('ticket') ?? '';

    it('changes the password through a single-use ticket page', async () => {
        await h.mgmt('PATCH', `/users/${encodeURIComponent(t.users.bob)}`, { email_verified: false });
        const created = await h.mgmt('POST', '/tickets/password-change', {
            user_id: t.users.bob,
            mark_email_as_verified: true,
            result_url: 'http://localhost:3000/done',
        });
        expect(created.status).toBe(201);
        expect(created.body.ticket).toMatch(new RegExp(`^${h.issuer}lo/reset\\?ticket=[A-Za-z0-9_-]{43}#$`));
        const ticket = ticketOf(created.body.ticket);
        const path = `/lo/reset?ticket=${ticket}`;

        const page = await h.fetch(path);
        expect(page.status).toBe(200);
        expect(page.headers.get('content-type')).toContain('text/html');
        const html = await page.text();
        expect(html).toContain(`<form method="post" action="${path}">`);
        expect(html).toContain('<input id="password" name="password" type="password"');
        expect(html).toContain('<input id="re-password" name="re-password" type="password"');
        expect(html).toContain('bob@example.com');

        const mismatch = await postForm(h, path, { password: 'NewPassw0rd!', 're-password': 'Different0!' });
        expect(mismatch.status).toBe(400);
        expect(await mismatch.text()).toContain(
            '<span id="error-element-password" class="error-message">Passwords do not match</span>'
        );

        const weak = await postForm(h, path, { password: 'short', 're-password': 'short' });
        expect(weak.status).toBe(400);
        expect(await weak.text()).toContain('Password is too weak');

        const done = await postForm(h, path, { password: 'NewPassw0rd!', 're-password': 'NewPassw0rd!' });
        expect(done.status).toBe(302);
        const location = new URL(done.headers.get('location') ?? 'about:blank');
        expect(`${location.origin}${location.pathname}`).toBe('http://localhost:3000/done');
        expect(location.searchParams.get('success')).toBe('true');
        expect(location.searchParams.get('message')).toBe(
            'You can now login to the application with the new password.'
        );

        expect((await login('bob@example.com', 'NewPassw0rd!')).status).toBe(200);
        const old = await login('bob@example.com', PASSWORD);
        expect(old.status).toBe(403);
        expect(old.body).toEqual({ error: 'invalid_grant', error_description: 'Wrong email or password.' });

        const user = await h.mgmt('GET', `/users/${encodeURIComponent(t.users.bob)}`);
        expect(user.body.email_verified).toBe(true);
        expect(user.body.last_password_reset).toEqual(expect.any(String));

        const reused = await h.fetch(path);
        expect(reused.status).toBe(400);
        expect(await reused.text()).toContain('This link is invalid or has expired');
        const reusedPost = await postForm(h, path, { password: 'Another0ne!', 're-password': 'Another0ne!' });
        expect(reusedPost.status).toBe(400);
    });

    it('rejects unknown tickets and tickets for another purpose', async () => {
        const res = await h.fetch('/lo/reset?ticket=nope');
        expect(res.status).toBe(400);
        expect(await res.text()).toContain('This link is invalid or has expired');

        const verification = await h.mgmt('POST', '/tickets/email-verification', { user_id: t.users.alice });
        expect(verification.status).toBe(201);
        const wrongPurpose = await h.fetch(`/lo/reset?ticket=${ticketOf(verification.body.ticket)}`);
        expect(wrongPurpose.status).toBe(400);
    });

    it('marks the email verified through the verification ticket', async () => {
        const carol = await h.mgmt('POST', '/users', {
            connection: REALM,
            email: 'carol@example.com',
            password: PASSWORD,
            email_verified: false,
        });
        expect(carol.status).toBe(201);
        expect(carol.body.email_verified).toBe(false);

        const created = await h.mgmt('POST', '/tickets/email-verification', {
            user_id: carol.body.user_id,
            result_url: 'http://localhost:3000/verified',
        });
        expect(created.status).toBe(201);
        expect(created.body.ticket).toMatch(
            new RegExp(`^${h.issuer}u/email-verification\\?ticket=[A-Za-z0-9_-]{43}#$`)
        );
        const path = `/u/email-verification?ticket=${ticketOf(created.body.ticket)}`;

        const res = await h.fetch(path);
        expect(res.status).toBe(302);
        const location = new URL(res.headers.get('location') ?? 'about:blank');
        expect(`${location.origin}${location.pathname}`).toBe('http://localhost:3000/verified');
        expect(location.searchParams.get('success')).toBe('true');

        const user = await h.mgmt('GET', `/users/${encodeURIComponent(carol.body.user_id)}`);
        expect(user.body.email_verified).toBe(true);

        const reused = await h.fetch(path);
        expect(reused.status).toBe(400);

        const withoutResult = await h.mgmt('POST', '/tickets/email-verification', { user_id: carol.body.user_id });
        const plain = await h.fetch(`/u/email-verification?ticket=${ticketOf(withoutResult.body.ticket)}`);
        expect(plain.status).toBe(200);
        expect(await plain.text()).toContain('Your email was verified.');
    });
});
