import { createHash, randomBytes } from 'node:crypto';
import type { Harness, JsonResponse } from './helpers.ts';

export const PASSWORD_REALM = 'http://auth0.com/oauth/grant-type/password-realm';
export const REALM = 'Username-Password-Authentication';
export const REDIRECT_URI = 'http://localhost:3000';
export const SESSION_COOKIE = 'auth0-mock.sid';

/** POST /oauth/token with extra request headers (`x-forwarded-for`, `authorization`, ...). */
export async function tokenRequest(
    h: Harness,
    body: Record<string, unknown>,
    headers: Record<string, string> = {}
): Promise<JsonResponse> {
    const res = await h.fetch('/oauth/token', {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify(body),
    });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : undefined, headers: res.headers };
}

/** Submit an HTML form (application/x-www-form-urlencoded). */
export function postForm(
    h: Harness,
    path: string,
    fields: Record<string, string>,
    headers: Record<string, string> = {}
): Promise<Response> {
    return h.fetch(path, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', ...headers },
        body: new URLSearchParams(fields).toString(),
    });
}

/** A fresh PKCE verifier and its S256 challenge. */
export function pkce(): { verifier: string; challenge: string } {
    const verifier = randomBytes(32).toString('base64url');
    return { verifier, challenge: createHash('sha256').update(verifier).digest('base64url') };
}

/** Every value a response assigns to the session cookie, in header order (`''` when it is cleared). */
export function sessionCookies(res: Response): string[] {
    return res.headers
        .getSetCookie()
        .map((header) => header.match(/^auth0-mock\.sid=([^;]*)/)?.[1])
        .filter((value): value is string => value !== undefined);
}

export const cookieHeader = (sid: string): Record<string, string> => ({ cookie: `${SESSION_COOKIE}=${sid}` });

export type AuthorizeParams = Record<string, string | undefined>;

/** GET /authorize with the given query, optionally presenting a session cookie. */
export function authorize(h: Harness, params: AuthorizeParams, sid?: string): Promise<Response> {
    const query = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) if (value !== undefined) query.set(key, value);
    return h.fetch(`/authorize?${query}`, sid ? { headers: cookieHeader(sid) } : {});
}

/** The emulator's transaction id from a `302 /u/login?state=` response. */
export function loginState(res: Response): string {
    const location = res.headers.get('location') ?? '';
    const match = location.match(/^\/u\/login\?state=([^&]+)$/);
    if (res.status !== 302 || !match?.[1]) throw new Error(`expected a login redirect, got ${res.status} ${location}`);
    return decodeURIComponent(match[1]);
}

/** Submit the login form of a transaction. */
export function submitLogin(h: Harness, state: string, username: string, password: string): Promise<Response> {
    return postForm(h, `/u/login?state=${encodeURIComponent(state)}`, { username, password, action: 'default' });
}

export interface BrowserLogin {
    /** Response to POST /u/login. */
    response: Response;
    /** `Location` of that response (`about:blank` when there was none). */
    location: URL;
    /** Parameters delivered to the redirect URI, from the fragment when present, else the query. */
    params: URLSearchParams;
    /** First value the session cookie was set to (`''` when none was set). */
    sid: string;
    code: string | null;
}

/** Run GET /authorize → POST /u/login with a password and collect the redirect, code and session cookie. */
export async function browserLogin(
    h: Harness,
    params: AuthorizeParams,
    username: string,
    password: string
): Promise<BrowserLogin> {
    const state = loginState(await authorize(h, params));
    const response = await submitLogin(h, state, username, password);
    const location = new URL(response.headers.get('location') ?? 'about:blank');
    const delivered = location.hash ? new URLSearchParams(location.hash.slice(1)) : location.searchParams;
    return {
        response,
        location,
        params: delivered,
        sid: sessionCookies(response)[0] ?? '',
        code: delivered.get('code'),
    };
}
