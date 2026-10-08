import { escapeHtml, page } from './layout.ts';

export interface LoginViewProps {
    /** Transaction identifier carried as `state` in the form action. */
    state: string;
    tenantName: string;
    clientName: string;
    username?: string;
    /** Show the password step only (identifier already known through `login_hint`). */
    passwordOnly: boolean;
    error?: string;
    allowSignup?: boolean;
}

/**
 * Markup follows Auth0's New Universal Login identifier/password screens: `input[name=username]`,
 * `input[name=password]`, `button[type=submit][name=action][value=default]`, `#error-element-password`.
 */
export function loginView(props: LoginViewProps): string {
    const error = props.error
        ? `<span id="error-element-password" class="error-message">${escapeHtml(props.error)}</span>`
        : '';
    const usernameField = props.passwordOnly
        ? `<label for="username">Email address</label>
<input id="username" name="username" type="email" value="${escapeHtml(props.username)}" readonly autocomplete="username">`
        : `<label for="username">Email address</label>
<input id="username" name="username" type="email" value="${escapeHtml(props.username)}" required autofocus autocomplete="username" inputmode="email">`;
    return page(
        `Log in | ${props.tenantName}`,
        `<h1>${props.passwordOnly ? 'Enter Your Password' : 'Welcome'}</h1>
<p class="description">${props.passwordOnly ? `Enter your password for ${escapeHtml(props.tenantName)} to continue to ${escapeHtml(props.clientName)}` : `Log in to ${escapeHtml(props.tenantName)} to continue to ${escapeHtml(props.clientName)}.`}</p>
<form method="post" action="/u/login?state=${encodeURIComponent(props.state)}" data-form-primary="true">
<input type="hidden" name="state" value="${escapeHtml(props.state)}">
${usernameField}
<label for="password">Password</label>
<input id="password" name="password" type="password" class="${props.error ? 'error' : ''}" required ${props.passwordOnly ? 'autofocus' : ''} autocomplete="current-password">
${error}
<button type="submit" name="action" value="default">Continue</button>
</form>`
    );
}
