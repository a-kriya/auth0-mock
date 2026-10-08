import { escapeHtml, page } from './layout.ts';

export function resetPasswordView(props: { ticket: string; email: string; error?: string }): string {
    const error = props.error
        ? `<span id="error-element-password" class="error-message">${escapeHtml(props.error)}</span>`
        : '';
    return page(
        'Change Password',
        `<h1>Change Your Password</h1>
<p class="description">Enter a new password for ${escapeHtml(props.email)}</p>
<form method="post" action="/lo/reset?ticket=${encodeURIComponent(props.ticket)}">
<input type="hidden" name="ticket" value="${escapeHtml(props.ticket)}">
<label for="password">New password</label>
<input id="password" name="password" type="password" required autofocus autocomplete="new-password">
<label for="re-password">Re-enter new password</label>
<input id="re-password" name="re-password" type="password" required autocomplete="new-password">
${error}
<button type="submit" name="action" value="default">Reset password</button>
</form>`
    );
}

export function messageView(title: string, message: string): string {
    return page(title, `<h1>${escapeHtml(title)}</h1><p class="success">${escapeHtml(message)}</p>`);
}
