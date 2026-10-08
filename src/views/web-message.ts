/**
 * `response_mode=web_message`: post the authorization response to the opener/parent window, which is how
 * auth0-spa-js performs silent authentication in a hidden iframe.
 */
export function webMessageView(redirectUri: string, response: Record<string, string | undefined>): string {
    const origin = new URL(redirectUri).origin;
    const payload = JSON.stringify({
        type: 'authorization_response',
        response: Object.fromEntries(Object.entries(response).filter(([, v]) => v !== undefined)),
    }).replaceAll('<', '\\u003c');
    return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Authorization Response</title></head>
<body>
<script>
(function (window, document) {
  var targetOrigin = ${JSON.stringify(origin)};
  var target = window.opener || window.parent;
  var message = ${payload};
  if (target && target !== window) {
    target.postMessage(message, targetOrigin);
  } else {
    document.body.textContent = 'Authorization response: ' + JSON.stringify(message.response);
  }
})(this, this.document);
</script>
</body>
</html>`;
}

/** `response_mode=form_post`: auto-submitting form back to the redirect URI. */
export function formPostView(redirectUri: string, fields: Record<string, string | undefined>): string {
    const inputs = Object.entries(fields)
        .filter(([, v]) => v !== undefined)
        .map(([k, v]) => `<input type="hidden" name="${k}" value="${String(v).replaceAll('"', '&quot;')}">`)
        .join('\n');
    return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>Redirecting…</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="${redirectUri.replaceAll('"', '&quot;')}">
${inputs}
<noscript><button type="submit">Continue</button></noscript>
</form>
</body></html>`;
}
