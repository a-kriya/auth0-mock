export function escapeHtml(value: unknown): string {
    return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

/** Shared chrome resembling Auth0's New Universal Login, with no external assets. */
export function page(title: string, body: string): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>
  :root { color-scheme: light; }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
         background: #f2f2f2; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; color: #1e212a; }
  main { background: #fff; width: 400px; max-width: calc(100vw - 32px); padding: 40px; border-radius: 5px; box-shadow: 0 12px 40px rgba(0,0,0,.12); box-sizing: border-box; }
  h1 { font-size: 24px; font-weight: 400; margin: 0 0 8px; text-align: center; }
  p.description { color: #65676e; text-align: center; margin: 0 0 24px; font-size: 14px; }
  label { display: block; font-size: 14px; margin-bottom: 4px; color: #1e212a; }
  input { width: 100%; box-sizing: border-box; padding: 12px 14px; border: 1px solid #c9cace; border-radius: 3px; font-size: 16px; margin-bottom: 16px; }
  input:focus { outline: none; border-color: #635dff; box-shadow: 0 0 0 1px #635dff; }
  input.error { border-color: #d03c38; }
  button { width: 100%; padding: 14px; border: 0; border-radius: 3px; background: #635dff; color: #fff; font-size: 16px; cursor: pointer; }
  button:hover { background: #5750e6; }
  .error-message { color: #d03c38; font-size: 14px; margin: -8px 0 16px; display: block; }
  .success { color: #0a7f42; font-size: 14px; text-align: center; }
  .brand { text-align: center; font-size: 12px; color: #9a9ba1; margin-top: 24px; }
</style>
</head>
<body>
<main>
${body}
<p class="brand">auth0-mock</p>
</main>
</body>
</html>`;
}
