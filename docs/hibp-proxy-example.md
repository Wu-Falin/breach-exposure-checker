# Minimal HIBP proxy (for the optional email lookup only)

> **You do not need this file for the password check.** The password feature
> uses the free `api.pwnedpasswords.com` range endpoint, which supports CORS,
> needs no key, and runs entirely from the browser. This document is only for
> the optional stretch feature in panel 04.

## Why a proxy is required

`haveibeenpwned.com/api/v3` deliberately does **not** send
`Access-Control-Allow-Origin` headers. A browser will therefore block the
response no matter how valid your API key is. The API also requires a
`user-agent` header, which browsers forbid scripts from setting. Both problems
go away when the call is made on the server side.

A second, better reason: putting your paid API key in a page means shipping it
to anyone who opens the page. Keeping it on the server is the only way it stays
yours.

## Node example (~25 lines)

```js
// proxy.js: run with  HIBP_KEY=your-key node proxy.js
// Then set "API base" in the app to: http://localhost:8787
import http from 'node:http';

const KEY = process.env.HIBP_KEY;
if (!KEY) throw new Error('Set HIBP_KEY in the environment. Never hardcode it.');

http.createServer(async (req, res) => {
  // Allow the local page to read the response.
  res.setHeader('Access-Control-Allow-Origin', 'http://localhost:8000');
  res.setHeader('Access-Control-Allow-Headers', 'hibp-api-key, accept');
  if (req.method === 'OPTIONS') return res.writeHead(204).end();

  // Only proxy the one endpoint this tool needs. An open relay for someone
  // else's paid key is a bad thing to leave running.
  if (!req.url.startsWith('/breachedaccount/')) {
    return res.writeHead(404).end('not proxied');
  }

  const upstream = await fetch('https://haveibeenpwned.com/api/v3' + req.url, {
    headers: { 'hibp-api-key': KEY, 'user-agent': 'personal-breach-checker' }
  });

  res.writeHead(upstream.status, { 'content-type': 'application/json' });
  res.end(await upstream.text());
}).listen(8787, () => console.log('HIBP proxy on http://localhost:8787'));
```

## Notes if you deploy this

- Keep the key in an environment variable or a secret store. Never in the
  repository, never in a client bundle, never in a URL.
- Bind to `localhost` unless you have a reason not to. An exposed proxy is
  somebody else's free HIBP subscription.
- Rate limit it. HIBP's own limit is per key, and you will be the one getting
  429s.
- **Keep the single address constraint.** Do not add a batch endpoint. See the
  scope note in the main README. This project checks your own accounts, not
  other people's.
