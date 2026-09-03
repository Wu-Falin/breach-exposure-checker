# PROJECT — NIGHTWING

Security portfolio. Small, self-contained tools built to demonstrate a specific
technique end-to-end, with the reasoning written down next to the code.

## Projects

### [`breach-exposure-checker/`](breach-exposure-checker/)

Check whether a password you own has appeared in a known public breach —
without the password, or its full hash, ever leaving the browser. Implements
the **k-anonymity** range protocol used by Have I Been Pwned's Pwned Passwords
service: only the first 5 characters of the SHA-1 hash are transmitted, and the
final comparison happens client-side against the returned bucket.

Vanilla HTML/CSS/JS, no backend, no dependencies, no API key.
Ties in to **OWASP WSTG-ATHN-07 — Testing for Weak Password Policy**.

```bash
cd breach-exposure-checker && python3 -m http.server 8000
```

## Scope and ethics

Every tool in this repository is built for **credentials and systems the user
personally owns or is explicitly authorised to test**. None of it is to be
adapted into bulk checkers, scanners, or credential-stuffing tooling aimed at
other people. Each project restates this constraint in its own README and in
comments beside the code it constrains.
