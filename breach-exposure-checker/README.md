# Personal Breach-Exposure Checker

A single-page tool that tells you whether **a password you own** has appeared in
a known public data breach — without that password, or even its full hash, ever
leaving your browser.

No backend. No API key. No dependencies. One HTML file, three JS files, one
stylesheet.

```
$ python3 -m http.server 8000     # then open http://localhost:8000
```

---

## What it actually does

| Step | Where it happens | What moves |
|------|------------------|------------|
| 1. You type a password | your keyboard | nothing |
| 2. `SHA-1(password)` is computed | your browser | nothing |
| 3. First **5 hex characters** are taken | your browser | nothing |
| 4. `GET api.pwnedpasswords.com/range/CBFDA` | the network | **5 characters** |
| 5. ~2,000 breached hash suffixes come back | the network | a public list |
| 6. Your remaining 35 characters are compared to that list | your browser | nothing |
| 7. Result is displayed | your screen | nothing |

The password and the full hash exist only as local variables in the tab. The
tool proves this rather than asserting it: the **"How this works"** panel shows
the live hash with the transmitted 5 characters highlighted against the 35 that
stay behind, the exact URL being requested, and the size of the anonymity set
for each lookup. Open DevTools → Network during a demo; there is exactly one
request and it contains five characters.

### Features

- Masked password input with a show/hide toggle
- Explicit **Check exposure** button, plus an opt-in "check as I type" mode
- **Debounced (700 ms) and rate-limited (900 ms floor)** requests, so a
  16-character password costs one request instead of sixteen
- **Response caching per prefix** — rechecking the same password sends nothing
  at all
- `Add-Padding: true` requested, so response *size* does not leak which prefix
  was queried (padding rows are counted and discarded; keeping them would
  produce a false "found in 0 breaches")
- Stale-response guard: if you keep typing while a request is in flight, the
  late answer is discarded instead of being shown against the wrong input
- Local activity log showing every request, cache hit, and throttle
- Works over `file://` too — falls back to a pure-JS SHA-1 when WebCrypto is
  unavailable outside a secure context

---

## Why k-anonymity matters

The obvious way to build this tool is to POST the password (or its hash) to a
server and ask "is this breached?". That design defeats its own purpose:

- The server now knows one of your passwords.
- So does anyone who compromises the server, or its logs, or its backups.
- SHA-1 is not a defence. It is fast and unsalted; a leaked hash of a
  human-chosen password is a cracked password, usually within seconds.
- The account is now *more* exposed than before you checked. A tool that
  increases risk while claiming to measure it is worse than no tool.

k-anonymity removes the need to trust the server at all. Instead of asking
about one hash, you ask for a **bucket** of hashes: "give me every breached
hash starting with `CBFDA`." The server returns roughly 800–3,000 of them. It
cannot tell which one you cared about, or whether yours was in the list at all
— your query is hidden in a crowd of size *k*.

Two properties follow, and both are worth being able to state in an interview:

1. **The server learns almost nothing.** A 5-hex-character prefix is 20 bits.
   Against a corpus of ~850 million hashes, that identifies a set of thousands,
   not an individual.
2. **You don't have to take that on faith.** The mechanism is verifiable from
   the client side: the request is visible in DevTools, and this tool prints
   the exact *k* for every lookup.

That second point is the real lesson. "Trust us, we don't log it" is a policy.
k-anonymity is a *design* that makes the policy unnecessary — which is the
distinction a tester should be able to draw when reviewing someone else's
architecture.

### How to read the result honestly

- **Found in N breaches** — this password is in public wordlists. Attackers
  spray exactly these. Change it anywhere you use it, and stop reusing it.
- **Not found** — it is not *in this dataset*. That is not "strong" and not
  "safe": a weak password nobody has leaked yet is still weak, and breaches
  that were never published cannot appear here.

---

## Running it locally

No build step, no `npm install`.

```bash
git clone https://github.com/Wu-Falin/PROJECT---NIGHTWING.git
cd PROJECT---NIGHTWING/breach-exposure-checker

# Recommended: any static server. Python is already on most machines.
python3 -m http.server 8000
# → http://localhost:8000
```

**Why serve it rather than double-click `index.html`?** Both work, but
`http://localhost` is a *secure context*, so the browser exposes
`crypto.subtle` and the app uses the native, audited SHA-1. Over `file://`,
`crypto.subtle` is undefined in Chrome, and the app falls back to the bundled
pure-JS SHA-1 (`js/sha1.js`, verified against the RFC 3174 test vectors). The
"How this works" panel tells you which engine is live.

### Project layout

```
breach-exposure-checker/
├── index.html               # markup + the "how this works" panel
├── css/styles.css           # dark terminal theme
├── js/
│   ├── sha1.js              # WebCrypto with a pure-JS RFC 3174 fallback
│   ├── pwned.js             # the k-anonymity range client (cache, throttle, padding)
│   ├── hibp-email.js        # optional email lookup — needs YOUR api key
│   └── app.js               # UI wiring, debounce, rendering
└── docs/hibp-proxy-example.md
```

---

## Demo values for screenshots

**Never use a real password in a screenshot, a recording, or a live interview
demo.** Even a masked field leaks length, and a "show" toggle is one misclick
away. These three are public, well-known throwaways that produce a clean
before/after story:

| Value | Expected result | Why it's a good demo |
|-------|-----------------|----------------------|
| `password123` | **Found — ~2.27 million times** | The dramatic screenshot. Verified against the live API. |
| `Tr0ub4dor&3` | **Found — ~3,200 times** | The XKCD 936 "strong-looking" password. Character substitution, mixed case, a symbol — and still breached. The best single slide about why complexity rules aren't strength. |
| `correct-horse-battery-staple-9182` | **Not found** | The contrast case. Long, high-entropy, and absent from the corpus — while still demonstrating that "not found" ≠ "safe". |

(Counts verified against `api.pwnedpasswords.com` in September 2026; they only
go up as new breaches are loaded.)

The three are wired to one-click buttons under the input so you never have to
type anything real during a demo.

---

## Optional: email breach lookup (requires your own API key)

Panel 04 is a **separate feature with a different privacy model**, deliberately
kept apart from the password check:

- The Pwned Passwords range API is free, keyless, and k-anonymous.
- The HIBP v3 **breach** API has no range mode for email addresses. The
  **full address is sent**, and it needs a **paid API key that you supply
  yourself**.

No key is hardcoded anywhere in this repository. The key you paste is held in a
module-local variable, never written to `localStorage`, a cookie, or the URL,
and is wiped after each request.

`haveibeenpwned.com/api/v3` also sends no CORS headers, so a direct browser
call is blocked no matter how valid your key is. That is HIBP's deliberate
design. To use this feature, point the "API base" field at a small proxy of
your own — a ~25 line example is in
[`docs/hibp-proxy-example.md`](docs/hibp-proxy-example.md).

---

## Pentest methodology tie-in — OWASP WSTG

This mirrors what a tester checks under **WSTG-ATHN-07, "Testing for Weak
Password Policy"** (OWASP Web Security Testing Guide, Authentication Testing).
That test case asks whether an application actually stops users from choosing
weak credentials — and modern guidance, including **NIST SP 800-63B §5.1.1.2**,
has moved away from composition rules ("one uppercase, one symbol") toward
screening candidate passwords against lists of known-compromised values. An
application that accepts `Tr0ub4dor&3` passes a complexity rule while failing
the control that matters.

Credential exposure matters in a real engagement for a blunt reason: **the most
common way into an organisation is not an exploit, it is a valid login.**
Credential stuffing and password spraying reuse the exact corpus this tool
queries, so a password already in the Pwned Passwords dataset is, for
assessment purposes, a password the attacker already has. During an engagement
this surfaces in three places — checking whether registration and
password-reset flows screen against breach corpora, testing whether an
in-scope account can be reached by spraying breached credentials from the
target's own domain, and reporting reuse between a breached personal account
and a corporate one.

Knowing the k-anonymity mechanism is also directly useful on the defensive
side: when a client asks "can we add breach screening without shipping our
users' passwords to a third party?", the answer is yes, and this is how.

---

## Ethical use and scope

> **This tool is built to check only credentials that the user personally owns
> and enters themselves. It must never be modified into a bulk-checker that
> runs lists of other people's emails, passwords, or NIK numbers — that would
> cross from a personal security tool into a tool for attacking others, which
> is illegal and out of scope for this project.**

This note is repeated as a comment at the top of `index.html`, `js/app.js`,
`js/pwned.js`, and `js/hibp-email.js`, next to the code it constrains.

The design reflects it. Both inputs take exactly one value; the email module
rejects anything containing a comma, semicolon, or whitespace; there is no file
upload, no textarea, no queue, and no loop over a list. Those are constraints,
not gaps — please don't "fix" them.

Checking your own password against a public dataset is personal security
hygiene. Running other people's credentials through the same pipeline is
unauthorised reconnaissance: it is illegal in most jurisdictions (in Indonesia,
UU ITE Art. 30 on unauthorised access and the PDP Law on personal data), it
violates the Have I Been Pwned acceptable-use terms, and it is the exact
behaviour that separates a penetration tester from someone committing a crime.
The line is authorisation, and it is not a technicality.

---

## Credits

Password data from [Have I Been Pwned — Pwned
Passwords](https://haveibeenpwned.com/Passwords), provided free by Troy Hunt
under a public-domain licence. The k-anonymity range API design is described in
[Troy Hunt's write-up](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/)
and Cloudflare's ["Validating Leaked Passwords with
k-Anonymity"](https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/).
