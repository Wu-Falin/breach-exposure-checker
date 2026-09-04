/*
 * pwned.js — the k-anonymity range client for the Pwned Passwords API.
 *
 * SCOPE GUARDRAIL (see README): this client is built to answer one question
 * about ONE credential that the person at the keyboard owns and typed
 * themselves. It deliberately has no batch/list/queue interface. Turning it
 * into a bulk checker that grinds through other people's credentials would
 * make it an attack tool, which is illegal and explicitly out of scope.
 *
 * THE PRIVACY PROPERTY, IN ONE PARAGRAPH
 * ----------------------------------------------------------------------
 * We compute SHA-1(password) locally and send ONLY the first 5 hex
 * characters. The server answers with every known-breached hash that starts
 * with those 5 characters -- in the current corpus that is roughly 800-3,000
 * candidates. It cannot tell which one (if any) is ours, and it never sees
 * the password or the full hash. The final comparison happens in this file,
 * in the browser, against the downloaded list. That is k-anonymity: our query
 * is hidden inside a crowd of k other possible answers.
 *
 * The only two places the full hash appears are (a) a local variable and
 * (b) the "How this works" panel, which the user asked to see.
 */

(function (global) {
  'use strict';

  const ENDPOINT = 'https://api.pwnedpasswords.com/range/';

  // Minimum wall-clock gap between two outbound requests. The range API is
  // generous, but hammering a free public service on every keystroke is
  // rude and makes the tool look amateur in a demo.
  const MIN_REQUEST_INTERVAL_MS = 900;

  // Prefix -> parsed suffix map. A cache is not just a speed trick here: a
  // repeated check of the same password produces ZERO extra network traffic,
  // so retyping does not leak an additional query for the same prefix.
  const rangeCache = new Map();

  let lastRequestAt = 0;
  let paddingSupported = true; // flipped off if the server/CORS rejects it

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  /**
   * Parse the API's text body into a Map of "SUFFIX" -> count.
   *
   * Body format is one entry per line: `SUFFIX35CHARS:COUNT`
   *
   * Entries with a count of 0 are PADDING (see below) and are dropped — if we
   * kept them we would report "found in 0 breaches", which is a false
   * positive.
   */
  function parseRangeBody(text) {
    const suffixes = new Map();
    let padded = 0;

    for (const rawLine of text.split('\n')) {
      const line = rawLine.trim();
      if (!line) continue;

      const separator = line.indexOf(':');
      if (separator === -1) continue;

      const suffix = line.slice(0, separator).toUpperCase();
      const count = parseInt(line.slice(separator + 1), 10);

      if (!Number.isFinite(count)) continue;
      if (count === 0) { padded++; continue; } // synthetic padding row

      suffixes.set(suffix, count);
    }

    return { suffixes, padded };
  }

  /**
   * Fetch every breached-hash suffix sharing this 5-char prefix.
   *
   * `Add-Padding: true` asks HIBP to bulk the response out with fake zero-count
   * entries. Without it, the *size* of the encrypted response is a side channel:
   * a network observer who knows the response length can narrow down which
   * prefix was requested. With it, all responses look alike. If the header is
   * rejected (proxy, restrictive CORS), we retry once without it rather than
   * failing the check.
   *
   * @param {string} prefix exactly 5 uppercase hex characters
   * @returns {Promise<{suffixes: Map<string, number>, cached: boolean,
   *                    padded: number, url: string, throttledMs: number}>}
   */
  async function fetchRange(prefix) {
    if (!/^[0-9A-F]{5}$/.test(prefix)) {
      throw new Error('Refusing to send a malformed prefix: ' + prefix);
    }

    const url = ENDPOINT + prefix;

    if (rangeCache.has(prefix)) {
      const hit = rangeCache.get(prefix);
      return { ...hit, cached: true, url, throttledMs: 0 };
    }

    // Client-side rate limit.
    const sinceLast = Date.now() - lastRequestAt;
    let throttledMs = 0;
    if (sinceLast < MIN_REQUEST_INTERVAL_MS) {
      throttledMs = MIN_REQUEST_INTERVAL_MS - sinceLast;
      await sleep(throttledMs);
    }
    lastRequestAt = Date.now();

    const headers = paddingSupported ? { 'Add-Padding': 'true' } : {};
    let response;

    try {
      response = await fetch(url, { method: 'GET', headers, mode: 'cors' });
    } catch (networkError) {
      if (paddingSupported) {
        // Most likely the custom header's CORS preflight was blocked.
        paddingSupported = false;
        response = await fetch(url, { method: 'GET', mode: 'cors' });
      } else {
        throw networkError;
      }
    }

    if (!response.ok) {
      throw new Error('Pwned Passwords API returned HTTP ' + response.status);
    }

    const parsed = parseRangeBody(await response.text());
    rangeCache.set(prefix, parsed);

    return { ...parsed, cached: false, url, throttledMs };
  }

  /**
   * The whole check, end to end.
   *
   * @param {string} password the user's own password, never transmitted
   * @returns {Promise<object>} everything the UI needs, including the
   *          intermediate values so the "How this works" panel can prove
   *          that only 5 characters left the device.
   */
  async function checkPassword(password) {
    const { hash, engine } = await global.Sha1.sha1Hex(password);

    const prefix = hash.slice(0, 5);  // <- the ONLY part that is transmitted
    const suffix = hash.slice(5);     // <- stays in this tab, forever

    const range = await fetchRange(prefix);
    const count = range.suffixes.get(suffix) || 0;

    return {
      hash,
      prefix,
      suffix,
      engine,
      url: range.url,
      cached: range.cached,
      padded: range.padded,
      throttledMs: range.throttledMs,
      candidateCount: range.suffixes.size, // this is the "k" in k-anonymity
      breachCount: count,
      found: count > 0
    };
  }

  global.PwnedPasswords = {
    ENDPOINT,
    MIN_REQUEST_INTERVAL_MS,
    checkPassword,
    fetchRange,
    parseRangeBody,
    clearCache: () => rangeCache.clear()
  };
})(window);
