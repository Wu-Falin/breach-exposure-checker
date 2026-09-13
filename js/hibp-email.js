/*
 * hibp-email.js: OPTIONAL stretch feature: look up an EMAIL ADDRESS against
 * the official Have I Been Pwned v3 breach API.
 *
 * ⚠ THIS IS NOT THE k-ANONYMITY FEATURE. Keep the two straight:
 *
 *   Password check (pwned.js)  : no key, no account, nothing sensitive leaves
 *                                the device. Send 5 hex characters.
 *   Email check   (this file)  : REQUIRES THE USER'S OWN PAID HIBP API KEY,
 *                                and the full email address IS sent to HIBP.
 *                                There is no k-anonymity here. The API has no
 *                                range mode for emails.
 *
 * SCOPE GUARDRAIL (see README): enter YOUR OWN email address only. Running
 * other people's addresses through this (a customer list, a scraped dump, a
 * roster of NIK/ID records) is reconnaissance against people who did not ask
 * for it. That is illegal in most jurisdictions, violates the HIBP terms of
 * use, and is explicitly out of scope for this project. Do not add a file
 * upload, a textarea of addresses, or a loop over an array here.
 *
 * KEY HANDLING
 *   - The key is NEVER hardcoded in this repository.
 *   - The key is held in a variable local to the module only. It is not written to
 *     localStorage, sessionStorage, cookies, or the URL, so it does not
 *     survive a refresh and cannot leak via browser history or a shared link.
 *
 * CORS REALITY CHECK
 *   haveibeenpwned.com/api/v3 does NOT send CORS headers, so a browser cannot
 *   call it directly. The request will be blocked no matter how valid the key
 *   is. That is HIBP's deliberate design, not a bug in this code. To use this
 *   feature you must point it at a small proxy of your own that adds the
 *   `hibp-api-key` and `user-agent` headers on the server side. A ~20 line example is
 *   in docs/hibp-proxy-example.md. The direct URL is left as the default so
 *   the failure is honest and visible rather than hidden.
 */

(function (global) {
  'use strict';

  const DIRECT_BASE = 'https://haveibeenpwned.com/api/v3';

  // In-memory only. Deliberately not persisted anywhere.
  let apiKey = '';

  function setApiKey(value) {
    apiKey = (value || '').trim();
  }

  function hasApiKey() {
    return apiKey.length > 0;
  }

  function clearApiKey() {
    apiKey = '';
  }

  /**
   * Look up a single email address.
   *
   * @param {string} email     the user's OWN address
   * @param {string} baseUrl   API base, the direct HIBP URL, or your proxy
   * @returns {Promise<{found: boolean, breaches: Array, status: number}>}
   */
  async function checkEmail(email, baseUrl) {
    const address = (email || '').trim();

    if (!address) {
      throw new Error('Enter an email address.');
    }
    // One address per call. No commas, no semicolons, no lists. See the
    // scope guardrail above.
    if (/[,;\s]/.test(address) || !address.includes('@')) {
      throw new Error('Enter exactly one email address that belongs to you.');
    }

    const base = (baseUrl || DIRECT_BASE).replace(/\/+$/, '');
    const url = base + '/breachedaccount/' + encodeURIComponent(address) +
      '?truncateResponse=false';

    const headers = { Accept: 'application/json' };
    // A proxy usually injects the key itself; only send it if we have one.
    // (`user-agent` is a forbidden header in browsers, so the proxy must add it.)
    if (hasApiKey()) {
      headers['hibp-api-key'] = apiKey;
    }

    const response = await fetch(url, { method: 'GET', headers });

    // 404 is HIBP's "good news" answer: the account is in no known breach.
    if (response.status === 404) {
      return { found: false, breaches: [], status: 404 };
    }
    if (response.status === 401) {
      throw new Error('HTTP 401 — the API key was missing, invalid, or expired.');
    }
    if (response.status === 429) {
      const retryAfter = response.headers.get('retry-after') || 'a few';
      throw new Error('HTTP 429 — rate limited. Wait ' + retryAfter + ' seconds.');
    }
    if (!response.ok) {
      throw new Error('HIBP API returned HTTP ' + response.status + '.');
    }

    const breaches = await response.json();
    return {
      found: Array.isArray(breaches) && breaches.length > 0,
      breaches: Array.isArray(breaches) ? breaches : [],
      status: response.status
    };
  }

  global.HibpEmail = {
    DIRECT_BASE,
    setApiKey,
    hasApiKey,
    clearApiKey,
    checkEmail
  };
})(window);
