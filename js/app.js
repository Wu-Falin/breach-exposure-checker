/*
 * app.js — UI wiring for the Personal Breach-Exposure Checker.
 *
 * ==========================================================================
 * ETHICAL / SCOPE GUARDRAIL
 * --------------------------------------------------------------------------
 * This tool is built to check ONLY credentials that the person using it
 * personally owns and enters themselves. It must never be modified into a
 * bulk checker that runs lists of other people's emails, passwords, or NIK /
 * national-ID numbers. That would cross the line from a personal security
 * tool into a tool for attacking other people — which is illegal, violates
 * the Have I Been Pwned terms of use, and is explicitly out of scope for this
 * project. The single-value input on this page is a design decision, not an
 * oversight: do not "improve" it into a file upload or a list runner.
 * ==========================================================================
 *
 * Structure of this file:
 *   1. Element handles
 *   2. Live local hashing (no network) — feeds the "How this works" panel
 *   3. The network check, debounced and rate-limited
 *   4. Result rendering
 *   5. Optional email lookup (stretch goal, user-supplied API key)
 */

(function () {
  'use strict';

  // --- 1. Element handles -------------------------------------------------

  const $ = (id) => document.getElementById(id);

  const passwordInput   = $('password-input');
  const toggleVisBtn    = $('toggle-visibility');
  const checkBtn        = $('check-btn');
  const autoCheckBox    = $('auto-check');
  const clearBtn        = $('clear-btn');

  const resultBox       = $('result');
  const resultHeadline  = $('result-headline');
  const resultDetail    = $('result-detail');

  const stepPassword    = $('step-password');
  const stepHashPrefix  = $('step-hash-prefix');
  const stepHashSuffix  = $('step-hash-suffix');
  const stepEngine      = $('step-engine');
  const stepUrl         = $('step-url');
  const stepResponse    = $('step-response');
  const stepMatch       = $('step-match');

  const logEl           = $('log');

  // Stretch-goal elements
  const emailForm       = $('email-form');
  const emailInput      = $('email-input');
  const emailKeyInput   = $('email-key');
  const emailBaseInput  = $('email-base');
  const emailResult     = $('email-result');

  // --- Shared helpers -----------------------------------------------------

  /** Timestamped line in the activity log. Local only; never uploaded. */
  function log(message, kind) {
    const line = document.createElement('div');
    line.className = 'log-line' + (kind ? ' log-' + kind : '');
    const time = new Date().toLocaleTimeString([], { hour12: false });
    line.textContent = '[' + time + '] ' + message;
    logEl.prepend(line);
    while (logEl.childElementCount > 40) {
      logEl.lastElementChild.remove();
    }
  }

  /** Classic trailing debounce. */
  function debounce(fn, waitMs) {
    let timer = null;
    const wrapped = function (...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(null, args), waitMs);
    };
    wrapped.cancel = () => clearTimeout(timer);
    return wrapped;
  }

  /** Remove the k-anonymity footnote from a previous result. */
  function clearKNotes() {
    resultBox.querySelectorAll('.k-note').forEach((node) => node.remove());
  }

  function setResultState(state) {
    resultBox.classList.remove('is-safe', 'is-pwned', 'is-error', 'is-busy');
    if (state) resultBox.classList.add('is-' + state);
  }

  // --- 2. Live local hashing (NO network) ---------------------------------
  //
  // This runs on every keystroke, but it only touches the CPU. It exists so
  // the "How this works" panel can show the hash forming in real time — the
  // point being that the user can watch the full hash sit there locally while
  // only 5 characters ever appear in the request line.

  let currentHash = '';

  async function refreshLocalHash() {
    const password = passwordInput.value;

    if (!password) {
      currentHash = '';
      stepPassword.textContent = '(empty)';
      stepHashPrefix.textContent = '';
      stepHashSuffix.textContent = '—';
      stepUrl.textContent = 'https://api.pwnedpasswords.com/range/…';
      stepResponse.textContent = '—';
      stepMatch.textContent = '—';
      return;
    }

    const { hash, engine } = await window.Sha1.sha1Hex(password);
    currentHash = hash;

    // Never render the password itself — only its shape. The whole pitch of
    // this tool is "your secret stays secret", including from a shoulder
    // surfer looking at the explainer panel.
    stepPassword.textContent = '•'.repeat(Math.min(password.length, 32)) +
      '  (' + password.length + ' chars, never transmitted)';

    stepHashPrefix.textContent = hash.slice(0, 5);
    stepHashSuffix.textContent = hash.slice(5);
    stepEngine.textContent = engine === 'webcrypto'
      ? 'WebCrypto (crypto.subtle)'
      : 'pure-JS fallback (page is not a secure context)';
    stepUrl.textContent = window.PwnedPasswords.ENDPOINT + hash.slice(0, 5);
  }

  // --- 3. The network check ----------------------------------------------

  let inFlight = false;

  async function runCheck() {
    const password = passwordInput.value;

    if (!password) {
      setResultState('error');
      resultHeadline.textContent = 'Nothing to check';
      resultDetail.textContent = 'Type a password first.';
      return;
    }

    if (inFlight) {
      log('Check already running — ignoring duplicate request.', 'warn');
      return;
    }

    inFlight = true;
    checkBtn.disabled = true;
    clearKNotes();          // a note from the previous check must not outlive it
    setResultState('busy');
    resultHeadline.textContent = 'Checking…';
    resultDetail.textContent = 'Hashing locally, then requesting the 5-character range.';

    try {
      const r = await window.PwnedPasswords.checkPassword(password);

      // Guard against a stale response: if the user kept typing while the
      // request was in the air, the answer no longer describes what is in
      // the box. Showing it anyway would be a lie.
      if (currentHash && r.hash !== currentHash) {
        log('Discarded a stale response — the input changed mid-request.', 'warn');
        return;
      }

      if (r.cached) {
        log('Range ' + r.prefix + ' served from local cache — no request sent.');
      } else {
        if (r.throttledMs > 0) {
          log('Rate limiter held the request for ' + r.throttledMs + ' ms.');
        }
        log('GET ' + r.url + ' → ' + r.candidateCount + ' real candidates' +
          (r.padded ? ' + ' + r.padded + ' padding rows' : '') + '.');
      }

      stepResponse.textContent = r.candidateCount + ' hash suffixes returned' +
        (r.padded ? ' (plus ' + r.padded + ' zero-count padding rows, discarded)' : '') +
        (r.cached ? ' — from cache' : '');

      if (r.found) {
        setResultState('pwned');
        resultHeadline.textContent = 'FOUND in ' + r.breachCount.toLocaleString() +
          ' known breach' + (r.breachCount === 1 ? '' : 'es');
        resultDetail.textContent =
          'This password appears ' + r.breachCount.toLocaleString() + ' times in the ' +
          'Pwned Passwords corpus. It is in the wordlists attackers spray. If you use ' +
          'it anywhere, change it there and stop reusing it.';
        stepMatch.textContent = 'Your suffix ' + r.suffix.slice(0, 10) +
          '… matched one of the ' + r.candidateCount + ' candidates.';
        log('MATCH — ' + r.breachCount + ' occurrences.', 'bad');
      } else {
        setResultState('safe');
        resultHeadline.textContent = 'Not found in known breaches';
        resultDetail.textContent =
          'No match in the Pwned Passwords corpus. That means "not in this dataset" — ' +
          'not "strong" and not "safe". A weak-but-unleaked password is still weak.';
        stepMatch.textContent = 'Your suffix ' + r.suffix.slice(0, 10) +
          '… matched none of the ' + r.candidateCount + ' candidates.';
        log('No match among ' + r.candidateCount + ' candidates.', 'good');
      }

      // The k in k-anonymity, made concrete for the demo. Appended last so it
      // reads as a footnote under the result.
      const kNote = document.createElement('div');
      kNote.className = 'k-note';
      kNote.textContent = 'Anonymity set for this query: ' + r.candidateCount +
        '. The server saw "' + r.prefix + '" and could not tell which of those ' +
        r.candidateCount + ' hashes — or none of them — was yours.';
      resultBox.appendChild(kNote);

    } catch (err) {
      setResultState('error');
      resultHeadline.textContent = 'Check failed';
      resultDetail.textContent = err.message +
        ' — if this is a CORS or network error, serve the page over http:// ' +
        'with a local web server rather than opening the file directly.';
      log('ERROR: ' + err.message, 'bad');
    } finally {
      inFlight = false;
      checkBtn.disabled = false;
    }
  }

  // Debounced variant, used only by the opt-in "check as I type" mode.
  // 700 ms of quiet is roughly a deliberate pause, so a 16-character password
  // costs one request instead of sixteen.
  const debouncedCheck = debounce(runCheck, 700);

  // --- Event wiring -------------------------------------------------------

  passwordInput.addEventListener('input', () => {
    refreshLocalHash();               // local, instant, free
    if (autoCheckBox.checked) {
      debouncedCheck();               // network, debounced + rate-limited
    }
  });

  passwordInput.addEventListener('keydown', (event) => {
    if (event.key === 'Enter') {
      event.preventDefault();
      debouncedCheck.cancel();
      runCheck();
    }
  });

  checkBtn.addEventListener('click', () => {
    debouncedCheck.cancel();          // an explicit click should not wait
    runCheck();
  });

  autoCheckBox.addEventListener('change', () => {
    log(autoCheckBox.checked
      ? 'Auto-check ON — requests fire 700 ms after you stop typing.'
      : 'Auto-check OFF — requests only fire when you press Check.');
    if (!autoCheckBox.checked) debouncedCheck.cancel();
  });

  toggleVisBtn.addEventListener('click', () => {
    const showing = passwordInput.type === 'text';
    passwordInput.type = showing ? 'password' : 'text';
    toggleVisBtn.textContent = showing ? 'show' : 'hide';
    toggleVisBtn.setAttribute('aria-pressed', String(!showing));
  });

  clearBtn.addEventListener('click', () => {
    debouncedCheck.cancel();
    passwordInput.value = '';
    passwordInput.type = 'password';
    toggleVisBtn.textContent = 'show';
    refreshLocalHash();
    setResultState(null);
    resultHeadline.textContent = 'Awaiting input';
    resultDetail.textContent = 'Nothing has been sent yet.';
    clearKNotes();
    passwordInput.focus();
    log('Input cleared.');
  });

  // Demo-password buttons — safe, publicly-known strings for screenshots.
  document.querySelectorAll('[data-demo]').forEach((btn) => {
    btn.addEventListener('click', () => {
      passwordInput.value = btn.getAttribute('data-demo');
      refreshLocalHash();
      log('Loaded demo value "' + btn.getAttribute('data-demo') + '" — ' +
        'a public throwaway, not anyone\'s real credential.');
    });
  });

  // --- 5. Stretch goal: email lookup --------------------------------------

  if (emailForm) {
    emailForm.addEventListener('submit', async (event) => {
      event.preventDefault();

      emailResult.className = 'email-result is-busy';
      emailResult.textContent = 'Querying…';

      window.HibpEmail.setApiKey(emailKeyInput.value);

      try {
        const r = await window.HibpEmail.checkEmail(
          emailInput.value,
          emailBaseInput.value || window.HibpEmail.DIRECT_BASE
        );

        if (r.found) {
          emailResult.className = 'email-result is-pwned';
          const names = r.breaches
            .map((b) => b.Name + (b.BreachDate ? ' (' + b.BreachDate + ')' : ''))
            .join(', ');
          emailResult.textContent = 'Found in ' + r.breaches.length +
            ' breach(es): ' + names;
        } else {
          emailResult.className = 'email-result is-safe';
          emailResult.textContent = 'No known breaches for that address (HTTP 404).';
        }
      } catch (err) {
        emailResult.className = 'email-result is-error';
        emailResult.textContent = err.message +
          ' — remember that haveibeenpwned.com/api/v3 does not send CORS headers, ' +
          'so a direct browser call is always blocked. Point "API base" at your own ' +
          'proxy (see docs/hibp-proxy-example.md).';
      } finally {
        // Drop the key from memory as soon as the request is done.
        window.HibpEmail.clearApiKey();
      }
    });
  }

  // --- Boot ---------------------------------------------------------------

  refreshLocalHash();
  log('Ready. Hashing happens in this tab; only a 5-character prefix is ever sent.');
  if (!window.Sha1.hasWebCrypto()) {
    log('WebCrypto unavailable (page is not a secure context) — using the ' +
      'pure-JS SHA-1 fallback. Serve over http://localhost for the native one.', 'warn');
  }
})();
