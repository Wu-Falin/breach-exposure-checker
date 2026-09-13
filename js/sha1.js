/*
 * sha1.js: SHA-1 hashing, entirely on the client side.
 *
 * SCOPE GUARDRAIL (see README): this file exists so that a password the user
 * typed about themselves can be hashed ON THEIR OWN DEVICE. Nothing here
 * transmits anything. Do not repurpose it to hash lists of other people's
 * credentials.
 *
 * Two implementations are provided:
 *
 *   1. window.crypto.subtle.digest('SHA-1', ...), the browser's native,
 *      audited implementation that runs in close to constant time. Preferred
 *      whenever it exists.
 *   2. A small pure JavaScript SHA-1 (RFC 3174) fallback. This matters
 *      because WebCrypto is only exposed in a "secure context" (https:// or
 *      http://localhost). If someone double clicks index.html and the page
 *      loads over file://, crypto.subtle is undefined in Chrome and the app
 *      would otherwise be dead on arrival. The fallback keeps the demo
 *      working with zero setup.
 *
 * Why SHA-1 at all? Not because it is a good password hash. It absolutely is
 * not (fast, unsalted, collision broken). It is used here only because the
 * Have I Been Pwned "Pwned Passwords" corpus is indexed by SHA-1, so we must
 * speak the same dialect to query it. This is a lookup key, not a credential
 * storage scheme.
 */

(function (global) {
  'use strict';

  /** Encode a JS string to UTF-8 bytes (HIBP hashes the UTF-8 encoding). */
  function utf8Bytes(str) {
    return new TextEncoder().encode(str);
  }

  /** Converts a Uint8Array to an uppercase hex string. */
  function bytesToHex(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i++) {
      out += bytes[i].toString(16).padStart(2, '0');
    }
    return out.toUpperCase();
  }

  /**
   * Pure JS SHA-1 over a byte array. Returns uppercase hex.
   * Straight transcription of RFC 3174; kept verbose so it is auditable.
   */
  function sha1BytesSync(bytes) {
    const messageLen = bytes.length;

    // Padding: 0x80, then zeros, then a 64 bit big endian bit length,
    // so the total is a multiple of 64 bytes.
    const blockCount = Math.floor((messageLen + 8) / 64) + 1;
    const padded = new Uint8Array(blockCount * 64);
    padded.set(bytes);
    padded[messageLen] = 0x80;

    const view = new DataView(padded.buffer);
    const bitLen = messageLen * 8;
    view.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
    view.setUint32(padded.length - 4, bitLen >>> 0);

    // Initial state (RFC 3174 section 6.1).
    let h0 = 0x67452301;
    let h1 = 0xefcdab89;
    let h2 = 0x98badcfe;
    let h3 = 0x10325476;
    let h4 = 0xc3d2e1f0;

    const w = new Uint32Array(80);

    for (let block = 0; block < blockCount; block++) {
      const offset = block * 64;

      for (let i = 0; i < 16; i++) {
        w[i] = view.getUint32(offset + i * 4);
      }
      for (let i = 16; i < 80; i++) {
        const mixed = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16];
        w[i] = (mixed << 1) | (mixed >>> 31); // rotate left 1
      }

      let a = h0, b = h1, c = h2, d = h3, e = h4;

      for (let i = 0; i < 80; i++) {
        let f, k;
        if (i < 20) {
          f = (b & c) | (~b & d);
          k = 0x5a827999;
        } else if (i < 40) {
          f = b ^ c ^ d;
          k = 0x6ed9eba1;
        } else if (i < 60) {
          f = (b & c) | (b & d) | (c & d);
          k = 0x8f1bbcdc;
        } else {
          f = b ^ c ^ d;
          k = 0xca62c1d6;
        }

        const temp = (((a << 5) | (a >>> 27)) + f + e + k + w[i]) >>> 0;
        e = d;
        d = c;
        c = ((b << 30) | (b >>> 2)) >>> 0; // rotate left 30
        b = a;
        a = temp;
      }

      h0 = (h0 + a) >>> 0;
      h1 = (h1 + b) >>> 0;
      h2 = (h2 + c) >>> 0;
      h3 = (h3 + d) >>> 0;
      h4 = (h4 + e) >>> 0;
    }

    return [h0, h1, h2, h3, h4]
      .map((word) => word.toString(16).padStart(8, '0'))
      .join('')
      .toUpperCase();
  }

  /** True when the browser gives us the native implementation. */
  function hasWebCrypto() {
    return typeof global.crypto !== 'undefined' &&
      typeof global.crypto.subtle !== 'undefined' &&
      typeof global.crypto.subtle.digest === 'function';
  }

  /**
   * Hash a string with SHA-1 and return uppercase hex.
   * Async because WebCrypto is async; the fallback just resolves immediately.
   *
   * @param {string} text
   * @returns {Promise<{hash: string, engine: 'webcrypto'|'fallback'}>}
   */
  async function sha1Hex(text) {
    const bytes = utf8Bytes(text);

    if (hasWebCrypto()) {
      try {
        const digest = await global.crypto.subtle.digest('SHA-1', bytes);
        return { hash: bytesToHex(new Uint8Array(digest)), engine: 'webcrypto' };
      } catch (err) {
        // Some locked down contexts expose subtle but refuse SHA-1.
        // Fall through to the JS implementation rather than failing the app.
      }
    }

    return { hash: sha1BytesSync(bytes), engine: 'fallback' };
  }

  global.Sha1 = { sha1Hex, sha1BytesSync, utf8Bytes, hasWebCrypto };
})(window);
