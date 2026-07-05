/**
 * Cryptography / Python-compat layer for the SimpleLogin Workers port.
 *
 * Every primitive here is byte-compatible with the Flask app so that values
 * signed/hashed by either side verify on the other:
 *   - bcrypt password hashing (cost 12, NFKC-normalized) via bcryptjs
 *   - pyotp-compatible TOTP (SHA1/30s/6-digit, ±2 step window) via otpauth
 *   - itsdangerous 1.1.0 `Signer` / `TimestampSigner` via WebCrypto
 *   - secrets-compatible random string / token / word generators
 *   - email sanitization + gmail/proton canonicalization
 *
 * Only WebCrypto (crypto.subtle / crypto.getRandomValues) is used directly;
 * node:crypto is never imported here.
 */

import bcrypt from "bcryptjs";
import { Secret, TOTP } from "otpauth";
import { WORDS } from "./words";

// --------------------------------------------------------------------------
// bcrypt password hashing (app/pw_models.py)
// --------------------------------------------------------------------------

/**
 * Fixed hash the Flask login path compares against when no user is found, so
 * that a missing account takes the same time as a wrong password.
 */
const DUMMY_HASH =
  "$2b$12$ZWqpL73h4rGNfLkJohAFAu0isqSw/bX9p/tzpbWRz/To5FAftaW8u";

/**
 * bcrypt cost 12 over the NFKC-normalized password (matches `set_password`).
 * bcryptjs emits the `$2b$` prefix by default, same as the Python bcrypt lib.
 */
export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password.normalize("NFKC"), 12);
}

/**
 * Verify a password against a stored bcrypt hash. When `hash` is null (e.g. a
 * social-login user with no password) a dummy comparison still runs so the
 * timing matches the found-user path, then returns false.
 */
export async function checkPassword(
  hash: string | null,
  password: string,
): Promise<boolean> {
  const normalized = password.normalize("NFKC");
  if (!hash) {
    await bcrypt.compare(normalized, DUMMY_HASH);
    return false;
  }
  return bcrypt.compare(normalized, hash);
}

// --------------------------------------------------------------------------
// TOTP (pyotp-compatible, app/api/views/auth_mfa.py)
// --------------------------------------------------------------------------

/**
 * TOTP verification matching `pyotp.TOTP(secret).verify(code, valid_window=2)`
 * plus the SimpleLogin `last_otp` replay guard.
 *
 * @param secret  base32 TOTP secret (case-insensitive, like pyotp casefold).
 * @param code    the submitted 6-digit code (string preserves leading zeros).
 * @param lastOtp the last accepted code for the user, or null; a repeat is rejected.
 * @param now     optional override (Date or epoch ms) for deterministic tests.
 * @returns true only if the code is valid within ±2 steps and is not a replay.
 */
export function verifyTotp(
  secret: string,
  code: string,
  lastOtp: string | null,
  now?: Date | number,
): boolean {
  // Replay guard: pyotp compares `user.last_otp == mfa_token` on the raw token.
  if (lastOtp !== null && code === lastOtp) return false;

  const normalizedSecret = secret.replace(/\s/g, "").toUpperCase();
  const totp = new TOTP({
    secret: Secret.fromBase32(normalizedSecret),
    algorithm: "SHA1",
    digits: 6,
    period: 30,
  });

  const timestamp =
    now === undefined
      ? Date.now()
      : now instanceof Date
        ? now.getTime()
        : now;

  // pyotp NFKC-normalizes both sides before the constant-time compare.
  const delta = totp.validate({
    token: code.normalize("NFKC"),
    timestamp,
    window: 2,
  });
  return delta !== null;
}

// --------------------------------------------------------------------------
// itsdangerous 1.1.0 Signer / TimestampSigner (WebCrypto)
// --------------------------------------------------------------------------

const ITSDANGEROUS_SALT = "itsdangerous.Signer";
const SEP = ".";
const enc = new TextEncoder();

/** base64url without padding, matching itsdangerous `base64_encode`. */
function b64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Inverse of {@link b64urlEncode}; throws on malformed input. */
function b64urlDecode(s: string): Uint8Array {
  const padded = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * itsdangerous "django-concat" key derivation:
 * derived_key = SHA1(salt + "signer" + secret).
 */
async function deriveKey(secret: string): Promise<CryptoKey> {
  const material = enc.encode(ITSDANGEROUS_SALT + "signer" + secret);
  const digest = await crypto.subtle.digest("SHA-1", material);
  return crypto.subtle.importKey(
    "raw",
    digest,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign", "verify"],
  );
}

/** HMAC-SHA1 signature (raw bytes) of `message` under the derived key. */
async function hmac(secret: string, message: string): Promise<Uint8Array> {
  const key = await deriveKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return new Uint8Array(sig);
}

/** Constant-time verify of a base64url signature over `message`. */
async function verifyHmac(
  secret: string,
  message: string,
  sigB64: string,
): Promise<boolean> {
  let sigBytes: Uint8Array;
  try {
    sigBytes = b64urlDecode(sigB64);
  } catch {
    return false;
  }
  const key = await deriveKey(secret);
  return crypto.subtle.verify(
    "HMAC",
    key,
    sigBytes as unknown as ArrayBuffer,
    enc.encode(message) as unknown as ArrayBuffer,
  );
}

/** `Signer(secret).sign(value)` — appends `.base64url(HMAC-SHA1(value))`. */
export async function itsdangerousSign(
  secret: string,
  value: string,
): Promise<string> {
  const sig = b64urlEncode(await hmac(secret, value));
  return value + SEP + sig;
}

/** `Signer(secret).unsign(signed)` — returns the value or null on bad signature. */
export async function itsdangerousUnsign(
  secret: string,
  signed: string,
): Promise<string | null> {
  const idx = signed.lastIndexOf(SEP);
  if (idx < 0) return null;
  const value = signed.slice(0, idx);
  const sig = signed.slice(idx + 1);
  return (await verifyHmac(secret, value, sig)) ? value : null;
}

/**
 * Minimal big-endian byte encoding of a non-negative integer, matching
 * itsdangerous `int_to_bytes` (no leading zero bytes; a trailing LSB zero is
 * kept). Arithmetic (not bitwise) so it is correct past 2**31.
 */
function intToBytes(num: number): Uint8Array {
  const rv: number[] = [];
  while (num > 0) {
    rv.push(num % 256);
    num = Math.floor(num / 256);
  }
  rv.reverse();
  return new Uint8Array(rv);
}

/** Inverse of {@link intToBytes} (big-endian). */
function bytesToInt(bytes: Uint8Array): number {
  let n = 0;
  for (const b of bytes) n = n * 256 + b;
  return n;
}

/**
 * `TimestampSigner(secret).sign(value)`:
 *   payload = value + "." + base64url(int_to_bytes(unix_seconds))
 *   signed  = payload + "." + base64url(HMAC-SHA1(payload))
 *
 * @param nowSecs optional unix-seconds override for deterministic tests.
 */
export async function timestampSign(
  secret: string,
  value: string,
  nowSecs?: number,
): Promise<string> {
  const epoch = nowSecs ?? Math.floor(Date.now() / 1000);
  const tsB64 = b64urlEncode(intToBytes(epoch));
  const payload = value + SEP + tsB64;
  const sig = b64urlEncode(await hmac(secret, payload));
  return payload + SEP + sig;
}

/**
 * `TimestampSigner(secret).unsign(signed, max_age=maxAgeSecs)`.
 *
 * Parsing splits on the RIGHTMOST two dots: first the signature, then the
 * timestamp — the value itself may contain dots (e.g. `.word@a.b.com`).
 * Returns the value, or null if the signature is bad, malformed, or the
 * timestamp is older than `maxAgeSecs` (both cases raise BadSignature in
 * Python and are collapsed to a 412 by the caller).
 *
 * @param nowSecs optional unix-seconds override for deterministic tests.
 */
export async function timestampUnsign(
  secret: string,
  signed: string,
  maxAgeSecs: number,
  nowSecs?: number,
): Promise<string | null> {
  // Signer level: split off the signature (rightmost dot).
  const sigIdx = signed.lastIndexOf(SEP);
  if (sigIdx < 0) return null;
  const payload = signed.slice(0, sigIdx);
  const sig = signed.slice(sigIdx + 1);
  if (!(await verifyHmac(secret, payload, sig))) return null;

  // TimestampSigner level: split value from timestamp (next rightmost dot).
  const tsIdx = payload.lastIndexOf(SEP);
  if (tsIdx < 0) return null;
  const value = payload.slice(0, tsIdx);
  const tsB64 = payload.slice(tsIdx + 1);

  let timestamp: number;
  try {
    timestamp = bytesToInt(b64urlDecode(tsB64));
  } catch {
    return null;
  }

  const now = nowSecs ?? Math.floor(Date.now() / 1000);
  if (now - timestamp > maxAgeSecs) return null; // SignatureExpired
  return value;
}

// --------------------------------------------------------------------------
// CSPRNG helpers (secrets module compat)
// --------------------------------------------------------------------------

const LOWERCASE = "abcdefghijklmnopqrstuvwxyz";

/**
 * Unbiased random index in [0, n) using rejection sampling over bytes, so the
 * distribution matches Python's `secrets.choice`.
 */
function randomIndex(n: number): number {
  const limit = Math.floor(256 / n) * n; // largest multiple of n <= 256
  const buf = new Uint8Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

/** `random_string(length)` — lowercase a–z only (no digits), CSPRNG-backed. */
export function randomString(length: number): string {
  let out = "";
  for (let i = 0; i < length; i++) out += LOWERCASE[randomIndex(26)];
  return out;
}

/** `secrets.token_urlsafe(nbytes)` — base64url(nbytes random bytes), no padding. */
export function tokenUrlsafe(nbytes = 32): string {
  const bytes = new Uint8Array(nbytes);
  crypto.getRandomValues(bytes);
  return b64urlEncode(bytes);
}

/** One random digit 0–9. */
function randomDigit(): string {
  return String(randomIndex(10));
}

/**
 * `random_words(words, numbers)` — `words` random words joined by "_", then
 * `numbers` trailing digits appended with no separator (e.g. "cat_zebra123").
 */
export function randomWords(nbWords: number, numbers = 0): string {
  const parts: string[] = [];
  for (let i = 0; i < nbWords; i++) parts.push(WORDS[randomIndex(WORDS.length)]);
  let out = parts.join("_");
  if (numbers > 0) {
    let digits = "";
    for (let i = 0; i < numbers; i++) digits += randomDigit();
    out += digits;
  }
  return out;
}

// --------------------------------------------------------------------------
// Email sanitization / canonicalization (app/utils.py)
// --------------------------------------------------------------------------

const RTL_MARK = "‏"; // U+200F RIGHT-TO-LEFT MARK

/** Gmail/Proton domains whose local parts are canonicalized (dots + suffix). */
const CANONICAL_DOMAINS = new Set([
  "googlemail.com",
  "gmail.com",
  "protonmail.com",
  "proton.me",
  "pm.me",
]);

/**
 * `sanitize_email(email, not_lower)`: strip surrounding whitespace, remove ALL
 * spaces, turn remaining newlines into a space, lowercase (unless notLower),
 * and drop the U+200F RTL mark.
 */
export function sanitizeEmail(email: string, notLower = false): string {
  let e = email;
  if (e) {
    e = e.trim().replaceAll(" ", "").replaceAll("\n", " ");
    if (!notLower) e = e.toLowerCase();
  }
  return e.replaceAll(RTL_MARK, "");
}

/**
 * `canonicalize_email(email)`: sanitize, then for gmail/proton domains strip the
 * "+suffix" and all dots from the local part. Non-2-part addresses return "".
 * Other domains are returned sanitized-but-unchanged.
 */
export function canonicalizeEmail(email: string): string {
  const sanitized = sanitizeEmail(email);
  const parts = sanitized.split("@");
  if (parts.length !== 2) return "";
  const [local, domain] = parts;
  if (CANONICAL_DOMAINS.has(domain)) {
    const first = local.split("+")[0].replaceAll(".", "");
    return `${first}@${domain}`.toLowerCase().trim();
  }
  return sanitized;
}
