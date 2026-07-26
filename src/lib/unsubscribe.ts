/**
 * UnsubscribeEncoder port (app/handler/unsubscribe_encoder.py) — byte-
 * compatible with Flask so signed links survive a migration in either
 * direction (state parity: a link minted by the Python app verifies here and
 * vice versa; checked against itsdangerous 1.1.0 vectors in
 * test/unsubscribe.test.ts).
 *
 * Encoded-request format (encode_subject L53-78):
 *   un.<payload>.<sig>
 *   payload = base64url(json.dumps([action, data])) with '=' padding stripped;
 *     json.dumps uses Python's DEFAULT rendering — ", " item separator and
 *     ensure_ascii \uXXXX escapes (see pyJson* helpers);
 *   sig     = itsdangerous.Signer(UNSUBSCRIBE_SECRET,
 *     digest_method=hashlib.sha3_224).get_signature(payload), i.e.
 *     base64url-no-pad HMAC-SHA3-224 under the "django-concat" derived key
 *     sha3_224("itsdangerous.Signer" + "signer" + secret). WebCrypto has no
 *     SHA3, hence @noble/hashes (same precedent as the transfer-token and
 *     recovery-code HMACs in src/web/).
 *   UNSUBSCRIBE_SECRET = FLASK_SECRET + "unsub" (config.py L227 — an
 *   unconditional concat, no env override).
 *
 * Deliberate deviations (each documented at its site):
 * - encodeUnsubscribeUrl puts the encoded request in the PATH where Flask's
 *   encode_url emits `?data=<payload>` — a known upstream bug (the Flask
 *   route only reads a path segment, so Flask's own web links for actions
 *   1/4 404 today; specs/web/04 §17 gotcha). The signed payload itself stays
 *   byte-identical.
 * - decodeUnsubscribeSubject returns null where Flask raises on a VERIFIED
 *   payload of unexpected shape (unknown action value → ValueError, short/
 *   non-array data → Type/IndexError) — uncaught 500s in Flask, collapsed to
 *   "invalid request" here per the port's clean-4xx convention.
 * - Flask's UnsubscribeEncoder.encode()/encode_mailto() mailto branch is not
 *   ported: UNSUBSCRIBER is never configured on this deployment (mailto
 *   unsubscribe needs a dedicated inbound address), so every link is the web
 *   form — encode(force_web=...) always collapses to encode_url with
 *   via_email=False.
 */

import { hmac } from "@noble/hashes/hmac.js";
import { sha3_224 } from "@noble/hashes/sha3.js";

const UNSUB_PREFIX = "un";
// itsdangerous default salt; the derivation suffix "signer" comes from the
// "django-concat" key derivation (itsdangerous 1.1.0 Signer.derive_key).
const ITSDANGEROUS_SALT = "itsdangerous.Signer";

const enc = new TextEncoder();

// UnsubscribeAction (unsubscribe_encoder.py L16-20).
export const UnsubscribeAction = {
  UnsubscribeNewsletter: 1,
  DisableAlias: 2,
  DisableContact: 3,
  OriginalUnsubscribeMailto: 4,
} as const;
export type UnsubscribeAction =
  (typeof UnsubscribeAction)[keyof typeof UnsubscribeAction];

/** UnsubscribeOriginalData (unsubscribe_encoder.py L23-27). */
export interface UnsubscribeOriginalData {
  aliasId: number;
  recipient: string;
  subject: string;
}

/** UnsubscribeData (unsubscribe_encoder.py L30-33). */
export interface UnsubscribeData {
  action: UnsubscribeAction;
  data: number | UnsubscribeOriginalData;
}

/** config.py L227: UNSUBSCRIBE_SECRET = FLASK_SECRET + "unsub". */
export function unsubscribeSecret(env: { FLASK_SECRET: string }): string {
  return `${env.FLASK_SECRET}unsub`;
}

// ---------------------------------------------------------------------------
// Python-parity primitives
// ---------------------------------------------------------------------------

/** base64.urlsafe_b64encode(...).rstrip(b"=") / itsdangerous base64_encode. */
function b64urlNoPad(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

/** Inverse, re-padding like Flask (`b"=" * (-len % 4)`); throws on bad input. */
function b64urlDecodePadded(s: string): Uint8Array {
  const padded =
    s.replaceAll("-", "+").replaceAll("_", "/") +
    "=".repeat((4 - (s.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * json.dumps of a JS string with ensure_ascii=True: JSON.stringify already
 * matches Python's escapes for `"`, `\` and controls; chars above 0x7e are
 * \uXXXX-escaped (astral chars are two UTF-16 units → a surrogate-pair
 * escape, exactly what Python emits).
 */
function pyJsonString(s: string): string {
  return JSON.stringify(s).replace(
    /[\u007f-\uffff]/g,
    (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

/**
 * json.dumps((action, data)) with the default ", " separator. For
 * OriginalUnsubscribeMailto the data tuple is (0, alias_id, recipient,
 * subject) — the initial 0 is a version number (unsubscribe_encoder.py L66).
 */
function pyJsonPayload(
  action: UnsubscribeAction,
  data: number | UnsubscribeOriginalData,
): string {
  const dataJson =
    typeof data === "number"
      ? String(data)
      : `[0, ${data.aliasId}, ${pyJsonString(data.recipient)}, ${pyJsonString(
          data.subject,
        )}]`;
  return `[${action}, ${dataJson}]`;
}

/** Signer.derive_key ("django-concat"): sha3_224(salt + "signer" + secret). */
function derivedKey(secret: string): Uint8Array {
  return sha3_224(enc.encode(`${ITSDANGEROUS_SALT}signer${secret}`));
}

/** Signer.get_signature: HMAC-SHA3-224(derived key, value), raw bytes. */
function signature(secret: string, value: string): Uint8Array {
  return hmac(sha3_224, derivedKey(secret), enc.encode(value));
}

/** itsdangerous constant_time_compare equivalent. */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------------------------------------------------------------------------
// encode / decode
// ---------------------------------------------------------------------------

/** UnsubscribeEncoder.encode_subject. Throws (like Flask's ValueError) on an
 *  action/data type mismatch; the >512-char case is only logged in Flask. */
export function encodeUnsubscribeSubject(
  secret: string,
  action: UnsubscribeAction,
  data: number | UnsubscribeOriginalData,
): string {
  if (
    action !== UnsubscribeAction.OriginalUnsubscribeMailto &&
    typeof data !== "number"
  )
    throw new Error(`Data has to be an int for an action of type ${action}`);
  if (
    action === UnsubscribeAction.OriginalUnsubscribeMailto &&
    typeof data === "number"
  )
    throw new Error(
      `Data has to be an UnsubscribeOriginalData for an action of type ${action}`,
    );
  const serialized = b64urlNoPad(enc.encode(pyJsonPayload(action, data)));
  const sig = b64urlNoPad(signature(secret, serialized));
  return `${UNSUB_PREFIX}.${serialized}.${sig}`;
}

/** UnsubscribeEncoder.decode_subject: UnsubscribeData or null (BadSignature /
 *  ValueError — plus the malformed-payload 500 paths, see file top). */
export function decodeUnsubscribeSubject(
  secret: string,
  data: string,
): UnsubscribeData | null {
  // Flask: `data.find(UNSUB_PREFIX) == -1` — "un" ANYWHERE passes this check;
  // the real framing comes from the fixed 3-char strip + the signature.
  if (!data.includes(UNSUB_PREFIX)) return null;
  const signed = data.slice(UNSUB_PREFIX.length + 1);

  // Signer.unsign: split on the rightmost separator, verify the signature.
  const sepIdx = signed.lastIndexOf(".");
  if (sepIdx < 0) return null;
  const value = signed.slice(0, sepIdx);
  let sigBytes: Uint8Array;
  try {
    sigBytes = b64urlDecodePadded(signed.slice(sepIdx + 1));
  } catch {
    return null;
  }
  if (!constantTimeEqual(sigBytes, signature(secret, value))) return null;

  let payload: unknown;
  try {
    payload = JSON.parse(new TextDecoder().decode(b64urlDecodePadded(value)));
  } catch {
    return null; // ValueError branch (unsubscribe_encoder.py L121-122)
  }
  if (!Array.isArray(payload) || payload.length < 2) return null;
  const action = payload[0] as UnsubscribeAction;
  if (
    action !== UnsubscribeAction.UnsubscribeNewsletter &&
    action !== UnsubscribeAction.DisableAlias &&
    action !== UnsubscribeAction.DisableContact &&
    action !== UnsubscribeAction.OriginalUnsubscribeMailto
  )
    return null;
  if (action === UnsubscribeAction.OriginalUnsubscribeMailto) {
    const d = payload[1];
    if (!Array.isArray(d) || d.length < 4) return null;
    // Skip the version number in d[0] — for now it's always 0 (L126).
    return {
      action,
      data: {
        aliasId: d[1] as number,
        recipient: d[2] as string,
        subject: d[3] as string,
      },
    };
  }
  return { action, data: payload[1] as number };
}

/**
 * UnsubscribeEncoder.encode_url. `urlBase` is env.URL (no trailing slash).
 * Deviation for the encoded actions (UnsubscribeNewsletter /
 * OriginalUnsubscribeMailto): Flask emits `/dashboard/unsubscribe/encoded
 * ?data=<payload>` (encode_url L100) but its route reads the payload from
 * the PATH, so Flask's own web links 404 (specs/web/04 §17 gotcha). This
 * port emits the path form so the link actually works; the alphabet
 * (base64url + ".") needs no percent-escaping in a path segment.
 */
export function encodeUnsubscribeUrl(
  urlBase: string,
  secret: string,
  action: UnsubscribeAction,
  data: number | UnsubscribeOriginalData,
): string {
  if (action === UnsubscribeAction.DisableAlias)
    return `${urlBase}/dashboard/unsubscribe/${data}`;
  if (action === UnsubscribeAction.DisableContact)
    return `${urlBase}/dashboard/block_contact/${data}`;
  const encoded = encodeUnsubscribeSubject(secret, action, data);
  return `${urlBase}/dashboard/unsubscribe/encoded/${encoded}`;
}
