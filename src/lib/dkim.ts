/**
 * Worker-side DKIM signing (RFC 6376), WebCrypto only.
 *
 * Cloudflare only auto-signs outbound mail on the paid Email Sending product,
 * so rewritten alias forwards and transactional email leave unsigned and are
 * rejected by receivers under the domain's DMARC p=reject. This module signs
 * them in the worker before they hand off to the send binding, mirroring what
 * the Flask app does with dkimpy (app/dkim.py, add_dkim_signature in
 * app/email_utils.py): a=rsa-sha256, c=relaxed/relaxed, q=dns/txt, default
 * selector "dkim".
 *
 * The canonicalization here is byte-for-byte compatible with dkimpy's
 * `dkim.canonicalization.Relaxed` (cross-checked in test/dkim.test.ts, which
 * verifies a real dkimpy-produced signature with WebCrypto).
 */

import type { Env } from "./env";

/** RFC 6376 relaxed algorithms, the only ones we emit. */
const CANON = "relaxed/relaxed";

/** Flask's default DKIM selector (config.py: DKIM_SELECTOR = b"dkim"). */
const DEFAULT_SELECTOR = "dkim";

/**
 * Headers we sign when present, in this order. Superset of the Flask app's
 * DKIM_HEADERS (from/to/subject/date/message-id) plus the MIME and list
 * headers that matter for forwarded mail. Only headers actually present in the
 * message are signed and listed in h=.
 */
export const SIGNED_HEADER_ORDER = [
  "from",
  "to",
  "subject",
  "date",
  "message-id",
  "reply-to",
  "mime-version",
  "content-type",
  "list-unsubscribe",
] as const;

export interface DkimOptions {
  domain: string;
  selector: string;
  privateKeyPem: string;
}

/**
 * Sign `raw` and return the message with a DKIM-Signature header prepended.
 * The original bytes are left untouched (DKIM covers them via the relaxed
 * canonicalizations, which are robust to the wire form), so we only prepend.
 */
export async function dkimSign(
  raw: Uint8Array,
  opts: DkimOptions,
): Promise<Uint8Array> {
  const key = await pemToCryptoKey(opts.privateKeyPem);
  const { headerText, body } = splitMessage(raw);
  const fields = splitHeaderFields(headerText);

  // bh: SHA-256 of the relaxed-canonicalized body.
  const bhBytes = new Uint8Array(
    await crypto.subtle.digest("SHA-256", relaxedBodyCanon(body)),
  );
  const bh = bytesToBase64(bhBytes);

  // Select the signed headers that are actually present, in order. If a header
  // appears more than once we sign the bottom-most occurrence (RFC 6376 §5.4.2
  // signs from the bottom); our generated messages have unique headers.
  const signed: { name: string; value: string }[] = [];
  for (const name of SIGNED_HEADER_ORDER) {
    for (let i = fields.length - 1; i >= 0; i--) {
      if (fields[i].name.trim().toLowerCase() === name) {
        signed.push({ name, value: fields[i].value });
        break;
      }
    }
  }
  const hList = signed.map((s) => s.name).join(":");
  const t = Math.floor(Date.now() / 1000);

  // Tag list with an empty b=; this exact string (canonicalized) is what we
  // sign, and it is what a verifier reconstructs after emptying b=. Keeping it
  // on one line before b= avoids any folding/canonicalization mismatch; only
  // the b= value is folded in the emitted header, and b= is emptied on verify.
  const preB =
    `v=1; a=rsa-sha256; c=${CANON}; d=${opts.domain}; ` +
    `s=${opts.selector}; t=${t}; q=dns/txt; h=${hList}; bh=${bh}; b=`;

  let hashInput = "";
  for (const s of signed)
    hashInput += `${relaxedHeaderCanon(s.name, s.value)}\r\n`;
  hashInput += relaxedHeaderCanon("DKIM-Signature", preB); // no trailing CRLF

  const sig = new Uint8Array(
    await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      key,
      new TextEncoder().encode(hashInput),
    ),
  );
  const b = bytesToBase64(sig);

  const headerLine = `DKIM-Signature: ${preB}${foldBase64(b)}\r\n`;
  const headerBytes = new TextEncoder().encode(headerLine);
  const out = new Uint8Array(headerBytes.length + raw.length);
  out.set(headerBytes, 0);
  out.set(raw, headerBytes.length);
  return out;
}

/**
 * Whether `domain` is one of ours (env.EMAIL_DOMAIN or a member of the
 * comma-separated env.ALIAS_DOMAINS) and therefore eligible for our DKIM key.
 */
export function isOwnEmailDomain(env: Env, domain: string): boolean {
  const d = domain.toLowerCase();
  if (d === env.EMAIL_DOMAIN.toLowerCase()) return true;
  return env.ALIAS_DOMAINS.split(",")
    .map((x) => x.trim().toLowerCase())
    .filter(Boolean)
    .includes(d);
}

/**
 * Env-aware outbound signer used by both the alias-forward path (email.ts) and
 * the transactional mailer (mailer.ts). Returns `raw` unchanged when no key is
 * configured or the From-header domain is not one of ours; otherwise returns
 * the message with a DKIM-Signature prepended, signed with d=<from domain>.
 */
export async function dkimSignOutbound(
  env: Env,
  fromAddress: string,
  raw: Uint8Array,
): Promise<Uint8Array> {
  if (!env.DKIM_PRIVATE_KEY) return raw;
  const at = fromAddress.lastIndexOf("@");
  if (at === -1) return raw;
  const domain = fromAddress
    .slice(at + 1)
    .trim()
    .toLowerCase();
  if (!domain || !isOwnEmailDomain(env, domain)) return raw;
  try {
    return await dkimSign(raw, {
      domain,
      selector: env.DKIM_SELECTOR ?? DEFAULT_SELECTOR,
      privateKeyPem: env.DKIM_PRIVATE_KEY,
    });
  } catch (e) {
    // A signing failure must not drop the mail; send it unsigned.
    console.error("[dkim] signing failed:", e);
    return raw;
  }
}

// ------------------------- canonicalization -------------------------------

/**
 * RFC 6376 §3.4.4 relaxed body canonicalization. Operates on bytes (treated as
 * latin1) so arbitrary body encodings round-trip exactly.
 */
export function relaxedBodyCanon(body: Uint8Array): Uint8Array {
  let s = "";
  for (const byte of body) s += String.fromCharCode(byte);

  // Normalize line endings to LF for processing.
  s = s.replace(/\r\n/g, "\n").replace(/\r/g, "\n");

  const lines = s.split("\n").map((line) =>
    // Reduce WSP sequences within the line to a single SP, then strip the
    // (at most one) trailing SP left over.
    line.replace(/[ \t]+/g, " ").replace(/ $/, ""),
  );
  let out = lines.join("\r\n");
  // Ignore all empty lines at the end of the body...
  out = out.replace(/(?:\r\n)+$/, "");
  // ...and if the body is non-empty, end it with a single CRLF.
  if (out.length > 0) out += "\r\n";

  const bytes = new Uint8Array(out.length);
  for (let i = 0; i < out.length; i++) bytes[i] = out.charCodeAt(i);
  return bytes;
}

/**
 * RFC 6376 §3.4.2 relaxed header canonicalization for a single field. Returns
 * the canonical `name:value` form (without a trailing CRLF).
 */
export function relaxedHeaderCanon(name: string, value: string): string {
  const canonValue = value
    .replace(/\r/g, "")
    .replace(/\n/g, "") // unfold continuation lines
    .replace(/[ \t]+/g, " ") // collapse WSP runs to a single SP
    .replace(/^[ \t]+/, "") // drop WSP after the colon
    .replace(/[ \t]+$/, ""); // drop trailing WSP
  return `${name.trim().toLowerCase()}:${canonValue}`;
}

// --------------------------- key handling ---------------------------------

const keyCache = new Map<string, Promise<CryptoKey>>();

/** Import a PKCS#8 PEM RSA private key for RSASSA-PKCS1-v1_5 / SHA-256. */
export function pemToCryptoKey(pem: string): Promise<CryptoKey> {
  const cached = keyCache.get(pem);
  if (cached) return cached;
  const promise = (async () => {
    const b64 = pem
      .replace(/-----BEGIN [^-]+-----/, "")
      .replace(/-----END [^-]+-----/, "")
      .replace(/\s+/g, "");
    const der = base64ToBytes(b64);
    return crypto.subtle.importKey(
      "pkcs8",
      der,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
  })();
  keyCache.set(pem, promise);
  return promise;
}

// ------------------------------- helpers ----------------------------------

function splitMessage(bytes: Uint8Array): {
  headerText: string;
  body: Uint8Array;
} {
  let headerEnd = bytes.length;
  let bodyStart = bytes.length;
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0x0a) continue;
    if (bytes[i + 1] === 0x0a) {
      headerEnd = i + 1;
      bodyStart = i + 2;
      break;
    }
    if (bytes[i + 1] === 0x0d && bytes[i + 2] === 0x0a) {
      headerEnd = i + 1;
      bodyStart = i + 3;
      break;
    }
  }
  return {
    headerText: new TextDecoder().decode(bytes.slice(0, headerEnd)),
    body: bytes.slice(bodyStart),
  };
}

/**
 * Split a header block into fields, keeping folded continuation lines attached
 * (as embedded newlines that relaxedHeaderCanon later unfolds).
 */
function splitHeaderFields(
  headerText: string,
): { name: string; value: string }[] {
  const normalized = headerText.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const fields: { name: string; value: string }[] = [];
  for (const line of normalized.split("\n")) {
    if (line === "") continue;
    if ((line[0] === " " || line[0] === "\t") && fields.length > 0) {
      fields[fields.length - 1].value += `\n${line}`;
      continue;
    }
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    fields.push({ name: line.slice(0, colon), value: line.slice(colon + 1) });
  }
  return fields;
}

/** Fold a base64 signature into CRLF + SP continuation lines. */
function foldBase64(b64: string): string {
  return (b64.match(/.{1,72}/g) ?? []).join("\r\n ");
}

function bytesToBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
