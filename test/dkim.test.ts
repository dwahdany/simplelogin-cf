/**
 * DKIM signing tests (src/lib/dkim.ts).
 *
 * Coverage:
 *  - RFC 6376 §3.4.5 relaxed canonicalization vectors, cross-checked against
 *    Python dkimpy (the library the Flask app uses) during development.
 *  - A full round-trip: sign a message with a freshly generated RSA key and
 *    verify the b= value with WebCrypto (re-canonicalize, recompute bh, verify).
 *  - Cross-implementation proof: verify a real signature produced by dkimpy
 *    using our own canonicalization + WebCrypto. If our relaxed canon were off
 *    by a single byte this would fail, so it pins byte-for-byte parity.
 *  - Integration: handleEmail's outbound send (outboundEmails seam) carries a
 *    DKIM-Signature for our domain when env.DKIM_PRIVATE_KEY is set.
 *
 * dkimpy vectors were generated with, e.g.:
 *   uv run --with dkimpy python -c '
 *     import dkim.canonicalization as c
 *     print(c.Relaxed.canonicalize_headers([(b"A", b" X\r\n"),
 *                                            (b"B ", b" Y\t\r\n\tZ  \r\n")]))
 *     print(c.Relaxed.canonicalize_body(b" C \r\nD \t E\r\n\r\n\r\n"))'
 */

import {
  createExecutionContext,
  env,
  waitOnExecutionContext,
} from "cloudflare:test";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { handleEmail, outboundEmails } from "../src/email";
import {
  dkimSign,
  relaxedBodyCanon,
  relaxedHeaderCanon,
} from "../src/lib/dkim";
import type { Env } from "../src/lib/env";
import type { MailboxRow } from "../src/lib/rows";
import { createAlias, createUser } from "./fixtures";

// ------------------------------ byte helpers ------------------------------

const enc = (s: string) => new TextEncoder().encode(s);
const dec = (b: Uint8Array) => new TextDecoder().decode(b);

function bytesToBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function base64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64.replace(/\s+/g, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function derToPem(der: Uint8Array, label: string): string {
  const lines = bytesToBase64(der).match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

async function sha256Base64(bytes: Uint8Array): Promise<string> {
  return bytesToBase64(
    new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)),
  );
}

// -------------------------- a small DKIM verifier -------------------------
// Mirrors what a receiver does: recompute bh, rebuild the signed header set
// with b= emptied, and RSA-verify. Deliberately reuses the module's exported
// canonicalization so a passing verify proves the canon is correct.

interface HeaderField {
  name: string;
  value: string; // continuation lines kept as embedded "\n"
}

function splitSigned(bytes: Uint8Array): {
  fields: HeaderField[];
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
  const headerText = dec(bytes.slice(0, headerEnd))
    .replace(/\r\n/g, "\n")
    .replace(/\r/g, "\n");
  const fields: HeaderField[] = [];
  for (const line of headerText.split("\n")) {
    if (line === "") continue;
    if ((line[0] === " " || line[0] === "\t") && fields.length > 0) {
      fields[fields.length - 1].value += `\n${line}`;
      continue;
    }
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    fields.push({ name: line.slice(0, colon), value: line.slice(colon + 1) });
  }
  return { fields, body: bytes.slice(bodyStart) };
}

function parseTags(dkimValue: string): Record<string, string> {
  const flat = dkimValue.replace(/[\r\n]+/g, "").replace(/[ \t]+/g, " ");
  const tags: Record<string, string> = {};
  for (const part of flat.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    tags[part.slice(0, eq).trim()] = part.slice(eq + 1).trim();
  }
  return tags;
}

async function dkimVerify(
  signed: Uint8Array,
  publicKey: CryptoKey,
): Promise<{ bhOk: boolean; sigOk: boolean; tags: Record<string, string> }> {
  const { fields, body } = splitSigned(signed);
  const dkimField = fields.find(
    (f) => f.name.trim().toLowerCase() === "dkim-signature",
  );
  if (!dkimField) throw new Error("no DKIM-Signature header");
  const tags = parseTags(dkimField.value);

  const bhOk = (await sha256Base64(relaxedBodyCanon(body))) === tags.bh;

  const names = tags.h.split(":").map((s) => s.trim().toLowerCase());
  let hashInput = "";
  for (const name of names) {
    // bottom-most occurrence, excluding the DKIM-Signature itself
    let field: HeaderField | undefined;
    for (let i = fields.length - 1; i >= 0; i--) {
      if (fields[i] === dkimField) continue;
      if (fields[i].name.trim().toLowerCase() === name) {
        field = fields[i];
        break;
      }
    }
    if (field) hashInput += `${relaxedHeaderCanon(name, field.value)}\r\n`;
  }
  // b= is the final tag; empty its value (RFC 6376 §3.7), no trailing CRLF.
  const emptyB = dkimField.value.replace(/(;\s*b\s*=)[^;]*$/, "$1");
  hashInput += relaxedHeaderCanon("DKIM-Signature", emptyB);

  const sigOk = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    base64ToBytes(tags.b),
    enc(hashInput),
  );
  return { bhOk, sigOk, tags };
}

// ------------------------------ test key ----------------------------------

let privateKeyPem: string;
let publicKey: CryptoKey;

beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const pkcs8 = new Uint8Array(
    await crypto.subtle.exportKey("pkcs8", pair.privateKey),
  );
  privateKeyPem = derToPem(pkcs8, "PRIVATE KEY");
  publicKey = pair.publicKey;
});

// ===================== relaxed canonicalization vectors ===================

describe("relaxed canonicalization (RFC 6376 §3.4.5, dkimpy cross-checked)", () => {
  it("canonicalizes headers like dkimpy (a:X / b:Y Z)", () => {
    // dkimpy: c.Relaxed.canonicalize_headers([(b"A", b" X\r\n"),
    //         (b"B ", b" Y\t\r\n\tZ  \r\n")]) -> [(b"a", b"X\r\n"), (b"b", b"Y Z\r\n")]
    expect(relaxedHeaderCanon("A", " X")).toBe("a:X");
    // folded continuation ("\t\r\n\t" -> single SP) with a mixed-case name
    expect(relaxedHeaderCanon("B ", " Y\t\n\tZ  ")).toBe("b:Y Z");
    expect(relaxedHeaderCanon("Subject", " Hello   World")).toBe(
      "subject:Hello World",
    );
  });

  it("canonicalizes the body like dkimpy (' C\\r\\nD E\\r\\n')", () => {
    // dkimpy: c.Relaxed.canonicalize_body(b" C \r\nD \t E\r\n\r\n\r\n")
    //         -> b" C\r\nD E\r\n"
    expect(dec(relaxedBodyCanon(enc(" C \r\nD \t E\r\n\r\n\r\n")))).toBe(
      " C\r\nD E\r\n",
    );
  });

  it("hashes an empty body to the well-known SHA-256 (dkimpy vector)", async () => {
    // dkimpy: canonicalize_body(b"") -> b"" ;
    //         base64(sha256(b"")) -> 47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=
    expect(relaxedBodyCanon(enc("")).length).toBe(0);
    expect(await sha256Base64(relaxedBodyCanon(enc("")))).toBe(
      "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=",
    );
  });

  it("matches dkimpy's body hash for a multi-line body", async () => {
    // dkimpy: canonicalize_body(b"Hello World  \r\n\r\nSecond   line\t\r\n\r\n\r\n")
    //         -> b"Hello World\r\n\r\nSecond line\r\n" ;
    //         base64(sha256(...)) -> UHKovKnWuA3cIdR9lnE1Bh6A7/+Kk9xM+tPUQwcXoDc=
    const body = enc("Hello World  \r\n\r\nSecond   line\t\r\n\r\n\r\n");
    expect(dec(relaxedBodyCanon(body))).toBe(
      "Hello World\r\n\r\nSecond line\r\n",
    );
    expect(await sha256Base64(relaxedBodyCanon(body))).toBe(
      "UHKovKnWuA3cIdR9lnE1Bh6A7/+Kk9xM+tPUQwcXoDc=",
    );
  });

  it("adds a trailing CRLF to a body without one", () => {
    expect(dec(relaxedBodyCanon(enc("abc")))).toBe("abc\r\n");
  });
});

// ============================ round-trip sign =============================

describe("dkimSign round-trip", () => {
  const message = enc(
    [
      "From: alice@sl.example.com",
      "To: bob@ext.example",
      "Subject: Round trip",
      "Date: Tue, 01 Jul 2025 00:00:00 +0000",
      "Message-ID: <rt-1@sl.example.com>",
      "MIME-Version: 1.0",
      'Content-Type: text/plain; charset="utf-8"',
      "",
      "Body line one  ",
      "Body line two",
      "",
    ].join("\r\n"),
  );

  it("prepends a well-formed DKIM-Signature header", async () => {
    const signed = await dkimSign(message, {
      domain: "sl.example.com",
      selector: "dkim",
      privateKeyPem,
    });
    const text = dec(signed);
    expect(text.startsWith("DKIM-Signature:")).toBe(true);
    // original message is left intact after the prepended header
    expect(text.slice(text.indexOf("From:"))).toBe(dec(message));
    const tags = parseTags(
      text.slice("DKIM-Signature:".length, text.indexOf("\r\nFrom:")),
    );
    expect(tags.v).toBe("1");
    expect(tags.a).toBe("rsa-sha256");
    expect(tags.c).toBe("relaxed/relaxed");
    expect(tags.d).toBe("sl.example.com");
    expect(tags.s).toBe("dkim");
    expect(tags.q).toBe("dns/txt");
    expect(tags.h).toBe(
      "from:to:subject:date:message-id:mime-version:content-type",
    );
    expect(Number(tags.t)).toBeGreaterThan(1_700_000_000);
  });

  it("produces a signature that verifies (recompute bh + RSA verify)", async () => {
    const signed = await dkimSign(message, {
      domain: "sl.example.com",
      selector: "dkim",
      privateKeyPem,
    });
    const { bhOk, sigOk } = await dkimVerify(signed, publicKey);
    expect(bhOk).toBe(true);
    expect(sigOk).toBe(true);
  });

  it("only signs headers that are present, in the fixed order", async () => {
    const minimal = enc(
      ["From: a@sl.example.com", "Subject: hi", "", "hello", ""].join("\r\n"),
    );
    const signed = await dkimSign(minimal, {
      domain: "sl.example.com",
      selector: "s1",
      privateKeyPem,
    });
    const text = dec(signed);
    const tags = parseTags(
      text.slice("DKIM-Signature:".length, text.indexOf("\r\nFrom:")),
    );
    expect(tags.h).toBe("from:subject");
    const { sigOk } = await dkimVerify(signed, publicKey);
    expect(sigOk).toBe(true);
  });

  it("verifies with an empty body", async () => {
    const empty = enc(
      ["From: a@sl.example.com", "Subject: empty", "", ""].join("\r\n"),
    );
    const signed = await dkimSign(empty, {
      domain: "sl.example.com",
      selector: "dkim",
      privateKeyPem,
    });
    const { bhOk, sigOk, tags } = await dkimVerify(signed, publicKey);
    expect(tags.bh).toBe("47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    expect(bhOk).toBe(true);
    expect(sigOk).toBe(true);
  });
});

// ==================== cross-verify a real dkimpy signature ================
// Generated once with dkimpy + cryptography (relaxed/relaxed, selector "dkim",
// d=sl.example.com, include_headers=from,to,subject,date,message-id,
// mime-version,content-type). If our relaxed canonicalization diverged from
// dkimpy by any byte, this RSA verify would fail.

const DKIMPY_SPKI_PEM_B64 =
  "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFxdmw4MTR3dXNNVDdFa3JuR3JnSQovUUpCNzM5R3pNSklsMm5xSWJJdGxkV2RtRjM0QmtLNFVZYU1IeEpXcXowUFJKVzRVd1ZwMkNib3JneUlxWlVyCkE1L3BrR0trU2VoNnVJN3ppUWlQZUJSMWcxR1VIdzRtYWVzVVpDUk9OcU9hcXpMa1VOdWxFSjY1cjJselpOSkUKYUpiY0hhRmtiYzI5T0ZJbXlETzRSUUMwZVl5WktmZ1pNbnlnMEhZZ1RjeEJUS1NGcnAveXBzRlEyTGNTU2NZcApaNWhoYmFJUDJLYldNY1A1TnF0NVg1R3QzVFFNRGw4RGJOVVBBOEIyTWE2Nm1haW1tQmFFeml6SXVvc2x4UUhrClc3TDM5aVUweHZIcjdrUmIreEcrQi90ZS9kdkRjVy9XMmE2U2FYeVJsUVhoRENVemFtUkw4dnlERWRxMnFUVHYKb3dJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";

const DKIMPY_SIGNED_MSG_B64 =
  "REtJTS1TaWduYXR1cmU6IHY9MTsgYT1yc2Etc2hhMjU2OyBjPXJlbGF4ZWQvcmVsYXhlZDsgZD1zbC5leGFtcGxlLmNvbTsNCiBpPUBzbC5leGFtcGxlLmNvbTsgcT1kbnMvdHh0OyBzPWRraW07IHQ9MTc4MzMyOTMxNDsgaD1mcm9tIDogdG8gOg0KIHN1YmplY3QgOiBkYXRlIDogbWVzc2FnZS1pZCA6IG1pbWUtdmVyc2lvbiA6IGNvbnRlbnQtdHlwZTsNCiBiaD1jRTJaQmVlS3k2ZmVvY2dZTXJNT2xEaVo5MmVqZVdLbWRMY3BWeUl1YnpjPTsNCiBiPUx6cnh4R3hoMG44ajRlR3MrdUo1a3Z4UGFXT0Riam5TbUhJekhPc0NaMHBrMHB2UXJSVUdrTlBYL0x2RHp1Z2JHenZINg0KIFp5UjVZbDFqNWQvK1ZXcTVBU2t0MVdrbm9kVlg4Q1hDek43bDJwai9DVDR5K1NXbVV4R1NLQXoySU9MQ0RFcHA1TFIweS9LDQogRkN0QjA4Nktaamh5ekJrOW0xVFcxK0o0djk2YTdoNStnVTlWZCt2ekpUV0twK2tkWlFJdFJnTzJvUWFCLytCTldOclE5YkINCiBDaUx2VDBrcEt3TXpQWGVnbUVMb3k4aTJaakRYN0UzMmxDMUdyQTRoOUFwMEtKc2h4THNNNjVqWmo2Z2VxSitORmErYUJycA0KIFd2eDIwL1BjUHhPSXZYbERRcTVXUzdLMmQ2U1FjUWlPYlduS1FMYUUrNjVsc3IwdXZNT250RkF1NDRVZz09DQpGcm9tOiBhbGljZUBzbC5leGFtcGxlLmNvbQ0KVG86IGJvYkBleHQuZXhhbXBsZQ0KU3ViamVjdDogREtJTSBjcm9zcy1jaGVjaw0KRGF0ZTogVHVlLCAwMSBKdWwgMjAyNSAwMDowMDowMCArMDAwMA0KTWVzc2FnZS1JRDogPGZpeGVkLW1zZy1pZEBzbC5leGFtcGxlLmNvbT4NCk1JTUUtVmVyc2lvbjogMS4wDQpDb250ZW50LVR5cGU6IHRleHQvcGxhaW47IGNoYXJzZXQ9InV0Zi04Ig0KDQpIZWxsbyBXb3JsZCAgDQpTZWNvbmQgICBsaW5lCQ0KDQo=";

describe("cross-verify dkimpy's relaxed/relaxed signature", () => {
  it("verifies a real dkimpy signature with our canonicalization", async () => {
    const spkiPem = dec(base64ToBytes(DKIMPY_SPKI_PEM_B64));
    const der = base64ToBytes(
      spkiPem
        .replace(/-----BEGIN [^-]+-----/, "")
        .replace(/-----END [^-]+-----/, "")
        .replace(/\s+/g, ""),
    );
    const pub = await crypto.subtle.importKey(
      "spki",
      der,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const signed = base64ToBytes(DKIMPY_SIGNED_MSG_B64);
    const { bhOk, sigOk, tags } = await dkimVerify(signed, pub);
    expect(tags.d).toBe("sl.example.com");
    expect(tags.bh).toBe("cE2ZBeeKy6feocgYMrMOlDiZ92ejeWKmdLcpVyIubzc=");
    expect(bhOk).toBe(true);
    expect(sigOk).toBe(true);
  });
});

// =========================== sendRawEmail wiring ==========================

function makeMessage(opts: {
  from: string;
  to: string;
  raw: string;
}): ForwardableEmailMessage {
  const rawBytes = enc(opts.raw);
  const headers = new Headers();
  let lastName: string | null = null;
  for (const line of opts.raw.split(/\r?\n\r?\n/)[0].split(/\r?\n/)) {
    if (!line) continue;
    if ((line.startsWith(" ") || line.startsWith("\t")) && lastName) {
      headers.set(lastName, `${headers.get(lastName)} ${line.trim()}`);
      continue;
    }
    const colon = line.indexOf(":");
    if (colon === -1) continue;
    lastName = line.slice(0, colon).trim();
    headers.append(lastName, line.slice(colon + 1).trim());
  }
  const mock = {
    from: opts.from,
    to: opts.to,
    headers,
    rawSize: rawBytes.length,
    raw: new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(rawBytes);
        controller.close();
      },
    }),
    setReject() {},
    async forward() {
      return { messageId: "mock-forward" };
    },
    async reply() {
      return { messageId: "mock-reply" };
    },
  };
  return mock as unknown as ForwardableEmailMessage;
}

describe("outbound send integration", () => {
  beforeEach(() => {
    outboundEmails.length = 0;
  });

  async function deliverForward(testEnv: Env): Promise<string> {
    const user = await createUser(env.DB);
    const mailbox = await env.DB.prepare("SELECT * FROM mailbox WHERE id = ?1")
      .bind(user.default_mailbox_id)
      .first<MailboxRow>();
    if (!mailbox) throw new Error("fixture mailbox missing");
    const alias = await createAlias(env.DB, user.id, mailbox.id);
    const msg = makeMessage({
      from: "john@wick.example",
      to: alias.email,
      raw: [
        "From: John Wick <john@wick.example>",
        `To: ${alias.email}`,
        "Subject: signed?",
        "Message-ID: <orig-dkim@wick.example>",
        "Content-Type: text/plain",
        "",
        "hi there",
        "",
      ].join("\r\n"),
    });
    const ctx = createExecutionContext();
    await handleEmail(msg, testEnv, ctx);
    await waitOnExecutionContext(ctx);
    expect(outboundEmails).toHaveLength(1);
    return outboundEmails[0].raw;
  }

  it("signs the outbound message with d=EMAIL_DOMAIN when a key is configured", async () => {
    const sends: { from: string; to: string }[] = [];
    const sendMock = {
      send: async (m: { from: string; to: string }) =>
        void sends.push({ from: m.from, to: m.to }),
    } as unknown as SendEmail;
    const testEnv: Env = {
      ...env,
      SEND_EMAIL: sendMock,
      DKIM_PRIVATE_KEY: privateKeyPem,
      DKIM_SELECTOR: "dkim",
    };

    const raw = await deliverForward(testEnv);
    expect(raw.startsWith("DKIM-Signature:")).toBe(true);
    expect(raw).toMatch(/d=sl\.example\.com/);
    expect(raw).toMatch(/s=dkim/);
    expect(raw).toMatch(/c=relaxed\/relaxed/);

    // The captured (signed) message must verify end-to-end.
    const { bhOk, sigOk } = await dkimVerify(enc(raw), publicKey);
    expect(bhOk).toBe(true);
    expect(sigOk).toBe(true);
  });

  it("leaves the outbound message unsigned when no key is configured", async () => {
    const sends: unknown[] = [];
    const sendMock = {
      send: async () => void sends.push(1),
    } as unknown as SendEmail;
    const testEnv: Env = { ...env, SEND_EMAIL: sendMock };

    const raw = await deliverForward(testEnv);
    expect(raw).not.toContain("DKIM-Signature:");
  });
});
