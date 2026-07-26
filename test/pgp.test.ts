/**
 * PGP tests: src/lib/pgp.ts (app/pgp_utils.py port), the mailbox-detail PGP
 * save/remove form (app/dashboard/views/mailbox_detail.py L147-196) and the
 * forward-phase PGP/MIME encryption (email_handler.py prepare_pgp_message
 * L382-459, call site L884-899). Web requests go through SELF.fetch (full
 * worker); the forward phase calls handleEmail directly like email.test.ts.
 * Test keypairs are generated with openpgp.js in beforeAll.
 */

import {
  createExecutionContext,
  env,
  SELF,
  waitOnExecutionContext,
} from "cloudflare:test";
import { Hono } from "hono";
import * as openpgp from "openpgp";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { handleEmail, outboundEmails } from "../src/email";
import type { Env } from "../src/lib/env";
import {
  encryptMessage,
  loadPublicKey,
  loadPublicKeyAndCheck,
  PGPException,
} from "../src/lib/pgp";
import type { MailboxRow, UserRow } from "../src/lib/rows";
import { createSession } from "../src/lib/session";
import type { WebEnv } from "../src/lib/web/webauth";
import { createAlias, createUser } from "./fixtures";

const BASE = "http://example.com";

// ------------------------------ keypairs ----------------------------------

let publicKey = "";
let privateKey = "";
let fingerprint = "";
/** A key with no encryption subkey: parses fine, cannot encrypt. */
let signOnlyPublicKey = "";

beforeAll(async () => {
  const pair = await openpgp.generateKey({
    userIDs: [{ name: "PGP Test", email: "pgp-mailbox@example.com" }],
  });
  publicKey = pair.publicKey;
  privateKey = pair.privateKey;
  fingerprint = (await openpgp.readKey({ armoredKey: pair.publicKey }))
    .getFingerprint()
    .toUpperCase();

  const signOnly = await openpgp.generateKey({
    userIDs: [{ name: "Sign Only", email: "sign-only@example.com" }],
    subkeys: [],
  });
  signOnlyPublicKey = signOnly.publicKey;
});

beforeEach(() => {
  outboundEmails.length = 0;
});

// ----------------------------- lib helpers --------------------------------

async function decryptArmored(armored: string): Promise<string> {
  const { data } = await openpgp.decrypt({
    message: await openpgp.readMessage({ armoredMessage: armored }),
    decryptionKeys: await openpgp.readPrivateKey({ armoredKey: privateKey }),
    format: "binary",
  });
  return new TextDecoder().decode(data as Uint8Array);
}

describe("src/lib/pgp.ts", () => {
  it("loadPublicKey returns the gnupg-format fingerprint (uppercase hex)", async () => {
    const fp = await loadPublicKey(publicKey);
    expect(fp).toBe(fingerprint);
    expect(fp).toMatch(/^[0-9A-F]{40}$/);
  });

  it("loadPublicKey raises PGPException on garbage", async () => {
    await expect(loadPublicKey("not a key")).rejects.toThrow(PGPException);
    await expect(loadPublicKey("not a key")).rejects.toThrow("Cannot load key");
  });

  it("loadPublicKeyAndCheck rejects a key that cannot encrypt", async () => {
    // parses (load_public_key would accept it) …
    await expect(loadPublicKey(signOnlyPublicKey)).resolves.toMatch(
      /^[0-9A-F]{40}$/,
    );
    // … but the trial encryption fails (load_public_key_and_check L96-107).
    await expect(loadPublicKeyAndCheck(signOnlyPublicKey)).rejects.toThrow(
      "Encryption fails with the key",
    );
  });

  it("encryptMessage round-trips through the private key", async () => {
    const armored = await encryptMessage(
      publicKey,
      new TextEncoder().encode("hello pgp"),
    );
    expect(armored).toContain("-----BEGIN PGP MESSAGE-----");
    expect(await decryptArmored(armored)).toBe("hello pgp");
  });

  it("encryptMessage raises PGPException on an unusable key", async () => {
    await expect(
      encryptMessage("garbage", new TextEncoder().encode("x")),
    ).rejects.toThrow(PGPException);
    await expect(
      encryptMessage(signOnlyPublicKey, new TextEncoder().encode("x")),
    ).rejects.toThrow(PGPException);
  });
});

// --------------------------- web form helpers -----------------------------
// Same local helpers as test/web-mailbox-domain-pages.test.ts (each web test
// file owns its copies).

async function sessionCookieFor(userId: number, sudo = false): Promise<string> {
  const helper = new Hono<WebEnv>();
  helper.get("/mk", async (c) => {
    await createSession(
      c,
      userId,
      sudo ? { sudo_time: Math.floor(Date.now() / 1000) } : {},
    );
    return c.text("ok");
  });
  const res = await helper.request("/mk", {}, env);
  return (res.headers.get("set-cookie") ?? "").split(";")[0];
}

async function get(path: string, cookie: string): Promise<Response> {
  return SELF.fetch(BASE + path, {
    headers: { Cookie: cookie },
    redirect: "manual",
  });
}

async function getCsrf(path: string, cookie: string): Promise<string> {
  const res = await get(path, cookie);
  const html = await res.text();
  const m = html.match(/name="csrf_token" type="hidden" value="([^"]+)"/);
  if (!m) throw new Error(`no csrf token on ${path} (status ${res.status})`);
  return m[1];
}

async function post(
  path: string,
  cookie: string,
  fields: Record<string, string>,
): Promise<Response> {
  const body = new URLSearchParams();
  for (const [k, v] of Object.entries(fields)) body.append(k, v);
  return SELF.fetch(BASE + path, {
    method: "POST",
    headers: {
      Cookie: cookie,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body,
    redirect: "manual",
  });
}

async function getFlashes(
  cookie: string,
): Promise<Array<{ category: string; message: string }>> {
  const token = cookie.split("=")[1];
  const raw = await env.KV.get(`session:${token}`);
  if (!raw) return [];
  return (JSON.parse(raw).flashes ?? []) as Array<{
    category: string;
    message: string;
  }>;
}

async function webSetup(userOverrides: Record<string, unknown> = {}): Promise<{
  user: UserRow;
  mb: MailboxRow;
  cookie: string;
  csrf: string;
}> {
  const user = await createUser(env.DB, userOverrides);
  const mb = (await env.DB.prepare("SELECT * FROM mailbox WHERE user_id = ?1")
    .bind(user.id)
    .first<MailboxRow>()) as MailboxRow;
  const cookie = await sessionCookieFor(user.id, true);
  const csrf = await getCsrf(`/dashboard/mailbox/${mb.id}`, cookie);
  return { user, mb, cookie, csrf };
}

describe("mailbox-detail PGP form", () => {
  it("save stores the key and the uppercase fingerprint, flashes success", async () => {
    const { mb, cookie, csrf } = await webSetup();
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "pgp",
      csrf_token: csrf,
      action: "save",
      pgp: publicKey,
    });
    expect(res.status).toBe(302);
    expect(res.headers.get("location")).toBe(`/dashboard/mailbox/${mb.id}`);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message: "Your PGP public key is saved successfully",
      },
    ]);
    const row = await env.DB.prepare(
      "SELECT pgp_public_key, pgp_finger_print FROM mailbox WHERE id = ?1",
    )
      .bind(mb.id)
      .first<{ pgp_public_key: string; pgp_finger_print: string }>();
    expect(row?.pgp_public_key).toBe(publicKey);
    expect(row?.pgp_finger_print).toBe(fingerprint);
  });

  it("save with an invalid key flashes the PGP error, stores nothing and echoes the key", async () => {
    const { mb, cookie, csrf } = await webSetup();
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "pgp",
      csrf_token: csrf,
      action: "save",
      pgp: "clearly not an armored key",
    });
    // Flask falls through to render (no redirect).
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("Cannot add the public key, please verify it");
    // the rejected key stays in the rendered textarea (uncommitted, L164)…
    expect(html).toContain("clearly not an armored key");
    // …but nothing reaches the DB.
    const row = await env.DB.prepare(
      "SELECT pgp_public_key, pgp_finger_print FROM mailbox WHERE id = ?1",
    )
      .bind(mb.id)
      .first<{
        pgp_public_key: string | null;
        pgp_finger_print: string | null;
      }>();
    expect(row?.pgp_public_key).toBeNull();
    expect(row?.pgp_finger_print).toBeNull();
  });

  it("save with a valid-but-unencryptable key flashes the same error", async () => {
    const { mb, cookie, csrf } = await webSetup();
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "pgp",
      csrf_token: csrf,
      action: "save",
      pgp: signOnlyPublicKey,
    });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain(
      "Cannot add the public key, please verify it",
    );
  });

  it("save is premium-gated", async () => {
    const { mb, cookie, csrf } = await webSetup({ trial_end: null });
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "pgp",
      csrf_token: csrf,
      action: "save",
      pgp: publicKey,
    });
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      { category: "warning", message: "Only premium plan can add PGP Key" },
    ]);
    const row = await env.DB.prepare(
      "SELECT pgp_public_key FROM mailbox WHERE id = ?1",
    )
      .bind(mb.id)
      .first<{ pgp_public_key: string | null }>();
    expect(row?.pgp_public_key).toBeNull();
  });

  it("remove clears key, fingerprint and disable_pgp", async () => {
    const { mb, cookie, csrf } = await webSetup();
    await env.DB.prepare(
      "UPDATE mailbox SET pgp_public_key = ?1, pgp_finger_print = ?2, disable_pgp = 1 WHERE id = ?3",
    )
      .bind(publicKey, fingerprint, mb.id)
      .run();
    const res = await post(`/dashboard/mailbox/${mb.id}`, cookie, {
      "form-name": "pgp",
      csrf_token: csrf,
      action: "remove",
    });
    expect(res.status).toBe(302);
    expect(await getFlashes(cookie)).toEqual([
      {
        category: "success",
        message: "Your PGP public key is removed successfully",
      },
    ]);
    const row = await env.DB.prepare(
      "SELECT pgp_public_key, pgp_finger_print, disable_pgp FROM mailbox WHERE id = ?1",
    )
      .bind(mb.id)
      .first<{
        pgp_public_key: string | null;
        pgp_finger_print: string | null;
        disable_pgp: number;
      }>();
    expect(row?.pgp_public_key).toBeNull();
    expect(row?.pgp_finger_print).toBeNull();
    expect(row?.disable_pgp).toBe(0);
  });
});

// ------------------------- forward-phase helpers ---------------------------
// Same mock-message/deliver helpers as test/email.test.ts.

interface MockMessage extends ForwardableEmailMessage {
  rejectReason: string | null;
}

function makeMessage(opts: {
  from: string;
  to: string;
  raw: string;
}): MockMessage {
  const rawBytes = new TextEncoder().encode(opts.raw);
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
    rejectReason: null as string | null,
    setReject(reason: string) {
      mock.rejectReason = reason;
    },
    async forward() {
      return { messageId: "mock-forward" };
    },
    async reply() {
      return { messageId: "mock-reply" };
    },
  };
  return mock as unknown as MockMessage;
}

function buildRaw(headers: [string, string][], body: string): string {
  return `${headers.map(([k, v]) => `${k}: ${v}`).join("\r\n")}\r\n\r\n${body}`;
}

function rawHeader(raw: string, name: string): string | null {
  const lines = raw.split(/\r?\n\r?\n/)[0].split(/\r?\n/);
  const lower = name.toLowerCase();
  for (let i = 0; i < lines.length; i++) {
    const colon = lines[i].indexOf(":");
    if (colon === -1) continue;
    if (lines[i].slice(0, colon).trim().toLowerCase() !== lower) continue;
    let value = lines[i].slice(colon + 1).trim();
    while (i + 1 < lines.length && /^[ \t]/.test(lines[i + 1]))
      value += ` ${lines[++i].trim()}`;
    return value;
  }
  return null;
}

function bodyOf(raw: string): string {
  const idx = raw.indexOf("\r\n\r\n");
  return idx === -1 ? "" : raw.slice(idx + 4);
}

/** Raw MIME parts of a multipart section (excludes preamble/epilogue). */
function mimeParts(section: string, boundary: string): string[] {
  const segments = section.split(`--${boundary}`);
  const parts: string[] = [];
  for (let i = 1; i < segments.length; i++) {
    if (segments[i].startsWith("--")) break;
    parts.push(segments[i]);
  }
  return parts;
}

function partBody(part: string): string {
  const idx = part.indexOf("\r\n\r\n");
  return idx === -1 ? "" : part.slice(idx + 4);
}

async function deliver(message: MockMessage, testEnv: Env) {
  const ctx = createExecutionContext();
  await handleEmail(message, testEnv, ctx);
  await waitOnExecutionContext(ctx);
}

function envWithSendMock(): Env {
  const mock = {
    send: async () => {},
  } as unknown as SendEmail;
  return { ...env, SEND_EMAIL: mock };
}

async function pgpForwardSetup(opts: {
  userOverrides?: Record<string, unknown>;
  aliasOverrides?: Record<string, unknown>;
  mailboxKey?: string | null;
  mailboxFingerprint?: string | null;
  disablePgp?: number;
}) {
  const user = await createUser(env.DB, opts.userOverrides ?? {});
  await env.DB.prepare(
    "UPDATE mailbox SET pgp_public_key = ?1, pgp_finger_print = ?2, disable_pgp = ?3 WHERE id = ?4",
  )
    .bind(
      opts.mailboxKey === undefined ? publicKey : opts.mailboxKey,
      opts.mailboxFingerprint === undefined
        ? fingerprint
        : opts.mailboxFingerprint,
      opts.disablePgp ?? 0,
      user.default_mailbox_id,
    )
    .run();
  const mailbox = (await env.DB.prepare("SELECT * FROM mailbox WHERE id = ?1")
    .bind(user.default_mailbox_id)
    .first<MailboxRow>()) as MailboxRow;
  const alias = await createAlias(
    env.DB,
    user.id,
    mailbox.id,
    opts.aliasOverrides ?? {},
  );
  return { user, mailbox, alias };
}

function pgpInbound(aliasEmail: string): MockMessage {
  return makeMessage({
    from: "john@wick.example",
    to: aliasEmail,
    raw: buildRaw(
      [
        ["From", "John Wick <john@wick.example>"],
        ["To", aliasEmail],
        ["Subject", "hello"],
        ["Message-ID", `<pgp-${Math.random()}@wick.example>`],
        ["Content-Type", "text/plain"],
      ],
      "secret body\r\n",
    ),
  });
}

describe("forward phase PGP", () => {
  it("wraps the forward in multipart/encrypted that decrypts to the original", async () => {
    const { mailbox, alias } = await pgpForwardSetup({});
    const msg = pgpInbound(alias.email);
    await deliver(msg, envWithSendMock());

    expect(msg.rejectReason).toBeNull();
    expect(outboundEmails).toHaveLength(1);
    const out = outboundEmails[0];
    expect(out.to).toBe(mailbox.email);
    const raw = out.raw;

    // RFC 3156 envelope (prepare_pgp_message L391 / L419-452).
    const ct = rawHeader(raw, "Content-Type") ?? "";
    expect(ct).toContain("multipart/encrypted");
    expect(ct).toContain('protocol="application/pgp-encrypted"');
    expect(rawHeader(raw, "MIME-Version")).toBe("1.0");
    // Non-MIME headers stay readable on the outer envelope: the From rewrite
    // to the reverse alias (step 11) applied AFTER encryption, like Flask.
    expect(rawHeader(raw, "From")).toContain("@sl.example.com");
    expect(rawHeader(raw, "From")).not.toContain("john@wick.example>");
    expect(rawHeader(raw, "Subject")).toBe("hello");
    expect(rawHeader(raw, "X-SimpleLogin-Type")).toBe("Forward");
    // the plaintext must not leak
    expect(raw).not.toContain("secret body");

    const boundary = ct.match(/boundary="([^"]+)"/)?.[1] ?? "";
    expect(boundary).not.toBe("");
    const parts = mimeParts(bodyOf(raw), boundary);
    expect(parts).toHaveLength(2);
    expect(rawHeader(parts[0].trimStart(), "Content-Type")).toBe(
      "application/pgp-encrypted",
    );
    expect(partBody(parts[0])).toContain("Version: 1");
    const part2 = parts[1].trimStart();
    expect(rawHeader(part2, "Content-Type")).toBe(
      'application/octet-stream; name="encrypted.asc"',
    );
    expect(rawHeader(part2, "Content-Disposition")).toBe(
      'inline; filename="encrypted.asc"',
    );

    // Round-trip: the encrypted payload is the inner MIME message (MIME
    // headers + body only, L400-417).
    const inner = await decryptArmored(partBody(parts[1]).trim());
    expect(inner).toContain("Content-Type: text/plain");
    expect(inner).toContain("Mime-Version: 1.0");
    expect(inner).toContain("secret body");
    // no outer header leaked into the encrypted part
    expect(inner).not.toContain("Subject");
  });

  it("disable_pgp bypasses encryption", async () => {
    const { alias } = await pgpForwardSetup({ disablePgp: 1 });
    await deliver(pgpInbound(alias.email), envWithSendMock());
    expect(outboundEmails).toHaveLength(1);
    const raw = outboundEmails[0].raw;
    expect(rawHeader(raw, "Content-Type")).toBe("text/plain");
    expect(raw).toContain("secret body");
  });

  it("alias-level disable_pgp bypasses encryption (email_handler.py L884)", async () => {
    const { alias } = await pgpForwardSetup({
      aliasOverrides: { disable_pgp: 1 },
    });
    await deliver(pgpInbound(alias.email), envWithSendMock());
    expect(outboundEmails).toHaveLength(1);
    expect(outboundEmails[0].raw).toContain("secret body");
    expect(outboundEmails[0].raw).not.toContain("multipart/encrypted");
  });

  it("non-premium users get plaintext (premium gate, email_handler.py L884)", async () => {
    const { alias } = await pgpForwardSetup({
      userOverrides: { trial_end: null },
    });
    await deliver(pgpInbound(alias.email), envWithSendMock());
    expect(outboundEmails).toHaveLength(1);
    expect(outboundEmails[0].raw).toContain("secret body");
    expect(outboundEmails[0].raw).not.toContain("multipart/encrypted");
  });

  it("a broken stored key delivers plaintext with the failure banner (L891-899)", async () => {
    const { mailbox, alias } = await pgpForwardSetup({
      mailboxKey: "broken key material",
      mailboxFingerprint: "AAAA0000BBBB1111CCCC2222DDDD3333EEEE4444",
    });
    await deliver(pgpInbound(alias.email), envWithSendMock());
    expect(outboundEmails).toHaveLength(1);
    const raw = outboundEmails[0].raw;
    expect(raw).not.toContain("multipart/encrypted");
    expect(raw).toContain(
      `PGP encryption fails with ${mailbox.email}'s PGP key`,
    );
    expect(raw).toContain("secret body");
  });
});
