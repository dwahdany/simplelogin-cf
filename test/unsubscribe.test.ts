/**
 * Byte-parity tests for the UnsubscribeEncoder port (src/lib/unsubscribe.ts).
 *
 * The hardcoded vectors were generated with the Flask implementation
 * (Python 3, itsdangerous 1.1.0 — the version pinned in poetry.lock):
 *
 *   secret = "test-flask-secretunsub"   # FLASK_SECRET + "unsub" under vitest
 *   signer = itsdangerous.Signer(secret, digest_method=hashlib.sha3_224)
 *   payload = (action, data)  # data = (0, alias_id, recipient, subject)
 *                             # for OriginalUnsubscribeMailto
 *   serialized = base64.urlsafe_b64encode(
 *       json.dumps(payload).encode("utf-8")).rstrip(b"=").decode()
 *   encoded = "un." + signer.sign(serialized).decode()
 *
 * Any drift in the JSON rendering (", " separators, ensure_ascii), the
 * base64url handling or the SHA3-224 signature chain breaks these exact
 * string comparisons.
 */

import { describe, expect, it } from "vitest";
import {
  decodeUnsubscribeSubject,
  encodeUnsubscribeSubject,
  encodeUnsubscribeUrl,
  UnsubscribeAction,
  unsubscribeSecret,
} from "../src/lib/unsubscribe";

/** unsubscribeSecret({FLASK_SECRET: "test-flask-secret"}) — the vitest env. */
const SECRET = "test-flask-secretunsub";

const V_NEWSLETTER_10 = "un.WzEsIDEwXQ.NTWnefwe7e0f2fhW7QH4OqeMuJ0gscUvI7FXmQ";
const V_DISABLE_ALIAS_42 =
  "un.WzIsIDQyXQ.9c59ZEHSAyeVLVyfyX_fImQehQ_ildDaYe1u6A";
const V_DISABLE_CONTACT_7 =
  "un.WzMsIDdd.cNMRvcHvr92VhsYK25CN89tH4Zne540c8v2Cww";
// UnsubscribeOriginalData(3, "unsub@list.example.com",
//   "Unsubscribe me ü — 100% off") — non-ASCII exercises ensure_ascii.
const V_ORIGINAL =
  "un.WzQsIFswLCAzLCAidW5zdWJAbGlzdC5leGFtcGxlLmNvbSIsICJVbnN1YnNjcmliZSBtZSBcdTAwZmMgXHUyMDE0IDEwMCUgb2ZmIl1d.xxS8huburmv2XvpZd4EamePNFLCv6WPVR0ElHQ";
const ORIGINAL_DATA = {
  aliasId: 3,
  recipient: "unsub@list.example.com",
  subject: "Unsubscribe me ü — 100% off",
};

describe("unsubscribeSecret", () => {
  it("is FLASK_SECRET + 'unsub' (config.py L227)", () => {
    expect(unsubscribeSecret({ FLASK_SECRET: "test-flask-secret" })).toBe(
      SECRET,
    );
  });
});

describe("encodeUnsubscribeSubject", () => {
  it("matches the Flask vectors byte for byte", () => {
    expect(
      encodeUnsubscribeSubject(
        SECRET,
        UnsubscribeAction.UnsubscribeNewsletter,
        10,
      ),
    ).toBe(V_NEWSLETTER_10);
    expect(
      encodeUnsubscribeSubject(SECRET, UnsubscribeAction.DisableAlias, 42),
    ).toBe(V_DISABLE_ALIAS_42);
    expect(
      encodeUnsubscribeSubject(SECRET, UnsubscribeAction.DisableContact, 7),
    ).toBe(V_DISABLE_CONTACT_7);
    expect(
      encodeUnsubscribeSubject(
        SECRET,
        UnsubscribeAction.OriginalUnsubscribeMailto,
        ORIGINAL_DATA,
      ),
    ).toBe(V_ORIGINAL);
  });

  it("throws on action/data type mismatches like Flask's ValueError", () => {
    expect(() =>
      encodeUnsubscribeSubject(
        SECRET,
        UnsubscribeAction.DisableAlias,
        ORIGINAL_DATA,
      ),
    ).toThrow();
    expect(() =>
      encodeUnsubscribeSubject(
        SECRET,
        UnsubscribeAction.OriginalUnsubscribeMailto,
        5,
      ),
    ).toThrow();
  });
});

describe("decodeUnsubscribeSubject", () => {
  it("decodes the Flask vectors", () => {
    expect(decodeUnsubscribeSubject(SECRET, V_NEWSLETTER_10)).toEqual({
      action: UnsubscribeAction.UnsubscribeNewsletter,
      data: 10,
    });
    expect(decodeUnsubscribeSubject(SECRET, V_DISABLE_ALIAS_42)).toEqual({
      action: UnsubscribeAction.DisableAlias,
      data: 42,
    });
    expect(decodeUnsubscribeSubject(SECRET, V_DISABLE_CONTACT_7)).toEqual({
      action: UnsubscribeAction.DisableContact,
      data: 7,
    });
    expect(decodeUnsubscribeSubject(SECRET, V_ORIGINAL)).toEqual({
      action: UnsubscribeAction.OriginalUnsubscribeMailto,
      data: ORIGINAL_DATA,
    });
  });

  it("round-trips an empty subject and an empty recipient", () => {
    const data = { aliasId: 12345, recipient: "", subject: "" };
    const encoded = encodeUnsubscribeSubject(
      SECRET,
      UnsubscribeAction.OriginalUnsubscribeMailto,
      data,
    );
    expect(decodeUnsubscribeSubject(SECRET, encoded)).toEqual({
      action: UnsubscribeAction.OriginalUnsubscribeMailto,
      data,
    });
  });

  it("rejects a tampered signature, payload, or wrong secret", () => {
    const flipped = `${V_DISABLE_ALIAS_42.slice(0, -1)}X`;
    expect(decodeUnsubscribeSubject(SECRET, flipped)).toBeNull();
    // signed "[2, 42]" payload swapped for "[2, 43]"
    const [, , sig] = V_DISABLE_ALIAS_42.split(".");
    expect(decodeUnsubscribeSubject(SECRET, `un.WzIsIDQzXQ.${sig}`)).toBeNull();
    expect(
      decodeUnsubscribeSubject("other-secret", V_DISABLE_ALIAS_42),
    ).toBeNull();
    expect(decodeUnsubscribeSubject(SECRET, "garbage")).toBeNull();
    expect(decodeUnsubscribeSubject(SECRET, "")).toBeNull();
  });
});

describe("encodeUnsubscribeUrl", () => {
  const URL_BASE = "https://app.sl.example.com";

  it("uses the plain dashboard links for DisableAlias/DisableContact", () => {
    expect(
      encodeUnsubscribeUrl(
        URL_BASE,
        SECRET,
        UnsubscribeAction.DisableAlias,
        42,
      ),
    ).toBe(`${URL_BASE}/dashboard/unsubscribe/42`);
    expect(
      encodeUnsubscribeUrl(
        URL_BASE,
        SECRET,
        UnsubscribeAction.DisableContact,
        7,
      ),
    ).toBe(`${URL_BASE}/dashboard/block_contact/7`);
  });

  it("puts the signed payload in the path for the encoded actions", () => {
    // Deviation from Flask's `?data=` form — see encodeUnsubscribeUrl.
    expect(
      encodeUnsubscribeUrl(
        URL_BASE,
        SECRET,
        UnsubscribeAction.UnsubscribeNewsletter,
        10,
      ),
    ).toBe(`${URL_BASE}/dashboard/unsubscribe/encoded/${V_NEWSLETTER_10}`);
    expect(
      encodeUnsubscribeUrl(
        URL_BASE,
        SECRET,
        UnsubscribeAction.OriginalUnsubscribeMailto,
        ORIGINAL_DATA,
      ),
    ).toBe(`${URL_BASE}/dashboard/unsubscribe/encoded/${V_ORIGINAL}`);
  });
});
