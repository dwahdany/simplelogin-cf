import { describe, expect, it } from "vitest";
import {
  canonicalizeEmail,
  checkPassword,
  hashPassword,
  itsdangerousSign,
  itsdangerousUnsign,
  randomString,
  randomWords,
  sanitizeEmail,
  timestampSign,
  timestampUnsign,
  tokenUrlsafe,
  verifyTotp,
} from "../src/lib/crypto";

/**
 * Cross-vectors generated from the real Python libraries (pinned versions),
 * so these assertions prove byte-for-byte compatibility with the Flask app:
 *
 *   uv run --with itsdangerous==1.1.0 python -c "..."   # Signer / TimestampSigner
 *   uv run --with bcrypt python -c "..."                # bcrypt (~=3.2)
 *   uv run --with pyotp python -c "..."                 # TOTP (~=2.4)
 *
 * The TimestampSigner vectors were signed at a FIXED epoch (see FIXED_EPOCH)
 * by manually calling the same code path pyotp/itsdangerous use internally,
 * so timestampSign(..., FIXED_EPOCH) must reproduce them exactly.
 */

const FLASK_SECRET = "test-flask-secret";
const CUSTOM_ALIAS_SECRET = `${FLASK_SECRET}custom_alias`; // app/config.py

// --- itsdangerous Signer (mfa_key) ---
const V_SIGNER = {
  value: "42",
  signed: "42.KKlLHiIaJ3lWDQKnDN9jFWfPDxY",
};

// --- itsdangerous TimestampSigner (signed_suffix) ---
const FIXED_EPOCH = 1700000000;
const V_TS = {
  value: ".test123@example.com",
  signedFixed: ".test123@example.com.ZVPxAA.0hG3qNvWy5lrdjqRsvWgD2_thzM",
  // A value containing several dots + an "@" — proves rightmost-split parsing.
  value2: "prefix.middle.suffix@sub.example.com",
  signedFixed2:
    "prefix.middle.suffix@sub.example.com.ZVPxAA.QP2r_KkBL5avY3FvkCVbkQsl2_E",
};

// --- bcrypt ---
const V_BCRYPT = {
  // "héllo" precomposed (U+00E9) vs decomposed (e + U+0301) — both NFKC-equal.
  precomposed: "héllo",
  decomposed: "héllo",
  nfkcHash: "$2b$12$1g8v1WOHl8IlN/7PXvUhEeyj4qPqs9CLOieK66uSmx4g0ZmzGykiq",
  simplePassword: "correct horse",
  simpleHash: "$2b$12$V3miTxhFhu8yIclYb9u4qOTorxEhNP7NimWAG73YsNToo1UyaI942",
};

// --- pyotp TOTP (secret JBSWY3DPEHPK3PXP) ---
const TOTP_SECRET = "JBSWY3DPEHPK3PXP";
const V_TOTP = {
  step0: "324550", // pyotp.at(1700000000)
  stepMinus2: "968785", // pyotp.at(1700000000 - 60)
  stepMinus1: "822542", // pyotp.at(1700000000 - 30)
  stepPlus1: "367665", // pyotp.at(1700000000 + 30)
  stepPlus2: "870960", // pyotp.at(1700000000 + 60)
  stepPlus3: "656781", // pyotp.at(1700000000 + 90) — outside window
  stepMinus3: "777646", // pyotp.at(1700000000 - 90) — outside window
};
const TOTP_NOW_MS = FIXED_EPOCH * 1000;

const BCRYPT_TIMEOUT = 60_000; // cost-12 bcrypt is CPU-heavy in pure JS

describe("itsdangerous Signer", () => {
  it("reproduces the Python Signer.sign() vector", async () => {
    expect(await itsdangerousSign(FLASK_SECRET, V_SIGNER.value)).toBe(
      V_SIGNER.signed,
    );
  });

  it("unsigns a Python-signed value", async () => {
    expect(await itsdangerousUnsign(FLASK_SECRET, V_SIGNER.signed)).toBe(
      V_SIGNER.value,
    );
  });

  it("round-trips sign -> unsign", async () => {
    const signed = await itsdangerousSign(FLASK_SECRET, "1234");
    expect(await itsdangerousUnsign(FLASK_SECRET, signed)).toBe("1234");
  });

  it("rejects a tampered signature", async () => {
    const tampered = `${V_SIGNER.signed.slice(0, -1)}X`;
    expect(await itsdangerousUnsign(FLASK_SECRET, tampered)).toBeNull();
  });

  it("rejects the wrong secret", async () => {
    expect(
      await itsdangerousUnsign("other-secret", V_SIGNER.signed),
    ).toBeNull();
  });

  it("returns null when there is no separator", async () => {
    expect(await itsdangerousUnsign(FLASK_SECRET, "nosep")).toBeNull();
  });
});

describe("itsdangerous TimestampSigner", () => {
  it("reproduces the Python TimestampSigner.sign() vector at a fixed epoch", async () => {
    expect(
      await timestampSign(CUSTOM_ALIAS_SECRET, V_TS.value, FIXED_EPOCH),
    ).toBe(V_TS.signedFixed);
  });

  it("reproduces the vector for a value containing dots and @", async () => {
    expect(
      await timestampSign(CUSTOM_ALIAS_SECRET, V_TS.value2, FIXED_EPOCH),
    ).toBe(V_TS.signedFixed2);
  });

  it("unsigns a Python-signed value within max_age (rightmost-split parsing)", async () => {
    // now = fixed epoch + 100s, max_age 600 -> still valid.
    expect(
      await timestampUnsign(
        CUSTOM_ALIAS_SECRET,
        V_TS.signedFixed,
        600,
        FIXED_EPOCH + 100,
      ),
    ).toBe(V_TS.value);
  });

  it("unsigns a dotted value correctly (splits only the rightmost two dots)", async () => {
    expect(
      await timestampUnsign(
        CUSTOM_ALIAS_SECRET,
        V_TS.signedFixed2,
        600,
        FIXED_EPOCH + 100,
      ),
    ).toBe(V_TS.value2);
  });

  it("returns null when the signature is older than max_age", async () => {
    // age = 700s > max_age 600 -> SignatureExpired -> null.
    expect(
      await timestampUnsign(
        CUSTOM_ALIAS_SECRET,
        V_TS.signedFixed,
        600,
        FIXED_EPOCH + 700,
      ),
    ).toBeNull();
  });

  it("returns null for a tampered signature", async () => {
    const tampered = `${V_TS.signedFixed.slice(0, -1)}A`;
    expect(
      await timestampUnsign(CUSTOM_ALIAS_SECRET, tampered, 600, FIXED_EPOCH),
    ).toBeNull();
  });

  it("round-trips sign -> unsign for a value with dots", async () => {
    const value = ".sunny_falcon123@my.custom.domain.com";
    const signed = await timestampSign(CUSTOM_ALIAS_SECRET, value, FIXED_EPOCH);
    expect(
      await timestampUnsign(CUSTOM_ALIAS_SECRET, signed, 600, FIXED_EPOCH + 10),
    ).toBe(value);
  });
});

describe("bcrypt password hashing", () => {
  it(
    "verifies both NFKC-equivalent forms against a Python bcrypt hash",
    async () => {
      expect(await checkPassword(V_BCRYPT.nfkcHash, V_BCRYPT.precomposed)).toBe(
        true,
      );
      expect(await checkPassword(V_BCRYPT.nfkcHash, V_BCRYPT.decomposed)).toBe(
        true,
      );
    },
    BCRYPT_TIMEOUT,
  );

  it(
    "verifies a simple password against a Python bcrypt hash",
    async () => {
      expect(
        await checkPassword(V_BCRYPT.simpleHash, V_BCRYPT.simplePassword),
      ).toBe(true);
      expect(await checkPassword(V_BCRYPT.simpleHash, "wrong password")).toBe(
        false,
      );
    },
    BCRYPT_TIMEOUT,
  );

  it(
    "runs a dummy comparison and returns false when the hash is null",
    async () => {
      expect(await checkPassword(null, "anything")).toBe(false);
    },
    BCRYPT_TIMEOUT,
  );

  it(
    "hashPassword produces a $2b$12$ hash that verifies",
    async () => {
      const hash = await hashPassword("swordfish");
      expect(hash.startsWith("$2b$12$")).toBe(true);
      expect(await checkPassword(hash, "swordfish")).toBe(true);
      expect(await checkPassword(hash, "Swordfish")).toBe(false);
    },
    BCRYPT_TIMEOUT,
  );
});

describe("TOTP verification (pyotp-compatible)", () => {
  it("accepts the current code", () => {
    expect(verifyTotp(TOTP_SECRET, V_TOTP.step0, null, TOTP_NOW_MS)).toBe(true);
  });

  it("accepts codes within the ±2 step window", () => {
    for (const code of [
      V_TOTP.stepMinus2,
      V_TOTP.stepMinus1,
      V_TOTP.step0,
      V_TOTP.stepPlus1,
      V_TOTP.stepPlus2,
    ]) {
      expect(verifyTotp(TOTP_SECRET, code, null, TOTP_NOW_MS)).toBe(true);
    }
  });

  it("rejects codes outside the ±2 step window", () => {
    expect(verifyTotp(TOTP_SECRET, V_TOTP.stepPlus3, null, TOTP_NOW_MS)).toBe(
      false,
    );
    expect(verifyTotp(TOTP_SECRET, V_TOTP.stepMinus3, null, TOTP_NOW_MS)).toBe(
      false,
    );
  });

  it("rejects a replayed code (equal to lastOtp)", () => {
    expect(
      verifyTotp(TOTP_SECRET, V_TOTP.step0, V_TOTP.step0, TOTP_NOW_MS),
    ).toBe(false);
  });

  it("accepts a valid code when lastOtp is a different code", () => {
    expect(
      verifyTotp(TOTP_SECRET, V_TOTP.step0, V_TOTP.stepPlus1, TOTP_NOW_MS),
    ).toBe(true);
  });

  it("accepts a lowercase secret (pyotp casefold behavior)", () => {
    expect(
      verifyTotp(TOTP_SECRET.toLowerCase(), V_TOTP.step0, null, TOTP_NOW_MS),
    ).toBe(true);
  });

  it("rejects a wrong code", () => {
    expect(verifyTotp(TOTP_SECRET, "000000", null, TOTP_NOW_MS)).toBe(false);
  });
});

describe("CSPRNG generators", () => {
  it("randomString yields lowercase a-z of the requested length", () => {
    const s = randomString(60);
    expect(s).toHaveLength(60);
    expect(s).toMatch(/^[a-z]+$/);
    // Two draws should (essentially) never collide.
    expect(randomString(60)).not.toBe(s);
  });

  it("tokenUrlsafe defaults to 32 bytes -> 43 url-safe chars, no padding", () => {
    const t = tokenUrlsafe();
    expect(t).toHaveLength(43);
    expect(t).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(t).not.toContain("=");
    expect(tokenUrlsafe(16)).toHaveLength(22);
  });

  it("randomWords joins words with underscores and appends digits", () => {
    expect(randomWords(1)).toMatch(/^[a-z][a-z-]*$/);
    expect(randomWords(2)).toMatch(/^[a-z][a-z-]*_[a-z][a-z-]*$/);
    expect(randomWords(2, 3)).toMatch(/^[a-z][a-z-]*_[a-z][a-z-]*[0-9]{3}$/);
    expect(randomWords(1, 3)).toMatch(/^[a-z][a-z-]*[0-9]{3}$/);
  });
});

describe("email sanitization", () => {
  it("strips whitespace, spaces and lowercases", () => {
    expect(sanitizeEmail("  Foo@Bar.com  ")).toBe("foo@bar.com");
    expect(sanitizeEmail("a b c@d.com")).toBe("abc@d.com");
  });

  it("preserves case when notLower is set", () => {
    expect(sanitizeEmail("Foo@Bar.com", true)).toBe("Foo@Bar.com");
  });

  it("removes the U+200F RTL mark", () => {
    expect(sanitizeEmail("foo‏@bar.com")).toBe("foo@bar.com");
  });

  it("turns internal newlines into a space (documented quirk)", () => {
    expect(sanitizeEmail("a\nb")).toBe("a b");
  });

  it("returns empty string for empty input", () => {
    expect(sanitizeEmail("")).toBe("");
  });
});

describe("email canonicalization", () => {
  it("strips dots and +suffix for gmail", () => {
    expect(canonicalizeEmail("John.Doe+news@gmail.com")).toBe(
      "johndoe@gmail.com",
    );
    expect(canonicalizeEmail("j.o.h.n@googlemail.com")).toBe(
      "john@googlemail.com",
    );
  });

  it("canonicalizes proton domains", () => {
    expect(canonicalizeEmail("a.b+x@proton.me")).toBe("ab@proton.me");
    expect(canonicalizeEmail("a.b@protonmail.com")).toBe("ab@protonmail.com");
    expect(canonicalizeEmail("a.b+x@pm.me")).toBe("ab@pm.me");
  });

  it("leaves non-canonical domains unchanged (but sanitized)", () => {
    expect(canonicalizeEmail("John.Doe+tag@Example.com")).toBe(
      "john.doe+tag@example.com",
    );
  });

  it("returns empty string when there is not exactly one @", () => {
    expect(canonicalizeEmail("notanemail")).toBe("");
    expect(canonicalizeEmail("a@b@c")).toBe("");
  });
});
