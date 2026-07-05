/**
 * Alias-creation route group (specs/03-alias-creation.md).
 *
 * Routes (all under /api, all @require_api_auth):
 *   GET  /v4/alias/options       — suffixes as [suffix, signed_suffix] pairs
 *   GET  /v5/alias/options       — suffixes as objects
 *   POST /v2/alias/custom/new    — ALIAS_LIMIT + alias_creation lock
 *   POST /v3/alias/custom/new    — same, requires mailbox_ids
 *   POST /alias/random/new       — word/uuid random alias
 *
 * Ported from app/api/views/alias_options.py, new_custom_alias.py,
 * new_random_alias.py + helpers in app/alias_suffix.py, app/alias_utils.py,
 * app/utils.py, app/models.py. Error strings/status codes are byte-exact.
 */

import type { Context, MiddlewareHandler } from "hono";
import { Hono } from "hono";
import { type AppEnv, requireApiAuth } from "../lib/auth";
import {
  randomWords,
  sanitizeEmail,
  timestampSign,
  timestampUnsign,
} from "../lib/crypto";
import { nowStr } from "../lib/dates";
import type { Env } from "../lib/env";
import { badRequest, jsonError, rateLimited } from "../lib/errors";
import {
  availableSlEmail,
  canCreateNewAlias,
  FLAG_CREATED_ALIAS_FROM_PARTNER,
  getCustomDomainById,
  getMailboxById,
  getPublicDomainById,
  getSLDomains,
  userInTrial,
  userIsPremium,
} from "../lib/models";
import { rateLimit, requestLock } from "../lib/ratelimit";
import type {
  AliasRow,
  CustomDomainRow,
  MailboxRow,
  PublicDomainRow,
  UserRow,
} from "../lib/rows";
import { getAliasInfoV2, serializeAliasInfoV2 } from "../lib/serializer";

export const aliasCreationRoutes = new Hono<AppEnv>();

// --------------------------------------------------------------------------
// Config constants (app/config.py)
// --------------------------------------------------------------------------

const ALIAS_LIMIT_DEFAULT = "100/day;50/hour;5/minute";
// env var ALIAS_RAND_SUFFIX_LENGTH in Flask; not part of the Env contract here.
const ALIAS_RANDOM_SUFFIX_LENGTH = 5;
// "10,900:50,3600" / "50,900:200,3600" parsed — [maxHits, bucketSeconds][]
const ALIAS_CREATE_RATE_LIMIT_FREE: ReadonlyArray<readonly [number, number]> = [
  [10, 900],
  [50, 3600],
];
const ALIAS_CREATE_RATE_LIMIT_PAID: ReadonlyArray<readonly [number, number]> = [
  [50, 900],
  [200, 3600],
];
const ALIAS_FLAG_PARTNER_CREATED = 1; // Alias.FLAG_PARTNER_CREATED = 1 << 0
const AliasGenerator = { word: 1, uuid: 2 } as const;

function customAliasSecret(env: Env): string {
  return `${env.FLASK_SECRET}custom_alias`;
}

/** flask-limiter @limiter.limit(ALIAS_LIMIT), keyed like the Flask default. */
function aliasLimit(name: string): MiddlewareHandler<AppEnv> {
  return (c, next) =>
    rateLimit(
      name,
      c.env.ALIAS_LIMIT ?? ALIAS_LIMIT_DEFAULT,
      "default",
    )(c, next);
}

// --------------------------------------------------------------------------
// Typed errors thrown by the Alias.create equivalent
// --------------------------------------------------------------------------

class EmailNotValidError extends Error {}
class AliasInTrashError extends Error {}
class BucketRateLimitError extends Error {}

// --------------------------------------------------------------------------
// app/utils.py helpers
// --------------------------------------------------------------------------

const ID_ALLOWED_CHARS = new Set(
  "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.",
);

/**
 * convert_to_id(): lowercase -> transliterate -> drop spaces -> non-allowed
 * chars to "_" -> truncate to 64. The unidecode step is approximated with
 * NFKD + combining-mark stripping (covers Latin accents; other scripts fall
 * through to "_" instead of an ASCII transliteration).
 */
function convertToId(s: string): string {
  let out = s.toLowerCase();
  out = out.normalize("NFKD").replace(/[\u0300-\u036f]/g, "");
  out = out.replaceAll(" ", "");
  let res = "";
  for (const ch of out) res += ID_ALLOWED_CHARS.has(ch) ? ch : "_";
  return res.slice(0, 64);
}

/** check_alias_prefix (app/alias_utils.py): 1-40 chars of [0-9a-z-_.]. */
function checkAliasPrefix(prefix: string): boolean {
  if (prefix.length > 40) return false;
  return /^[0-9a-z\-_.]+$/.test(prefix);
}

/**
 * tldextract-lite: registrable label of a hostname (PSL approximated with a
 * snapshot of common two-level public suffixes). "www.groupon.com" ->
 * "groupon", "foo.co.uk" -> "foo".
 */
const TWO_LEVEL_SUFFIXES = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "me.uk",
  "net.uk",
  "ltd.uk",
  "plc.uk",
  "sch.uk",
  "com.au",
  "net.au",
  "org.au",
  "edu.au",
  "gov.au",
  "id.au",
  "co.nz",
  "net.nz",
  "org.nz",
  "govt.nz",
  "co.jp",
  "ne.jp",
  "or.jp",
  "ac.jp",
  "go.jp",
  "com.br",
  "net.br",
  "org.br",
  "gov.br",
  "com.mx",
  "org.mx",
  "net.mx",
  "co.in",
  "net.in",
  "org.in",
  "com.cn",
  "net.cn",
  "org.cn",
  "gov.cn",
  "com.tw",
  "org.tw",
  "net.tw",
  "com.hk",
  "org.hk",
  "net.hk",
  "co.kr",
  "or.kr",
  "ne.kr",
  "co.za",
  "org.za",
  "net.za",
  "web.za",
  "com.ar",
  "com.tr",
  "com.sg",
  "com.my",
  "com.ph",
  "com.vn",
  "com.eg",
  "com.sa",
  "com.co",
  "com.pe",
  "com.ve",
  "co.id",
  "co.th",
  "co.il",
  "org.il",
  "com.pl",
  "net.pl",
  "org.pl",
  "com.ua",
  "in.ua",
]);

function extractDomainLabel(hostname: string): string {
  let h = hostname.trim().toLowerCase();
  h = h.replace(/^[a-z][a-z0-9+.-]*:\/\//, "");
  h = h.split("/")[0].split("?")[0].split("#")[0];
  const at = h.lastIndexOf("@");
  if (at >= 0) h = h.slice(at + 1);
  h = h.split(":")[0];
  const labels = h.split(".").filter((l) => l.length > 0);
  if (labels.length === 0) return "";
  if (labels.length === 1) return labels[0];
  const lastTwo = labels.slice(-2).join(".");
  const suffixLen = TWO_LEVEL_SUFFIXES.has(lastTwo) ? 2 : 1;
  if (labels.length <= suffixLen) return "";
  return labels[labels.length - suffixLen - 1];
}

// --------------------------------------------------------------------------
// email-validator 2.2.0 approximation (check_deliverability=False,
// allow_smtputf8=False): ASCII dot-atom local part, dotted domain whose TLD
// contains a letter. Returns the domain part or throws EmailNotValidError.
// --------------------------------------------------------------------------

const LOCAL_PART_RE =
  /^[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+(?:\.[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]+)*$/;
const DOMAIN_LABEL_RE = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/;

function validateEmailOrThrow(email: string): string {
  // printable ASCII only, no spaces (allow_smtputf8=False rejects non-ASCII)
  if (!/^[\x21-\x7e]+$/.test(email)) throw new EmailNotValidError(email);
  const idx = email.lastIndexOf("@");
  if (idx < 0) throw new EmailNotValidError(email);
  const local = email.slice(0, idx);
  const domain = email.slice(idx + 1);
  if (!local || local.length > 64 || !LOCAL_PART_RE.test(local)) {
    throw new EmailNotValidError(email);
  }
  if (!domain || domain.length > 253) throw new EmailNotValidError(email);
  const labels = domain.split(".");
  if (labels.length < 2) throw new EmailNotValidError(email); // needs a period
  for (const label of labels) {
    if (!DOMAIN_LABEL_RE.test(label)) throw new EmailNotValidError(email);
  }
  if (!/[A-Za-z]/.test(labels[labels.length - 1])) {
    throw new EmailNotValidError(email); // all-numeric TLD
  }
  return domain.toLowerCase();
}

// --------------------------------------------------------------------------
// Random suffix / random email generation (app/models.py)
// --------------------------------------------------------------------------

const LOWER_ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789";

/** Unbiased random index like secrets.choice (rejection sampling). */
function randomIndex(n: number): number {
  const RANGE = 2 ** 32;
  const limit = RANGE - (RANGE % n);
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

/** random_string(length, include_digits=True) — lowercase a-z + 0-9. */
function randomLowerAlnum(length: number): string {
  let out = "";
  for (let i = 0; i < length; i++)
    out += LOWER_ALNUM[randomIndex(LOWER_ALNUM.length)];
  return out;
}

/** User.get_random_alias_suffix(custom_domain) (models.py L1260). */
function getRandomAliasSuffix(
  user: UserRow,
  customDomain?: CustomDomainRow | null,
): string {
  if (user.random_alias_suffix === 1) {
    return randomLowerAlnum(ALIAS_RANDOM_SUFFIX_LENGTH);
  }
  if (!customDomain) return randomWords(1, 3);
  return randomWords(1);
}

/**
 * generate_random_alias_email (models.py L1567). Gotcha kept: the retry
 * recursion drops alias_domain and falls back to FIRST_ALIAS_DOMAIN.
 */
async function generateRandomAliasEmail(
  db: D1Database,
  env: Env,
  scheme: number,
  aliasDomain?: string,
  retries = 10,
): Promise<string> {
  if (retries <= 0) throw new Error("Cannot generate alias after many retries");
  const domain =
    aliasDomain ?? (env.FIRST_ALIAS_DOMAIN || env.EMAIL_DOMAIN).toLowerCase();
  const local =
    scheme === AliasGenerator.uuid ? crypto.randomUUID() : randomWords(2, 3);
  const email = `${local}@${domain}`.toLowerCase().trim();
  if (await availableSlEmail(db, email)) return email;
  return generateRandomAliasEmail(db, env, scheme, undefined, retries - 1);
}

// --------------------------------------------------------------------------
// Suffix building & verification (app/alias_suffix.py)
// --------------------------------------------------------------------------

interface AliasSuffix {
  isCustom: boolean;
  suffix: string;
  signedSuffix: string;
  isPremium: boolean;
  domain: string;
  mxVerified: boolean;
}

/** User.verified_custom_domains(): ownership_verified, domain ASC. */
async function verifiedCustomDomains(
  db: D1Database,
  userId: number,
): Promise<CustomDomainRow[]> {
  const res = await db
    .prepare(
      "SELECT * FROM custom_domain WHERE user_id = ?1 AND ownership_verified = 1 ORDER BY domain ASC",
    )
    .bind(userId)
    .all<CustomDomainRow>();
  return res.results;
}

/** get_alias_suffixes(user) — order matters (default first, custom first). */
async function getAliasSuffixes(
  db: D1Database,
  env: Env,
  user: UserRow,
): Promise<AliasSuffix[]> {
  const secret = customAliasSecret(env);
  const disableSuffix = env.DISABLE_ALIAS_SUFFIX !== undefined;
  const suffixes: AliasSuffix[] = [];

  for (const cd of await verifiedCustomDomains(db, user.id)) {
    if (cd.random_prefix_generation) {
      const suffix = `.${getRandomAliasSuffix(user, cd)}@${cd.domain}`;
      const aliasSuffix: AliasSuffix = {
        isCustom: true,
        suffix,
        signedSuffix: await timestampSign(secret, suffix),
        isPremium: false,
        domain: cd.domain,
        mxVerified: !!cd.verified,
      };
      if (user.default_alias_custom_domain_id === cd.id) {
        suffixes.unshift(aliasSuffix);
      } else {
        suffixes.push(aliasSuffix);
      }
    }

    const suffix = `@${cd.domain}`;
    const aliasSuffix: AliasSuffix = {
      isCustom: true,
      suffix,
      signedSuffix: await timestampSign(secret, suffix),
      isPremium: false,
      domain: cd.domain,
      mxVerified: !!cd.verified,
    };
    if (
      user.default_alias_custom_domain_id === cd.id &&
      !cd.random_prefix_generation
    ) {
      suffixes.unshift(aliasSuffix);
    } else {
      suffixes.push(aliasSuffix);
    }
  }

  const slDomains = await getSLDomains(db, user, env);
  let defaultDomainFound = false;
  for (const sl of slDomains) {
    const prefix = disableSuffix ? "" : `.${getRandomAliasSuffix(user)}`;
    const suffix = `${prefix}@${sl.domain}`;
    const aliasSuffix: AliasSuffix = {
      isCustom: false,
      suffix,
      signedSuffix: await timestampSign(secret, suffix),
      isPremium: !!sl.premium_only,
      domain: sl.domain,
      mxVerified: true,
    };
    if (
      user.default_alias_public_domain_id === null ||
      user.default_alias_public_domain_id !== sl.id
    ) {
      suffixes.push(aliasSuffix);
    } else {
      defaultDomainFound = true;
      suffixes.unshift(aliasSuffix);
    }
  }

  if (!defaultDomainFound && user.default_alias_public_domain_id !== null) {
    const premium = await userIsPremium(db, user);
    const sql = premium
      ? "SELECT * FROM public_domain WHERE id = ?1 AND hidden = 0"
      : "SELECT * FROM public_domain WHERE id = ?1 AND hidden = 0 AND premium_only = 0";
    const sl = await db
      .prepare(sql)
      .bind(user.default_alias_public_domain_id)
      .first<PublicDomainRow>();
    if (sl) {
      const prefix = disableSuffix ? "" : `.${getRandomAliasSuffix(user)}`;
      const suffix = `${prefix}@${sl.domain}`;
      suffixes.unshift({
        isCustom: false,
        suffix,
        signedSuffix: await timestampSign(secret, suffix),
        isPremium: !!sl.premium_only,
        domain: sl.domain,
        mxVerified: true,
      });
    }
  }

  return suffixes;
}

/** verify_prefix_suffix(user, prefix, suffix) (app/alias_suffix.py L45). */
function verifyPrefixSuffix(
  env: Env,
  aliasPrefix: string,
  aliasSuffix: string,
  slDomains: PublicDomainRow[],
  customDomains: CustomDomainRow[],
): boolean {
  if (!aliasPrefix || !aliasSuffix) return false;

  const userCustomDomains = customDomains.map((cd) => cd.domain);
  const suffix = aliasSuffix.trim();
  const at = suffix.indexOf("@");
  // Flask would raise (500) on a suffix without "@"; unreachable for suffixes
  // that passed signature verification — return a clean false instead.
  if (at < 0) return false;
  const aliasDomainPrefix = suffix.slice(0, at);
  const aliasDomain = suffix.slice(at + 1);

  const availableSlDomains = slDomains.map((d) => d.domain);
  const availableDomains = new Set([
    ...availableSlDomains,
    ...userCustomDomains,
  ]);
  if (!availableDomains.has(aliasDomain)) return false;

  const disableSuffix = env.DISABLE_ALIAS_SUFFIX !== undefined;
  if (
    availableSlDomains.includes(aliasDomain) &&
    !userCustomDomains.includes(aliasDomain) &&
    !disableSuffix
  ) {
    if (!aliasDomainPrefix.startsWith(".")) return false;
  } else if (!userCustomDomains.includes(aliasDomain)) {
    if (!disableSuffix) return false;
    if (!availableSlDomains.includes(aliasDomain)) return false;
  }

  return true;
}

// --------------------------------------------------------------------------
// Alias.create equivalent (app/models.py L1791)
// --------------------------------------------------------------------------

/** rate_limiter.check_bucket_limit for both alias-creation buckets. */
async function checkBucketLimits(
  db: D1Database,
  env: Env,
  user: UserRow,
): Promise<void> {
  if (env.DISABLE_RATE_LIMIT !== undefined) return;
  const now = new Date();
  const premium = await userIsPremium(db, user, now);
  const trial = await userInTrial(db, user, now);
  const limits =
    premium && !trial
      ? ALIAS_CREATE_RATE_LIMIT_PAID
      : ALIAS_CREATE_RATE_LIMIT_FREE;
  const nowSec = Math.floor(now.getTime() / 1000);
  for (const [maxHits, bucketSeconds] of limits) {
    const bucketId = nowSec - (nowSec % bucketSeconds);
    const key = `bl:alias_create_${bucketSeconds}:${user.id}:${bucketId}`;
    const row = await db
      .prepare(
        `INSERT INTO rate_limit (key, window_start, count) VALUES (?1, ?2, 1)
         ON CONFLICT(key) DO UPDATE SET count = count + 1 RETURNING count`,
      )
      .bind(key, bucketId)
      .first<{ count: number }>();
    if ((row?.count ?? 1) > maxHits) throw new BucketRateLimitError();
  }
}

/** Alias.get_custom_domain(email): domain lookup unless it is an SL domain. */
async function getCustomDomainForEmail(
  db: D1Database,
  email: string,
): Promise<CustomDomainRow | null> {
  const domain = validateEmailOrThrow(email);
  const sl = await db
    .prepare("SELECT 1 FROM public_domain WHERE domain = ?1 LIMIT 1")
    .bind(domain)
    .first();
  if (sl) return null;
  return db
    .prepare("SELECT * FROM custom_domain WHERE domain = ?1 LIMIT 1")
    .bind(domain)
    .first<CustomDomainRow>();
}

interface NewAliasInput {
  email: string;
  mailboxId: number | null;
  note: unknown;
  name?: string | null;
}

/**
 * Alias.create: bucket rate limits, trash check, custom-domain detection +
 * partner flags, insert. Throws BucketRateLimitError / AliasInTrashError /
 * EmailNotValidError. (DailyMetric/audit-log/partner-event side effects have
 * no table in this port and are skipped — no HTTP contract impact.)
 */
async function insertAlias(
  db: D1Database,
  env: Env,
  user: UserRow,
  input: NewAliasInput,
): Promise<AliasRow> {
  await checkBucketLimits(db, env, user);

  const sanitized = sanitizeEmail(input.email);
  const trashed = await db
    .prepare(
      `SELECT 1 AS x FROM deleted_alias WHERE email = ?1
       UNION SELECT 1 FROM domain_deleted_alias WHERE email = ?1 LIMIT 1`,
    )
    .bind(sanitized)
    .first();
  if (trashed) throw new AliasInTrashError(sanitized);

  const customDomain = await getCustomDomainForEmail(db, sanitized);
  let flags = 0;
  let customDomainId: number | null = null;
  if (customDomain) {
    // AliasDomainForbidden is unhandled in the Flask routes too (-> 500);
    // verify_prefix_suffix prevents reaching this in practice.
    if (customDomain.user_id !== user.id) {
      throw new Error(`alias domain ${customDomain.domain} is forbidden`);
    }
    customDomainId = customDomain.id;
    if (customDomain.partner_id !== null) flags |= ALIAS_FLAG_PARTNER_CREATED;
  }

  const now = nowStr();
  const row = await db
    .prepare(
      `INSERT INTO alias (user_id, email, note, name, mailbox_id, custom_domain_id, flags, created_at)
       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8) RETURNING *`,
    )
    .bind(
      user.id,
      input.email,
      (input.note ?? null) as string | null,
      input.name ?? null,
      input.mailboxId,
      customDomainId,
      flags,
      now,
    )
    .first<AliasRow>();
  if (!row) throw new Error("alias insert returned no row");

  if (
    (flags & ALIAS_FLAG_PARTNER_CREATED) !== 0 &&
    (user.flags & FLAG_CREATED_ALIAS_FROM_PARTNER) === 0
  ) {
    await db
      .prepare(
        "UPDATE users SET flags = flags | ?1, updated_at = ?2 WHERE id = ?3",
      )
      .bind(FLAG_CREATED_ALIAS_FROM_PARTNER, now, user.id)
      .run();
  }

  return row;
}

/** Alias.create_new_random (models.py L1907). */
async function createNewRandom(
  db: D1Database,
  env: Env,
  user: UserRow,
  scheme: number,
  note: unknown,
): Promise<AliasRow> {
  let customDomain: CustomDomainRow | null = null;
  let randomEmail: string | null = null;

  if (user.default_alias_custom_domain_id) {
    customDomain = await getCustomDomainById(
      db,
      user.default_alias_custom_domain_id,
    );
    if (!customDomain) {
      throw new Error(
        `custom domain ${user.default_alias_custom_domain_id} not found`,
      );
    }
    randomEmail = await generateRandomAliasEmail(
      db,
      env,
      scheme,
      customDomain.domain,
    );
  } else if (user.default_alias_public_domain_id) {
    const sl = await getPublicDomainById(
      db,
      user.default_alias_public_domain_id,
    );
    if (!sl) {
      throw new Error(
        `public domain ${user.default_alias_public_domain_id} not found`,
      );
    }
    if (!(sl.premium_only && !(await userIsPremium(db, user)))) {
      randomEmail = await generateRandomAliasEmail(db, env, scheme, sl.domain);
    }
  }

  if (!randomEmail) {
    randomEmail = await generateRandomAliasEmail(db, env, scheme);
  }

  const alias = await insertAlias(db, env, user, {
    email: randomEmail,
    mailboxId: user.default_mailbox_id,
    note,
  });

  if (customDomain && alias.custom_domain_id !== customDomain.id) {
    await db
      .prepare(
        "UPDATE alias SET custom_domain_id = ?1, updated_at = ?2 WHERE id = ?3",
      )
      .bind(customDomain.id, nowStr(), alias.id)
      .run();
    alias.custom_domain_id = customDomain.id;
  }

  return alias;
}

// --------------------------------------------------------------------------
// Small shared route helpers
// --------------------------------------------------------------------------

function freePlanLimitMsg(env: Env): string {
  const parsed = Number.parseInt(env.MAX_NB_EMAIL_FREE_PLAN, 10);
  const max = Number.isNaN(parsed) ? 5 : parsed;
  return (
    "You have reached the limitation of a free account with the maximum of " +
    `${max} aliases, please upgrade your plan to create more aliases`
  );
}

/**
 * Flask request.get_json(): null when the content type is not JSON; throws
 * SyntaxError (-> framework 400 {"error": "Bad Request"}) on malformed JSON.
 */
async function getJsonBody(c: Context<AppEnv>): Promise<unknown> {
  const ct = (c.req.header("Content-Type") ?? "").split(";")[0].trim();
  const mime = ct.toLowerCase();
  if (mime !== "application/json" && !mime.endsWith("+json")) return null;
  return await c.req.json();
}

/** Python truthiness for JSON values (None/False/0/""/[]/{} are falsy). */
function isFalsyJson(v: unknown): boolean {
  if (v === null || v === undefined || v === false || v === 0 || v === "") {
    return true;
  }
  if (Array.isArray(v)) return v.length === 0;
  if (typeof v === "object") return Object.keys(v).length === 0;
  return false;
}

async function emailInAliasOrTrash(
  db: D1Database,
  email: string,
): Promise<boolean> {
  const row = await db
    .prepare(
      `SELECT 1 AS x FROM alias WHERE email = ?1
       UNION SELECT 1 FROM deleted_alias WHERE email = ?1
       UNION SELECT 1 FROM domain_deleted_alias WHERE email = ?1 LIMIT 1`,
    )
    .bind(email)
    .first();
  return !!row;
}

function insertAliasUsedOn(
  db: D1Database,
  aliasId: number,
  hostname: string,
  userId: number,
): Promise<D1Result> {
  return db
    .prepare(
      "INSERT INTO alias_used_on (alias_id, user_id, hostname, created_at) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(aliasId, userId, hostname, nowStr())
    .run();
}

async function serializedAliasResponse(
  c: Context<AppEnv>,
  alias: AliasRow,
  user: UserRow,
): Promise<Response> {
  const info = await getAliasInfoV2(c.env.DB, alias, user);
  return c.json({ alias: alias.email, ...serializeAliasInfoV2(info) }, 201);
}

// --------------------------------------------------------------------------
// GET /v4/alias/options and /v5/alias/options
// --------------------------------------------------------------------------

async function handleAliasOptions(
  c: Context<AppEnv>,
  v5: boolean,
): Promise<Response> {
  const user = c.get("user");
  const db = c.env.DB;
  const hostname = c.req.query("hostname");

  const ret: Record<string, unknown> = {
    can_create: await canCreateNewAlias(db, c.env, user),
    suffixes: [],
    prefix_suggestion: "",
  };

  if (hostname) {
    const rec = await db
      .prepare(
        `SELECT a.email FROM alias_used_on auo
         JOIN alias a ON auo.alias_id = a.id
         WHERE a.user_id = ?1 AND auo.hostname = ?2
         ORDER BY auo.created_at DESC, auo.id DESC LIMIT 1`,
      )
      .bind(user.id, hostname)
      .first<{ email: string }>();
    if (rec) ret.recommendation = { alias: rec.email, hostname };
    ret.prefix_suggestion = convertToId(extractDomainLabel(hostname));
  }

  const suffixes = await getAliasSuffixes(db, c.env, user);
  ret.suffixes = v5
    ? suffixes.map((s) => ({
        suffix: s.suffix,
        signed_suffix: s.signedSuffix,
        is_custom: s.isCustom,
        is_premium: s.isPremium,
      }))
    : suffixes.map((s) => [s.suffix, s.signedSuffix]);

  return c.json(ret);
}

aliasCreationRoutes.get("/v4/alias/options", requireApiAuth, (c) =>
  handleAliasOptions(c, false),
);
aliasCreationRoutes.get("/v5/alias/options", requireApiAuth, (c) =>
  handleAliasOptions(c, true),
);

// --------------------------------------------------------------------------
// POST /v2/alias/custom/new
// --------------------------------------------------------------------------

aliasCreationRoutes.post(
  "/v2/alias/custom/new",
  requireApiAuth,
  aliasLimit("new_custom_alias_v2"),
  requestLock("alias_creation"),
  async (c) => {
    const user = c.get("user");
    const db = c.env.DB;

    if (!(await canCreateNewAlias(db, c.env, user))) {
      return badRequest(c, freePlanLimitMsg(c.env));
    }

    const hostname = c.req.query("hostname");
    const data = await getJsonBody(c);
    if (isFalsyJson(data)) {
      return badRequest(c, "request body cannot be empty");
    }
    // Flask 500s (AttributeError) on a truthy non-dict body; the missing
    // fields produce the first field error instead here.
    const body =
      typeof data === "object" && data !== null && !Array.isArray(data)
        ? (data as Record<string, unknown>)
        : {};

    const prefixRaw = body.alias_prefix ?? "";
    if (typeof prefixRaw !== "string" || !prefixRaw) {
      return badRequest(c, "invalid value for alias_prefix");
    }
    let aliasPrefix = prefixRaw.trim().toLowerCase().replaceAll(" ", "");

    const suffixRaw = body.signed_suffix ?? "";
    if (typeof suffixRaw !== "string" || !suffixRaw) {
      return badRequest(c, "invalid value for signed_suffix");
    }
    const signedSuffix = suffixRaw.trim();

    const note = body.note ?? null;
    aliasPrefix = convertToId(aliasPrefix);

    const aliasSuffix = await timestampUnsign(
      customAliasSecret(c.env),
      signedSuffix,
      600,
    );
    if (!aliasSuffix) {
      return jsonError(c, 412, "Alias creation time is expired, please retry");
    }

    const customDomains = await verifiedCustomDomains(db, user.id);
    const slDomains = await getSLDomains(db, user, c.env);
    if (
      !verifyPrefixSuffix(
        c.env,
        aliasPrefix,
        aliasSuffix,
        slDomains,
        customDomains,
      )
    ) {
      return badRequest(c, "wrong alias prefix or suffix");
    }

    const fullAlias = aliasPrefix + aliasSuffix;
    if (await emailInAliasOrTrash(db, fullAlias)) {
      return jsonError(c, 409, `alias ${fullAlias} already exists`);
    }

    if (fullAlias.includes("..")) {
      return badRequest(
        c,
        "2 consecutive dot signs aren't allowed in an email address",
      );
    }

    let alias: AliasRow;
    try {
      alias = await insertAlias(db, c.env, user, {
        email: fullAlias,
        mailboxId: user.default_mailbox_id,
        note,
      });
    } catch (e) {
      if (e instanceof EmailNotValidError) {
        return badRequest(c, "Email is not valid");
      }
      if (e instanceof BucketRateLimitError) return rateLimited(c);
      throw e;
    }

    if (hostname) {
      await insertAliasUsedOn(db, alias.id, hostname, alias.user_id);
    }

    return serializedAliasResponse(c, alias, user);
  },
);

// --------------------------------------------------------------------------
// POST /v3/alias/custom/new
// --------------------------------------------------------------------------

aliasCreationRoutes.post(
  "/v3/alias/custom/new",
  requireApiAuth,
  aliasLimit("new_custom_alias_v3"),
  requestLock("alias_creation"),
  async (c) => {
    const user = c.get("user");
    const db = c.env.DB;

    if (!(await canCreateNewAlias(db, c.env, user))) {
      return badRequest(c, freePlanLimitMsg(c.env));
    }

    const hostname = c.req.query("hostname");
    const data = await getJsonBody(c);
    if (isFalsyJson(data)) {
      return badRequest(c, "request body cannot be empty");
    }
    if (typeof data !== "object" || data === null || Array.isArray(data)) {
      return badRequest(c, "request body does not follow the required format");
    }
    const body = data as Record<string, unknown>;

    // data.get("alias_prefix", "") or "" — any falsy value becomes ""
    const prefixRaw = isFalsyJson(body.alias_prefix ?? "")
      ? ""
      : body.alias_prefix;
    if (typeof prefixRaw !== "string") {
      return badRequest(c, "request body does not follow the required format");
    }
    let aliasPrefix = prefixRaw.trim().toLowerCase().replaceAll(" ", "");

    const suffixRaw = isFalsyJson(body.signed_suffix ?? "")
      ? ""
      : body.signed_suffix;
    if (typeof suffixRaw !== "string") {
      return badRequest(c, "request body does not follow the required format");
    }
    const signedSuffix = suffixRaw.trim();

    const mailboxIds = body.mailbox_ids;
    const note = body.note ?? null;
    // Flask 500s (AttributeError) on a truthy non-string name; treat as absent.
    let name: string | null = null;
    if (body.name && typeof body.name === "string") {
      name = body.name.replaceAll("\n", "");
    }
    aliasPrefix = convertToId(aliasPrefix);

    if (!checkAliasPrefix(aliasPrefix)) {
      return badRequest(c, "alias prefix invalid format or too long");
    }

    if (!Array.isArray(mailboxIds)) {
      return badRequest(c, "mailbox_ids must be an array of id");
    }
    const mailboxes: MailboxRow[] = [];
    for (const mailboxId of mailboxIds) {
      const mailbox =
        typeof mailboxId === "number"
          ? await getMailboxById(db, mailboxId)
          : null;
      if (!mailbox || mailbox.user_id !== user.id || !mailbox.verified) {
        return badRequest(c, "Errors with Mailbox");
      }
      mailboxes.push(mailbox);
    }
    if (mailboxes.length === 0) {
      return badRequest(c, "At least one mailbox must be selected");
    }

    const aliasSuffix = await timestampUnsign(
      customAliasSecret(c.env),
      signedSuffix,
      600,
    );
    if (!aliasSuffix) {
      return jsonError(c, 412, "Alias creation time is expired, please retry");
    }

    const customDomains = await verifiedCustomDomains(db, user.id);
    const slDomains = await getSLDomains(db, user, c.env);
    if (
      !verifyPrefixSuffix(
        c.env,
        aliasPrefix,
        aliasSuffix,
        slDomains,
        customDomains,
      )
    ) {
      return badRequest(c, "wrong alias prefix or suffix");
    }

    const fullAlias = aliasPrefix + aliasSuffix;
    if (await emailInAliasOrTrash(db, fullAlias)) {
      return jsonError(c, 409, `alias ${fullAlias} already exists`);
    }

    if (fullAlias.includes("..")) {
      return badRequest(
        c,
        "2 consecutive dot signs aren't allowed in an email address",
      );
    }

    try {
      validateEmailOrThrow(fullAlias);
    } catch (e) {
      if (e instanceof EmailNotValidError) {
        return badRequest(c, "Email alias is invalid");
      }
      throw e;
    }

    let alias: AliasRow;
    try {
      alias = await insertAlias(db, c.env, user, {
        email: fullAlias,
        mailboxId: mailboxes[0].id,
        note,
        name: name || null,
      });
    } catch (e) {
      if (e instanceof BucketRateLimitError) return rateLimited(c);
      throw e;
    }

    for (let i = 1; i < mailboxes.length; i++) {
      await db
        .prepare(
          "INSERT INTO alias_mailbox (alias_id, mailbox_id, created_at) VALUES (?1, ?2, ?3)",
        )
        .bind(alias.id, mailboxes[i].id, nowStr())
        .run();
    }

    if (hostname) {
      await insertAliasUsedOn(db, alias.id, hostname, alias.user_id);
    }

    return serializedAliasResponse(c, alias, user);
  },
);

// --------------------------------------------------------------------------
// POST /alias/random/new
// --------------------------------------------------------------------------

aliasCreationRoutes.post(
  "/alias/random/new",
  requireApiAuth,
  aliasLimit("new_random_alias"),
  requestLock("alias_creation"),
  async (c) => {
    const user = c.get("user");
    const db = c.env.DB;

    if (!(await canCreateNewAlias(db, c.env, user))) {
      return badRequest(c, freePlanLimitMsg(c.env));
    }

    // request.get_json(silent=True): malformed JSON is tolerated
    let note: unknown = null;
    let data: unknown = null;
    try {
      data = await getJsonBody(c);
    } catch {
      data = null;
    }
    if (
      data &&
      typeof data === "object" &&
      !Array.isArray(data) &&
      !isFalsyJson(data)
    ) {
      note = (data as Record<string, unknown>).note ?? null;
    }

    let alias: AliasRow | null = null;
    const hostname = c.req.query("hostname");

    try {
      if (hostname && user.include_website_in_one_click_alias) {
        const prefixSuggestion = convertToId(extractDomainLabel(hostname));
        const suffixes = await getAliasSuffixes(db, c.env, user);
        // Flask indexes suffixes[0] unguarded (IndexError -> 500 when a user
        // has no available domain at all); fall through to the random path.
        if (suffixes.length > 0) {
          const suggestedAlias = prefixSuggestion + suffixes[0].suffix;
          const existing = await db
            .prepare("SELECT * FROM alias WHERE email = ?1")
            .bind(suggestedAlias)
            .first<AliasRow>();

          if (existing && existing.user_id !== user.id) {
            alias = null; // belongs to another user
          } else if (existing) {
            // reuse only if it was created for this website
            const used = await db
              .prepare(
                "SELECT 1 FROM alias_used_on WHERE alias_id = ?1 AND hostname = ?2 AND user_id = ?3 LIMIT 1",
              )
              .bind(existing.id, hostname, existing.user_id)
              .first();
            alias = used ? existing : null;
          } else {
            try {
              alias = await insertAlias(db, c.env, user, {
                email: suggestedAlias,
                mailboxId: user.default_mailbox_id,
                note,
              });
            } catch (e) {
              if (e instanceof AliasInTrashError) alias = null;
              else throw e;
            }
          }
        }
      }

      if (!alias) {
        let scheme = user.alias_generator;
        const mode = c.req.query("mode");
        if (mode) {
          if (mode === "word") scheme = AliasGenerator.word;
          else if (mode === "uuid") scheme = AliasGenerator.uuid;
          else return badRequest(c, `${mode} must be either word or uuid`);
        }
        alias = await createNewRandom(db, c.env, user, scheme, note);
      }

      if (hostname) {
        const used = await db
          .prepare(
            "SELECT 1 FROM alias_used_on WHERE alias_id = ?1 AND hostname = ?2 LIMIT 1",
          )
          .bind(alias.id, hostname)
          .first();
        if (!used) {
          await insertAliasUsedOn(db, alias.id, hostname, alias.user_id);
        }
      }
    } catch (e) {
      if (e instanceof BucketRateLimitError) return rateLimited(c);
      throw e;
    }

    return serializedAliasResponse(c, alias, user);
  },
);
