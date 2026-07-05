/**
 * Alias & contact serializers ported from app/api/serializer.py + the relevant
 * Contact/EmailLog methods in app/models.py. See specs/02-aliases.md.
 *
 * Date fields: `creation_date` etc. are returned verbatim from the stored
 * column (already arrow's "YYYY-MM-DD HH:MM:SS+00:00"); `*_timestamp` are
 * integer unix seconds via toEpoch. Booleans are emitted as JSON true/false.
 */

import { toDate, toEpoch } from "./dates";
import { getContactById, getMailboxById } from "./models";
import type {
  AliasRow,
  ContactRow,
  EmailLogRow,
  MailboxRow,
  UserRow,
} from "./rows";

const PAGE_LIMIT = 20; // config.PAGE_LIMIT

// SenderFormatEnum values (models.py L209): AT=0, A=2, NAME_ONLY=5, AT_ONLY=6, NO_NAME=7
const SENDER_FORMAT_VALUES = new Set([0, 2, 5, 6, 7]);

interface MailboxLite {
  id: number;
  email: string;
}

/** Mirror of app.api.serializer.AliasInfo (the fields the serializers read). */
export interface AliasInfo {
  alias: AliasRow;
  /** primary mailbox = alias.mailbox */
  mailbox: MailboxLite;
  mailboxes: MailboxLite[];
  nb_forward: number;
  nb_blocked: number;
  nb_reply: number;
  /** Alias.mailbox_support_pgp() — computed over verified mailboxes. */
  supportPgp: boolean;
  latestEmailLog: EmailLogRow | null;
  latestContact: ContactRow | null;
  /** owner user's sender_format, for the reverse_alias display string. */
  senderFormat: number;
}

/** EmailLog.get_action(): reply | bounced | block | forward (models.py L2333). */
export function emailLogAction(
  log: EmailLogRow,
): "reply" | "bounced" | "block" | "forward" {
  if (log.is_reply) return "reply";
  if (log.bounced) return "bounced";
  if (log.blocked) return "block";
  return "forward";
}

/**
 * Best-effort flanker `address.parse(...).display_name`: pull the display name
 * out of a "Name <email>" header, stripping surrounding quotes. Bare addresses
 * (and unparseable input) yield "".
 */
function parseDisplayName(raw: string): string {
  const m = raw.match(/^\s*(.*?)\s*<[^>]*>\s*$/);
  if (!m) return "";
  let name = m[1].trim();
  if (name.length >= 2 && name.startsWith('"') && name.endsWith('"')) {
    name = name.slice(1, -1);
  }
  return name;
}

/**
 * Contact.website_send_to() (models.py L2161) — the "reverse_alias" display
 * string `"{name} | {email}" <reply_email>` where the email's "@" is rewritten
 * per the owner's sender_format. When senderFormat is null/unknown/AT the "@"
 * becomes " at "; A(2) uses "(a)"; 5/6/7 leave the address untouched.
 */
export function reverseAliasDisplay(
  contact: ContactRow,
  senderFormat: number | null,
): string {
  let email = contact.website_email;
  const known = senderFormat !== null && SENDER_FORMAT_VALUES.has(senderFormat);
  if (senderFormat === null || !known || senderFormat === 0) {
    email = email.replaceAll("@", " at ");
  } else if (senderFormat === 2) {
    email = email.replaceAll("@", "(a)");
  }

  let name = contact.name;
  if (!name && contact.website_from)
    name = parseDisplayName(contact.website_from);
  if (name) name = name.replaceAll('"', "");

  const display = name ? `${name} | ${email}` : email;
  return `"${display}" <${contact.reply_email}>`;
}

/** serialize_alias_info (v1) — note the key is `nb_block`, not `nb_blocked`. */
export function serializeAliasInfo(info: AliasInfo): Record<string, unknown> {
  return {
    id: info.alias.id,
    email: info.alias.email,
    creation_date: info.alias.created_at,
    creation_timestamp: toEpoch(info.alias.created_at),
    enabled: !!info.alias.enabled,
    note: info.alias.note,
    nb_forward: info.nb_forward,
    nb_block: info.nb_blocked,
    nb_reply: info.nb_reply,
  };
}

/** serialize_alias_info_v2. */
export function serializeAliasInfoV2(info: AliasInfo): Record<string, unknown> {
  const res: Record<string, unknown> = {
    id: info.alias.id,
    email: info.alias.email,
    creation_date: info.alias.created_at,
    creation_timestamp: toEpoch(info.alias.created_at),
    enabled: !!info.alias.enabled,
    note: info.alias.note,
    name: info.alias.name,
    nb_forward: info.nb_forward,
    nb_block: info.nb_blocked,
    nb_reply: info.nb_reply,
    mailbox: { id: info.mailbox.id, email: info.mailbox.email },
    mailboxes: info.mailboxes.map((m) => ({ id: m.id, email: m.email })),
    support_pgp: info.supportPgp,
    disable_pgp: !!info.alias.disable_pgp,
    latest_activity: null,
    pinned: !!info.alias.pinned,
  };

  if (info.latestEmailLog && info.latestContact) {
    const log = info.latestEmailLog;
    const contact = info.latestContact;
    res.latest_activity = {
      timestamp: toEpoch(log.created_at),
      action: emailLogAction(log),
      contact: {
        email: contact.website_email,
        name: contact.name,
        reverse_alias: reverseAliasDisplay(contact, info.senderFormat),
      },
    };
  }
  return res;
}

/**
 * serialize_contact (specs/02 §11). `lastReply` is Contact.last_reply() — the
 * caller passes it (the serializer is otherwise pure); when omitted the
 * last_email_sent_* fields stay null.
 */
export function serializeContact(
  contact: ContactRow,
  existed = false,
  user?: UserRow,
  lastReply?: EmailLogRow | null,
): Record<string, unknown> {
  const res: Record<string, unknown> = {
    id: contact.id,
    creation_date: contact.created_at,
    creation_timestamp: toEpoch(contact.created_at),
    last_email_sent_date: null,
    last_email_sent_timestamp: null,
    contact: contact.website_email,
    reverse_alias: reverseAliasDisplay(contact, user?.sender_format ?? null),
    reverse_alias_address: contact.reply_email,
    existed,
    block_forward: !!contact.block_forward,
  };
  if (lastReply) {
    res.last_email_sent_date = lastReply.created_at;
    res.last_email_sent_timestamp = toEpoch(lastReply.created_at);
  }
  return res;
}

async function fetchMailboxMap(
  db: D1Database,
  ids: number[],
): Promise<Map<number, MailboxRow>> {
  const map = new Map<number, MailboxRow>();
  if (ids.length === 0) return map;
  const placeholders = ids.map((_, i) => `?${i + 1}`).join(", ");
  const res = await db
    .prepare(`SELECT * FROM mailbox WHERE id IN (${placeholders})`)
    .bind(...ids)
    .all<MailboxRow>();
  for (const m of res.results) map.set(m.id, m);
  return map;
}

/**
 * get_alias_info_v2 (specs/02 §3): counts iterate ALL (contact, email_log) for
 * the alias; latest activity is the log with created_at *strictly greater* than
 * alias.created_at. Mailboxes are set-based and *include unverified* secondary
 * mailboxes (unlike the list endpoints); support_pgp is still computed over the
 * verified mailboxes only.
 */
export async function getAliasInfoV2(
  db: D1Database,
  alias: AliasRow,
  user: UserRow,
): Promise<AliasInfo> {
  const primary = await getMailboxById(db, alias.mailbox_id);

  const amRows = await db
    .prepare(
      "SELECT mailbox_id FROM alias_mailbox WHERE alias_id = ?1 ORDER BY id",
    )
    .bind(alias.id)
    .all<{ mailbox_id: number }>();
  const ids = [alias.mailbox_id];
  for (const r of amRows.results)
    if (!ids.includes(r.mailbox_id)) ids.push(r.mailbox_id);

  const mbMap = await fetchMailboxMap(db, ids);
  const mailboxes: MailboxLite[] = ids
    .map((id) => mbMap.get(id))
    .filter((m): m is MailboxRow => !!m)
    .map((m) => ({ id: m.id, email: m.email }));
  const supportPgp = ids.some((id) => {
    const m = mbMap.get(id);
    return !!m && !!m.verified && !!m.pgp_finger_print && !m.disable_pgp;
  });

  const logs = await db
    .prepare(
      `SELECT el.* FROM email_log el JOIN contact c ON el.contact_id = c.id
       WHERE c.alias_id = ?1 ORDER BY el.created_at, el.id`,
    )
    .bind(alias.id)
    .all<EmailLogRow>();

  let nbReply = 0;
  let nbBlocked = 0;
  let nbForward = 0;
  let latestEmailLog: EmailLogRow | null = null;
  let latestActivity = toDate(alias.created_at).getTime();
  for (const el of logs.results) {
    if (el.is_reply) nbReply++;
    else if (el.blocked) nbBlocked++;
    else nbForward++;

    const t = toDate(el.created_at).getTime();
    if (t > latestActivity) {
      latestActivity = t;
      latestEmailLog = el;
    }
  }

  const latestContact = latestEmailLog
    ? await getContactById(db, latestEmailLog.contact_id)
    : null;

  return {
    alias,
    mailbox: primary
      ? { id: primary.id, email: primary.email }
      : { id: alias.mailbox_id, email: "" },
    mailboxes,
    nb_forward: nbForward,
    nb_blocked: nbBlocked,
    nb_reply: nbReply,
    supportPgp,
    latestEmailLog,
    latestContact,
    senderFormat: user.sender_format,
  };
}

// ---------------------------------------------------------------------------
// v3 list search filter — Postgres semantics reproduced in JS
// (app/api/serializer.py L153-163). D1/SQLite has neither ILIKE (its LIKE is
// ASCII-only case-insensitive) nor ts_vector/plainto_tsquery, so the filter
// runs in JS over the SQL-ordered rows before pagination.
// ---------------------------------------------------------------------------

/**
 * Postgres `col ILIKE '%' || query || '%'` as a RegExp: full-Unicode
 * case-insensitive containment where % and _ inside the query stay wildcards
 * and backslash escapes the following character (LIKE's default escape).
 */
export function ilikeToRegExp(query: string): RegExp {
  const escapeChar = (ch: string) => ch.replace(/[.*+?^${}()|[\]\\]/, "\\$&");
  let pattern = "";
  for (let i = 0; i < query.length; i++) {
    const ch = query[i];
    if (ch === "\\" && i + 1 < query.length) {
      i += 1;
      pattern += escapeChar(query[i]);
    } else if (ch === "%") pattern += "[\\s\\S]*";
    else if (ch === "_") pattern += "[\\s\\S]";
    else pattern += escapeChar(ch);
  }
  return new RegExp(pattern, "iu");
}

/** Postgres english.stop — tokens dropped by the 'english' text-search config. */
const FT_STOPWORDS = new Set(
  (
    "i me my myself we our ours ourselves you your yours yourself yourselves " +
    "he him his himself she her hers herself it its itself they them their " +
    "theirs themselves what which who whom this that these those am is are " +
    "was were be been being have has had having do does did doing a an the " +
    "and but if or because as until while of at by for with about against " +
    "between into through during before after above below to from up down " +
    "in out on off over under again further then once here there when where " +
    "why how all any both each few more most other some such no nor not " +
    "only own same so than too very s t can will just don should now"
  ).split(" "),
);

const FT_VOWELS = "aeiouy";
const FT_DOUBLES = new Set([
  "bb",
  "dd",
  "ff",
  "gg",
  "mm",
  "nn",
  "pp",
  "rr",
  "tt",
]);
const FT_LI_ENDING = "cdeghkmnrt";

// snowball english exceptional forms
const FT_EXCEPTIONS1 = new Map<string, string>([
  ["skis", "ski"],
  ["skies", "sky"],
  ["dying", "die"],
  ["lying", "lie"],
  ["tying", "tie"],
  ["idly", "idl"],
  ["gently", "gentl"],
  ["ugly", "ugli"],
  ["early", "earli"],
  ["only", "onli"],
  ["singly", "singl"],
  ["sky", "sky"],
  ["news", "news"],
  ["howe", "howe"],
  ["atlas", "atlas"],
  ["cosmos", "cosmos"],
  ["bias", "bias"],
  ["andes", "andes"],
]);
const FT_EXCEPTIONS2 = new Set([
  "inning",
  "outing",
  "canning",
  "herring",
  "earring",
  "proceed",
  "exceed",
  "succeed",
]);

const ftIsVowel = (ch: string | undefined): boolean =>
  ch !== undefined && FT_VOWELS.includes(ch);

function ftHasVowel(s: string): boolean {
  for (const ch of s) if (ftIsVowel(ch)) return true;
  return false;
}

/** Snowball "short syllable": non-vowel + vowel + non-vowel(≠ w/x/Y), or a
 * vowel at the start of the word followed by a non-vowel. */
function endsInShortSyllable(w: string): boolean {
  const n = w.length;
  if (n === 2) return ftIsVowel(w[0]) && !ftIsVowel(w[1]);
  if (n < 3) return false;
  const c = w[n - 1];
  return (
    !ftIsVowel(w[n - 3]) &&
    ftIsVowel(w[n - 2]) &&
    !ftIsVowel(c) &&
    c !== "w" &&
    c !== "x" &&
    c !== "Y"
  );
}

/**
 * The Snowball English ("Porter2") stemmer — what Postgres' 'english'
 * text-search dictionary applies to every non-stopword token. Input must be
 * lowercase.
 */
export function englishStem(word: string): string {
  if (word.length <= 2) return word;
  let w = word;
  if (w.startsWith("'")) w = w.slice(1);

  const exception = FT_EXCEPTIONS1.get(w);
  if (exception !== undefined) return exception;

  // mark consonant y's as "Y" (initial y, or y after a vowel)
  const chars = [...w];
  if (chars[0] === "y") chars[0] = "Y";
  for (let i = 1; i < chars.length; i++) {
    if (chars[i] === "y" && FT_VOWELS.includes(chars[i - 1])) chars[i] = "Y";
  }
  w = chars.join("");

  // R1/R2 as absolute offsets — suffix operations never move them
  let r1 = w.length;
  const exceptionalPrefix = ["gener", "commun", "arsen"].find((p) =>
    w.startsWith(p),
  );
  if (exceptionalPrefix) {
    r1 = exceptionalPrefix.length;
  } else {
    for (let i = 1; i < w.length; i++) {
      if (!ftIsVowel(w[i]) && ftIsVowel(w[i - 1])) {
        r1 = i + 1;
        break;
      }
    }
  }
  let r2 = w.length;
  for (let i = r1 + 1; i < w.length; i++) {
    if (!ftIsVowel(w[i]) && ftIsVowel(w[i - 1])) {
      r2 = i + 1;
      break;
    }
  }
  const inR1 = (suffix: string) => w.length - suffix.length >= r1;
  const inR2 = (suffix: string) => w.length - suffix.length >= r2;

  // step 0: apostrophe suffixes
  for (const suf of ["'s'", "'s", "'"]) {
    if (w.endsWith(suf)) {
      w = w.slice(0, -suf.length);
      break;
    }
  }

  // step 1a
  if (w.endsWith("sses")) {
    w = w.slice(0, -2);
  } else if (w.endsWith("ied") || w.endsWith("ies")) {
    w = w.length - 3 > 1 ? w.slice(0, -2) : w.slice(0, -1);
  } else if (w.endsWith("us") || w.endsWith("ss")) {
    // no-op
  } else if (w.endsWith("s")) {
    if (ftHasVowel(w.slice(0, -2))) w = w.slice(0, -1);
  }

  if (FT_EXCEPTIONS2.has(w)) return w;

  // step 1b
  {
    const suf = ["eedly", "ingly", "edly", "eed", "ing", "ed"].find((sfx) =>
      w.endsWith(sfx),
    );
    if (suf === "eed" || suf === "eedly") {
      if (inR1(suf)) w = `${w.slice(0, -suf.length)}ee`;
    } else if (suf) {
      const stem = w.slice(0, -suf.length);
      if (ftHasVowel(stem)) {
        w = stem;
        if (w.endsWith("at") || w.endsWith("bl") || w.endsWith("iz")) w += "e";
        else if (FT_DOUBLES.has(w.slice(-2))) w = w.slice(0, -1);
        else if (r1 >= w.length && endsInShortSyllable(w)) w += "e";
      }
    }
  }

  // step 1c: y -> i after a non-vowel that is not the first letter
  if (w.length > 2) {
    const last = w[w.length - 1];
    if ((last === "y" || last === "Y") && !ftIsVowel(w[w.length - 2])) {
      w = `${w.slice(0, -1)}i`;
    }
  }

  // step 2 (longest suffix, applied only when it lies in R1)
  {
    const map: [string, string][] = [
      ["ational", "ate"],
      ["fulness", "ful"],
      ["iveness", "ive"],
      ["ization", "ize"],
      ["ousness", "ous"],
      ["biliti", "ble"],
      ["lessli", "less"],
      ["tional", "tion"],
      ["alism", "al"],
      ["aliti", "al"],
      ["ation", "ate"],
      ["entli", "ent"],
      ["fulli", "ful"],
      ["iviti", "ive"],
      ["ousli", "ous"],
      ["anci", "ance"],
      ["abli", "able"],
      ["alli", "al"],
      ["ator", "ate"],
      ["enci", "ence"],
      ["izer", "ize"],
      ["bli", "ble"],
      ["ogi", "og"],
      ["li", ""],
    ];
    for (const [suf, rep] of map) {
      if (!w.endsWith(suf)) continue;
      if (inR1(suf)) {
        if (suf === "ogi") {
          if (w[w.length - 4] === "l") w = w.slice(0, -1);
        } else if (suf === "li") {
          if (FT_LI_ENDING.includes(w[w.length - 3] ?? "")) w = w.slice(0, -2);
        } else {
          w = w.slice(0, -suf.length) + rep;
        }
      }
      break;
    }
  }

  // step 3 (in R1; "ative" additionally requires R2)
  {
    const map: [string, string][] = [
      ["ational", "ate"],
      ["tional", "tion"],
      ["alize", "al"],
      ["icate", "ic"],
      ["iciti", "ic"],
      ["ative", ""],
      ["ical", "ic"],
      ["ness", ""],
      ["ful", ""],
    ];
    for (const [suf, rep] of map) {
      if (!w.endsWith(suf)) continue;
      if (inR1(suf)) {
        if (suf === "ative") {
          if (inR2(suf)) w = w.slice(0, -5);
        } else {
          w = w.slice(0, -suf.length) + rep;
        }
      }
      break;
    }
  }

  // step 4 (in R2; "ion" only after s/t)
  {
    const sufs = [
      "ement",
      "ance",
      "ence",
      "able",
      "ible",
      "ment",
      "ant",
      "ent",
      "ism",
      "ate",
      "iti",
      "ous",
      "ive",
      "ize",
      "ion",
      "al",
      "er",
      "ic",
    ];
    for (const suf of sufs) {
      if (!w.endsWith(suf)) continue;
      if (inR2(suf)) {
        if (suf === "ion") {
          const prev = w[w.length - 4];
          if (prev === "s" || prev === "t") w = w.slice(0, -3);
        } else {
          w = w.slice(0, -suf.length);
        }
      }
      break;
    }
  }

  // step 5
  if (w.endsWith("e")) {
    if (inR2("e") || (inR1("e") && !endsInShortSyllable(w.slice(0, -1)))) {
      w = w.slice(0, -1);
    }
  } else if (w.endsWith("l")) {
    if (inR2("l") && w[w.length - 2] === "l") w = w.slice(0, -1);
  }

  return w.replaceAll("Y", "y");
}

/** Approximate the Postgres default parser: word tokens are letter/digit
 * runs; hyphenated compounds also emit the whole compound (hword). */
function ftTokenize(text: string): string[] {
  const tokens: string[] = [];
  for (const m of text.matchAll(/[\p{L}\p{N}]+(?:-[\p{L}\p{N}]+)*/gu)) {
    const whole = m[0];
    if (whole.includes("-")) {
      tokens.push(whole);
      for (const part of whole.split("-")) tokens.push(part);
    } else {
      tokens.push(whole);
    }
  }
  return tokens;
}

/** to_tsvector('english', text) lexemes: lowercase, drop stopwords, stem. */
function ftLexemes(text: string): string[] {
  const out: string[] = [];
  for (const token of ftTokenize(text)) {
    const lower = token.toLowerCase();
    if (FT_STOPWORDS.has(lower)) continue;
    out.push(englishStem(lower));
  }
  return out;
}

/**
 * `Alias.ts_vector @@ plainto_tsquery('english', query)` where ts_vector is
 * the generated column to_tsvector('english', note): every query lexeme must
 * appear among the note's lexemes (plainto AND-joins them). An empty tsquery
 * (all stopwords) matches nothing, and a NULL note never matches.
 */
export function tsVectorMatches(note: string | null, query: string): boolean {
  if (note === null) return false;
  const queryLexemes = ftLexemes(query);
  if (queryLexemes.length === 0) return false;
  const noteLexemes = new Set(ftLexemes(note));
  return queryLexemes.every((lex) => noteLexemes.has(lex));
}

export interface AliasListOptions {
  query?: string | null;
  /** presence-based filters, precedence pinned > disabled > enabled */
  pinned?: boolean;
  disabled?: boolean;
  enabled?: boolean;
}

/**
 * get_alias_infos_with_pagination_v3 (specs/02 §2) translated to SQLite.
 *
 * Counts come from an activity subquery joined on alias.id = email_log.alias_id.
 * Latest activity comes from the alias.last_email_log_id join (NOT a MAX()).
 * Default sort: pinned DESC, then MAX(created_at, latest-log created_at) DESC
 * (SQLite MAX(a,b) returns NULL if either arg is NULL, so IFNULL emulates
 * Postgres GREATEST's NULL-skipping), with id DESC as a deterministic tiebreak
 * (spec 06 recommends an id tiebreak given second-precision timestamps).
 *
 * The `query` filter (email/note/name ILIKE + ts_vector full-text over note)
 * has no SQLite equivalent, so when a query is present ALL rows are fetched
 * in SQL order and the filter + LIMIT/OFFSET are applied in JS.
 */
export async function getAliasInfosWithPaginationV3(
  db: D1Database,
  user: UserRow,
  pageId: number,
  opts: AliasListOptions = {},
): Promise<AliasInfo[]> {
  const query = opts.query || null; // Flask `if query:` — falsy = no filter
  const conds: string[] = [];

  if (opts.pinned) conds.push("a.pinned = 1");
  else if (opts.disabled) conds.push("a.enabled = 0");
  else if (opts.enabled) conds.push("a.enabled = 1");

  const whereExtra = conds.length ? ` AND ${conds.join(" AND ")}` : "";

  const sql = `
    SELECT a.*,
           sub.nb_reply AS _nb_reply,
           sub.nb_blocked AS _nb_blocked,
           sub.nb_forward AS _nb_forward
    FROM alias a
    JOIN (
      SELECT alias.id AS aid,
        SUM(CASE WHEN email_log.is_reply = 1 THEN 1 ELSE 0 END) AS nb_reply,
        SUM(CASE WHEN email_log.is_reply = 0 AND email_log.blocked = 1 THEN 1 ELSE 0 END) AS nb_blocked,
        SUM(CASE WHEN email_log.is_reply = 0 AND email_log.blocked = 0 THEN 1 ELSE 0 END) AS nb_forward
      FROM alias LEFT OUTER JOIN email_log ON alias.id = email_log.alias_id
      WHERE alias.user_id = ? AND alias.delete_on IS NULL
      GROUP BY alias.id
    ) sub ON a.id = sub.aid
    LEFT OUTER JOIN email_log el ON a.last_email_log_id = el.id
    WHERE 1 = 1${whereExtra}
    ORDER BY a.pinned DESC,
             MAX(a.created_at, IFNULL(el.created_at, a.created_at)) DESC,
             a.id DESC${query ? "" : "\n    LIMIT ? OFFSET ?"}`;

  const bind = query ? [user.id] : [user.id, PAGE_LIMIT, pageId * PAGE_LIMIT];
  const rows = await db
    .prepare(sql)
    .bind(...bind)
    .all<
      AliasRow & { _nb_reply: number; _nb_blocked: number; _nb_forward: number }
    >();

  let pageRows = rows.results;
  if (query) {
    // app/api/serializer.py L154-162: email ILIKE OR note ILIKE OR
    // ts_vector @@ plainto_tsquery('english', query) OR name ILIKE
    const re = ilikeToRegExp(query);
    pageRows = pageRows.filter(
      (r) =>
        re.test(r.email) ||
        (r.note !== null && re.test(r.note)) ||
        tsVectorMatches(r.note, query) ||
        (r.name !== null && re.test(r.name)),
    );
    const start = pageId * PAGE_LIMIT;
    pageRows = pageRows.slice(start, start + PAGE_LIMIT);
  }

  if (pageRows.length === 0) return [];

  // Batch-load the latest email_log + contact for the page.
  const logIds = [
    ...new Set(
      pageRows
        .map((r) => r.last_email_log_id)
        .filter((v): v is number => v !== null),
    ),
  ];
  const logMap = new Map<number, EmailLogRow>();
  if (logIds.length > 0) {
    const ph = logIds.map((_, i) => `?${i + 1}`).join(", ");
    const res = await db
      .prepare(`SELECT * FROM email_log WHERE id IN (${ph})`)
      .bind(...logIds)
      .all<EmailLogRow>();
    for (const l of res.results) logMap.set(l.id, l);
  }
  const contactIds = [
    ...new Set([...logMap.values()].map((l) => l.contact_id)),
  ];
  const contactMap = new Map<number, ContactRow>();
  if (contactIds.length > 0) {
    const ph = contactIds.map((_, i) => `?${i + 1}`).join(", ");
    const res = await db
      .prepare(`SELECT * FROM contact WHERE id IN (${ph})`)
      .bind(...contactIds)
      .all<ContactRow>();
    for (const c of res.results) contactMap.set(c.id, c);
  }

  // Batch-load mailboxes (primary + additional) for the page.
  const aliasIds = pageRows.map((r) => r.id);
  const amPh = aliasIds.map((_, i) => `?${i + 1}`).join(", ");
  const amRes = await db
    .prepare(
      `SELECT alias_id, mailbox_id FROM alias_mailbox WHERE alias_id IN (${amPh}) ORDER BY id`,
    )
    .bind(...aliasIds)
    .all<{ alias_id: number; mailbox_id: number }>();
  const additionalByAlias = new Map<number, number[]>();
  for (const r of amRes.results) {
    const list = additionalByAlias.get(r.alias_id) ?? [];
    list.push(r.mailbox_id);
    additionalByAlias.set(r.alias_id, list);
  }
  const allMailboxIds = new Set<number>();
  for (const r of pageRows) allMailboxIds.add(r.mailbox_id);
  for (const list of additionalByAlias.values())
    for (const id of list) allMailboxIds.add(id);
  const mbMap = await fetchMailboxMap(db, [...allMailboxIds]);

  return pageRows.map((row) => {
    const { _nb_reply, _nb_blocked, _nb_forward, ...aliasCols } = row;
    const alias = aliasCols as AliasRow;

    // Alias.mailboxes property: [primary] + additional, deduped, verified-only, email-sorted.
    const ids = [alias.mailbox_id];
    for (const id of additionalByAlias.get(alias.id) ?? [])
      if (!ids.includes(id)) ids.push(id);
    const verified = ids
      .map((id) => mbMap.get(id))
      .filter((m): m is MailboxRow => !!m && !!m.verified)
      .sort((a, b) => (a.email < b.email ? -1 : a.email > b.email ? 1 : 0));
    const mailboxes: MailboxLite[] = verified.map((m) => ({
      id: m.id,
      email: m.email,
    }));
    const supportPgp = verified.some(
      (m) => !!m.pgp_finger_print && !m.disable_pgp,
    );

    const primary = mbMap.get(alias.mailbox_id);
    const latestEmailLog = alias.last_email_log_id
      ? (logMap.get(alias.last_email_log_id) ?? null)
      : null;
    const latestContact = latestEmailLog
      ? (contactMap.get(latestEmailLog.contact_id) ?? null)
      : null;

    return {
      alias,
      mailbox: primary
        ? { id: primary.id, email: primary.email }
        : { id: alias.mailbox_id, email: "" },
      mailboxes,
      nb_forward: _nb_forward,
      nb_blocked: _nb_blocked,
      nb_reply: _nb_reply,
      supportPgp,
      latestEmailLog,
      latestContact,
      senderFormat: user.sender_format,
    };
  });
}
