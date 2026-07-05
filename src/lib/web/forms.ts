/**
 * Flask-WTF equivalent for the web port (specs/web/00-web-infra.md §9):
 * - per-session CSRF secret (SessionData.csrf), hidden-field token signed
 *   with FLASK_SECRET, 1 h expiry, exact flask-wtf error strings;
 * - field objects renderable by the _formhelpers.html macros: label,
 *   description, errors, and a render(attrs) function (wtforms' field(**kwargs)).
 *
 * CSRF failure semantics match Flask: validation just fails and the view
 * re-renders with 200 — no 400 page.
 */

import type { Context } from "hono";
import { timestampSign, timestampUnsign } from "../crypto";
import type { Env } from "../env";
import { getSession, type SessionData, saveSession } from "../session";
import { markSafe, type SafeStringLike } from "./templates";

const CSRF_SALT = "wtf-csrf-token";
const CSRF_TIME_LIMIT_SECS = 3600;

export const CSRF_ERRORS = {
  missing: "The CSRF token is missing.",
  sessionMissing: "The CSRF session token is missing.",
  expired: "The CSRF token has expired.",
  invalid: "The CSRF token is invalid.",
  mismatch: "The CSRF tokens do not match.",
} as const;

function randomHex40(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Get-or-create the session CSRF secret and return a signed hidden-field
 * token. Creates an anonymous session when none exists (like Flask writing
 * `session["csrf_token"]` from a pre-login form render).
 */
export async function generateCsrfToken<E extends { Bindings: Env }>(
  c: Context<E>,
  session?: SessionData | null,
): Promise<string> {
  let sess = session ?? (await getSession(c));
  if (!sess) sess = {};
  if (!sess.csrf) {
    sess.csrf = randomHex40();
    await saveSession(c, sess);
  }
  return timestampSign(`${c.env.FLASK_SECRET}${CSRF_SALT}`, sess.csrf);
}

/** Validate a submitted csrf_token field. Returns null when OK, else the exact flask-wtf error string. */
export async function validateCsrfToken<E extends { Bindings: Env }>(
  c: Context<E>,
  token: string | undefined | null,
  session?: SessionData | null,
): Promise<string | null> {
  if (!token) return CSRF_ERRORS.missing;
  const sess = session ?? (await getSession(c));
  if (!sess?.csrf) return CSRF_ERRORS.sessionMissing;
  const value = await timestampUnsign(
    `${c.env.FLASK_SECRET}${CSRF_SALT}`,
    token,
    CSRF_TIME_LIMIT_SECS,
  );
  if (value === null) {
    // Distinguish expired from tampered like flask-wtf does.
    const noAgeCheck = await timestampUnsign(
      `${c.env.FLASK_SECRET}${CSRF_SALT}`,
      token,
      Number.MAX_SAFE_INTEGER,
    );
    return noAgeCheck === null ? CSRF_ERRORS.invalid : CSRF_ERRORS.expired;
  }
  if (value !== sess.csrf) return CSRF_ERRORS.mismatch;
  return null;
}

// ---------------------------------------------------------------------------
// Field objects for the _formhelpers macros / page templates
// ---------------------------------------------------------------------------

const escapeHtml = (s: string) =>
  s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");

export interface FieldSpec {
  name: string;
  /** input type: text|password|email|hidden|checkbox|textarea|select */
  type?: string;
  label?: string;
  description?: string;
  value?: string;
  checked?: boolean;
  options?: Array<{ value: string; label: string; selected?: boolean }>;
}

/**
 * A wtforms-like field object. NOT callable: nunjucks' memberLookup wraps
 * function-valued members in a fresh binder that loses attached properties,
 * so `{{ form.email(...) }}` call sites are codemodded to
 * `{{ form.email.render(...) }}` (identical HTML output).
 */
export interface FormField {
  name: string;
  id: string;
  label: { text: string; html: SafeStringLike };
  description: string;
  errors: string[];
  data: string;
  render: (attrs?: Record<string, unknown>) => SafeStringLike;
}

/** Build a renderable field object (wtforms-widget-compatible markup). */
export function makeField(spec: FieldSpec, errors: string[] = []): FormField {
  const id = spec.name;
  const render = (attrs: Record<string, unknown> = {}): SafeStringLike => {
    const merged: Record<string, string> = { id, name: spec.name };
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "__keywords") continue; // nunjucks kwargs marker
      if (v === undefined || v === null || v === false) continue;
      merged[k === "class_" ? "class" : k] = v === true ? k : String(v);
    }
    const attrStr = (extra: Record<string, string>) =>
      Object.entries({ ...merged, ...extra })
        .map(([k, v]) => `${escapeHtml(k)}="${escapeHtml(v)}"`)
        .join(" ");

    if (spec.type === "textarea") {
      return markSafe(
        `<textarea ${attrStr({})}>${escapeHtml(spec.value ?? "")}</textarea>`,
      );
    }
    if (spec.type === "select") {
      const opts = (spec.options ?? [])
        .map(
          (o) =>
            `<option value="${escapeHtml(o.value)}"${o.selected ? " selected" : ""}>${escapeHtml(o.label)}</option>`,
        )
        .join("");
      return markSafe(`<select ${attrStr({})}>${opts}</select>`);
    }
    const type = spec.type ?? "text";
    const extra: Record<string, string> = { type };
    if (spec.value !== undefined) extra.value = spec.value;
    if (spec.type === "checkbox" && spec.checked) extra.checked = "checked";
    return markSafe(`<input ${attrStr(extra)}>`);
  };

  const labelText = spec.label ?? "";
  return {
    name: spec.name,
    id,
    label: {
      text: labelText,
      html: markSafe(
        `<label for="${escapeHtml(id)}">${escapeHtml(labelText)}</label>`,
      ),
    },
    description: spec.description ?? "",
    errors,
    data: spec.value ?? "",
    render: (attrs?: Record<string, unknown>) => render(attrs ?? {}),
  };
}

/** The `{{ form.csrf_token }}` hidden input (never rendered via hidden_tag()). */
export function csrfTokenField(token: string): SafeStringLike {
  return markSafe(
    `<input id="csrf_token" name="csrf_token" type="hidden" value="${escapeHtml(token)}">`,
  );
}
