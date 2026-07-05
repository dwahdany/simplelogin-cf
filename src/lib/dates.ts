/**
 * Date helpers replicating arrow 0.16 behavior from the Flask app.
 *
 * DB storage + API `*_date` fields: "YYYY-MM-DD HH:MM:SS+00:00" (UTC, second
 * precision, no T separator, no Z, no fractional seconds).
 * API `*_timestamp` fields: integer unix seconds.
 */

const pad = (n: number, w = 2) => String(n).padStart(w, "0");

/** Format a Date as the canonical DB/API string (UTC, second precision). */
export function toStr(d: Date): string {
  return (
    `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())}+00:00`
  );
}

/** Current time as the canonical string. */
export function nowStr(): string {
  return toStr(new Date());
}

/** Parse a canonical DB string (or ISO-8601) into a Date. */
export function toDate(s: string): Date {
  // "YYYY-MM-DD HH:MM:SS+00:00" is not ISO-8601 (space separator) — normalize.
  return new Date(s.includes("T") ? s : s.replace(" ", "T"));
}

/** Unix seconds for a canonical DB string (arrow `.timestamp`). */
export function toEpoch(s: string): number {
  return Math.floor(toDate(s).getTime() / 1000);
}

export function addSeconds(d: Date, secs: number): Date {
  return new Date(d.getTime() + secs * 1000);
}

export const addMinutes = (d: Date, m: number) => addSeconds(d, m * 60);
export const addHours = (d: Date, h: number) => addSeconds(d, h * 3600);
export const addDays = (d: Date, days: number) => addSeconds(d, days * 86400);

/**
 * arrow 0.16 `.humanize()` for past datetimes, "en" locale, granularity=auto.
 * Thresholds copied from arrow.Arrow.humanize source (verified empirically).
 */
export function humanize(dateStr: string, now: Date = new Date()): string {
  const then = toDate(dateStr);
  const delta = Math.round((now.getTime() - then.getTime()) / 1000);
  const diff = Math.abs(delta);
  const future = delta < 0;
  const phrase = (s: string) => (future ? `in ${s}` : `${s} ago`);

  if (diff < 10) return "just now";
  if (diff < 45) return phrase(`${diff} seconds`);
  if (diff < 90) return phrase("a minute");
  if (diff < 2700) return phrase(`${Math.trunc(Math.max(diff / 60, 2))} minutes`);
  if (diff < 5400) return phrase("an hour");
  if (diff < 79200) return phrase(`${Math.trunc(Math.max(diff / 3600, 2))} hours`);
  if (diff < 172800) return phrase("a day");
  if (diff < 554400) return phrase(`${Math.trunc(Math.max(diff / 86400, 2))} days`);
  if (diff < 907200) return phrase("a week");
  if (diff < 2419200) return phrase(`${Math.trunc(Math.max(diff / 604800, 2))} weeks`);
  if (diff < 3888000) return phrase("a month");
  if (diff < 29808000) {
    const selfMonths = then.getUTCFullYear() * 12 + then.getUTCMonth();
    const otherMonths = now.getUTCFullYear() * 12 + now.getUTCMonth();
    const months = Math.trunc(Math.max(Math.abs(otherMonths - selfMonths), 2));
    return phrase(`${months} months`);
  }
  if (diff < 47260800) return phrase("a year");
  return phrase(`${Math.trunc(Math.max(diff / 31536000, 2))} years`);
}
