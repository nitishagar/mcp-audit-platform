/**
 * Single redaction layer (I4). Every emitter and the error formatter route
 * through here. Findings reference secret LOCATIONS, never values.
 */

/** Config key names whose values are always secrets (matched case-insensitively). */
export const KEY_DENYLIST = [
  "api_key",
  "apikey",
  "token",
  "secret",
  "password",
  "passwd",
  "auth",
  "bearer",
  "webhook",
  "private_key",
  "client_secret",
  "access_key",
] as const;

/** Value-shape patterns for secrets stored under non-denylisted keys. */
export const VALUE_PATTERNS: { name: string; re: RegExp }[] = [
  { name: "pattern", re: /sk-[A-Za-z0-9-]{8,}/g },
  { name: "pattern", re: /gh[pousr]_[A-Za-z0-9]{8,}/g },
  { name: "pattern", re: /xox[baprs]-[A-Za-z0-9-]{8,}/g },
  { name: "pattern", re: /https:\/\/hooks\.slack\.com\/\S+/g },
  { name: "pattern", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
  { name: "pattern", re: /AKIA[0-9A-Z]{16}/g },
];

const DENY = new Set<string>(KEY_DENYLIST.map((k) => k.toLowerCase()));

export function isDenylistedKey(key: string): boolean {
  // Segment-aware match: the whole normalized key or any segment must EQUAL a
  // denylisted term. Substring matching is banned — it flags `author` via `auth`.
  const normalized = key.toLowerCase().replace(/[_-]+/g, "");
  if (DENY.has(normalized)) return true;
  // Split on _/-/whitespace AND camel boundaries; every segment must equal a term.
  const segments = key
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .split(/[\s_-]+/)
    .map((s) => s.toLowerCase());
  return segments.some((s) => DENY.has(s));
}

/** Redact secret-shaped substrings inside a free-text string. */
export function redactString(s: string): string {
  let out = s;
  for (const { re } of VALUE_PATTERNS) {
    re.lastIndex = 0;
    out = out.replace(re, "[REDACTED:pattern]");
  }
  return out;
}

/**
 * Redact a config value in the context of its key. Returns the redacted value:
 * denylisted keys are replaced wholesale (with the key name kept as location),
 * other strings are pattern-scrubbed, structures are walked.
 */
export function redactValue(key: string | null, value: unknown): unknown {
  if (key !== null && isDenylistedKey(key)) return `[REDACTED:${key}]`;
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) return value.map((v) => redactValue(null, v));
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = redactValue(k, v);
    }
    return out;
  }
  return value;
}
