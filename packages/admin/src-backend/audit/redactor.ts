/**
 * Permission-driven field redaction for audit rows.
 *
 * Audit `payload`s (before/after diffs, deleted-row copies) and
 * `snapshot`s can contain credentials and personal data. The same row
 * must therefore look different to different operators: an admin sees
 * the real values, a mod gets masked PII, and credential-shaped values
 * are removed for *everyone* — an operator never needs a user's
 * password hash or session token to investigate an incident.
 *
 * The redactor is a single pure recursive walk used by every audit
 * read surface (query API, streaming export, and the generic CRUD
 * read of `adminAudit`) so the policy can't drift between them.
 */
import type { Role } from '@colyseus/database';

export type RedactMode = 'redact' | 'mask';

export interface RedactRule {
  /**
   * Field (leaf key) the rule applies to, SQL-column name.
   * Matching is case-insensitive and applies at every nesting level,
   * so `changes.password_hash.after` is covered by `password_hash`.
   */
  field: string;
  /**
   * 'redact' (default) replaces the value wholesale; 'mask' keeps a
   * type-preserving stub (`j***@example.com`, `192.0.x.x`, `****1234`).
   */
  mode?: RedactMode;
  /**
   * Minimum role that sees the *unredacted* value. Defaults to
   * 'admin', i.e. nobody below admin sees it. Roles are ranked
   * admin > mod > user.
   */
  minRole?: Role;
  /**
   * Restrict the rule to one audit resource (e.g. email masking only
   * makes sense on `users`). Without this the rule applies to every
   * resource — used for the credential denylist.
   */
  resource?: string;
}

/** Placeholder substituted in 'redact' mode — stable so exports diff cleanly. */
export const REDACTED_PLACEHOLDER = '[REDACTED]';

const ROLE_RANK: Record<Role, number> = { user: 1, mod: 2, admin: 3 };

function canSee(rule: RedactRule, role: Role): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[rule.minRole ?? 'admin'];
}

/**
 * Credential-shaped leaf names removed for every viewer — including
 * admins. Matching is token-based (the name split on non-alphanumerics
 * and camelCase boundaries), so `tokenVersion` — a revocation counter,
 * not a secret — does NOT match `token`, while `accessToken`,
 * `session_token` and `apiKeySecret` do.
 */
const ALWAYS_REDACT_TOKENS = new Set([
  'password',
  'passwd',
  'pwd',
  'hash',
  'token',
  'secret',
  'apikey',
  'cookie',
  'authorization',
  'credential',
  'credentials',
  'sessionid',
]);

// Whole-name substrings that are unsafe regardless of tokenization
// (e.g. `passwordhash` is one lowercased token, but "password" as a
// plain substring must still catch variants like `xpasswordy`).
const ALWAYS_REDACT_SUBSTRINGS = [
  'password',
  'passwd',
  'apikey',
  'api_key',
  'session_id',
  'sessionid',
  'authorization',
  'credential',
] as const;

function splitFieldTokens(field: string): string[] {
  return field
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length > 0);
}

function isCredentialField(field: string): boolean {
  const f = field.toLowerCase();
  if (ALWAYS_REDACT_SUBSTRINGS.some((p) => f.includes(p))) { return true; }
  // Explicit safe names — values that resemble credential words but
  // are counters/flags, never secrets.
  if (f === 'tokenversion' || f === 'token_version') { return false; }
  // `hash` / `secret` / `token` / `cookie` as standalone tokens
  // (`accessToken` → ["access", "token"]; `api_key_secret` → tokens).
  return splitFieldTokens(field).some((t) => ALWAYS_REDACT_TOKENS.has(t));
}

/**
 * PII / sensitive-but-not-secret fields masked for sub-admin viewers.
 * `resource`-scoped rules live here too (users.email).
 */
const DEFAULT_RULES: RedactRule[] = [
  // Email: preserve domain + first char so support can still tell
  // users apart ("j***@example.com"), full value admin-only.
  { field: 'email', mode: 'mask', minRole: 'admin' },
  { field: 'email_address', mode: 'mask', minRole: 'admin' },
  { field: 'emailaddress', mode: 'mask', minRole: 'admin' },

  // Phone / address / identity / network — masked to a stub for mods.
  { field: 'phone', mode: 'mask', minRole: 'admin' },
  { field: 'phone_number', mode: 'mask', minRole: 'admin' },
  { field: 'phonenumber', mode: 'mask', minRole: 'admin' },
  { field: 'address', mode: 'mask', minRole: 'admin' },
  { field: 'ip', mode: 'mask', minRole: 'admin' },
  { field: 'ip_address', mode: 'mask', minRole: 'admin' },
  { field: 'ipaddress', mode: 'mask', minRole: 'admin' },
  { field: 'real_name', mode: 'mask', minRole: 'admin' },
  { field: 'first_name', mode: 'mask', minRole: 'admin' },
  { field: 'last_name', mode: 'mask', minRole: 'admin' },
  { field: 'date_of_birth', mode: 'redact', minRole: 'admin' },
  { field: 'dob', mode: 'redact', minRole: 'admin' },

  // Ban metadata is operational, not secret — but a reason can quote
  // player conversations, so mods get it masked away from the audit
  // surfaces while still seeing it on the user's own profile.
  { field: 'banned_reason', mode: 'mask', minRole: 'admin', resource: 'users' },
];

/**
 * Resolve the effective rule list: built-in defaults first, then the
 * deployment's rules (ResourceDefinition `audit.redactFields`), so
 * callers can tighten (more rules) but never loosen the denylist —
 * credential matching is hard-coded inside the walk.
 */
export function resolveRedactRules(custom: RedactRule[] | undefined): RedactRule[] {
  return custom ? [...DEFAULT_RULES, ...custom] : DEFAULT_RULES;
}

function findRule(rules: RedactRule[], resource: string, field: string): RedactRule | undefined {
  return rules.find((r) => {
    if (r.field.toLowerCase() !== field.toLowerCase()) { return false; }
    if (r.resource && r.resource !== resource) { return false; }
    return true;
  });
}

/**
 * Mask a value preserving its rough shape. Non-strings/unknown shapes
 * fall back to the fixed placeholder — masking must never invent data.
 */
export function maskValue(value: unknown): unknown {
  if (typeof value !== 'string') { return REDACTED_PLACEHOLDER; }
  if (value.length === 0) { return value; }

  // email-ish
  const at = value.indexOf('@');
  if (at > 0 && value.includes('.', at)) {
    const local = value.slice(0, at);
    const domain = value.slice(at);
    return `${local[0] ?? ''}***${domain}`;
  }

  // IPv4-ish: keep first two octets (network), hide host part.
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(value)) {
    const [a, b] = value.split('.');
    return `${a}.${b}.x.x`;
  }

  // Generic string: keep last 4 chars when long enough, else all stars.
  if (value.length > 8) { return `****${value.slice(-4)}`; }
  return '****';
}

/**
 * Recursively redact a JSON-like value (payload or snapshot.fields).
 * `resource` scopes resource-specific rules; `path` is internal
 * recursion state and should not be passed by callers.
 *
 * Pure: returns a new object/array when anything changed; untouched
 * branches keep reference identity, which keeps export serialization
 * allocations low.
 */
export function redactValue(
  value: unknown,
  resource: string,
  role: Role,
  rules: RedactRule[],
): unknown {
  if (Array.isArray(value)) {
    let changed = false;
    const out = value.map((item) => {
      const r = redactValue(item, resource, role, rules);
      if (r !== item) { changed = true; }
      return r;
    });
    return changed ? out : value;
  }
  if (value !== null && typeof value === 'object') {
    let changed = false;
    const out: Record<string, unknown> = {};
    for (const [key, v] of Object.entries(value as Record<string, unknown>)) {
      const treated = redactLeaf(key, v, resource, role, rules);
      if (treated !== v) { changed = true; }
      // A leaf value that was itself an object/array was redacted
      // wholesale; otherwise recurse via redactLeaf's own walk.
      out[key] = treated;
    }
    return changed ? out : value;
  }
  return value;
}

function redactLeaf(
  key: string,
  value: unknown,
  resource: string,
  role: Role,
  rules: RedactRule[],
): unknown {
  // Credentials never leave the server, regardless of role.
  if (isCredentialField(key)) { return REDACTED_PLACEHOLDER; }

  const rule = findRule(rules, resource, key);
  if (rule && !canSee(rule, role)) {
    return rule.mode === 'mask' ? maskValue(value) : REDACTED_PLACEHOLDER;
  }

  // Recurse into nested containers ({before, after}, arrays of rows).
  if (value !== null && typeof value === 'object') {
    return redactValue(value, resource, role, rules);
  }
  return value;
}

/**
 * Redact every sensitive field on an audit row according to the
 * viewer's role. Mutates nothing; the returned row is a shallow copy
 * with redacted `payload` / `snapshot`. Top-level scalar columns
 * (operator_id, target_id, action, ...) are identity-bearing, not
 * secret — their visibility is governed by the `list` policy on the
 * audit resource, not by this walk.
 */
export interface RedactableAuditRow {
  resource: string;
  payload?: unknown;
  snapshot?: unknown;
}

export function redactAuditRow<T extends RedactableAuditRow>(
  row: T,
  role: Role,
  rules: RedactRule[],
): T {
  const payload = row.payload !== undefined
    ? redactValue(row.payload, row.resource, role, rules)
    : row.payload;
  let snapshot = row.snapshot;
  if (snapshot !== null && typeof snapshot === 'object') {
    const snapObj = snapshot as Record<string, unknown>;
    const fields = snapObj.fields !== undefined
      ? redactValue(snapObj.fields, row.resource, role, rules)
      : snapObj.fields;
    // Also scrub a credential embedded in the free-form label.
    const label = typeof snapObj.label === 'string' && /token|password|secret/i.test(snapObj.label)
      ? REDACTED_PLACEHOLDER
      : snapObj.label;
    snapshot = fields !== snapObj.fields || label !== snapObj.label
      ? { ...snapObj, fields, label }
      : snapObj;
  }
  if (payload === row.payload && snapshot === row.snapshot) { return row; }
  return { ...row, payload, snapshot };
}
