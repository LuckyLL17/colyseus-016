/**
 * Permission-driven field redaction for audit payloads.
 *
 * Audit entries can carry sensitive before/after row data — password
 * hashes, ban reasons, IP addresses, email addresses. The admin list
 * and the export endpoint must never leak those to a viewer whose role
 * doesn't clear them, even though that viewer is allowed to read the
 * audit log at all (mods, or a deployment that widened `list`/`read`
 * via policies).
 *
 * Design:
 *   - `redactAuditEntry()` is PURE: entry in, cloned+redacted entry
 *     out. Both the JSON list endpoint and the streaming export call
 *     it per row so masking can't drift between the two surfaces.
 *   - Rules are keyed by (resource, field-path). `admin()` merges
 *     built-in rules with any per-resource overrides from
 *     `defineAdminResource`.
 *   - The deciding inputs are the VIEWER's live role and the resource's
 *     RBAC policy for `read` — permission is re-checked per request,
 *     never cached on the row.
 *
 * Redaction replaces a value with a fixed marker; the key stays so the
 * reader can see the field existed. Strings retain a length hint for
 * triage ("***redacted:18***") without revealing content.
 */
import type { AuditEntry } from '@colyseus/database';

export type RedactRole = 'admin' | 'mod' | 'user';

/** Minimum role that may view a field in the clear. */
export type MinimumRole = 'admin' | 'mod';

export interface RedactRule {
  /**
   * Dotted path inside `payload` (e.g. "row.email", "changes.email.after").
   * A single segment matches the same key at ANY depth when `deep` is
   * set — that's how "passwordHash anywhere under changes" is expressed
   * without enumerating before/after.
   */
  field: string;
  /** 'admin' (default) → admins only; 'mod' → admins and mods. */
  minRole?: MinimumRole;
  /** Match `field` as a terminal key at any depth. */
  deep?: boolean;
}

/**
 * Effective ruleset for a request: built-in rules (keyed by canonical
 * resource name) plus the viewer's live role. Constructed once per
 * request by the audit endpoint — build is cheap but there's no reason
 * to redo it per row.
 */
export interface RedactionContext {
  role: RedactRole;
  /** Per-resource rules, merged from built-ins + resource overrides. */
  rules: Record<string, RedactRule[]>;
}

export interface RedactionResult {
  entry: AuditEntry;
  /** Dotted paths actually replaced on this row — surfaced as metadata. */
  redactedFields: string[];
}

const ROLE_RANK: Record<RedactRole, number> = { user: 0, mod: 1, admin: 2 };

function clears(role: RedactRole, min: MinimumRole): boolean {
  return ROLE_RANK[role] >= ROLE_RANK[min];
}

/**
 * Field names that are ALWAYS sensitive regardless of placement:
 * credentials, secrets, tokens. A deep rule for each is auto-added to
 * every resource — even a custom game table that happens to carry a
 * `passwordHash` column gets masked for non-admins.
 *
 * Matching is case-insensitive on the terminal key, and the common
 * `xxxDigest` / `xxxToken` suffixes are included.
 */
const ALWAYS_SENSITIVE_KEYS = new Set([
  'password',
  'passwordhash',
  'passworddigest',
  'secret',
  'token',
  'accesstoken',
  'refreshtoken',
  'apikey',
  'twofactorsecret',
  'recoverycode',
]);

/** Keys treated as secrets only when they live on a users-shaped row. */
const USER_SECRET_KEYS = new Set([
  'email',
  'phonenumber',
  'ip',
  'ipaddress',
  'bannedreason',
  'anonymousid',
]);

/**
 * Wildcard resource key: rules under it apply to EVERY resource. The
 * built-in credential rules live here so a custom game table carrying
 * a `token` column gets masked without per-resource configuration.
 */
export const ALL_RESOURCES = '*';

/**
 * Built-in per-resource rules. `deep: true` rules walk the whole
 * payload subtree; explicit paths target the conventional CRUD payload
 * shapes ({ row }, { changes: { f: { before, after } } }).
 */
export function builtInRules(): Record<string, RedactRule[]> {
  const deepSecret: RedactRule[] = [];
  for (const field of ALWAYS_SENSITIVE_KEYS) {
    deepSecret.push({ field, deep: true, minRole: 'admin' });
  }
  // Ban/workflow payloads (users resource + user.* actions)
  const userPii: RedactRule[] = [
    ...[...USER_SECRET_KEYS].map((field): RedactRule => ({ field, deep: true, minRole: 'mod' })),
    // ban reason is admin-only; email/ip mods may see (minRole: 'mod').
    { field: 'bannedreason', deep: true, minRole: 'admin' },
    { field: 'reason', deep: true, minRole: 'admin' },
    // free-form note text a mod can write but not read back in bulk export
    { field: 'text', deep: true, minRole: 'admin' },
  ];

  return {
    // Credentials are masked everywhere, not just on known resources.
    [ALL_RESOURCES]: deepSecret,
    users: userPii,
    roles: [
      // A role assignment row reveals nothing by itself, but keep the
      // scopes list admin-only in exports (it maps the org's authority
      // topology). Credential masking comes from the wildcard set.
      { field: 'scopes', deep: true, minRole: 'admin' },
    ],
  };
}

/**
 * Merge built-in rules with resource overrides. Overrides for a resource
 * APPEND to the built-ins (so games can only ADD protection, never
 * remove the credential defaults). Pass `audit.redactRules` from
 * AdminOptions.
 */
export function mergeRules(
  builtins: Record<string, RedactRule[]>,
  overrides?: Record<string, RedactRule[]>,
): Record<string, RedactRule[]> {
  if (!overrides) { return builtins; }
  const out: Record<string, RedactRule[]> = { ...builtins };
  for (const [resource, rules] of Object.entries(overrides)) {
    out[resource] = [...(out[resource] ?? []), ...rules];
  }
  return out;
}

/**
 * Does any rule bind the viewer? Cheap pre-check an endpoint can use to
 * skip cloning when nothing would be masked. Considers both the
 * resource-specific rules and the wildcard (`*`) credential set.
 */
export function resourceHasBindingRules(
  rules: Record<string, RedactRule[]>,
  resource: string,
  role: RedactRole,
): boolean {
  const list = [...(rules[ALL_RESOURCES] ?? []), ...(rules[resource] ?? [])];
  if (list.length === 0) { return false; }
  return list.some((r) => !clears(role, r.minRole ?? 'admin'));
}

const MARK = (value: unknown): string => {
  if (typeof value === 'string') { return `***redacted:${value.length}***`; }
  return '***redacted***';
};

interface CompiledRule extends RedactRule {
  /** Exact path segments for non-deep rules. */
  path: string[];
  /** Lowercased terminal key for deep matching. */
  terminal: string;
}

function compile(list: RedactRule[]): CompiledRule[] {
  return list.map((r) => ({
    ...r,
    path: r.field.split('.').filter(Boolean),
    terminal: r.field.split('.').filter(Boolean).pop()!.toLowerCase(),
  }));
}

/**
 * Walk `value`, replacing anything a binding rule covers. Deep rules
 * match their terminal key at ANY depth (including object entries
 * nested inside arrays), which is what makes `{ changes: { f: { after:
 * <secret> } } }` mask without spelling out every CRUD payload path.
 *
 * Mutates the clone owned by the caller; never the original entry.
 */
function walk(
  value: any,
  compiled: CompiledRule[],
  role: RedactRole,
  redacted: string[],
  trail: string[] = [],
): any {
  if (Array.isArray(value)) {
    return value.map((v, i) => {
      // An array ENTRY can itself be masked (e.g. scopes: ['a','b']) —
      // match deep rules against the array key one level up.
      const parentKey = trail[trail.length - 1]?.toLowerCase();
      const deep = parentKey
        ? compiled.find((r) => r.deep && r.terminal === parentKey)
        : undefined;
      if (deep && !clears(role, deep.minRole ?? 'admin')) {
        redacted.push([...trail, String(i)].join('.'));
        return MARK(v);
      }
      return walk(v, compiled, role, redacted, [...trail, String(i)]);
    });
  }
  if (value === null || typeof value !== 'object') { return value; }

  const out: Record<string, any> = {};
  for (const [key, child] of Object.entries(value)) {
    const here = [...trail, key];

    // Exact path rules take precedence; otherwise a deep rule keyed on
    // this terminal segment applies. Most protective matching rule
    // wins per-field (hide if ANY bound rule hides it for this role).
    const terminal = key.toLowerCase();
    const exact = compiled.find((r) =>
      !r.deep
      && r.path.length === here.length
      && r.path.every((seg, i) => seg.toLowerCase() === here[i]!.toLowerCase()),
    );
    const deep = !exact
      ? compiled.find((r) => r.deep && r.terminal === terminal)
      : undefined;
    const rule = exact ?? deep;

    if (rule && !clears(role, rule.minRole ?? 'admin')) {
      out[key] = MARK(child);
      redacted.push(here.join('.'));
      continue;
    }
    out[key] = walk(child, compiled, role, redacted, here);
  }
  return out;
}

/**
 * Return a redacted clone of `entry` plus the list of replaced paths.
 * Top-level identifying columns (operator/resource/target ids + labels)
 * are never masked here — they're the audit index, not row contents.
 * Only `payload` is walked.
 */
export function redactAuditEntry(
  entry: AuditEntry,
  context: RedactionContext,
): RedactionResult {
  // Nothing to walk — cheap common path (auth.logout rows etc.).
  if (entry.payload === null || entry.payload === undefined) {
    return { entry, redactedFields: [] };
  }
  const list = [
    ...(context.rules[ALL_RESOURCES] ?? []),
    ...(context.rules[entry.resource] ?? []),
  ];
  if (list.length === 0) {
    return { entry, redactedFields: [] };
  }
  if (!resourceHasBindingRules(context.rules, entry.resource, context.role)) {
    return { entry, redactedFields: [] };
  }
  const redactedFields: string[] = [];
  const payload = walk(entry.payload, compile(list), context.role, redactedFields);
  return {
    entry: { ...entry, payload },
    redactedFields,
  };
}

/**
 * Serialize one entry for API/NDJSON output: camelCase DB keys → the
 * snake_case the admin frontend uses everywhere, Date → ISO string.
 */
export function serializeAuditEntry(entry: AuditEntry): Record<string, unknown> {
  return {
    id: entry.id,
    operator_id: entry.operatorId,
    operator_label: entry.operatorLabel ?? null,
    action: entry.action,
    resource: entry.resource,
    resource_label: entry.resourceLabel ?? null,
    target_id: entry.targetId,
    target_label: entry.targetLabel ?? null,
    payload: entry.payload,
    created_at: entry.createdAt instanceof Date ? entry.createdAt.toISOString() : entry.createdAt,
  };
}
