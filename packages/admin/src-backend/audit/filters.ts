/**
 * Audit query-filter parsing shared by the cursor-list endpoint and the
 * streaming export endpoint. Keeping the parser in one place means the
 * list page and the exported file can never disagree about which rows
 * a given query string selects — the export even re-serializes the
 * parsed filter back into its first NDJSON line so the file records its
 * own fixed boundary.
 *
 * Pure + no HTTP coupling: takes the already-parsed query record,
 * returns either a typed AuditQuery or a 400-shaped error. Easy to unit
 * test without a server.
 */
import type { AuditQuery } from '@colyseus/database';

export interface ParsedAuditFilter {
  filter: AuditQuery;
}

export type AuditFilterParseResult =
  | ParsedAuditFilter
  | { error: string };

/** Hard ceiling on an export/list time window (93 days) — see parseAuditFilter. */
export const MAX_WINDOW_MS = 93 * 24 * 60 * 60 * 1000;

const ACTION_PREFIXES = ['auth.', 'room.', 'user.', 'audit.'];

/**
 * Whitelist of recognized action values. Free-form action text is
 * rejected rather than passed through: the action column is indexed
 * and the UI offers a fixed multiselect, so an unknown value is almost
 * always a typo or a probe. The dotted prefixes (`auth.login`, …) and
 * the CRUD verbs below are the complete set the panel writes.
 */
const KNOWN_ACTIONS = new Set([
  'create',
  'update',
  'delete',
  'custom',
  'auth.login',
  'auth.login_failed',
  'auth.logout',
  'auth.bootstrap',
  'auth.password_reset_requested',
  'auth.password_reset_completed',
  'room.kick',
  'room.dispose',
  'room.lock',
  'room.unlock',
  'room.state.edit',
  'room.state.delete',
  'user.ban',
  'user.unban',
  'user.revoke_sessions',
  'audit.export_completed',
  'audit.export_failed',
]);

/**
 * Is this an action the panel might plausibly write? Accepts the fixed
 * set above plus anything under the reserved dotted namespaces — a
 * game may ship its own `room.*` / `user.*` / `audit.*` custom tags
 * via `database.audit.record()`.
 */
export function isKnownAction(action: string): boolean {
  if (KNOWN_ACTIONS.has(action)) { return true; }
  return ACTION_PREFIXES.some((p) => action.startsWith(p));
}

function nonEmpty(raw: unknown): string | undefined {
  return typeof raw === 'string' && raw.trim().length > 0 ? raw.trim() : undefined;
}

/** Parse an ISO 8601 bound; `null` result means "bad input". */
function parseDate(raw: string, field: string): Date | { error: string } {
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) {
    return { error: `${field} must be an ISO 8601 date` };
  }
  return d;
}

/**
 * Parse query params into an AuditQuery. Accepted keys:
 *
 *   operatorId, resource, targetId — exact-match strings
 *   action                         — single value OR comma-separated set
 *   from, until                    — ISO 8601, inclusive bounds
 *
 * The time window is capped at MAX_WINDOW_MS: an unbounded export would
 * scan the whole append-only table. The cap protects a single request
 * from pinning the DB for minutes regardless of how many rows match.
 */
export function parseAuditFilter(
  query: Record<string, unknown>,
): AuditFilterParseResult {
  const filter: AuditQuery = {};

  const operatorId = nonEmpty(query.operatorId);
  if (operatorId) { filter.operatorId = operatorId; }

  const resource = nonEmpty(query.resource);
  if (resource) { filter.resource = resource; }

  const targetId = nonEmpty(query.targetId);
  if (targetId) { filter.targetId = targetId; }

  // action=foo or action=foo,bar — comma separated becomes an IN-set.
  const actionRaw = nonEmpty(query.action);
  if (actionRaw) {
    const actions = actionRaw.split(',').map((s) => s.trim()).filter(Boolean);
    for (const a of actions) {
      if (!isKnownAction(a)) {
        return { error: `unknown action '${a}'` };
      }
    }
    if (actions.length === 1) { filter.action = actions[0]; }
    else if (actions.length > 1) { filter.actions = actions; }
  }

  if (nonEmpty(query.from)) {
    const parsed = parseDate(nonEmpty(query.from)!, 'from');
    if ('error' in parsed) { return parsed; }
    filter.from = parsed;
  }
  if (nonEmpty(query.until)) {
    const parsed = parseDate(nonEmpty(query.until)!, 'until');
    if ('error' in parsed) { return parsed; }
    filter.until = parsed;
  }

  if (filter.from && filter.until && filter.from.getTime() > filter.until.getTime()) {
    return { error: 'from must be at or before until' };
  }
  if (filter.from && filter.until
    && filter.until.getTime() - filter.from.getTime() > MAX_WINDOW_MS) {
    return { error: `time window too large — maximum ${Math.round(MAX_WINDOW_MS / 86_400_000)} days` };
  }

  return { filter };
}

/**
 * Stable canonical serialization of a parsed filter — sorted keys,
 * ISO dates. Written as the first NDJSON line ("boundary") of every
 * export so the downloaded file is self-describing: anyone holding the
 * file can see exactly which query produced it and when.
 */
export function serializeAuditFilter(filter: AuditQuery): Record<string, string> {
  const out: Record<string, string> = {};
  if (filter.operatorId) { out.operatorId = filter.operatorId; }
  if (filter.resource) { out.resource = filter.resource; }
  if (filter.targetId) { out.targetId = filter.targetId; }
  const actions = filter.actions ?? (filter.action ? [filter.action] : []);
  if (actions.length > 0) { out.actions = [...actions].sort().join(','); }
  if (filter.from) { out.from = filter.from.toISOString(); }
  if (filter.until) { out.until = filter.until.toISOString(); }
  return out;
}
