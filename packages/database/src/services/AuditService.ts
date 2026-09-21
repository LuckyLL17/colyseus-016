import { and, desc, eq, gte, inArray, lt, lte, or, type SQL } from 'drizzle-orm';
import type { AdminAuditTableShape } from '../types.ts';
import { affectedRows, type ServiceDb } from './_db.ts';

/**
 * Audit action tags. CRUD verbs cover mutations through the admin's
 * create/update/delete endpoints; `custom` is for `_action`-style
 * handlers; `auth.*` covers admin sign-in/out/bootstrap so a stolen
 * credential trail is visible in the same log as data mutations;
 * `audit.export` records each streaming audit export (its filters and
 * success/failure status) in the same table it reads from.
 */
export type AuditAction =
  | 'create'
  | 'update'
  | 'delete'
  | 'custom'
  | 'auth.login'
  | 'auth.login_failed'
  | 'auth.logout'
  | 'auth.bootstrap'
  | 'auth.password_reset_requested'
  | 'auth.password_reset_completed'
  | 'room.kick'
  | 'room.dispose'
  | 'room.lock'
  | 'room.unlock'
  | 'room.state.edit'
  | 'room.state.delete'
  | 'user.ban'
  | 'user.unban'
  | 'user.revoke_sessions'
  | 'audit.export';

/**
 * Reduced context captured at record time so an audit entry stays
 * readable after its target row (or whole resource table) is gone.
 * `fields` holds a small whitelist of scalar values — display name,
 * email, ban reason — not the full row. The admin layer decides which
 * fields to capture and applies the viewer's redaction policy on read,
 * so values here follow the same permission rules as `payload`.
 */
export interface AuditSnapshot {
  /** Human label for the target at record time, if one was available. */
  label?: string | null;
  /** Scalar context fields keyed by SQL column name. */
  fields?: Record<string, unknown>;
}

export interface AuditEntry {
  id: string;
  operatorId: string | null;
  action: string;
  resource: string;
  targetId: string | null;
  payload: any;
  snapshot: AuditSnapshot | null;
  createdAt: Date;
}

/**
 * Column-level diff between two row snapshots. Result keys are the
 * shared/changed column names; values are `{ before, after }` pairs
 * for fields that actually differ. Untouched columns are omitted.
 *
 * Equality:
 *   - `===` for primitives
 *   - `getTime()` for Date instances
 *   - stringified for objects (good enough for audit payloads)
 *
 * Exported so game code can produce audit-shaped diffs from
 * non-admin code paths (e.g. cron jobs, scheduled migrations).
 */
export function diffRows(
  before: Record<string, any> | null | undefined,
  after: Record<string, any> | null | undefined,
): Record<string, { before: any; after: any }> {
  const out: Record<string, { before: any; after: any }> = {};
  const keys = new Set<string>([
    ...Object.keys(before ?? {}),
    ...Object.keys(after ?? {}),
  ]);
  for (const k of keys) {
    const a = before?.[k];
    const b = after?.[k];
    if (!isShallowlyEqual(a, b)) {
      out[k] = { before: a, after: b };
    }
  }
  return out;
}

function isShallowlyEqual(a: any, b: any): boolean {
  if (a === b) { return true; }
  if (a == null || b == null) { return false; }
  if (a instanceof Date && b instanceof Date) { return a.getTime() === b.getTime(); }
  if (typeof a === 'object' && typeof b === 'object') {
    try { return JSON.stringify(a) === JSON.stringify(b); }
    catch { return false; }
  }
  return false;
}

/**
 * Filters shared by the query API and exports. All are optional and
 * combined with AND. Time windows are inclusive on both ends — callers
 * that want "up to now" simply omit `createdBefore`.
 */
export interface AuditQuery {
  operatorId?: string | null;
  resource?: string | null;
  /** Single action or an OR-list (e.g. all `room.*` at once). */
  action?: string | string[] | null;
  targetId?: string | null;
  createdAfter?: Date | null;
  createdBefore?: Date | null;
}

/**
 * Opaque keyset position: `(createdAt, id)` of the last row the caller
 * received. Encoding/decoding lives here so the HTTP layer and any
 * other consumer share one implementation. The payload is base64url
 * JSON — not encrypted, but callers must treat it as opaque and never
 * hand-craft it.
 */
export interface AuditCursor {
  /** ISO timestamp of the last delivered row. */
  ts: string;
  /** Id of the last delivered row (tie-breaker for equal timestamps). */
  id: string;
}

export function encodeAuditCursor(cursor: AuditCursor): string {
  const json = JSON.stringify({ ts: cursor.ts, id: cursor.id });
  return Buffer.from(json, 'utf8').toString('base64url');
}

/** Returns null for malformed cursors so callers can answer 400 uniformly. */
export function decodeAuditCursor(raw: string): AuditCursor | null {
  try {
    const json = Buffer.from(raw, 'base64url').toString('utf8');
    const parsed = JSON.parse(json);
    if (typeof parsed !== 'object' || parsed === null) { return null; }
    const { ts, id } = parsed as Record<string, unknown>;
    if (typeof ts !== 'string' || typeof id !== 'string') { return null; }
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) { return null; }
    return { ts, id };
  } catch {
    return null;
  }
}

export interface AuditPage {
  entries: AuditEntry[];
  /** Present when another page likely exists; absent on the last page. */
  nextCursor: string | null;
}

/** Hard cap so a single query/export can't pin the DB. */
export const AUDIT_MAX_LIMIT = 500;
/** Rows per page / per export batch when the caller doesn't specify. */
export const AUDIT_DEFAULT_BATCH = 200;
/** Rows per streaming export batch — small enough to bound memory. */
export const AUDIT_EXPORT_BATCH = 200;
/** Exports may not scan a window wider than this (ms) — 1 year. */
export const AUDIT_MAX_WINDOW_MS = 366 * 24 * 60 * 60 * 1000;

/**
 * Append-only log of admin actions. Used by the admin's
 * Create/Update/Delete/custom-action endpoints to record who did what,
 * when, and to which row. Reads are cheap (keyset paginated, indexed by
 * operator / resource / action + createdAt); writes are fire-and-forget
 * — the calling endpoint shouldn't fail just because the audit insert
 * did.
 *
 * For high-volume games, retention is the operator's responsibility.
 * Provide `prune(before)` so a cron can drop entries older than N
 * days.
 */
export class AuditService<T extends AdminAuditTableShape = AdminAuditTableShape> {
  private db: ServiceDb;
  private audit: T;

  constructor(db: ServiceDb, audit: T) {
    this.db = db;
    this.audit = audit;
  }

  /**
   * Record a single audit entry. Designed to be called from inside
   * admin endpoint handlers — wraps in try/catch in callers since
   * we don't want a logger failure to break the user's mutation.
   *
   * `snapshot` carries deletion-proof context (label + a few scalar
   * fields) captured from the target at record time; see AuditSnapshot.
   */
  async record(entry: {
    operatorId?: string | null;
    action: AuditAction | string;
    resource: string;
    targetId?: string | null;
    payload?: unknown;
    snapshot?: AuditSnapshot | null;
  }): Promise<AuditEntry> {
    const [row] = await this.db
      .insert(this.audit)
      .values({
        operatorId: entry.operatorId ?? null,
        action: entry.action,
        resource: entry.resource,
        targetId: entry.targetId ?? null,
        payload: entry.payload ?? null,
        snapshot: entry.snapshot ?? null,
      })
      .returning();
    return row as AuditEntry;
  }

  /**
   * Convenience for the common "I just updated row X, log the change"
   * pattern. Computes a column-level diff via `diffRows` and stores it
   * under `payload.changes`. Equivalent to:
   *
   *   audit.record({
   *     ...,
   *     action: 'update',
   *     payload: { changes: diffRows(before, after) },
   *   });
   */
  async recordUpdate(opts: {
    operatorId?: string | null;
    resource: string;
    targetId?: string | null;
    before: Record<string, any> | null | undefined;
    after: Record<string, any>;
    snapshot?: AuditSnapshot | null;
  }): Promise<AuditEntry> {
    return this.record({
      operatorId: opts.operatorId ?? null,
      action: 'update',
      resource: opts.resource,
      targetId: opts.targetId ?? null,
      payload: { changes: diffRows(opts.before, opts.after) },
      snapshot: opts.snapshot ?? null,
    });
  }

  /**
   * Build the shared WHERE clause for `query()` and `iterate()`.
   * Extracted so both paths — and their indexes — stay identical:
   * pagination must never widen/narrow the filter between pages.
   */
  private buildConditions(filter: AuditQuery): SQL[] {
    const conds: SQL[] = [];
    if (filter.operatorId) { conds.push(eq(this.audit.operatorId, filter.operatorId)); }
    if (filter.resource) { conds.push(eq(this.audit.resource, filter.resource)); }
    if (filter.targetId) { conds.push(eq(this.audit.targetId, filter.targetId)); }
    if (filter.action) {
      const actions = Array.isArray(filter.action) ? filter.action : [filter.action];
      const list = actions.filter((a) => typeof a === 'string' && a.length > 0);
      if (list.length === 1) {
        conds.push(eq(this.audit.action, list[0]!));
      } else if (list.length > 1) {
        conds.push(inArray(this.audit.action, list));
      }
    }
    if (filter.createdAfter) { conds.push(gte(this.audit.createdAt, filter.createdAfter)); }
    if (filter.createdBefore) { conds.push(lte(this.audit.createdAt, filter.createdBefore)); }
    return conds;
  }

  /**
   * Keyset-paginated audit read, newest-first. The cursor is the
   * `(created_at, id)` of the last row previously returned, so
   * concurrent inserts never duplicate or skip rows — unlike OFFSET.
   *
   * `limit` is the page size, clamped to [1, AUDIT_MAX_LIMIT].
   * `nextCursor` is null on the final page; we fetch limit+1 rows to
   * decide without a second COUNT query.
   */
  async query(opts: AuditQuery & {
    cursor?: AuditCursor | null;
    limit?: number;
  } = {}): Promise<AuditPage> {
    const limit = clampLimit(opts.limit ?? 50, AUDIT_MAX_LIMIT);
    const conds = this.buildConditions(opts);
    if (opts.cursor) {
      const cursorDate = new Date(opts.cursor.ts);
      // Keyset predicate for ORDER BY created_at DESC, id DESC:
      // (created_at, id) < (cursor.ts, cursor.id)
      conds.push(or(
        lt(this.audit.createdAt, cursorDate),
        and(eq(this.audit.createdAt, cursorDate), lt(this.audit.id, opts.cursor.id)),
      )!);
    }
    const whereClause = conds.length === 0 ? undefined
      : conds.length === 1 ? conds[0]!
      : and(...conds);

    let q = this.db.select().from(this.audit);
    if (whereClause) { q = q.where(whereClause); }
    q = q.orderBy(desc(this.audit.createdAt), desc(this.audit.id)).limit(limit + 1);
    const rows = (await q) as AuditEntry[];

    const hasMore = rows.length > limit;
    const page = hasMore ? rows.slice(0, limit) : rows;
    const last = page[page.length - 1];
    return {
      entries: page,
      nextCursor: hasMore && last
        ? encodeAuditCursor({ ts: last.createdAt.toISOString(), id: last.id })
        : null,
    };
  }

  /**
   * Async generator for bounded-memory exports. Yields one batch at a
   * time; the consumer fully controls backpressure (await between
   * batches) and no more than `batchSize` rows are ever resident.
   *
   * The filter is captured once at call time — "fix the query
   * boundary" — and every internal page reuses it verbatim, so an
   * export can't silently drift onto rows inserted (or pruned)
   * halfway through.
   */
  async *iterate(filter: AuditQuery, opts: { batchSize?: number } = {}): AsyncGenerator<AuditEntry[], void, void> {
    const batchSize = clampLimit(opts.batchSize ?? AUDIT_EXPORT_BATCH, AUDIT_MAX_LIMIT);
    let cursor: AuditCursor | null = null;
    do {
      const page = await this.query({ ...filter, cursor, limit: batchSize });
      if (page.entries.length > 0) { yield page.entries; }
      cursor = page.nextCursor ? decodeAuditCursor(page.nextCursor) : null;
    } while (cursor);
  }

  /**
   * Legacy unpaginated read. Kept for existing callers and tests; new
   * code should use `query()` (keyset pagination) or `iterate()`
   * (exports). The `before` cursor here is a loose timestamp only —
   * equal-timestamp rows could be skipped — which is exactly what the
   * `(createdAt, id)` keyset in `query()` fixes.
   */
  async list(opts: {
    operatorId?: string;
    resource?: string;
    before?: Date;
    limit?: number;
  } = {}): Promise<AuditEntry[]> {
    const limit = clampLimit(opts.limit ?? 100, AUDIT_MAX_LIMIT);
    const conds: SQL[] = [];
    if (opts.operatorId) { conds.push(eq(this.audit.operatorId, opts.operatorId)); }
    if (opts.resource) { conds.push(eq(this.audit.resource, opts.resource)); }
    if (opts.before) { conds.push(lt(this.audit.createdAt, opts.before)); }

    // ServiceDb returns `any` from select() — chain inference would need
    // pinning to a specific drizzle subclass and isn't worth the coupling.
    // Local `q` keeps the conditional `.where(...)` legible.
    let q = this.db.select().from(this.audit);
    if (conds.length === 1) { q = q.where(conds[0]); }
    else if (conds.length > 1) { q = q.where(and(...conds)); }
    q = q.orderBy(desc(this.audit.createdAt), desc(this.audit.id)).limit(limit);
    return q as Promise<AuditEntry[]>;
  }

  /** Drop entries older than `before`. Returns the number of rows removed. */
  async prune(before: Date): Promise<number> {
    const result = await this.db
      .delete(this.audit)
      .where(lt(this.audit.createdAt, before));
    return affectedRows(result);
  }
}

function clampLimit(n: number, max: number): number {
  if (!Number.isFinite(n) || n < 1) { return 1; }
  return Math.min(Math.floor(n), max);
}
