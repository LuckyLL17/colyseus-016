import { and, desc, eq, gte, inArray, lt, lte, or, sql, type SQL } from 'drizzle-orm';
import type { AdminAuditTableShape } from '../types.ts';
import { affectedRows, type ServiceDb } from './_db.ts';

/**
 * Audit action tags. CRUD verbs cover mutations through the admin's
 * create/update/delete endpoints; `custom` is for `_action`-style
 * handlers; `auth.*` covers admin sign-in/out/bootstrap so a stolen
 * credential trail is visible in the same log as data mutations.
 * `audit.export_*` records admin audit-log exports (success/failure)
 * — the log logs accesses of itself.
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
  | 'audit.export_completed'
  | 'audit.export_failed';

export interface AuditEntry {
  id: string;
  operatorId: string | null;
  operatorLabel: string | null;
  action: string;
  resource: string;
  resourceLabel: string | null;
  targetId: string | null;
  targetLabel: string | null;
  payload: any;
  createdAt: Date;
}

/**
 * Filtered audit query. All fields optional; every field narrows the
 * result. Time bounds are inclusive on both ends so an export requested
 * for "2026-09-01 … 2026-09-02" is reproducible across paged reads.
 */
export interface AuditQuery {
  operatorId?: string;
  resource?: string;
  /** Target row id ("what was acted on"). Distinct from operatorId. */
  targetId?: string;
  /** Single action or, via `actions`, an OR-set (UI action multiselect). */
  action?: string;
  actions?: string[];
  /** Inclusive lower bound on createdAt. */
  from?: Date;
  /** Inclusive upper bound on createdAt. */
  until?: Date;
}

/**
 * Opaque continuation cursor. Encodes the (createdAt, id) pair of the
 * last row the caller saw; the next page returns rows strictly older.
 * Base64url JSON keeps it URL-safe without a signed-token dependency —
 * the cursor carries no authority, it only positions the scan.
 */
export type AuditCursor = string;

/** Result page of a cursor walk. `nextCursor` is null at the end. */
export interface AuditPage {
  entries: AuditEntry[];
  nextCursor: AuditCursor | null;
}

/** Row position the cursor is built from. Exported for tests/tooling. */
export function encodeCursor(createdAt: Date, id: string): AuditCursor {
  const json = JSON.stringify({ t: createdAt.getTime(), i: id });
  return Buffer.from(json, 'utf8').toString('base64url');
}

/** Parse a cursor. Throws on malformed input so callers can 400 it. */
export function decodeCursor(cursor: AuditCursor): { createdAt: Date; id: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
  } catch {
    throw new Error('malformed audit cursor');
  }
  const t = (parsed as any)?.t;
  const i = (parsed as any)?.i;
  if (typeof t !== 'number' || !Number.isFinite(t) || typeof i !== 'string' || i.length === 0) {
    throw new Error('malformed audit cursor');
  }
  return { createdAt: new Date(t), id: i };
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
 * Append-only log of admin actions. Used by the admin's
 * Create/Update/Delete/custom-action endpoints to record who did what,
 * when, and to which row. Reads are cheap (paginated, indexed by
 * resource + createdAt); writes are fire-and-forget — the calling
 * endpoint shouldn't fail just because the audit insert did.
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
   * `operatorLabel` / `resourceLabel` / `targetLabel` are optional
   * write-time context snapshots: pass them so the row stays legible
   * after the referenced user/resource/row is deleted.
   */
  async record(entry: {
    operatorId?: string | null;
    operatorLabel?: string | null;
    action: AuditAction | string;
    resource: string;
    resourceLabel?: string | null;
    targetId?: string | null;
    targetLabel?: string | null;
    payload?: unknown;
  }): Promise<AuditEntry> {
    const [row] = await this.db
      .insert(this.audit)
      .values({
        operatorId: entry.operatorId ?? null,
        operatorLabel: entry.operatorLabel ?? null,
        action: entry.action,
        resource: entry.resource,
        resourceLabel: entry.resourceLabel ?? null,
        targetId: entry.targetId ?? null,
        targetLabel: entry.targetLabel ?? null,
        payload: entry.payload ?? null,
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
    operatorLabel?: string | null;
    resource: string;
    resourceLabel?: string | null;
    targetId?: string | null;
    targetLabel?: string | null;
    before: Record<string, any> | null | undefined;
    after: Record<string, any>;
  }): Promise<AuditEntry> {
    return this.record({
      operatorId: opts.operatorId ?? null,
      operatorLabel: opts.operatorLabel ?? null,
      action: 'update',
      resource: opts.resource,
      resourceLabel: opts.resourceLabel ?? null,
      targetId: opts.targetId ?? null,
      targetLabel: opts.targetLabel ?? null,
      payload: { changes: diffRows(opts.before, opts.after) },
    });
  }

  /**
   * Build the WHERE clause for a filtered query. Shared by `list`,
   * `queryPage`, and `iterate` so the three can never disagree on
   * filter semantics. The cursor predicate (strictly older than the
   * last-seen row, tie-broken by id) is appended by callers.
   */
  private buildConditions(filter: AuditQuery): SQL[] {
    const conds: SQL[] = [];
    if (filter.operatorId) { conds.push(eq(this.audit.operatorId, filter.operatorId)); }
    if (filter.resource) { conds.push(eq(this.audit.resource, filter.resource)); }
    if (filter.targetId) { conds.push(eq(this.audit.targetId, filter.targetId)); }
    if (filter.actions && filter.actions.length > 0) {
      conds.push(inArray(this.audit.action, filter.actions));
    } else if (filter.action) {
      conds.push(eq(this.audit.action, filter.action));
    }
    if (filter.from) { conds.push(gte(this.audit.createdAt, filter.from)); }
    if (filter.until) { conds.push(lte(this.audit.createdAt, filter.until)); }
    return conds;
  }

  /** AND together a condition list the way every query in this file does. */
  private whereFrom(conds: SQL[]): SQL | undefined {
    if (conds.length === 0) { return undefined; }
    if (conds.length === 1) { return conds[0]!; }
    return and(...conds);
  }

  /**
   * List entries newest-first, optionally filtered. Backward-compatible
   * wrapper around `queryPage` — existing callers use offset-free
   * time-based `before` paging, which we translate into an inclusive
   * `until` bound. New code should use `queryPage` (cursor) or
   * `iterate` (streaming batches).
   */
  async list(opts: (AuditQuery & {
    before?: Date;
    limit?: number;
  }) = {}): Promise<AuditEntry[]> {
    const { before, limit, ...filter } = opts;
    const page = await this.queryPage({
      filter: { ...filter, until: before ?? filter.until },
      limit,
    });
    return page.entries;
  }

  /**
   * One cursor-based page, newest-first. Keyset pagination on
   * (createdAt DESC, id DESC): rows inserted WHILE a client pages can't
   * skip or duplicate entries, unlike LIMIT/OFFSET. `limit` is clamped
   * to [1, 500] server-side.
   */
  async queryPage(opts: {
    filter?: AuditQuery;
    cursor?: AuditCursor;
    limit?: number;
  } = {}): Promise<AuditPage> {
    const limit = clampLimit(opts.limit, 100);
    const conds = this.buildConditions(opts.filter ?? {});
    if (opts.cursor) {
      const pos = decodeCursor(opts.cursor);
      // Keyset predicate: strictly before (createdAt, id) in DESC order.
      conds.push(
        orTupleOlder(this.audit.createdAt, this.audit.id, pos.createdAt, pos.id) as SQL,
      );
    }

    let q = this.db.select().from(this.audit);
    const where = this.whereFrom(conds);
    if (where) { q = q.where(where); }
    q = q.orderBy(desc(this.audit.createdAt), desc(this.audit.id)).limit(limit + 1);
    const rows = (await q) as AuditEntry[];

    // Fetch limit+1: a final extra row means "more follows" and gives
    // the cursor its position without a second COUNT query.
    const hasMore = rows.length > limit;
    const entries = hasMore ? rows.slice(0, limit) : rows;
    const last = entries[entries.length - 1];
    return {
      entries,
      nextCursor: hasMore && last ? encodeCursor(last.createdAt, last.id) : null,
    };
  }

  /**
   * Stream matching entries in fixed-size batches WITHOUT accumulating
   * them: each `for await` iteration receives one page and the page is
   * released on the next. Designed for the admin's NDJSON export, which
   * must never hold the full result set in memory.
   *
   * The filter is captured once at iterator creation ("fixed query
   * boundary") — late-bound caller mutation can't widen an in-flight
   * export. `maxRows` is a hard safety cap; iteration stops at it.
   *
   * Failures surface as a rejection from the batch query — the caller
   * (export endpoint) is responsible for recording the failure audit
   * entry and writing an error trailer.
   */
  iterate(opts: {
    filter?: AuditQuery;
    batchSize?: number;
    maxRows?: number;
  } = {}): AsyncIterableIterator<AuditEntry[]> {
    // Snapshot the filter now; object identity is frozen via a shallow
    // copy plus frozen Date bounds (Dates aren't frozen, but callers
    // pass parsed-query Dates they never touch again).
    const filter: AuditQuery = { ...(opts.filter ?? {}) };
    const batchSize = clampLimit(opts.batchSize, 500);
    const maxRows = opts.maxRows ?? 100_000;
    const audit = this;
    let cursor: AuditCursor | null = null;
    let emitted = 0;
    let done = false;

    const next = async (): Promise<IteratorResult<AuditEntry[]>> => {
      if (done || emitted >= maxRows) { return { value: undefined as any, done: true }; }
      const remaining = maxRows - emitted;
      const page = await audit.queryPage({
        filter,
        cursor: cursor ?? undefined,
        limit: Math.min(batchSize, remaining),
      });
      if (page.entries.length === 0) {
        done = true;
        return { value: undefined as any, done: true };
      }
      cursor = page.nextCursor;
      emitted += page.entries.length;
      if (!page.nextCursor || emitted >= maxRows) { done = true; }
      return { value: page.entries, done: false };
    };

    // Both properties live on ONE object — `for await` grabs the
    // iterator via [Symbol.asyncIterator]() then calls .next() on the
    // returned value, so a method-shorthand that referenced `this` from
    // a different receiver would lose the next() binding.
    const iterator: AsyncIterableIterator<AuditEntry[]> = {
      next,
      [Symbol.asyncIterator]() { return iterator; },
    };
    return iterator;
  }

  /** Drop entries older than `before`. Returns the number of rows removed. */
  async prune(before: Date): Promise<number> {
    const result = await this.db
      .delete(this.audit)
      .where(lt(this.audit.createdAt, before));
    return affectedRows(result);
  }
}

/** Clamp a page/batch size into a sane range; non-finite → fallback. */
export function clampLimit(value: number | undefined, fallback: number): number {
  if (value === undefined || !Number.isFinite(value)) { return fallback; }
  return Math.max(1, Math.min(500, Math.floor(value)));
}

/**
 * Keyset "strictly older" predicate for DESC (createdAt, id) ordering:
 *
 *   (createdAt < t) OR (createdAt = t AND id < i)
 *
 * The `sql` branch only covers the same-timestamp tie-break, where id
 * ordering is plain lexicographic on both sqlite text and pg varchar.
 */
function orTupleOlder(createdAtCol: any, idCol: any, t: Date, id: string): SQL {
  return or(
    lt(createdAtCol, t),
    and(eq(createdAtCol, t), sql`${idCol} < ${id}`),
  ) as SQL;
}
