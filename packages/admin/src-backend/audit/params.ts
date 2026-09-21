/**
 * Query-string parsing/validation for the audit query and export
 * endpoints. Both accept the same filter vocabulary, so parsing lives
 * here once:
 *
 *   operatorId    (repeatable / comma list) — first value used
 *   resource      target table / domain
 *   action        repeatable / comma list (OR within, AND with others)
 *   targetId      affected row id
 *   createdAfter  ISO 8601, inclusive
 *   createdBefore ISO 8601, inclusive
 *
 * The parsed result is a *fixed boundary*: the export captures it once
 * and reuses the exact same AuditQuery for every batch, so rows
 * inserted or pruned mid-stream can't change what the export covers.
 */
import type { AuditQuery } from '@colyseus/database';
import { AUDIT_MAX_WINDOW_MS } from '@colyseus/database';

export interface ParsedAuditParams {
  filter: AuditQuery;
  /** Echoed verbatim into the export audit entry / response headers. */
  raw: Record<string, string>;
}

export class AuditParamError extends Error {
  status = 400;
  constructor(message: string) { super(message); }
}

function firstString(raw: unknown): string | undefined {
  if (Array.isArray(raw)) { return typeof raw[0] === 'string' ? raw[0] : undefined; }
  return typeof raw === 'string' && raw.length > 0 ? raw : undefined;
}

function listValues(raw: unknown): string[] | undefined {
  const values: string[] = [];
  const push = (v: unknown) => {
    if (typeof v === 'string') {
      for (const part of v.split(',')) {
        const t = part.trim();
        if (t.length > 0) { values.push(t); }
      }
    }
  };
  if (Array.isArray(raw)) { for (const v of raw) { push(v); } }
  else { push(raw); }
  return values.length > 0 ? values : undefined;
}

function parseDate(value: string | undefined, field: string): Date | undefined {
  if (value === undefined) { return undefined; }
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) {
    throw new AuditParamError(`${field} must be an ISO 8601 date`);
  }
  return d;
}

/**
 * Parse + validate audit filters. `requireWindow` (exports) enforces a
 * finite, width-capped time window — an unbounded export over an
 * append-only table is an operational incident waiting to happen.
 */
export function parseAuditParams(
  query: Record<string, any> | undefined,
  opts: { requireWindow?: boolean } = {},
): ParsedAuditParams {
  const q = query ?? {};
  const operatorId = firstString(q.operatorId) ?? firstString(q.operator_id);
  const resource = firstString(q.resource);
  const targetId = firstString(q.targetId) ?? firstString(q.target_id);
  const actions = listValues(q.action) ?? listValues(q.actions);
  const createdAfter = parseDate(firstString(q.createdAfter) ?? firstString(q.created_after), 'createdAfter');
  const createdBefore = parseDate(firstString(q.createdBefore) ?? firstString(q.created_before), 'createdBefore');

  if (createdAfter && createdBefore && createdAfter > createdBefore) {
    throw new AuditParamError('createdAfter must not be later than createdBefore');
  }

  if (opts.requireWindow) {
    if (!createdAfter || !createdBefore) {
      throw new AuditParamError('export requires both createdAfter and createdBefore');
    }
    if (createdBefore.getTime() - createdAfter.getTime() > AUDIT_MAX_WINDOW_MS) {
      throw new AuditParamError(`export window must not exceed ${AUDIT_MAX_WINDOW_MS} ms`);
    }
  }

  const filter: AuditQuery = {};
  if (operatorId) { filter.operatorId = operatorId; }
  if (resource) { filter.resource = resource; }
  if (targetId) { filter.targetId = targetId; }
  if (actions) { filter.action = actions; }
  if (createdAfter) { filter.createdAfter = createdAfter; }
  if (createdBefore) { filter.createdBefore = createdBefore; }

  const raw: Record<string, string> = {};
  for (const [k, v] of Object.entries(q)) {
    if (typeof v === 'string') { raw[k] = v; }
  }
  return { filter, raw };
}
