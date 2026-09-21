/**
 * Admin audit-log query API. Three routes, deliberately scoped to the
 * audit log rather than a generic reports surface:
 *
 *   GET  /admin-api/audit/entries
 *        Cursor-paginated, filtered query (operator/resource/action/
 *        target/time-window). Returns masked rows — field visibility
 *        follows the viewer's live role.
 *
 *   GET  /admin-api/audit/export
 *        Streaming NDJSON export of the SAME filtered query. The
 *        boundary (parsed filter + server-side `until` cap) is fixed
 *        before the first byte; rows are read in batches through
 *        AuditService.iterate() and serialized one at a time, so the
 *        full result set never sits in memory. Every export writes an
 *        audit.export_completed / audit.export_failed row recording the
 *        boundary, row count, and disposition.
 *
 *   GET  /admin-api/audit/exports
 *        Recent export-status records (the audit.export_* entries) for
 *        the "Recent exports" panel on the audit page.
 *
 * RBAC: all three gate on the synthetic 'adminAudit' resource (`list`
 * for queries, `read` for export) so a deployment can widen audit
 * access to mods via policies — redaction then automatically masks
 * whatever that role may not see.
 */
import { createEndpoint, type Endpoint } from '@colyseus/core';
import type { Role } from '@colyseus/database';
import type { EndpointContext } from '../internal/context.js';
import { guard } from '../internal/context.js';
import { errorResponse, json } from '../internal/http.js';
import {
  parseAuditFilter, serializeAuditFilter,
} from './filters.js';
import {
  builtInRules, mergeRules, redactAuditEntry,
  serializeAuditEntry, type RedactionContext, type RedactRole,
} from './redact.js';
import { recordAudit, resolveOperator } from './record.js';

const RESOURCE = 'adminAudit';
const EXPORT_BATCH = 500;
/** Default safety cap regardless of the (already window-capped) filter. */
const DEFAULT_EXPORT_MAX_ROWS = 100_000;
/** Recent-exports panel size. */
const RECENT_EXPORTS_LIMIT = 25;

// ---------------------------------------------------------------------------
// Shared request plumbing
// ---------------------------------------------------------------------------

/**
 * Resolve the viewer's redaction context for one request. The role is
 * the LIVE role read from the DB (never a cached claim), so a demoted
 * viewer loses field visibility on their very next request.
 *
 * When RBAC is disabled (dev mode, same convention as `guard()`), the
 * viewer is treated as the most-permissive role — the audit rows are
 * local dev data and the request already bypassed authentication.
 */
async function redactionContext(
  ctx: EndpointContext,
  reqCtx: any,
): Promise<RedactionContext> {
  let role: Role = 'admin';
  if (ctx.enforceRbac) {
    const userId = await ctx.resolveUserId({ getHeader: reqCtx.getHeader });
    if (userId) { role = await ctx.database.moderation.getRole(userId); }
  }
  const rules = mergeRules(builtInRules(), ctx.auditRedactRules);
  return { role: role as RedactRole, rules };
}

function parsePagination(q: Record<string, unknown>): { limit: number; cursor?: string } | Response {
  let limit = 100;
  if (q.limit !== undefined) {
    const n = Number(q.limit);
    if (!Number.isInteger(n) || n < 1 || n > 500) {
      return errorResponse(400, 'limit must be an integer between 1 and 500');
    }
    limit = n;
  }
  const cursor = typeof q.cursor === 'string' && q.cursor.length > 0 ? q.cursor : undefined;
  return { limit, cursor };
}

// ---------------------------------------------------------------------------
// GET /audit/entries — cursor-paginated filtered query
// ---------------------------------------------------------------------------

export function auditEntriesEndpoint(ctx: EndpointContext): Endpoint {
  return createEndpoint(`${ctx.apiPath}/audit/entries`, { method: 'GET' }, async (reqCtx) => {
    const denied = await guard(ctx, reqCtx, 'list', RESOURCE);
    if (denied) { return denied; }

    const parsedFilter = parseAuditFilter(reqCtx.query ?? {});
    if ('error' in parsedFilter) { return errorResponse(400, parsedFilter.error); }

    const page = parsePagination(reqCtx.query ?? {});
    if (page instanceof Response) { return page; }

    let result;
    try {
      result = await ctx.database.audit.queryPage({
        filter: parsedFilter.filter,
        cursor: page.cursor,
        limit: page.limit,
      });
    } catch (err) {
      // decodeCursor throws on malformed/tampered cursors.
      if (err instanceof Error && /cursor/i.test(err.message)) {
        return errorResponse(400, err.message);
      }
      throw err;
    }

    const redaction = await redactionContext(ctx, reqCtx);

    let anyRedacted = false;
    const data = result.entries.map((entry) => {
      const { entry: masked, redactedFields } = redactAuditEntry(entry, redaction);
      if (redactedFields.length > 0) { anyRedacted = true; }
      return { ...serializeAuditEntry(masked), _redacted: redactedFields };
    });

    return json({
      data,
      cursor: result.nextCursor,
      ...(anyRedacted ? { redacted: true } : {}),
    });
  });
}

// ---------------------------------------------------------------------------
// GET /audit/export — streaming NDJSON export
// ---------------------------------------------------------------------------

export function auditExportEndpoint(ctx: EndpointContext): Endpoint {
  return createEndpoint(`${ctx.apiPath}/audit/export`, { method: 'GET' }, async (reqCtx) => {
    const denied = await guard(ctx, reqCtx, 'read', RESOURCE);
    if (denied) { return denied; }

    const redaction = await redactionContext(ctx, reqCtx);

    const parsedFilter = parseAuditFilter(reqCtx.query ?? {});
    if ('error' in parsedFilter) { return errorResponse(400, parsedFilter.error); }

    const operatorId = await resolveOperator(ctx, reqCtx);

    // Fix the boundary BEFORE streaming: the upper bound is pinned to
    // "now" server-side so pages read during a long export can't creep
    // forward into rows written after the export started. The parsed
    // filter object is then frozen into the iterator + boundary record.
    const startedAt = new Date();
    const until = parsedFilter.filter.until ?? startedAt;
    const fixedFilter = Object.freeze({ ...parsedFilter.filter, until });
    // Self-describing boundary written as line 1 of the NDJSON file.
    const boundary = { ...serializeAuditFilter(fixedFilter) };

    const maxRows = ctx.auditExportMaxRows ?? DEFAULT_EXPORT_MAX_ROWS;
    const iterator = ctx.database.audit.iterate({
      filter: fixedFilter,
      batchSize: EXPORT_BATCH,
      maxRows,
    });

    const encoder = new TextEncoder();
    let rowCount = 0;
    let settled = false;

    /**
     * Record the export disposition EXACTLY ONCE. The audit insert is
     * awaited on stream completion (success path) and on first failure
     * (error path). Client disconnects count as failure.
     */
    const recordDisposition = async (status: 'completed' | 'failed', reason?: string) => {
      if (settled) { return; }
      settled = true;
      await recordAudit(ctx, {
        operatorId,
        action: status === 'completed' ? 'audit.export_completed' : 'audit.export_failed',
        resource: RESOURCE,
        payload: {
          boundary,
          rows: rowCount,
          truncated: rowCount >= maxRows,
          ...(reason ? { reason } : {}),
        },
      });
    };

    const stream = new ReadableStream<Uint8Array>({
      async start(controller) {
        const enqueue = (obj: unknown) => {
          controller.enqueue(encoder.encode(`${JSON.stringify(obj)}\n`));
        };
        // Line 1: self-describing boundary. Anyone holding the file can
        // see which query produced it and when.
        enqueue({ type: 'boundary', exportedAt: startedAt.toISOString(), filter: boundary });

        try {
          for await (const batch of iterator) {
            // One serialized line per row — never the batch, never the
            // whole result set.
            for (const entry of batch) {
              const { entry: masked, redactedFields } = redactAuditEntry(entry, redaction);
              enqueue({
                type: 'entry',
                ...serializeAuditEntry(masked),
                ...(redactedFields.length > 0 ? { _redacted: redactedFields } : {}),
              });
              rowCount++;
            }
          }
          enqueue({
            type: 'result',
            status: 'completed',
            rows: rowCount,
            truncated: rowCount >= maxRows,
          });
          controller.close();
          await recordDisposition('completed');
        } catch (err) {
          const reason = err instanceof Error ? err.message : String(err);
          // Best-effort error trailer — the client may already be gone.
          try {
            enqueue({ type: 'result', status: 'failed', rows: rowCount, error: reason });
            controller.close();
          } catch {
            try { controller.error(err); } catch { /* already closed */ }
          }
          await recordDisposition('failed', reason);
        }
      },
      cancel() {
        // Client disconnected mid-stream. Mark failure without trying
        // to enqueue a trailer (the sink is gone).
        void recordDisposition('failed', 'client disconnected');
      },
    });

    const filename = `audit-${startedAt.toISOString().replace(/[:.]/g, '-')}.ndjson`;
    return new Response(stream as any, {
      status: 200,
      headers: {
        'content-type': 'application/x-ndjson; charset=utf-8',
        'content-disposition': `attachment; filename="${filename}"`,
        'cache-control': 'no-store',
        // No content-length — chunked; that's what makes it a stream.
        'connection': 'close',
      },
    });
  });
}

// ---------------------------------------------------------------------------
// GET /audit/exports — recent export-status records
// ---------------------------------------------------------------------------

export function auditExportsEndpoint(ctx: EndpointContext): Endpoint {
  return createEndpoint(`${ctx.apiPath}/audit/exports`, { method: 'GET' }, async (reqCtx) => {
    const denied = await guard(ctx, reqCtx, 'list', RESOURCE);
    if (denied) { return denied; }

    const rows = await ctx.database.audit.list({
      actions: ['audit.export_completed', 'audit.export_failed'],
      limit: RECENT_EXPORTS_LIMIT,
    });

    const data = rows.map((entry) => ({
      id: entry.id,
      operator_id: entry.operatorId,
      operator_label: entry.operatorLabel ?? null,
      action: entry.action,
      created_at: entry.createdAt instanceof Date ? entry.createdAt.toISOString() : entry.createdAt,
      // Export-status payloads (boundary, rows, error) are operational
      // metadata, not user data — shown in the clear to anyone who can
      // list the audit log.
      ...(entry.payload ?? {}),
    }));

    return json({ data });
  });
}
