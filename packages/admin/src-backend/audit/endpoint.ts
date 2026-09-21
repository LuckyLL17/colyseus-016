/**
 * Audit-specific read endpoints:
 *
 *   GET  /admin-api/audit/query         — filtered, keyset-paginated rows
 *   GET  /admin-api/audit/export        — streaming NDJSON/CSV export
 *
 * Both gate on the `list` policy of the `adminAudit` resource (admin by
 * default) and run every returned row through the permission-driven
 * redactor. They deliberately do NOT go through the generic CRUD list:
 * that endpoint speaks offset pagination + refine's filter dialect,
 * while incident review needs operator/action filters, stable keyset
 * paging under concurrent inserts, and — for export — fixed boundaries
 * with bounded memory.
 *
 * The export:
 *   1. parses + validates the window once (fixed query boundary);
 *   2. writes an `audit.export` row BEFORE streaming (status pending);
 *   3. pulls batches of AUDIT_EXPORT_BATCH rows through `audit.iterate`,
 *      redacts, serializes and flushes each batch (never whole payload);
 *   4. writes a second `audit.export` row recording success (rows/flushed
 *      bytes) or failure (error), best-effort via the audit service.
 */
import { createEndpoint, type Endpoint } from '@colyseus/core';
import {
  decodeAuditCursor,
  AUDIT_MAX_LIMIT,
  AUDIT_EXPORT_BATCH,
  type AuditQuery,
  type Role,
} from '@colyseus/database';
import { guard, type EndpointContext } from '../internal/context.js';
import { errorResponse } from '../internal/http.js';
import { resolveRedactRules, redactAuditRow, type RedactRule } from './redactor.js';
import { parseAuditParams, AuditParamError } from './params.js';
import {
  csvHeader, exportContentType, exportFilename, parseExportFormat, serializeBatch,
} from './export-format.js';

const AUDIT_RESOURCE = 'adminAudit';

/**
 * Resolve the effective redaction rules for this deployment. Resource
 * definitions can extend the built-in list via `audit.redactFields`
 * (see ResourceDefinition); the credential denylist can't be relaxed.
 */
function redactionRules(ctx: EndpointContext): RedactRule[] {
  const custom: RedactRule[] = [];
  for (const [resourceName, def] of Object.entries(ctx.resources)) {
    for (const rule of def.audit?.redactFields ?? []) {
      // Rules declared on a resource definition are scoped to that
      // resource's audit rows unless the rule names one explicitly.
      custom.push({ resource: resourceName, ...rule });
    }
  }
  return resolveRedactRules(custom);
}

async function viewerRole(ctx: EndpointContext, reqCtx: any): Promise<Role | null> {
  const userId = await ctx.resolveUserId({ getHeader: reqCtx.getHeader });
  if (!userId) { return null; }
  return ctx.database.moderation.getRole(userId);
}

// ---------------------------------------------------------------------------
// GET /admin-api/audit/query
// ---------------------------------------------------------------------------

export function auditQueryEndpoint(ctx: EndpointContext): Endpoint {
  return createEndpoint(`${ctx.apiPath}/audit/query`, { method: 'GET' }, async (reqCtx) => {
    // guard() also emits the stale-cookie 403 self-heal used elsewhere.
    const denied = await guard(ctx, reqCtx, 'list', AUDIT_RESOURCE);
    if (denied) { return denied; }

    let parsed;
    try {
      parsed = parseAuditParams(reqCtx.query);
    } catch (err) {
      if (err instanceof AuditParamError) { return errorResponse(400, err.message); }
      throw err;
    }

    let cursor: ReturnType<typeof decodeAuditCursor> = null;
    const rawCursor = reqCtx.query?.cursor;
    if (typeof rawCursor === 'string' && rawCursor.length > 0) {
      cursor = decodeAuditCursor(rawCursor);
      if (!cursor) { return errorResponse(400, 'invalid cursor'); }
    }
    const rawLimit = Number(reqCtx.query?.limit ?? 50);
    // Clamp at the edge; the service also clamps, but validating here
    // keeps the documented contract (1..AUDIT_MAX_LIMIT) honest.
    const limit = Number.isFinite(rawLimit)
      ? Math.min(Math.max(Math.trunc(rawLimit), 1), AUDIT_MAX_LIMIT)
      : 50;

    const role = (await viewerRole(ctx, reqCtx))!;
    const rules = redactionRules(ctx);
    const page = await ctx.database.audit.query({ ...parsed.filter, cursor, limit });

    return {
      entries: page.entries.map((row) => redactAuditRow(row, role, rules)),
      nextCursor: page.nextCursor,
    };
  });
}

// ---------------------------------------------------------------------------
// GET /admin-api/audit/export — streaming
// ---------------------------------------------------------------------------

export function auditExportEndpoint(ctx: EndpointContext): Endpoint {
  return createEndpoint(`${ctx.apiPath}/audit/export`, { method: 'GET' }, async (reqCtx) => {
    const denied = await guard(ctx, reqCtx, 'list', AUDIT_RESOURCE);
    if (denied) { return denied; }

    let parsed;
    try {
      parsed = parseAuditParams(reqCtx.query, { requireWindow: true });
    } catch (err) {
      if (err instanceof AuditParamError) { return errorResponse(400, err.message); }
      throw err;
    }

    const format = parseExportFormat(typeof reqCtx.query?.format === 'string' ? reqCtx.query.format : undefined);
    const operatorId = await ctx.resolveUserId({ getHeader: reqCtx.getHeader });
    const role = (await viewerRole(ctx, reqCtx))!;
    const rules = redactionRules(ctx);
    const { filter, raw } = parsed;
    const after = filter.createdAfter!;
    const before = filter.createdBefore!;

    // --- Fixed boundary captured. Record the export BEFORE reading so a
    // crash mid-stream still leaves a "someone started an export over
    // exactly this window" trail (no completion row follows).
    const startedAt = new Date();
    await tryRecordExport(ctx, {
      operatorId, action: 'audit.export', resource: AUDIT_RESOURCE, targetId: null,
      payload: {
        status: 'started', format,
        filter: stableFilter(filter, raw),
        startedAt: startedAt.toISOString(),
      },
    });

    const encoder = new TextEncoder();
    let rowsWritten = 0;
    let bytesWritten = 0;

    // Pull-driven stream: each `pull()` enqueues at most one serialized
    // batch, so the consumer (HTTP socket) sets the pace and at most one
    // batch of rows + one chunk string are ever resident. The iterator
    // captures the fixed `filter` for its whole lifetime — batches can't
    // drift onto rows inserted/pruned after the export started.
    const iterator = ctx.database.audit.iterate(
      { ...filter, action: excludeExportAction(filter.action) },
      { batchSize: AUDIT_EXPORT_BATCH },
    )[Symbol.asyncIterator]();
    const unfiltered = filter.action === undefined;

    let headerWritten = false;
    let finished = false;

    const stream = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          if (!headerWritten) {
            headerWritten = true;
            // UTF-8 BOM for CSV so Excel detects UTF-8; NDJSON stays clean.
            if (format === 'csv') {
              controller.enqueue(encoder.encode('﻿'));
              controller.enqueue(encoder.encode(csvHeader()));
            }
          }

          const { value: batch, done } = await iterator.next();
          if (done) {
            if (!finished) {
              finished = true;
              await tryRecordExport(ctx, {
                operatorId, action: 'audit.export', resource: AUDIT_RESOURCE, targetId: null,
                payload: {
                  status: 'success', format,
                  filter: stableFilter(filter, raw),
                  startedAt: startedAt.toISOString(),
                  finishedAt: new Date().toISOString(),
                  rows: rowsWritten,
                  bytes: bytesWritten,
                },
              });
              ctx.logger?.info?.(
                { operatorId, rows: rowsWritten, bytes: bytesWritten, format },
                '[admin] audit export complete',
              );
            }
            controller.close();
            return;
          }

          // Drop the export's own started/success/failed rows when the
          // action filter couldn't exclude them in SQL.
          const visible = unfiltered
            ? batch.filter((r) => !isExportBookkeeping(r))
            : batch;
          rowsWritten += visible.length;
          const redacted = visible.map((row) => redactAuditRow(row, role, rules));
          const chunk = serializeBatch(redacted, format);
          if (chunk.length > 0) {
            const bytes = encoder.encode(chunk);
            bytesWritten += bytes.byteLength;
            controller.enqueue(bytes);
          }
        } catch (err: any) {
          // Response headers may already be flushed — best-effort status
          // row + log are the durable record of failure.
          ctx.logger?.error?.({ err: err?.message ?? String(err) }, 'audit export failed');
          await tryRecordExport(ctx, {
            operatorId, action: 'audit.export', resource: AUDIT_RESOURCE, targetId: null,
            payload: {
              status: 'failed', format,
              filter: stableFilter(filter, raw),
              startedAt: startedAt.toISOString(),
              finishedAt: new Date().toISOString(),
              rowsBeforeFailure: rowsWritten,
              error: err?.message ?? String(err),
            },
          });
          controller.error(err instanceof Error ? err : new Error(String(err)));
        }
      },
      cancel() {
        // Client disconnected. Not a failure worth alarming about, but
        // record it — partial exports of sensitive data should be
        // traceable too.
        finished = true;
        ctx.logger?.warn?.(
          { operatorId, rows: rowsWritten },
          '[admin] audit export aborted (client disconnected)',
        );
        void iterator.return?.().catch(() => {});
        void tryRecordExport(ctx, {
          operatorId, action: 'audit.export', resource: AUDIT_RESOURCE, targetId: null,
          payload: {
            status: 'aborted', format,
            filter: stableFilter(filter, raw),
            startedAt: startedAt.toISOString(),
            finishedAt: new Date().toISOString(),
            rowsBeforeAbort: rowsWritten,
          },
        });
      },
    });

    return new Response(stream as any, {
      status: 200,
      headers: {
        'content-type': exportContentType(format),
        'content-disposition': `attachment; filename="${exportFilename(format, after, before)}"`,
        // Explicitly no content-length: the row count is intentionally
        // not COUNT-ed up front (that would scan the full window).
        'cache-control': 'no-store',
      },
    });
  });
}

/**
 * Fire-and-forget export self-audit. The export must not fail because
 * its own bookkeeping insert failed.
 */
async function tryRecordExport(
  ctx: EndpointContext,
  entry: Parameters<EndpointContext['database']['audit']['record']>[0],
): Promise<void> {
  try {
    await ctx.database.audit.record(entry);
  } catch (err) {
    ctx.logger?.warn?.({ err }, '[admin] audit export bookkeeping insert failed');
  }
}

/** Canonical, JSON-stable copy of the filters used by an export. */
function stableFilter(
  filter: AuditQuery,
  raw: Record<string, string>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(filter)) {
    out[k] = v instanceof Date ? v.toISOString() : v;
  }
  out._raw = raw;
  return out;
}

/**
 * Pin the export's own bookkeeping action out of the scanned rows. The
 * AuditService only supports positive action lists (IN), so when the
 * caller didn't narrow by action we can't express "everything except
 * audit.export" at the SQL level — keep the action filter unset there
 * and drop the self-rows in the batch loop.
 */
const EXPORT_ACTION = 'audit.export';

function isExportBookkeeping(row: { action: string }): boolean {
  return row.action === EXPORT_ACTION;
}
function excludeExportAction(action: AuditQuery['action']): string[] | undefined {
  const list = action == null
    ? undefined
    : Array.isArray(action) ? action : [action];
  // Caller narrowed to other actions → SQL already excludes self-rows.
  if (list && !list.includes(EXPORT_ACTION)) { return list; }
  return undefined;
}
