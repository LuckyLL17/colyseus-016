/**
 * Shared audit-write helpers for admin endpoints.
 *
 * `recordAudit()` is the single write path every endpoint should use:
 * it resolves the operator once, captures the three context labels
 * (operator/resource/target — see ./labels.ts), and swallows failures
 * so an audit insert can never break the mutation it describes.
 *
 * The label lookups are best-effort and skipped whenever the caller
 * already hands us the relevant snapshot (CRUD endpoints hold the
 * deleted/before/after rows in memory), keeping the happy path to a
 * single INSERT.
 */
import type { AuditAction } from '@colyseus/database';
import type { EndpointContext } from '../internal/context.js';
import {
  captureOperatorLabel, captureTargetLabel, resourceLabelOf,
} from './labels.js';

export interface RecordAuditInput {
  operatorId?: string | null;
  action: AuditAction | string;
  resource: string;
  targetId?: string | null;
  /** Already-loaded rows to derive the target label from (deleted row first). */
  targetRowHints?: Array<Record<string, any> | null | undefined>;
  /** Skip the target lookup and use this label (synthetic resources, rooms). */
  targetLabel?: string | null;
  payload?: unknown;
}

/**
 * Write one audit entry with context labels resolved. Never throws —
 * failures go to the admin logger as `audit log write failed`, matching
 * the long-standing `tryAudit` contract.
 */
export async function recordAudit(
  ctx: EndpointContext,
  input: RecordAuditInput,
): Promise<void> {
  try {
    const operatorId = input.operatorId ?? null;
    const [operatorLabel, targetLabel] = await Promise.all([
      captureOperatorLabel(ctx, operatorId),
      input.targetLabel !== undefined
        ? Promise.resolve(input.targetLabel)
        : captureTargetLabel(ctx, input.resource, input.targetId ?? null, input.targetRowHints ?? []),
    ]);
    await ctx.database.audit.record({
      operatorId,
      operatorLabel,
      action: input.action,
      resource: input.resource,
      resourceLabel: resourceLabelOf(ctx, input.resource),
      targetId: input.targetId ?? null,
      targetLabel,
      payload: input.payload,
    });
  } catch (err: any) {
    ctx.logger?.error?.(
      { err: err?.message ?? String(err) },
      'audit log write failed',
    );
  }
}

/** Resolve the caller's operator id from a better-call request context. */
export async function resolveOperator(
  ctx: EndpointContext,
  reqCtx: any,
): Promise<string | null> {
  return (await ctx.resolveUserId({ getHeader: reqCtx.getHeader })) ?? null;
}

/**
 * Update-variant: computes the column-level diff via the database
 * AuditService (`{ changes: { col: { before, after } } }`) and resolves
 * the same context labels as `recordAudit`. The post-update snapshot
 * is the preferred target hint; the before snapshot is the fallback.
 */
export async function recordAuditUpdate(
  ctx: EndpointContext,
  input: Omit<RecordAuditInput, 'action' | 'payload'> & {
    before: Record<string, any> | null | undefined;
    after: Record<string, any>;
  },
): Promise<void> {
  try {
    const operatorId = input.operatorId ?? null;
    const [operatorLabel, targetLabel] = await Promise.all([
      captureOperatorLabel(ctx, operatorId),
      input.targetLabel !== undefined
        ? Promise.resolve(input.targetLabel)
        : captureTargetLabel(ctx, input.resource, input.targetId ?? null, input.targetRowHints ?? []),
    ]);
    await ctx.database.audit.recordUpdate({
      operatorId,
      operatorLabel,
      resource: input.resource,
      resourceLabel: resourceLabelOf(ctx, input.resource),
      targetId: input.targetId ?? null,
      targetLabel,
      before: input.before,
      after: input.after,
    });
  } catch (err: any) {
    ctx.logger?.error?.(
      { err: err?.message ?? String(err) },
      'audit log write failed',
    );
  }
}
