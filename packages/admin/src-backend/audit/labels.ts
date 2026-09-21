/**
 * Write-time label snapshots for audit rows.
 *
 * Audit entries store ids (operatorId, resource, targetId), but ids are
 * useless after the referenced row is deleted: a banned user that's
 * later purged, a config that's removed, a room that's disposed. The
 * audit page must still show *who* did *what to which thing*, so the
 * admin captures a best-effort human label at write time and stores it
 * alongside the id:
 *
 *   operatorLabel  — the acting operator's email / display name
 *   resourceLabel  — the catalog label of the affected collection
 *   targetLabel    — a name/key/email identifying the affected row
 *
 * Everything here is BEST EFFORT: any lookup failure resolves to null
 * and the audit write proceeds. Labels never gate the mutation they
 * describe.
 */
import { eq } from 'drizzle-orm';
import type { EndpointContext } from '../internal/context.js';
import { castPk, isTableColumn, pkColumns, type TableColumn } from '../internal/helpers.js';

/** Columns that conventionally hold a human-readable row label, in priority order. */
const LABEL_COLUMNS = [
  'display_name', 'displayName',
  'name', 'title', 'label',
  'key',
  'email',
  'username', 'handle', 'nickname',
  'anonymous_id', 'anonymousId',
];

/** Cap so a malformed/unbounded text column can't bloat the audit table. */
const MAX_LABEL_LEN = 200;

export function clampLabel(value: unknown): string | null {
  if (value === null || value === undefined) { return null; }
  const s = String(value).trim();
  if (s.length === 0) { return null; }
  return s.length > MAX_LABEL_LEN ? `${s.slice(0, MAX_LABEL_LEN - 1)}…` : s;
}

/**
 * Pick a label from an already-loaded row snapshot. Checks the
 * conventional label columns first, then falls back to the first
 * short-ish text value so custom tables still get something useful.
 * Accepts both SQL-keyed (snake_case) and JS-keyed snapshots.
 */
export function labelFromRow(
  row: Record<string, any> | null | undefined,
  cfgColumns?: TableColumn[],
): string | null {
  if (!row || typeof row !== 'object') { return null; }

  for (const name of LABEL_COLUMNS) {
    const hit = clampLabel(row[name]);
    if (hit) { return hit; }
  }

  // Fallback: first short text column with a value. Skips ids, json,
  // dates and long blobs.
  const textCols = new Set(
    (cfgColumns ?? [])
      .filter((c) => /^(text|varchar|char)/i.test(c.getSQLType?.() ?? '') && !c.primary)
      .map((c) => c.name),
  );
  for (const [k, v] of Object.entries(row)) {
    if (textCols.has(k)) {
      const hit = clampLabel(v);
      if (hit && hit.length <= 80) { return hit; }
    }
  }
  return null;
}

/** The configured UI label for a resource, falling back to its canonical name. */
export function resourceLabelOf(ctx: EndpointContext, resource: string): string {
  return ctx.resources[resource]?.label ?? resource;
}

/** Map of JS-key → drizzle column for the SQL names requested. */
function columnsBySqlName(table: any, sqlNames: ReadonlyArray<string>): Record<string, any> {
  const wanted = new Set(sqlNames);
  const out: Record<string, any> = {};
  for (const [jsKey, col] of Object.entries(table)) {
    if (isTableColumn(col) && wanted.has(col.name)) { out[jsKey] = col; }
  }
  return out;
}

/**
 * Best-effort operator label: read the users row (when the table exists)
 * and pick email → displayName → anonymousId. Null on any failure.
 */
export async function captureOperatorLabel(
  ctx: EndpointContext,
  operatorId: string | null | undefined,
): Promise<string | null> {
  if (!operatorId) { return null; }
  const users = ctx.tables.users;
  if (!users) { return null; }
  try {
    const projection = columnsBySqlName(users, ['email', 'display_name', 'anonymous_id']);
    if (Object.keys(projection).length === 0) { return null; }
    const idCol = (users as any).id;
    if (!isTableColumn(idCol)) { return null; }
    const rows = await ctx.database.drizzle
      .select(projection)
      .from(users)
      .where(eq(idCol as any, castPk(operatorId, idCol as TableColumn)))
      .limit(1);
    const row = rows?.[0];
    if (!row) { return null; }
    return clampLabel(row.email ?? row.displayName ?? row.anonymousId);
  } catch {
    return null;
  }
}

/**
 * Best-effort target label. Prefer a row snapshot the caller already
 * holds (the deleted row / before-after pair) — it works even when the
 * row no longer exists, which is exactly the case labels exist for.
 * Only fall back to a live PK lookup when no hint produced a label
 * (workflow endpoints that didn't load the row).
 */
export async function captureTargetLabel(
  ctx: EndpointContext,
  resource: string,
  targetId: string | null | undefined,
  rowHints: Array<Record<string, any> | null | undefined> = [],
): Promise<string | null> {
  if (!targetId) { return null; }
  const table = ctx.tables[resource];

  if (!table) {
    // Synthetic resource (rooms/auth) — hints are the only source.
    for (const hint of rowHints) {
      const hit = labelFromRow(hint);
      if (hit) { return hit; }
    }
    return null;
  }

  const cfg = ctx.getTableConfig(table);
  for (const hint of rowHints) {
    const hit = labelFromRow(hint, cfg.columns);
    if (hit) { return hit; }
  }

  try {
    const pk = pkColumns(cfg)[0];
    if (!pk) { return null; }
    const projection = columnsBySqlName(table, [pk.name, ...LABEL_COLUMNS]);
    const pkJsKey = Object.entries(table)
      .find(([, col]) => isTableColumn(col) && (col as TableColumn).name === pk.name)?.[0];
    if (!pkJsKey || !projection[pkJsKey]) { return null; }
    const rows = await ctx.database.drizzle
      .select(projection)
      .from(table)
      .where(eq(projection[pkJsKey] as any, castPk(targetId, pk)))
      .limit(1);
    const row = rows?.[0];
    if (!row) { return null; }
    return labelFromRow(row, cfg.columns);
  } catch {
    return null;
  }
}
