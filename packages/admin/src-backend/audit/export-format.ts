/**
 * Streaming serializers for audit exports. Two formats:
 *
 *   - ndjson (default): one JSON object per line. Stream-friendly,
 *     trivially splittable for big-data tooling, preserves the nested
 *     payload/snapshot structure losslessly.
 *   - csv: flat columns (payload + snapshot JSON-encoded into cells)
 *     for spreadsheets. RFC-4180 quoting.
 *
 * Serializers are frame builders — they never accumulate rows. The
 * endpoint feeds one redacted batch at a time and writes the returned
 * strings straight to the response, so peak memory is one batch plus
 * one serialized line.
 */
export type AuditExportFormat = 'ndjson' | 'csv';

/** Flat-ish columns emitted in CSV mode; payload/snapshot stay JSON. */
const CSV_COLUMNS = [
  'id', 'created_at', 'operator_id', 'action', 'resource', 'target_id',
  'snapshot', 'payload',
] as const;

export interface ExportRow {
  id: string;
  createdAt: Date | string;
  operatorId: string | null;
  action: string;
  resource: string;
  targetId: string | null;
  payload: unknown;
  snapshot: unknown;
}

/** Structural shape serializeBatch actually reads — AuditEntry satisfies it. */
type SerializableAuditRow = ExportRow;

export function parseExportFormat(raw: string | undefined): AuditExportFormat {
  return raw === 'csv' ? 'csv' : 'ndjson';
}

export function exportContentType(format: AuditExportFormat): string {
  return format === 'csv'
    ? 'text/csv; charset=utf-8'
    : 'application/x-ndjson; charset=utf-8';
}

/** Suggested download filename with the fixed export boundary. */
export function exportFilename(format: AuditExportFormat, after: Date, before: Date): string {
  const stamp = (d: Date) => d.toISOString().replace(/[:.]/g, '-');
  return `audit-${stamp(after)}_${stamp(before)}.${format === 'csv' ? 'csv' : 'ndjson'}`;
}

/** CSV header line (with UTF-8 BOM prefix handled by the caller once). */
export function csvHeader(): string {
  return `${CSV_COLUMNS.join(',')}\n`;
}

function csvCell(value: unknown): string {
  const s = value === null || value === undefined ? '' : String(value);
  // Quote when the cell contains a comma, quote, CR or LF. Inner
  // quotes doubled per RFC 4180.
  if (/[",\r\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

function toFlatCells(row: ExportRow): string[] {
  const created = row.createdAt instanceof Date ? row.createdAt.toISOString() : String(row.createdAt);
  return [
    row.id,
    created,
    row.operatorId ?? '',
    row.action,
    row.resource,
    row.targetId ?? '',
    row.snapshot == null ? '' : JSON.stringify(row.snapshot),
    row.payload == null ? '' : JSON.stringify(row.payload),
  ];
}

/** Serialize one batch into a single chunk. Never throws on data shape. */
export function serializeBatch(rows: ExportRow[], format: AuditExportFormat): string {
  if (format === 'csv') {
    return rows.map((r) => `${toFlatCells(r).map(csvCell).join(',')}\n`).join('');
  }
  return rows.map((r) => JSON.stringify({
    id: r.id,
    created_at: r.createdAt instanceof Date ? r.createdAt.toISOString() : r.createdAt,
    operator_id: r.operatorId,
    action: r.action,
    resource: r.resource,
    target_id: r.targetId,
    snapshot: r.snapshot ?? null,
    payload: r.payload ?? null,
  })).join('\n') + (rows.length > 0 ? '\n' : '');
}
