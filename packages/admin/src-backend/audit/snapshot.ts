/**
 * Audit snapshots — reduced, deletion-proof context captured *at record
 * time* from the row being mutated.
 *
 * The audit log must answer "who/what was this entry about?" even after
 * the target row — or its whole resource table — is deleted. Joining the
 * live resource at read time can't do that, so every mutation stores a
 * small `snapshot: { label, fields }` next to the full diff `payload`.
 *
 * Only scalar whitelisted fields are captured: the snapshot is a
 * finding-aid for reviewers, not a second copy of the row. Values still
 * pass through the same permission-driven redactor as `payload` on read
 * (see ./redactor.ts), so capturing an email here doesn't leak it to a
 * mod.
 */
import type { AuditSnapshot } from '@colyseus/database';
import type { TableConfig } from '../internal/helpers.js';

/**
 * Candidate label columns in priority order, SQL names. Works across
 * the built-in tables (users.display_name / email, configs.key,
 * leaderboards.name, notes...) without per-resource configuration.
 */
const LABEL_COLUMNS = ['display_name', 'name', 'title', 'key', 'email', 'username', 'handle'];

/**
 * Scalar context fields worth keeping after the row is gone, in the
 * order they render. Identity + state columns only — free-form bodies
 * (the full diff) already live in `payload`.
 */
const CONTEXT_COLUMNS = [
  'email',
  'display_name',
  'username',
  'banned_until',
  'banned_reason',
  'token_version',
  'anonymous',
  'role',
  'value',
  'state',
];

const MAX_LABEL_LEN = 200;
const MAX_FIELD_LEN = 500;

function isScalar(v: unknown): v is string | number | boolean {
  return (typeof v === 'string' && v.length <= MAX_FIELD_LEN)
    || typeof v === 'number'
    || typeof v === 'boolean';
}

/**
 * Build a snapshot from a SQL-keyed row (the shape every CRUD endpoint
 * already has from `sqlKeyedProjection`). Returns null when the row has
 * nothing worth preserving, so callers can store NULL rather than `{}`.
 *
 * `cfg` supplies column metadata — unknown columns on custom tables are
 * still captured if they're in the CONTEXT_COLUMNS whitelist, but
 * arbitrary fields never leak in (keeps snapshot rows bounded).
 */
export function buildSnapshot(
  row: Record<string, unknown> | null | undefined,
  cfg?: TableConfig,
): AuditSnapshot | null {
  if (!row || typeof row !== 'object') { return null; }

  const knownNames = new Set((cfg?.columns ?? []).map((c) => c.name));
  const fields: Record<string, unknown> = {};

  let label: string | null = null;
  for (const candidate of LABEL_COLUMNS) {
    const v = row[candidate];
    if (typeof v === 'string' && v.length > 0) {
      label = v.length > MAX_LABEL_LEN ? `${v.slice(0, MAX_LABEL_LEN - 1)}…` : v;
      break;
    }
  }

  for (const name of CONTEXT_COLUMNS) {
    if (!(name in row)) { continue; }
    if (knownNames.size > 0 && !knownNames.has(name)) { continue; }
    const v = row[name];
    if (v === null || v === undefined) { continue; }
    if (v instanceof Date) {
      fields[name] = v.toISOString();
    } else if (isScalar(v)) {
      fields[name] = v;
    }
  }

  if (label === null && Object.keys(fields).length === 0) { return null; }
  const out: AuditSnapshot = {};
  if (label !== null) { out.label = label; }
  if (Object.keys(fields).length > 0) { out.fields = fields; }
  return out;
}
