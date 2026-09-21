/**
 * Admin audit page — `/audit`.
 *
 * Dedicated surface for incident review:
 *   - filters: operator, resource, action, target, time window
 *   - keyset (cursor) pagination via GET /admin-api/audit/query, so
 *     rows inserted while paging never duplicate or skip
 *   - streaming export (NDJSON/CSV) via GET /admin-api/audit/export;
 *     the browser downloads the response as it arrives — no full
 *     payload is assembled client- or server-side
 *
 * Intentionally NOT a Refine resource page: the generic list speaks
 * offset pagination + the refine filter dialect, while the audit API
 * uses opaque cursors and fixed filter boundaries.
 */
import * as React from 'react';
import { Link } from 'react-router-dom';
import { Download, Loader2, Search } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Empty } from '@/components/ui/empty';
import { Page } from '@/components/ui/page';
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table';
import { AuditActionBadge } from './internals/audit-action-badge';
import { JsonViewer } from './internals/json-viewer';
import { relativeTime, absoluteTime } from './internals/format-cell';
import { API } from '@/lib/runtime-config';
import { cn } from '@/lib/utils';

const PAGE_SIZE = 50;

interface AuditRow {
  id: string;
  operator_id: string | null;
  action: string;
  resource: string;
  target_id: string | null;
  payload: unknown;
  snapshot: { label?: string | null; fields?: Record<string, unknown> } | null;
  created_at: string;
}

interface Filters {
  operatorId: string;
  resource: string;
  action: string;
  targetId: string;
  createdAfter: string;
  createdBefore: string;
}

const EMPTY_FILTERS: Filters = {
  operatorId: '', resource: '', action: '', targetId: '',
  createdAfter: '', createdBefore: '',
};

function toQueryString(filters: Filters, cursor: string | null): string {
  const params = new URLSearchParams();
  params.set('limit', String(PAGE_SIZE));
  if (filters.operatorId.trim()) { params.set('operatorId', filters.operatorId.trim()); }
  if (filters.resource.trim()) { params.set('resource', filters.resource.trim()); }
  if (filters.action.trim()) { params.set('action', filters.action.trim()); }
  if (filters.targetId.trim()) { params.set('targetId', filters.targetId.trim()); }
  if (filters.createdAfter) { params.set('createdAfter', new Date(filters.createdAfter).toISOString()); }
  if (filters.createdBefore) { params.set('createdBefore', new Date(filters.createdBefore).toISOString()); }
  if (cursor) { params.set('cursor', cursor); }
  return params.toString();
}

export function AuditPage() {
  // Committed filters = what the last query ran with. The inputs edit
  // draftFilters until "Apply" so typing doesn't fire a request per key.
  const [draft, setDraft] = React.useState<Filters>(EMPTY_FILTERS);
  const [applied, setApplied] = React.useState<Filters>(EMPTY_FILTERS);
  // Cursor stack implements "load more" + "back to newest" without an
  // offset counter.
  const [cursorStack, setCursorStack] = React.useState<string[]>([]);
  const [rows, setRows] = React.useState<AuditRow[]>([]);
  const [nextCursor, setNextCursor] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [exporting, setExporting] = React.useState<'ndjson' | 'csv' | null>(null);
  const [exportError, setExportError] = React.useState<string | null>(null);

  const currentCursor = cursorStack[cursorStack.length - 1] ?? null;

  const load = React.useCallback(async (
    filters: Filters,
    cursor: string | null,
    replace: boolean,
  ) => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API}/audit/query?${toQueryString(filters, cursor)}`, {
        credentials: 'include',
      });
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        throw new Error(body?.error ?? `request failed (${res.status})`);
      }
      const data = (await res.json()) as { entries: AuditRow[]; nextCursor: string | null };
      setRows((prev) => replace ? data.entries : [...prev, ...data.entries]);
      setNextCursor(data.nextCursor);
    } catch (err: any) {
      setError(err?.message ?? 'failed to load audit entries');
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => { void load(EMPTY_FILTERS, null, true); }, [load]);

  const applyFilters = () => {
    setApplied(draft);
    setCursorStack([]);
    void load(draft, null, true);
  };

  const loadMore = () => {
    if (!nextCursor) { return; }
    setCursorStack((s) => [...s, nextCursor]);
    void load(applied, nextCursor, false);
  };

  const backToNewest = () => {
    setCursorStack([]);
    void load(applied, null, true);
  };

  // Streaming export: the browser handles the download progressively
  // (Content-Disposition attachment). The server fixes the window and
  // batches reads, so memory stays bounded on both sides.
  const runExport = async (format: 'ndjson' | 'csv') => {
    setExporting(format);
    setExportError(null);
    try {
      const params = new URLSearchParams(toQueryString(applied, null));
      params.set('format', format);
      // Export requires an explicit, bounded window — never silently
      // export "all history".
      if (!applied.createdAfter || !applied.createdBefore) {
        throw new Error('set both "after" and "before" before exporting (max window 366 days)');
      }
      const res = await fetch(`${API}/audit/export?${params.toString()}`, {
        credentials: 'include',
      });
      if (!res.ok) {
        const body = await res.json().catch(() => null);
        throw new Error(body?.error ?? `export failed (${res.status})`);
      }
      const blob = await res.blob();
      const disposition = res.headers.get('content-disposition') ?? '';
      const match = /filename="([^"]+)"/.exec(disposition);
      const filename = match?.[1] ?? `audit-export.${format === 'csv' ? 'csv' : 'ndjson'}`;
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    } catch (err: any) {
      setExportError(err?.message ?? 'export failed');
    } finally {
      setExporting(null);
    }
  };

  const set = (key: keyof Filters) => (e: React.ChangeEvent<HTMLInputElement>) => {
    setDraft((d) => ({ ...d, [key]: e.target.value }));
  };

  return (
    <Page
      bare
      title="Audit log"
      actions={
        <div className="flex items-center gap-2">
          <Button
            variant="outline" size="sm"
            disabled={exporting !== null || !applied.createdAfter || !applied.createdBefore}
            onClick={() => void runExport('ndjson')}
            data-testid="export-ndjson"
            title={!applied.createdAfter || !applied.createdBefore
              ? 'Pick a time window (after + before) to export'
              : 'Stream NDJSON export for the current filters'}
          >
            {exporting === 'ndjson'
              ? <Loader2 className="size-4 animate-spin" />
              : <Download className="size-4" />}
            Export NDJSON
          </Button>
          <Button
            variant="outline" size="sm"
            disabled={exporting !== null || !applied.createdAfter || !applied.createdBefore}
            onClick={() => void runExport('csv')}
            data-testid="export-csv"
            title={!applied.createdAfter || !applied.createdBefore
              ? 'Pick a time window (after + before) to export'
              : 'Stream CSV export for the current filters'}
          >
            {exporting === 'csv'
              ? <Loader2 className="size-4 animate-spin" />
              : <Download className="size-4" />}
            Export CSV
          </Button>
        </div>
      }
    >
      <div className="flex flex-col gap-4">
        {/* Filter bar */}
        <div className="rounded-lg border bg-background p-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            <FilterField label="Operator ID">
              <Input value={draft.operatorId} onChange={set('operatorId')} placeholder="user_…" data-testid="filter-operator" />
            </FilterField>
            <FilterField label="Resource">
              <Input value={draft.resource} onChange={set('resource')} placeholder="users, configs…" data-testid="filter-resource" />
            </FilterField>
            <FilterField label="Action">
              <Input value={draft.action} onChange={set('action')} placeholder="user.ban, delete…" data-testid="filter-action" />
            </FilterField>
            <FilterField label="Target ID">
              <Input value={draft.targetId} onChange={set('targetId')} placeholder="row id" data-testid="filter-target" />
            </FilterField>
            <FilterField label="After (local time)">
              <Input type="datetime-local" value={draft.createdAfter} onChange={set('createdAfter')} data-testid="filter-after" />
            </FilterField>
            <FilterField label="Before (local time)">
              <Input type="datetime-local" value={draft.createdBefore} onChange={set('createdBefore')} data-testid="filter-before" />
            </FilterField>
          </div>
          <div className="mt-3 flex items-center gap-2">
            <Button size="sm" onClick={applyFilters} data-testid="apply-filters">
              <Search className="size-4" /> Apply
            </Button>
            <Button
              size="sm" variant="ghost"
              onClick={() => { setDraft(EMPTY_FILTERS); setApplied(EMPTY_FILTERS); setCursorStack([]); void load(EMPTY_FILTERS, null, true); }}
            >
              Reset
            </Button>
            {currentCursor && (
              <Button size="sm" variant="link" onClick={backToNewest}>
                back to newest
              </Button>
            )}
          </div>
          {exportError && (
            <p className="mt-2 text-sm text-destructive" data-testid="export-error">{exportError}</p>
          )}
        </div>

        {/* Results */}
        <div className="rounded-lg border bg-background">
          {error ? (
            <div className="p-4 text-sm text-destructive" data-testid="audit-error">{error}</div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-44">When</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Operator</TableHead>
                  <TableHead>Resource</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Context</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((row) => <AuditTableRow key={row.id} row={row} />)}
              </TableBody>
            </Table>
          )}
          {!loading && !error && rows.length === 0 && (
            <div className="p-6">
              <Empty title="No audit entries match these filters." />
            </div>
          )}
          <div className="flex items-center justify-between border-t p-3">
            <span className="text-xs text-muted-foreground" data-testid="audit-count">
              {rows.length} loaded
            </span>
            {nextCursor && (
              <Button size="sm" variant="outline" onClick={loadMore} disabled={loading} data-testid="load-more">
                {loading ? <Loader2 className="size-4 animate-spin" /> : null}
                Load older
              </Button>
            )}
          </div>
        </div>
      </div>
    </Page>
  );
}

function FilterField({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      {children}
    </div>
  );
}

function AuditTableRow({ row }: { row: AuditRow }) {
  const [expanded, setExpanded] = React.useState(false);
  const created = new Date(row.created_at);
  const valid = !Number.isNaN(created.getTime());
  const payload = normalizeJson(row.payload);
  const hasDetail = payload !== null || (row.snapshot?.fields && Object.keys(row.snapshot.fields).length > 0);

  return (
    <TableRow
      className={cn(hasDetail && 'cursor-pointer')}
      onClick={() => hasDetail && setExpanded((v) => !v)}
      data-testid={`audit-row-${row.id}`}
    >
      <TableCell className="whitespace-nowrap text-xs tabular-nums text-muted-foreground" title={valid ? absoluteTime(created) : undefined}>
        {valid ? relativeTime(created) : '—'}
      </TableCell>
      <TableCell><AuditActionBadge action={row.action} /></TableCell>
      <TableCell>
        {row.operator_id ? (
          <Link
            to={`/users/show/${encodeURIComponent(row.operator_id)}`}
            className="text-primary hover:underline"
            onClick={(e) => e.stopPropagation()}
          >
            {shortId(row.operator_id)}
          </Link>
        ) : (
          <span className="text-muted-foreground">system</span>
        )}
      </TableCell>
      <TableCell className="font-mono text-xs">{row.resource}</TableCell>
      <TableCell>
        {row.target_id ? <TargetLink resource={row.resource} id={row.target_id} /> : '—'}
        {row.snapshot?.label && (
          <span className="ml-2 text-xs text-muted-foreground">{row.snapshot.label}</span>
        )}
      </TableCell>
      <TableCell className="max-w-[28rem]">
        {row.snapshot?.fields && Object.keys(row.snapshot.fields).length > 0 ? (
          <span className="text-xs text-muted-foreground">
            {Object.entries(row.snapshot.fields).slice(0, 3).map(([k, v]) => `${k}=${String(v)}`).join(' · ')}
          </span>
        ) : (
          <span className="text-muted-foreground text-xs">—</span>
        )}
        {expanded && hasDetail && (
          <div
            className="mt-2 rounded border bg-muted/40 p-2"
            onClick={(e) => e.stopPropagation()}
            data-testid={`audit-detail-${row.id}`}
          >
            {/* Snapshot = deletion-proof context; render it first and
                label it distinctly from the full payload. */}
            {row.snapshot?.fields && Object.keys(row.snapshot.fields).length > 0 && (
              <div className="mb-2">
                <div className="mb-1 text-[11px] uppercase tracking-wide text-muted-foreground">
                  Captured context
                </div>
                <JsonViewer data={row.snapshot} />
              </div>
            )}
            {payload !== null && (
              <div>
                <div className="mb-1 text-[11px] uppercase tracking-wide text-muted-foreground">
                  Payload
                </div>
                <JsonViewer data={payload} />
              </div>
            )}
          </div>
        )}
      </TableCell>
    </TableRow>
  );
}

/**
 * Link to the target when it's a catalog resource we know how to show.
 * Deleted rows 404 on the show page — that's fine, the row's snapshot
 * keeps the relevant context visible right here.
 */
function TargetLink({ resource, id }: { resource: string; id: string }) {
  const linkable = new Set(['users', 'configs', 'cloudSaves', 'leaderboards', 'userNotes', 'roles']);
  if (!linkable.has(resource)) {
    return <span className="font-mono text-xs">{shortId(id)}</span>;
  }
  return (
    <Link
      to={`/${resource}/show/${encodeURIComponent(id)}`}
      className="font-mono text-xs text-primary hover:underline"
      onClick={(e) => e.stopPropagation()}
    >
      {shortId(id)}
    </Link>
  );
}

function normalizeJson(value: unknown): unknown {
  if (typeof value !== 'string') { return value ?? null; }
  try { return JSON.parse(value); } catch { return value; }
}

function shortId(id: string): string {
  return id.length <= 10 ? id : `${id.slice(0, 6)}…${id.slice(-4)}`;
}
