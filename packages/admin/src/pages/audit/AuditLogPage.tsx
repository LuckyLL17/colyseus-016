/**
 * Admin → Audit log page.
 *
 * The generic CRUD list page is the wrong surface for audit rows:
 *   - filters here are audit-specific (operator / resource / action /
 *     time window), not free-text-per-column;
 *   - paging is CURSOR-based ("Load older") so concurrent inserts can't
 *     skip or duplicate rows — the generic page uses LIMIT/OFFSET;
 *   - export is a server-side STREAM (NDJSON), not "load everything and
 *     hit CSV";
 *   - payload fields arrive pre-masked by the server according to the
 *     viewer's role — this page never sees values it may not read.
 *
 * This page is intentionally narrow: query, read, export. It does not
 * aspire to be a reports builder (no grouping, charts, saved queries).
 */
import * as React from 'react';
import { Link } from 'react-router-dom';
import { ChevronDown, Download, Loader2, Search } from 'lucide-react';
import { toast } from 'sonner';
import { Page } from '@/components/ui/page';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { API } from '@/lib/runtime-config';
import { cn } from '@/lib/utils';
import { AuditActionBadge } from '../internals/audit-action-badge';
import { JsonViewer } from '../internals/json-viewer';
import { relativeTime, absoluteTime } from '../internals/format-cell';

/** Complete set of actions the panel writes (mirror of the backend list). */
const ACTIONS = [
  'create', 'update', 'delete', 'custom',
  'auth.login', 'auth.login_failed', 'auth.logout', 'auth.bootstrap',
  'auth.password_reset_requested', 'auth.password_reset_completed',
  'room.kick', 'room.dispose', 'room.lock', 'room.unlock',
  'room.state.edit', 'room.state.delete',
  'user.ban', 'user.unban', 'user.revoke_sessions',
  'audit.export_completed', 'audit.export_failed',
] as const;

interface AuditRow {
  id: string;
  operator_id: string | null;
  operator_label: string | null;
  action: string;
  resource: string;
  resource_label: string | null;
  target_id: string | null;
  target_label: string | null;
  payload: any;
  created_at: string;
  _redacted?: string[];
}

interface Filters {
  operatorId: string;
  resource: string;
  targetId: string;
  actions: string[];
  from: string;
  until: string;
}

const EMPTY_FILTERS: Filters = {
  operatorId: '', resource: '', targetId: '', actions: [], from: '', until: '',
};

/** datetime-local → ISO string, or undefined when blank/invalid. */
function isoFromLocal(value: string): string | undefined {
  if (!value) { return undefined; }
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/** Build the audit API query string from the current filters. */
function buildQuery(filters: Filters, extra?: Record<string, string>): string {
  const params = new URLSearchParams();
  if (filters.operatorId.trim()) { params.set('operatorId', filters.operatorId.trim()); }
  if (filters.resource.trim()) { params.set('resource', filters.resource.trim()); }
  if (filters.targetId.trim()) { params.set('targetId', filters.targetId.trim()); }
  if (filters.actions.length > 0) { params.set('action', filters.actions.join(',')); }
  const from = isoFromLocal(filters.from);
  if (from) { params.set('from', from); }
  const until = isoFromLocal(filters.until);
  if (until) { params.set('until', until); }
  for (const [k, v] of Object.entries(extra ?? {})) { params.set(k, v); }
  const qs = params.toString();
  return qs ? `?${qs}` : '';
}

export function AuditLogPage() {
  const [draftFilters, setDraftFilters] = React.useState<Filters>(EMPTY_FILTERS);
  const [appliedFilters, setAppliedFilters] = React.useState<Filters>(EMPTY_FILTERS);
  const [rows, setRows] = React.useState<AuditRow[]>([]);
  const [cursor, setCursor] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [loadingMore, setLoadingMore] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [redacted, setRedacted] = React.useState(false);
  const [exports, setExports] = React.useState<any[] | null>(null);

  const fetchPage = React.useCallback(async (f: Filters, nextCursor?: string) => {
    const qs = buildQuery(f, nextCursor ? { cursor: nextCursor, limit: '50' } : { limit: '50' });
    const res = await fetch(`${API}/audit/entries${qs}`, { credentials: 'include' });
    if (!res.ok) {
      const body = await res.json().catch(() => null);
      throw new Error(body?.error ?? `request failed (${res.status})`);
    }
    return (await res.json()) as { data: AuditRow[]; cursor: string | null; redacted?: boolean };
  }, []);

  const runSearch = React.useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const page = await fetchPage(draftFilters);
      setRows(page.data);
      setCursor(page.cursor);
      setRedacted(!!page.redacted);
      setAppliedFilters(draftFilters);
    } catch (err: any) {
      setError(err?.message ?? 'failed to load audit entries');
    } finally {
      setLoading(false);
    }
  }, [draftFilters, fetchPage]);

  const loadMore = React.useCallback(async () => {
    if (!cursor) { return; }
    setLoadingMore(true);
    try {
      const page = await fetchPage(appliedFilters, cursor);
      setRows((prev) => [...prev, ...page.data]);
      setCursor(page.cursor);
      if (page.redacted) { setRedacted(true); }
    } catch (err: any) {
      toast.error(err?.message ?? 'failed to load more entries');
    } finally {
      setLoadingMore(false);
    }
  }, [cursor, appliedFilters, fetchPage]);

  const refreshExports = React.useCallback(async () => {
    try {
      const res = await fetch(`${API}/audit/exports`, { credentials: 'include' });
      if (!res.ok) { return; }
      const body = await res.json();
      setExports(body.data ?? []);
    } catch {
      // Non-fatal panel — leave the section as-is.
    }
  }, []);

  // Initial load + recent-exports list.
  React.useEffect(() => {
    void runSearch();
    void refreshExports();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // The browser streams the response straight to disk through the
  // anchor — no fetch()+blob, so an export never accumulates in the
  // page's memory either. Cookies ride along same-origin.
  const startExport = () => {
    const url = `${API}/audit/export${buildQuery(appliedFilters)}`;
    const a = document.createElement('a');
    a.href = url;
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
    toast.success('Export started — the download streams as NDJSON. Status appears under "Recent exports".');
    // The server writes the completion/failure audit row once the
    // stream finishes; poll the panel a few times so operators see it
    // land without a manual refresh.
    const polls = [4_000, 10_000, 20_000];
    for (const delay of polls) {
      setTimeout(() => void refreshExports(), delay);
    }
  };

  const toggleAction = (action: string) => {
    setDraftFilters((f) => ({
      ...f,
      actions: f.actions.includes(action)
        ? f.actions.filter((a) => a !== action)
        : [...f.actions, action],
    }));
  };

  return (
    <Page
      title="Audit log"
      actions={
        <Button size="sm" variant="outline" onClick={startExport} data-testid="audit-export">
          <Download className="size-4" />
          Export
        </Button>
      }
    >
      {/* Filter bar — fixed set of audit dimensions. No free-form query
          builder on purpose; this isn't a reports system. */}
      <div className="space-y-3" data-testid="audit-filters">
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          <Field label="Operator id">
            <Input
              value={draftFilters.operatorId}
              onChange={(e) => setDraftFilters((f) => ({ ...f, operatorId: e.target.value }))}
              placeholder="user_…"
              data-testid="filter-operator"
            />
          </Field>
          <Field label="Resource">
            <Input
              value={draftFilters.resource}
              onChange={(e) => setDraftFilters((f) => ({ ...f, resource: e.target.value }))}
              placeholder="users, configs, rooms…"
              data-testid="filter-resource"
              list="audit-resources"
            />
            <datalist id="audit-resources">
              <option value="users" />
              <option value="configs" />
              <option value="rooms" />
              <option value="auth" />
              <option value="adminAudit" />
            </datalist>
          </Field>
          <Field label="Target id">
            <Input
              value={draftFilters.targetId}
              onChange={(e) => setDraftFilters((f) => ({ ...f, targetId: e.target.value }))}
              placeholder="the acted-on row id"
              data-testid="filter-target"
            />
          </Field>
          <Field label="From (inclusive)">
            <Input
              type="datetime-local"
              value={draftFilters.from}
              onChange={(e) => setDraftFilters((f) => ({ ...f, from: e.target.value }))}
              data-testid="filter-from"
            />
          </Field>
          <Field label="Until (inclusive)">
            <Input
              type="datetime-local"
              value={draftFilters.until}
              onChange={(e) => setDraftFilters((f) => ({ ...f, until: e.target.value }))}
              data-testid="filter-until"
            />
          </Field>
          <div className="flex items-end">
            <Button size="sm" onClick={() => void runSearch()} disabled={loading} data-testid="audit-search">
              {loading ? <Loader2 className="size-4 animate-spin" /> : <Search className="size-4" />}
              Apply filters
            </Button>
          </div>
        </div>

        {/* Action multiselect — compact checkbox chips */}
        <div className="flex flex-wrap gap-1.5" data-testid="filter-actions">
          {ACTIONS.map((action) => {
            const active = draftFilters.actions.includes(action);
            return (
              <button
                key={action}
                type="button"
                onClick={() => toggleAction(action)}
                className={cn(
                  'rounded-full border px-2 py-0.5 font-mono text-[11px] transition-colors',
                  active
                    ? 'border-primary bg-primary text-primary-foreground'
                    : 'text-muted-foreground hover:bg-accent',
                )}
                aria-pressed={active}
              >
                {action}
              </button>
            );
          })}
        </div>
      </div>

      {redacted && (
        <div
          className="rounded-md border bg-muted/40 px-3 py-2 text-xs text-muted-foreground"
          data-testid="audit-redacted-note"
        >
          Some fields are masked for your role — masked values are marked inline as
          <code className="mx-1">***redacted***</code>. The export applies the same rules.
        </div>
      )}

      {error && (
        <div className="rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </div>
      )}

      {/* Results timeline */}
      {loading ? (
        <div className="flex items-center justify-center py-10 text-muted-foreground">
          <Loader2 className="size-4 animate-spin mr-2" /> loading…
        </div>
      ) : rows.length === 0 && !error ? (
        <p className="py-8 text-center text-sm text-muted-foreground">
          No audit entries match the current filters.
        </p>
      ) : (
        <ol className="space-y-2" data-testid="audit-entries">
          {rows.map((row) => <AuditRowView key={row.id} row={row} />)}
        </ol>
      )}

      {cursor && (
        <div className="flex justify-center">
          <Button variant="outline" size="sm" onClick={() => void loadMore()} disabled={loadingMore}>
            {loadingMore ? <Loader2 className="size-4 animate-spin" /> : null}
            Load older
          </Button>
        </div>
      )}

      <RecentExports exports={exports} onRefresh={() => void refreshExports()} />
    </Page>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="space-y-1">
      <Label className="text-xs text-muted-foreground">{label}</Label>
      {children}
    </div>
  );
}

function AuditRowView({ row }: { row: AuditRow }) {
  const created = new Date(row.created_at);
  const valid = !Number.isNaN(created.getTime());
  const payload = React.useMemo(() => {
    if (typeof row.payload === 'string') {
      try { return JSON.parse(row.payload); } catch { return null; }
    }
    return row.payload ?? null;
  }, [row.payload]);
  const hasPayload = payload !== null && typeof payload === 'object' && Object.keys(payload).length > 0;
  const [expanded, setExpanded] = React.useState(false);

  // Prefer the write-time label snapshot; fall back to the id. This is
  // what keeps deleted users/rooms legible.
  const operator = row.operator_label ?? row.operator_id;
  const target = row.target_label ?? row.target_id;
  const resourceLabel = row.resource_label ?? row.resource;

  return (
    <li
      className={cn(
        'rounded-md border bg-muted/20',
        hasPayload && 'cursor-pointer hover:bg-muted/40',
      )}
      data-testid={`audit-entry-${row.id}`}
      {...(hasPayload ? {
        role: 'button', tabIndex: 0, 'aria-expanded': expanded,
        onClick: () => setExpanded((v) => !v),
        onKeyDown: (e) => {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setExpanded((v) => !v); }
        },
      } : {})}
    >
      <div className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
        <div className="inline-flex flex-wrap items-center gap-2 text-sm">
          <AuditActionBadge action={row.action} />
          <span className="text-muted-foreground">by</span>
          {row.operator_id ? (
            <Link
              to={`/users/show/${row.operator_id}`}
              className="text-primary hover:underline"
              onClick={(e) => e.stopPropagation()}
            >
              {operator ?? row.operator_id}
            </Link>
          ) : (
            <span className="text-muted-foreground italic">system</span>
          )}
          <span className="text-muted-foreground">on</span>
          <Badge variant="outline">{resourceLabel}</Badge>
          {target && (
            <>
              <span className="text-muted-foreground">→</span>
              <TargetLink row={row}>{target}</TargetLink>
            </>
          )}
        </div>
        <div className="inline-flex items-center gap-2">
          {row._redacted && row._redacted.length > 0 && (
            <span className="text-[10px] uppercase tracking-wide text-amber-600" title={row._redacted.join(', ')}>
              {row._redacted.length} field{row._redacted.length === 1 ? '' : 's'} masked
            </span>
          )}
          <span
            className="whitespace-nowrap text-xs text-muted-foreground tabular-nums"
            title={valid ? absoluteTime(created) : undefined}
          >
            {valid ? relativeTime(created) : '—'}
          </span>
          {hasPayload && (
            <ChevronDown className={cn('size-4 text-muted-foreground transition-transform', expanded && 'rotate-180')} />
          )}
        </div>
      </div>
      {expanded && hasPayload && (
        <div className="border-t px-3 py-2" data-testid={`audit-entry-payload-${row.id}`}>
          <JsonViewer data={payload} />
        </div>
      )}
    </li>
  );
}

/**
 * Deep-link the target when its resource is still in the catalog;
 * otherwise render the snapshot label as plain text — the whole point
 * of the label columns is that deleted resources still display.
 */
function TargetLink({ row, children }: { row: AuditRow; children: React.ReactNode }) {
  // resources/rooms/auth aren't known statically here; only users has a
  // reliable route shape. For anything else we render plain text (the
  // snapshot label is still informative).
  if (row.resource === 'users' && row.target_id) {
    return (
      <Link
        to={`/users/show/${row.target_id}`}
        className="font-medium hover:underline"
        onClick={(e) => e.stopPropagation()}
      >
        {children}
      </Link>
    );
  }
  if (row.resource === 'rooms' && row.target_id) {
    return (
      <Link
        to={`/rooms/${row.target_id}`}
        className="font-medium hover:underline"
        onClick={(e) => e.stopPropagation()}
      >
        {children}
      </Link>
    );
  }
  return <span className="font-medium">{children}</span>;
}

function RecentExports({ exports, onRefresh }: { exports: any[] | null; onRefresh: () => void }) {
  const [open, setOpen] = React.useState(false);
  if (!exports || exports.length === 0) { return null; }
  return (
    <div className="rounded-md border">
      <button
        type="button"
        className="flex w-full items-center justify-between px-3 py-2 text-sm font-medium"
        onClick={() => setOpen((v) => !v)}
        data-testid="recent-exports-toggle"
      >
        Recent exports
        <ChevronDown className={cn('size-4 transition-transform', open && 'rotate-180')} />
      </button>
      {open && (
        <div className="border-t px-3 py-2" data-testid="recent-exports">
          <ul className="space-y-1">
            {exports.map((x) => (
              <li key={x.id} className="flex flex-wrap items-center gap-2 text-xs">
                <Badge variant={x.action === 'audit.export_completed' ? 'success' : 'destructive'}>
                  {x.action === 'audit.export_completed' ? 'completed' : 'failed'}
                </Badge>
                <span className="tabular-nums text-muted-foreground">
                  {relativeTime(new Date(x.created_at))}
                </span>
                <span>{x.operator_label ?? x.operator_id ?? 'system'}</span>
                <span className="text-muted-foreground">{x.rows ?? 0} rows</span>
                {x.truncated && <span className="text-amber-600">(capped)</span>}
                {x.reason && <span className="text-destructive">{x.reason}</span>}
                {x.boundary && (
                  <span className="text-muted-foreground" title={JSON.stringify(x.boundary)}>
                    {Object.entries(x.boundary).map(([k, v]) => `${k}=${v}`).join(' · ')}
                  </span>
                )}
              </li>
            ))}
          </ul>
          <Button variant="ghost" size="sm" className="mt-2" onClick={onRefresh}>
            Refresh
          </Button>
        </div>
      )}
    </div>
  );
}
