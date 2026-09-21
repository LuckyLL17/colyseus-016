/**
 * Audit filter parsing — pure unit tests for the query-string →
 * AuditQuery boundary shared by the list + export endpoints.
 */
import assert from 'node:assert';
import { describe, it } from 'node:test';
import { parseAuditFilter, serializeAuditFilter, MAX_WINDOW_MS } from '../src-backend/audit/filters.ts';

describe('parseAuditFilter', () => {
  it('returns an empty filter for an empty query', () => {
    const r = parseAuditFilter({});
    assert.deepStrictEqual(r, { filter: {} });
  });

  it('parses the equality dimensions', () => {
    const r = parseAuditFilter({
      operatorId: 'op-1',
      resource: 'users',
      targetId: 'u-9',
    });
    assert.ok('filter' in r);
    assert.deepStrictEqual(r.filter, {
      operatorId: 'op-1',
      resource: 'users',
      targetId: 'u-9',
    });
  });

  it('ignores blank/whitespace values', () => {
    const r = parseAuditFilter({ operatorId: '   ', resource: '' });
    assert.deepStrictEqual(r, { filter: {} });
  });

  it('parses a single action and a comma-separated set', () => {
    const single = parseAuditFilter({ action: 'user.ban' });
    assert.ok('filter' in single);
    assert.equal(single.filter.action, 'user.ban');

    const multi = parseAuditFilter({ action: 'user.ban, user.unban ,delete' });
    assert.ok('filter' in multi);
    assert.deepStrictEqual(multi.filter.actions, ['user.ban', 'user.unban', 'delete']);
  });

  it('rejects an unknown action but accepts reserved-namespace tags', () => {
    const bad = parseAuditFilter({ action: 'drop.table' });
    assert.ok('error' in bad);

    const custom = parseAuditFilter({ action: 'room.custom_freeze' });
    assert.ok('filter' in custom);
  });

  it('parses ISO time bounds', () => {
    const r = parseAuditFilter({
      from: '2026-09-01T00:00:00Z',
      until: '2026-09-02T00:00:00Z',
    });
    assert.ok('filter' in r);
    assert.equal(r.filter.from!.toISOString(), '2026-09-01T00:00:00.000Z');
    assert.equal(r.filter.until!.toISOString(), '2026-09-02T00:00:00.000Z');
  });

  it('rejects a malformed date', () => {
    const r = parseAuditFilter({ from: 'not-a-date' });
    assert.ok('error' in r);
    assert.match(r.error, /from must be/);
  });

  it('rejects from > until', () => {
    const r = parseAuditFilter({
      from: '2026-09-10T00:00:00Z',
      until: '2026-09-01T00:00:00Z',
    });
    assert.ok(!('filter' in r) && 'error' in r);
    assert.match(r.error, /at or before/);
  });

  it('rejects a window larger than the safety cap', () => {
    const r = parseAuditFilter({
      from: new Date(Date.now() - MAX_WINDOW_MS - 86_400_000).toISOString(),
      until: new Date().toISOString(),
    });
    assert.ok('error' in r);
    assert.match(r.error, /time window too large/);
  });
});

describe('serializeAuditFilter', () => {
  it('produces a stable canonical boundary record', () => {
    const a = parseAuditFilter({
      operatorId: 'op', resource: 'users',
      action: 'user.unban,user.ban',
      from: '2026-09-01T00:00:00Z',
      until: '2026-09-02T00:00:00Z',
    });
    assert.ok('filter' in a);
    const out = serializeAuditFilter(a.filter);
    assert.equal(out.actions, 'user.ban,user.unban', 'actions sort for a stable boundary');
    assert.equal(out.operatorId, 'op');
    assert.equal(out.resource, 'users');
    assert.equal(out.from, '2026-09-01T00:00:00.000Z');
    assert.equal(out.until, '2026-09-02T00:00:00.000Z');
  });
});
