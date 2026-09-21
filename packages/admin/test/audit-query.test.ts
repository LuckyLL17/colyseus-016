import assert from 'assert';
import { describe, it } from 'node:test';
import {
  decodeAuditCursor, encodeAuditCursor,
} from '@colyseus/database';
import { parseAuditParams, AuditParamError } from '../src-backend/audit/params.ts';
import {
  serializeBatch, csvHeader, parseExportFormat, exportFilename,
  type ExportRow,
} from '../src-backend/audit/export-format.ts';

const row = (over: Partial<ExportRow> = {}): ExportRow => ({
  id: 'r1',
  createdAt: new Date('2026-01-02T03:04:05.000Z'),
  operatorId: 'op1',
  action: 'user.ban',
  resource: 'users',
  targetId: 'u1',
  payload: { reason: 'cheating' },
  snapshot: { label: 'jane', fields: { email: 'j@x.com' } },
  ...over,
});

describe('audit cursor codec', () => {
  it('round-trips a cursor', () => {
    const encoded = encodeAuditCursor({ ts: '2026-01-01T00:00:00.000Z', id: 'abc123' });
    assert.strictEqual(typeof encoded, 'string');
    const decoded = decodeAuditCursor(encoded);
    assert.deepStrictEqual(decoded, { ts: '2026-01-01T00:00:00.000Z', id: 'abc123' });
  });

  it('rejects malformed input', () => {
    assert.strictEqual(decodeAuditCursor('not-base64-json!!'), null);
    assert.strictEqual(decodeAuditCursor(Buffer.from('{"ts":"bad"}').toString('base64url')), null);
    assert.strictEqual(decodeAuditCursor(Buffer.from('{"ts":"2026-01-01","id":5}').toString('base64url')), null);
  });
});

describe('parseAuditParams', () => {
  it('parses the full filter vocabulary with snake_case aliases', () => {
    const { filter } = parseAuditParams({
      operator_id: 'op1',
      resource: 'users',
      action: 'user.ban,user.unban',
      target_id: 'u1',
      created_after: '2026-01-01T00:00:00Z',
      created_before: '2026-02-01T00:00:00Z',
    });
    assert.strictEqual(filter.operatorId, 'op1');
    assert.strictEqual(filter.resource, 'users');
    assert.deepStrictEqual(filter.action, ['user.ban', 'user.unban']);
    assert.strictEqual(filter.targetId, 'u1');
    assert.ok(filter.createdAfter instanceof Date);
    assert.ok(filter.createdBefore instanceof Date);
  });

  it('returns an empty filter for no params', () => {
    const { filter } = parseAuditParams({});
    assert.deepStrictEqual(filter, {});
  });

  it('rejects bad dates and inverted windows', () => {
    assert.throws(() => parseAuditParams({ createdAfter: 'not-a-date' }), AuditParamError);
    assert.throws(
      () => parseAuditParams({
        createdAfter: '2026-02-01T00:00:00Z',
        createdBefore: '2026-01-01T00:00:00Z',
      }),
      AuditParamError,
    );
  });

  it('accepts a bounded window when the requirement is enabled', () => {
    assert.doesNotThrow(() => parseAuditParams({
      createdAfter: '2026-01-01T00:00:00Z',
      createdBefore: '2026-01-02T00:00:00Z',
    }, { requireWindow: true }));
  });

  it('rejects windows wider than the one-year cap', () => {
    assert.throws(
      () => parseAuditParams({
        createdAfter: '2020-01-01T00:00:00Z',
        createdBefore: '2026-01-01T00:00:00Z',
      }, { requireWindow: true }),
      /exceed/,
    );
  });
});

describe('export serializer', () => {
  it('emits NDJSON one object per line with SQL-style keys', () => {
    const out = serializeBatch([row()], 'ndjson');
    const lines = out.trim().split('\n');
    assert.strictEqual(lines.length, 1);
    const parsed = JSON.parse(lines[0]!);
    assert.strictEqual(parsed.operator_id, 'op1');
    assert.strictEqual(parsed.snapshot.label, 'jane');
    assert.strictEqual(parsed.created_at, '2026-01-02T03:04:05.000Z');
  });

  it('emits CSV with header order and RFC-4180 quoting', () => {
    const tricky = row({
      payload: { note: 'has, comma and "quote"' },
    });
    const out = csvHeader() + serializeBatch([tricky], 'csv');
    const lines = out.split('\n');
    assert.strictEqual(lines[0], 'id,created_at,operator_id,action,resource,target_id,snapshot,payload');
    // Comma inside the JSON payload cell forces quoting; inner quotes doubled.
    const payloadCell = lines[1]!.slice(lines[1]!.lastIndexOf('"{""note"'));
    assert.ok(payloadCell.startsWith('"{""note"'));
  });

  it('parses formats and builds window-stamped filenames', () => {
    assert.strictEqual(parseExportFormat('csv'), 'csv');
    assert.strictEqual(parseExportFormat('ndjson'), 'ndjson');
    assert.strictEqual(parseExportFormat(undefined), 'ndjson');
    const name = exportFilename('ndjson', new Date('2026-01-01T00:00:00Z'), new Date('2026-01-02T00:00:00Z'));
    assert.match(name, /^audit-.*\.ndjson$/);
  });
});
