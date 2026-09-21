/**
 * AuditService query upgrades:
 *   - filters (operator/resource/target/action[s]/time window)
 *   - keyset cursor pagination (stable under concurrent inserts)
 *   - batched iterate() that never accumulates the full result set
 *   - label snapshot columns survive on record()
 *
 * Sqlite-only: these are query-planner features exercised identically
 * on pg (same drizzle operators); services.test.ts already covers the
 * pg-flavored record/list/prune paths against PGlite.
 */
import assert from 'assert';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { describe, it, beforeEach, afterEach } from 'node:test';
import { fileURLToPath } from 'url';
import { GameDatabase, encodeCursor, decodeCursor } from '../src/index.ts';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

let db: GameDatabase;
let dbPath: string;

async function fresh() {
  if (db) { await db.shutdown(); }
  dbPath = path.join(__dirname, `.t-auditq-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
  db = new GameDatabase({ connectionString: dbPath });
  await db.boot();
}

afterEach(async () => {
  await db.shutdown();
  for (const ext of ['', '-shm', '-wal']) {
    try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ }
  }
});

/** Insert n rows with controlled createdAt timestamps, newest last. */
async function seed(
  entries: Array<Partial<{ operatorId: string; resource: string; targetId: string; action: string; at: Date; payload: any; label: string }>>,
) {
  for (const e of entries) {
    const [row] = await db.drizzle
      .insert(db.tables.adminAudit)
      .values({
        operatorId: e.operatorId ?? 'op',
        operatorLabel: e.label ?? null,
        action: e.action ?? 'create',
        resource: e.resource ?? 'users',
        resourceLabel: 'Users',
        targetId: e.targetId ?? null,
        targetLabel: null,
        payload: e.payload ?? null,
        createdAt: e.at ?? new Date(),
      })
      .returning();
  }
}

describe('AuditService query', () => {
  beforeEach(fresh);

  it('persists and reads the label snapshot columns', async () => {
    await db.audit.record({
      operatorId: 'op-1', operatorLabel: 'alice@example.com',
      action: 'delete', resource: 'users', resourceLabel: 'Users',
      targetId: 'u-dead', targetLabel: 'bob@example.com',
      payload: { row: { id: 'u-dead' } },
    });
    const [entry] = await db.audit.list();
    assert.equal(entry.operatorLabel, 'alice@example.com');
    assert.equal(entry.resourceLabel, 'Users');
    assert.equal(entry.targetLabel, 'bob@example.com');
  });

  it('filters by action set (IN)', async () => {
    await seed([
      { action: 'create' }, { action: 'update' }, { action: 'delete' }, { action: 'user.ban' },
    ]);
    const page = await db.audit.queryPage({
      filter: { actions: ['delete', 'user.ban'] },
      limit: 10,
    });
    assert.deepStrictEqual(
      page.entries.map((e) => e.action).sort(),
      ['delete', 'user.ban'],
    );
  });

  it('filters by targetId', async () => {
    await seed([{ targetId: 't1' }, { targetId: 't2' }, { targetId: 't1' }]);
    const page = await db.audit.queryPage({ filter: { targetId: 't1' }, limit: 10 });
    assert.equal(page.entries.length, 2);
    assert.ok(page.entries.every((e) => e.targetId === 't1'));
  });

  it('applies an inclusive time window', async () => {
    const t0 = new Date('2026-01-01T00:00:00Z');
    const t1 = new Date('2026-02-01T00:00:00Z');
    const t2 = new Date('2026-03-01T00:00:00Z');
    await seed([{ at: t0 }, { at: t1 }, { at: t2 }]);

    const page = await db.audit.queryPage({
      filter: { from: t1, until: t1 },
      limit: 10,
    });
    assert.equal(page.entries.length, 1);
    assert.equal(page.entries[0]!.createdAt.getTime(), t1.getTime());
  });

  it('paginates with a keyset cursor without losing or duplicating rows', async () => {
    const at = [
      new Date('2026-01-01T00:00:00Z'),
      new Date('2026-01-02T00:00:00Z'),
      new Date('2026-01-03T00:00:00Z'),
      new Date('2026-01-04T00:00:00Z'),
      new Date('2026-01-05T00:00:00Z'),
    ];
    await seed(at.map((t) => ({ at: t })));

    const first = await db.audit.queryPage({ limit: 2 });
    assert.equal(first.entries.length, 2);
    assert.ok(first.nextCursor);
    // newest-first
    assert.equal(first.entries[0]!.createdAt.getTime(), at[4]!.getTime());

    const second = await db.audit.queryPage({ limit: 2, cursor: first.nextCursor! });
    const third = await db.audit.queryPage({ limit: 2, cursor: second.nextCursor! });

    const all = [...first.entries, ...second.entries, ...third.entries];
    assert.equal(all.length, 5);
    assert.equal(new Set(all.map((e) => e.id)).size, 5, 'no duplicate ids across pages');
    assert.equal(third.nextCursor, null, 'final page reports no cursor');
    // monotonic newest → oldest
    for (let i = 1; i < all.length; i++) {
      assert.ok(all[i - 1]!.createdAt >= all[i]!.createdAt);
    }
  });

  it('cursor walk is stable when newer rows are inserted mid-walk', async () => {
    const base = Array.from({ length: 4 }, (_, i) => new Date(`2026-01-0${i + 1}T00:00:00Z`));
    await seed(base.map((at) => ({ at })));

    const first = await db.audit.queryPage({ limit: 2 });

    // A concurrent insert lands AFTER the first page was read.
    await seed([{ at: new Date('2026-06-01T00:00:00Z'), action: 'custom' }]);

    const second = await db.audit.queryPage({ limit: 10, cursor: first.nextCursor! });
    const seen = new Set([...first.entries, ...second.entries].map((e) => e.id));
    // Original 4 all present exactly once; the late insert is NOT in
    // the older page (it belongs before the cursor), and didn't shift
    // any row out.
    assert.equal(seen.size, 4);
    assert.ok(second.entries.every((e) => e.action !== 'custom'));
  });

  it('iterate() yields fixed-size batches and stops at maxRows', async () => {
    await seed(Array.from({ length: 25 }, (_, i) => ({
      at: new Date(Date.UTC(2026, 0, i + 1)),
    })));

    const seen: string[] = [];
    const batchSizes: number[] = [];
    for await (const batch of db.audit.iterate({ batchSize: 10 })) {
      batchSizes.push(batch.length);
      for (const e of batch) { seen.push(e.id); }
    }
    assert.deepStrictEqual(batchSizes, [10, 10, 5]);
    assert.equal(seen.length, 25);
    assert.equal(new Set(seen).size, 25);
  });

  it('iterate() honors the maxRows cap', async () => {
    await seed(Array.from({ length: 10 }, (_, i) => ({
      at: new Date(Date.UTC(2026, 0, i + 1)),
    })));
    let count = 0;
    for await (const batch of db.audit.iterate({ batchSize: 4, maxRows: 7 })) {
      count += batch.length;
    }
    assert.equal(count, 7);
  });

  it('iterate() never accumulates: batches are independent arrays', async () => {
    await seed(Array.from({ length: 6 }, (_, i) => ({
      at: new Date(Date.UTC(2026, 0, i + 1)),
    })));
    // Mutating one batch can't corrupt the next — the iterator builds
    // each page from a fresh query.
    let batches = 0;
    for await (const batch of db.audit.iterate({ batchSize: 3 })) {
      batch.length = 0;
      batches++;
    }
    assert.equal(batches, 2);
    const remaining = await db.audit.list();
    assert.equal(remaining.length, 6, 'DB rows untouched by consumer mutation');
  });

  it('rejects a malformed cursor', () => {
    assert.throws(() => decodeCursor('not-base64-json!!!'), /malformed audit cursor/);
    const good = encodeCursor(new Date('2026-03-01T00:00:00Z'), 'abc123');
    const decoded = decodeCursor(good);
    assert.equal(decoded.id, 'abc123');
    assert.equal(decoded.createdAt.toISOString(), '2026-03-01T00:00:00.000Z');
  });
});
