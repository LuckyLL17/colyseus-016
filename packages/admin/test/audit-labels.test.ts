/**
 * Write-time label snapshots — the audit record must retain human
 * context after the referenced row is deleted. Exercises both paths:
 *   - label from an in-memory row snapshot (the DELETE case: row is
 *     already gone, only the hint can supply the label)
 *   - label from a live PK lookup (workflow endpoints with no hint)
 */
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { describe, it, before, after } from 'node:test';
import { fileURLToPath } from 'url';
import { eq } from 'drizzle-orm';
import { GameDatabase } from '@colyseus/database';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
process.env.JWT_SECRET = process.env.JWT_SECRET || 'audit-labels-test-secret';

const { admin } = await import('../src-backend/index.ts');
const { captureTargetLabel, labelFromRow, resourceLabelOf } = await import('../src-backend/audit/labels.ts');

let db: GameDatabase;
let dbPath: string;
let distDir: string;
let ctx: any;

before(async () => {
  dbPath = path.join(os.tmpdir(), `admin-labels-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
  db = new GameDatabase({ connectionString: dbPath });
  await db.boot();
  distDir = fs.mkdtempSync(path.join(os.tmpdir(), 'admin-labels-dist-'));
  fs.writeFileSync(path.join(distDir, 'index.html'), '<html></html>');
  // Build the same EndpointContext the admin factory builds, without
  // booting express — labels only need tables/getTableConfig/drizzle.
  const panel = admin({ database: db, uiDistDir: distDir, logger: null, enforceRbac: false });
  // The factory returns middleware; the context is captured inside, so
  // instead construct a duck-typed context via the same building blocks.
  const { getTableConfig: getSqliteTableConfig } = await import('drizzle-orm/sqlite-core');
  ctx = {
    database: db,
    tables: db.tables as any,
    resources: { users: { __tableName: 'colyseus_users', label: 'Players' } },
    getTableConfig: getSqliteTableConfig as any,
    logger: null,
  };
  // Touch panel so the import isn't tree-shaken (documents the
  // dependency but keeps the test free of a listening socket).
  assert.equal(typeof panel, 'function');
});

after(async () => {
  await db.shutdown();
  for (const ext of ['', '-shm', '-wal']) {
    try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ }
  }
  fs.rmSync(distDir, { recursive: true, force: true });
});

describe('labelFromRow', () => {
  it('picks conventional label columns', () => {
    assert.equal(labelFromRow({ id: 'x', email: 'a@b.c' }), 'a@b.c');
    assert.equal(labelFromRow({ id: 'x', name: 'Config A', value: 1 }), 'Config A');
    assert.equal(labelFromRow({ id: 'x', key: 'double_xp' }), 'double_xp');
  });

  it('returns null for empty/unknown shapes', () => {
    assert.equal(labelFromRow(null), null);
    // An id-only row has no label column; fallback skips primary keys.
    assert.equal(labelFromRow({ id: 'x' }), null);
  });

  it('truncates very long labels', () => {
    const long = 'x'.repeat(500);
    const out = labelFromRow({ email: long });
    assert.ok(out!.length <= 200);
    assert.match(out!, /…$/);
  });
});

describe('captureTargetLabel', () => {
  it('uses the row hint even after the row is deleted', async () => {
    // The users table has no such row — but the caller (delete
    // endpoint) holds the snapshot at audit-write time.
    const label = await captureTargetLabel(ctx, 'users', 'ghost-id', [
      { id: 'ghost-id', email: 'ghost@example.com' },
    ]);
    assert.equal(label, 'ghost@example.com');
  });

  it('falls back to a live lookup when there is no hint', async () => {
    await db.drizzle.insert(db.tables.users).values({
      id: 'live-1', email: 'live@example.com', anonymous: false,
    } as any);
    const label = await captureTargetLabel(ctx, 'users', 'live-1');
    assert.equal(label, 'live@example.com');

    // Now the row is deleted — a second lookup without a hint yields
    // null, demonstrating WHY the snapshot hint exists.
    await db.drizzle.delete(db.tables.users).where(eq(db.tables.users.id, 'live-1'));
    assert.equal(await captureTargetLabel(ctx, 'users', 'live-1'), null);
    // …but with the hint, the label survives the deletion.
    assert.equal(
      await captureTargetLabel(ctx, 'users', 'live-1', [{ id: 'live-1', email: 'live@example.com' }]),
      'live@example.com',
    );
  });

  it('returns the hint label for synthetic (table-less) resources', async () => {
    const label = await captureTargetLabel(ctx, 'rooms', 'room-xyz', [
      { roomId: 'room-xyz', name: 'arena#1' },
    ]);
    assert.equal(label, 'arena#1');
  });
});

describe('resourceLabelOf', () => {
  it('uses the configured label then canonical name', () => {
    assert.equal(resourceLabelOf(ctx, 'users'), 'Players');
    assert.equal(resourceLabelOf(ctx, 'configs'), 'configs');
  });
});
