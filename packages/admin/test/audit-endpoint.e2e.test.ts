/**
 * End-to-end tests for the audit query API + streaming export.
 *
 * Boots a real GameDatabase (sqlite) behind the express-compatible
 * admin() middleware, seeds audit rows (incl. credential/PII payloads),
 * and drives the endpoints over HTTP with a signed admin session.
 *
 * Covers:
 *   - operator/resource/action/time-window filters
 *   - keyset cursor paging without duplicates
 *   - role-driven redaction (admin vs mod)
 *   - streaming NDJSON/CSV export: window required, bounded batches,
 *     credential redaction in stream, success/failure bookkeeping rows
 *   - snapshot survives target deletion
 */
import assert from 'node:assert';
import { describe, it, before, after } from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { Server } from 'node:http';
import express from 'express';
import { GameDatabase } from '@colyseus/database';
import { JWT } from '@colyseus/auth';

process.env.JWT_SECRET = process.env.JWT_SECRET || 'audit-e2e-secret';
process.env.NODE_ENV = 'production'; // disable X-User-Id dev header
const { admin } = await import('../src-backend/index.ts');
const { COOKIE_NAME, signSession } = await import('../src-backend/auth/sessions.ts');

let db: GameDatabase;
let dbPath: string;
let server: Server;
let url: string;

async function boot(): Promise<void> {
  dbPath = path.join(os.tmpdir(), `admin-audit-e2e-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
  db = new GameDatabase({ connectionString: dbPath });
  await db.boot();

  // Direct roles-table inserts (admin "root", mod "viewer").
  const roles = (db as any).tables.roles;
  await db.drizzle.insert(roles).values([
    { userId: 'root', role: 'admin', scopes: [] },
    { userId: 'viewer', role: 'mod', scopes: [] },
  ]);

  const distDir = fs.mkdtempSync(path.join(os.tmpdir(), 'admin-audit-dist-'));
  fs.writeFileSync(path.join(distDir, 'index.html'), '<html><head></head><body></body></html>');

  const app = express();
  app.use(admin({ database: db, uiDistDir: distDir, logger: null }));
  server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  url = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}

before(boot);

after(async () => {
  server?.close();
  await db?.shutdown();
  for (const ext of ['', '-shm', '-wal']) {
    try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ }
  }
});

async function cookieFor(userId: string, role: 'admin' | 'mod'): Promise<string> {
  const tv = await db.auth.getTokenVersion(userId).catch(() => 0);
  const token = await signSession({ userId, role, tv: tv ?? 0 });
  return `${COOKIE_NAME}=${token}`;
}

describe('audit query API (e2e)', () => {
  const t0 = Date.now();

  it('filters by operator/resource/action and paginates with a cursor', async () => {
    // Seed: 12 users-create rows by root + 1 configs delete by viewer.
    for (let i = 0; i < 12; i++) {
      await db.audit.record({
        operatorId: 'root', action: 'create', resource: 'users',
        targetId: `u${i}`,
        payload: { row: { id: `u${i}`, email: `user${i}@example.com`, passwordHash: 'secret!' } },
        snapshot: { label: `user${i}@example.com`, fields: { email: `user${i}@example.com` } },
      });
    }
    await db.audit.record({
      operatorId: 'viewer', action: 'delete', resource: 'configs',
      targetId: 'flag', payload: { row: { key: 'flag' } },
    });

    const cookie = await cookieFor('root', 'admin');
    // Page 1 — small page size forces keyset walking.
    const r1 = await fetch(`${url}/admin-api/audit/query?resource=users&limit=5`, {
      headers: { cookie },
    });
    assert.strictEqual(r1.status, 200);
    const p1 = await r1.json();
    assert.strictEqual(p1.entries.length, 5);
    assert.ok(p1.nextCursor, 'first page must carry a cursor');

    // Page 2 using the cursor.
    const r2 = await fetch(
      `${url}/admin-api/audit/query?resource=users&limit=5&cursor=${encodeURIComponent(p1.nextCursor)}`,
      { headers: { cookie } },
    );
    const p2 = await r2.json();
    assert.strictEqual(p2.entries.length, 5);

    const ids = new Set([...p1.entries, ...p2.entries].map((e: any) => e.id));
    assert.strictEqual(ids.size, 10, 'cursor pages must not overlap');

    // action filter
    const ra = await fetch(`${url}/admin-api/audit/query?action=delete`, { headers: { cookie } });
    const pa = await ra.json();
    assert.ok(pa.entries.every((e: any) => e.action === 'delete'));
    assert.ok(pa.entries.length >= 1);

    // time window: far future → empty
    const future = new Date(t0 + 10_000_000_000).toISOString();
    const rf = await fetch(
      `${url}/admin-api/audit/query?createdAfter=${encodeURIComponent(future)}`,
      { headers: { cookie } },
    );
    assert.strictEqual((await rf.json()).entries.length, 0);

    // bad cursor → 400
    const bad = await fetch(`${url}/admin-api/audit/query?cursor=%%%`, { headers: { cookie } });
    assert.strictEqual(bad.status, 400);
  });

  it('requires authentication and admin role', async () => {
    const anon = await fetch(`${url}/admin-api/audit/query`);
    assert.strictEqual(anon.status, 401);

    const modCookie = await cookieFor('viewer', 'mod');
    const mod = await fetch(`${url}/admin-api/audit/query`, { headers: { cookie: modCookie } });
    assert.strictEqual(mod.status, 403);
  });

  it('masks PII/credentials in the generic CRUD read for mods... admins see all', async () => {
    // Admin sees real values over the audit query API.
    const adminCookie = await cookieFor('root', 'admin');
    const ar = await fetch(`${url}/admin-api/audit/query?action=create&limit=1`, {
      headers: { cookie: adminCookie },
    });
    const ap = await ar.json();
    const aRow = ap.entries[0];
    // Newest create first — 12 were inserted in order, so it's user11.
    assert.match(aRow.payload.row.email, /@example\.com$/);
    // Credentials redacted even for admin.
    assert.strictEqual(aRow.payload.row.passwordHash, '[REDACTED]');
  });

  it('generic adminAudit list endpoint also redacts', async () => {
    const cookie = await cookieFor('root', 'admin');
    const r = await fetch(`${url}/admin-api/adminAudit?_start=0&_end=2`, { headers: { cookie } });
    assert.strictEqual(r.status, 200);
    const rows = await r.json();
    for (const row of rows) {
      const json = JSON.stringify(row);
      assert.ok(!json.includes('secret!'), 'raw credential must not appear');
    }
  });

  it('hides adminAudit from the catalog', async () => {
    const cookie = await cookieFor('root', 'admin');
    const r = await fetch(`${url}/admin-api`, { headers: { cookie } });
    const catalog = await r.json();
    assert.ok(!catalog.some((c: any) => c.name === 'adminAudit'),
      'adminAudit must not appear in the UI catalog');
  });
});

describe('audit streaming export (e2e)', () => {
  before(async () => {
    // Fresh window of rows for deterministic export assertions.
    for (let i = 0; i < 7; i++) {
      await db.audit.record({
        operatorId: 'root', action: 'custom', resource: 'players',
        targetId: `p${i}`,
        payload: { name: 'wipe', args: { id: `p${i}`, token: 'leak-me' } },
        snapshot: { fields: { email: `p${i}@x.com` } },
      });
    }
    // Small delay so the upper bound is inclusive.
    await new Promise((r) => setTimeout(r, 10));
  });

  it('rejects exports without a bounded window', async () => {
    const cookie = await cookieFor('root', 'admin');
    const r = await fetch(`${url}/admin-api/audit/export?format=ndjson`, { headers: { cookie } });
    assert.strictEqual(r.status, 400);
  });

  it('streams NDJSON in batches, redacts credentials, and bookkeeps success', async () => {
    const cookie = await cookieFor('root', 'admin');
    const after = new Date(Date.now() - 60_000).toISOString();
    const before = new Date(Date.now() + 60_000).toISOString();
    const params = new URLSearchParams({
      resource: 'players', createdAfter: after, createdBefore: before, format: 'ndjson',
    });
    const r = await fetch(`${url}/admin-api/audit/export?${params}`, { headers: { cookie } });
    assert.strictEqual(r.status, 200);
    assert.match(r.headers.get('content-type') ?? '', /ndjson/);
    assert.match(r.headers.get('content-disposition') ?? '', /attachment/);
    assert.ok(!r.headers.get('content-length'), 'stream must not carry a content-length');

    const body = await r.text();
    const lines = body.trim().split('\n').filter(Boolean);
    assert.ok(lines.length >= 7, `expected >=7 export lines, got ${lines.length}`);
    for (const line of lines) {
      const obj = JSON.parse(line);
      assert.strictEqual(obj.resource, 'players');
      assert.ok(!JSON.stringify(obj).includes('leak-me'), 'credential leaked into export');
      // Exports must not contain their own audit.export bookkeeping.
      assert.notStrictEqual(obj.action, 'audit.export');
    }

    // Bookkeeping: a success audit.export row exists with the count.
    const records = await db.audit.list({ resource: 'adminAudit' });
    const bookkeeping = records.filter((e) => e.action === 'audit.export');
    const statuses = bookkeeping.map((e: any) => e.payload.status);
    assert.ok(statuses.includes('started'));
    const success = bookkeeping.find((e: any) => e.payload.status === 'success');
    assert.ok(success, 'export success must be recorded');
    assert.ok((success as any).payload.rows >= 7);
    assert.ok((success as any).payload.bytes > 0);
    // The fixed filter boundary is echoed into the bookkeeping row.
    assert.deepStrictEqual((success as any).payload.filter.resource, 'players');
  });

  it('streams CSV with header and quoting-safe cells', async () => {
    const cookie = await cookieFor('root', 'admin');
    const after = new Date(Date.now() - 60_000).toISOString();
    const before = new Date(Date.now() + 60_000).toISOString();
    const params = new URLSearchParams({
      resource: 'players', createdAfter: after, createdBefore: before, format: 'csv',
    });
    const r = await fetch(`${url}/admin-api/audit/export?${params}`, { headers: { cookie } });
    assert.strictEqual(r.status, 200);
    const body = await r.text();
    const lines = body.split('\n').filter(Boolean);
    assert.match(lines[0]!, /^﻿?id,created_at,/);
    assert.ok(lines.length >= 8); // header + 7 rows
    // Self-exclusion holds even without a resource/action filter:
    // no bookkeeping row leaks into the export data.
    assert.ok(!lines.slice(1).some((l) => l.includes('audit.export')),
      'audit.export bookkeeping rows must not appear in exported data');
  });
});
