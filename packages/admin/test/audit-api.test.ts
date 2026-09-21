/**
 * End-to-end coverage for the audit query API:
 *
 *   GET /admin-api/audit/entries — filtered, cursor-paginated, masked
 *   GET /admin-api/audit/export  — streaming NDJSON, fixed boundary,
 *                                  batched, disposition audit record
 *   GET /admin-api/audit/exports — recent export statuses
 *
 * Boots a real sqlite GameDatabase + express-mounted admin with two
 * operator accounts (admin + mod) so RBAC + permission-based masking
 * are exercised over HTTP, not just at the helper layer.
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

process.env.JWT_SECRET = process.env.JWT_SECRET || 'audit-api-test-secret';
const { admin } = await import('../src-backend/index.ts');
const { signSession, COOKIE_NAME } = await import('../src-backend/auth/sessions.ts');

let db: GameDatabase;
let dbPath: string;
let server: Server;
let base: string;
let distDir: string;
const cookies: Record<string, string> = {};

async function sessionCookie(userId: string, role: 'admin' | 'mod'): Promise<string> {
  const token = await signSession({ userId, role, tv: 0 });
  return `${COOKIE_NAME}=${token}`;
}

before(async () => {
  JWT.settings.secret = process.env.JWT_SECRET;
  dbPath = path.join(os.tmpdir(), `admin-audit-api-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
  db = new GameDatabase({ connectionString: dbPath });
  await db.boot();

  // Two operators + one plain user.
  await db.moderation.setRole('admin-1', 'admin');
  await db.moderation.setRole('mod-1', 'mod');

  distDir = fs.mkdtempSync(path.join(os.tmpdir(), 'admin-audit-dist-'));
  fs.writeFileSync(path.join(distDir, 'index.html'), '<html><body>ui</body></html>');

  const app = express();
  app.use(admin({ database: db, uiDistDir: distDir, logger: null }));
  server = await new Promise<Server>((resolve) => {
    const s = app.listen(0, () => resolve(s));
  });
  base = `http://127.0.0.1:${(server.address() as any).port}`;

  cookies.admin = await sessionCookie('admin-1', 'admin');
  cookies.mod = await sessionCookie('mod-1', 'mod');

  // Seed audit rows directly, including a row whose "target user" no
  // longer exists — the label snapshot is all that remains.
  await db.audit.record({
    operatorId: 'admin-1', operatorLabel: 'admin@example.com',
    action: 'user.ban', resource: 'users', resourceLabel: 'Users',
    targetId: 'ghost-1', targetLabel: 'ghost@example.com',
    payload: { reason: 'chargeback', email: 'ghost@example.com', sessionsClosed: 3 },
  });
  await new Promise((r) => setTimeout(r, 5));
  await db.audit.record({
    operatorId: 'mod-1', operatorLabel: 'mod@example.com',
    action: 'create', resource: 'configs', resourceLabel: 'Configs',
    targetId: 'double_xp', targetLabel: 'double_xp',
    payload: { row: { key: 'double_xp', value: 'on' } },
  });
  await new Promise((r) => setTimeout(r, 5));
  for (let i = 0; i < 3; i++) {
    await db.audit.record({
      operatorId: 'mod-1', action: 'update', resource: 'users',
      targetId: `u${i}`,
      payload: { changes: { level: { before: i, after: i + 1 } } },
    });
    await new Promise((r) => setTimeout(r, 5));
  }
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  await db.shutdown();
  for (const ext of ['', '-shm', '-wal']) {
    try { fs.unlinkSync(dbPath + ext); } catch { /* ignore */ }
  }
  fs.rmSync(distDir, { recursive: true, force: true });
});

async function get(who: 'admin' | 'mod', urlPath: string) {
  return fetch(`${base}${urlPath}`, { headers: { cookie: cookies[who] } });
}

describe('GET /audit/entries', () => {
  it('requires an operator session', async () => {
    const res = await fetch(`${base}/admin-api/audit/entries`);
    assert.equal(res.status, 401);
  });

  it('returns filtered rows newest-first with the label snapshots', async () => {
    const res = await get('admin', '/admin-api/audit/entries?limit=10');
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(Array.isArray(body.data));
    assert.equal(body.data.length, 5);
    const ban = body.data.find((r: any) => r.action === 'user.ban');
    assert.equal(ban.target_label, 'ghost@example.com', 'deleted-target label survives');
    assert.equal(ban.operator_label, 'admin@example.com');
  });

  it('filters by resource + action', async () => {
    const res = await get('admin', '/admin-api/audit/entries?resource=users&action=update&limit=10');
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.data.length, 3);
    assert.ok(body.data.every((r: any) => r.resource === 'users' && r.action === 'update'));
  });

  it('filters by operator', async () => {
    const res = await get('admin', '/admin-api/audit/entries?operatorId=mod-1&limit=10');
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(body.data.every((r: any) => r.operator_id === 'mod-1'));
    assert.equal(body.data.length, 4);
  });

  it('rejects an unknown action with 400', async () => {
    const res = await get('admin', '/admin-api/audit/entries?action=drop.table');
    assert.equal(res.status, 400);
  });

  it('paginates with cursors', async () => {
    const first = await (await get('admin', '/admin-api/audit/entries?limit=2')).json();
    assert.equal(first.data.length, 2);
    assert.ok(typeof first.cursor === 'string');
    const second = await (await get('admin', `/admin-api/audit/entries?limit=2&cursor=${encodeURIComponent(first.cursor)}`)).json();
    assert.equal(second.data.length, 2);
    const ids = [...first.data, ...second.data].map((r: any) => r.id);
    assert.equal(new Set(ids).size, 4, 'no overlap between pages');
  });

  it('rejects a malformed cursor with 400', async () => {
    const res = await get('admin', '/admin-api/audit/entries?cursor=%21%21not-json');
    assert.equal(res.status, 400);
  });

  it('masks fields for mods but shows them to admins', async () => {
    // Admin sees the reason + email in the clear.
    const adminRes = await get('admin', '/admin-api/audit/entries?action=user.ban&limit=1');
    const adminBody = await adminRes.json();
    assert.equal(adminBody.data[0].payload.reason, 'chargeback');
    assert.equal(adminBody.data[0].payload.email, 'ghost@example.com');

    // Default policy denies mods entirely (list: ['admin']) → 403.
    const modRes = await get('mod', '/admin-api/audit/entries?limit=1');
    assert.equal(modRes.status, 403);
  });
});

describe('GET /audit/export', () => {
  it('streams an NDJSON file with boundary + result trailers', async () => {
    const res = await get('admin', '/admin-api/audit/export?resource=users');
    assert.equal(res.status, 200);
    assert.match(res.headers.get('content-type') ?? '', /ndjson/);
    assert.match(res.headers.get('content-disposition') ?? '', /attachment/);

    const text = await res.text();
    const lines = text.trim().split('\n').map((l) => JSON.parse(l));

    assert.equal(lines[0].type, 'boundary');
    assert.equal(lines[0].filter.resource, 'users');
    // Server pinned the upper bound.
    assert.ok(lines[0].filter.until);

    const entries = lines.filter((l) => l.type === 'entry');
    const result = lines.find((l) => l.type === 'result');
    assert.equal(entries.length, 4, '3 updates + 1 ban (configs excluded)');
    assert.equal(result.status, 'completed');
    assert.equal(result.rows, 4);
    assert.equal(result.truncated, false);
  });

  it('applies the fixed window — rows after until are excluded', async () => {
    const all = await (await get('admin', '/admin-api/audit/entries?limit=10')).json();
    const oldestCreated = all.data[all.data.length - 1].created_at;
    // until = oldest row → only that one row qualifies.
    const res = await get('admin', `/admin-api/audit/export?until=${encodeURIComponent(oldestCreated)}`);
    const text = await res.text();
    const lines = text.trim().split('\n').map((l) => JSON.parse(l));
    const entries = lines.filter((l) => l.type === 'entry');
    assert.equal(entries.length, 1);
  });

  it('records a completion audit row that shows up in /audit/exports', async () => {
    // The exports from the previous two tests already wrote records;
    // allow the async disposition writes to settle.
    await new Promise((r) => setTimeout(r, 50));
    const res = await get('admin', '/admin-api/audit/exports');
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.ok(body.data.length >= 2);
    const completed = body.data
      .filter((x: any) => x.action === 'audit.export_completed' && x.boundary?.resource === 'users')
      .pop();
    assert.ok(completed, 'a successful resource-filtered export was logged');
    assert.equal(completed.operator_id, 'admin-1');
    assert.ok(completed.rows >= 1);
    assert.equal(completed.boundary.resource, 'users');
  });

  it('denies mods under the default admin-only policy', async () => {
    const res = await get('mod', '/admin-api/audit/export');
    assert.equal(res.status, 403);
  });
});

describe('permission-driven masking with widened policy', () => {
  let wideServer: Server;
  let wideBase: string;

  before(async () => {
    const { defineAdminResource } = await import('../src-backend/index.ts');
    // A deployment grants mods read access to the audit log. RBAC then
    // passes, but payload redaction must hide fields mods can't clear —
    // that's the "masking rules decided by permission" contract.
    const wideAudit = defineAdminResource(db.tables.adminAudit, {
      label: 'Audit log',
      policies: {
        list: ['admin', 'mod'],
        read: ['admin', 'mod'],
        create: 'deny',
        update: 'deny',
        delete: 'deny',
      },
    });
    const app = express();
    app.use(admin({
      database: db, uiDistDir: distDir, logger: null,
      resources: { wideAudit },
    }));
    wideServer = await new Promise<Server>((resolve) => {
      const s = app.listen(0, () => resolve(s));
    });
    wideBase = `http://127.0.0.1:${(wideServer.address() as any).port}`;
  });

  after(async () => {
    await new Promise<void>((resolve) => wideServer.close(() => resolve()));
  });

  it('lets a mod read the log but masks admin-only fields inline', async () => {
    const res = await fetch(`${wideBase}/admin-api/audit/entries?action=user.ban&limit=1`, {
      headers: { cookie: cookies.mod },
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.data.length, 1);
    const payload = body.data[0].payload;
    // Admin-only ban reason is masked for the mod…
    assert.match(String(payload.reason), /redacted/);
    // …while mod-cleared PII (email) stays visible.
    assert.equal(payload.email, 'ghost@example.com');
    assert.equal(body.redacted, true);
  });

  it('masks the same fields in the mod export stream', async () => {
    const res = await fetch(`${wideBase}/admin-api/audit/export?action=user.ban`, {
      headers: { cookie: cookies.mod },
    });
    assert.equal(res.status, 200);
    const lines = (await res.text()).trim().split('\n').map((l) => JSON.parse(l));
    const entry = lines.find((l) => l.type === 'entry');
    assert.ok(entry);
    assert.match(String(entry.payload.reason), /redacted/);
    assert.equal(entry.payload.email, 'ghost@example.com');
  });
});
