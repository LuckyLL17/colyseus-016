/**
 * Permission-driven audit payload redaction — pure unit tests.
 *
 * Covers: built-in credential masking, deep key matching, role
 * thresholds, per-resource rules, the string length hint, and the
 * guarantee that redaction never mutates the source entry.
 */
import assert from 'node:assert';
import { describe, it } from 'node:test';
import type { AuditEntry } from '@colyseus/database';
import {
  builtInRules, mergeRules, redactAuditEntry, resourceHasBindingRules,
  serializeAuditEntry, type RedactRole, type RedactionContext,
} from '../src-backend/audit/redact.ts';

function entry(overrides: Partial<AuditEntry> = {}): AuditEntry {
  return {
    id: 'e1',
    operatorId: 'op',
    operatorLabel: 'admin@x.io',
    action: 'update',
    resource: 'users',
    resourceLabel: 'Users',
    targetId: 'u1',
    targetLabel: 'target@x.io',
    payload: {},
    createdAt: new Date('2026-09-01T00:00:00Z'),
    ...overrides,
  };
}

function ctx(role: RedactRole, extra?: Record<string, any[]>): RedactionContext {
  return { role, rules: mergeRules(builtInRules(), extra as any) };
}

describe('redactAuditEntry', () => {
  it('admins see payloads in the clear', () => {
    const e = entry({ payload: { changes: { email: { before: 'a@x', after: 'b@x' } } } });
    const { entry: out, redactedFields } = redactAuditEntry(e, ctx('admin'));
    assert.equal(redactedFields.length, 0);
    assert.deepStrictEqual(out.payload, e.payload);
  });

  it('masks credentials for mods and users but not admins', () => {
    const e = entry({
      action: 'create',
      payload: { row: { id: 'u1', passwordHash: 'super-secret-hash', level: 3 } },
    });
    for (const role of ['mod', 'user'] as RedactRole[]) {
      const { entry: out, redactedFields } = redactAuditEntry(e, ctx(role));
      assert.match(String((out.payload as any).row.passwordHash), /redacted/);
      assert.equal((out.payload as any).row.level, 3, 'non-secret fields pass through');
      assert.ok(redactedFields.includes('row.passwordHash'));
    }
    const { entry: adminOut } = redactAuditEntry(e, ctx('admin'));
    assert.equal((adminOut.payload as any).row.passwordHash, 'super-secret-hash');
  });

  it('deep-masks credentials nested inside before/after diffs', () => {
    const e = entry({
      payload: {
        changes: {
          passwordHash: { before: 'h1', after: 'h2-with-quite-a-length' },
        },
      },
    });
    const { entry: out } = redactAuditEntry(e, ctx('mod'));
    // The sensitive key is masked at the first matching node — the
    // whole {before,after} object becomes the marker rather than
    // leaking either side.
    const diff = (out.payload as any).changes.passwordHash;
    assert.equal(typeof diff, 'string');
    assert.match(diff, /redacted/);
  });

  it('lets mods see mod-cleared PII (email) but hides admin-only reasons', () => {
    const e = entry({
      action: 'user.ban',
      payload: { email: 'player@x.io', reason: 'chargeback fraud', sessionsClosed: 2 },
    });
    const mod = redactAuditEntry(e, ctx('mod'));
    assert.equal((mod.entry.payload as any).email, 'player@x.io');
    assert.match(String((mod.entry.payload as any).reason), /redacted/);

    const user = redactAuditEntry(e, ctx('user'));
    assert.match(String((user.entry.payload as any).email), /redacted/);
    assert.match(String((user.entry.payload as any).reason), /redacted/);
  });

  it('never mutates the source entry', () => {
    const e = entry({ payload: { row: { passwordHash: 'abc' } } });
    const snapshot = JSON.stringify(e);
    redactAuditEntry(e, ctx('user'));
    assert.equal(JSON.stringify(e), snapshot);
  });

  it('leaves null payloads and ungoverned resources untouched', () => {
    const e = entry({ resource: 'rooms', payload: null });
    const r = redactAuditEntry(e, ctx('user'));
    assert.equal(r.entry, e);

    const free = entry({ resource: 'leaderboards', payload: { whatever: 1 } });
    assert.equal(redactAuditEntry(free, ctx('user')).redactedFields.length, 0);
  });

  it('appends game-provided rules without weakening built-in protection', () => {
    const e = entry({
      resource: 'orders',
      payload: { cardLast4: '4242', note: 'ok' },
    });
    const custom = ctx('user', {
      orders: [{ field: 'cardLast4', minRole: 'admin' }],
    });
    const { entry: out, redactedFields } = redactAuditEntry(e, custom);
    assert.match(String((out.payload as any).cardLast4), /redacted/);
    assert.ok(redactedFields.includes('cardLast4'));

    // and built-in credential masking still applies on the custom resource
    const withSecret = entry({
      resource: 'orders',
      payload: { token: 't' },
    });
    assert.ok(redactAuditEntry(withSecret, custom).redactedFields.includes('token'));
  });

  it('masks an array-typed value whole (scopes list)', () => {
    const e = entry({
      resource: 'roles',
      payload: { row: { scopes: ['users', 'configs'], role: 'mod' } },
    });
    const { entry: out, redactedFields } = redactAuditEntry(e, ctx('mod'));
    // The whole sensitive array becomes the marker (keeps its length
    // hint); non-secret siblings pass through.
    assert.equal(typeof (out.payload as any).row.scopes, 'string');
    assert.match((out.payload as any).row.scopes, /redacted/);
    assert.equal((out.payload as any).row.role, 'mod');
    assert.ok(redactedFields.some((p) => p.startsWith('row.scopes')));
  });
});

describe('resourceHasBindingRules', () => {
  it('is false once the viewer clears every rule', () => {
    const rules = builtInRules();
    assert.equal(resourceHasBindingRules(rules, 'users', 'admin'), false);
    assert.equal(resourceHasBindingRules(rules, 'users', 'mod'), true);
  });

  it('binds unknown resources for non-admins via the wildcard credential set', () => {
    const rules = builtInRules();
    assert.equal(resourceHasBindingRules(rules, 'anything', 'user'), true);
    assert.equal(resourceHasBindingRules(rules, 'anything', 'admin'), false);
  });
});

describe('serializeAuditEntry', () => {
  it('maps DB keys to the API snake_case shape with ISO dates', () => {
    const out = serializeAuditEntry(entry());
    assert.equal(out.created_at, '2026-09-01T00:00:00.000Z');
    assert.equal(out.operator_id, 'op');
    assert.equal(out.target_label, 'target@x.io');
    assert.ok(!('operatorId' in out));
  });
});
