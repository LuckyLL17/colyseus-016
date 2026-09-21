import assert from 'assert';
import { describe, it } from 'node:test';
import {
  redactAuditRow,
  redactValue,
  resolveRedactRules,
  maskValue,
  REDACTED_PLACEHOLDER,
} from '../src-backend/audit/redactor.ts';

const rules = resolveRedactRules(undefined);

describe('audit redactor', () => {
  it('removes credential-shaped fields for every role, including admin', () => {
    const payload = {
      changes: {
        password_hash: { before: 'a', after: 'b' },
        tokenVersion: { before: 1, after: 2 },
      },
      sessionToken: 'abc',
      nested: { deep: { api_key: 'k-1', kept: 'yes' } },
    };
    for (const role of ['admin', 'mod', 'user'] as const) {
      const out = redactValue(payload, 'users', role, rules) as any;
      // A credential leaf is replaced wholesale — even though the
      // value is a {before, after} object, neither side leaks.
      assert.strictEqual(out.changes.password_hash, REDACTED_PLACEHOLDER);
      assert.strictEqual(out.sessionToken, REDACTED_PLACEHOLDER);
      assert.strictEqual(out.nested.deep.api_key, REDACTED_PLACEHOLDER);
      // Non-credential values survive.
      assert.strictEqual(out.nested.deep.kept, 'yes');
      // tokenVersion is a revocation COUNTER, not a secret — it must
      // stay visible (operational audit signal).
      assert.strictEqual(out.changes.tokenVersion.after, 2);
    }
  });

  it('masks PII for mods but reveals it to admins', () => {
    const payload = { email: 'jane@example.com', ip: '192.168.1.5' };
    const modView = redactValue(payload, 'users', 'mod', rules) as any;
    assert.ok(modView.email.endsWith('@example.com'));
    assert.notStrictEqual(modView.email, 'jane@example.com');
    assert.match(modView.ip, /x\.x$/);

    const adminView = redactValue(payload, 'users', 'admin', rules) as any;
    assert.strictEqual(adminView.email, 'jane@example.com');
    assert.strictEqual(adminView.ip, '192.168.1.5');
  });

  it('resource-scoped rules only apply to their resource', () => {
    // banned_reason masking is scoped to users; same field name on a
    // custom resource isn't affected by the built-in rule.
    const row = { resource: 'guilds', payload: { banned_reason: 'toxic chat' } };
    const out = redactAuditRow(row, 'mod', rules) as any;
    assert.strictEqual(out.payload.banned_reason, 'toxic chat');

    const userRow = { resource: 'users', payload: { banned_reason: 'toxic chat' } };
    const userOut = redactAuditRow(userRow, 'mod', rules) as any;
    assert.notStrictEqual(userOut.payload.banned_reason, 'toxic chat');
  });

  it('redacts snapshot fields and credential-like labels', () => {
    const row = {
      resource: 'users',
      snapshot: {
        label: 'jane@example.com',
        fields: { email: 'jane@example.com', display_name: 'Jane' },
      },
    };
    const modView = redactAuditRow(row, 'mod', rules) as any;
    assert.notStrictEqual(modView.snapshot.fields.email, 'jane@example.com');
    assert.strictEqual(modView.snapshot.fields.display_name, 'Jane');

    const leaked = {
      resource: 'users',
      snapshot: { label: 'password reset token shown here', fields: {} },
    };
    assert.strictEqual(
      (redactAuditRow(leaked, 'admin', rules) as any).snapshot.label,
      REDACTED_PLACEHOLDER,
    );
  });

  it('custom rules can only extend the built-in set', () => {
    const custom = resolveRedactRules([
      { field: 'credit_card', mode: 'mask', minRole: 'admin' },
    ]);
    const payload = { credit_card: '4242424242424242', password: 'hunter2' };
    const out = redactValue(payload, 'guilds', 'mod', custom) as any;
    assert.match(String(out.credit_card), /\*+4242$/);
    assert.strictEqual(out.password, REDACTED_PLACEHOLDER);
  });

  it('maskValue preserves rough shapes', () => {
    assert.strictEqual(maskValue('jane@example.com'), 'j***@example.com');
    assert.strictEqual(maskValue('10.0.0.42'), '10.0.x.x');
    assert.ok(String(maskValue('longstringvalue')).endsWith('alue'));
    assert.strictEqual(maskValue(42), REDACTED_PLACEHOLDER);
    assert.strictEqual(maskValue(''), '');
  });
});
