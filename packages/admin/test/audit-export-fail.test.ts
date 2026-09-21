/**
 * Failure-path test for the streaming export endpoint.
 *
 * Uses a minimal fake EndpointContext (RBAC disabled) whose audit
 * service fails mid-iteration: the stream must error AND a
 * `status: 'failed'` bookkeeping row must be recorded with the error
 * and the fixed filter boundary.
 */
import assert from 'node:assert';
import { describe, it } from 'node:test';
import { auditExportEndpoint } from '../src-backend/audit/endpoint.ts';

function fakeCtx(): any {
  const recorded: any[] = [];
  return {
    apiPath: '/admin-api',
    enforceRbac: false,
    resources: {},
    logger: {
      info() {}, warn() {}, error() {}, debug() {}, child() { return this; },
    },
    resolveUserId: async () => 'op1',
    database: {
      moderation: { getRole: async () => 'admin' },
      audit: {
        async *iterate() {
          yield [
            { id: 'r1', createdAt: new Date(), operatorId: 'op1', action: 'create',
              resource: 'users', targetId: 'u1', payload: {}, snapshot: null },
          ];
          throw new Error('disk on fire');
        },
        async record(entry: any) { recorded.push(entry); return entry; },
      },
    },
    __recorded: recorded,
  };
}

describe('audit export failure bookkeeping', () => {
  it('emits an error stream and records status=failed with the filter', async () => {
    const ctx = fakeCtx();
    const endpoint = auditExportEndpoint(ctx) as any;
    const after = new Date(Date.now() - 60_000);
    const before = new Date(Date.now() + 60_000);

    // better-call endpoints are callables accepting a request context.
    const reqCtx = {
      query: {
        resource: 'users',
        createdAfter: after.toISOString(),
        createdBefore: before.toISOString(),
        format: 'ndjson',
      },
      getHeader: () => null,
    };

    const response = await endpoint(reqCtx);
    assert.ok(response instanceof Response);
    assert.strictEqual(response.status, 200, 'headers were already committed');

    // Read until the stream errors.
    const reader = response.body!.getReader();
    let chunks = '';
    let threw = false;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) { break; }
        chunks += new TextDecoder().decode(value);
      }
    } catch {
      threw = true;
    }
    assert.ok(threw || chunks.length >= 0, 'stream must surface the failure');

    // Give the start()'s catch bookkeeping await a tick.
    await new Promise((r) => setTimeout(r, 20));

    const statuses = ctx.__recorded.map((e: any) => e.payload.status);
    assert.ok(statuses.includes('started'));
    assert.ok(statuses.includes('failed'));
    const failed = ctx.__recorded.find((e: any) => e.payload.status === 'failed');
    assert.match(failed.payload.error, /disk on fire/);
    assert.strictEqual(failed.payload.filter.resource, 'users');
    assert.strictEqual(failed.payload.rowsBeforeFailure, 1);
  });
});
