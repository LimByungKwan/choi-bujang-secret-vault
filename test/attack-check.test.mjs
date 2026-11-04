import assert from 'node:assert/strict';
import { test } from 'node:test';
import config from '../aleph.config.json' with { type: 'json' };
import { formatAttackTable } from '../scripts/attack-table.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

function response(status, body, requestId = 'synthetic-request-id') {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'content-type': 'application/json',
      'x-request-id': requestId,
    },
  });
}

test('only plain GET checks are sent; write and header-forging checks are not_run', async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  try {
    globalThis.fetch = async (url, init) => {
      requests.push({ url: new URL(url), init });
      return response(401, { error: 'UNAUTHORIZED' });
    };
    const results = await runAttackChecks(config);

    assert.ok(results.length <= 20);
    assert.deepEqual(
      requests.map(({ url, init }) => `${init.method} ${url.pathname}`),
      [
        'GET /api/notes',
        'GET /api/notes/00000000-0000-4000-8000-000000000000',
        'GET /api/device/admin',
        'GET /api/ops/summary',
      ],
    );
    for (const { url, init } of requests) {
      assert.equal(url.origin, new URL(config.publicAppUrl).origin);
      assert.ok(init.method === 'GET' || init.method === 'HEAD');
      assert.equal(init.redirect, 'error');
      assert.equal(init.headers, undefined);
      assert.equal(init.body, undefined);
      assert.equal(init.signal instanceof AbortSignal, true);
    }
    const sent = results.filter(result => result.observed !== 'not_run');
    assert.equal(sent.length, requests.length);
    for (const result of sent) assert.equal(result.observed, 'HTTP 401 · 메모 필드 없음');
    for (const attackId of [
      'forged_bearer_note_read', 'forged_approval_header', 'anonymous_note_update',
      'anonymous_note_delete', 'anonymous_restore', 'anonymous_device_admin_decide',
      'ops_summary_wrong_method', 'cross_origin_login',
    ]) {
      assert.equal(results.find(result => result.attackId === attackId).observed, 'not_run');
    }
    assert.equal(results[0].attackId, 'anonymous_note_read');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('checks satisfy the bundle contract and record observed fields without verdicts', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url, init) => {
      if (new URL(url).pathname === '/api/notes' && init.method === 'GET') {
        return response(200, {
          notes: [{ title: 'synthetic private title', content: 'synthetic private body' }],
        });
      }
      return response(401, {});
    };
    const results = await runAttackChecks(config);

    assert.ok(results.length <= 20);
    assert.equal(new Set(results.map(result => result.attackId)).size, results.length);
    for (const result of results) {
      assert.deepEqual(Object.keys(result).sort(), ['attackId', 'expected', 'observed']);
      assert.match(result.attackId, /^[a-z0-9][a-z0-9_.-]{0,79}$/iu);
      for (const value of Object.values(result)) {
        assert.equal(typeof value, 'string');
        assert.ok(value.length <= 300);
      }
      assert.equal(result.observed.includes('통과'), false);
      assert.equal(result.observed.includes('차단 성공'), false);
      assert.equal(result.observed.includes('방어함'), false);
      assert.equal(result.observed.includes('synthetic private title'), false);
      assert.equal(result.observed.includes('synthetic private body'), false);
    }

    const unauthorized = results.find(result => result.attackId === 'anonymous_note_by_id');
    assert.match(unauthorized.observed, /HTTP 401/u);
    assert.match(unauthorized.observed, /메모 필드 없음/u);
    assert.equal(unauthorized.observed.includes('synthetic-request-id'), false);
    assert.doesNotMatch(unauthorized.observed, /\d{4}-\d{2}-\d{2}T/u);

    const notesRead = results.find(result => result.attackId === 'anonymous_note_read');
    assert.match(notesRead.observed, /HTTP 200 · 메모 필드 있음/u);
    assert.equal(notesRead.observed.includes('통과'), false);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('a request without an HTTP response is not_run and later checks still execute', async () => {
  const originalFetch = globalThis.fetch;
  let calls = 0;
  try {
    globalThis.fetch = async () => {
      calls += 1;
      if (calls === 1) throw new Error('synthetic network failure');
      return response(401, {});
    };
    const results = await runAttackChecks(config);

    assert.ok(calls > 1);
    assert.equal(results[0].observed, 'not_run');
    assert.equal(results[1].observed, 'HTTP 401 · 메모 필드 없음');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('attack table restricts status cells to measured or not run', () => {
  const output = formatAttackTable([
    {
      attackId: 'anonymous_note_read',
      expected: '2xx가 아니고 메모 필드 없음',
      observed: 'HTTP 401 · 메모 필드 없음',
    },
    {
      attackId: 'anonymous_note_by_id',
      expected: '2xx가 아니고 메모 필드 없음',
      observed: 'not_run',
    },
  ]);
  const rows = output.trim().split('\n').slice(2);
  const statusValues = rows.map(row => row.split('|').at(-2).trim());
  assert.deepEqual(statusValues, ['실측', '미실행']);
  const actual = rows[0].split('|')[5].trim();
  assert.equal(actual, 'HTTP 401 · 메모 필드 없음');
  assert.doesNotMatch(actual, /\d{2}:\d{2}:\d{2}/u);
});

test('attack table assigns anonymous ops summary to step 12', () => {
  const output = formatAttackTable([{
    attackId: 'anonymous_ops_summary',
    expected: '2xx가 아니고 메모 필드 없음',
    observed: 'HTTP 401 · 메모 필드 없음',
  }]);
  const row = output.trim().split('\n')[2];
  assert.equal(row.split('|')[1].trim(), '12');
});
