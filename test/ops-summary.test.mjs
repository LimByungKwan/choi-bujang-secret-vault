// 이 테스트는 Supabase 모의 데이터에 대한 검증이며 운영 환경 확인이 아닙니다.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { RULE_IDS } from '../src/decider.mjs';
import { createOpsSummaryHandler } from '../api/ops/summary.js';

const adminId = '30000000-0000-4000-8000-000000000002';
const studentId = '30000000-0000-4000-8000-000000000001';
const token = 'synthetic-ops-summary-token';
const credentialMarker = 'synthetic-credential-marker';
const backupMarker = 'synthetic-backup-ref-marker';
const noteTitle = 'synthetic private note title';
const noteBody = 'synthetic private note body';
const latestAt = '2026-11-04T10:20:30.000Z';

function createDatabase({
  failCredentials = false,
  failRestoreRpc = false,
  rpcData,
} = {}) {
  const credentials = [
    { status: 'pending', credential_id: credentialMarker, owner_id: studentId },
    { status: 'pending', credential_id: 'credential-2', owner_id: studentId },
    { status: 'approved', credential_id: 'credential-3', owner_id: studentId },
    { status: 'rejected', credential_id: 'credential-4', owner_id: studentId },
    { status: 'rejected', credential_id: 'credential-5', owner_id: studentId },
    { status: 'revoked', credential_id: 'credential-6', owner_id: studentId },
  ];
  const audits = [
    { outcome: 'restored', created_at: '2026-11-04T09:00:00.000Z', actor_id: studentId, backup_ref: backupMarker, title: noteTitle, content: noteBody },
    { outcome: 'no_change', created_at: '2026-11-04T09:10:00.000Z', actor_id: studentId, backup_ref: backupMarker, title: noteTitle, content: noteBody },
    { outcome: 'no_change', created_at: latestAt, actor_id: studentId, backup_ref: backupMarker, title: noteTitle, content: noteBody },
    { outcome: 'conflict', created_at: '2026-11-04T09:30:00.000Z', actor_id: studentId, backup_ref: backupMarker, title: noteTitle, content: noteBody },
    { outcome: 'not_owned', created_at: '2026-11-04T09:40:00.000Z', actor_id: studentId, backup_ref: backupMarker, title: noteTitle, content: noteBody },
    { outcome: 'failed', created_at: '2026-11-04T09:50:00.000Z', actor_id: studentId, backup_ref: backupMarker, title: noteTitle, content: noteBody },
    { outcome: 'rejected', created_at: '2026-11-04T10:00:00.000Z', actor_id: studentId, backup_ref: backupMarker, title: noteTitle, content: noteBody },
  ];
  const calls = [];
  const fromCalls = [];
  const rpcCalls = [];
  const supabase = {
    from(table) {
      fromCalls.push(table);
      let filters = [];
      const query = {
        select(selected, options) {
          calls.push({ table, selected, options });
          return query;
        },
        eq(key, value) {
          filters.push([key, value]);
          return query;
        },
        then(resolve, reject) {
          return query.execute().then(resolve, reject);
        },
        async execute() {
          if (failCredentials && table === 'device_approval_credentials') {
            return { data: null, count: null, error: new Error('synthetic credentials query failure') };
          }
          const rows = credentials;
          const filtered = rows.filter(row => filters.every(([key, value]) => row[key] === value));
          return { data: null, count: filtered.length, error: null };
        },
      };
      return query;
    },
    async rpc(name) {
      rpcCalls.push(name);
      assert.equal(name, 'learning_note_restore_audit_summary');
      if (failRestoreRpc) {
        return { data: null, error: new Error('synthetic restore RPC failure') };
      }
      if (rpcData !== undefined) return { data: rpcData, error: null };
      const outcomes = new Map();
      for (const audit of audits) {
        const summary = outcomes.get(audit.outcome) ?? { outcome_count: 0, latest_at: null };
        summary.outcome_count += 1;
        if (summary.latest_at === null || audit.created_at > summary.latest_at) {
          summary.latest_at = audit.created_at;
        }
        outcomes.set(audit.outcome, summary);
      }
      return {
        data: [...outcomes].map(([outcome, summary]) => ({ outcome, ...summary })),
        error: null,
      };
    },
  };
  return { supabase, calls, fromCalls, rpcCalls };
}

function createHarness({
  identity = { kind: 'student', userId: adminId },
  adminList = adminId,
  database = createDatabase(),
} = {}) {
  const handler = createOpsSummaryHandler({
    env: {
      SUPABASE_URL: 'https://synthetic.supabase.invalid',
      SUPABASE_SECRET_KEY: 'synthetic-server-key',
      DEVICE_APPROVAL_ADMIN_USER_IDS: adminList,
      VERCEL_GIT_COMMIT_SHA: '1234567890abcdef',
    },
    createVerifier: () => async value => value === `Bearer ${token}` ? identity : null,
    createSupabase: () => database.supabase,
  });
  return { handler, ...database };
}

async function invoke(handler, { method = 'GET', authorization = `Bearer ${token}` } = {}) {
  let statusCode;
  let body;
  const headers = new Map();
  await handler({
    method,
    url: 'https://app.example/api/ops/summary',
    headers: authorization ? { authorization } : {},
  }, {
    setHeader: (name, value) => headers.set(name.toLowerCase(), value),
    status(value) {
      statusCode = value;
      return { json: result => { body = result; } };
    },
  });
  return { statusCode, body, headers };
}

test('rejects unauthenticated, non-admin, and non-GET requests', async () => {
  const unauthenticated = createHarness();
  const missing = await invoke(unauthenticated.handler, { authorization: null });
  assert.equal(missing.statusCode, 401);
  assert.equal(unauthenticated.calls.length, 0);

  const nonAdmin = createHarness({ identity: { kind: 'student', userId: studentId } });
  const forbidden = await invoke(nonAdmin.handler);
  assert.equal(forbidden.statusCode, 403);
  assert.equal(nonAdmin.calls.length, 0);

  const wrongMethod = createHarness();
  const methodNotAllowed = await invoke(wrongMethod.handler, { method: 'POST' });
  assert.equal(methodNotAllowed.statusCode, 405);
  assert.equal(methodNotAllowed.headers.get('allow'), 'GET');
  assert.equal(wrongMethod.calls.length, 0);
});

test('empty restore RPC results return zero counts and no latest timestamp', async () => {
  const harness = createHarness({ database: createDatabase({ rpcData: [] }) });
  const response = await invoke(harness.handler);
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body.sections.restore, {
    source: 'api_measured',
    outcomes: {
      restored: 0,
      no_change: 0,
      conflict: 0,
      not_owned: 0,
      failed: 0,
      rejected: 0,
    },
    latestAt: null,
  });
  assert.deepEqual(harness.fromCalls, [
    'device_approval_credentials',
    'device_approval_credentials',
    'device_approval_credentials',
    'device_approval_credentials',
  ]);
  assert.deepEqual(harness.rpcCalls, ['learning_note_restore_audit_summary']);
});

test('restore RPC failure affects only the restore section', async () => {
  const harness = createHarness({ database: createDatabase({ failRestoreRpc: true }) });
  const response = await invoke(harness.handler);
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body.sections.revocation, {
    source: 'api_measured',
    counts: { pending: 2, approved: 1, rejected: 2, revoked: 1 },
  });
  assert.deepEqual(response.body.sections.restore, { source: 'query_failed' });
});

test('credential query failure affects only the revocation section', async () => {
  const harness = createHarness({ database: createDatabase({ failCredentials: true }) });
  const response = await invoke(harness.handler);
  assert.equal(response.statusCode, 200);
  assert.deepEqual(response.body.sections.revocation, { source: 'query_failed' });
  assert.deepEqual(response.body.sections.restore, {
    source: 'api_measured',
    outcomes: {
      restored: 1,
      no_change: 2,
      conflict: 1,
      not_owned: 1,
      failed: 1,
      rejected: 1,
    },
    latestAt,
  });
});

test('unknown restore outcomes and non-numeric counts fail only the restore section', async t => {
  for (const [name, rpcData] of [
    ['unknown outcome', [{ outcome: 'unexpected', outcome_count: 1, latest_at: latestAt }]],
    ['non-numeric count', [{ outcome: 'restored', outcome_count: '1', latest_at: latestAt }]],
  ]) {
    await t.test(name, async () => {
      const harness = createHarness({ database: createDatabase({ rpcData }) });
      const response = await invoke(harness.handler);
      assert.equal(response.statusCode, 200);
      assert.deepEqual(response.body.sections.restore, { source: 'query_failed' });
      assert.deepEqual(response.body.sections.revocation, {
        source: 'api_measured',
        counts: { pending: 2, approved: 1, rejected: 2, revoked: 1 },
      });
    });
  }
});

test('returns measured counts and excludes private audit and credential fields', async () => {
  const harness = createHarness();
  const response = await invoke(harness.handler);
  assert.equal(response.statusCode, 200);
  assert.deepEqual(Object.keys(response.body).sort(), ['checkedAt', 'commit', 'requestId', 'sections']);
  assert.match(response.body.requestId, /^[0-9a-f-]{36}$/u);
  assert.equal(response.headers.get('x-request-id'), response.body.requestId);
  assert.ok(Number.isFinite(Date.parse(response.body.checkedAt)));
  assert.equal(response.body.commit, '1234567');
  assert.deepEqual(response.body.sections.decider, {
    source: 'code_static',
    rules: RULE_IDS,
  });
  assert.deepEqual(response.body.sections.detect, {
    source: 'not_connected',
    events: null,
  });
  assert.deepEqual(response.body.sections.revocation, {
    source: 'api_measured',
    counts: { pending: 2, approved: 1, rejected: 2, revoked: 1 },
  });
  assert.deepEqual(response.body.sections.restore, {
    source: 'api_measured',
    outcomes: {
      restored: 1,
      no_change: 2,
      conflict: 1,
      not_owned: 1,
      failed: 1,
      rejected: 1,
    },
    latestAt,
  });
  assert.equal(harness.calls.length, 4);
  assert.equal(harness.fromCalls.includes('learning_note_restore_audit'), false);
  assert.deepEqual(harness.rpcCalls, ['learning_note_restore_audit_summary']);
  assert.ok(harness.calls.every(call => {
    return call.table === 'device_approval_credentials'
      && call.selected === 'status'
      && call.options?.count === 'exact'
      && call.options?.head === true;
  }));

  const json = JSON.stringify(response.body);
  for (const privateValue of [
    'owner_id', 'actor_id', studentId, adminId, credentialMarker, 'public_key',
    'challenge', backupMarker, noteTitle, noteBody,
  ]) {
    assert.equal(json.includes(privateValue), false, `response included ${privateValue}`);
  }
});
