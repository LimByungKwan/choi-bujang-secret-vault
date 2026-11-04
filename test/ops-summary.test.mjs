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

function createDatabase({ fail = false } = {}) {
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
  const supabase = {
    from(table) {
      let column;
      let filters = [];
      let ordered = false;
      let limit = null;
      const query = {
        select(selected, options) {
          column = selected;
          calls.push({ table, selected, options });
          return query;
        },
        eq(key, value) {
          filters.push([key, value]);
          return query;
        },
        order(key, options) {
          assert.equal(key, 'created_at');
          assert.deepEqual(options, { ascending: false });
          ordered = true;
          return query;
        },
        limit(value) {
          limit = value;
          return query;
        },
        async maybeSingle() {
          const result = await query.execute();
          return { data: result.data?.[0] ?? null, error: result.error };
        },
        then(resolve, reject) {
          return query.execute().then(resolve, reject);
        },
        async execute() {
          if (fail) return { data: null, count: null, error: new Error('synthetic database failure') };
          const rows = table === 'device_approval_credentials' ? credentials : audits;
          const filtered = rows.filter(row => filters.every(([key, value]) => row[key] === value));
          if (ordered) {
            return {
              data: filtered.sort((left, right) => right.created_at.localeCompare(left.created_at))
                .slice(0, limit),
              error: null,
            };
          }
          return { data: null, count: filtered.length, error: null };
        },
      };
      return query;
    },
  };
  return { supabase, calls };
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

test('returns 503 when a database count query fails', async () => {
  const harness = createHarness({ database: createDatabase({ fail: true }) });
  const response = await invoke(harness.handler);
  assert.equal(response.statusCode, 503);
  assert.deepEqual(response.body, { error: 'OPS_SUMMARY_UNAVAILABLE' });
  assert.match(response.headers.get('x-request-id'), /^[0-9a-f-]{36}$/u);
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
  assert.equal(harness.calls.length, 11);
  assert.ok(harness.calls.every(call => {
    if (call.table === 'device_approval_credentials') {
      return call.selected === 'status'
        && call.options?.count === 'exact'
        && call.options?.head === true;
    }
    return call.table === 'learning_note_restore_audit'
      && ((call.selected === 'outcome'
        && call.options?.count === 'exact'
        && call.options?.head === true)
        || (call.selected === 'created_at' && call.options === undefined));
  }));

  const json = JSON.stringify(response.body);
  for (const privateValue of [
    'owner_id', 'actor_id', studentId, adminId, credentialMarker, 'public_key',
    'challenge', backupMarker, noteTitle, noteBody,
  ]) {
    assert.equal(json.includes(privateValue), false, `response included ${privateValue}`);
  }
});
