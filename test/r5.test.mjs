import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 2,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 2,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.equal(deploymentIdentity(env, { ...config, step: 3 }).step, 3);
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('notes function uses its server key for Supabase without returning it', async () => {
  const previousUrl = process.env.SUPABASE_URL;
  const previousKey = process.env.SUPABASE_SECRET_KEY;
  const originalFetch = globalThis.fetch;
  const testKey = 'not-a-real-key';
  const headers = new Map();
  let statusCode;
  let body;
  process.env.SUPABASE_URL = 'https://unit-test.supabase.co';
  process.env.SUPABASE_SECRET_KEY = testKey;
  try {
    globalThis.fetch = async (url, init) => {
      assert.match(String(url), /\/rest\/v1\/learning_notes/u);
      assert.equal(new Headers(init?.headers).get('apikey'), testKey);
      return new Response(JSON.stringify([{ title: '가상', content: '가상 본문' }]), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const { default: handler } = await import('../api/notes.js');
    await handler({ method: 'GET' }, {
      setHeader: (name, value) => headers.set(name.toLowerCase(), value),
      status: value => { statusCode = value; return { json: value => { body = value; } }; },
    });
    assert.equal(statusCode, 200);
    assert.equal(headers.get('cache-control'), 'no-store');
    assert.deepEqual(body, { notes: [{ title: '가상', content: '가상 본문' }] });
    assert.equal(JSON.stringify(body).includes(testKey), false);
  } finally {
    globalThis.fetch = originalFetch;
    if (previousUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = previousUrl;
    if (previousKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = previousKey;
  }
});

test('notes function logs only safe diagnostics for Supabase failures', async () => {
  const previousUrl = process.env.SUPABASE_URL;
  const previousKey = process.env.SUPABASE_SECRET_KEY;
  const originalFetch = globalThis.fetch;
  const originalConsoleError = console.error;
  const testKey = 'server-secret-sentinel';
  const privateMessage = 'private-message-header-query-sentinel';
  const logEntries = [];
  const results = [];
  process.env.SUPABASE_URL = 'https://unit-test.supabase.co';
  process.env.SUPABASE_SECRET_KEY = testKey;
  console.error = (...args) => logEntries.push(args);
  try {
    const { default: handler } = await import('../api/notes.js');
    const invoke = async () => {
      let statusCode;
      let body;
      await handler({ method: 'GET' }, {
        setHeader: () => {},
        status: value => { statusCode = value; return { json: value => { body = value; } }; },
      });
      results.push({ statusCode, body });
    };

    globalThis.fetch = async () => new Response(JSON.stringify({
      code: '42501', message: privateMessage, details: privateMessage, hint: privateMessage,
    }), { status: 403, headers: { 'content-type': 'application/json' } });
    await invoke();

    process.env.SUPABASE_URL = 'not-a-valid-url';
    await invoke();

    assert.deepEqual(results, [
      { statusCode: 502, body: { error: 'NOTES_UNAVAILABLE' } },
      { statusCode: 502, body: { error: 'NOTES_UNAVAILABLE' } },
    ]);
    assert.deepEqual(logEntries, [
      ['Supabase notes query failed', { code: '42501', status: 403 }],
      ['Supabase notes query failed', { code: 'UNKNOWN', status: null }],
    ]);
    const output = JSON.stringify({ results, logEntries });
    assert.equal(output.includes(testKey), false);
    assert.equal(output.includes(privateMessage), false);
    assert.equal(output.includes('unit-test.supabase.co'), false);
    assert.equal(output.includes('not-a-valid-url'), false);
    assert.equal(output.includes('/rest/v1/learning_notes'), false);
  } finally {
    globalThis.fetch = originalFetch;
    console.error = originalConsoleError;
    if (previousUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = previousUrl;
    if (previousKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = previousKey;
  }
});

test('attack check reads the public notes API without credentials', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(JSON.stringify({ notes: [{ title: '가상' }] }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const [result] = await runAttackChecks(config);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/api/notes');
    assert.equal(options.redirect, 'error');
    assert.match(result.observed, /메모 응답이 확인됨/u);
    globalThis.fetch = async () => new Response('<html>not the data</html>', { status: 200 });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /보이지 않음/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
