import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createNotesHandler } from '../api/notes.js';
import { verifyProtectedDeviceAssertion } from '../src/device-approval-service.mjs';

const userId = '30000000-0000-4000-8000-000000000001';
const challengeId = '40000000-0000-4000-8000-000000000001';
const credentialId = 'Y3JlZGVudGlhbC1pZA';

test('direct API access with body or header approval flags is denied before note queries', async () => {
  const previousUrl = process.env.SUPABASE_URL;
  const previousKey = process.env.SUPABASE_SECRET_KEY;
  const originalFetch = globalThis.fetch;
  process.env.SUPABASE_URL = 'https://unit-test.supabase.co';
  process.env.SUPABASE_SECRET_KEY = 'test-secret-placeholder';
  let noteQueries = 0;
  globalThis.fetch = async () => {
    noteQueries += 1;
    return new Response('[]', { status: 200 });
  };

  try {
    const handler = createNotesHandler({
      createVerifier: () => async () => ({ kind: 'student', userId }),
    });

    test('approved note access verifies the assertion against stored challenge and owner-bound key', async () => {
      const calls = [];
      const supabase = {
        from(table) {
          const filters = [];
          const query = {
            select() { return query; },
            eq(key, value) { filters.push([key, value]); return query; },
            async maybeSingle() {
              calls.push({ table, filters });
              if (table === 'device_approval_challenges') {
                return {
                  data: {
                    id: challengeId,
                    challenge: 'fresh-challenge',
                    expires_at: new Date(Date.now() + 60_000).toISOString(),
                    consumed_at: null,
                    http_method: 'GET',
                    canonical_target: '/api/notes',
                    body_sha256: null,
                    body_present: false,
                  },
                  error: null,
                };
              }
              return {
                data: {
                  credential_id: credentialId,
                  public_key: Buffer.from('public-key').toString('base64url'),
                  sign_count: 0,
                  transports: ['internal'],
                  status: 'approved',
                },
                error: null,
              };
            },
          };
          return query;
        },
        async rpc(name, args) {
          assert.equal(name, 'consume_device_assertion');
          assert.equal(args.p_owner_id, userId);
          assert.equal(args.p_credential_id, credentialId);
          assert.equal(args.p_challenge, 'fresh-challenge');
          assert.equal(args.p_http_method, 'GET');
          assert.equal(args.p_canonical_target, '/api/notes');
          assert.equal(args.p_body_sha256, null);
          assert.equal(args.p_body_present, false);
          return { data: 'approved', error: null };
        },
      };
      const verified = await verifyProtectedDeviceAssertion({
        method: 'GET',
        url: '/api/notes',
        headers: {
          'x-device-assertion': JSON.stringify({
            challengeId,
            response: { id: credentialId },
          }),
        },
      }, { kind: 'student', userId }, supabase, async options => {
        assert.equal(options.expectedChallenge, 'fresh-challenge');
        assert.equal(options.requireUserVerification, true);
        return { verified: true, authenticationInfo: { newCounter: 1 } };
      });

      assert.equal(verified, true);
      assert.equal(calls.length, 2);
      assert.ok(calls.every(({ filters }) => filters.some(([key, value]) => (
        key === 'owner_id' && value === userId
      ))));
    });

    test('missing, altered, expired, and consumed request assertions fail closed before DB work', async t => {
      const { verifyProtectedDeviceAssertion } = await import('../src/device-approval-service.mjs');
      const baseChallenge = {
        id: challengeId,
        challenge: 'fresh-challenge',
        expires_at: new Date(Date.now() + 60_000).toISOString(),
        consumed_at: null,
        http_method: 'POST',
        canonical_target: '/api/notes?mode=write&tag=a',
        body_sha256: 'a'.repeat(64),
        body_present: true,
      };

      for (const scenario of [
        { name: 'missing assertion', header: null, request: {} },
        {
          name: 'changed method',
          header: JSON.stringify({ challengeId, response: { id: credentialId } }),
          request: { method: 'PUT', url: '/api/notes?mode=write&tag=a', body: { title: 'x' } },
        },
        {
          name: 'changed path and query',
          header: JSON.stringify({ challengeId, response: { id: credentialId } }),
          request: { method: 'POST', url: '/api/notes?mode=read&tag=a', body: { title: 'x' } },
        },
        {
          name: 'changed body',
          header: JSON.stringify({ challengeId, response: { id: credentialId } }),
          request: { method: 'POST', url: '/api/notes?tag=a&mode=write', body: { title: 'changed' } },
        },
        {
          name: 'expired challenge',
          header: JSON.stringify({ challengeId, response: { id: credentialId } }),
          request: { method: 'POST', url: '/api/notes?tag=a&mode=write', body: { title: 'x' } },
          expires: new Date(Date.now() - 60_000).toISOString(),
        },
        {
          name: 'replayed challenge',
          header: JSON.stringify({ challengeId, response: { id: credentialId } }),
          request: { method: 'POST', url: '/api/notes?tag=a&mode=write', body: { title: 'x' } },
          consumed: new Date().toISOString(),
        },
      ]) {
        await t.test(scenario.name, async () => {
          let rpcCalls = 0;
          const supabase = {
            from(table) {
              const query = {
                select() { return query; },
                eq() { return query; },
                async maybeSingle() {
                  if (table === 'device_approval_challenges') {
                    return {
                      data: {
                        ...baseChallenge,
                        expires_at: scenario.expires ?? baseChallenge.expires_at,
                        consumed_at: scenario.consumed ?? null,
                      },
                      error: null,
                    };
                  }
                  return {
                    data: {
                      credential_id: credentialId,
                      public_key: Buffer.from('public-key').toString('base64url'),
                      sign_count: 0,
                      transports: ['internal'],
                      status: 'approved',
                    },
                    error: null,
                  };
                },
              };
              return query;
            },
            async rpc() {
              rpcCalls += 1;
              return { data: 'approved', error: null };
            },
          };
          const request = {
            ...scenario.request,
            headers: scenario.header
              ? { 'x-device-assertion': scenario.header }
              : {},
          };
          const result = await verifyProtectedDeviceAssertion(
            request,
            { kind: 'student', userId },
            supabase,
            async () => ({ verified: true, authenticationInfo: { newCounter: 1 } }),
          );
          assert.equal(result, false);
          assert.equal(rpcCalls, 0);
        });
      }
    });
    let statusCode;
    let responseBody;
    await handler({
      method: 'GET',
      url: '/api/notes',
      headers: {
        authorization: 'Bearer verified-test-session',
        'x-device-approved': 'true',
      },
      body: { approved: true },
    }, {
      setHeader: () => {},
      status: value => {
        statusCode = value;
        return { json: valueBody => { responseBody = valueBody; } };
      },
    });

    assert.equal(statusCode, 403);
    assert.deepEqual(responseBody, { error: 'DEVICE_NOT_APPROVED' });
    assert.equal(noteQueries, 0);
  } finally {
    globalThis.fetch = originalFetch;
    if (previousUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = previousUrl;
    if (previousKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = previousKey;
  }
});
