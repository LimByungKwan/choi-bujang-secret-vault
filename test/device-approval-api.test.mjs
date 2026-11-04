import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createDeviceApprovalHandler } from '../src/device-approval-service.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const userId = '30000000-0000-4000-8000-000000000001';
const adminId = '30000000-0000-4000-8000-000000000002';
const credentialId = 'Y3JlZGVudGlhbC1pZA';
const challengeId = '40000000-0000-4000-8000-000000000001';
const statusChallengeId = '40000000-0000-4000-8000-000000000002';

function createDatabase() {
  const credentials = [];
  const challenges = [];

  function builder(table) {
    const filters = [];
    let rows = null;
    return {
      select() { return this; },
      eq(key, value) { filters.push([key, value]); return this; },
      in(key, values) { filters.push([key, values]); return this; },
      order() { return this; },
      insert(value) { rows = Array.isArray(value) ? value : [value]; return this; },
      async single() {
        const result = await this.execute();
        return { data: result.data?.[0] ?? null, error: result.error };
      },
      async maybeSingle() {
        const result = await this.execute();
        return { data: result.data?.[0] ?? null, error: result.error };
      },
      then(resolve, reject) { return this.execute().then(resolve, reject); },
      async execute() {
        const source = table === 'device_approval_credentials' ? credentials : challenges;
        if (rows) {
          const created = rows.map(row => ({
            ...row,
            id: row.id ?? challengeId,
            expires_at: row.expires_at ?? new Date(Date.now() + 300_000).toISOString(),
            consumed_at: null,
          }));
          source.push(...created);
          return { data: created, error: null };
        }
        return {
          data: source.filter(row => filters.every(([key, value]) => (
            Array.isArray(value) ? value.includes(row[key]) : row[key] === value
          ))),
          error: null,
        };
      },
    };
  }

  return {
    credentials,
    challenges,
    supabase: {
      from: builder,
      async rpc(name, args) {
        if (name === 'issue_device_approval_challenge') {
          const id = args.p_purpose === 'registration' ? challengeId : statusChallengeId;
          challenges.push({
            id,
            owner_id: args.p_owner_id,
            purpose: args.p_purpose,
            challenge: args.p_challenge,
            expires_at: args.p_expires_at,
            consumed_at: null,
            http_method: args.p_http_method,
            canonical_target: args.p_canonical_target,
            body_sha256: args.p_body_sha256,
            body_present: args.p_body_present,
          });
          return { data: id, error: null };
        }
        if (name === 'complete_device_registration') {
          const challenge = challenges.find(item => item.id === args.p_challenge_id
            && item.owner_id === args.p_owner_id
            && item.purpose === 'registration'
            && item.challenge === args.p_challenge
            && item.consumed_at === null);
          if (!challenge) return { data: 'invalid_challenge', error: null };
          challenge.consumed_at = new Date().toISOString();
          if (credentials.some(item => item.credential_id === args.p_credential_id)) {
            return { data: 'credential_conflict', error: null };
          }
          credentials.push({
            credential_id: args.p_credential_id,
            owner_id: args.p_owner_id,
            public_key: args.p_public_key,
            sign_count: args.p_sign_count,
            transports: args.p_transports,
            status: 'pending',
          });
          return { data: 'pending', error: null };
        }
        if (name === 'consume_device_assertion') {
          const challenge = challenges.find(item => item.id === args.p_challenge_id
            && item.owner_id === args.p_owner_id
            && item.challenge === args.p_challenge
            && item.consumed_at === null
            && item.http_method === args.p_http_method
            && item.canonical_target === args.p_canonical_target
            && item.body_sha256 === args.p_body_sha256
            && item.body_present === args.p_body_present);
          if (!challenge) return { data: 'invalid_challenge', error: null };
          challenge.consumed_at = new Date().toISOString();
          const credential = credentials.find(item => item.credential_id === args.p_credential_id
            && item.owner_id === args.p_owner_id);
          if (!credential) return { data: 'unknown', error: null };
          credential.sign_count = args.p_sign_count;
          return { data: credential.status, error: null };
        }
        if (name === 'decide_device_approval') {
          const credential = credentials.find(item => item.credential_id === args.p_credential_id
            && item.owner_id === args.p_owner_id);
          if (!credential) return { data: 'not_found', error: null };
          if (credential.status === 'pending' && ['approve', 'reject'].includes(args.p_action)) {
            credential.status = args.p_action === 'approve' ? 'approved' : 'rejected';
            return { data: credential.status, error: null };
          }
          if (credential.status === 'approved' && args.p_action === 'revoke') {
            credential.status = 'revoked';
            return { data: 'revoked', error: null };
          }
          return { data: 'conflict', error: null };
        }
        return { data: null, error: { code: 'UNEXPECTED_RPC' } };
      },
    },
  };
}

function createHarness({
  user = userId,
  adminList = adminId,
  db = createDatabase(),
  verifyRegistration = async () => ({
    verified: true,
    registrationInfo: {
      credential: {
        id: credentialId,
        publicKey: Buffer.from('public-key'),
        counter: 0,
        transports: ['internal'],
      },
    },
  }),
  verifyAssertionResponse = async () => ({
    verified: true,
    authenticationInfo: { newCounter: 1 },
  }),
} = {}) {
  const handler = createDeviceApprovalHandler({
    env: {
      SUPABASE_URL: 'https://unit-test.supabase.co',
      SUPABASE_SECRET_KEY: 'test-secret-placeholder',
      DEVICE_APPROVAL_ADMIN_USER_IDS: adminList,
    },
    createVerifier: () => async authorization => authorization === 'Bearer test'
      ? { kind: 'student', userId: user }
      : null,
    createSupabase: () => db.supabase,
    makeRegistrationOptions: async () => ({ challenge: 'registration-challenge' }),
    ...(verifyRegistration ? { verifyRegistration } : {}),
    makeAuthenticationOptions: async () => ({
      challenge: 'authentication-challenge',
      allowCredentials: [{ id: credentialId }],
    }),
    ...(verifyAssertionResponse ? { verifyAssertionResponse } : {}),
  });
  return { handler, ...db };
}

async function invoke(handler, action, body = {}, authorization = 'Bearer test', method = 'POST') {
  let statusCode;
  let responseBody;
  const headers = new Map();
  await handler({
    method,
    url: `https://app.example/api/device/${action}`,
    headers: authorization ? { authorization } : {},
    body,
  }, {
    setHeader: (name, value) => headers.set(name.toLowerCase(), value),
    status: value => {
      statusCode = value;
      return { json: valueBody => { responseBody = valueBody; } };
    },
  });
  return { statusCode, body: responseBody, headers };
}

async function registerDevice(harness) {
  const options = await invoke(harness.handler, 'registration-options');
  assert.equal(options.statusCode, 200);
  const registered = await invoke(harness.handler, 'registration-verify', {
    challengeId,
    response: { id: credentialId },
  });
  assert.deepEqual(registered, {
    statusCode: 201,
    body: { status: 'pending' },
    headers: new Map([['cache-control', 'no-store']]),
  });
}

test('WebAuthn registration proof is stored as pending, not implicitly approved', async () => {
  const harness = createHarness();
  await registerDevice(harness);
  assert.equal(harness.credentials.length, 1);
  assert.equal(harness.credentials[0].status, 'pending');
  assert.equal(harness.credentials[0].public_key, Buffer.from('public-key').toString('base64url'));
});

test('cookie-authenticated device requests still require same-origin CSRF validation', async () => {
  let verifierCalls = 0;
  const handler = createDeviceApprovalHandler({
    env: {
      SUPABASE_URL: 'https://unit-test.supabase.co',
      SUPABASE_SECRET_KEY: 'test-secret-placeholder',
    },
    createVerifier: () => {
      verifierCalls += 1;
      return async () => ({ kind: 'student', userId });
    },
    createSupabase: () => {
      assert.fail('database client must not be created before CSRF validation');
    },
  });
  let statusCode;
  let body;
  await handler({
    method: 'POST',
    url: 'https://app.example/api/device/challenge',
    headers: {
      cookie: `__Secure-aleph_access=session; __Secure-aleph_csrf=${'a'.repeat(64)}`,
      origin: config.publicAppUrl,
    },
    body: { purpose: 'status' },
  }, {
    setHeader: () => {},
    status: value => {
      statusCode = value;
      return { json: result => { body = result; } };
    },
  });

  assert.equal(statusCode, 403);
  assert.deepEqual(body, { error: 'CSRF_FAILED' });
  assert.equal(verifierCalls, 0);
});

test('admin allowlist is checked server-side before approval decisions', async () => {
  const harness = createHarness({ user: userId });
  await registerDevice(harness);

  const denied = await invoke(harness.handler, 'admin', {
    ownerId: userId, credentialId, decision: 'approve',
  });
  assert.equal(denied.statusCode, 403);
  assert.deepEqual(denied.body, { error: 'FORBIDDEN' });
  assert.equal(harness.credentials[0].status, 'pending');

  const adminHarness = createHarness({ user: adminId });
  adminHarness.credentials.push({
    credential_id: credentialId, owner_id: userId, status: 'pending',
  });
  const pending = await invoke(adminHarness.handler, 'admin', {}, 'Bearer test', 'GET');
  assert.equal(pending.statusCode, 200);
  assert.equal(pending.body.requests.length, 1);
  assert.equal(Object.hasOwn(pending.body.requests[0], 'public_key'), false);
  const approved = await invoke(adminHarness.handler, 'admin', {
    ownerId: userId, credentialId, decision: 'approve',
  });
  assert.equal(approved.statusCode, 200);
  assert.deepEqual(approved.body, { status: 'approved' });

  const revoked = await invoke(adminHarness.handler, 'admin', {
    ownerId: userId, credentialId, decision: 'revoke',
  });
  assert.equal(revoked.statusCode, 200);
  assert.deepEqual(revoked.body, { status: 'revoked' });
});

test('administrator can reject a pending device and unconfigured allowlist denies', async () => {
  const harness = createHarness({ user: adminId });
  harness.credentials.push({
    credential_id: credentialId, owner_id: userId, status: 'pending',
  });
  const rejected = await invoke(harness.handler, 'admin', {
    ownerId: userId, credentialId, decision: 'reject',
  });
  assert.equal(rejected.statusCode, 200);
  assert.deepEqual(rejected.body, { status: 'rejected' });

  const unconfigured = createHarness({ user: adminId, adminList: '' });
  const denied = await invoke(unconfigured.handler, 'admin', {
    ownerId: userId, credentialId, decision: 'approve',
  });
  assert.equal(denied.statusCode, 403);
});

test('approved status requires a valid fresh assertion and assertion errors fail closed', async () => {
  const harness = createHarness();
  harness.credentials.push({
    credential_id: credentialId, owner_id: userId, status: 'approved',
    public_key: Buffer.from('public-key').toString('base64url'),
    sign_count: 0, transports: ['internal'],
  });

  test('protected challenge stores canonical method, target, and body digest', async () => {
    const harness = createHarness();
    harness.credentials.push({
      credential_id: credentialId,
      owner_id: userId,
      status: 'approved',
      public_key: Buffer.from('public-key').toString('base64url'),
      sign_count: 0,
      transports: ['internal'],
    });
    const result = await invoke(harness.handler, 'challenge', {
      purpose: 'notes',
      method: 'post',
      target: '/api/notes?b=two&a=one',
      hasBody: true,
      body: { title: 'virtual', body: 'content' },
    });

    assert.equal(result.statusCode, 200);
    const challenge = harness.challenges[0];
    assert.equal(challenge.http_method, 'POST');
    assert.equal(challenge.canonical_target, '/api/notes?a=one&b=two');
    assert.match(challenge.body_sha256, /^[a-f0-9]{64}$/u);
    assert.equal(challenge.body_present, true);
  });

  test('WebAuthn verification errors produce an unapproved result', async () => {
    const harness = createHarness({
      verifyAssertionResponse: async () => {
        throw new Error('synthetic invalid authenticator proof');
      },
    });

    test('real WebAuthn library rejects malformed registration and assertion responses', async () => {
      const registration = createHarness({ verifyRegistration: null });
      await invoke(registration.handler, 'registration-options');
      const rejectedRegistration = await invoke(registration.handler, 'registration-verify', {
        challengeId,
        response: { id: credentialId },
      });
      assert.equal(rejectedRegistration.statusCode, 400);
      assert.deepEqual(rejectedRegistration.body, { error: 'INVALID_REGISTRATION' });
      assert.equal(registration.credentials.length, 0);

      const authentication = createHarness({ verifyAssertionResponse: null });
      authentication.credentials.push({
        credential_id: credentialId,
        owner_id: userId,
        status: 'approved',
        public_key: Buffer.from('public-key').toString('base64url'),
        sign_count: 0,
        transports: ['internal'],
      });
      await invoke(authentication.handler, 'challenge', { purpose: 'status' });
      const rejectedAssertion = await invoke(authentication.handler, 'verify', {
        purpose: 'status',
        challengeId: statusChallengeId,
        response: { id: credentialId },
      });
      assert.equal(rejectedAssertion.statusCode, 200);
      assert.deepEqual(rejectedAssertion.body, { status: 'invalid_assertion' });
      assert.equal(authentication.challenges[0].consumed_at, null);
    });
    harness.credentials.push({
      credential_id: credentialId,
      owner_id: userId,
      status: 'approved',
      public_key: Buffer.from('public-key').toString('base64url'),
      sign_count: 0,
      transports: ['internal'],
    });
    await invoke(harness.handler, 'challenge', { purpose: 'status' });
    const result = await invoke(harness.handler, 'verify', {
      purpose: 'status',
      challengeId: statusChallengeId,
      response: { id: credentialId },
    });

    assert.equal(result.statusCode, 200);
    assert.deepEqual(result.body, { status: 'invalid_assertion' });
    assert.equal(harness.challenges[0].consumed_at, null);
  });
  await invoke(harness.handler, 'challenge', { purpose: 'status' });
  const result = await invoke(harness.handler, 'verify', {
    purpose: 'status',
    challengeId: statusChallengeId,
    response: { id: credentialId },
  });
  assert.equal(result.statusCode, 200);
  assert.deepEqual(result.body, { status: 'approved' });
  assert.ok(harness.challenges[0].consumed_at);

  const failed = createHarness();
  failed.credentials.push({
    credential_id: credentialId, owner_id: userId, status: 'approved',
    public_key: Buffer.from('public-key').toString('base64url'),
    sign_count: 0, transports: ['internal'],
  });
  const notApproved = await invoke(failed.handler, 'verify', {
    purpose: 'notes', challengeId,
    response: { id: credentialId },
  });
  assert.equal(notApproved.body.status, 'invalid_challenge');
});
