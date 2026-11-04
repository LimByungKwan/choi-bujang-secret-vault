import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createDeviceApprovalGuard } from '../src/device-approval-guard.mjs';

test('approved server verification runs the protected operation', async () => {
  let databaseCalls = 0;
  const runWithApprovedDevice = createDeviceApprovalGuard({
    verifyApproval: async () => 'approved',
  });

  const result = await runWithApprovedDevice(
    { authenticatedUserId: 'synthetic-user' },
    async () => {
      databaseCalls += 1;
      return 'synthetic-notes';
    },
  );

  assert.deepEqual(result, { allowed: true, value: 'synthetic-notes' });
  assert.equal(databaseCalls, 1);
});

test('pending, rejected, revoked, unknown, and malformed results deny before database access', async t => {
  for (const status of ['pending', 'rejected', 'revoked', 'unknown', null, { status: 'approved' }]) {
    await t.test(String(status), async () => {
      let databaseCalls = 0;
      const runWithApprovedDevice = createDeviceApprovalGuard({
        verifyApproval: async () => status,
      });

      const result = await runWithApprovedDevice(
        { authenticatedUserId: 'synthetic-user' },
        async () => {
          databaseCalls += 1;
        },
      );

      assert.deepEqual(result, { allowed: false, reason: 'approval_required' });
      assert.equal(databaseCalls, 0);
    });
  }
});

test('verification errors deny before database access', async () => {
  let databaseCalls = 0;
  const runWithApprovedDevice = createDeviceApprovalGuard({
    verifyApproval: async () => {
      throw new Error('synthetic verifier failure');
    },
  });

  const result = await runWithApprovedDevice(
    { authenticatedUserId: 'synthetic-user' },
    async () => {
      databaseCalls += 1;
    },
  );

  assert.deepEqual(result, { allowed: false, reason: 'verification_unavailable' });
  assert.equal(databaseCalls, 0);
});

test('request approval flags are not used as verification results', async () => {
  let databaseCalls = 0;
  const runWithApprovedDevice = createDeviceApprovalGuard({
    verifyApproval: async serverContext => {
      assert.equal(serverContext.request.body.approved, true);
      assert.equal(serverContext.request.headers['x-device-approved'], 'true');
      return 'pending';
    },
  });

  const result = await runWithApprovedDevice({
    authenticatedUserId: 'synthetic-user',
    request: {
      body: { approved: true },
      headers: { 'x-device-approved': 'true' },
    },
  }, async () => {
    databaseCalls += 1;
  });

  assert.deepEqual(result, { allowed: false, reason: 'approval_required' });
  assert.equal(databaseCalls, 0);
});

test('the protected operation is not called when the verifier is missing or invalid', async () => {
  assert.throws(() => createDeviceApprovalGuard({}), {
    name: 'TypeError',
    message: 'verify_approval_required',
  });
  assert.throws(() => createDeviceApprovalGuard({ verifyApproval: true }), {
    name: 'TypeError',
    message: 'verify_approval_required',
  });

  const runWithApprovedDevice = createDeviceApprovalGuard({
    verifyApproval: async () => 'approved',
  });
  await assert.rejects(runWithApprovedDevice({}, null), {
    name: 'TypeError',
    message: 'protected_operation_required',
  });
});
