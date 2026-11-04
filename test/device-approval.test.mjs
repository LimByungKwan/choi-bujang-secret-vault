import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createDeviceApprovalController } from '../public/device-approval.mjs';

function deferred() {
  let resolve;
  const promise = new Promise(resolvePromise => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function createHarness(checkApproval) {
  const states = [];
  let clearCount = 0;
  const loadCalls = [];
  const controller = createDeviceApprovalController({
    checkApproval,
    clearProtectedUi: () => { clearCount += 1; },
    onStateChange: state => states.push(state),
    loadNotes: async isCurrent => {
      loadCalls.push(isCurrent);
    },
  });
  return {
    controller,
    states,
    loadCalls,
    get clearCount() { return clearCount; },
  };
}

test('only an approved server result loads protected notes', async () => {
  const harness = createHarness(async () => 'approved');

  await harness.controller.setSession({ id: 'synthetic-user' });

  assert.equal(harness.controller.state, 'approved');
  assert.equal(harness.controller.isApproved(), true);
  assert.equal(harness.loadCalls.length, 1);
  assert.equal(harness.loadCalls[0](), true);
  assert.deepEqual(harness.states, ['unknown', 'checking', 'approved']);
});

test('denied, pending, and unrecognized results clear protected UI without loading notes', async t => {
  for (const [label, result] of [
    ['denied', 'denied'],
    ['pending', 'pending'],
    ['unrecognized response', { status: 'approved' }],
  ]) {
    await t.test(label, async () => {
      const harness = createHarness(async () => result);

      await harness.controller.setSession({ id: 'synthetic-user' });

      assert.equal(harness.controller.state, 'unapproved');
      assert.equal(harness.controller.isApproved(), false);
      assert.equal(harness.loadCalls.length, 0);
      assert.ok(harness.clearCount >= 2);
    });
  }
});

test('approval lookup errors block access and clear protected UI', async () => {
  const harness = createHarness(async () => {
    throw new Error('synthetic approval service failure');
  });

  await harness.controller.setSession({ id: 'synthetic-user' });

  assert.equal(harness.controller.state, 'unavailable');
  assert.equal(harness.controller.isApproved(), false);
  assert.equal(harness.loadCalls.length, 0);
  assert.ok(harness.clearCount >= 2);
});

test('a late approval result after a session change is ignored', async () => {
  const lookup = deferred();
  const harness = createHarness(() => lookup.promise);
  const oldSession = harness.controller.setSession({ id: 'synthetic-user-a' });

  await harness.controller.setSession(null);
  lookup.resolve('approved');
  await oldSession;

  assert.equal(harness.controller.state, 'signed_out');
  assert.equal(harness.controller.isApproved(), false);
  assert.equal(harness.loadCalls.length, 0);
});

test('a newer session ignores stale approval and invalidates an in-flight note-load callback', async () => {
  const firstLookup = deferred();
  const secondLookup = deferred();
  const thirdLookup = deferred();
  const lookups = [firstLookup, secondLookup, thirdLookup];
  const noteLoad = deferred();
  const loadCalls = [];
  const controller = createDeviceApprovalController({
    checkApproval: () => lookups.shift().promise,
    clearProtectedUi: () => {},
    onStateChange: () => {},
    loadNotes: async isCurrent => {
      loadCalls.push(isCurrent);
      await noteLoad.promise;
    },
  });

  const firstSession = controller.setSession({ id: 'synthetic-user-a' });
  const secondSession = controller.setSession({ id: 'synthetic-user-b' });
  firstLookup.resolve('approved');
  await firstSession;
  assert.equal(loadCalls.length, 0);

  secondLookup.resolve('approved');
  await Promise.resolve();
  await Promise.resolve();
  assert.equal(controller.isApproved(), true);
  assert.equal(loadCalls.length, 1);
  assert.equal(loadCalls[0](), true);

  const thirdSession = controller.setSession({ id: 'synthetic-user-c' });
  assert.equal(loadCalls[0](), false);
  thirdLookup.resolve('denied');
  noteLoad.resolve();
  await Promise.all([secondSession, thirdSession]);
  assert.equal(controller.isApproved(), false);
  assert.equal(controller.state, 'unapproved');
});

test('session replacement invalidates the current approved state immediately', async () => {
  const firstLookup = deferred();
  const secondLookup = deferred();
  const lookups = [firstLookup, secondLookup];
  const harness = createHarness(() => lookups.shift().promise);
  const firstSession = harness.controller.setSession({ id: 'synthetic-user-a' });
  firstLookup.resolve('approved');
  await firstSession;
  assert.equal(harness.controller.isApproved(), true);

  const nextSession = harness.controller.setSession({ id: 'synthetic-user-b' });
  assert.equal(harness.controller.isApproved(), false);
  assert.equal(harness.controller.state, 'checking');
  secondLookup.resolve('denied');
  await nextSession;
  assert.equal(harness.controller.state, 'unapproved');
  assert.equal(harness.loadCalls.length, 1);
});
