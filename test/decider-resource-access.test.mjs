import assert from 'node:assert/strict';
import { test } from 'node:test';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide, RULE_IDS } from '../src/decider.mjs';

const RESPONSE_KEYS = ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema'];

function requestWith(base, overrides) {
  return { ...base, ...overrides };
}

async function assertDecision(request, decision, reasonCode, ruleIds) {
  const response = await decide(request);
  assert.deepEqual(Object.keys(response).sort(), RESPONSE_KEYS);
  assert.equal(response.schema, 'aleph.decision.v1');
  assert.equal(response.requestId, request.requestId);
  assert.equal(response.decision, decision);
  assert.equal(response.reasonCode, reasonCode);
  assert.deepEqual(response.ruleIds, ruleIds);
  assert.ok(response.ruleIds.every(id => RULE_IDS.includes(id)));
}

test('preserves device and risk policy for allowed individual note GETs', async () => {
  const { normal, suspicious } = fixtureRequests();
  await assertDecision(normal, 'allow', 'approved', ['device_registered']);
  await assertDecision(
    requestWith(suspicious, { stepUp: { verified: false, authAgeSeconds: null } }),
    'step_up',
    'step_up_required',
    ['device_registered', 'step_up_required'],
  );
  await assertDecision(
    requestWith(suspicious, { stepUp: { verified: true, authAgeSeconds: 60 } }),
    'allow',
    'approved',
    ['device_registered'],
  );
});

test('denies unregistered devices before resource or risk evaluation', async () => {
  const { suspicious } = fixtureRequests();
  await assertDecision(
    requestWith(suspicious, { deviceRegistered: false }),
    'deny',
    'device_not_registered',
    ['device_registered'],
  );
  await assertDecision(
    requestWith(suspicious, { deviceRegistered: undefined }),
    'deny',
    'device_not_registered',
    ['device_registered'],
  );
});

test('denies note collection and write methods', async () => {
  const { normal } = fixtureRequests();
  for (const [method, path, route] of [
    ['GET', '/notes', 'GET /notes'],
    ['PUT', '/notes/note-a', 'PUT /notes/:id'],
    ['DELETE', '/notes/note-a', 'DELETE /notes/:id'],
  ]) {
    await assertDecision(
      requestWith(normal, { method, path, route }),
      'deny',
      'resource_access_denied',
      ['resource_access'],
    );
  }
});

test('allows announcement GET and denies write methods', async () => {
  const { normal } = fixtureRequests();
  await assertDecision(
    requestWith(normal, {
      service: 'announcements',
      method: 'GET',
      path: '/announcements',
      route: 'GET /announcements',
    }),
    'allow',
    'approved',
    ['device_registered'],
  );

  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    await assertDecision(
      requestWith(normal, {
        service: 'announcements',
        method,
        path: '/announcements/notice-a',
        route: `${method} /announcements/:id`,
      }),
      'deny',
      'resource_access_denied',
      ['resource_access'],
    );
  }
});

test('denies instructor materials, unknown paths, and route spoofing', async () => {
  const { normal } = fixtureRequests();
  for (const overrides of [
    {
      service: 'instructor_materials',
      method: 'GET',
      path: '/instructor-materials/material-a',
      route: 'GET /instructor-materials/:id',
    },
    {
      service: 'instructor_materials',
      method: 'PUT',
      path: '/instructor-materials/material-a',
      route: 'PUT /instructor-materials/:id',
    },
    {
      service: 'unknown',
      method: 'GET',
      path: '/unknown/item-a',
      route: 'GET /unknown/:id',
    },
    {
      service: 'notes',
      method: 'GET',
      path: '/notes/note-a/export',
      route: 'GET /notes/:id/export',
    },
    {
      service: 'notes',
      method: 'GET',
      path: '/notes/note-a',
      route: 'GET /notes',
    },
  ]) {
    await assertDecision(
      requestWith(normal, overrides),
      'deny',
      'resource_access_denied',
      ['resource_access'],
    );
  }
});

test('candidate reason code is local-only and not asserted as an operational code', async () => {
  const { normal } = fixtureRequests();
  const response = await decide(requestWith(normal, {
    service: 'unknown',
    path: '/unknown/item-a',
    route: 'GET /unknown/:id',
  }));
  assert.equal(response.reasonCode, 'resource_access_denied');
  assert.equal(RULE_IDS.includes('resource_access'), true);
});
