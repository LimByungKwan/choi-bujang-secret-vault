import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHttpRequestBinding } from '../public/request-binding.mjs';

test('request binding normalizes method, path, and query order', async () => {
  const first = await createHttpRequestBinding({
    method: 'get',
    target: '/api/notes?id=20000000-0000-4000-8000-000000000001&view=full',
    hasBody: false,
  });
  const reordered = await createHttpRequestBinding({
    method: 'GET',
    target: '/api/notes?view=full&id=20000000-0000-4000-8000-000000000001',
    hasBody: false,
  });

  assert.deepEqual(first, {
    method: 'GET',
    target: '/api/notes?id=20000000-0000-4000-8000-000000000001&view=full',
    bodySha256: null,
    bodyPresent: false,
  });
  assert.deepEqual(reordered, first);
});

test('request body digest uses recursively sorted JSON keys and distinguishes edits', async () => {
  const first = await createHttpRequestBinding({
    method: 'POST',
    target: '/api/notes',
    body: { title: 'virtual', details: { z: 2, a: 1 } },
    hasBody: true,
  });
  const reordered = await createHttpRequestBinding({
    method: 'POST',
    target: '/api/notes',
    body: { details: { a: 1, z: 2 }, title: 'virtual' },
    hasBody: true,
  });
  const changed = await createHttpRequestBinding({
    method: 'POST',
    target: '/api/notes',
    body: { details: { a: 1, z: 3 }, title: 'virtual' },
    hasBody: true,
  });

  assert.match(first.bodySha256, /^[a-f0-9]{64}$/u);
  assert.equal(first.bodySha256, reordered.bodySha256);
  assert.notEqual(first.bodySha256, changed.bodySha256);
});

test('request binding rejects ambiguous path forms and non-JSON values', async () => {
  await assert.rejects(createHttpRequestBinding({
    method: 'GET', target: '/api/notes/%2f..', hasBody: false,
  }), { message: 'invalid_request_target' });
  await assert.rejects(createHttpRequestBinding({
    method: 'GET', target: '/api/notes/../admin', hasBody: false,
  }), { message: 'invalid_request_target' });
  await assert.rejects(createHttpRequestBinding({
    method: 'POST', target: '/api/notes', body: { value: undefined }, hasBody: true,
  }), { message: 'invalid_json_body' });
});
