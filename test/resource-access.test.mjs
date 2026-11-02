import assert from 'node:assert/strict';
import { test } from 'node:test';
import { classifyResourceAccess } from '../src/resource-access.mjs';

const classify = (service, method, path, route) =>
  classifyResourceAccess({ service, method, path, route });

function assertOutcome(result, outcome, detail) {
  assert.equal(result.outcome, outcome);
  assert.equal(result.detail, detail);
  assert.equal(result.contractStatus, 'local_proposal_not_engine_verified');
}

test('allows an individual note GET using a non-UUID fixture identifier', () => {
  const result = classify('notes', 'GET', '/notes/fixture-note-7', 'GET /notes/:id');
  assertOutcome(result, 'allow_candidate', 'route_matches_local_convention');
  assert.equal(result.resourceType, 'personal_note');
});

test('denies the note collection and methods other than GET', () => {
  assertOutcome(
    classify('notes', 'GET', '/notes', 'GET /notes'),
    'deny_candidate',
    'individual_get_only',
  );
  assertOutcome(
    classify('notes', 'PUT', '/notes/note-a', 'PUT /notes/:id'),
    'deny_candidate',
    'individual_get_only',
  );
});

test('allows announcement reads and denies every write method', () => {
  const list = classify('announcements', 'GET', '/announcements', 'GET /announcements');
  assertOutcome(list, 'allow_candidate', 'route_matches_local_convention');
  assert.equal(list.resourceType, 'class_announcement');

  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
    assertOutcome(
      classify('announcements', method, '/announcements/a1', `${method} /announcements/:id`),
      'deny_candidate',
      'read_only_resource',
    );
  }
});

test('denies every instructor-material request under the local convention', () => {
  for (const [method, path, route] of [
    ['GET', '/instructor-materials', 'GET /instructor-materials'],
    ['GET', '/instructor-materials/a1', 'GET /instructor-materials/:id'],
    ['POST', '/instructor-materials/a1', 'POST /instructor-materials/:id'],
  ]) {
    assertOutcome(
      classify('instructor_materials', method, path, route),
      'deny_candidate',
      'resource_denied',
    );
  }
});

test('denies unknown services and paths', () => {
  assertOutcome(
    classify('unknown', 'GET', '/unknown/a1', 'GET /unknown/:id'),
    'deny_candidate',
    'unknown_service',
  );
  assertOutcome(
    classify('notes', 'GET', '/notes/a1/export', 'GET /notes/:id/export'),
    'deny_candidate',
    'invalid_path_shape',
  );
  assertOutcome(
    classify('notes', 'GET', '/notes/export', 'GET /notes/:id'),
    'deny_candidate',
    'reserved_function_path',
  );
});

test('denies encoded reserved paths, double encoding, and encoded separators', () => {
  for (const id of [
    '%65xport',
    '%2578port',
    '%2fexport',
    '%5cexport',
    '%252fexport',
  ]) {
    assertOutcome(
      classify('notes', 'GET', `/notes/${id}`, 'GET /notes/:id'),
      'deny_candidate',
      'invalid_path_shape',
    );
  }
});

test('denies paths with normalization ambiguity', () => {
  for (const path of [
    '/notes/../export',
    '/notes/./note-a',
    '/notes//note-a',
    '/notes\\export',
    '/notes/ note-a',
    '/notes/EXPORT',
  ]) {
    assertOutcome(
      classify('notes', 'GET', path, 'GET /notes/:id'),
      'deny_candidate',
      path.endsWith('/EXPORT') ? 'reserved_function_path' : 'invalid_path_shape',
    );
  }
});

test('denies service, method, path, and route mismatches', () => {
  const cases = [
    ['notes', 'POST', '/notes/a1', 'GET /notes/:id', 'service_method_path_route_mismatch'],
    ['notes', 'GET', '/notes/a1', 'GET /notes', 'service_method_path_route_mismatch'],
    ['notes', 'GET', '/announcements/a1', 'GET /notes/:id', 'invalid_path_shape'],
    ['announcements', 'GET', '/announcements/a1', 'GET /notes/:id',
      'service_method_path_route_mismatch'],
    ['notes', 'get', '/notes/a1', 'get /notes/:id', 'invalid_path_shape'],
    ['notes', 'GET', '/notes/a1?export=1', 'GET /notes/:id', 'invalid_path_shape'],
    ['notes', 'GET', '/notes/a%2Fb', 'GET /notes/:id', 'invalid_path_shape'],
  ];

  for (const [service, method, path, route, detail] of cases) {
    assertOutcome(
      classify(service, method, path, route),
      'deny_candidate',
      detail,
    );
  }

  assertOutcome(classify(null), 'deny_candidate', 'unknown_service');
});
