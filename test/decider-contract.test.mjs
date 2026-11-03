import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide, RULE_IDS } from '../src/decider.mjs';

const REQUEST_FIELDS = new Set([
  'schema',
  'requestId',
  'classId',
  'projectId',
  'subjectId',
  'deviceId',
  'service',
  'method',
  'path',
  'route',
  'queryLength',
  'querySha256',
  'at',
  'policyRevision',
  'deviceRegistered',
  'stepUp',
  'recentEvents',
  'signals',
]);

test('decider source reads only request properties in the published contract', async () => {
  const source = await readFile(new URL('../src/decider.mjs', import.meta.url), 'utf8');
  const actual = [...source.matchAll(/\brequest(?:\?\.|\.)\s*([A-Za-z_$][\w$]*)/gu)]
    .map(match => match[1]);

  assert.ok(actual.length > 0);
  assert.ok(actual.every(field => REQUEST_FIELDS.has(field)), actual.join(', '));
  assert.doesNotMatch(source, /request\.(?:identity|device|geo|role)\b/u);
  assert.deepEqual([...RULE_IDS], [
    'device_registered',
    'step_up_required',
    'resource_access',
  ]);
});

test('normal, suspicious, step-up verified, and unregistered fixtures return contract responses', async () => {
  const { normal, suspicious } = fixtureRequests();
  const requests = [
    { request: normal, decision: 'allow', reasonCode: 'approved' },
    {
      request: { ...suspicious, stepUp: { verified: false, authAgeSeconds: null } },
      decision: 'step_up',
      reasonCode: 'step_up_required',
    },
    {
      request: { ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } },
      decision: 'allow',
      reasonCode: 'approved',
    },
    {
      request: { ...normal, deviceRegistered: false },
      decision: 'deny',
      reasonCode: 'device_not_registered',
    },
  ];

  for (const { request, decision, reasonCode } of requests) {
    const response = await decide(request);
    assert.deepEqual(Object.keys(response).sort(), [
      'decision',
      'reasonCode',
      'requestId',
      'ruleIds',
      'schema',
    ]);
    assert.equal(response.schema, 'aleph.decision.v1');
    assert.equal(response.requestId, request.requestId);
    assert.equal(response.decision, decision);
    assert.equal(response.reasonCode, reasonCode);
    assert.ok(response.ruleIds.every(rule => RULE_IDS.includes(rule)));
  }
});
