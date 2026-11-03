import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { test } from 'node:test';
import { createNoteBackupManifest } from '../src/note-backup-manifest.mjs';
import { readCompleteBackup } from '../src/note-backup-read.mjs';
import { signNoteBackupManifest } from '../src/note-backup-sign.mjs';
import { saveVerifiedNoteBackup } from '../src/note-backup-store.mjs';

const userId = '30000000-0000-4000-8000-000000000051';
const otherUserId = '30000000-0000-4000-8000-000000000052';
const noteId = '50000000-0000-4000-8000-000000000051';
const otherNoteId = '50000000-0000-4000-8000-000000000052';
const backupVersion = 'synthetic-reader-backup-v1';
const keyId = 'synthetic-reader-key';
const title = 'synthetic reader private title marker';
const content = 'synthetic reader private content marker';
const tokenMarker = 'synthetic-reader-token-marker';
const privateKeyMarker = 'synthetic-reader-private-key-marker';
const storagePrefix = 'note-backups/v1';

function createMemoryAdapter() {
  const objects = new Map();
  const readCalls = [];
  let createCount = 0;
  return {
    objects,
    readCalls,
    async createIfAbsent(path, bytes) {
      createCount += 1;
      if (objects.has(path)) return false;
      objects.set(path, Buffer.from(bytes));
      return true;
    },
    async read(path) {
      readCalls.push(path);
      if (!objects.has(path)) return undefined;
      return Buffer.from(objects.get(path));
    },
  };
}

function createFixture() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const backup = {
    id: noteId,
    owner_id: userId,
    title,
    content,
    backupVersion,
  };
  const manifest = createNoteBackupManifest({
    ...backup,
    keyId,
  });
  const signature = signNoteBackupManifest({ manifest, privateKey });
  return {
    backup,
    manifest,
    signature,
    trustedPublicKeys: [{
      keyId,
      publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    }],
    privateKeyMarker,
    tokenMarker,
  };
}

function hash(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function expectedPaths(targetId = noteId, ownerId = userId, version = backupVersion) {
  const versionSegment = Buffer.from(version, 'utf8').toString('base64url');
  const root = `${storagePrefix}/${ownerId}/${targetId}/${versionSegment}`;
  const rootHash = hash(Buffer.from(root, 'utf8'));
  return {
    backup: `${root}/backup.json`,
    manifest: `${root}/manifest.json`,
    signature: `${root}/signature.txt`,
    completion: `${storagePrefix}/completed/nb1_${rootHash}.json`,
  };
}

async function saveFixture(fixture, adapter = createMemoryAdapter()) {
  const result = await saveVerifiedNoteBackup({
    backup: fixture.backup,
    manifest: fixture.manifest,
    signature: fixture.signature,
    trustedPublicKeys: fixture.trustedPublicKeys,
    storageAdapter: adapter,
  });
  assert.equal(result.saved, true);
  assert.equal(result.status, 'complete');
  return { adapter, result };
}

function read(fixture, adapter, overrides = {}) {
  return readCompleteBackup({
    targetId: noteId,
    ownerId: userId,
    backupVersion,
    trustedPublicKeys: fixture.trustedPublicKeys,
    storageAdapter: adapter,
    ...overrides,
  });
}

function completionMarker(adapter, paths = expectedPaths()) {
  return JSON.parse(adapter.objects.get(paths.completion).toString('utf8'));
}

function setCompletionMarker(adapter, marker, path = expectedPaths().completion) {
  adapter.objects.set(path, Buffer.from(JSON.stringify(marker), 'utf8'));
}

function updateObjectHashInMarker(adapter, name, objectPath, markerPath) {
  const marker = completionMarker(adapter);
  marker.objects[name] = {
    path: objectPath,
    sha256: hash(adapter.objects.get(objectPath)),
  };
  setCompletionMarker(adapter, marker, markerPath);
}

function assertSafeFailure(result) {
  assert.equal(result.read, false);
  assert.equal(result.status, 'unavailable');
  const serialized = JSON.stringify(result);
  for (const marker of [title, content, tokenMarker, privateKeyMarker]) {
    assert.equal(serialized.includes(marker), false);
  }
}

test('reads a saved synthetic backup only after completion and all integrity checks', async () => {
  const fixture = createFixture();
  const { adapter } = await saveFixture(fixture);

  const result = await read(fixture, adapter);

  assert.equal(result.read, true);
  assert.equal(result.status, 'complete');
  assert.deepEqual(result.backup, fixture.backup);
  assert.equal(result.backup.id, noteId);
  assert.equal(result.backup.owner_id, userId);
  assert.equal(result.backup.title, title);
  assert.equal(result.backup.content, content);
  assert.deepEqual(result.manifest, fixture.manifest);
  assert.equal(result.manifest.contentSha256, fixture.manifest.contentSha256);
  assert.equal(result.manifest.noteSha256, fixture.manifest.noteSha256);
  assert.equal(result.signature, fixture.signature);
});

test('a missing completion marker prevents reads of all backup objects', async () => {
  const fixture = createFixture();
  const { adapter } = await saveFixture(fixture);
  adapter.objects.delete(expectedPaths().completion);
  adapter.readCalls.length = 0;

  const result = await read(fixture, adapter);

  assertSafeFailure(result);
  assert.equal(result.reason, 'completion_marker_unavailable');
  assert.deepEqual(adapter.readCalls, [expectedPaths().completion]);
});

test('malformed or mismatched completion markers are rejected before object reads', async t => {
  const cases = [
    ['malformed JSON', () => Buffer.from('{', 'utf8')],
    ['wrong schema', marker => ({ ...marker, schema: 'wrong-schema' })],
    ['wrong backup reference', marker => ({ ...marker, backupRef: 'nb1_wrong' })],
    ['extra marker field', marker => ({ ...marker, targetId: noteId })],
    ['missing object entry', marker => ({
      ...marker,
      objects: { backup: marker.objects.backup, manifest: marker.objects.manifest },
    })],
    ['wrong object path', marker => ({
      ...marker,
      objects: {
        ...marker.objects,
        backup: { ...marker.objects.backup, path: `${marker.objects.backup.path}.other` },
      },
    })],
    ['invalid object digest', marker => ({
      ...marker,
      objects: {
        ...marker.objects,
        signature: { ...marker.objects.signature, sha256: 'not-a-digest' },
      },
    })],
  ];

  for (const [name, transform] of cases) {
    await t.test(name, async () => {
      const fixture = createFixture();
      const { adapter } = await saveFixture(fixture);
      const path = expectedPaths().completion;
      const original = adapter.objects.get(path);
      if (name === 'malformed JSON') {
        adapter.objects.set(path, transform());
      } else {
        setCompletionMarker(adapter, transform(completionMarker(adapter)), path);
      }
      adapter.readCalls.length = 0;

      const result = await read(fixture, adapter);

      assertSafeFailure(result);
      assert.equal(result.reason, 'completion_marker_invalid');
      assert.deepEqual(adapter.readCalls, [path]);
      assert.notDeepEqual(adapter.objects.get(path), original);
    });
  }
});

test('the requested target ID, owner ID, and version bind the marker path', async t => {
  const cases = [
    ['other target ID', { targetId: otherNoteId }],
    ['other owner ID', { ownerId: otherUserId }],
    ['other backup version', { backupVersion: 'other-synthetic-version' }],
  ];

  for (const [name, override] of cases) {
    await t.test(name, async () => {
      const fixture = createFixture();
      const { adapter } = await saveFixture(fixture);
      adapter.readCalls.length = 0;

      const result = await read(fixture, adapter, override);
      const requestedPath = expectedPaths(
        override.targetId ?? noteId,
        override.ownerId ?? userId,
        override.backupVersion ?? backupVersion,
      ).completion;

      assertSafeFailure(result);
      assert.equal(result.reason, 'completion_marker_unavailable');
      assert.equal(adapter.readCalls.length, 1);
      assert.equal(adapter.readCalls[0], requestedPath);
      const savedPath = [...adapter.objects.keys()]
        .find(path => path.startsWith(`${storagePrefix}/completed/`));
      assert.ok(savedPath);
      assert.notEqual(requestedPath, savedPath);
    });
  }
});

test('a completion marker with any referenced object missing is rejected', async t => {
  for (const name of ['backup', 'manifest', 'signature']) {
    await t.test(name, async () => {
      const fixture = createFixture();
      const { adapter } = await saveFixture(fixture);
      const paths = expectedPaths();
      adapter.objects.delete(paths[name]);
      adapter.readCalls.length = 0;

      const result = await read(fixture, adapter);

      assertSafeFailure(result);
      assert.equal(result.reason, 'backup_object_unavailable');
      assert.equal(adapter.readCalls[0], paths.completion);
      assert.equal(adapter.readCalls.includes(paths[name]), true);
      assert.equal(adapter.objects.has(paths.completion), true);
    });
  }
});

test('stored backup, manifest, and signature byte modifications are detected', async t => {
  for (const name of ['backup', 'manifest', 'signature']) {
    await t.test(name, async () => {
      const fixture = createFixture();
      const { adapter } = await saveFixture(fixture);
      const path = expectedPaths()[name];
      const changed = Buffer.from(adapter.objects.get(path));
      changed[0] ^= 1;
      adapter.objects.set(path, changed);

      const result = await read(fixture, adapter);

      assertSafeFailure(result);
      assert.equal(result.reason, 'backup_object_hash_mismatch');
    });
  }
});

test('a matching marker byte hash does not bypass backup content hash verification', async () => {
  const fixture = createFixture();
  const { adapter } = await saveFixture(fixture);
  const paths = expectedPaths();
  const backup = JSON.parse(adapter.objects.get(paths.backup).toString('utf8'));
  backup.content = 'altered synthetic content';
  adapter.objects.set(paths.backup, Buffer.from(JSON.stringify(backup), 'utf8'));
  updateObjectHashInMarker(adapter, 'backup', paths.backup, paths.completion);

  const result = await read(fixture, adapter);

  assertSafeFailure(result);
  assert.equal(result.reason, 'backup_hash_mismatch');
});

test('a matching marker byte hash does not bypass Ed25519 signature verification', async () => {
  const fixture = createFixture();
  const { adapter } = await saveFixture(fixture);
  const paths = expectedPaths();
  const signature = Buffer.from(adapter.objects.get(paths.signature));
  signature[0] = signature[0] === 65 ? 66 : 65;
  adapter.objects.set(paths.signature, signature);
  updateObjectHashInMarker(adapter, 'signature', paths.signature, paths.completion);

  const result = await read(fixture, adapter);

  assertSafeFailure(result);
  assert.equal(result.reason, 'manifest_signature_invalid');
});

test('untrusted public keys reject an otherwise intact completed backup', async () => {
  const fixture = createFixture();
  const { adapter } = await saveFixture(fixture);
  const result = await read(fixture, adapter, { trustedPublicKeys: [] });

  assertSafeFailure(result);
  assert.equal(result.reason, 'manifest_signature_invalid');
});

test('different target IDs or owners cannot read another completed backup', async t => {
  for (const [name, override] of [
    ['target ID', { targetId: otherNoteId }],
    ['owner ID', { ownerId: otherUserId }],
  ]) {
    await t.test(name, async () => {
      const fixture = createFixture();
      const { adapter } = await saveFixture(fixture);

      const result = await read(fixture, adapter, override);

      assertSafeFailure(result);
      assert.equal(result.status, 'unavailable');
    });
  }
});

test('invalid request identity, version, and trusted key inputs are rejected safely', async t => {
  const cases = [
    ['invalid target UUID', { targetId: '../not-a-uuid' }],
    ['invalid owner UUID', { ownerId: 'not-a-uuid' }],
    ['empty backup version', { backupVersion: '' }],
    ['oversized backup version', { backupVersion: 'x'.repeat(101) }],
    ['non-array trusted keys', { trustedPublicKeys: 'not-an-array' }],
  ];

  for (const [name, override] of cases) {
    await t.test(name, async () => {
      const fixture = createFixture();
      const adapter = createMemoryAdapter();

      const result = await read(fixture, adapter, override);

      assertSafeFailure(result);
      assert.equal(adapter.readCalls.length, 0);
    });
  }
});

test('storage read exceptions and invalid byte types fail without exposing input', async t => {
  for (const [name, response] of [
    ['throws', async () => { throw new Error(tokenMarker); }],
    ['string', async () => tokenMarker],
    ['plain object', async () => ({ bytes: tokenMarker })],
  ]) {
    await t.test(name, async () => {
      const fixture = createFixture();
      const adapter = createMemoryAdapter();
      adapter.read = async path => {
        adapter.readCalls.push(path);
        return response();
      };

      const result = await read(fixture, adapter);

      assertSafeFailure(result);
      assert.equal(result.reason, 'completion_marker_unavailable');
      assert.deepEqual(adapter.readCalls, [expectedPaths().completion]);
    });
  }
});

test('completion marker with matching hashes but invalid JSON objects is rejected', async t => {
  for (const name of ['backup', 'manifest']) {
    await t.test(name, async () => {
      const fixture = createFixture();
      const { adapter } = await saveFixture(fixture);
      const paths = expectedPaths();
      adapter.objects.set(paths[name], Buffer.from('{', 'utf8'));
      updateObjectHashInMarker(adapter, name, paths[name], paths.completion);

      const result = await read(fixture, adapter);

      assertSafeFailure(result);
      assert.equal(result.reason, 'backup_object_invalid');
    });
  }
});

test('success output shape is deliberately not an API response contract', async () => {
  // The successful reader result contains the full backup, including title
  // and content. An operational API must not return it directly to clients.
  const fixture = createFixture();
  const { adapter } = await saveFixture(fixture);
  const result = await read(fixture, adapter);

  assert.equal(result.read, true);
  assert.deepEqual(Object.keys(result).sort(), [
    'backup',
    'backupRef',
    'manifest',
    'read',
    'signature',
    'status',
  ]);
});
